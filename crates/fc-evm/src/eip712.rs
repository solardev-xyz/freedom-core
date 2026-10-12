//! EIP-712 hashing with ethers v6 `TypedDataEncoder` semantics, as
//! `Wallet.signTypedData(domain, types, message)` applies them (design 0002).
//!
//! Where ethers is lenient, this is stricter, and every such case is a
//! `deviation` vector:
//! - `bool` takes only JSON booleans. ethers encodes any truthy value as true
//!   (including `"false"` and `"0"`), and a missing bool field as false.
//! - Quantity strings are `[-]digits` or `[-]0x hex` (see `parse_signed`).
//! - Type and field names are identifiers, so `encodeType` strings can't be
//!   made ambiguous by names containing `(`, `,` or spaces.
//! - Limits: 256 types, 256 fields per type, nesting depth 32. ethers has
//!   none, and its subtype walk is exponential on diamond-shaped types.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::{Error, U256, keccak256, parse_address, parse_bytes, parse_signed};

const MAX_TYPES: usize = 256;
const MAX_FIELDS: usize = 256;
const MAX_DEPTH: usize = 32;
/// The largest integer a JS number holds exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const DOMAIN_FIELDS: [(&str, &str); 5] = [
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
    ("salt", "bytes32"),
];

fn err(message: impl Into<String>) -> Error {
    Error::TypedData(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Base {
    Uint(u32),
    Int(u32),
    FixedBytes(usize),
    Bytes,
    String,
    Address,
    Bool,
    Struct(String),
}

/// A field type: its base, and array dimensions from innermost to outermost
/// (`None` is dynamic).
#[derive(Debug, Clone)]
struct FieldType {
    base: Base,
    dims: Vec<Option<u64>>,
}

#[derive(Debug, Clone)]
struct Field {
    name: String,
    /// As ethers prints it in `encodeType`: the base (with `uint`/`int`
    /// aliases resolved) and the array suffix exactly as written.
    type_text: String,
    ty: FieldType,
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// ethers' `splitArray`: the base (up to the first `[`) and, if the rest is
/// entirely `[digits?]` groups, their counts. Otherwise the whole string is
/// the base.
fn split_array(text: &str) -> (&str, &str, Vec<Option<u64>>) {
    let Some(open) = text.find('[') else {
        return (text, "", Vec::new());
    };
    let (base, suffix) = text.split_at(open);
    let mut dims = Vec::new();
    let mut rest = suffix;
    while let Some(after) = rest.strip_prefix('[') {
        let Some(close) = after.find(']') else {
            return (text, "", Vec::new());
        };
        let digits = &after[..close];
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return (text, "", Vec::new());
        }
        // Absurd counts can't match any value; ethers' parseInt behaves alike.
        dims.push(if digits.is_empty() {
            None
        } else {
            Some(digits.parse().unwrap_or(u64::MAX))
        });
        rest = &after[close + 1..];
    }
    if rest.is_empty() {
        (base, suffix, dims)
    } else {
        (text, "", Vec::new())
    }
}

/// ethers' `getBaseEncoder` types; an ill-formed width is an error, as there.
fn primitive(base: &str) -> Result<Option<Base>, Error> {
    let width = |digits: &str, max: u32, step: u32| -> Result<u32, Error> {
        let width: u32 = digits
            .parse()
            .map_err(|_| err(format!("invalid width in {base:?}")))?;
        if width == 0 || width > max || !width.is_multiple_of(step) || digits != width.to_string() {
            return Err(err(format!("invalid width in {base:?}")));
        }
        Ok(width)
    };
    let numeric = |digits: &str| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    if let Some(digits) = base.strip_prefix("uint").filter(|d| numeric(d)) {
        return Ok(Some(Base::Uint(width(digits, 256, 8)?)));
    }
    if let Some(digits) = base.strip_prefix("int").filter(|d| numeric(d)) {
        return Ok(Some(Base::Int(width(digits, 256, 8)?)));
    }
    if let Some(digits) = base.strip_prefix("bytes").filter(|d| numeric(d)) {
        return Ok(Some(Base::FixedBytes(width(digits, 32, 1)? as usize)));
    }
    Ok(match base {
        "address" => Some(Base::Address),
        "bool" => Some(Base::Bool),
        "bytes" => Some(Base::Bytes),
        "string" => Some(Base::String),
        _ => None,
    })
}

struct Types {
    fields: BTreeMap<String, Vec<Field>>,
    primary: String,
    /// `encodeType` of each struct with its sorted subtypes appended.
    full: BTreeMap<String, String>,
}

impl Types {
    fn parse(value: &Value) -> Result<Self, Error> {
        let object = value
            .as_object()
            .ok_or_else(|| err("types: expected an object"))?;
        if object.len() > MAX_TYPES {
            return Err(err("types: too many"));
        }
        for name in object.keys() {
            if !is_identifier(name) {
                return Err(err(format!("type name {name:?} is not an identifier")));
            }
        }
        let mut fields = BTreeMap::new();
        let mut parents: BTreeMap<&str, usize> = object.keys().map(|k| (k.as_str(), 0)).collect();
        let mut links: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (name, list) in object {
            let list = list
                .as_array()
                .ok_or_else(|| err(format!("{name}: expected a field list")))?;
            if list.len() > MAX_FIELDS {
                return Err(err(format!("{name}: too many fields")));
            }
            let mut seen = BTreeSet::new();
            let mut parsed = Vec::with_capacity(list.len());
            let children = links.entry(name.clone()).or_default();
            for field in list {
                let field_name = field.get("name").and_then(Value::as_str);
                let field_type = field.get("type").and_then(Value::as_str);
                let (Some(field_name), Some(field_type)) = (field_name, field_type) else {
                    return Err(err(format!("{name}: fields need a string name and type")));
                };
                if !is_identifier(field_name) {
                    return Err(err(format!(
                        "field name {field_name:?} is not an identifier"
                    )));
                }
                if !seen.insert(field_name) {
                    return Err(err(format!("duplicate field {field_name:?} in {name:?}")));
                }
                let (raw_base, suffix, dims) = split_array(field_type);
                let base_text = match raw_base {
                    "int" if !object.contains_key("int") => "int256",
                    "uint" if !object.contains_key("uint") => "uint256",
                    other => other,
                };
                if base_text == name {
                    return Err(err(format!("circular type reference to {name:?}")));
                }
                let base = match primitive(base_text)? {
                    Some(base) => base,
                    None => {
                        let count = parents
                            .get_mut(base_text)
                            .ok_or_else(|| err(format!("unknown type {base_text:?}")))?;
                        *count += 1;
                        children.insert(base_text.to_owned());
                        Base::Struct(base_text.to_owned())
                    }
                };
                parsed.push(Field {
                    name: field_name.to_owned(),
                    type_text: format!("{base_text}{suffix}"),
                    ty: FieldType { base, dims },
                });
            }
            fields.insert(name.clone(), parsed);
        }
        let roots: Vec<&str> = parents
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(k, _)| *k)
            .collect();
        let primary = match roots.as_slice() {
            [] => return Err(err("missing primary type")),
            [one] => (*one).to_owned(),
            _ => {
                return Err(err(format!(
                    "ambiguous primary types or unused types: {roots:?}"
                )));
            }
        };

        // Descendants of every type reachable from the primary type, with
        // cycle detection (ethers' checkCircular, without its exponential
        // re-walking of shared subtypes).
        let mut descendants: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut in_progress = BTreeSet::new();
        collect(&primary, &links, &mut descendants, &mut in_progress)?;

        let encode_type = |name: &str| {
            let list = fields.get(name).map(Vec::as_slice).unwrap_or_default();
            let inner: Vec<String> = list
                .iter()
                .map(|f: &Field| format!("{} {}", f.type_text, f.name))
                .collect();
            format!("{name}({})", inner.join(","))
        };
        let mut full = BTreeMap::new();
        for (name, subtypes) in &descendants {
            // BTreeSet iterates in byte order: JS sort order for ASCII names.
            let mut text = encode_type(name);
            for subtype in subtypes {
                text.push_str(&encode_type(subtype));
            }
            full.insert(name.clone(), text);
        }
        Ok(Types {
            fields,
            primary,
            full,
        })
    }

    fn type_hash(&self, name: &str) -> Result<[u8; 32], Error> {
        self.full
            .get(name)
            .map(|text| keccak256(text.as_bytes()))
            .ok_or_else(|| err(format!("unknown type {name:?}")))
    }

    /// `encodeData` of a struct: its type hash, then each field's 32 bytes.
    fn encode_struct(&self, name: &str, value: &Value, depth: usize) -> Result<Vec<u8>, Error> {
        if depth > MAX_DEPTH {
            return Err(err("nested too deeply"));
        }
        let object = value
            .as_object()
            .ok_or_else(|| err(format!("{name}: expected an object")))?;
        let fields = self
            .fields
            .get(name)
            .ok_or_else(|| err(format!("unknown type {name:?}")))?;
        let mut out = Vec::with_capacity(32 * (fields.len() + 1));
        out.extend_from_slice(&self.type_hash(name)?);
        for field in fields {
            let value = object
                .get(&field.name)
                .filter(|v| !v.is_null())
                .ok_or_else(|| err(format!("{name}.{}: missing", field.name)))?;
            out.extend_from_slice(&self.encode_field(
                &field.ty.base,
                &field.ty.dims,
                value,
                depth + 1,
            )?);
        }
        Ok(out)
    }

    /// One field's 32-byte encoding: structs and arrays are hashed.
    fn encode_field(
        &self,
        base: &Base,
        dims: &[Option<u64>],
        value: &Value,
        depth: usize,
    ) -> Result<[u8; 32], Error> {
        if depth > MAX_DEPTH {
            return Err(err("nested too deeply"));
        }
        let Some((outer, inner)) = dims.split_last() else {
            return match base {
                Base::Struct(name) => Ok(keccak256(&self.encode_struct(name, value, depth)?)),
                _ => encode_base(base, value),
            };
        };
        let items = value.as_array().ok_or_else(|| err("expected an array"))?;
        if let Some(count) = outer
            && items.len() as u64 != *count
        {
            return Err(err(format!(
                "array length mismatch; expected length {count}"
            )));
        }
        let mut concatenated = Vec::with_capacity(32 * items.len());
        for item in items {
            concatenated.extend_from_slice(&self.encode_field(base, inner, item, depth + 1)?);
        }
        Ok(keccak256(&concatenated))
    }
}

fn collect(
    name: &str,
    links: &BTreeMap<String, BTreeSet<String>>,
    descendants: &mut BTreeMap<String, BTreeSet<String>>,
    in_progress: &mut BTreeSet<String>,
) -> Result<(), Error> {
    if descendants.contains_key(name) {
        return Ok(());
    }
    if !in_progress.insert(name.to_owned()) {
        return Err(err(format!("circular type reference to {name:?}")));
    }
    let mut all = BTreeSet::new();
    for child in links.get(name).into_iter().flatten() {
        collect(child, links, descendants, in_progress)?;
        all.insert(child.clone());
        if let Some(grandchildren) = descendants.get(child) {
            all.extend(grandchildren.iter().cloned());
        }
    }
    in_progress.remove(name);
    descendants.insert(name.to_owned(), all);
    Ok(())
}

/// A JSON integer within ±(2^53 - 1), or a quantity string.
fn number(value: &Value) -> Result<(bool, U256), Error> {
    match value {
        Value::String(text) => {
            parse_signed(text).ok_or_else(|| err(format!("{text:?} is not a quantity")))
        }
        Value::Number(n) => {
            let integral = if let Some(i) = n.as_i64() {
                Some((i < 0, i.unsigned_abs()))
            } else if let Some(u) = n.as_u64() {
                Some((false, u))
            } else {
                // "1e2" or "5.0": ethers sees the JS number, an integer.
                n.as_f64()
                    .filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER as f64)
                    .map(|f| (f < 0.0, f.abs() as u64))
            };
            match integral {
                Some((negative, magnitude)) if magnitude <= MAX_SAFE_INTEGER => {
                    Ok((negative && magnitude != 0, U256::from_u64(magnitude)))
                }
                _ => Err(err(format!("{n} is not a safe integer"))),
            }
        }
        _ => Err(err("expected a number")),
    }
}

fn encode_base(base: &Base, value: &Value) -> Result<[u8; 32], Error> {
    match base {
        Base::Uint(bits) => {
            let (negative, magnitude) = number(value)?;
            if negative || magnitude > U256::mask(*bits) {
                return Err(err(format!("value out-of-bounds for uint{bits}")));
            }
            Ok(magnitude.to_be_bytes())
        }
        Base::Int(bits) => {
            let (negative, magnitude) = number(value)?;
            // -2^(bits-1) ..= 2^(bits-1) - 1
            let max = U256::mask(bits - 1);
            let limit = if negative {
                max.checked_add(&U256::from_u64(1))
            } else {
                Some(max)
            };
            if limit.is_none_or(|limit| magnitude > limit) {
                return Err(err(format!("value out-of-bounds for int{bits}")));
            }
            Ok(if negative {
                magnitude.wrapping_neg()
            } else {
                magnitude
            }
            .to_be_bytes())
        }
        Base::FixedBytes(width) => {
            let bytes = parse_bytes(
                value.as_str().ok_or_else(|| err("expected hex bytes"))?,
                "bytes",
            )?;
            if bytes.len() != *width {
                return Err(err(format!("invalid length for bytes{width}")));
            }
            let mut out = [0u8; 32];
            out[..*width].copy_from_slice(&bytes);
            Ok(out)
        }
        Base::Bytes => {
            let bytes = parse_bytes(
                value.as_str().ok_or_else(|| err("expected hex bytes"))?,
                "bytes",
            )?;
            Ok(keccak256(&bytes))
        }
        Base::String => Ok(keccak256(
            value
                .as_str()
                .ok_or_else(|| err("expected a string"))?
                .as_bytes(),
        )),
        Base::Address => {
            let address = parse_address(value.as_str().ok_or_else(|| err("expected an address"))?)?;
            let mut out = [0u8; 32];
            out[12..].copy_from_slice(&address);
            Ok(out)
        }
        Base::Bool => match value {
            Value::Bool(flag) => Ok(U256::from_u64(u64::from(*flag)).to_be_bytes()),
            _ => Err(err("bool takes only true or false")),
        },
        Base::Struct(_) => Err(err("struct where a value was expected")),
    }
}

/// ethers' `hashDomain`: the fields present (null ones skipped), in the
/// canonical order.
fn domain_hash(value: &Value) -> Result<[u8; 32], Error> {
    let domain: &Map<String, Value> = value
        .as_object()
        .ok_or_else(|| err("domain: expected an object"))?;
    for (key, value) in domain {
        if !value.is_null() && !DOMAIN_FIELDS.iter().any(|(name, _)| name == key) {
            return Err(err(format!("invalid typed-data domain key: {key:?}")));
        }
    }
    let present: Vec<(&str, &str, &Value)> = DOMAIN_FIELDS
        .iter()
        .filter_map(|(name, ty)| {
            domain
                .get(*name)
                .filter(|v| !v.is_null())
                .map(|v| (*name, *ty, v))
        })
        .collect();
    let type_text = format!(
        "EIP712Domain({})",
        present
            .iter()
            .map(|(name, ty, _)| format!("{ty} {name}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut out = Vec::with_capacity(32 * (present.len() + 1));
    out.extend_from_slice(&keccak256(type_text.as_bytes()));
    for (_, ty, value) in present {
        let base = primitive(ty)?.ok_or_else(|| err("domain type"))?;
        out.extend_from_slice(&encode_base(&base, value)?);
    }
    Ok(keccak256(&out))
}

/// `TypedDataEncoder.hash(domain, types, message)`: the digest
/// `Wallet.signTypedData` signs.
pub fn typed_data_hash(domain: &Value, types: &Value, message: &Value) -> Result<[u8; 32], Error> {
    let types = Types::parse(types)?;
    let domain = domain_hash(domain)?;
    let message = keccak256(&types.encode_struct(&types.primary, message, 0)?);
    let mut data = Vec::with_capacity(66);
    data.extend_from_slice(&[0x19, 0x01]);
    data.extend_from_slice(&domain);
    data.extend_from_slice(&message);
    Ok(keccak256(&data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn split_array_matches_ethers() {
        assert_eq!(split_array("uint8").2, vec![]);
        assert_eq!(split_array("uint8[2][]").2, vec![Some(2), None]);
        assert_eq!(split_array("uint8[02]").1, "[02]");
        assert_eq!(split_array("uint8[a]").0, "uint8[a]");
        assert_eq!(split_array("uint8[").0, "uint8[");
        assert_eq!(split_array("uint8[]x").0, "uint8[]x");
    }

    #[test]
    fn widths() {
        assert_eq!(primitive("uint8").unwrap(), Some(Base::Uint(8)));
        assert_eq!(primitive("int256").unwrap(), Some(Base::Int(256)));
        assert_eq!(primitive("bytes32").unwrap(), Some(Base::FixedBytes(32)));
        for bad in [
            "uint7", "uint0", "uint264", "uint08", "bytes0", "bytes33", "bytes01",
        ] {
            assert!(primitive(bad).is_err(), "{bad}");
        }
        assert_eq!(primitive("uint").unwrap(), None);
        assert_eq!(primitive("Mail").unwrap(), None);
    }

    #[test]
    fn diamond_types_are_linear() {
        // 40 levels of diamonds: 2^40 paths for a path-based walk.
        let mut types = Map::new();
        for level in 0..40 {
            let next = format!("T{}", level + 1);
            types.insert(format!("T{level}"), json!([{ "name": "a", "type": format!("A{level}") }, { "name": "b", "type": format!("B{level}") }]));
            types.insert(format!("A{level}"), json!([{ "name": "x", "type": next }]));
            types.insert(format!("B{level}"), json!([{ "name": "x", "type": next }]));
        }
        types.insert("T40".into(), json!([{ "name": "v", "type": "uint8" }]));
        let types = Value::Object(types);
        assert!(Types::parse(&types).is_ok());
        // Encoding it needs depth > 32.
        assert!(typed_data_hash(&json!({}), &types, &json!({})).is_err());
    }

    #[test]
    fn int_bounds() {
        let ok = |v: Value| encode_base(&Base::Int(8), &v).is_ok();
        assert!(ok(json!(-128)) && ok(json!(127)) && ok(json!("-0x80")));
        assert!(!ok(json!(-129)) && !ok(json!(128)));
        assert_eq!(encode_base(&Base::Int(8), &json!(-1)).unwrap(), [0xff; 32]);
        let min = format!(
            "-{}",
            "57896044618658097711785492504343953926634992332820282019728792003956564819968"
        );
        assert!(encode_base(&Base::Int(256), &json!(min)).is_ok());
    }
}
