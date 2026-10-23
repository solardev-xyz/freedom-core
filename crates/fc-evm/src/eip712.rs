//! EIP-712 hashing with ethers v6 `TypedDataEncoder` semantics, as
//! `Wallet.signTypedData(domain, types, message)` applies them (design 0002).
//!
//! Where ethers is lenient, this is stricter, and every such case is a
//! `deviation` vector:
//! - `bool` takes only JSON booleans. ethers encodes any truthy value as true
//!   (including `"false"` and `"0"`), and a missing bool field as false.
//! - Quantity strings are `[-]digits` or `[-]0x hex` (see `parse_signed`).
//! - Type and field names are identifiers, so `encodeType` strings can't be
//!   made ambiguous by names containing `(`, `,` or spaces; and a type may
//!   not be named like a primitive (`bool`, `uint256`, `uint7`), which ethers
//!   would encode with the primitive's encoder.
//! - A struct value must be a JSON object, even for a struct with no fields
//!   (ethers then reads nothing, so it accepts null, a string or no value).
//! - Limits: 256 types, 256 fields per type, 1024 fields in total, names of
//!   at most 256 characters, nesting depth 32, 32 array dimensions per type,
//!   1 MiB of type-hash text, 100,000 values and 32 MiB hashed while
//!   encoding. ethers
//!   has none, and its subtype walk is exponential on diamond-shaped types.
//!   Type hashes are computed once per type, so the work is bounded by the
//!   input size and these limits.
//! - A type named `EIP712Domain` is refused, as ethers' `getPayload` refuses
//!   it: the view adds that type itself (#88).
//!
//! The pass that hashes also writes the view of what is signed (design 0002,
//! "What the user is shown", #88): ethers' `getPayload(domain, types,
//! message)`, as compact JSON text, measured while it is written, with the
//! reports `ignored`, `named_type` and `chain`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::{
    Error, U256, keccak256, parse_address, parse_bytes, parse_signed, quoted, quoted_list,
    shortened, to_hex,
};

const MAX_TYPES: usize = 256;
const MAX_FIELDS: usize = 256;
const MAX_TOTAL_FIELDS: usize = 1024;
const MAX_DEPTH: usize = 32;
const MAX_DIMENSIONS: usize = 32;
/// `encodeType` text hashed across all type hashes: each struct's own text,
/// counted once more for every struct whose type hash includes it.
const MAX_TYPE_TEXT: usize = 1 << 20;
/// Bytes hashed while encoding the message. A 1 MiB frame can drive at most
/// about 22 MiB (32 bytes per value plus array concatenations), so this
/// refuses nothing a frame can carry and still caps the work.
const MAX_ENCODE_BYTES: usize = 32 << 20;
/// Values encoded (fields, array elements, structs): it bounds the time a
/// request can hold the core's event loop (design 0002, "Limits").
const MAX_VALUES: usize = 100_000;
const MAX_NAME: usize = 256;
/// The largest integer a JS number holds exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const DOMAIN_TYPE: &str = "EIP712Domain";
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
    if name.len() > MAX_NAME {
        return false;
    }
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
            .map_err(|_| err(format!("invalid width in {}", quoted(base))))?;
        if width == 0 || width > max || !width.is_multiple_of(step) || digits != width.to_string() {
            return Err(err(format!("invalid width in {}", quoted(base))));
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
    /// The type names in the order the request's object gives them, as
    /// `getPayload` lists them.
    order: Vec<String>,
    primary: String,
    /// keccak256 of each reachable struct's `encodeType` with its sorted
    /// subtypes appended, computed once.
    type_hashes: BTreeMap<String, [u8; 32]>,
}

/// Work done so far while encoding: bytes hashed and values visited.
#[derive(Default)]
struct Budget {
    bytes: usize,
    values: usize,
}

impl Budget {
    fn hash(&mut self, data: &[u8]) -> Result<[u8; 32], Error> {
        self.bytes += data.len();
        if self.bytes > MAX_ENCODE_BYTES {
            return Err(err("message too large to hash"));
        }
        Ok(keccak256(data))
    }

    fn visit(&mut self) -> Result<(), Error> {
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err(err("message has too many values"));
        }
        Ok(())
    }
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
            if name == DOMAIN_TYPE {
                return Err(err("types must not contain EIP712Domain"));
            }
            if !is_identifier(name) {
                return Err(err(format!(
                    "type name {} is not an identifier",
                    quoted(name)
                )));
            }
            if !matches!(primitive(name), Ok(None)) {
                return Err(err(format!(
                    "type name {} is a primitive type",
                    quoted(name)
                )));
            }
        }
        let mut fields = BTreeMap::new();
        let mut parents: BTreeMap<&str, usize> = object.keys().map(|k| (k.as_str(), 0)).collect();
        let mut links: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut total_fields = 0usize;
        for (name, list) in object {
            let list = list
                .as_array()
                .ok_or_else(|| err(format!("{}: expected a field list", shortened(name))))?;
            total_fields += list.len();
            if list.len() > MAX_FIELDS || total_fields > MAX_TOTAL_FIELDS {
                return Err(err(format!("{}: too many fields", shortened(name))));
            }
            let mut seen = BTreeSet::new();
            let mut parsed = Vec::with_capacity(list.len());
            let children = links.entry(name.clone()).or_default();
            for field in list {
                let field_name = field.get("name").and_then(Value::as_str);
                let field_type = field.get("type").and_then(Value::as_str);
                let (Some(field_name), Some(field_type)) = (field_name, field_type) else {
                    return Err(err(format!(
                        "{}: fields need a string name and type",
                        shortened(name)
                    )));
                };
                if !is_identifier(field_name) {
                    return Err(err(format!(
                        "field name {} is not an identifier",
                        quoted(field_name)
                    )));
                }
                if !seen.insert(field_name) {
                    return Err(err(format!(
                        "duplicate field {} in {}",
                        quoted(field_name),
                        quoted(name)
                    )));
                }
                let (raw_base, suffix, dims) = split_array(field_type);
                if dims.len() > MAX_DIMENSIONS {
                    return Err(err(format!(
                        "{}.{}: too many array dimensions",
                        shortened(name),
                        shortened(field_name)
                    )));
                }
                let base_text = match raw_base {
                    "int" if !object.contains_key("int") => "int256",
                    "uint" if !object.contains_key("uint") => "uint256",
                    other => other,
                };
                if base_text == name {
                    return Err(err(format!("circular type reference to {}", quoted(name))));
                }
                let base = match primitive(base_text)? {
                    Some(base) => base,
                    None => {
                        let count = parents
                            .get_mut(base_text)
                            .ok_or_else(|| err(format!("unknown type {}", quoted(base_text))))?;
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
                    "ambiguous primary types or unused types: {}",
                    quoted_list(&roots)
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
        // Bound the type-hash text before building it.
        let own: BTreeMap<&str, usize> = descendants
            .keys()
            .map(|name| (name.as_str(), encode_type(name).len()))
            .collect();
        let mut total = 0usize;
        for (name, subtypes) in &descendants {
            total += own[name.as_str()] + subtypes.iter().map(|s| own[s.as_str()]).sum::<usize>();
            if total > MAX_TYPE_TEXT {
                return Err(err("types: too much type-hash text"));
            }
        }
        let mut type_hashes = BTreeMap::new();
        for (name, subtypes) in &descendants {
            // BTreeSet iterates in byte order: JS sort order for ASCII names.
            let mut text = encode_type(name);
            for subtype in subtypes {
                text.push_str(&encode_type(subtype));
            }
            type_hashes.insert(name.clone(), keccak256(text.as_bytes()));
        }
        Ok(Types {
            fields,
            order: object.keys().cloned().collect(),
            primary,
            type_hashes,
        })
    }

    fn type_hash(&self, name: &str) -> Result<[u8; 32], Error> {
        self.type_hashes
            .get(name)
            .copied()
            .ok_or_else(|| err(format!("unknown type {}", quoted(name))))
    }

    /// `encodeData` of a struct: its type hash, then each field's 32 bytes.
    /// The view gets the declared fields, in order, normalized.
    fn encode_struct(
        &self,
        name: &str,
        value: &Value,
        depth: usize,
        budget: &mut Budget,
        view: &mut ViewText,
    ) -> Result<Vec<u8>, Error> {
        if depth > MAX_DEPTH {
            return Err(err("nested too deeply"));
        }
        let object = value
            .as_object()
            .ok_or_else(|| err(format!("{}: expected an object", shortened(name))))?;
        let fields = self
            .fields
            .get(name)
            .ok_or_else(|| err(format!("unknown type {}", quoted(name))))?;
        let mut out = Vec::with_capacity(32 * (fields.len() + 1));
        out.extend_from_slice(&self.type_hash(name)?);
        view.raw("{")?;
        for (index, field) in fields.iter().enumerate() {
            if index > 0 {
                view.raw(",")?;
            }
            view.string(&field.name)?;
            view.raw(":")?;
            let value = object
                .get(&field.name)
                .filter(|v| !v.is_null())
                .ok_or_else(|| {
                    err(format!(
                        "{}.{}: missing",
                        shortened(name),
                        shortened(&field.name)
                    ))
                })?;
            out.extend_from_slice(&self.encode_field(
                &field.ty.base,
                &field.ty.dims,
                value,
                depth + 1,
                budget,
                view,
            )?);
        }
        view.raw("}")?;
        Ok(out)
    }

    /// One field's 32-byte encoding: structs and arrays are hashed.
    fn encode_field(
        &self,
        base: &Base,
        dims: &[Option<u64>],
        value: &Value,
        depth: usize,
        budget: &mut Budget,
        view: &mut ViewText,
    ) -> Result<[u8; 32], Error> {
        if depth > MAX_DEPTH {
            return Err(err("nested too deeply"));
        }
        budget.visit()?;
        let Some((outer, inner)) = dims.split_last() else {
            return match base {
                Base::Struct(name) => {
                    let encoded = self.encode_struct(name, value, depth, budget, view)?;
                    budget.hash(&encoded)
                }
                _ => encode_base(base, value, budget, view),
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
        view.raw("[")?;
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                view.raw(",")?;
            }
            concatenated.extend_from_slice(&self.encode_field(
                base,
                inner,
                item,
                depth + 1,
                budget,
                view,
            )?);
        }
        view.raw("]")?;
        budget.hash(&concatenated)
    }

    /// The view's `types`: every type as the request lists them, with the
    /// alias-resolved field types `encodeType` uses, then `EIP712Domain`
    /// for the domain fields present.
    fn write_types(&self, view: &mut ViewText, domain: &[DomainField<'_>]) -> Result<(), Error> {
        view.raw("{")?;
        for name in &self.order {
            view.string(name)?;
            view.raw(":")?;
            let fields = self.fields.get(name).map(Vec::as_slice).unwrap_or_default();
            write_field_list(
                view,
                fields
                    .iter()
                    .map(|field| (field.name.as_str(), field.type_text.as_str())),
            )?;
            view.raw(",")?;
        }
        view.string(DOMAIN_TYPE)?;
        view.raw(":")?;
        write_field_list(view, domain.iter().map(|field| (field.name, field.ty)))?;
        view.raw("}")
    }
}

/// `[{"name":…,"type":…},…]`.
fn write_field_list<'a>(
    view: &mut ViewText,
    fields: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<(), Error> {
    view.raw("[")?;
    for (index, (name, ty)) in fields.enumerate() {
        if index > 0 {
            view.raw(",")?;
        }
        view.raw("{\"name\":")?;
        view.string(name)?;
        view.raw(",\"type\":")?;
        view.string(ty)?;
        view.raw("}")?;
    }
    view.raw("]")
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
        return Err(err(format!("circular type reference to {}", quoted(name))));
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
            parse_signed(text).ok_or_else(|| err(format!("{} is not a quantity", quoted(text))))
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

/// One value's 32 bytes; the view gets it as `getPayload` normalizes it:
/// integers as decimal strings, bytes and addresses as lowercase hex.
fn encode_base(
    base: &Base,
    value: &Value,
    budget: &mut Budget,
    view: &mut ViewText,
) -> Result<[u8; 32], Error> {
    match base {
        Base::Uint(bits) => {
            let (negative, magnitude) = number(value)?;
            if negative || magnitude > U256::mask(*bits) {
                return Err(err(format!("value out-of-bounds for uint{bits}")));
            }
            view.integer(false, &magnitude)?;
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
            view.integer(negative, &magnitude)?;
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
            view.hex(&bytes)?;
            let mut out = [0u8; 32];
            out[..*width].copy_from_slice(&bytes);
            Ok(out)
        }
        Base::Bytes => {
            let bytes = parse_bytes(
                value.as_str().ok_or_else(|| err("expected hex bytes"))?,
                "bytes",
            )?;
            view.hex(&bytes)?;
            budget.hash(&bytes)
        }
        Base::String => {
            let text = value.as_str().ok_or_else(|| err("expected a string"))?;
            view.string(text)?;
            budget.hash(text.as_bytes())
        }
        Base::Address => {
            let address = parse_address(value.as_str().ok_or_else(|| err("expected an address"))?)?;
            view.hex(&address)?;
            let mut out = [0u8; 32];
            out[12..].copy_from_slice(&address);
            Ok(out)
        }
        Base::Bool => match value {
            Value::Bool(flag) => {
                view.raw(if *flag { "true" } else { "false" })?;
                Ok(U256::from_u64(u64::from(*flag)).to_be_bytes())
            }
            _ => Err(err("bool takes only true or false")),
        },
        Base::Struct(_) => Err(err("struct where a value was expected")),
    }
}

/// A domain field present (not null), in the canonical order.
struct DomainField<'a> {
    name: &'static str,
    ty: &'static str,
    value: &'a Value,
}

/// The domain's fields present (null ones skipped, even unknown ones), in
/// the canonical order; any other key is an error, as in ethers.
fn domain_fields(value: &Value) -> Result<Vec<DomainField<'_>>, Error> {
    let domain: &Map<String, Value> = value
        .as_object()
        .ok_or_else(|| err("domain: expected an object"))?;
    for (key, value) in domain {
        if !value.is_null() && !DOMAIN_FIELDS.iter().any(|(name, _)| name == key) {
            return Err(err(format!(
                "invalid typed-data domain key: {}",
                quoted(key)
            )));
        }
    }
    Ok(DOMAIN_FIELDS
        .iter()
        .filter_map(|(name, ty)| {
            domain
                .get(*name)
                .filter(|v| !v.is_null())
                .map(|value| DomainField { name, ty, value })
        })
        .collect())
}

/// ethers' `hashDomain` over the fields present.
fn domain_hash(present: &[DomainField<'_>]) -> Result<[u8; 32], Error> {
    let type_text = format!(
        "{DOMAIN_TYPE}({})",
        present
            .iter()
            .map(|field| format!("{} {}", field.ty, field.name))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut out = Vec::with_capacity(32 * (present.len() + 1));
    out.extend_from_slice(&keccak256(type_text.as_bytes()));
    for field in present {
        let base = primitive(field.ty)?.ok_or_else(|| err("domain type"))?;
        out.extend_from_slice(&encode_base(
            &base,
            field.value,
            &mut Budget::default(),
            &mut ViewText::none(),
        )?);
    }
    Ok(keccak256(&out))
}

/// The view's `domain`, as `getPayload` gives it: the fields present, in
/// the canonical order; `chainId` as a hex quantity (`"0x1"`: pinned ethers
/// tests `Number.isSafeInteger` on a `BigInt`, which never holds), the
/// address and salt as lowercase hex. Returns the domain's chain id.
fn write_domain(view: &mut ViewText, present: &[DomainField<'_>]) -> Result<Option<U256>, Error> {
    let mut chain = None;
    view.raw("{")?;
    for (index, field) in present.iter().enumerate() {
        if index > 0 {
            view.raw(",")?;
        }
        view.string(field.name)?;
        view.raw(":")?;
        if field.name == "chainId" {
            let (_, id) = number(field.value)?;
            view.quantity(&id)?;
            chain = Some(id);
        } else {
            let base = primitive(field.ty)?.ok_or_else(|| err("domain type"))?;
            encode_base(&base, field.value, &mut Budget::default(), view)?;
        }
    }
    view.raw("}")?;
    Ok(chain)
}

/// The view's JSON text, written while the data is hashed: refused past its
/// longest length, so no more than that is ever held. A disabled view
/// writes nothing.
struct ViewText {
    out: Option<String>,
    max: usize,
}

impl ViewText {
    fn none() -> Self {
        ViewText { out: None, max: 0 }
    }

    fn new(max: usize) -> Self {
        ViewText {
            out: Some(String::new()),
            max,
        }
    }

    fn raw(&mut self, text: &str) -> Result<(), Error> {
        if let Some(out) = &mut self.out {
            if out.len().saturating_add(text.len()) > self.max {
                return Err(Error::ViewTooLarge);
            }
            out.push_str(text);
        }
        Ok(())
    }

    /// A JSON string, escaped as serde_json writes it.
    fn string(&mut self, text: &str) -> Result<(), Error> {
        if self.out.is_none() {
            return Ok(());
        }
        // Each character escapes to at most 6 bytes: refuse a string that
        // can't fit before escaping it.
        if let Some(out) = &self.out
            && out.len().saturating_add(text.len()) > self.max
        {
            return Err(Error::ViewTooLarge);
        }
        let escaped =
            serde_json::to_string(text).map_err(|_| err("a string the view can't hold"))?;
        self.raw(&escaped)
    }

    fn hex(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.out.is_none() {
            return Ok(());
        }
        if let Some(out) = &self.out
            && out.len().saturating_add(2 * bytes.len()) > self.max
        {
            return Err(Error::ViewTooLarge);
        }
        self.raw("\"")?;
        self.raw(&to_hex(bytes))?;
        self.raw("\"")
    }

    /// An integer as a decimal string, `-` first when negative.
    fn integer(&mut self, negative: bool, magnitude: &U256) -> Result<(), Error> {
        if self.out.is_none() {
            return Ok(());
        }
        self.raw(if negative { "\"-" } else { "\"" })?;
        self.raw(&magnitude.to_decimal())?;
        self.raw("\"")
    }

    /// A hex quantity string, as ethers' `toQuantity`: `"0x0"`, `"0x1f"`.
    fn quantity(&mut self, value: &U256) -> Result<(), Error> {
        if self.out.is_none() {
            return Ok(());
        }
        let hex = to_hex(&value.to_minimal_be());
        let digits = hex[2..].trim_start_matches('0');
        self.raw("\"0x")?;
        self.raw(if digits.is_empty() { "0" } else { digits })?;
        self.raw("\"")
    }

    fn finish(self) -> String {
        self.out.unwrap_or_default()
    }
}

/// What a caller passes beside the typed data for its view (#88). Neither
/// changes what is signed.
#[derive(Debug, Clone, Copy)]
pub struct ViewRequest<'a> {
    /// The `primary_type` the requester named, any JSON value; `None` when
    /// it named none.
    pub primary_type: Option<&'a Value>,
    /// The chain the requester is on; `None` when not given.
    pub chain_id: Option<U256>,
    /// The longest view text accepted, in bytes: past it the request is
    /// refused (`view-size`).
    pub max_len: usize,
}

/// A digest and the view of what it signs (#88).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedDataView {
    /// `TypedDataEncoder.hash(domain, types, message)`.
    pub hash: [u8; 32],
    /// Compact JSON text: `{"types":…,"domain":…,"primary_type":…,
    /// "message":…,"ignored":[…],"named_type":…,"chain":…}`. The first four
    /// are ethers' `getPayload`, with its `primaryType` as `primary_type`:
    /// - `ignored`: the message's top-level keys the primary type doesn't
    ///   declare, which are sent but not signed, sorted;
    /// - `named_type`: `match` when `primary_type` is a string equal to the
    ///   inferred root, `mismatch` for any other value, `unknown` without
    ///   one;
    /// - `chain`: `absent` without a domain `chainId` (or with a null one),
    ///   else `match` or `mismatch` against `chain_id`, `unknown` without
    ///   one.
    pub view: String,
}

/// The digest, with the view of exactly what is signed written in the same
/// pass (design 0002, #88). Refuses typed data whose view would be longer
/// than `request.max_len` ([`Error::ViewTooLarge`]), measured while it is
/// written.
pub fn typed_data_view(
    domain: &Value,
    types: &Value,
    message: &Value,
    request: &ViewRequest<'_>,
) -> Result<TypedDataView, Error> {
    let mut view = ViewText::new(request.max_len);
    let hash = encode(domain, types, message, &mut view, Some(request))?;
    Ok(TypedDataView {
        hash,
        view: view.finish(),
    })
}

/// `TypedDataEncoder.hash(domain, types, message)`: the digest
/// `Wallet.signTypedData` signs.
pub fn typed_data_hash(domain: &Value, types: &Value, message: &Value) -> Result<[u8; 32], Error> {
    encode(domain, types, message, &mut ViewText::none(), None)
}

fn encode(
    domain: &Value,
    types: &Value,
    message: &Value,
    view: &mut ViewText,
    request: Option<&ViewRequest<'_>>,
) -> Result<[u8; 32], Error> {
    let types = Types::parse(types)?;
    let present = domain_fields(domain)?;
    let domain = domain_hash(&present)?;
    view.raw("{\"types\":")?;
    types.write_types(view, &present)?;
    view.raw(",\"domain\":")?;
    let chain = write_domain(view, &present)?;
    view.raw(",\"primary_type\":")?;
    view.string(&types.primary)?;
    view.raw(",\"message\":")?;
    let mut budget = Budget::default();
    let encoded = types.encode_struct(&types.primary, message, 0, &mut budget, view)?;
    let message_hash = budget.hash(&encoded)?;
    if let Some(request) = request {
        write_reports(view, &types, message, chain, request)?;
    }
    view.raw("}")?;
    let mut data = Vec::with_capacity(66);
    data.extend_from_slice(&[0x19, 0x01]);
    data.extend_from_slice(&domain);
    data.extend_from_slice(&message_hash);
    Ok(keccak256(&data))
}

/// `ignored`, `named_type` and `chain` (#88). None changes what is signed.
fn write_reports(
    view: &mut ViewText,
    types: &Types,
    message: &Value,
    chain: Option<U256>,
    request: &ViewRequest<'_>,
) -> Result<(), Error> {
    let declared: BTreeSet<&str> = types
        .fields
        .get(&types.primary)
        .into_iter()
        .flatten()
        .map(|field| field.name.as_str())
        .collect();
    let ignored: BTreeSet<&str> = message
        .as_object()
        .into_iter()
        .flat_map(Map::keys)
        .map(String::as_str)
        .filter(|key| !declared.contains(key))
        .collect();
    view.raw(",\"ignored\":[")?;
    for (index, key) in ignored.into_iter().enumerate() {
        if index > 0 {
            view.raw(",")?;
        }
        view.string(key)?;
    }
    view.raw("],\"named_type\":")?;
    // Only a string can match: true, false and null are valid struct names,
    // so a non-string's JSON text could name the root.
    view.raw(match request.primary_type {
        None => "\"unknown\"",
        Some(Value::String(named)) if *named == types.primary => "\"match\"",
        Some(_) => "\"mismatch\"",
    })?;
    view.raw(",\"chain\":")?;
    view.raw(match (chain, request.chain_id) {
        (None, _) => "\"absent\"",
        (Some(_), None) => "\"unknown\"",
        (Some(domain), Some(active)) if domain == active => "\"match\"",
        (Some(_), Some(_)) => "\"mismatch\"",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Instant;

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
        for name in [
            "bool", "uint256", "uint7", "bytes", "bytes32", "address", "string", "int8",
        ] {
            let types = json!({ name: [{ "name": "v", "type": "uint8" }] });
            assert!(Types::parse(&types).is_err(), "{name}");
        }
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
    fn worst_case_types_within_the_limits_are_fast() {
        // 256 types in a chain, the 1024 fields spread over them, long
        // names: every type hash includes all its descendants.
        let mut types = Map::new();
        let long = |prefix: &str, i: usize| format!("{prefix}{i:0>4}{}", "x".repeat(40));
        for i in 0..256 {
            let mut fields = Vec::new();
            for j in 0..3 {
                fields.push(json!({ "name": long("f", j), "type": "uint256" }));
            }
            if i < 255 {
                fields.push(json!({ "name": "next", "type": long("T", i + 1) }));
            }
            types.insert(long("T", i), Value::Array(fields));
        }
        let started = std::time::Instant::now();
        let result = typed_data_hash(&json!({}), &Value::Object(types), &json!({}));
        // Rejected by the text budget or the depth limit, but quickly.
        assert!(result.is_err());
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
    }

    /// Types and a message, under an empty domain.
    type Input = (Value, Value);

    /// The hash, with the view written in the same pass: the timings below
    /// cover both (#88).
    fn hash((types, message): &Input) -> Result<[u8; 32], Error> {
        typed_data_view(&json!({}), types, message, &unbounded()).map(|hashed| hashed.hash)
    }

    fn unbounded() -> ViewRequest<'static> {
        ViewRequest {
            primary_type: None,
            chain_id: None,
            max_len: usize::MAX,
        }
    }

    /// The view is refused exactly past its longest length (#88,
    /// `view-size`): measured as written, a view of that length passes and
    /// one byte more is refused, whatever part of the view crosses it.
    #[test]
    fn the_view_is_refused_exactly_past_its_length() {
        let types = json!({ "M": [
            { "name": "s", "type": "string" },
            { "name": "b", "type": "bytes" },
            { "name": "n", "type": "int256[]" },
        ] });
        let message = json!({ "s": "q\"\u{1}é", "b": "0xABCD", "n": [-5, "0x10"], "extra": 1 });
        let domain = json!({ "name": "N", "chainId": 31 });
        let full = typed_data_view(&domain, &types, &message, &unbounded()).unwrap();
        let len = full.view.len();
        let view: Value = serde_json::from_str(&full.view).unwrap();
        assert_eq!(
            view["message"],
            json!({ "s": "q\"\u{1}é", "b": "0xabcd", "n": ["-5", "16"] })
        );
        assert_eq!(view["domain"], json!({ "name": "N", "chainId": "0x1f" }));
        assert_eq!(view["ignored"], json!(["extra"]));
        // serde_json's own escaping, byte for byte.
        assert!(
            full.view
                .contains(&serde_json::to_string("q\"\u{1}é").unwrap())
        );
        for max_len in [len, len + 1, usize::MAX] {
            let request = ViewRequest {
                max_len,
                ..unbounded()
            };
            assert_eq!(
                typed_data_view(&domain, &types, &message, &request),
                Ok(full.clone())
            );
        }
        // Every shorter bound is refused, wherever the view crosses it.
        for max_len in 0..len {
            let request = ViewRequest {
                max_len,
                ..unbounded()
            };
            assert_eq!(
                typed_data_view(&domain, &types, &message, &request),
                Err(Error::ViewTooLarge),
                "{max_len}"
            );
        }
        // The hash alone has no view and no bound.
        assert_eq!(typed_data_hash(&domain, &types, &message), Ok(full.hash));
    }

    /// A long string is refused before it is escaped: no more than the
    /// bound is ever held.
    #[test]
    fn a_long_string_is_refused_before_it_is_copied() {
        let types = json!({ "M": [{ "name": "s", "type": "string" }] });
        let message = json!({ "s": "x".repeat(1 << 20) });
        let request = ViewRequest {
            max_len: 1 << 10,
            ..unbounded()
        };
        assert_eq!(
            typed_data_view(&json!({}), &types, &message, &request),
            Err(Error::ViewTooLarge)
        );
    }

    /// ethers' getPayload refuses a type named EIP712Domain, so a view of
    /// such data can't be ethers': refused, like every other ill-formed
    /// type set (deviation `domain-type`).
    #[test]
    fn a_type_named_eip712domain_is_refused() {
        let types = json!({
            "M": [{ "name": "d", "type": "EIP712Domain" }],
            "EIP712Domain": [{ "name": "name", "type": "string" }],
        });
        let message = json!({ "d": { "name": "x" } });
        assert!(typed_data_hash(&json!({}), &types, &message).is_err());
        assert!(typed_data_view(&json!({}), &types, &message, &unbounded()).is_err());
    }

    /// The reports compare and never change what is signed (#88).
    #[test]
    fn reports_change_nothing_signed() {
        let types = json!({ "true": [{ "name": "v", "type": "uint8" }] });
        let message = json!({ "v": 1 });
        let domain = json!({ "chainId": "0x64" });
        let reference = typed_data_hash(&domain, &types, &message).unwrap();
        let report = |primary_type: Option<&Value>, chain_id: Option<u64>| {
            let request = ViewRequest {
                primary_type,
                chain_id: chain_id.map(U256::from_u64),
                max_len: usize::MAX,
            };
            let hashed = typed_data_view(&domain, &types, &message, &request).unwrap();
            assert_eq!(hashed.hash, reference);
            let view: Value = serde_json::from_str(&hashed.view).unwrap();
            (view["named_type"].clone(), view["chain"].clone())
        };
        assert_eq!(
            report(Some(&json!("true")), Some(100)),
            (json!("match"), json!("match"))
        );
        assert_eq!(
            report(Some(&json!(true)), Some(1)),
            (json!("mismatch"), json!("mismatch"))
        );
        assert_eq!(
            report(Some(&Value::Null), None),
            (json!("mismatch"), json!("unknown"))
        );
        assert_eq!(report(None, None), (json!("unknown"), json!("unknown")));
    }

    /// Asserts that hashing `inputs` takes about as long as hashing
    /// `baseline`, the same amount of work while the work is linear: less
    /// than 5 times as long. Each check below is built so that the
    /// regression it guards against takes far longer than that.
    ///
    /// There is no wall-clock bound. Each try times the two back to back,
    /// so they share the machine's speed and load, each side repeated to
    /// take about 100 ms, many scheduler slices; one try in five must pass.
    fn assert_as_long_as(inputs: &[Input], baseline: &[Input]) {
        let time = |inputs: &[Input], times: u32| {
            let started = Instant::now();
            for _ in 0..times {
                for input in inputs {
                    let result = hash(input);
                    assert!(result.is_ok(), "{result:?}");
                }
            }
            started.elapsed().as_secs_f64()
        };
        // Once each to warm up, and to see how long the inputs take.
        let once = time(inputs, 1);
        time(baseline, 1);
        let times = ((0.1 / once).ceil() as u32).clamp(1, 100);
        let mut ratios = Vec::new();
        for _ in 0..5 {
            let ratio = time(inputs, times) / time(baseline, times);
            if ratio < 5.0 {
                return;
            }
            ratios.push(ratio);
        }
        panic!("{ratios:.1?} times as long as the baseline");
    }

    /// The review's case at the name limit (18-M1): an array of `count`
    /// empty instances of a type with a 256-character name.
    fn empty_instances(count: usize) -> Input {
        let name = format!("E{}", "x".repeat(MAX_NAME - 1));
        let mut types = Map::new();
        types.insert(
            "M".into(),
            json!([{ "name": "items", "type": format!("{name}[]") }]),
        );
        types.insert(name, json!([]));
        let message = json!({ "items": vec![json!({}); count] });
        (Value::Object(types), message)
    }

    /// `count` instances of `E`, each holding an empty array of `W`, a
    /// struct of `width` fields with 256-character names. `E`'s type hash
    /// covers all of `W`'s text, while each instance is two values.
    fn instances(count: usize, width: usize) -> Input {
        let fields: Vec<Value> = (0..width)
            .map(|i| {
                let name = format!("f{i:03}{}", "x".repeat(MAX_NAME - 4));
                json!({ "name": name, "type": "uint8" })
            })
            .collect();
        let types = json!({
            "M": [{ "name": "items", "type": "E[]" }],
            "E": [{ "name": "w", "type": "W[]" }],
            "W": fields,
        });
        (types, json!({ "items": vec![json!({ "w": [] }); count] }))
    }

    /// Four types of `width` string fields under the primary type, each
    /// value 850 bytes.
    fn strings(width: usize) -> Input {
        let mut types = Map::new();
        let mut message = Map::new();
        let mut root = Vec::new();
        for t in 0..4 {
            let fields: Vec<Value> = (0..width)
                .map(|f| json!({ "name": format!("f{f}"), "type": "string" }))
                .collect();
            types.insert(format!("T{t}"), Value::Array(fields));
            root.push(json!({ "name": format!("t{t}"), "type": format!("T{t}") }));
            let value: Map<String, Value> = (0..width)
                .map(|f| (format!("f{f}"), json!("y".repeat(850))))
                .collect();
            message.insert(format!("t{t}"), Value::Object(value));
        }
        types.insert("M".into(), Value::Array(root));
        (Value::Object(types), Value::Object(message))
    }

    #[test]
    fn accepted_inputs_near_the_limits_take_linear_time() {
        // The review's case: with the array field, one value per instance
        // reaches the value cap, which is accepted; one more is refused.
        let at_cap = empty_instances(MAX_VALUES - 1);
        let result = hash(&at_cap);
        assert!(result.is_ok(), "{result:?}");
        assert!(hash(&empty_instances(MAX_VALUES)).is_err());
        // Linear in the instances: as long as 30 arrays of a thirtieth as
        // many each.
        let thirtieths: Vec<Input> = (0..30)
            .map(|_| empty_instances((MAX_VALUES - 1) / 30))
            .collect();
        assert_as_long_as(&[at_cap], &thirtieths);

        // A type's hash is computed once, not for every instance (18-M1):
        // instances of a type whose hash covers 66 KB of text (in a subtype
        // they leave empty) take as long as those of one covering 270 bytes.
        assert_as_long_as(&[instances(10_000, 250)], &[instances(10_000, 1)]);

        // 1024 fields in total (4 types of 255, and the root's 4), ~870 KB
        // of string values: accepted, and linear in the fields.
        let result = hash(&strings(255));
        assert!(result.is_ok(), "{result:?}");
        let tenths: Vec<Input> = (0..10).map(|_| strings(25)).collect();
        assert_as_long_as(&[strings(250)], &tenths);
    }

    #[test]
    fn the_encode_budget_holds() {
        // 40 MiB of string data (far more than one frame carries): refused.
        let types = json!({ "M": [{ "name": "v", "type": "string[]" }] });
        let items = vec![json!("z".repeat(1 << 16)); 640];
        assert!(typed_data_hash(&json!({}), &types, &json!({ "v": items })).is_err());
    }

    #[test]
    fn limits() {
        let field = |t: &str| json!([{ "name": "v", "type": t }]);
        let dims = format!("uint8{}", "[]".repeat(33));
        assert!(Types::parse(&json!({ "M": field(&dims) })).is_err());
        assert!(Types::parse(&json!({ "M": field(&format!("uint8{}", "[]".repeat(32))) })).is_ok());
        let many: Vec<Value> = (0..257)
            .map(|i| json!({ "name": format!("f{i}"), "type": "uint8" }))
            .collect();
        assert!(Types::parse(&json!({ "M": many })).is_err());
        assert!(!is_identifier(&"n".repeat(257)));
        assert!(is_identifier(&"n".repeat(256)));
    }

    /// The decimal digits of 5^n.
    fn five_to(n: u32) -> String {
        let mut digits = vec![1u8]; // little-endian
        for _ in 0..n {
            let mut carry = 0u8;
            for digit in &mut digits {
                let product = *digit * 5 + carry;
                *digit = product % 10;
                carry = product / 10;
            }
            if carry > 0 {
                digits.push(carry);
            }
        }
        digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
    }

    /// A JSON number is read as `JSON.parse` reads it, correctly rounded to
    /// the nearest double, ties to even, before the integer rules apply
    /// (#87): `parse_json` rereads each double from its spelling. serde_json
    /// rounds approximately, and its `float_roundtrip` parser still
    /// misrounds padded spellings and halfway subnormals, so the core could
    /// sign another integer than the one ethers signs and the approval UI
    /// shows, or refuse one ethers accepts.
    #[test]
    fn numbers_are_read_as_json_parse_reads_them() {
        let hash = |kind: &str, number: &str| {
            let message = crate::parse_json(&format!(r#"{{"v":{number}}}"#)).unwrap();
            let types = json!({ "M": [{ "name": "v", "type": kind }] });
            typed_data_hash(&json!({ "name": "N" }), &types, &message)
        };
        let uint = |number: &str| hash("uint256", number);
        let int = |number: &str| hash("int256", number);
        // 2^52 + 0.5 is a tie between 2^52 and 2^52 + 1: JSON.parse gives
        // 2^52, which ethers signs.
        assert_eq!(
            uint("4503599627370496.5").unwrap(),
            uint("4503599627370496").unwrap()
        );
        assert_eq!(
            uint("45035996273704965e-1").unwrap(),
            uint("4503599627370496").unwrap()
        );
        // The same tie with its integer significand padded by 752 zeros and
        // a compensating exponent, which float_roundtrip reads as 2^52 + 1;
        // and just above the tie, which rounds up.
        let zeros = "0".repeat(752);
        let padded = format!("45035996273704965{zeros}e-753");
        assert_eq!(uint(&padded).unwrap(), uint("4503599627370496").unwrap());
        assert_eq!(
            int(&format!("-{padded}")).unwrap(),
            int("-4503599627370496").unwrap()
        );
        let above = format!("45035996273704965{}1e-754", "0".repeat(752));
        assert_eq!(uint(&above).unwrap(), uint("4503599627370497").unwrap());
        // 2^52 + 1.5 is a tie too, and rounds up to the even 2^52 + 2.
        assert_eq!(
            uint("4503599627370497.5").unwrap(),
            uint("4503599627370498").unwrap()
        );
        // (2^53 - 1) + 0.5 rounds to 2^53, which is no safe integer: an
        // error, as in ethers.
        assert!(uint("9007199254740991.5").is_err());
        assert!(uint("9007199254740991").is_ok());
        // 2^-1075, halfway between 0 and the smallest subnormal, is 0 (ties
        // to even), which ethers accepts; float_roundtrip reads the
        // subnormal and refuses it. Just above halfway is the subnormal: no
        // integer, refused by both.
        let half = format!("{}{}e-1092", five_to(1075), "0".repeat(17));
        assert_eq!(uint(&half).unwrap(), uint("0").unwrap());
        assert_eq!(int(&format!("-{half}")).unwrap(), int("0").unwrap());
        let over = format!("{}{}1e-1093", five_to(1075), "0".repeat(17));
        assert!(uint(&over).is_err());
        // Exponents std doesn't read whole (from 655,360 on, it stops at
        // 0x10000) are compensated exactly: 1 is signed as 1, not 0 (a
        // wrong signature) and not refused as infinite; 2^53 + 1 is the
        // unsafe 2^53, refused, not 0.
        let zeros = "0".repeat(655_359);
        assert_eq!(
            uint(&format!("0.{zeros}1e+655360")).unwrap(),
            uint("1").unwrap()
        );
        assert_eq!(
            int(&format!("-0.{zeros}5e+655360")).unwrap(),
            int("-5").unwrap()
        );
        assert_eq!(
            uint(&format!("1{}e-1048000", "0".repeat(1_048_000))).unwrap(),
            uint("1").unwrap()
        );
        assert!(uint(&format!("0.{zeros}9007199254740993e+655375")).is_err());
        // The hashes the pinned ethers gives these spellings (JSON.parse,
        // then TypedDataEncoder.hash): 1, and the large padded tie (2^52)
        // and just above it (2^52 + 1).
        let hex = |hash: [u8; 32]| crate::to_hex(&hash);
        assert_eq!(
            hex(uint(&format!("0.{zeros}1e+655360")).unwrap()),
            "0x0b4d71ebb529b3a73e4ed8c1f6d477af49f3deddab5e0fc048d609ddcffb9d2c"
        );
        let wide = "0".repeat(655_360);
        assert_eq!(
            hex(uint(&format!("45035996273704965{wide}e-655361")).unwrap()),
            "0x95aff59408c2ac285ddb313edb76e664b1a64c10be8e5a8230982322e605ae0c"
        );
        assert_eq!(
            hex(uint(&format!("45035996273704965{wide}1e-655362")).unwrap()),
            "0x99f65ce034fa0d2a2920040427c93df7b4e14f81b0fd54cb95879c8c05de870d"
        );
        // Literals between 2^52 and 2^53, where a double holds only
        // integers, padded or not: each reads as Rust's correctly rounded
        // parser reads it.
        let mut differ = Vec::new();
        for i in 0..2048u64 {
            let integer = (1u64 << 52) + i.wrapping_mul(1_099_511_627_791) % (1u64 << 52);
            for fraction in ["5", "25", "75", "4999999999", "5000000001"] {
                for literal in [
                    format!("{integer}.{fraction}"),
                    format!(
                        "{integer}{fraction}{}e-{}",
                        "0".repeat(40),
                        fraction.len() + 40
                    ),
                ] {
                    let parsed = crate::parse_json(&literal).unwrap();
                    if parsed.as_f64() != literal.parse::<f64>().ok() {
                        differ.push(literal);
                    }
                }
            }
        }
        assert!(
            differ.is_empty(),
            "{} differ: {:?}",
            differ.len(),
            &differ[..differ.len().min(5)]
        );
    }

    #[test]
    fn int_bounds() {
        let ok = |v: Value| {
            encode_base(
                &Base::Int(8),
                &v,
                &mut Budget::default(),
                &mut ViewText::none(),
            )
            .is_ok()
        };
        assert!(ok(json!(-128)) && ok(json!(127)) && ok(json!("-0x80")));
        assert!(!ok(json!(-129)) && !ok(json!(128)));
        assert_eq!(
            encode_base(
                &Base::Int(8),
                &json!(-1),
                &mut Budget::default(),
                &mut ViewText::none()
            )
            .unwrap(),
            [0xff; 32]
        );
        let min = format!(
            "-{}",
            "57896044618658097711785492504343953926634992332820282019728792003956564819968"
        );
        assert!(
            encode_base(
                &Base::Int(256),
                &json!(min),
                &mut Budget::default(),
                &mut ViewText::none()
            )
            .is_ok()
        );
    }
}
