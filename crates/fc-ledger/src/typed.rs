//! Typed data on the device, field by field (design 0016, "The APDU
//! grammar", the `sign.typed_data` rows): the definitions, every type in
//! ascending order of its name with `EIP712Domain` among them, each type's
//! name then its fields' descriptors; then the values, the domain's and the
//! message's, depth first, each in pieces of 255 (deviation
//! `field-pieces`).
//!
//! The values are fc-evm's parse of the bound typed data, which its hash
//! and view (#88) read, encoded as hw-app-eth's `EIP712_TYPE_ENCODERS`
//! encode them. Every bound is checked before the first APDU (deviation
//! `device-bounds`); the APDUs themselves are built one at a time, from
//! the parse moved into the stream, so the stream holds the request and a
//! cursor, not the APDUs.

use fc_evm::{ParsedTypedData, TypedBase, TypedField, TypedStruct, TypedValue, U256};
use serde_json::Value;

use crate::Refusal;
use crate::apdu::{Apdu, MAX_DATA, header};
use crate::bounds::{Bound, MAX_BYTE, MAX_VALUE};

/// One value-row APDU or the run of pieces of one value.
#[derive(Debug)]
enum Event {
    /// `E0 1C 00 00` and a type's name: the domain's, or the primary type's.
    Root(usize),
    /// `E0 1C 00 0F` and an array's length.
    Length(u8),
    /// A value's bytes, sent as `2-byte length ‖ bytes` in pieces of 255.
    Value(Vec<u8>),
}

#[derive(Debug, Clone, Copy)]
enum Cursor {
    /// The next type's name.
    Type(usize),
    /// The type's next field.
    Field(usize, usize),
    /// The next event, and the next piece of a value.
    Event(usize, usize),
    Done,
}

/// The definitions and values of one typed-data operation.
#[derive(Debug)]
pub(crate) struct TypedStream {
    /// Ascending by name, as evm-tools' `sortObjectAlphabetically` sorts
    /// them (names are ASCII, so byte order is UTF-16 order).
    types: Vec<TypedStruct>,
    events: Vec<Event>,
    cursor: Cursor,
}

impl TypedStream {
    /// The stream of `parsed`, refused when a bound is past or the APDUs
    /// would be more than `budget`.
    pub(crate) fn new(parsed: ParsedTypedData, budget: usize) -> Result<TypedStream, Refusal> {
        let ParsedTypedData {
            primary_type,
            mut types,
            domain,
            message,
            ..
        } = parsed;
        // Names are ASCII (0002's identifier rule), so a name's length is
        // its bytes and its characters (deviation `name-ascii`).
        for ty in &types {
            check_name(&ty.name)?;
            for field in &ty.fields {
                check_name(&field.name)?;
            }
        }
        types.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        let mut count = 0usize;
        for ty in &types {
            count = within(count, 1, budget)?;
            for field in &ty.fields {
                descriptor(field)?;
                count = within(count, 1, budget)?;
            }
        }
        let index = |name: &str| {
            types
                .binary_search_by(|ty| ty.name.as_bytes().cmp(name.as_bytes()))
                .map_err(|_| Refusal::Inconsistent)
        };
        let domain_index = index("EIP712Domain")?;
        let primary_index = index(&primary_type)?;
        let mut walk = Walk {
            types: &types,
            events: Vec::new(),
            count: 0,
            budget: budget.saturating_sub(count),
        };
        walk.root(domain_index, domain)?;
        walk.root(primary_index, message)?;
        let Walk {
            events,
            count: values,
            ..
        } = walk;
        within(count, values, budget)?;
        Ok(TypedStream {
            types,
            events,
            cursor: Cursor::Type(0),
        })
    }

    /// The next definition or value APDU; `None` after the last.
    pub(crate) fn next(&mut self) -> Option<Apdu> {
        loop {
            match self.cursor {
                Cursor::Type(t) => match self.types.get(t) {
                    Some(ty) => {
                        self.cursor = Cursor::Field(t, 0);
                        return Apdu::new(header::TYPE_NAME, ty.name.as_bytes());
                    }
                    None => self.cursor = Cursor::Event(0, 0),
                },
                Cursor::Field(t, f) => match self.types.get(t).and_then(|ty| ty.fields.get(f)) {
                    Some(field) => {
                        self.cursor = Cursor::Field(t, f + 1);
                        let data = descriptor(field).ok()?;
                        return Apdu::new(header::TYPE_FIELD, &data);
                    }
                    None => self.cursor = Cursor::Type(t + 1),
                },
                Cursor::Event(e, piece) => match self.events.get(e) {
                    Some(Event::Root(t)) => {
                        self.cursor = Cursor::Event(e + 1, 0);
                        let ty = self.types.get(*t)?;
                        return Apdu::new(header::ROOT, ty.name.as_bytes());
                    }
                    Some(Event::Length(n)) => {
                        self.cursor = Cursor::Event(e + 1, 0);
                        return Apdu::new(header::ARRAY, &[*n]);
                    }
                    Some(Event::Value(bytes)) => {
                        let last = piece + 1 >= pieces(bytes.len());
                        self.cursor = if last {
                            Cursor::Event(e + 1, 0)
                        } else {
                            Cursor::Event(e, piece + 1)
                        };
                        let data = piece_data(bytes, piece)?;
                        let header = if last {
                            header::VALUE_LAST
                        } else {
                            header::VALUE_MORE
                        };
                        return Apdu::new(header, &data);
                    }
                    None => self.cursor = Cursor::Done,
                },
                Cursor::Done => return None,
            }
        }
    }
}

/// Every field's array suffix, as the request writes it, must be the one
/// the device rebuilds from the field's descriptor: `[]` or `[n]` with `n`
/// in decimal, no leading zero (`array-suffix-written-form`). The hash's
/// `encodeType` keeps the written suffix (ethers' `uint8[02]`), the
/// device's has its own (`uint8[2]`), so their digests would differ.
/// `types` is the request fc-evm parsed into `parsed`.
pub(crate) fn check_written_forms(types: &Value, parsed: &ParsedTypedData) -> Result<(), Refusal> {
    let object = types.as_object().ok_or(Refusal::Inconsistent)?;
    for (name, list) in object {
        let ty = parsed
            .types
            .iter()
            .find(|ty| ty.name == *name)
            .ok_or(Refusal::Inconsistent)?;
        let list = list.as_array().ok_or(Refusal::Inconsistent)?;
        if list.len() != ty.fields.len() {
            return Err(Refusal::Inconsistent);
        }
        for (written, field) in list.iter().zip(&ty.fields) {
            let text = written.get("type").and_then(Value::as_str);
            let text = text.ok_or(Refusal::Inconsistent)?;
            let suffix = text
                .find('[')
                .and_then(|at| text.get(at..))
                .unwrap_or_default();
            if suffix != rebuilt(&field.dims) {
                return Err(Refusal::NotCanonical);
            }
        }
    }
    Ok(())
}

/// The array suffix the device rebuilds from a descriptor's dimensions.
fn rebuilt(dims: &[Option<u64>]) -> String {
    dims.iter()
        .map(|dim| match dim {
            None => "[]".to_owned(),
            Some(n) => format!("[{n}]"),
        })
        .collect()
}

/// `count + n`, refused past `budget`.
fn within(count: usize, n: usize, budget: usize) -> Result<usize, Refusal> {
    let count = count.saturating_add(n);
    if count > budget {
        return Err(Refusal::TooLarge(Bound::Apdus));
    }
    Ok(count)
}

fn check_name(name: &str) -> Result<(), Refusal> {
    if !name.is_ascii() {
        return Err(Refusal::Name);
    }
    if name.len() > MAX_BYTE {
        return Err(Refusal::TooLarge(Bound::Name(name.len())));
    }
    Ok(())
}

/// The pieces of a value of `len` bytes: `2 + len` bytes in pieces of 255.
fn pieces(len: usize) -> usize {
    (len + 2).div_ceil(MAX_DATA)
}

/// Piece `k` of `2-byte length ‖ bytes`.
fn piece_data(bytes: &[u8], k: usize) -> Option<Vec<u8>> {
    let len = u16::try_from(bytes.len()).ok()?;
    let start = k.checked_mul(MAX_DATA)?;
    let end = start.checked_add(MAX_DATA)?.min(bytes.len() + 2);
    if start == 0 {
        let mut out = Vec::with_capacity(end);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes.get(..end.checked_sub(2)?)?);
        Some(out)
    } else {
        bytes
            .get(start.checked_sub(2)?..end.checked_sub(2)?)
            .map(<[u8]>::to_vec)
    }
}

/// hw-app-eth's `EIP712_TYPE_PROPERTIES` keys (`EIP712/utils.js:28–56`).
fn key(base: &TypedBase) -> u8 {
    match base {
        TypedBase::Struct(_) => 0,
        TypedBase::Int(_) => 1,
        TypedBase::Uint(_) => 2,
        TypedBase::Address => 3,
        TypedBase::Bool => 4,
        TypedBase::String => 5,
        TypedBase::FixedBytes(_) => 6,
        TypedBase::Bytes => 7,
    }
}

/// A field's descriptor: its type byte, its custom type's name with a
/// length byte, its size, its array dimensions, and its name with a length
/// byte; refused past a byte's bounds or an APDU's data.
fn descriptor(field: &TypedField) -> Result<Vec<u8>, Refusal> {
    let size = match field.base {
        TypedBase::Uint(bits) | TypedBase::Int(bits) => Some(bits / 8),
        TypedBase::FixedBytes(width) => u32::try_from(width).ok(),
        _ => None,
    };
    let mut out = vec![
        (if field.dims.is_empty() { 0 } else { 0x80 })
            | (if size.is_some() { 0x40 } else { 0 })
            | key(&field.base),
    ];
    if let TypedBase::Struct(name) = &field.base {
        push_name(&mut out, name)?;
    }
    if let Some(size) = size {
        // A width of at most 32 bytes.
        out.push(u8::try_from(size).map_err(|_| Refusal::Inconsistent)?);
    }
    if !field.dims.is_empty() {
        let dimensions = u8::try_from(field.dims.len())
            .map_err(|_| Refusal::TooLarge(Bound::Dimensions(field.dims.len())))?;
        out.push(dimensions);
        for dim in &field.dims {
            match dim {
                None => out.push(0),
                Some(n) => {
                    let n8 =
                        u8::try_from(*n).map_err(|_| Refusal::TooLarge(Bound::FixedSize(*n)))?;
                    out.extend_from_slice(&[1, n8]);
                }
            }
        }
    }
    push_name(&mut out, &field.name)?;
    if out.len() > MAX_DATA {
        return Err(Refusal::TooLarge(Bound::Definition(out.len())));
    }
    Ok(out)
}

fn push_name(out: &mut Vec<u8>, name: &str) -> Result<(), Refusal> {
    check_name(name)?;
    // At most 255 bytes, checked above.
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    Ok(())
}

/// The values' walk, depth first, as hw-app-eth's walks them: an array's
/// length, then its entries, the last dimension peeled; a struct's
/// declared fields in order; a value's bytes.
struct Walk<'a> {
    types: &'a [TypedStruct],
    events: Vec<Event>,
    count: usize,
    budget: usize,
}

impl Walk<'_> {
    fn push(&mut self, event: Event, apdus: usize) -> Result<(), Refusal> {
        self.count = within(self.count, apdus, self.budget)?;
        self.events.push(event);
        Ok(())
    }

    fn root(&mut self, index: usize, values: Vec<TypedValue>) -> Result<(), Refusal> {
        self.push(Event::Root(index), 1)?;
        self.fields(index, values)
    }

    fn fields(&mut self, index: usize, values: Vec<TypedValue>) -> Result<(), Refusal> {
        let fields = &self.types.get(index).ok_or(Refusal::Inconsistent)?.fields;
        if fields.len() != values.len() {
            return Err(Refusal::Inconsistent);
        }
        for (field, value) in fields.iter().zip(values) {
            self.value(&field.base, &field.dims, value)?;
        }
        Ok(())
    }

    fn value(
        &mut self,
        base: &TypedBase,
        dims: &[Option<u64>],
        value: TypedValue,
    ) -> Result<(), Refusal> {
        if let Some((_, inner)) = dims.split_last() {
            let TypedValue::Array(entries) = value else {
                return Err(Refusal::Inconsistent);
            };
            let length = u8::try_from(entries.len())
                .map_err(|_| Refusal::TooLarge(Bound::ArrayEntries(entries.len())))?;
            self.push(Event::Length(length), 1)?;
            for entry in entries {
                self.value(base, inner, entry)?;
            }
            return Ok(());
        }
        if let TypedBase::Struct(name) = base {
            let TypedValue::Struct(values) = value else {
                return Err(Refusal::Inconsistent);
            };
            let index = self
                .types
                .binary_search_by(|ty| ty.name.as_bytes().cmp(name.as_bytes()))
                .map_err(|_| Refusal::Inconsistent)?;
            return self.fields(index, values);
        }
        let bytes = encode(base, value).ok_or(Refusal::Inconsistent)?;
        if bytes.len() > MAX_VALUE {
            return Err(Refusal::TooLarge(Bound::Value(bytes.len())));
        }
        let apdus = pieces(bytes.len());
        self.push(Event::Value(bytes), apdus)
    }
}

/// A value as hw-app-eth's `EIP712_TYPE_ENCODERS` encode it
/// (`EIP712/utils.js:62–102`): an integer's minimal big-endian bytes (one
/// zero byte for 0), a negative one in two's complement of its width; a
/// bool as 0 or 1; an address's 20 bytes; bytes as they are; a string's
/// UTF-8.
fn encode(base: &TypedBase, value: TypedValue) -> Option<Vec<u8>> {
    match (base, value) {
        (TypedBase::Uint(_), TypedValue::Uint(n)) => Some(minimal(&n)),
        (
            TypedBase::Int(bits),
            TypedValue::Int {
                negative,
                magnitude,
            },
        ) => Some(if negative {
            minimal(
                &U256::mask(*bits)
                    .checked_sub(&magnitude)?
                    .checked_add(&U256::from_u64(1))?,
            )
        } else {
            minimal(&magnitude)
        }),
        (TypedBase::Bool, TypedValue::Bool(flag)) => Some(vec![u8::from(flag)]),
        (TypedBase::Address, TypedValue::Address(address)) => Some(address.to_vec()),
        (TypedBase::FixedBytes(_), TypedValue::FixedBytes(bytes))
        | (TypedBase::Bytes, TypedValue::Bytes(bytes)) => Some(bytes),
        (TypedBase::String, TypedValue::String(text)) => Some(text.into_bytes()),
        _ => None,
    }
}

fn minimal(n: &U256) -> Vec<u8> {
    let bytes = n.to_minimal_be();
    if bytes.is_empty() { vec![0] } else { bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_cut_in_pieces_of_255() {
        for (len, want) in [
            (0, vec![2]),
            (253, vec![255]),
            (254, vec![255, 1]),
            (508, vec![255, 255]),
            (509, vec![255, 255, 1]),
            (65_535, [vec![255; 257], vec![2]].concat()),
        ] {
            let bytes: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let got: Vec<usize> = (0..pieces(len))
                .map(|k| piece_data(&bytes, k).unwrap().len())
                .collect();
            assert_eq!(got, want, "{len}");
            let joined: Vec<u8> = (0..pieces(len))
                .flat_map(|k| piece_data(&bytes, k).unwrap())
                .collect();
            assert_eq!(joined[..2], (len as u16).to_be_bytes());
            assert_eq!(joined[2..], bytes[..]);
        }
    }

    #[test]
    fn integers_as_the_encoders_write_them() {
        let int = |negative, magnitude| TypedValue::Int {
            negative,
            magnitude: U256::from_u64(magnitude),
        };
        assert_eq!(
            encode(&TypedBase::Uint(8), TypedValue::Uint(U256::ZERO)),
            Some(vec![0])
        );
        assert_eq!(
            encode(
                &TypedBase::Uint(256),
                TypedValue::Uint(U256::from_u64(0x2105))
            ),
            Some(vec![0x21, 0x05])
        );
        assert_eq!(encode(&TypedBase::Int(8), int(true, 1)), Some(vec![0xff]));
        assert_eq!(encode(&TypedBase::Int(8), int(true, 128)), Some(vec![0x80]));
        assert_eq!(
            encode(&TypedBase::Int(16), int(true, 1)),
            Some(vec![0xff, 0xff])
        );
        assert_eq!(
            encode(&TypedBase::Int(256), int(true, 1)),
            Some(vec![0xff; 32])
        );
        assert_eq!(
            encode(&TypedBase::Int(8), int(false, 127)),
            Some(vec![0x7f])
        );
        assert_eq!(
            encode(&TypedBase::Bool, TypedValue::Bool(true)),
            Some(vec![1])
        );
        assert_eq!(encode(&TypedBase::Bool, TypedValue::Uint(U256::ZERO)), None);
    }

    #[test]
    fn descriptors() {
        let field = |name: &str, base, dims| TypedField {
            name: name.to_owned(),
            base,
            dims,
        };
        assert_eq!(
            descriptor(&field("chainId", TypedBase::Uint(256), vec![])).unwrap(),
            b"\x42\x20\x07chainId"
        );
        assert_eq!(
            descriptor(&field("from", TypedBase::Struct("Person".into()), vec![])).unwrap(),
            b"\x00\x06Person\x04from"
        );
        assert_eq!(
            descriptor(&field("v", TypedBase::Uint(8), vec![Some(2), None])).unwrap(),
            b"\xc2\x01\x02\x01\x02\x00\x01v"
        );
        assert_eq!(
            descriptor(&field("n", TypedBase::FixedBytes(32), vec![])).unwrap(),
            b"\x46\x20\x01n"
        );
        // A string field's name of 253 characters: 255 bytes; one more, 256.
        let name = "a".repeat(253);
        assert_eq!(
            descriptor(&field(&name, TypedBase::String, vec![]))
                .unwrap()
                .len(),
            255
        );
        let name = "a".repeat(254);
        assert_eq!(
            descriptor(&field(&name, TypedBase::String, vec![])),
            Err(Refusal::TooLarge(Bound::Definition(256)))
        );
        assert_eq!(
            descriptor(&field("v", TypedBase::Uint(8), vec![Some(256)])),
            Err(Refusal::TooLarge(Bound::FixedSize(256)))
        );
        assert_eq!(
            descriptor(&field("v", TypedBase::Uint(8), vec![Some(255)])).unwrap(),
            b"\xc2\x01\x01\x01\xff\x01v"
        );
    }
}
