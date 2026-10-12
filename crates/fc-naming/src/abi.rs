//! The few ABI shapes naming needs, decoded with ethers v6's rules
//! (`AbiCoder.defaultAbiCoder()`, strict mode), because which malformed
//! answers resolve and which don't is part of the parity contract:
//!
//! - a read past the end of the data, or reading more than 1,024 times the
//!   data's length in total, fails the whole decode (ethers' `BUFFER_OVERRUN`);
//! - any other problem with one field (invalid UTF-8, an address with high
//!   bits set, an index above 2^53 - 1) fails only that field. ethers keeps
//!   the error as the field's value and throws when the field is read, so a
//!   caller that never reads it never sees it;
//! - offsets are relative to the start of their tuple, and padding bytes are
//!   never checked.

use std::cell::Cell;

/// The whole decode failed (ethers' `BUFFER_OVERRUN`, or an offset word
/// above 2^53 - 1, which ethers reads outside its per-field guard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

/// One field failed to decode; reading it is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldError {
    /// A length or count above JavaScript's 2^53 - 1.
    Overflow,
    /// An address word with any of its high 12 bytes set.
    AddressTooWide,
    /// A string that isn't valid UTF-8.
    InvalidUtf8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Address,
    Uint256,
    Bytes4,
    Bytes,
    String,
    StringArray,
}

impl Kind {
    fn dynamic(self) -> bool {
        matches!(self, Kind::Bytes | Kind::String | Kind::StringArray)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Address([u8; 20]),
    Uint256([u8; 32]),
    Bytes4([u8; 4]),
    Bytes(Vec<u8>),
    String(String),
    StringArray(Vec<Result<String, FieldError>>),
}

pub type Field = Result<Value, FieldError>;

const WORD: usize = 32;
const MAX_INFLATION: usize = 1024;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Shared by a decode and all its sub-readers: ethers counts bytes read
/// against the root data's length.
struct Budget {
    read: Cell<usize>,
    limit: usize,
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
    budget: &'a Budget,
}

/// `Overrun` aborts the decode; `Field` is caught per field by the tuple.
enum Fail {
    Overrun,
    Field(FieldError),
}

impl From<FieldError> for Fail {
    fn from(e: FieldError) -> Self {
        Fail::Field(e)
    }
}

impl<'a> Reader<'a> {
    fn sub(&self, offset: usize) -> Reader<'a> {
        // JavaScript's `slice` clamps an offset past the end to empty.
        let start = self.offset.saturating_add(offset).min(self.data.len());
        Reader {
            data: &self.data[start..],
            offset: 0,
            budget: self.budget,
        }
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], Fail> {
        let aligned = length
            .div_ceil(WORD)
            .checked_mul(WORD)
            .ok_or(Fail::Overrun)?;
        let end = self.offset.checked_add(aligned).ok_or(Fail::Overrun)?;
        if end > self.data.len() {
            return Err(Fail::Overrun);
        }
        let read = self.budget.read.get().saturating_add(length);
        self.budget.read.set(read);
        if read > self.budget.limit {
            return Err(Fail::Overrun);
        }
        let bytes = &self.data[self.offset..self.offset + length];
        self.offset = end;
        Ok(bytes)
    }

    fn read_word(&mut self) -> Result<[u8; 32], Fail> {
        let bytes = self.read_bytes(WORD)?;
        let mut word = [0u8; 32];
        word.copy_from_slice(bytes);
        Ok(word)
    }

    /// `readIndex`: a word as a JavaScript safe integer.
    fn read_index(&mut self) -> Result<usize, Fail> {
        let word = self.read_word()?;
        if word[..24].iter().any(|&b| b != 0) {
            return Err(FieldError::Overflow.into());
        }
        let mut low = [0u8; 8];
        low.copy_from_slice(&word[24..]);
        let value = u64::from_be_bytes(low);
        if value > MAX_SAFE_INTEGER {
            return Err(FieldError::Overflow.into());
        }
        usize::try_from(value).map_err(|_| Fail::Overrun)
    }

    fn read_dynamic_bytes(&mut self) -> Result<&'a [u8], Fail> {
        let length = self.read_index()?;
        self.read_bytes(length)
    }

    fn decode(&mut self, kind: Kind) -> Result<Value, Fail> {
        Ok(match kind {
            Kind::Address => {
                let word = self.read_word()?;
                if word[..12].iter().any(|&b| b != 0) {
                    return Err(FieldError::AddressTooWide.into());
                }
                let mut address = [0u8; 20];
                address.copy_from_slice(&word[12..]);
                Value::Address(address)
            }
            Kind::Uint256 => Value::Uint256(self.read_word()?),
            Kind::Bytes4 => {
                let bytes = self.read_bytes(4)?;
                let mut out = [0u8; 4];
                out.copy_from_slice(bytes);
                Value::Bytes4(out)
            }
            Kind::Bytes => Value::Bytes(self.read_dynamic_bytes()?.to_vec()),
            Kind::String => Value::String(utf8(self.read_dynamic_bytes()?)?),
            Kind::StringArray => {
                let count = self.read_index()?;
                // ethers: each element needs at least a word.
                if count.checked_mul(WORD).is_none_or(|n| n > self.data.len()) {
                    return Err(Fail::Overrun);
                }
                let items = self.unpack(&vec![Kind::String; count])?;
                Value::StringArray(
                    items
                        .into_iter()
                        .map(|item| match item {
                            Ok(Value::String(s)) => Ok(s),
                            Ok(_) => Err(FieldError::InvalidUtf8),
                            Err(e) => Err(e),
                        })
                        .collect(),
                )
            }
        })
    }

    /// ethers' `unpack`: a tuple's fields, each caught on its own.
    fn unpack(&mut self, kinds: &[Kind]) -> Result<Vec<Field>, Fail> {
        let base = self.sub(0);
        let mut fields = Vec::with_capacity(kinds.len());
        for &kind in kinds {
            let result = if kind.dynamic() {
                // The offset itself is read outside the per-field guard.
                let offset = self.read_index().map_err(|e| match e {
                    Fail::Field(_) => Fail::Overrun,
                    other => other,
                })?;
                base.sub(offset).decode(kind)
            } else {
                self.decode(kind)
            };
            fields.push(match result {
                Ok(value) => Ok(value),
                Err(Fail::Field(e)) => Err(e),
                Err(Fail::Overrun) => return Err(Fail::Overrun),
            });
        }
        Ok(fields)
    }
}

fn utf8(bytes: &[u8]) -> Result<String, FieldError> {
    // Rust and ethers' strict `toUtf8String` refuse the same sequences:
    // overlong forms, surrogates, code points above U+10FFFF, and stray or
    // missing continuation bytes.
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| FieldError::InvalidUtf8)
}

/// `AbiCoder.defaultAbiCoder().decode(kinds, data)`.
pub fn decode(kinds: &[Kind], data: &[u8]) -> Result<Vec<Field>, DecodeError> {
    let budget = Budget {
        read: Cell::new(0),
        limit: data.len().saturating_mul(MAX_INFLATION),
    };
    let mut reader = Reader {
        data,
        offset: 0,
        budget: &budget,
    };
    reader.unpack(kinds).map_err(|_| DecodeError)
}

/// Head-and-tail encoding of dynamic `bytes`/`string` and static words, for
/// the calls naming makes. Each item is a word or a dynamic byte string.
pub enum Token<'a> {
    Word([u8; 32]),
    Dynamic(&'a [u8]),
}

pub fn encode(tokens: &[Token<'_>]) -> Vec<u8> {
    let mut head = Vec::with_capacity(tokens.len() * WORD);
    let mut tail = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) => head.extend_from_slice(word),
            Token::Dynamic(bytes) => {
                head.extend_from_slice(&word_from_usize(tokens.len() * WORD + tail.len()));
                tail.extend_from_slice(&word_from_usize(bytes.len()));
                tail.extend_from_slice(bytes);
                tail.resize(tail.len().div_ceil(WORD) * WORD, 0);
            }
        }
    }
    head.extend_from_slice(&tail);
    head
}

pub fn word_from_usize(value: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

pub fn word_from_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple_bytes_address(bytes: &[u8], address: [u8; 20]) -> Vec<u8> {
        encode(&[
            Token::Dynamic(bytes),
            Token::Word(word_from_address(&address)),
        ])
    }

    #[test]
    fn round_trips_bytes_and_address() {
        let data = tuple_bytes_address(b"hello", [7; 20]);
        let fields = decode(&[Kind::Bytes, Kind::Address], &data).unwrap();
        assert_eq!(
            fields,
            vec![
                Ok(Value::Bytes(b"hello".to_vec())),
                Ok(Value::Address([7; 20]))
            ]
        );
    }

    #[test]
    fn missing_padding_fails_the_whole_decode() {
        let mut data = tuple_bytes_address(b"hello", [7; 20]);
        data.truncate(data.len() - 1);
        assert_eq!(
            decode(&[Kind::Bytes, Kind::Address], &data),
            Err(DecodeError)
        );
    }

    #[test]
    fn a_wide_address_fails_only_its_field() {
        let mut data = tuple_bytes_address(b"x", [7; 20]);
        data[32] = 1; // the address word's top byte
        let fields = decode(&[Kind::Bytes, Kind::Address], &data).unwrap();
        assert_eq!(fields[0], Ok(Value::Bytes(b"x".to_vec())));
        assert_eq!(fields[1], Err(FieldError::AddressTooWide));
    }

    #[test]
    fn invalid_utf8_fails_only_its_field() {
        let data = encode(&[Token::Dynamic(&[0xc0, 0x80]), Token::Word([0; 32])]);
        let fields = decode(&[Kind::String, Kind::Uint256], &data).unwrap();
        assert_eq!(fields[0], Err(FieldError::InvalidUtf8));
        assert!(fields[1].is_ok());
    }

    #[test]
    fn an_offset_past_the_end_fails_the_whole_decode() {
        let mut data = tuple_bytes_address(b"x", [7; 20]);
        data[31] = 0xff;
        assert_eq!(
            decode(&[Kind::Bytes, Kind::Address], &data),
            Err(DecodeError)
        );
    }

    #[test]
    fn a_huge_offset_fails_the_whole_decode() {
        let mut data = tuple_bytes_address(b"x", [7; 20]);
        data[0] = 1;
        assert_eq!(
            decode(&[Kind::Bytes, Kind::Address], &data),
            Err(DecodeError)
        );
    }

    #[test]
    fn a_huge_length_fails_only_its_field() {
        let mut data = tuple_bytes_address(b"x", [7; 20]);
        data[64] = 1; // the length word's top byte
        let fields = decode(&[Kind::Bytes, Kind::Address], &data).unwrap();
        assert_eq!(fields[0], Err(FieldError::Overflow));
    }
}
