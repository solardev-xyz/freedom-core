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

use crate::ethers;

/// The whole decode failed (ethers' `BUFFER_OVERRUN`, or a top-level offset
/// word above 2^53 - 1, which ethers reads outside its per-field guard).
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
/// Design 0004's decode budget: the bytes and strings one decode may
/// produce (deviation `decode-budget`). Offsets let one string stand for
/// many, so the reads alone don't bound the output.
pub const MAX_DECODE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Shared by a decode and all its sub-readers: ethers counts bytes read
/// against the root data's length, and its message names the root's data
/// and offset.
struct Budget<'a> {
    read: Cell<usize>,
    limit: usize,
    root: &'a [u8],
    root_offset: Cell<usize>,
    output: Cell<usize>,
    output_limit: usize,
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
    budget: &'a Budget<'a>,
    /// The decode's own reader, whose offset the inflation message names.
    root: bool,
}

/// How a read failed, each with ethers' message. `Overrun` (ethers'
/// `BUFFER_OVERRUN`) aborts the decode; `Field` is caught per field by the
/// tuple; `Overflow` is an index above 2^53 - 1, a field error inside a
/// field's guard and the decode's failure outside one.
enum Fail {
    Overrun(String),
    Field(FieldError),
    Overflow(String),
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
            root: false,
        }
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], Fail> {
        let aligned = (length as u128).div_ceil(WORD as u128) * WORD as u128;
        let end = self.offset as u128 + aligned;
        if end > self.data.len() as u128 {
            // The offset as ethers computes and prints it: a double.
            #[allow(clippy::cast_precision_loss)]
            let offset = self.offset as f64 + (length as f64 / WORD as f64).ceil() * WORD as f64;
            return Err(Fail::Overrun(ethers::make_error(
                "data out-of-bounds",
                "BUFFER_OVERRUN",
                &[
                    ("buffer", ethers::hex(self.data)),
                    ("length", self.data.len().to_string()),
                    ("offset", number(offset)),
                ],
            )));
        }
        let read = self.budget.read.get().saturating_add(length);
        self.budget.read.set(read);
        if read > self.budget.limit {
            return Err(Fail::Overrun(ethers::make_error(
                &format!(
                    "compressed ABI data exceeds inflation ratio of {MAX_INFLATION} ( see: https://github.com/ethers-io/ethers.js/issues/4537 )"
                ),
                "BUFFER_OVERRUN",
                &[
                    ("buffer", ethers::hex(self.budget.root)),
                    ("offset", self.budget.root_offset.get().to_string()),
                    ("length", number(length as f64)),
                    (
                        "info",
                        format!(
                            "{{ \"bytesRead\": {read}, \"dataLength\": {} }}",
                            self.budget.root.len()
                        ),
                    ),
                ],
            )));
        }
        let end = self.offset + length.div_ceil(WORD) * WORD;
        let bytes = &self.data[self.offset..self.offset + length];
        self.offset = end;
        if self.root {
            self.budget.root_offset.set(end);
        }
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
        let overflow = || {
            Fail::Overflow(ethers::make_error(
                "overflow",
                "INVALID_ARGUMENT",
                &[
                    ("argument", ethers::string("value")),
                    ("value", ethers::u256_decimal(&word)),
                ],
            ))
        };
        if word[..24].iter().any(|&b| b != 0) {
            return Err(overflow());
        }
        let mut low = [0u8; 8];
        low.copy_from_slice(&word[24..]);
        let value = u64::from_be_bytes(low);
        if value > MAX_SAFE_INTEGER {
            return Err(overflow());
        }
        usize::try_from(value).map_err(|_| overflow())
    }

    fn read_dynamic_bytes(&mut self) -> Result<&'a [u8], Fail> {
        let length = self.read_index()?;
        self.read_bytes(length)
    }

    /// Charges decoded output to the budget (deviation `decode-budget`):
    /// what a field produces, so a string that fails UTF-8 costs nothing,
    /// as the reference's patch counts.
    fn charge(&self, length: usize) -> Result<(), Fail> {
        let output = self.budget.output.get().saturating_add(length);
        self.budget.output.set(output);
        if output > self.budget.output_limit {
            // The core's own budget (deviation `decode-budget`), failing as
            // the patched reference's does.
            return Err(Fail::Overrun(ethers::make_error(
                "decode budget exceeded",
                "BUFFER_OVERRUN",
                &[],
            )));
        }
        Ok(())
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
            Kind::Bytes => {
                let bytes = self.read_dynamic_bytes()?;
                self.charge(bytes.len())?;
                Value::Bytes(bytes.to_vec())
            }
            Kind::String => {
                let text = utf8(self.read_dynamic_bytes()?)?;
                self.charge(text.len())?;
                Value::String(text)
            }
            Kind::StringArray => {
                let count = self.read_index()?;
                // ethers: each element needs at least a word.
                let needed = count as u128 * WORD as u128;
                if needed > self.data.len() as u128 {
                    // `count * WordSize`, a double as ethers prints it.
                    #[allow(clippy::cast_precision_loss)]
                    let offset = count as f64 * WORD as f64;
                    return Err(Fail::Overrun(ethers::make_error(
                        "insufficient data length",
                        "BUFFER_OVERRUN",
                        &[
                            ("buffer", ethers::hex(self.data)),
                            ("offset", number(offset)),
                            ("length", self.data.len().to_string()),
                        ],
                    )));
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
                // The offset is read outside this tuple's per-field guard, so
                // its failure leaves the tuple: inside an enclosing field (a
                // string[] item) that field catches it; at the top it ends
                // the decode (see `decode`).
                let offset = self.read_index()?;
                base.sub(offset).decode(kind)
            } else {
                self.decode(kind)
            };
            fields.push(match result {
                Ok(value) => Ok(value),
                Err(Fail::Field(e)) => Err(e),
                Err(Fail::Overflow(_)) => Err(FieldError::Overflow),
                Err(overrun @ Fail::Overrun(_)) => return Err(overrun),
            });
        }
        Ok(fields)
    }
}

/// A JavaScript number as `String(n)` prints it.
fn number(n: f64) -> String {
    crate::jsjson::number_to_string(n)
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
    decode_within(kinds, data, MAX_DECODE_BYTES)
}

/// [`decode`] with its output limited to `output_limit` bytes.
pub fn decode_within(
    kinds: &[Kind],
    data: &[u8],
    output_limit: usize,
) -> Result<Vec<Field>, DecodeError> {
    decode_explained_within(kinds, data, output_limit).map_err(|_| DecodeError)
}

/// [`decode`], with ethers' message when the whole decode fails.
pub fn decode_explained(kinds: &[Kind], data: &[u8]) -> Result<Vec<Field>, String> {
    decode_explained_within(kinds, data, MAX_DECODE_BYTES)
}

/// [`decode_explained`] with its output limited to `output_limit` bytes.
pub fn decode_explained_within(
    kinds: &[Kind],
    data: &[u8],
    output_limit: usize,
) -> Result<Vec<Field>, String> {
    let budget = Budget {
        read: Cell::new(0),
        limit: data.len().saturating_mul(MAX_INFLATION),
        root: data,
        root_offset: Cell::new(0),
        output: Cell::new(0),
        output_limit,
    };
    let mut reader = Reader {
        data,
        offset: 0,
        budget: &budget,
        root: true,
    };
    reader.unpack(kinds).map_err(|fail| match fail {
        Fail::Overrun(message) | Fail::Overflow(message) => message,
        // Field errors are caught inside the tuple.
        Fail::Field(_) => String::new(),
    })
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
mod explained {
    use super::*;

    const LOOKUP: [Kind; 5] = [
        Kind::Address,
        Kind::StringArray,
        Kind::Bytes,
        Kind::Bytes4,
        Kind::Bytes,
    ];

    fn word(n: usize) -> Vec<u8> {
        word_from_usize(n).to_vec()
    }

    #[test]
    fn the_decode_budget_includes_its_bound() {
        // One four-byte string: output 4.
        let mut data = word(32);
        data.extend(word(4));
        data.extend(b"abcd");
        data.extend([0u8; 28]);
        assert!(decode_within(&[Kind::String], &data, 4).is_ok());
        assert!(decode_within(&[Kind::String], &data, 3).is_err());
        // A string that isn't UTF-8 costs nothing: it produces no output.
        let mut bad = word(32);
        bad.extend(word(4));
        bad.extend([0xff, 0xfe, 0xfd, 0xfc]);
        bad.extend([0u8; 28]);
        assert!(matches!(
            decode_within(&[Kind::String], &bad, 0).as_deref(),
            Ok([Err(FieldError::InvalidUtf8)])
        ));
    }

    /// Messages the pinned ethers produced for the same inputs.
    #[test]
    fn whole_decode_failures_carry_ethers_messages() {
        assert_eq!(
            decode_explained(&LOOKUP, &[0; 40]).err().as_deref(),
            Some(&*format!(
                "data out-of-bounds (buffer=0x{}, length=40, offset=64, code=BUFFER_OVERRUN, version=6.17.0)",
                "00".repeat(40)
            ))
        );
        let mut data = vec![0u8; 32];
        data.extend([0xff; 32]);
        data.extend([0u8; 96]);
        assert_eq!(
            decode_explained(&LOOKUP, &data).err().as_deref(),
            Some(
                "overflow (argument=\"value\", value=115792089237316195423570985008687907853269984665640564039457584007913129639935, code=INVALID_ARGUMENT, version=6.17.0)"
            )
        );
        // A count of 2^53 - 1: its offset is a double, printed as one.
        let mut data = word(32);
        data.extend(word((1 << 53) - 1));
        assert_eq!(
            decode_explained(&[Kind::StringArray], &data)
                .err()
                .as_deref(),
            Some(
                "insufficient data length (buffer=0x000000000000000000000000000000000000000000000000001fffffffffffff, offset=288230376151711700, length=32, code=BUFFER_OVERRUN, version=6.17.0)"
            )
        );
        let mut data = word(32);
        data.extend(word(1000));
        assert_eq!(
            decode_explained(&[Kind::StringArray], &data)
                .err()
                .as_deref(),
            Some(
                "insufficient data length (buffer=0x00000000000000000000000000000000000000000000000000000000000003e8, offset=32000, length=32, code=BUFFER_OVERRUN, version=6.17.0)"
            )
        );
        // One 64 KiB string referenced 2,048 times: the root's data and
        // offset, the failing read, and the totals.
        let (n, len) = (2048, 65536);
        let mut data = word(32);
        data.extend(word(n));
        for _ in 0..n {
            data.extend(word(n * 32));
        }
        data.extend(word(len));
        data.extend(vec![0x78; len]);
        // ethers' own cap, with the core's decode budget lifted (it would
        // refuse this first).
        let message = decode_explained_within(&[Kind::StringArray], &data, usize::MAX)
            .err()
            .unwrap_or_default();
        assert_eq!(
            decode_explained(&[Kind::StringArray], &data)
                .err()
                .as_deref(),
            Some("decode budget exceeded (code=BUFFER_OVERRUN, version=6.17.0)")
        );
        assert!(message.starts_with("compressed ABI data exceeds inflation ratio of 1024 ( see: https://github.com/ethers-io/ethers.js/issues/4537 ) (buffer=0x0000"));
        assert!(message.ends_with(", offset=32, length=65536, info={ \"bytesRead\": 134348864, \"dataLength\": 131168 }, code=BUFFER_OVERRUN, version=6.17.0)"));
        assert_eq!(message.len(), 262_576);
    }
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
