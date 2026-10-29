//! A protobuf field reader over bytes already held (0009, Bounded
//! decoding): it allocates nothing, skips unknown fields by wire type in
//! time linear in their bytes, refuses groups, and checks every length
//! against the bytes remaining.

use crate::varint;

/// A field's value, a view into the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    Varint(u64),
    Fixed64(&'a [u8]),
    Bytes(&'a [u8]),
    Fixed32(&'a [u8]),
}

/// The fields of a message, in order. Yields `Err(())` once, at the first
/// malformed field, then nothing.
pub struct Fields<'a> {
    rest: &'a [u8],
    failed: bool,
}

pub fn fields(message: &[u8]) -> Fields<'_> {
    Fields {
        rest: message,
        failed: false,
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<(u64, Value<'a>), ()>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        let item = self.read();
        if item.is_err() {
            self.failed = true;
        }
        Some(item)
    }
}

impl<'a> Fields<'a> {
    fn read(&mut self) -> Result<(u64, Value<'a>), ()> {
        let (key, n) = varint::read(self.rest).ok_or(())?;
        let rest = &self.rest[n..];
        let number = key >> 3;
        if number == 0 {
            return Err(());
        }
        let (value, used) = match key & 7 {
            0 => {
                let (v, n) = varint::read(rest).ok_or(())?;
                (Value::Varint(v), n)
            }
            1 => (Value::Fixed64(rest.get(..8).ok_or(())?), 8),
            2 => {
                let (len, n) = varint::read(rest).ok_or(())?;
                let len = usize::try_from(len).map_err(|_| ())?;
                let end = n.checked_add(len).ok_or(())?;
                (Value::Bytes(rest.get(n..end).ok_or(())?), end)
            }
            5 => (Value::Fixed32(rest.get(..4).ok_or(())?), 4),
            // 3 and 4 are groups, which no format here uses; 6 and 7 don't exist.
            _ => return Err(()),
        };
        self.rest = &rest[used..];
        Ok((number, value))
    }
}
