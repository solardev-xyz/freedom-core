//! APDUs and their answers (design 0016, "`shell.ledger_apdu`", "The APDU
//! grammar", "Answers the core checks").

use std::fmt;

use fc_evm::{keccak256, parse_address, to_hex};

/// The most data one APDU carries: `Lc` is one byte.
pub const MAX_DATA: usize = 255;
/// An answer's bounds: its status word, after at most 258 bytes.
pub const MIN_ANSWER: usize = 2;
pub const MAX_ANSWER: usize = 260;

/// The status word that goes on.
pub const STATUS_OK: u16 = 0x9000;
/// "Instruction not supported": after the operation's first `E0 1A`, the
/// hash-only form follows (Q23).
pub const STATUS_INS_NOT_SUPPORTED: u16 = 0x6d00;

/// One APDU: `CLA INS P1 P2 Lc data`, 5 to 260 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Apdu(Vec<u8>);

impl Apdu {
    /// `None` when the data is longer than [`MAX_DATA`].
    pub(crate) fn new(header: [u8; 4], data: &[u8]) -> Option<Apdu> {
        let lc = u8::try_from(data.len()).ok()?;
        let mut out = Vec::with_capacity(5 + data.len());
        out.extend_from_slice(&header);
        out.push(lc);
        out.extend_from_slice(data);
        Some(Apdu(out))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// `CLA INS P1 P2`.
    pub fn header(&self) -> [u8; 4] {
        let mut header = [0u8; 4];
        if let Some(head) = self.0.get(..4) {
            header.copy_from_slice(head);
        }
        header
    }

    pub fn data(&self) -> &[u8] {
        self.0.get(5..).unwrap_or_default()
    }
}

impl fmt::Debug for Apdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Apdu({})", to_hex(&self.0))
    }
}

/// The headers of design 0016's rows.
pub(crate) mod header {
    pub const ADDRESS: [u8; 4] = [0xe0, 0x02, 0x00, 0x00];
    pub const ADDRESS_DISPLAY: [u8; 4] = [0xe0, 0x02, 0x01, 0x00];
    pub const APP: [u8; 4] = [0xb0, 0x01, 0x00, 0x00];
    pub const TX_FIRST: [u8; 4] = [0xe0, 0x04, 0x00, 0x00];
    pub const TX_MORE: [u8; 4] = [0xe0, 0x04, 0x80, 0x00];
    pub const MESSAGE_FIRST: [u8; 4] = [0xe0, 0x08, 0x00, 0x00];
    pub const MESSAGE_MORE: [u8; 4] = [0xe0, 0x08, 0x80, 0x00];
    pub const TYPE_NAME: [u8; 4] = [0xe0, 0x1a, 0x00, 0x00];
    pub const TYPE_FIELD: [u8; 4] = [0xe0, 0x1a, 0x00, 0xff];
    pub const ROOT: [u8; 4] = [0xe0, 0x1c, 0x00, 0x00];
    pub const ARRAY: [u8; 4] = [0xe0, 0x1c, 0x00, 0x0f];
    pub const VALUE_MORE: [u8; 4] = [0xe0, 0x1c, 0x01, 0xff];
    pub const VALUE_LAST: [u8; 4] = [0xe0, 0x1c, 0x00, 0xff];
    pub const SIGN_FIELDS: [u8; 4] = [0xe0, 0x0c, 0x00, 0x01];
    pub const SIGN_HASHES: [u8; 4] = [0xe0, 0x0c, 0x00, 0x00];
}

/// Why an answer can't be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AnswerFault {
    /// More or fewer bytes than the APDU's answer has.
    #[error("an answer of another length")]
    Length,
    /// `E0 02`'s key isn't 65 bytes of an uncompressed key.
    #[error("not an uncompressed public key")]
    Key,
    /// `E0 02`'s address isn't 40 ASCII hex digits (EIP-55 if mixed case).
    #[error("not an address")]
    AddressText,
    /// `E0 02`'s address isn't the one its key derives (deviation
    /// `key-check`).
    #[error("the address isn't the key's")]
    KeyNotAddress,
}

/// An answer: its data, then its status word.
pub(crate) struct Answer<'a> {
    pub body: &'a [u8],
    pub status: u16,
}

/// `None` outside 2 to 260 bytes.
pub(crate) fn split(answer: &[u8]) -> Option<Answer<'_>> {
    if !(MIN_ANSWER..=MAX_ANSWER).contains(&answer.len()) {
        return None;
    }
    let (body, status) = answer.split_last_chunk::<2>()?;
    Some(Answer {
        body,
        status: u16::from_be_bytes(*status),
    })
}

/// `E0 02`'s answer, `65 ‖ key (65 bytes) ‖ 40 ‖ address (40 ASCII hex)`:
/// the address, which must be the one the key derives, the last 20 bytes
/// of keccak256 of its last 64 bytes (deviation `key-check`).
pub(crate) fn read_address(body: &[u8]) -> Result<[u8; 20], AnswerFault> {
    let [65, rest @ ..] = body else {
        return Err(AnswerFault::Length);
    };
    let (key, rest) = rest.split_first_chunk::<65>().ok_or(AnswerFault::Length)?;
    let [40, text @ ..] = rest else {
        return Err(AnswerFault::Length);
    };
    if text.len() != 40 {
        return Err(AnswerFault::Length);
    }
    let [0x04, point @ ..] = key.as_slice() else {
        return Err(AnswerFault::Key);
    };
    let text = std::str::from_utf8(text).map_err(|_| AnswerFault::AddressText)?;
    let address = parse_address(&format!("0x{text}")).map_err(|_| AnswerFault::AddressText)?;
    let hash = keccak256(point);
    if hash.get(12..) != Some(address.as_slice()) {
        return Err(AnswerFault::KeyNotAddress);
    }
    Ok(address)
}

/// `B0 01`'s answer: format, the name and the version, each within its
/// length, then the flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct App {
    pub format: u8,
    pub name: Vec<u8>,
    pub version: Vec<u8>,
}

pub(crate) fn read_app(body: &[u8]) -> Result<App, AnswerFault> {
    let (format, rest) = body.split_first().ok_or(AnswerFault::Length)?;
    let (name, rest) = length_prefixed(rest)?;
    let (version, rest) = length_prefixed(rest)?;
    // The flags, if sent, are one length-prefixed field, and nothing follows.
    if !rest.is_empty() {
        let (_, rest) = length_prefixed(rest)?;
        if !rest.is_empty() {
            return Err(AnswerFault::Length);
        }
    }
    Ok(App {
        format: *format,
        name: name.to_vec(),
        version: version.to_vec(),
    })
}

fn length_prefixed(bytes: &[u8]) -> Result<(&[u8], &[u8]), AnswerFault> {
    let (length, rest) = bytes.split_first().ok_or(AnswerFault::Length)?;
    let length = usize::from(*length);
    if rest.len() < length {
        return Err(AnswerFault::Length);
    }
    Ok(rest.split_at(length))
}

/// A signature's answer, `v ‖ r ‖ s`: exactly 65 bytes.
pub(crate) fn read_signature(body: &[u8]) -> Option<(u8, [u8; 64])> {
    let (v, rs) = body.split_first()?;
    let rs: [u8; 64] = rs.try_into().ok()?;
    Some((*v, rs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdus_frame_their_data() {
        let apdu = Apdu::new(header::APP, &[]).unwrap();
        assert_eq!(apdu.as_bytes(), [0xb0, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(apdu.header(), header::APP);
        assert!(apdu.data().is_empty());
        let full = Apdu::new(header::ROOT, &[7; 255]).unwrap();
        assert_eq!(full.as_bytes().len(), 260);
        assert_eq!(full.as_bytes()[4], 255);
        assert!(Apdu::new(header::ROOT, &[7; 256]).is_none());
    }

    #[test]
    fn answers_within_their_bounds() {
        assert!(split(&[0x90]).is_none());
        assert!(split(&[0; 261]).is_none());
        let answer = split(&[0x90, 0x00]).unwrap();
        assert_eq!((answer.body.len(), answer.status), (0, 0x9000));
        let answer = split(&[1, 2, 0x6d, 0x00]).unwrap();
        assert_eq!((answer.body, answer.status), (&[1u8, 2][..], 0x6d00));
        assert!(split(&[0; 260]).is_some());
    }

    #[test]
    fn the_app_answer() {
        let mut body = vec![1, 8];
        body.extend_from_slice(b"Ethereum");
        body.push(6);
        body.extend_from_slice(b"1.13.0");
        let bare = read_app(&body).unwrap();
        assert_eq!(
            (bare.format, &bare.name[..], &bare.version[..]),
            (1, &b"Ethereum"[..], &b"1.13.0"[..])
        );
        body.extend_from_slice(&[1, 0]);
        assert_eq!(read_app(&body).unwrap(), bare);
        for cut in 0..body.len() {
            if cut != body.len() - 2 {
                assert!(read_app(&body[..cut]).is_err(), "{cut}");
            }
        }
        body.push(0);
        assert_eq!(read_app(&body), Err(AnswerFault::Length));
    }
}
