//! A streaming CAR v1 reader (0009, The CAR request): the header (at most
//! 64 KiB, a DAG-CBOR map with `version: 1`; its roots are ignored), then
//! sections of at most 2 MiB plus the CID, each length checked before a
//! byte of the section is buffered. It checks framing only: each block is
//! the caller's to check against its CID, and to match against its walk.

use crate::Refusal;
use crate::block::MAX_BLOCK;
use crate::cbor;
use crate::cid;
use crate::varint;

pub const MAX_HEADER: usize = 64 * 1024;
/// A section's most bytes: a block and its CID (four varints and a digest).
pub const MAX_SECTION: usize = MAX_BLOCK + 4 * varint::MAX_LEN + cid::MAX_DIGEST;
/// What boxo appends to a CAR that fails partway (ipfs/boxo#1197).
pub const BOXO_MARKER: &[u8] = b"\n\n[Gateway Error: CAR stream truncated, response is incomplete]";

/// A section, whole: its CID's bytes, then its block, in the one buffer the
/// reader filled (no copy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    bytes: Vec<u8>,
    cid_len: usize,
}

impl Section {
    pub fn cid(&self) -> &[u8] {
        &self.bytes[..self.cid_len]
    }

    pub fn block(&self) -> &[u8] {
        &self.bytes[self.cid_len..]
    }
}

/// What a [`Reader::push`] gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pushed {
    pub sections: Vec<Section>,
    pub error: Option<Refusal>,
}

/// How the stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// At a section boundary: whether the walk has what it needs is the
    /// walk's question.
    Complete,
    /// Inside a section, or with boxo's truncation marker: the gateway
    /// says it failed, a piece failure.
    Early,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    HeaderLen,
    Header(usize),
    SectionLen,
    Section(usize),
    Marker,
    Failed,
}

#[derive(Debug)]
pub struct Reader {
    state: State,
    buf: Vec<u8>,
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

fn check_header(bytes: &[u8]) -> Result<(), Refusal> {
    let map = cbor::top_map(bytes).map_err(|e| match e {
        cbor::Error::TooDeep => Refusal::Unverifiable,
        cbor::Error::Malformed => Refusal::VerificationFailed,
    })?;
    match map.iter().find(|(k, _)| *k == "version") {
        Some((_, cbor::Item::Uint(1))) => Ok(()),
        _ => Err(Refusal::VerificationFailed),
    }
}

impl Reader {
    pub fn new() -> Self {
        Self {
            state: State::HeaderLen,
            buf: Vec::new(),
        }
    }

    /// The bytes the item being read still needs held, at most: what a
    /// caller reserves before feeding more.
    pub fn holding(&self) -> usize {
        match self.state {
            State::Header(n) | State::Section(n) => n,
            State::Marker => BOXO_MARKER.len(),
            _ => varint::MAX_LEN,
        }
    }

    /// Feeds bytes as they arrive: the sections they completed, then the
    /// error that stopped the reader, if one did. The sections come first:
    /// those read whole before a framing error are good, and the walk may
    /// use them. After an error the reader refuses everything.
    pub fn push(&mut self, mut input: &[u8]) -> Pushed {
        let mut sections = Vec::new();
        let result = self.consume(&mut input, &mut sections);
        if result.is_err() {
            self.state = State::Failed;
            self.buf = Vec::new();
        }
        Pushed {
            sections,
            error: result.err(),
        }
    }

    fn consume(&mut self, input: &mut &[u8], out: &mut Vec<Section>) -> Result<(), Refusal> {
        while !input.is_empty() {
            match self.state {
                State::Failed => return Err(Refusal::VerificationFailed),
                State::HeaderLen | State::SectionLen => {
                    if self.state == State::SectionLen
                        && self.buf.is_empty()
                        && input[0] == BOXO_MARKER[0]
                    {
                        // Boxo's marker, or a section of 10 bytes: the next
                        // byte tells, since no CID starts with a newline.
                        self.buf.push(input[0]);
                        *input = &input[1..];
                        self.state = State::Marker;
                        continue;
                    }
                    self.buf.push(input[0]);
                    *input = &input[1..];
                    if self.buf.last().is_some_and(|b| b & 0x80 != 0) {
                        if self.buf.len() >= varint::MAX_LEN {
                            return Err(Refusal::VerificationFailed);
                        }
                        continue;
                    }
                    let (len, _) = varint::read(&self.buf).ok_or(Refusal::VerificationFailed)?;
                    self.buf.clear();
                    let len = usize::try_from(len).map_err(|_| Refusal::VerificationFailed)?;
                    self.state = if self.state == State::HeaderLen {
                        if len == 0 || len > MAX_HEADER {
                            return Err(Refusal::VerificationFailed);
                        }
                        State::Header(len)
                    } else {
                        if len == 0 || len > MAX_SECTION {
                            return Err(Refusal::VerificationFailed);
                        }
                        State::Section(len)
                    };
                }
                State::Header(len) | State::Section(len) => {
                    let take = (len - self.buf.len()).min(input.len());
                    self.buf.extend_from_slice(&input[..take]);
                    *input = &input[take..];
                    if self.buf.len() < len {
                        continue;
                    }
                    let bytes = std::mem::take(&mut self.buf);
                    if matches!(self.state, State::Header(_)) {
                        check_header(&bytes)?;
                    } else {
                        let (_, cid_len) = cid::read(&bytes).ok_or(Refusal::VerificationFailed)?;
                        out.push(Section { bytes, cid_len });
                    }
                    self.state = State::SectionLen;
                }
                State::Marker => {
                    let have = self.buf.len();
                    if have >= BOXO_MARKER.len() {
                        // Bytes after the marker: not a CAR.
                        return Err(Refusal::VerificationFailed);
                    }
                    if input[0] == BOXO_MARKER[have] {
                        self.buf.push(input[0]);
                        *input = &input[1..];
                        continue;
                    }
                    if have == 1 {
                        // The newline was a section length of 10.
                        self.buf.clear();
                        self.state = State::Section(10);
                        continue;
                    }
                    return Err(Refusal::VerificationFailed);
                }
            }
        }
        Ok(())
    }

    /// The stream ended.
    pub fn finish(&self) -> Result<End, Refusal> {
        match self.state {
            State::SectionLen if self.buf.is_empty() => Ok(End::Complete),
            State::SectionLen | State::Section(_) | State::Marker => Ok(End::Early),
            State::HeaderLen | State::Header(_) | State::Failed => Err(Refusal::VerificationFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // {"roots": [], "version": 1}
    const HEADER: &[u8] = &[
        0x11, 0xa2, 0x65, b'r', b'o', b'o', b't', b's', 0x80, 0x67, b'v', b'e', b'r', b's', b'i',
        b'o', b'n', 0x01,
    ];
    // A section of 10 bytes, which starts with a newline as the marker does:
    // an identity CID of "abc" and its block.
    const TEN: &[u8] = &[
        0x0a, 0x01, 0x55, 0x00, 0x03, b'a', b'b', b'c', b'a', b'b', b'c',
    ];

    fn read(chunks: &[&[u8]]) -> (Vec<Section>, Option<Refusal>, Result<End, Refusal>) {
        let mut r = Reader::new();
        let mut sections = Vec::new();
        for c in chunks {
            let p = r.push(c);
            sections.extend(p.sections);
            if p.error.is_some() {
                return (sections, p.error, r.finish());
            }
        }
        let end = r.finish();
        (sections, None, end)
    }

    #[test]
    fn a_ten_byte_section_isnt_the_marker() {
        let body = [HEADER, TEN].concat();
        for split in 0..body.len() {
            let (s, e, end) = read(&[&body[..split], &body[split..]]);
            assert_eq!(
                (s.len(), e, end),
                (1, None, Ok(End::Complete)),
                "split at {split}"
            );
            assert_eq!(s[0].block(), b"abc");
        }
    }

    #[test]
    fn the_marker_is_an_early_end() {
        let body = [HEADER, TEN, BOXO_MARKER].concat();
        for split in 0..body.len() {
            let (s, e, end) = read(&[&body[..split], &body[split..]]);
            assert_eq!(
                (s.len(), e, end),
                (1, None, Ok(End::Early)),
                "split at {split}"
            );
        }
        // A cut marker is an early end too; bytes after it aren't a CAR.
        let cut = [HEADER, &BOXO_MARKER[..5]].concat();
        assert_eq!(read(&[&cut]).2, Ok(End::Early));
        let after = [HEADER, BOXO_MARKER, b"x"].concat();
        assert_eq!(read(&[&after]).1, Some(Refusal::VerificationFailed));
    }

    #[test]
    fn a_lone_newline_is_a_cut_section() {
        let body = [HEADER, &[0x0a][..]].concat();
        assert_eq!(read(&[&body]).2, Ok(End::Early));
    }

    #[test]
    fn no_header_is_no_car() {
        assert_eq!(read(&[&HEADER[..5]]).2, Err(Refusal::VerificationFailed));
        assert_eq!(read(&[]).2, Err(Refusal::VerificationFailed));
    }
}
