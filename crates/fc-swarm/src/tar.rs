//! The tar body of a collection upload (design 0015, "Building the body"),
//! byte for byte as bee-js 13.2.0's `TarStream` writes it (`utils/tar.js`,
//! through `tar-writer.js` and `tar-uploader.js`) for `publishCollection`:
//!
//! - a ustar header per entry: mode `0000777`, owner and group `0001750`,
//!   the size and the modification time as 11 octal digits, the checksum,
//!   type `0`, magic `ustar\0` and version `\0\0`;
//! - the entry's bytes, padded with zeros to 512;
//! - 1,024 zero bytes at the end.
//!
//! **Long paths** take bee-js's three forms: the whole path in the name
//! field; else a split at the rightmost `/` whose name fits 100 bytes and
//! whose prefix fits 155, the prefix in the ustar prefix field; else a GNU
//! `././@LongLink` entry holding the whole path, then a header with the last
//! segment, cut to 100 bytes.
//!
//! **One deviation, `tar-paths` (F-3):** bee-js measures a path in UTF-16
//! units but writes it into fields counted in bytes, so a name of at most
//! 100 units and more than 100 UTF-8 bytes is cut silently. Here every
//! length is in bytes, so such a name takes the split or the long link and
//! is kept whole. For every path bee-js doesn't cut, ASCII ones included,
//! the bytes are bee-js's.
//!
//! The writer streams: it hands out the bytes around each entry's data and
//! counts the data, which the caller sends itself. Its state is a few
//! integers; an entry's header bytes are allocated per entry, sized by its
//! path.

/// A tar block.
pub const BLOCK: usize = 512;
/// The archive's end: two zero blocks.
pub const END: [u8; 2 * BLOCK] = [0; 2 * BLOCK];
/// The largest value 11 octal digits hold: a size or a time past it doesn't
/// fit its field (bee-js would write a truncated number).
pub const MAX_OCTAL_FIELD: u64 = 0o77777777777;

const NAME: usize = 100;
const PREFIX: usize = 155;
const PADDING: [u8; BLOCK] = [0; BLOCK];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TarError {
    #[error("entry size {0} doesn't fit the size field")]
    Size(u64),
    #[error("modification time {0} doesn't fit the time field")]
    Time(u64),
    #[error("an entry is open")]
    EntryOpen,
    #[error("no entry is open")]
    NoEntry,
    #[error("{written} bytes written for a {size}-byte entry")]
    Length { size: u64, written: u64 },
}

/// Where a path goes in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Split<'a> {
    Name(&'a str),
    Prefixed { prefix: &'a str, name: &'a str },
    LongLink { name: &'a str },
}

/// bee-js's `splitPath`, with lengths in bytes (F-3).
fn split(path: &str) -> Split<'_> {
    if path.len() <= NAME {
        return Split::Name(path);
    }
    for (i, _) in path.rmatch_indices('/') {
        let (prefix, name) = (&path[..i], &path[i + 1..]);
        if name.len() <= NAME && prefix.len() <= PREFIX {
            return Split::Prefixed { prefix, name };
        }
    }
    let last = path.rfind('/').map_or(path, |i| &path[i + 1..]);
    Split::LongLink {
        name: cut(last, NAME),
    }
}

/// The longest prefix of `s` of at most `max` bytes that ends on a
/// character boundary: what Node's `Buffer.write` keeps of a string given
/// `max` bytes.
fn cut(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// `value` as `digits` zero-padded octal digits into `out`.
fn octal(out: &mut [u8], value: u64, digits: usize) {
    let mut v = value;
    for i in (0..digits).rev() {
        out[i] = b'0' + (v & 7) as u8;
        v >>= 3;
    }
}

/// Writes the checksum: the sum of the header's bytes with the checksum
/// field as spaces, six octal digits, a NUL and a space.
fn checksum(header: &mut [u8; BLOCK]) {
    header[148..156].copy_from_slice(b"        ");
    let sum: u64 = header.iter().map(|&b| u64::from(b)).sum();
    octal(&mut header[148..154], sum, 6);
    header[154] = 0;
    header[155] = b' ';
}

/// bee-js's `createHeader`.
fn header(name: &str, prefix: &str, size: u64, mtime: u64) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000777\0");
    h[108..116].copy_from_slice(b"0001750\0");
    h[116..124].copy_from_slice(b"0001750\0");
    octal(&mut h[124..135], size, 11);
    octal(&mut h[136..147], mtime, 11);
    h[156] = b'0';
    h[257..264].copy_from_slice(b"ustar\0\0");
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    checksum(&mut h);
    h
}

/// bee-js's `createLongLinkHeader`.
fn long_link_header(size: u64) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..13].copy_from_slice(b"././@LongLink");
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    octal(&mut h[124..135], size, 11);
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = b'L';
    h[257..264].copy_from_slice(b"ustar\0\0");
    checksum(&mut h);
    h
}

fn padding(len: u64) -> usize {
    (BLOCK - (len % BLOCK as u64) as usize) % BLOCK
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Open {
    size: u64,
    written: u64,
}

/// A tar body in the making: [`TarWriter::begin`] each entry, pass its
/// bytes (counted with [`TarWriter::data`]), [`TarWriter::end`] it, and
/// [`TarWriter::finish`] the archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarWriter {
    mtime: u64,
    open: Option<Open>,
}

impl TarWriter {
    /// A writer stamping every header with `mtime`, in whole seconds since
    /// the epoch: bee-js writes `Math.floor(Date.now() / 1000)`, which here
    /// comes from the caller's clock.
    pub fn new(mtime: u64) -> Result<Self, TarError> {
        if mtime > MAX_OCTAL_FIELD {
            return Err(TarError::Time(mtime));
        }
        Ok(Self { mtime, open: None })
    }

    /// The bytes before an entry's data: a long-link entry when the path
    /// needs one, then the entry's header. The entry stays open for its
    /// `size` bytes.
    pub fn begin(&mut self, path: &str, size: u64) -> Result<Vec<u8>, TarError> {
        if self.open.is_some() {
            return Err(TarError::EntryOpen);
        }
        if size > MAX_OCTAL_FIELD {
            return Err(TarError::Size(size));
        }
        let mut out = Vec::with_capacity(2 * BLOCK);
        let (name, prefix) = match split(path) {
            Split::Name(name) => (name, ""),
            Split::Prefixed { prefix, name } => (name, prefix),
            Split::LongLink { name } => {
                let len = path.len() as u64 + 1;
                out.extend_from_slice(&long_link_header(len));
                out.extend_from_slice(path.as_bytes());
                out.push(0);
                out.extend_from_slice(&PADDING[..padding(len)]);
                (name, "")
            }
        };
        out.extend_from_slice(&header(name, prefix, size, self.mtime));
        self.open = Some(Open { size, written: 0 });
        Ok(out)
    }

    /// Counts `len` bytes of the open entry's data, which the caller sends
    /// as they are. More than the entry's size is refused.
    pub fn data(&mut self, len: usize) -> Result<(), TarError> {
        let open = self.open.as_mut().ok_or(TarError::NoEntry)?;
        let written = open.written.saturating_add(len as u64);
        if written > open.size {
            return Err(TarError::Length {
                size: open.size,
                written,
            });
        }
        open.written = written;
        Ok(())
    }

    /// Ends the open entry, which must have had all its bytes: the zeros
    /// that pad it to a block.
    pub fn end(&mut self) -> Result<&'static [u8], TarError> {
        let open = self.open.ok_or(TarError::NoEntry)?;
        if open.written != open.size {
            return Err(TarError::Length {
                size: open.size,
                written: open.written,
            });
        }
        self.open = None;
        Ok(&PADDING[..padding(open.size)])
    }

    /// The archive's end, once no entry is open.
    pub fn finish(self) -> Result<&'static [u8; 2 * BLOCK], TarError> {
        if self.open.is_some() {
            return Err(TarError::EntryOpen);
        }
        Ok(&END)
    }
}

/// A whole tar body for `entries` (path, bytes), in their order: the
/// streaming writer run over data in memory.
pub fn write(entries: &[(&str, &[u8])], mtime: u64) -> Result<Vec<u8>, TarError> {
    let mut writer = TarWriter::new(mtime)?;
    let mut out = Vec::new();
    for (path, data) in entries {
        out.extend_from_slice(&writer.begin(path, data.len() as u64)?);
        writer.data(data.len())?;
        out.extend_from_slice(data);
        out.extend_from_slice(writer.end()?);
    }
    out.extend_from_slice(writer.finish()?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn paths_split_as_bee_js_splits_ascii() {
        let a100 = "a".repeat(100);
        assert_eq!(split(&a100), Split::Name(&a100));
        let p = format!("{}/{}", "d".repeat(155), "n".repeat(100));
        assert_eq!(
            split(&p),
            Split::Prefixed {
                prefix: &p[..155],
                name: &p[156..]
            }
        );
        // The rightmost slash that fits wins.
        let p = format!("{}/{}/{}", "a".repeat(50), "b".repeat(50), "c".repeat(60));
        assert_eq!(
            split(&p),
            Split::Prefixed {
                prefix: &p[..101],
                name: &p[102..]
            }
        );
        let long = "x".repeat(101);
        assert_eq!(split(&long), Split::LongLink { name: &long[..100] });
        let p = format!("{}/{}", "d".repeat(156), "n".repeat(10));
        assert_eq!(split(&p), Split::LongLink { name: &p[157..] });
    }

    /// F-3: 64 characters of 2 bytes and a `.txt`: 124 bytes, 64 units.
    /// bee-js writes it as a name and cuts it at 100 bytes; here it takes a
    /// long link, and the header's name is the same cut.
    #[test]
    fn a_long_non_ascii_name_is_kept() {
        let name = format!("{}.txt", "é".repeat(60));
        assert_eq!((name.len(), name.encode_utf16().count()), (124, 64));
        match split(&name) {
            Split::LongLink { name: cut } => assert_eq!(cut.len(), 100),
            other => panic!("{other:?}"),
        }
        // A 3-byte character astride byte 100 is left out whole.
        let name = format!("{}{}", "a".repeat(99), "€€");
        assert_eq!(split(&name), Split::LongLink { name: &name[..99] });
    }

    #[test]
    fn the_writer_holds_entries_to_their_size() {
        let mut w = TarWriter::new(0).unwrap();
        assert_eq!(w.data(1), Err(TarError::NoEntry));
        assert_eq!(w.end(), Err(TarError::NoEntry));
        w.begin("a", 3).unwrap();
        assert_eq!(w.begin("b", 0), Err(TarError::EntryOpen));
        w.data(2).unwrap();
        assert_eq!(
            w.end(),
            Err(TarError::Length {
                size: 3,
                written: 2
            })
        );
        assert_eq!(
            w.data(2),
            Err(TarError::Length {
                size: 3,
                written: 4
            })
        );
        w.data(1).unwrap();
        assert_eq!(w.end().unwrap().len(), 509);
        w.begin("c", 512).unwrap();
        assert_eq!(w.clone().finish(), Err(TarError::EntryOpen));
        w.data(512).unwrap();
        assert_eq!(w.end().unwrap().len(), 0);
        assert_eq!(w.finish().unwrap().len(), 1024);
    }

    #[test]
    fn fields_past_eleven_octal_digits_are_refused() {
        assert_eq!(
            TarWriter::new(MAX_OCTAL_FIELD + 1),
            Err(TarError::Time(MAX_OCTAL_FIELD + 1))
        );
        let mut w = TarWriter::new(MAX_OCTAL_FIELD).unwrap();
        assert_eq!(
            w.begin("a", MAX_OCTAL_FIELD + 1),
            Err(TarError::Size(MAX_OCTAL_FIELD + 1))
        );
        assert!(w.begin("a", MAX_OCTAL_FIELD).is_ok());
    }
}
