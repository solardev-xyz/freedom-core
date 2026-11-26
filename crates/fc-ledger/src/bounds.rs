//! What a Ledger can carry (design 0016, "Bounds", deviation
//! `device-bounds`): anything past these is refused `LEDGER_TOO_LARGE`
//! before the first APDU.

/// APDUs in one operation, all of them: the address check and `B0 01`
/// included.
pub const MAX_APDUS: usize = 2048;
/// A typed-data value's bytes: its 2-byte length can say no more.
pub const MAX_VALUE: usize = 65_535;
/// An array's entries, a fixed array's size, a number of dimensions, a
/// type or field name's bytes: each is sent in one byte.
pub const MAX_BYTE: usize = 255;

/// Which bound an input is past, and by how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Bound {
    #[error("an array of {0} entries")]
    ArrayEntries(usize),
    #[error("a fixed array size of {0}")]
    FixedSize(u64),
    #[error("{0} array dimensions")]
    Dimensions(usize),
    #[error("a name of {0} characters")]
    Name(usize),
    /// A definition APDU's data: a field's descriptor.
    #[error("a definition of {0} bytes")]
    Definition(usize),
    #[error("a value of {0} bytes")]
    Value(usize),
    /// More than [`MAX_APDUS`] (counted up to the first past it).
    #[error("more than {MAX_APDUS} APDUs")]
    Apdus,
}
