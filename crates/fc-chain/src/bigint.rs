//! The integers `BigInt(value)` gives, as far as the router uses them:
//! parsing strings and doubles, comparing, subtracting, and printing in
//! hex and decimal.
//!
//! Hex, octal and binary convert in linear time, at any width. Decimal
//! conversions take time quadratic in the width, so they are bounded
//! (deviation `bigint-width`): decimal input wider than [`MAX_DECIMAL_BITS`]
//! bits is [`Parsed::TooWide`], and so is a gas price. A fee computed from
//! an accepted gas price (`2 · baseFee + priority`) can be one bit wider,
//! and still prints.
//! Nothing EVM-sized comes near: quantities are at most 256 bits.

use std::cmp::Ordering;

use crate::js::trim;

/// The widest decimal input, and gas price, in bits (deviation
/// `bigint-width`); computed fees print one bit wider.
pub const MAX_DECIMAL_BITS: usize = 4096;

/// 2^4096 has 1,234 decimal digits: more significant digits are wider.
const MAX_DECIMAL_DIGITS: usize = 1234;

/// 10^19, the largest power of ten in a 64-bit limb.
const TEN_19: u64 = 10_000_000_000_000_000_000;

/// A JavaScript BigInt: a sign and a magnitude in little-endian 64-bit
/// limbs, without high zero limbs. Zero has no limbs and no sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BigInt {
    negative: bool,
    limbs: Vec<u64>,
}

/// What `BigInt(string)` gives, when it doesn't throw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    Value(BigInt),
    /// A decimal of 2^4096 or more, unconverted (`bigint-width`).
    TooWide {
        negative: bool,
    },
}

impl BigInt {
    pub(crate) fn zero() -> Self {
        Self {
            negative: false,
            limbs: Vec::new(),
        }
    }

    fn new(negative: bool, mut limbs: Vec<u64>) -> Self {
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
        Self {
            negative: negative && !limbs.is_empty(),
            limbs,
        }
    }

    pub(crate) fn from_u64(value: u64) -> Self {
        Self::new(false, vec![value])
    }

    pub(crate) fn is_negative(&self) -> bool {
        self.negative
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// What its limbs hold on the heap.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.limbs.capacity().saturating_mul(8)
    }

    /// The same value, its limbs holding no more than it needs: a value
    /// parsed from a long text with leading zeros keeps that text's room
    /// until it is compacted.
    pub(crate) fn compact(mut self) -> Self {
        self.limbs.shrink_to_fit();
        self
    }

    /// The magnitude's width in bits.
    pub(crate) fn bits(&self) -> usize {
        self.limbs.last().map_or(0, |top| {
            64 * (self.limbs.len() - 1) + (64 - top.leading_zeros() as usize)
        })
    }

    /// `NumberToBigInt`: `None` (a RangeError) unless `x` is an integer.
    pub(crate) fn from_f64(x: f64) -> Option<Self> {
        if !x.is_finite() || x.fract() != 0.0 {
            return None;
        }
        let negative = x < 0.0;
        let magnitude = x.abs();
        if magnitude < 18_446_744_073_709_551_616.0 {
            // Exact: an integer below 2^64.
            return Some(Self::new(negative, vec![magnitude as u64]));
        }
        // magnitude = mantissa * 2^shift, with shift >= 12 at this size.
        let bits = magnitude.to_bits();
        let mantissa = (bits & ((1 << 52) - 1)) | (1 << 52);
        let shift = ((bits >> 52) & 0x7ff) as usize - 1075;
        let mut limbs = vec![0u64; shift / 64];
        let offset = shift % 64;
        limbs.push(mantissa << offset);
        if offset > 0 {
            limbs.push(mantissa >> (64 - offset));
        }
        Some(Self::new(negative, limbs))
    }

    /// `bigint.toString(16)`: lowercase, a `-` for negatives.
    pub(crate) fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        if self.negative {
            out.push('-');
        }
        let mut limbs = self.limbs.iter().rev();
        match limbs.next() {
            None => out.push('0'),
            Some(top) => {
                let _ = write!(out, "{top:x}");
                for limb in limbs {
                    let _ = write!(out, "{limb:016x}");
                }
            }
        }
        out
    }

    /// `bigint.toString()`. Quadratic in the width: callers keep it within
    /// [`MAX_DECIMAL_BITS`] (plus a bit for sums).
    pub(crate) fn to_decimal(&self) -> String {
        use std::fmt::Write as _;
        let mut limbs = self.limbs.clone();
        // Base-10^19 digits, least significant first.
        let mut chunks = Vec::new();
        while !limbs.is_empty() {
            let mut remainder: u128 = 0;
            for limb in limbs.iter_mut().rev() {
                let current = (remainder << 64) | u128::from(*limb);
                *limb = (current / u128::from(TEN_19)) as u64;
                remainder = current % u128::from(TEN_19);
            }
            chunks.push(remainder as u64);
            while limbs.last() == Some(&0) {
                limbs.pop();
            }
        }
        let mut out = String::new();
        if self.negative {
            out.push('-');
        }
        let mut chunks = chunks.iter().rev();
        match chunks.next() {
            None => out.push('0'),
            Some(top) => {
                let _ = write!(out, "{top}");
                for chunk in chunks {
                    let _ = write!(out, "{chunk:019}");
                }
            }
        }
        out
    }

    /// Compares two values, signs included.
    pub(crate) fn compare(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => compare_magnitudes(&self.limbs, &other.limbs),
            (true, true) => compare_magnitudes(&other.limbs, &self.limbs),
        }
    }

    /// `self - other` for `self >= other >= 0`.
    pub(crate) fn minus(&self, other: &Self) -> Self {
        let mut limbs = self.limbs.clone();
        let mut borrow = false;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let subtrahend = other.limbs.get(i).copied().unwrap_or(0);
            let (value, first) = limb.overflowing_sub(subtrahend);
            let (value, second) = value.overflowing_sub(u64::from(borrow));
            *limb = value;
            borrow = first || second;
        }
        Self::new(false, limbs)
    }

    /// `⌊self / 2⌋` for a non-negative value.
    pub(crate) fn half(&self) -> Self {
        let mut limbs = self.limbs.clone();
        let mut carry = 0u64;
        for limb in limbs.iter_mut().rev() {
            let low = *limb & 1;
            *limb = (*limb >> 1) | (carry << 63);
            carry = low;
        }
        Self::new(false, limbs)
    }

    /// `self · factor` for a non-negative value.
    pub(crate) fn times(&self, factor: u64) -> Self {
        let mut limbs = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u128;
        for limb in &self.limbs {
            let product = u128::from(*limb) * u128::from(factor) + carry;
            limbs.push(product as u64);
            carry = product >> 64;
        }
        limbs.push(carry as u64);
        Self::new(false, limbs)
    }

    /// `⌊self / divisor⌋` for a non-negative value and a divisor above 0.
    pub(crate) fn divided(&self, divisor: u64) -> Self {
        let mut limbs = self.limbs.clone();
        let mut remainder = 0u128;
        for limb in limbs.iter_mut().rev() {
            let value = (remainder << 64) | u128::from(*limb);
            *limb = (value / u128::from(divisor)) as u64;
            remainder = value % u128::from(divisor);
        }
        Self::new(false, limbs)
    }

    /// The greater of two values.
    pub(crate) fn max<'a>(&'a self, other: &'a Self) -> &'a Self {
        if other.compare(self) == Ordering::Greater {
            other
        } else {
            self
        }
    }

    /// The lesser of two values.
    pub(crate) fn min<'a>(&'a self, other: &'a Self) -> &'a Self {
        if other.compare(self) == Ordering::Less {
            other
        } else {
            self
        }
    }

    /// `self + other` for non-negative values.
    pub(crate) fn plus(&self, other: &Self) -> Self {
        let len = self.limbs.len().max(other.limbs.len());
        let mut limbs = Vec::with_capacity(len + 1);
        let mut carry = false;
        for i in 0..len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            let (value, first) = a.overflowing_add(b);
            let (value, second) = value.overflowing_add(u64::from(carry));
            limbs.push(value);
            carry = first || second;
        }
        limbs.push(u64::from(carry));
        Self::new(false, limbs)
    }
}

fn compare_magnitudes(a: &[u64], b: &[u64]) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

/// `BigInt(string)` (`StringToBigInt`): `None` where it throws a
/// SyntaxError.
///
/// - JavaScript whitespace around the number is removed; nothing left is 0.
/// - `0x`, `0o` and `0b` (either case) take at least one digit and no sign.
/// - Otherwise an optional `+` or `-`, then ASCII decimal digits: leading
///   zeros are fine, `-0` is 0.
pub(crate) fn parse_string(units: &[u16]) -> Option<Parsed> {
    let units = trim(units);
    if units.is_empty() {
        return Some(Parsed::Value(BigInt::zero()));
    }
    let bits_per_digit = match units {
        [0x30, 0x78 | 0x58, ..] => Some(4), // 0x 0X
        [0x30, 0x6f | 0x4f, ..] => Some(3), // 0o 0O
        [0x30, 0x62 | 0x42, ..] => Some(1), // 0b 0B
        _ => None,
    };
    if let Some(bits) = bits_per_digit {
        return from_power_of_two(units.get(2..)?, bits).map(Parsed::Value);
    }
    let (negative, digits) = match units {
        [0x2b, rest @ ..] => (false, rest), // +
        [0x2d, rest @ ..] => (true, rest),  // -
        _ => (false, units),
    };
    if digits.is_empty() || !digits.iter().all(|u| (0x30..=0x39).contains(u)) {
        return None;
    }
    let first = digits
        .iter()
        .position(|u| *u != 0x30)
        .unwrap_or(digits.len());
    let significant = digits.get(first..)?;
    if significant.len() > MAX_DECIMAL_DIGITS {
        return Some(Parsed::TooWide { negative });
    }
    let value = from_decimal(significant, negative);
    if value.bits() > MAX_DECIMAL_BITS {
        return Some(Parsed::TooWide { negative });
    }
    Some(Parsed::Value(value))
}

/// Hex, octal or binary digits, of `bits` bits each: linear in their
/// number.
fn from_power_of_two(digits: &[u16], bits: usize) -> Option<BigInt> {
    if digits.is_empty() {
        return None;
    }
    let radix = 1u32 << bits;
    let mut limbs = vec![0u64; (digits.len() * bits).div_ceil(64)];
    let mut position = 0usize;
    for unit in digits.iter().rev() {
        let digit = char::from_u32(u32::from(*unit))?.to_digit(radix)?;
        let (limb, offset) = (position / 64, position % 64);
        if let Some(slot) = limbs.get_mut(limb) {
            *slot |= u64::from(digit) << offset;
        }
        if offset + bits > 64
            && let Some(slot) = limbs.get_mut(limb + 1)
        {
            *slot |= u64::from(digit) >> (64 - offset);
        }
        position += bits;
    }
    Some(BigInt::new(false, limbs))
}

/// At most [`MAX_DECIMAL_DIGITS`] ASCII decimal digits.
fn from_decimal(digits: &[u16], negative: bool) -> BigInt {
    let mut limbs: Vec<u64> = Vec::new();
    let head = match digits.len() % 19 {
        0 => 19,
        n => n,
    };
    let mut rest = digits;
    let mut take = head.min(digits.len());
    while !rest.is_empty() {
        let (chunk, tail) = rest.split_at(take.min(rest.len()));
        let value = chunk
            .iter()
            .fold(0u64, |acc, u| acc * 10 + u64::from(*u - 0x30));
        let multiplier = 10u64.pow(chunk.len() as u32);
        let mut carry = u128::from(value);
        for limb in limbs.iter_mut() {
            let product = u128::from(*limb) * u128::from(multiplier) + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry > 0 {
            limbs.push(carry as u64);
        }
        rest = tail;
        take = 19;
    }
    BigInt::new(negative, limbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Option<String> {
        let units: Vec<u16> = text.encode_utf16().collect();
        match parse_string(&units)? {
            Parsed::Value(v) => Some(v.to_decimal()),
            Parsed::TooWide { negative } => Some(format!("too wide ({negative})")),
        }
    }

    #[test]
    fn strings_parse_like_v8() {
        for (text, value) in [
            ("0x", None),
            ("0x_1", None),
            ("1n", None),
            (" 0x10 ", Some("16")),
            ("-0x10", None),
            ("+0x10", None),
            ("0X1F", Some("31")),
            ("0B1", Some("1")),
            ("0O7", Some("7")),
            ("08", Some("8")),
            ("0777", Some("777")),
            ("-", None),
            ("+", None),
            ("", Some("0")),
            (" \u{feff}\u{2028} ", Some("0")),
            ("\u{0}", None),
            ("1e3", None),
            ("1.5", None),
            ("-0", Some("0")),
            ("+5", Some("5")),
            ("--1", None),
            ("- 1", None),
            ("Infinity", None),
            ("1_000", None),
            ("\u{661}", None),
            ("0b", None),
            ("0o8", None),
            ("0b2", None),
            ("00x1", None),
            ("0x1\n", Some("1")),
            ("-18446744073709551616", Some("-18446744073709551616")),
            ("0o1777777777777777777777", Some("18446744073709551615")),
            ("0x10000000000000000", Some("18446744073709551616")),
        ] {
            assert_eq!(parse(text).as_deref(), value, "{text:?}");
        }
    }

    #[test]
    fn decimal_width_is_bounded() {
        let max = BigInt::new(false, vec![u64::MAX; 64]);
        assert_eq!(max.bits(), MAX_DECIMAL_BITS);
        let decimal = max.to_decimal();
        assert_eq!(decimal.len(), MAX_DECIMAL_DIGITS);
        assert_eq!(parse(&decimal), Some(decimal.clone()));
        // 2^4096 has as many digits and is too wide.
        let over = max.plus(&BigInt::new(false, vec![1]));
        assert_eq!(over.bits(), MAX_DECIMAL_BITS + 1);
        assert_eq!(
            parse(&over.to_decimal()).as_deref(),
            Some("too wide (false)")
        );
        assert_eq!(
            parse(&format!("-{}", "9".repeat(5000))).as_deref(),
            Some("too wide (true)")
        );
        assert_eq!(parse(&format!("{}x", "9".repeat(5000))), None);
        // Leading zeros cost nothing.
        assert_eq!(
            parse(&format!("{}{decimal}", "0".repeat(100_000))),
            Some(decimal)
        );
        // Hex has no bound.
        let wide: Vec<u16> = format!("0x1{}", "0".repeat(5000)).encode_utf16().collect();
        let Some(Parsed::Value(value)) = parse_string(&wide) else {
            panic!()
        };
        assert_eq!(value.bits(), 20_001);
    }

    #[test]
    fn doubles_and_arithmetic() {
        for (x, hex) in [
            (0.0, Some("0")),
            (-0.0, Some("0")),
            (21000.0, Some("5208")),
            (-5.0, Some("-5")),
            (1e21, Some("3635c9adc5dea00000")),
            (9007199254740993.0, Some("20000000000000")),
            (18446744073709551616.0, Some("10000000000000000")),
            (1.5, None),
            (5e-324, None),
            (f64::INFINITY, None),
            (f64::NAN, None),
        ] {
            assert_eq!(
                BigInt::from_f64(x).map(|v| v.to_hex()).as_deref(),
                hex,
                "{x}"
            );
        }
        let max = BigInt::from_f64(f64::MAX).unwrap();
        assert_eq!(max.bits(), 1024);
        assert!(max.to_hex().starts_with("fffffffffffff8000"));
        let a = BigInt::new(false, vec![0, 1]);
        let b = BigInt::new(false, vec![1]);
        assert_eq!(a.minus(&b).to_hex(), "ffffffffffffffff");
        assert_eq!(a.minus(&b).plus(&b), a);
        assert_eq!(a.compare(&b), Ordering::Greater);
        assert_eq!(
            BigInt::new(true, vec![1]).compare(&BigInt::zero()),
            Ordering::Less
        );
        assert_eq!(
            BigInt::new(true, vec![2]).compare(&BigInt::new(true, vec![1])),
            Ordering::Less
        );
        assert_eq!(BigInt::zero().to_decimal(), "0");
        assert_eq!(
            BigInt::new(false, vec![TEN_19]).to_decimal(),
            "10000000000000000000"
        );
        // Halving carries across limbs and rounds down.
        assert_eq!(a.half().to_hex(), "8000000000000000");
        assert_eq!(
            BigInt::new(false, vec![1, 1]).half().to_hex(),
            "8000000000000000"
        );
        assert_eq!(BigInt::from_u64(17).half().to_decimal(), "8");
        assert_eq!(BigInt::from_u64(1).half(), BigInt::zero());
        assert_eq!(BigInt::zero().half(), BigInt::zero());
        assert_eq!(a.min(&b), &b);
        assert_eq!(b.min(&a), &b);
    }
}
