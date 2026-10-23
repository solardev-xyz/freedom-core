//! A minimal unsigned 256-bit integer: parsing, comparison, two's complement
//! and big-endian bytes. Enough for transaction fields and EIP-712 values.

use core::cmp::Ordering;

/// Little-endian 64-bit limbs.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct U256([u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    pub fn from_u64(value: u64) -> Self {
        U256([value, 0, 0, 0])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    /// The value as a u64, if it fits.
    pub fn to_u64(&self) -> Option<u64> {
        (self.0[1..] == [0; 3]).then_some(self.0[0])
    }

    /// Number of significant bits.
    pub fn bits(&self) -> u32 {
        for (index, limb) in self.0.iter().enumerate().rev() {
            if *limb != 0 {
                return 64 * index as u32 + (64 - limb.leading_zeros());
            }
        }
        0
    }

    /// `2^bits - 1`, for `bits` in `0..=256`.
    pub fn mask(bits: u32) -> Self {
        let mut limbs = [0u64; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let low = 64 * index as u32;
            if bits >= low + 64 {
                *limb = u64::MAX;
            } else if bits > low {
                *limb = (1u64 << (bits - low)) - 1;
            }
        }
        U256(limbs)
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, limb) in self.0.iter().enumerate() {
            out[24 - 8 * index..32 - 8 * index].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 32 {
            return None;
        }
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(bytes);
        let mut limbs = [0u64; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&padded[24 - 8 * index..32 - 8 * index]);
            *limb = u64::from_be_bytes(chunk);
        }
        Some(U256(limbs))
    }

    /// Big-endian bytes without leading zeros (empty for zero), as RLP
    /// encodes integers.
    pub fn to_minimal_be(&self) -> Vec<u8> {
        let bytes = self.to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(32);
        bytes[start..].to_vec()
    }

    /// `self * mul + add`, or `None` on overflow.
    fn mul_add_small(&self, mul: u64, add: u64) -> Option<Self> {
        let mut limbs = [0u64; 4];
        let mut carry = u128::from(add);
        for (out, limb) in limbs.iter_mut().zip(self.0) {
            let product = u128::from(limb) * u128::from(mul) + carry;
            *out = product as u64;
            carry = product >> 64;
        }
        (carry == 0).then_some(U256(limbs))
    }

    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        let mut limbs = [0u64; 4];
        let mut carry = false;
        for ((out, a), b) in limbs.iter_mut().zip(self.0).zip(other.0) {
            let (sum, c1) = a.overflowing_add(b);
            let (sum, c2) = sum.overflowing_add(u64::from(carry));
            *out = sum;
            carry = c1 || c2;
        }
        (!carry).then_some(U256(limbs))
    }

    /// Two's complement negation modulo 2^256.
    pub fn wrapping_neg(&self) -> Self {
        let inverted = U256(self.0.map(|limb| !limb));
        let mut limbs = [0u64; 4];
        let mut carry = true;
        for (out, limb) in limbs.iter_mut().zip(inverted.0) {
            let (sum, c) = limb.overflowing_add(u64::from(carry));
            *out = sum;
            carry = c;
        }
        U256(limbs)
    }

    /// `(self / divisor, self % divisor)` for a nonzero `divisor`.
    fn div_rem_small(&self, divisor: u64) -> (Self, u64) {
        let mut limbs = [0u64; 4];
        let mut remainder = 0u128;
        for (out, limb) in limbs.iter_mut().zip(self.0).rev() {
            let current = (remainder << 64) | u128::from(limb);
            *out = (current / u128::from(divisor)) as u64;
            remainder = current % u128::from(divisor);
        }
        (U256(limbs), remainder as u64)
    }

    /// The decimal digits, without leading zeros (`"0"` for zero), as
    /// `BigInt.toString()` writes them.
    pub fn to_decimal(&self) -> String {
        const CHUNK: u64 = 10_000_000_000_000_000_000; // 10^19
        let mut chunks = Vec::new();
        let mut rest = *self;
        while !rest.is_zero() {
            let (quotient, remainder) = rest.div_rem_small(CHUNK);
            chunks.push(remainder);
            rest = quotient;
        }
        let mut out = chunks
            .last()
            .map(u64::to_string)
            .unwrap_or_else(|| "0".into());
        for chunk in chunks.iter().rev().skip(1) {
            out.push_str(&format!("{chunk:019}"));
        }
        out
    }

    /// Decimal digits only (at least one; leading zeros allowed).
    pub fn parse_decimal(digits: &str) -> Option<Self> {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.bytes().try_fold(U256::ZERO, |value, digit| {
            value.mul_add_small(10, u64::from(digit - b'0'))
        })
    }

    /// Hex digits only, either case (at least one; leading zeros allowed).
    pub fn parse_hex(digits: &str) -> Option<Self> {
        if digits.is_empty() {
            return None;
        }
        digits.chars().try_fold(U256::ZERO, |value, digit| {
            value.mul_add_small(16, u64::from(digit.to_digit(16)?))
        })
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A quantity string: `[-]` then decimal digits, or `0x`/`0X` and hex digits.
/// Stricter than ethers' `getBigInt`, which passes strings to JS `BigInt()`
/// and so also takes whitespace, `+`, `0b`/`0o` and a lone `-` as zero
/// (design 0002).
pub fn parse_signed(text: &str) -> Option<(bool, U256)> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let magnitude = match rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        Some(hex) => U256::parse_hex(hex)?,
        None => U256::parse_decimal(rest)?,
    };
    // -0 is 0.
    Some((negative && !magnitude.is_zero(), magnitude))
}

/// An unsigned quantity string (no sign).
pub fn parse_unsigned(text: &str) -> Option<U256> {
    match parse_signed(text)? {
        (false, value) if !text.starts_with('-') => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_bounds() {
        assert_eq!(U256::parse_decimal("0"), Some(U256::ZERO));
        assert_eq!(U256::parse_decimal("00012"), Some(U256::from_u64(12)));
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(U256::parse_decimal(max), Some(U256::MAX));
        assert_eq!(U256::parse_decimal(&format!("{max}0")), None);
        assert_eq!(U256::parse_hex(&"f".repeat(64)), Some(U256::MAX));
        assert_eq!(U256::parse_hex(&"f".repeat(65)), None);
        assert_eq!(
            U256::parse_hex(&format!("0{}", "f".repeat(64))),
            Some(U256::MAX)
        );
        for bad in [
            "", " 1", "1 ", "+1", "1e3", "0b1", "0o7", "-", "--1", "0x", "1_0",
        ] {
            assert_eq!(parse_signed(bad), None, "{bad:?}");
        }
        assert_eq!(parse_signed("-0x10"), Some((true, U256::from_u64(16))));
        assert_eq!(parse_signed("-0"), Some((false, U256::ZERO)));
        assert_eq!(parse_unsigned("-0"), None);
        assert_eq!(parse_unsigned("0X1F"), Some(U256::from_u64(31)));
    }

    #[test]
    fn decimal_digits() {
        assert_eq!(U256::ZERO.to_decimal(), "0");
        assert_eq!(U256::from_u64(7).to_decimal(), "7");
        assert_eq!(U256::from_u64(u64::MAX).to_decimal(), u64::MAX.to_string());
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(U256::MAX.to_decimal(), max);
        for digits in [
            "10000000000000000000",
            "9999999999999999999",
            "100000000000000000000000000000000000000",
            "123456789012345678901234567890",
        ] {
            assert_eq!(U256::parse_decimal(digits).unwrap().to_decimal(), digits);
        }
    }

    #[test]
    fn arithmetic() {
        assert_eq!(U256::MAX.bits(), 256);
        assert_eq!(U256::from_u64(1).bits(), 1);
        assert_eq!(U256::ZERO.bits(), 0);
        assert_eq!(U256::mask(8), U256::from_u64(255));
        assert_eq!(U256::mask(256), U256::MAX);
        assert_eq!(U256::from_u64(1).wrapping_neg(), U256::MAX);
        assert_eq!(U256::ZERO.wrapping_neg(), U256::ZERO);
        assert_eq!(U256::MAX.checked_add(&U256::from_u64(1)), None);
        assert_eq!(U256::from_u64(0x1234).to_minimal_be(), vec![0x12, 0x34]);
        assert!(U256::ZERO.to_minimal_be().is_empty());
        assert_eq!(U256::from_be_slice(&[1, 0]), Some(U256::from_u64(256)));
        assert!(U256::from_u64(2) > U256::from_u64(1));
        assert!(U256::MAX > U256::mask(255));
    }
}
