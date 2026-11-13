//! 0005's fee check (A), as the reference's `wallet/fee-check.js` judges a
//! send (design 0012, "The fee check"): the reference fee from the core's
//! own `chain.fee_reference` evidence (`readEvidence`, `referenceFee`), and
//! the verdict on a transaction's fees (`judgeFees`).
//!
//! - **At minting,** a send above the threshold gets no token without
//!   `fee_ack`, and the reply carries the [`Verdict`] for the screen.
//! - **Under a standing rule,** a send is covered only when
//!   [`Verdict::auto_approve`]: a reference from more than one endpoint, and
//!   a fee no more than [`FEE_CHECK_MULTIPLE`] times it.
//!
//! The evidence is the reply the core served for the chain, read from its
//! JSON as the reference reads it; how old it may be is judged here, on the
//! vault's clock from when it was asked for, and the header's time on the
//! wall clock. Time comes in as parameters (AGENTS rule 2).
//!
//! The reference computes in `BigInt`. The amounts here fit in [`Wei`]'s
//! 640 bits: a reply's decimals have at most 78 digits, and a
//! transaction's fields are 256-bit quantities.

use fc_evm::U256;
use serde_json::Value;

/// The threshold: a fee above three times the reference.
pub const FEE_CHECK_MULTIPLE: u64 = 3;

/// The priority fee a header reference adds when no quote names one
/// (0.05 gwei).
pub const MIN_PRIORITY_FEE_WEI: u64 = 50_000_000;

/// How old the evidence may be: its header by the wall clock, its quote
/// since it was asked for.
pub const EVIDENCE_MAX_AGE_MS: u64 = 60_000;

/// An amount in wei, wide enough for every product the check makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Wei(wide::Wide);

impl Wei {
    /// The reference's `decimal()`: `0`, or up to 78 digits with no leading
    /// zero.
    pub fn parse_decimal(text: &str) -> Option<Wei> {
        let bytes = text.as_bytes();
        let canonical = !bytes.is_empty()
            && bytes.len() <= 78
            && bytes.iter().all(u8::is_ascii_digit)
            && (bytes.len() == 1 || bytes[0] != b'0');
        canonical.then(|| Wei(wide::Wide::from_decimal(bytes)))
    }

    /// Any decimal digits that fit (at most 192), leading zeros allowed: a
    /// reference fee or a cost as the check writes it.
    pub fn from_digits(text: &str) -> Option<Wei> {
        let bytes = text.as_bytes();
        let digits =
            !bytes.is_empty() && bytes.len() <= 192 && bytes.iter().all(u8::is_ascii_digit);
        digits.then(|| Wei(wide::Wide::from_decimal(bytes)))
    }

    pub fn from_u256(value: &U256) -> Wei {
        Wei(wide::Wide::from_be_bytes(&value.to_be_bytes()))
    }

    pub fn from_u64(value: u64) -> Wei {
        Wei(wide::Wide::from_u64(value))
    }

    /// Its decimal digits, as `BigInt.toString()` writes them.
    pub fn to_decimal(&self) -> String {
        self.0.to_decimal()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

/// A verified header, as the reference's `readHeader` keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub number: Wei,
    /// In seconds.
    pub timestamp: Wei,
    /// None for a chain without EIP-1559.
    pub base_fee: Option<Wei>,
}

/// A combined quote's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteType {
    Eip1559,
    Legacy,
}

impl QuoteType {
    pub fn name(self) -> &'static str {
        match self {
            QuoteType::Eip1559 => "eip1559",
            QuoteType::Legacy => "legacy",
        }
    }
}

/// A direct quote, as the reference's `readQuote` keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    pub kind: QuoteType,
    /// `maxFeePerGas`, or a legacy quote's `gasPrice`.
    pub per_gas: Wei,
    /// How many endpoints answered.
    pub answered: u64,
}

/// The evidence one `chain.fee_reference` reply gives (`readEvidence`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// When it was asked for, on the vault's clock.
    pub requested_at_ms: u64,
    pub header: Option<Header>,
    pub lowest_priority: Option<Wei>,
    pub quote: Option<Quote>,
}

/// Where a reference fee comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    Header,
    Quote,
}

impl Basis {
    pub fn name(self) -> &'static str {
        match self {
            Basis::Header => "header",
            Basis::Quote => "quote",
        }
    }
}

/// The reference fee per gas (`referenceFee`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub fee: Wei,
    pub basis: Basis,
    /// A quote only one endpoint answered: never auto-approved.
    pub one_endpoint: bool,
}

/// A transaction's fee fields, as the core parsed them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fees {
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub gas_price: Option<U256>,
    pub gas_limit: Option<U256>,
}

/// The verdict on a transaction's fees (`judgeFees`), for the screen and
/// for a standing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The fee per gas times the gas limit, in decimal, when both are named.
    pub max_cost: Option<String>,
    /// Whether there was a reference to compare the fee with.
    pub comparable: bool,
    /// The fee as a multiple of the reference, to a tenth below 10, whole
    /// from 10 (rounded half up).
    pub ratio: Option<String>,
    /// Above [`FEE_CHECK_MULTIPLE`] times the reference.
    pub above: bool,
    pub one_endpoint: bool,
    pub basis: Option<Basis>,
    /// What a standing rule may answer: comparable, not above, and not one
    /// endpoint's reference.
    pub auto_approve: bool,
}

fn decimal(value: Option<&Value>) -> Option<Wei> {
    value.and_then(Value::as_str).and_then(Wei::parse_decimal)
}

fn read_header(header: Option<&Value>) -> Option<Header> {
    let header = header.filter(|header| header.is_object())?;
    if header.get("source").and_then(Value::as_str) != Some("colibri") {
        return None;
    }
    let number = decimal(header.get("number"))?;
    let timestamp = decimal(header.get("timestamp"))?;
    let base_fee = match header.get("base_fee") {
        Some(Value::Null) => None,
        other => Some(decimal(other)?),
    };
    Some(Header {
        number,
        timestamp,
        base_fee,
    })
}

/// `Number.isSafeInteger(n) && n >= 1`.
fn answered(value: Option<&Value>) -> Option<u64> {
    let n = value.and_then(Value::as_f64)?;
    let safe = n.fract() == 0.0 && (1.0..=9_007_199_254_740_991.0).contains(&n);
    safe.then_some(n as u64)
}

fn read_quote(quote: Option<&Value>) -> Option<Quote> {
    let quote = quote.filter(|quote| quote.is_object())?;
    if quote.get("source").and_then(Value::as_str) != Some("direct") {
        return None;
    }
    let answered = answered(quote.get("answered"))?;
    let (kind, per_gas) = match quote.get("type").and_then(Value::as_str) {
        Some("eip1559") => (QuoteType::Eip1559, decimal(quote.get("maxFeePerGas"))?),
        Some("legacy") => (QuoteType::Legacy, decimal(quote.get("gasPrice"))?),
        _ => return None,
    };
    Some(Quote {
        kind,
        per_gas,
        answered,
    })
}

impl Evidence {
    /// `readEvidence`: a `chain.fee_reference` reply's JSON, asked for at
    /// `requested_at_ms` (the vault's clock). What doesn't read as the
    /// reference reads it is none.
    pub fn read(reply: &Value, requested_at_ms: u64) -> Evidence {
        let reply = Some(reply).filter(|reply| reply.is_object());
        let field = |name: &str| reply.and_then(|reply| reply.get(name));
        Evidence {
            requested_at_ms,
            header: read_header(field("header")),
            lowest_priority: match field("lowest_priority") {
                Some(Value::Null) => None,
                other => decimal(other),
            },
            quote: read_quote(field("quote")),
        }
    }
}

/// `referenceFee`: the header's (twice its base fee, plus the lowest
/// priority fee quoted or [`MIN_PRIORITY_FEE_WEI`]) while its time is
/// within [`EVIDENCE_MAX_AGE_MS`] of the wall clock either way; otherwise
/// the quote's, while the evidence is that young on the vault's clock. None
/// without either, or for a fee of 0.
pub fn reference_fee(
    evidence: Option<&Evidence>,
    wall_now_ms: u64,
    monotonic_now_ms: u64,
) -> Option<Reference> {
    let evidence = evidence?;
    let max_age = i128::from(EVIDENCE_MAX_AGE_MS);
    let mut reference = None;
    if let Some(header) = &evidence.header
        && let Some(base_fee) = header.base_fee
    {
        let fresh = header.timestamp.0.to_u64().is_some_and(|seconds| {
            (i128::from(wall_now_ms) - i128::from(seconds) * 1000).abs() <= max_age
        });
        if fresh {
            let priority = evidence
                .lowest_priority
                .unwrap_or(Wei::from_u64(MIN_PRIORITY_FEE_WEI));
            reference = Some(Reference {
                fee: Wei(base_fee.0.mul_small(2).add(&priority.0)),
                basis: Basis::Header,
                one_endpoint: false,
            });
        }
    }
    if reference.is_none()
        && let Some(quote) = &evidence.quote
        && i128::from(monotonic_now_ms) - i128::from(evidence.requested_at_ms) <= max_age
    {
        reference = Some(Reference {
            fee: quote.per_gas,
            basis: Basis::Quote,
            one_endpoint: quote.answered == 1,
        });
    }
    reference.filter(|reference| !reference.fee.is_zero())
}

/// `feePerGas`: `maxFeePerGas` when the priority fee is named too, else
/// `gasPrice`.
fn fee_per_gas(fees: &Fees) -> Option<Wei> {
    match (&fees.max_fee_per_gas, &fees.max_priority_fee_per_gas) {
        (Some(max_fee), Some(_)) => Some(Wei::from_u256(max_fee)),
        _ => fees.gas_price.as_ref().map(Wei::from_u256),
    }
}

/// `ratioText`: `fee / reference` to a tenth, rounded half up, or whole
/// from 10.
fn ratio_text(fee: &wide::Wide, reference: &wide::Wide) -> String {
    let half = reference.div(&wide::Wide::from_u64(2));
    let tenths = fee.mul_small(10).add(&half).div(reference);
    if tenths >= wide::Wide::from_u64(100) {
        return fee.add(&half).div(reference).to_decimal();
    }
    // Below 100 tenths: one limb.
    let tenths = tenths.to_u64().unwrap_or(0);
    let (whole, rest) = (tenths / 10, tenths % 10);
    if rest == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{rest}")
    }
}

/// `judgeFees`: the verdict on a transaction's fees against the reference.
pub fn judge_fees(fees: &Fees, reference: Option<&Reference>) -> Verdict {
    let per_gas = fee_per_gas(fees);
    let gas_limit = fees.gas_limit.as_ref().map(Wei::from_u256);
    let max_cost = match (per_gas, gas_limit) {
        (Some(per_gas), Some(gas_limit)) => Some(per_gas.0.mul(&gas_limit.0).to_decimal()),
        _ => None,
    };
    let (Some(reference), Some(per_gas)) = (reference, per_gas) else {
        return Verdict {
            max_cost,
            comparable: false,
            ratio: None,
            above: false,
            one_endpoint: false,
            basis: None,
            auto_approve: false,
        };
    };
    let above = per_gas.0 > reference.fee.0.mul_small(FEE_CHECK_MULTIPLE);
    Verdict {
        max_cost,
        comparable: true,
        ratio: Some(ratio_text(&per_gas.0, &reference.fee.0)),
        above,
        one_endpoint: reference.one_endpoint,
        basis: Some(reference.basis),
        auto_approve: !above && !reference.one_endpoint,
    }
}

/// An unsigned integer of 640 bits, little-endian limbs: enough for a
/// product of two 256-bit quantities and for a reference fee from 78-digit
/// decimals, with room for the ratio's arithmetic. Every operation the
/// check makes stays inside it; one that wouldn't wraps.
mod wide {
    const LIMBS: usize = 10;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct Wide([u64; LIMBS]);

    impl Ord for Wide {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.iter().rev().cmp(other.0.iter().rev())
        }
    }

    impl PartialOrd for Wide {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Wide {
        const ZERO: Wide = Wide([0; LIMBS]);

        pub(super) fn from_u64(value: u64) -> Wide {
            let mut limbs = [0; LIMBS];
            limbs[0] = value;
            Wide(limbs)
        }

        pub(super) fn from_be_bytes(bytes: &[u8; 32]) -> Wide {
            let mut limbs = [0; LIMBS];
            for (index, chunk) in bytes.rchunks(8).enumerate() {
                let mut word = [0u8; 8];
                word.copy_from_slice(chunk);
                limbs[index] = u64::from_be_bytes(word);
            }
            Wide(limbs)
        }

        /// ASCII digits, already checked.
        pub(super) fn from_decimal(digits: &[u8]) -> Wide {
            digits.iter().fold(Wide::ZERO, |value, digit| {
                value
                    .mul_small(10)
                    .add(&Wide::from_u64(u64::from(digit - b'0')))
            })
        }

        pub(super) fn is_zero(&self) -> bool {
            self.0.iter().all(|limb| *limb == 0)
        }

        pub(super) fn to_u64(self) -> Option<u64> {
            self.0[1..]
                .iter()
                .all(|limb| *limb == 0)
                .then_some(self.0[0])
        }

        pub(super) fn add(&self, other: &Wide) -> Wide {
            let mut out = [0; LIMBS];
            let mut carry = 0u128;
            for (index, slot) in out.iter_mut().enumerate() {
                let sum = u128::from(self.0[index]) + u128::from(other.0[index]) + carry;
                *slot = sum as u64;
                carry = sum >> 64;
            }
            Wide(out)
        }

        fn sub(&self, other: &Wide) -> Wide {
            let mut out = [0; LIMBS];
            let mut borrow = 0u64;
            for (index, slot) in out.iter_mut().enumerate() {
                let (step, first) = self.0[index].overflowing_sub(other.0[index]);
                let (step, second) = step.overflowing_sub(borrow);
                *slot = step;
                borrow = u64::from(first || second);
            }
            Wide(out)
        }

        pub(super) fn mul_small(&self, factor: u64) -> Wide {
            let mut out = [0; LIMBS];
            let mut carry = 0u128;
            for (index, slot) in out.iter_mut().enumerate() {
                let product = u128::from(self.0[index]) * u128::from(factor) + carry;
                *slot = product as u64;
                carry = product >> 64;
            }
            Wide(out)
        }

        pub(super) fn mul(&self, other: &Wide) -> Wide {
            let mut out = [0u64; LIMBS];
            for i in 0..LIMBS {
                if self.0[i] == 0 {
                    continue;
                }
                let mut carry = 0u128;
                for j in 0..(LIMBS - i) {
                    let current = u128::from(out[i + j])
                        + u128::from(self.0[i]) * u128::from(other.0[j])
                        + carry;
                    out[i + j] = current as u64;
                    carry = current >> 64;
                }
            }
            Wide(out)
        }

        fn bit(&self, index: usize) -> bool {
            (self.0[index / 64] >> (index % 64)) & 1 == 1
        }

        fn shl1(&self) -> Wide {
            let mut out = [0; LIMBS];
            let mut carry = 0;
            for (index, slot) in out.iter_mut().enumerate() {
                *slot = (self.0[index] << 1) | carry;
                carry = self.0[index] >> 63;
            }
            Wide(out)
        }

        /// The quotient, by long division; zero for a divisor of zero (the
        /// check never divides by one).
        pub(super) fn div(&self, divisor: &Wide) -> Wide {
            if divisor.is_zero() {
                return Wide::ZERO;
            }
            let mut quotient = [0u64; LIMBS];
            let mut remainder = Wide::ZERO;
            for index in (0..LIMBS * 64).rev() {
                remainder = remainder.shl1();
                if self.bit(index) {
                    remainder.0[0] |= 1;
                }
                if remainder >= *divisor {
                    remainder = remainder.sub(divisor);
                    quotient[index / 64] |= 1 << (index % 64);
                }
            }
            Wide(quotient)
        }

        fn div_rem_small(&self, divisor: u64) -> (Wide, u64) {
            let mut out = [0; LIMBS];
            let mut remainder = 0u128;
            for index in (0..LIMBS).rev() {
                let current = (remainder << 64) | u128::from(self.0[index]);
                out[index] = (current / u128::from(divisor)) as u64;
                remainder = current % u128::from(divisor);
            }
            (Wide(out), remainder as u64)
        }

        pub(super) fn to_decimal(self) -> String {
            const CHUNK: u64 = 10_000_000_000_000_000_000; // 10^19
            let mut chunks = Vec::new();
            let mut rest = self;
            while !rest.is_zero() {
                let (quotient, remainder) = rest.div_rem_small(CHUNK);
                chunks.push(remainder);
                rest = quotient;
            }
            let mut out = chunks.last().map_or_else(|| "0".to_owned(), u64::to_string);
            for chunk in chunks.iter().rev().skip(1) {
                out.push_str(&format!("{chunk:019}"));
            }
            out
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn of(text: &str) -> Wide {
            Wide::from_decimal(text.as_bytes())
        }

        #[test]
        fn arithmetic() {
            let max256 =
                "115792089237316195423570985008687907853269984665640564039457584007913129639935";
            let product = of(max256).mul(&of(max256));
            assert_eq!(
                product.to_decimal(),
                "13407807929942597099574024998205846127479365820592393377723561443721764030073315392623399665776056285720014482370779510884422601683867654778417822746804225"
            );
            assert_eq!(product.div(&of(max256)), of(max256));
            assert_eq!(of("1000").div(&of("7")).to_decimal(), "142");
            assert_eq!(of("0").to_decimal(), "0");
            assert_eq!(
                of("12345678901234567890123").mul_small(10).to_decimal(),
                "123456789012345678901230"
            );
            assert_eq!(of("5").div(&Wide::ZERO), Wide::ZERO);
        }
    }
}
