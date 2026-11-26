//! The SafeTx (design 0016, "Built and hashed in the core"): one CALL with
//! no refund, as protocol-kit's `createTransaction` makes it for
//! `safe-executor.js`'s `buildSafeTransaction`, its typed data as
//! `generateTypedData` writes it, its hash, and `execTransaction`'s
//! calldata.

use fc_evm::{
    U256, checksum_address, parse_address, parse_bytes, parse_unsigned, to_hex, typed_data_hash,
};
use fc_naming::abi::Token;
use serde_json::{Map, Value, json};

use crate::constants::CHAIN_ID;
use crate::{Error, address_word, call};

/// The largest Safe nonce: `Number.MAX_SAFE_INTEGER`. protocol-kit reads
/// the nonce as a JS number and ethers hashes none past it, and
/// safe-pending.json keeps it as a JSON number.
pub const MAX_NONCE: u64 = (1 << 53) - 1;

/// The most data a SafeTx carries (design 0016, "The pending store",
/// proposed): the executor's calldata stays far below what transaction
/// pools accept.
pub const MAX_DATA: usize = 64 * 1024;

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// The SafeTx's fields, in the order protocol-kit's `getEip712TxTypes`
/// lists them: `(type, name)`.
const SAFE_TX_TYPE: [(&str, &str); 10] = [
    ("address", "to"),
    ("uint256", "value"),
    ("bytes", "data"),
    ("uint8", "operation"),
    ("uint256", "safeTxGas"),
    ("uint256", "baseGas"),
    ("uint256", "gasPrice"),
    ("address", "gasToken"),
    ("address", "refundReceiver"),
    ("uint256", "nonce"),
];

/// A SafeTx as Freedom makes every one: `operation` CALL (0), `safeTxGas`,
/// `baseGas` and `gasPrice` 0, no gas token or refund receiver. Only `to`,
/// `value`, `data` and `nonce` vary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeTx {
    to: [u8; 20],
    value: U256,
    data: Vec<u8>,
    nonce: u64,
}

/// How a pending SafeTx stands against the Safe's nonce (design 0016, "The
/// executor").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceState {
    /// The Safe's nonce is the SafeTx's: it can execute.
    Ready,
    /// The Safe's nonce is past it: it never can, as today.
    Superseded,
    /// The Safe's nonce is below it: refused, `safe_nonce_behind`
    /// (deviation `nonce-behind`; the reference executes it).
    Behind,
}

impl SafeTx {
    /// Refuses a nonce above [`MAX_NONCE`] and data longer than
    /// [`MAX_DATA`].
    pub fn new(to: [u8; 20], value: U256, data: Vec<u8>, nonce: u64) -> Result<Self, Error> {
        if nonce > MAX_NONCE {
            return Err(Error::Nonce);
        }
        if data.len() > MAX_DATA {
            return Err(Error::DataTooLong);
        }
        Ok(SafeTx {
            to,
            value,
            data,
            nonce,
        })
    }

    /// A Safe nonce read from the chain, as the SafeTx's: refused above
    /// [`MAX_NONCE`].
    pub fn nonce_from(chain_nonce: &U256) -> Result<u64, Error> {
        chain_nonce
            .to_u64()
            .filter(|nonce| *nonce <= MAX_NONCE)
            .ok_or(Error::Nonce)
    }

    pub fn to(&self) -> &[u8; 20] {
        &self.to
    }

    pub fn value(&self) -> &U256 {
        &self.value
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// The SafeTx's fields as the reference keeps them (`safeTxData`, and
    /// the typed data's `message`), in its property order: `to`
    /// checksummed, `value` in decimal, `data` in lowercase hex, `operation`
    /// and `nonce` as numbers, the gas fields as `"0"`, both addresses zero.
    pub fn fields(&self) -> Value {
        fields_of(
            &self.to,
            &self.value,
            &self.data,
            &U256::from_u64(self.nonce),
        )
    }

    /// The SafeTx's fields read back, as [`SafeTx::fields`] writes them and
    /// safe-pending.json keeps them: refused when any operation, gas field,
    /// gas token or refund receiver isn't Freedom's ([`Error::Field`]), and
    /// when a field is missing, unknown or not in its shape
    /// ([`Error::Malformed`]). A number field reads as a JSON integer or as
    /// quantity text, decimal or `0x` hex (`value` as text only): an entry
    /// the reference wrote keeps the value a page gave, which may be hex.
    pub fn from_fields(fields: &Value) -> Result<Self, Error> {
        let fields = fields
            .as_object()
            .ok_or(Error::Malformed("the fields are not an object"))?;
        if fields.len() != SAFE_TX_TYPE.len() {
            return Err(Error::Malformed("not the ten SafeTx fields"));
        }
        let field = |name: &'static str| {
            fields
                .get(name)
                .ok_or(Error::Malformed("not the ten SafeTx fields"))
        };
        let text = |name: &'static str| {
            field(name)?
                .as_str()
                .ok_or(Error::Malformed("a field that isn't text"))
        };
        let to = parse_address(text("to")?).map_err(|_| Error::Malformed("to"))?;
        let value = parse_unsigned(text("value")?).ok_or(Error::Malformed("value"))?;
        let data = parse_bytes(text("data")?, "data").map_err(|_| Error::Malformed("data"))?;
        for name in ["operation", "safeTxGas", "baseGas", "gasPrice"] {
            if !quantity(field(name)?)?.is_zero() {
                return Err(Error::Field(name));
            }
        }
        for name in ["gasToken", "refundReceiver"] {
            let address = parse_address(text(name)?).map_err(|_| Error::Malformed(name))?;
            if address != [0; 20] {
                return Err(Error::Field(name));
            }
        }
        let nonce = Self::nonce_from(&quantity(field("nonce")?)?)?;
        SafeTx::new(to, value, data, nonce)
    }

    /// The typed data every owner signs, EIP712Domain included, as the
    /// reference keeps it with the pending SafeTx: the domain
    /// `{ verifyingContract: safe, chainId: 100 }`, then the fields.
    pub fn typed_data(&self, safe: &[u8; 20]) -> Value {
        safe_tx_typed_data(
            CHAIN_ID,
            safe,
            &self.to,
            &self.value,
            &self.data,
            &U256::from_u64(self.nonce),
        )
    }

    /// The SafeTx's hash (`safeTxHash`): `TypedDataEncoder.hash` of
    /// [`SafeTx::typed_data`], through `fc-evm`.
    pub fn hash(&self, safe: &[u8; 20]) -> Result<[u8; 32], Error> {
        safe_tx_hash(
            CHAIN_ID,
            safe,
            &self.to,
            &self.value,
            &self.data,
            &U256::from_u64(self.nonce),
        )
    }

    /// The SafeTx against the Safe's nonce on chain.
    pub fn nonce_state(&self, chain_nonce: &U256) -> NonceState {
        let nonce = U256::from_u64(self.nonce);
        if *chain_nonce == nonce {
            NonceState::Ready
        } else if *chain_nonce > nonce {
            NonceState::Superseded
        } else {
            NonceState::Behind
        }
    }
}

/// A SafeTx's typed data on `chain_id`, EIP712Domain included, in
/// [`SafeTx::typed_data`]'s form: one CALL with no refund, `to`, `value`,
/// `data` and `nonce` as given, unbounded. [`SafeTx`] is Freedom's own, on
/// Gnosis; this is for fc-approval's Safe approvals (design 0012, APR-3),
/// which bind the SafeTx main builds on any chain a `safe-send` token
/// allows, and hash it here (design 0016, SAFE-2's D5). A number is a JSON
/// number where JavaScript holds it exactly (up to 2^53 − 1), as the
/// reference writes it, and decimal text past that; fc-evm hashes both
/// alike.
pub fn safe_tx_typed_data(
    chain_id: u64,
    safe: &[u8; 20],
    to: &[u8; 20],
    value: &U256,
    data: &[u8],
    nonce: &U256,
) -> Value {
    json!({
        "types": {
            "EIP712Domain": domain_type(),
            "SafeTx": type_of(&SAFE_TX_TYPE),
        },
        "domain": {
            "verifyingContract": checksum_address(safe),
            "chainId": uint_json(&U256::from_u64(chain_id)),
        },
        "primaryType": "SafeTx",
        "message": fields_of(to, value, data, nonce),
    })
}

/// The hash of [`safe_tx_typed_data`]: `TypedDataEncoder.hash`, through
/// `fc-evm`.
pub fn safe_tx_hash(
    chain_id: u64,
    safe: &[u8; 20],
    to: &[u8; 20],
    value: &U256,
    data: &[u8],
    nonce: &U256,
) -> Result<[u8; 32], Error> {
    let typed = safe_tx_typed_data(chain_id, safe, to, value, data, nonce);
    let mut types = Map::new();
    types.insert("SafeTx".into(), type_of(&SAFE_TX_TYPE));
    typed_data_hash(&typed["domain"], &Value::Object(types), &typed["message"])
        .map_err(|error| Error::TypedData(error.to_string()))
}

/// The selector of `execTransaction(address,uint256,bytes,uint8,uint256,
/// uint256,uint256,address,address,bytes)`.
pub const EXEC_TRANSACTION_SELECTOR: [u8; 4] = [0x6a, 0x76, 0x12, 0x02];

/// `execTransaction(to, value, data, 0, 0, 0, 0, 0x0, 0x0, signatures)`:
/// the executor's calldata, to the Safe, with the joined signatures
/// ([`crate::Signatures::joined`]).
pub fn exec_transaction(tx: &SafeTx, signatures: &[u8]) -> Vec<u8> {
    exec_call(&tx.to, &tx.value, &tx.data, signatures)
}

/// [`exec_transaction`]'s calldata for a SafeTx's `to`, `value` and `data`,
/// unbounded: what fc-approval compares the executor's transaction with
/// (design 0016, SAFE-2's D5).
pub fn exec_call(to: &[u8; 20], value: &U256, data: &[u8], signatures: &[u8]) -> Vec<u8> {
    call(
        "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
        &[
            Token::Word(address_word(to)),
            Token::Word(value.to_be_bytes()),
            Token::Dynamic(data),
            Token::Word([0; 32]),
            Token::Word([0; 32]),
            Token::Word([0; 32]),
            Token::Word([0; 32]),
            Token::Word([0; 32]),
            Token::Word([0; 32]),
            Token::Dynamic(signatures),
        ],
    )
}

/// The ten fields in the reference's property order ([`SafeTx::fields`]).
fn fields_of(to: &[u8; 20], value: &U256, data: &[u8], nonce: &U256) -> Value {
    json!({
        "to": checksum_address(to),
        "value": value.to_decimal(),
        "data": to_hex(data),
        "operation": 0,
        "baseGas": "0",
        "gasPrice": "0",
        "gasToken": ZERO_ADDRESS,
        "refundReceiver": ZERO_ADDRESS,
        "nonce": uint_json(nonce),
        "safeTxGas": "0",
    })
}

/// A uint as typed data carries it: a JSON number up to 2^53 − 1, which
/// JavaScript (and fc-evm, as ethers) reads exactly, and decimal text past
/// it.
pub(crate) fn uint_json(n: &U256) -> Value {
    match n.to_u64().filter(|n| *n <= MAX_NONCE) {
        Some(n) => json!(n),
        None => json!(n.to_decimal()),
    }
}

/// A uint field as the reference writes one: a JSON integer, or quantity
/// text.
fn quantity(value: &Value) -> Result<U256, Error> {
    match value {
        Value::Number(n) => n.as_u64().map(U256::from_u64),
        Value::String(text) => parse_unsigned(text),
        _ => None,
    }
    .ok_or(Error::Malformed("a number field that isn't a uint"))
}

/// protocol-kit's `EIP712_DOMAIN` for Safe 1.3.0 and later.
pub(crate) fn domain_type() -> Value {
    type_of(&[("uint256", "chainId"), ("address", "verifyingContract")])
}

/// A type's fields as protocol-kit writes them: `{ type, name }` each.
pub(crate) fn type_of(fields: &[(&str, &str)]) -> Value {
    Value::Array(
        fields
            .iter()
            .map(|(kind, name)| json!({ "type": kind, "name": name }))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tx() -> SafeTx {
        SafeTx::new([0x11; 20], U256::from_u64(5), vec![0xab, 0xcd], 7).unwrap()
    }

    #[test]
    fn its_fields_read_back() {
        let tx = tx();
        assert_eq!(SafeTx::from_fields(&tx.fields()), Ok(tx.clone()));
        // As a page gave them: hex, either case.
        let mut fields = tx.fields();
        fields["value"] = json!("0x5");
        fields["data"] = json!("0xABCD");
        fields["to"] = json!("0x1111111111111111111111111111111111111111");
        fields["nonce"] = json!("7");
        assert_eq!(SafeTx::from_fields(&fields), Ok(tx));
    }

    #[test]
    fn any_other_operation_gas_token_or_receiver_is_refused() {
        let other = |name: &str, value: Value| {
            let mut fields = tx().fields();
            fields[name] = value;
            SafeTx::from_fields(&fields).map_err(|e| e.kind())
        };
        for (name, value) in [
            ("operation", json!(1)),
            ("operation", json!("1")),
            ("safeTxGas", json!("1")),
            ("safeTxGas", json!(21_000)),
            ("baseGas", json!("1")),
            ("gasPrice", json!("1000000000")),
            (
                "gasToken",
                json!("0x0000000000000000000000000000000000000001"),
            ),
            (
                "refundReceiver",
                json!("0x1111111111111111111111111111111111111111"),
            ),
        ] {
            assert_eq!(other(name, value.clone()), Err("field"), "{name} {value}");
        }
        // A zero in either spelling is Freedom's.
        for name in ["operation", "safeTxGas", "baseGas", "gasPrice"] {
            assert!(other(name, json!(0)).is_ok(), "{name}");
            assert!(other(name, json!("0")).is_ok(), "{name}");
        }
    }

    #[test]
    fn malformed_fields_are_refused() {
        let mut missing = tx().fields();
        missing.as_object_mut().unwrap().shift_remove("safeTxGas");
        assert_eq!(
            SafeTx::from_fields(&missing).map_err(|e| e.kind()),
            Err("malformed")
        );
        let mut extra = tx().fields();
        extra["signatures"] = json!("0x");
        assert_eq!(
            SafeTx::from_fields(&extra).map_err(|e| e.kind()),
            Err("malformed")
        );
        for (name, value) in [
            ("to", json!("0x11")),
            ("value", json!("-5")),
            ("value", json!(5)),
            ("data", json!("abcd")),
            ("operation", json!(-1)),
            ("operation", json!(0.5)),
            ("baseGas", json!(null)),
            ("gasToken", json!(0)),
            ("nonce", json!("seven")),
        ] {
            let mut fields = tx().fields();
            fields[name] = value.clone();
            assert_eq!(
                SafeTx::from_fields(&fields).map_err(|e| e.kind()),
                Err("malformed"),
                "{name} {value}"
            );
        }
        assert_eq!(
            SafeTx::from_fields(&json!([])).map_err(|e| e.kind()),
            Err("malformed")
        );
    }

    #[test]
    fn the_nonce_and_data_are_bounded() {
        assert!(SafeTx::new([1; 20], U256::ZERO, vec![], MAX_NONCE).is_ok());
        assert_eq!(
            SafeTx::new([1; 20], U256::ZERO, vec![], MAX_NONCE + 1),
            Err(Error::Nonce)
        );
        assert!(SafeTx::new([1; 20], U256::ZERO, vec![0; MAX_DATA], 0).is_ok());
        assert_eq!(
            SafeTx::new([1; 20], U256::ZERO, vec![0; MAX_DATA + 1], 0),
            Err(Error::DataTooLong)
        );
        assert_eq!(
            SafeTx::nonce_from(&U256::from_u64(MAX_NONCE)),
            Ok(MAX_NONCE)
        );
        assert_eq!(
            SafeTx::nonce_from(&U256::from_u64(MAX_NONCE + 1)),
            Err(Error::Nonce)
        );
        assert_eq!(SafeTx::nonce_from(&U256::MAX), Err(Error::Nonce));
        let mut fields = tx().fields();
        fields["nonce"] = json!(MAX_NONCE + 1);
        assert_eq!(SafeTx::from_fields(&fields), Err(Error::Nonce));
    }

    #[test]
    fn the_nonce_state() {
        let tx = tx();
        assert_eq!(tx.nonce_state(&U256::from_u64(7)), NonceState::Ready);
        assert_eq!(tx.nonce_state(&U256::from_u64(8)), NonceState::Superseded);
        assert_eq!(tx.nonce_state(&U256::MAX), NonceState::Superseded);
        assert_eq!(tx.nonce_state(&U256::from_u64(6)), NonceState::Behind);
        assert_eq!(tx.nonce_state(&U256::ZERO), NonceState::Behind);
    }
}
