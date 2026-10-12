//! EIP-155 legacy and EIP-1559 transactions, byte-for-byte as ethers v6
//! `Wallet.signTransaction` serializes them (design 0002, `sign.transaction`).

use k256::ecdsa::SigningKey;
use serde_json::{Map, Value};

use crate::signature::sign_prehash;
use crate::{Error, U256, keccak256, parse_address, parse_bytes, parse_unsigned, rlp};

/// ethers keeps the nonce in a JS number: at most 2^53 - 1.
const MAX_NONCE: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Fees {
    Legacy {
        gas_price: U256,
    },
    Eip1559 {
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
    },
}

/// A fully specified transaction, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    chain_id: U256,
    nonce: u64,
    gas_limit: U256,
    to: Option<[u8; 20]>,
    value: U256,
    data: Vec<u8>,
    fees: Fees,
}

/// `raw` is the signed serialization; `hash` its keccak256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    pub raw: Vec<u8>,
    pub hash: [u8; 32],
}

fn err(message: impl Into<String>) -> Error {
    Error::Transaction(message.into())
}

fn quantity(fields: &Map<String, Value>, name: &str) -> Result<U256, Error> {
    match fields.get(name) {
        Some(Value::String(text)) => {
            parse_unsigned(text).ok_or_else(|| err(format!("{name}: not a quantity")))
        }
        Some(_) => Err(err(format!("{name}: expected a quantity string"))),
        None => Err(err(format!("{name}: missing"))),
    }
}

impl Transaction {
    /// The `tx` object of `sign.transaction`. Unknown fields are rejected.
    pub fn from_json(value: &Value) -> Result<Self, Error> {
        let fields = value.as_object().ok_or_else(|| err("expected an object"))?;
        let tx_type = fields.get("type").and_then(Value::as_u64);
        let allowed: &[&str] = match tx_type {
            Some(0) => &[
                "type",
                "chain_id",
                "nonce",
                "gas_limit",
                "to",
                "value",
                "data",
                "gas_price",
            ],
            Some(2) => &[
                "type",
                "chain_id",
                "nonce",
                "gas_limit",
                "to",
                "value",
                "data",
                "max_fee_per_gas",
                "max_priority_fee_per_gas",
            ],
            _ => return Err(err("type: only 0 (legacy) and 2 (EIP-1559)")),
        };
        if let Some(unknown) = fields.keys().find(|key| !allowed.contains(&key.as_str())) {
            return Err(err(format!("{unknown}: unknown field")));
        }
        let chain_id = quantity(fields, "chain_id")?;
        if chain_id.is_zero() {
            return Err(err("chain_id: must be at least 1"));
        }
        let nonce = quantity(fields, "nonce")?
            .to_u64()
            .filter(|nonce| *nonce <= MAX_NONCE)
            .ok_or_else(|| err("nonce: above 2^53 - 1"))?;
        let to = match fields.get("to") {
            Some(Value::Null) => None,
            Some(Value::String(text)) => {
                Some(parse_address(text).map_err(|_| err("to: not an address"))?)
            }
            Some(_) => return Err(err("to: expected an address or null")),
            None => return Err(err("to: missing")),
        };
        let data = match fields.get("data") {
            Some(Value::String(text)) => {
                parse_bytes(text, "data").map_err(|e| err(e.to_string()))?
            }
            _ => return Err(err("data: expected hex bytes")),
        };
        let fees = if tx_type == Some(0) {
            // EIP-155's v = chain_id * 2 + 36 must fit.
            if chain_id > U256::mask(254) {
                return Err(err("chain_id: too large"));
            }
            Fees::Legacy {
                gas_price: quantity(fields, "gas_price")?,
            }
        } else {
            let max_fee_per_gas = quantity(fields, "max_fee_per_gas")?;
            let max_priority_fee_per_gas = quantity(fields, "max_priority_fee_per_gas")?;
            if max_priority_fee_per_gas > max_fee_per_gas {
                return Err(err("priority fee above max fee"));
            }
            Fees::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            }
        };
        Ok(Transaction {
            chain_id,
            nonce,
            gas_limit: quantity(fields, "gas_limit")?,
            to,
            value: quantity(fields, "value")?,
            data,
            fees,
        })
    }

    /// The fields every type shares, after its fee fields.
    fn common(&self, out: &mut Vec<u8>) {
        rlp::uint(out, &self.gas_limit);
        rlp::bytes(out, self.to.as_ref().map_or(&[][..], |to| &to[..]));
        rlp::uint(out, &self.value);
        rlp::bytes(out, &self.data);
    }

    fn eip1559_fields(&self, out: &mut Vec<u8>, max_fee: &U256, priority: &U256) {
        rlp::uint(out, &self.chain_id);
        rlp::uint(out, &U256::from_u64(self.nonce));
        rlp::uint(out, priority);
        rlp::uint(out, max_fee);
        self.common(out);
        rlp::list(out, &[]); // access list
    }

    pub fn sign(&self, key: &SigningKey) -> Result<SignedTransaction, Error> {
        let raw = match &self.fees {
            Fees::Legacy { gas_price } => {
                let mut fields = Vec::new();
                rlp::uint(&mut fields, &U256::from_u64(self.nonce));
                rlp::uint(&mut fields, gas_price);
                self.common(&mut fields);
                // EIP-155: the chain id, then two empty fields, are signed.
                let mut unsigned = fields.clone();
                rlp::uint(&mut unsigned, &self.chain_id);
                rlp::uint(&mut unsigned, &U256::ZERO);
                rlp::uint(&mut unsigned, &U256::ZERO);
                let mut payload = Vec::new();
                rlp::list(&mut payload, &unsigned);
                let (signature, parity) = sign_prehash(key, &keccak256(&payload))?;
                // v = chain_id * 2 + 35 + parity
                let v = self
                    .chain_id
                    .checked_add(&self.chain_id)
                    .and_then(|double| double.checked_add(&U256::from_u64(35 + u64::from(parity))))
                    .ok_or_else(|| err("chain_id: too large"))?;
                rlp::uint(&mut fields, &v);
                push_rs(&mut fields, &signature);
                let mut raw = Vec::new();
                rlp::list(&mut raw, &fields);
                raw
            }
            Fees::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => {
                let mut fields = Vec::new();
                self.eip1559_fields(&mut fields, max_fee_per_gas, max_priority_fee_per_gas);
                let mut unsigned = vec![0x02];
                rlp::list(&mut unsigned, &fields);
                let (signature, parity) = sign_prehash(key, &keccak256(&unsigned))?;
                rlp::uint(&mut fields, &U256::from_u64(u64::from(parity)));
                push_rs(&mut fields, &signature);
                let mut raw = vec![0x02];
                rlp::list(&mut raw, &fields);
                raw
            }
        };
        let hash = keccak256(&raw);
        Ok(SignedTransaction { raw, hash })
    }
}

/// `r` and `s` as RLP integers (leading zeros stripped).
fn push_rs(out: &mut Vec<u8>, signature: &[u8; 65]) {
    for part in [&signature[..32], &signature[32..64]] {
        let start = part.iter().position(|b| *b != 0).unwrap_or(32);
        rlp::bytes(out, &part[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> Value {
        json!({
            "type": 2, "chain_id": "1", "nonce": "0", "gas_limit": "21000",
            "to": "0x8ba1f109551bD432803012645Ac136ddd64DBA72", "value": "0", "data": "0x",
            "max_fee_per_gas": "2", "max_priority_fee_per_gas": "1"
        })
    }

    fn with(edit: impl FnOnce(&mut Map<String, Value>)) -> Result<Transaction, Error> {
        let mut value = base();
        edit(value.as_object_mut().unwrap());
        Transaction::from_json(&value)
    }

    #[test]
    fn rejects_what_the_design_excludes() {
        assert!(Transaction::from_json(&base()).is_ok());
        for (field, bad) in [
            ("type", json!(1)),
            ("type", json!(3)),
            ("type", json!("2")),
            ("chain_id", json!("0")),
            ("chain_id", json!(1)),
            ("nonce", json!("9007199254740992")),
            ("nonce", json!("-1")),
            ("to", json!("vitalik.eth")),
            ("to", json!("0x8Ba1f109551bD432803012645Ac136ddd64DBA72")),
            ("data", json!("0x0")),
            ("data", json!(null)),
            ("value", json!(" 1")),
            ("max_priority_fee_per_gas", json!("3")),
            ("access_list", json!([])),
            ("gas_price", json!("1")),
        ] {
            assert!(
                with(|tx| {
                    tx.insert(field.into(), bad.clone());
                })
                .is_err(),
                "{field} {bad}"
            );
        }
        assert!(
            with(|tx| {
                tx.remove("to");
            })
            .is_err()
        );
        assert!(
            with(|tx| {
                tx.remove("chain_id");
            })
            .is_err()
        );
        let legacy = json!({
            "type": 0, "chain_id": "1", "nonce": "0", "gas_limit": "21000", "to": null,
            "value": "0", "data": "0x", "gas_price": "1"
        });
        assert!(Transaction::from_json(&legacy).is_ok());
        let mut mixed = legacy.clone();
        mixed["max_fee_per_gas"] = json!("1");
        assert!(Transaction::from_json(&mixed).is_err());
    }
}
