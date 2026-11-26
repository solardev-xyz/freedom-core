//! The SafeMessage (EIP-1271; design 0016, "Messages"): `{ message: digest }`
//! under the Safe's domain, as `safe-messages.js` builds it, the digest
//! being the one a verifier computes for the page's request.

use fc_evm::{checksum_address, eip191_digest, to_hex, typed_data_hash};
use serde_json::{Map, Value, json};

use crate::Error;
use crate::constants::CHAIN_ID;
use crate::tx::{domain_type, type_of};

/// A SafeMessage over a request's digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeMessage {
    digest: [u8; 32],
}

impl SafeMessage {
    pub fn new(digest: [u8; 32]) -> Self {
        SafeMessage { digest }
    }

    /// A `personal_sign` of `message` (its bytes, as `normalizeMessage`
    /// gives them): the EIP-191 digest.
    pub fn personal_sign(message: &[u8]) -> Self {
        Self::new(eip191_digest(message))
    }

    /// An `eth_signTypedData_v4` of `{ domain, types, message }` (`types`
    /// without EIP712Domain): the core's EIP-712 hash, as 0002 signs it.
    pub fn typed_data_request(
        domain: &Value,
        types: &Value,
        message: &Value,
    ) -> Result<Self, Error> {
        typed_data_hash(domain, types, message)
            .map(Self::new)
            .map_err(|error| Error::TypedData(error.to_string()))
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The typed data every owner signs, EIP712Domain included, as the
    /// reference builds it: the domain `{ chainId: 100, verifyingContract:
    /// safe }`, the message `{ message: digest }`.
    pub fn typed_data(&self, safe: &[u8; 20]) -> Value {
        json!({
            "types": {
                "EIP712Domain": domain_type(),
                "SafeMessage": message_type(),
            },
            "domain": { "chainId": CHAIN_ID, "verifyingContract": checksum_address(safe) },
            "primaryType": "SafeMessage",
            "message": { "message": to_hex(&self.digest) },
        })
    }

    /// The SafeMessage's hash: `TypedDataEncoder.hash` of
    /// [`SafeMessage::typed_data`], through `fc-evm`.
    pub fn hash(&self, safe: &[u8; 20]) -> Result<[u8; 32], Error> {
        let typed = self.typed_data(safe);
        let mut types = Map::new();
        types.insert("SafeMessage".into(), message_type());
        typed_data_hash(&typed["domain"], &Value::Object(types), &typed["message"])
            .map_err(|error| Error::TypedData(error.to_string()))
    }
}

/// protocol-kit's `getEip712MessageTypes`' `SafeMessage`.
fn message_type() -> Value {
    type_of(&[("bytes", "message")])
}
