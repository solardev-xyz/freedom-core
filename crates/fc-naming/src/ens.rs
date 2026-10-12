//! namehash, DNS encoding and ENSIP-11 coin types, as ethers v6 and
//! `ens-resolver.js` compute them.

use sha3::{Digest, Keccak256};

use crate::Error;

/// SLIP-44 coin type of Ether, used for chain 1.
pub const ETH_COIN_TYPE: u64 = 60;

/// ethers' `ensNameSplit`: ENSIP-15 first (ethers normalizes again, without
/// trimming), then the UTF-8 labels, none of them empty.
fn split(name: &str) -> Result<Vec<Vec<u8>>, Error> {
    if name.is_empty() {
        return Err(Error::InvalidName("empty label".into()));
    }
    let normalized =
        ens_normalize::ens_normalize(name).map_err(|e| Error::InvalidName(e.to_string()))?;
    let labels: Vec<Vec<u8>> = normalized
        .split('.')
        .map(|label| label.as_bytes().to_vec())
        .collect();
    if labels.iter().any(Vec::is_empty) {
        return Err(Error::EmptyComponent);
    }
    Ok(labels)
}

/// ethers' `namehash`.
pub fn namehash(name: &str) -> Result<[u8; 32], Error> {
    let mut node = [0u8; 32];
    for label in split(name)?.iter().rev() {
        let mut hasher = Keccak256::new();
        hasher.update(node);
        hasher.update(Keccak256::digest(label));
        node = hasher.finalize().into();
    }
    Ok(node)
}

/// ethers' `dnsEncode(name, max_label)`: length-prefixed labels and a final
/// zero byte. The resolver uses `max_label` 255.
pub fn dns_encode(name: &str, max_label: usize) -> Result<Vec<u8>, Error> {
    if max_label > 255 {
        return Err(Error::LabelLimitTooLarge);
    }
    let mut out = Vec::new();
    for label in split(name)? {
        if label.len() > max_label {
            return Err(Error::LabelTooLong(max_label));
        }
        // max_label <= 255, so the length fits a byte.
        out.push(u8::try_from(label.len()).map_err(|_| Error::LabelTooLong(max_label))?);
        out.extend_from_slice(&label);
    }
    out.push(0);
    Ok(out)
}

/// `ensCoinType`: ENSIP-11's coin type for an EVM chain. Chain 1 is Ether's
/// SLIP-44 type; others are `0x80000000 + chain_id` for 1 <= chain_id < 2^31.
pub fn coin_type(chain_id: u64) -> Result<u64, Error> {
    match chain_id {
        1 => Ok(ETH_COIN_TYPE),
        2..0x8000_0000 => Ok(0x8000_0000 + chain_id),
        _ => Err(Error::InvalidChainId),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_namehash_and_dns_encoding() {
        assert_eq!(
            hex::encode(namehash("vitalik.eth").unwrap()),
            "ee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835"
        );
        assert_eq!(
            hex::encode(namehash("eth").unwrap()),
            "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
        assert_eq!(
            hex::encode(dns_encode("vitalik.eth", 255).unwrap()),
            "07766974616c696b0365746800"
        );
    }

    #[test]
    fn refuses_what_ethers_refuses() {
        assert!(matches!(namehash(""), Err(Error::InvalidName(_))));
        assert!(namehash("foo..eth").is_err());
        assert!(namehash(".eth").is_err());
        assert!(namehash(" vitalik.eth").is_err());
        let long = "a".repeat(256);
        assert_eq!(
            dns_encode(&format!("{long}.eth"), 255),
            Err(Error::LabelTooLong(255))
        );
        assert_eq!(dns_encode("a.eth", 256), Err(Error::LabelLimitTooLarge));
        assert!(dns_encode(&format!("{}.eth", "a".repeat(255)), 255).is_ok());
    }

    #[test]
    fn coin_types() {
        assert_eq!(coin_type(1), Ok(60));
        assert_eq!(coin_type(8453), Ok(2_147_492_101));
        assert_eq!(coin_type(0x7FFF_FFFF), Ok(0xFFFF_FFFF));
        assert_eq!(coin_type(0), Err(Error::InvalidChainId));
        assert_eq!(coin_type(0x8000_0000), Err(Error::InvalidChainId));
    }
}
