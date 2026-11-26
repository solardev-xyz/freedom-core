//! Owners' signatures (design 0016, "Owner signatures"; deviation
//! `owner-signatures`): each checked before it is kept, and the kept ones
//! joined as Safe's `checkSignatures` reads them.

use fc_evm::recover_address;

use crate::{Error, SignatureError};

/// One owner's signature over a SafeTx's or SafeMessage's hash, checked:
/// 65 bytes `r ‖ s ‖ v`, `v` 27 or 28, recovered to that owner, one of the
/// Safe's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerSignature {
    owner: [u8; 20],
    signature: [u8; 65],
}

impl OwnerSignature {
    /// `owner`'s `signature` over `hash`, for a Safe whose owners are
    /// `owners`. Freedom makes no other kind than this one, so any other is
    /// refused: a `v` of 0 or 1 (which a Safe reads as a contract's
    /// signature and an approved hash), an EIP-155 `v`, EIP-2098's 64
    /// bytes, a high `s`, and one that recovers to anyone but the owner.
    pub fn check(
        hash: &[u8; 32],
        signature: &[u8],
        owner: &[u8; 20],
        owners: &[[u8; 20]],
    ) -> Result<Self, SignatureError> {
        if !owners.contains(owner) {
            return Err(SignatureError::NotOwner);
        }
        let signature: [u8; 65] = signature.try_into().map_err(|_| SignatureError::Length)?;
        if !matches!(signature[64], 27 | 28) {
            return Err(SignatureError::V);
        }
        let recovered = recover_address(hash, &signature).map_err(|_| SignatureError::Recovery)?;
        if recovered != *owner {
            return Err(SignatureError::Mismatch);
        }
        Ok(OwnerSignature {
            owner: *owner,
            signature,
        })
    }

    pub fn owner(&self) -> &[u8; 20] {
        &self.owner
    }

    pub fn signature(&self) -> &[u8; 65] {
        &self.signature
    }
}

/// The signatures kept for one SafeTx or SafeMessage: at most one per
/// owner, in owner order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signatures {
    kept: Vec<OwnerSignature>,
}

impl Signatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps `signature` unless its owner signed already: a second one from
    /// the same owner is dropped (`false`), the first kept.
    pub fn add(&mut self, signature: OwnerSignature) -> bool {
        match self
            .kept
            .binary_search_by(|kept| kept.owner.cmp(&signature.owner))
        {
            Ok(_) => false,
            Err(at) => {
                self.kept.insert(at, signature);
                true
            }
        }
    }

    pub fn len(&self) -> usize {
        self.kept.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kept.is_empty()
    }

    /// The kept signatures, in owner order.
    pub fn kept(&self) -> &[OwnerSignature] {
        &self.kept
    }

    /// The signatures as `execTransaction` and EIP-1271 take them, as
    /// protocol-kit's `buildSignatureBytes` joins them: sorted by owner
    /// address, each its 65 bytes.
    pub fn joined(&self) -> Vec<u8> {
        self.kept.iter().flat_map(|kept| kept.signature).collect()
    }

    /// [`Signatures::joined`], once there are at least `threshold`.
    pub fn joined_at(&self, threshold: usize) -> Result<Vec<u8>, Error> {
        if self.kept.len() < threshold {
            return Err(Error::Threshold {
                have: self.kept.len(),
                need: threshold,
            });
        }
        Ok(self.joined())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use fc_evm::{address_of, keccak256, sign_digest};
    use k256::ecdsa::SigningKey;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&keccak256(&[n]).into()).unwrap()
    }

    fn signed(n: u8, hash: &[u8; 32]) -> (SigningKey, [u8; 20], [u8; 65]) {
        let key = key(n);
        let address = address_of(&key);
        let signature = sign_digest(&key, hash).unwrap();
        (key, address, signature)
    }

    #[test]
    fn an_owners_signature_is_kept() {
        let hash = keccak256(b"a SafeTx");
        let (_, owner, signature) = signed(1, &hash);
        let checked = OwnerSignature::check(&hash, &signature, &owner, &[[9; 20], owner]).unwrap();
        assert_eq!(checked.owner(), &owner);
        assert_eq!(checked.signature(), &signature);
    }

    #[test]
    fn any_other_kind_is_refused() {
        let hash = keccak256(b"a SafeTx");
        let (_, owner, signature) = signed(1, &hash);
        let (_, other, other_signature) = signed(2, &hash);
        let owners = [owner, other];
        let check = |bytes: &[u8], owner: &[u8; 20]| {
            OwnerSignature::check(&hash, bytes, owner, &owners).map(|_| ())
        };
        let mut v = signature;
        for value in [0u8, 1, 26, 29, 30, 37, 38, 255] {
            v[64] = value;
            assert_eq!(check(&v, &owner), Err(SignatureError::V), "v {value}");
        }
        assert_eq!(check(&signature[..64], &owner), Err(SignatureError::Length));
        assert_eq!(
            check(&[signature.as_slice(), &[0]].concat(), &owner),
            Err(SignatureError::Length)
        );
        assert_eq!(check(&[], &owner), Err(SignatureError::Length));
        // Another owner's signature on this owner's row.
        assert_eq!(
            check(&other_signature, &owner),
            Err(SignatureError::Mismatch)
        );
        // Over another hash.
        let (_, _, elsewhere) = signed(1, &keccak256(b"another SafeTx"));
        assert_eq!(check(&elsewhere, &owner), Err(SignatureError::Mismatch));
        // Not an owner of this Safe.
        assert_eq!(
            OwnerSignature::check(&hash, &signature, &owner, &[other]).map(|_| ()),
            Err(SignatureError::NotOwner)
        );
        let mut zero = signature;
        zero[..32].fill(0);
        assert_eq!(check(&zero, &owner), Err(SignatureError::Recovery));
    }

    #[test]
    fn one_per_owner_joined_in_owner_order() {
        let hash = keccak256(b"a SafeTx");
        let mut owners: Vec<_> = (1..=3).map(|n| signed(n, &hash)).collect();
        let addresses: Vec<[u8; 20]> = owners.iter().map(|(_, address, _)| *address).collect();
        let mut signatures = Signatures::new();
        for (_, owner, signature) in owners.iter().rev() {
            let checked = OwnerSignature::check(&hash, signature, owner, &addresses).unwrap();
            assert!(signatures.add(checked));
            assert!(
                !signatures.add(checked),
                "a second from one owner is dropped"
            );
        }
        owners.sort_by_key(|(_, address, _)| *address);
        let expected: Vec<u8> = owners
            .iter()
            .flat_map(|(_, _, signature)| *signature)
            .collect();
        assert_eq!(signatures.joined(), expected);
        assert_eq!(signatures.len(), 3);
        assert_eq!(signatures.joined_at(3), Ok(expected));
        assert_eq!(
            signatures.joined_at(4),
            Err(Error::Threshold { have: 3, need: 4 })
        );
        assert_eq!(Signatures::new().joined(), Vec::<u8>::new());
    }
}
