//! did:key, Radicle node IDs and IPFS identities for Ed25519 public keys,
//! matching freedom-browser's `formats.js`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use crate::Ed25519Key;

/// Multicodec prefix for an Ed25519 public key (`0xed 0x01`).
const ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// `did:key:z…` for an Ed25519 public key (`didFromPublicKey`).
pub fn did_key(public: &[u8; 32]) -> String {
    format!("did:key:{}", radicle_node_id(public))
}

/// Radicle node ID: the did:key without its `did:key:` prefix.
pub fn radicle_node_id(public: &[u8; 32]) -> String {
    let mut bytes = [0u8; 34];
    bytes[..2].copy_from_slice(&ED25519_PUB);
    bytes[2..].copy_from_slice(public);
    format!("z{}", bs58::encode(bytes).into_string())
}

/// IPFS PeerID (`12D3KooW…`): base58btc of the identity multihash of the
/// public-key protobuf.
///
/// Desktop runs IPFS with an ephemeral identity; this exists for the vectors
/// and a possible future stable identity.
pub fn ipfs_peer_id(public: &[u8; 32]) -> String {
    let mut bytes = [0u8; 38];
    bytes[..6].copy_from_slice(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
    bytes[6..].copy_from_slice(public);
    bs58::encode(bytes).into_string()
}

/// IPFS config `Identity.PrivKey`: base64 of the private-key protobuf
/// (type Ed25519, 64 bytes private || public).
pub fn ipfs_private_key(key: &Ed25519Key) -> Zeroizing<String> {
    let mut protobuf = Zeroizing::new([0u8; 68]);
    protobuf[..4].copy_from_slice(&[0x08, 0x01, 0x12, 0x40]);
    protobuf[4..36].copy_from_slice(key.to_secret_bytes().as_slice());
    protobuf[36..].copy_from_slice(&key.public_key());
    let mut encoded = Zeroizing::new(String::with_capacity(92));
    STANDARD.encode_string(protobuf.as_slice(), &mut encoded);
    encoded
}
