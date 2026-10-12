//! The ENS Universal Resolver and the WNS/GNS NameNFT contracts: the calls
//! `ens-resolver.js` makes, the answers it decodes, and how it classifies
//! reverts.

use crate::abi::{self, Field, Kind, Token, Value};

/// The DAO-owned Universal Resolver proxy.
pub const UNIVERSAL_RESOLVER: [u8; 20] = hex20("eeeeeeee14d718c2b47d9923deab1335e144eeee");
/// WNS (`.wei`) and GNS (`.gwei`) NameNFT registries.
pub const WNS_REGISTRY: [u8; 20] = hex20("0000000000696760e15f265e828db644a0c242eb");
pub const GNS_REGISTRY: [u8; 20] = hex20("9d51d507bc7264d4fe8ad1cf7fe191933a0a81d6");

/// `resolve(bytes,bytes)` and `reverse(bytes,uint256)`.
pub const RESOLVE: [u8; 4] = [0x90, 0x61, 0xb9, 0x23];
pub const REVERSE: [u8; 4] = [0x5d, 0x78, 0xa2, 0x17];
/// `contenthash(bytes32)`, `addr(bytes32)`, `addr(bytes32,uint256)`.
pub const CONTENTHASH: [u8; 4] = [0xbc, 0x1c, 0x58, 0xd1];
pub const ADDR: [u8; 4] = [0x3b, 0x3b, 0x57, 0xde];
pub const ADDR_MULTICOIN: [u8; 4] = [0xf1, 0xcb, 0x7e, 0x06];
/// NameNFT `reverseResolve(address)`.
pub const REVERSE_RESOLVE: [u8; 4] = [0x9a, 0xf8, 0xb7, 0xaa];

/// Revert selectors.
pub const RESOLVER_NOT_FOUND: [u8; 4] = [0x77, 0x20, 0x9f, 0xe8];
pub const RESOLVER_NOT_CONTRACT: [u8; 4] = [0x1e, 0x95, 0x35, 0xf2];
pub const REVERSE_ADDRESS_MISMATCH: [u8; 4] = [0xef, 0x9c, 0x03, 0xce];
pub const OFFCHAIN_LOOKUP: [u8; 4] = [0x55, 0x6f, 0x18, 0x30];

const fn hex20(text: &str) -> [u8; 20] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

fn with_selector(selector: [u8; 4], body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&selector);
    out.extend_from_slice(&body);
    out
}

fn word_from_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// `resolve(dnsEncode(name), call)`.
pub fn encode_resolve(dns_name: &[u8], call: &[u8]) -> Vec<u8> {
    with_selector(
        RESOLVE,
        abi::encode(&[Token::Dynamic(dns_name), Token::Dynamic(call)]),
    )
}

/// `reverse(address bytes, coinType)`.
pub fn encode_reverse(address: &[u8; 20], coin_type: u64) -> Vec<u8> {
    with_selector(
        REVERSE,
        abi::encode(&[
            Token::Dynamic(address),
            Token::Word(word_from_u64(coin_type)),
        ]),
    )
}

pub fn contenthash_call(node: &[u8; 32]) -> Vec<u8> {
    with_selector(CONTENTHASH, node.to_vec())
}

pub fn addr_call(node: &[u8; 32]) -> Vec<u8> {
    with_selector(ADDR, node.to_vec())
}

pub fn addr_multicoin_call(node: &[u8; 32], coin_type: u64) -> Vec<u8> {
    with_selector(
        ADDR_MULTICOIN,
        abi::encode(&[Token::Word(*node), Token::Word(word_from_u64(coin_type))]),
    )
}

pub fn reverse_resolve_call(address: &[u8; 20]) -> Vec<u8> {
    with_selector(REVERSE_RESOLVE, abi::word_from_address(address).to_vec())
}

/// `nodeFromResolverCallData`: the namehash argument of a resolver call.
pub fn node_from_call(call: &[u8]) -> Option<[u8; 32]> {
    let mut node = [0u8; 32];
    node.copy_from_slice(call.get(4..36)?);
    Some(node)
}

/// Why `Interface.decodeFunctionResult` refused a call's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultError {
    /// Not a multiple of 32 bytes: "invalid length for result data".
    InvalidLength,
    /// "could not decode result data".
    Undecodable,
}

/// ethers' `Interface.decodeFunctionResult`: the data must be a whole number
/// of words, then decodes with the strict coder. Field errors stay lazy.
pub fn decode_result(kinds: &[Kind], data: &[u8]) -> Result<Vec<Field>, ResultError> {
    decode_result_within(kinds, data, abi::MAX_DECODE_BYTES)
}

/// [`decode_result`] under a decode budget (deviation `decode-budget`).
pub fn decode_result_within(
    kinds: &[Kind],
    data: &[u8],
    output_limit: usize,
) -> Result<Vec<Field>, ResultError> {
    if !data.len().is_multiple_of(32) {
        return Err(ResultError::InvalidLength);
    }
    abi::decode_within(kinds, data, output_limit).map_err(|_| ResultError::Undecodable)
}

/// How a Universal Resolver revert is classified, by its data's selector.
/// (The JS also matches the error *message* against the error names; see
/// design 0003, Deviations.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revert {
    ResolverNotFound,
    ReverseAddressMismatch,
    OffchainLookup,
    Other,
}

/// `getRevertData` keeps data of at least 4 bytes; the selector decides.
pub fn classify_revert(data: &[u8]) -> Option<Revert> {
    let selector: [u8; 4] = data.get(..4)?.try_into().ok()?;
    Some(match selector {
        RESOLVER_NOT_FOUND | RESOLVER_NOT_CONTRACT => Revert::ResolverNotFound,
        REVERSE_ADDRESS_MISMATCH => Revert::ReverseAddressMismatch,
        OFFCHAIN_LOOKUP => Revert::OffchainLookup,
        _ => Revert::Other,
    })
}

/// EIP-3668's `OffchainLookup(address,string[],bytes,bytes4,bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffchainLookup {
    pub sender: [u8; 20],
    /// Each URL decoded on its own: the JS reads them in order and only
    /// fails on reaching a bad one, after trying every gateway before it.
    pub urls: Vec<Result<String, crate::abi::FieldError>>,
    pub call_data: Vec<u8>,
    pub callback: [u8; 4],
    pub extra_data: Vec<u8>,
}

/// Decodes the revert data (selector included). The JS destructures all
/// five fields, so a problem with any of them is an error; single URLs stay
/// lazy (see `urls`).
pub fn decode_offchain_lookup(data: &[u8]) -> Option<OffchainLookup> {
    decode_offchain_lookup_explained(data).ok()
}

/// [`decode_offchain_lookup`] under a decode budget of `output_limit`
/// bytes (deviation `decode-budget`).
pub fn decode_offchain_lookup_within(data: &[u8], output_limit: usize) -> Option<OffchainLookup> {
    decode_offchain_lookup_explained_within(data, output_limit).ok()
}

/// [`decode_offchain_lookup`], or the message the reference's error
/// carries: ethers' own for a whole-decode failure, else the deferred error
/// of the first field the destructuring reads.
pub fn decode_offchain_lookup_explained(data: &[u8]) -> Result<OffchainLookup, String> {
    decode_offchain_lookup_explained_within(data, abi::MAX_DECODE_BYTES)
}

/// [`decode_offchain_lookup_explained`] under a decode budget.
pub fn decode_offchain_lookup_explained_within(
    data: &[u8],
    output_limit: usize,
) -> Result<OffchainLookup, String> {
    if data.get(..4) != Some(&OFFCHAIN_LOOKUP[..]) {
        return Err(String::new());
    }
    let kinds = [
        Kind::Address,
        Kind::StringArray,
        Kind::Bytes,
        Kind::Bytes4,
        Kind::Bytes,
    ];
    let fields = abi::decode_explained_within(&kinds, &data[4..], output_limit)?;
    if let Some(index) = fields.iter().position(Result::is_err) {
        return Err(crate::ethers::deferred(index));
    }
    let mut fields = fields.into_iter();
    let (
        Some(Ok(Value::Address(sender))),
        Some(Ok(Value::StringArray(urls))),
        Some(Ok(Value::Bytes(call_data))),
        Some(Ok(Value::Bytes4(callback))),
        Some(Ok(Value::Bytes(extra_data))),
    ) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    )
    else {
        return Err(String::new());
    };
    Ok(OffchainLookup {
        sender,
        urls,
        call_data,
        callback,
        extra_data,
    })
}

/// The callback call: `callback ‖ abi.encode(bytes response, bytes extraData)`.
pub fn encode_callback(callback: [u8; 4], response: &[u8], extra_data: &[u8]) -> Vec<u8> {
    with_selector(
        callback,
        abi::encode(&[Token::Dynamic(response), Token::Dynamic(extra_data)]),
    )
}

/// `decodeReverseMismatchClaimedName`: the name a reverse record claimed,
/// from `ReverseAddressMismatch(string,bytes)`. Empty or undecodable is none.
pub fn reverse_mismatch_claimed_name(data: &[u8]) -> Option<String> {
    if data.get(..4)? != REVERSE_ADDRESS_MISMATCH {
        return None;
    }
    let fields = abi::decode(&[Kind::String, Kind::Bytes], &data[4..]).ok()?;
    match fields.into_iter().next()? {
        Ok(Value::String(name)) if !name.is_empty() => Some(name),
        _ => None,
    }
}

/// `REVERSE_OUTCOME`: how a reverse answer is encoded so quorum legs can
/// compare it byte for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReverseOutcome {
    NoRecord = 0,
    Name = 1,
    Mismatch = 2,
    Error = 3,
}

/// `abi.encode(uint8 status, string detail)`.
pub fn encode_reverse_outcome(status: ReverseOutcome, detail: &str) -> Vec<u8> {
    abi::encode(&[
        Token::Word(word_from_u64(status as u64)),
        Token::Dynamic(detail.as_bytes()),
    ])
}

/// Which name system a name belongs to, by suffix (`nameSystemForName`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSystem {
    Ens,
    Wns,
    Gns,
}

impl NameSystem {
    pub fn for_name(name: &str) -> NameSystem {
        let lower = name.to_lowercase();
        if lower.ends_with(".wei") {
            NameSystem::Wns
        } else if lower.ends_with(".gwei") {
            NameSystem::Gns
        } else {
            NameSystem::Ens
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            NameSystem::Ens => "ens",
            NameSystem::Wns => "wns",
            NameSystem::Gns => "gns",
        }
    }

    /// The NameNFT registry, for WNS and GNS.
    pub fn registry(self) -> Option<[u8; 20]> {
        match self {
            NameSystem::Ens => None,
            NameSystem::Wns => Some(WNS_REGISTRY),
            NameSystem::Gns => Some(GNS_REGISTRY),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    fn selector(signature: &str) -> [u8; 4] {
        let hash = Keccak256::digest(signature.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }

    #[test]
    fn selectors_match_their_signatures() {
        assert_eq!(RESOLVE, selector("resolve(bytes,bytes)"));
        assert_eq!(REVERSE, selector("reverse(bytes,uint256)"));
        assert_eq!(CONTENTHASH, selector("contenthash(bytes32)"));
        assert_eq!(ADDR, selector("addr(bytes32)"));
        assert_eq!(ADDR_MULTICOIN, selector("addr(bytes32,uint256)"));
        assert_eq!(REVERSE_RESOLVE, selector("reverseResolve(address)"));
        assert_eq!(RESOLVER_NOT_FOUND, selector("ResolverNotFound(bytes)"));
        assert_eq!(
            RESOLVER_NOT_CONTRACT,
            selector("ResolverNotContract(bytes,address)")
        );
        assert_eq!(
            REVERSE_ADDRESS_MISMATCH,
            selector("ReverseAddressMismatch(string,bytes)")
        );
        assert_eq!(
            OFFCHAIN_LOOKUP,
            selector("OffchainLookup(address,string[],bytes,bytes4,bytes)")
        );
    }

    #[test]
    fn offchain_lookup_round_trip() {
        // The lookup as a resolver encodes it.
        let urls = [
            "https://gw.example/{sender}/{data}.json",
            "https://gw2.example",
        ];
        let mut body = Vec::new();
        let url_items: Vec<u8> = {
            let tokens: Vec<Token<'_>> =
                urls.iter().map(|u| Token::Dynamic(u.as_bytes())).collect();
            let mut array = abi::word_from_usize(urls.len()).to_vec();
            array.extend(abi::encode(&tokens));
            array
        };
        // Head: sender, offset(urls), offset(callData), callback, offset(extraData).
        let call_data = b"\x01\x02";
        let extra = b"\x09";
        let head_len = 5 * 32;
        let urls_at = head_len;
        let call_at = urls_at + url_items.len();
        let call_tail = {
            let mut t = abi::word_from_usize(call_data.len()).to_vec();
            t.extend_from_slice(call_data);
            t.resize(t.len().div_ceil(32) * 32, 0);
            t
        };
        let extra_at = call_at + call_tail.len();
        body.extend_from_slice(&abi::word_from_address(&UNIVERSAL_RESOLVER));
        body.extend_from_slice(&abi::word_from_usize(urls_at));
        body.extend_from_slice(&abi::word_from_usize(call_at));
        let mut callback_word = [0u8; 32];
        callback_word[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        body.extend_from_slice(&callback_word);
        body.extend_from_slice(&abi::word_from_usize(extra_at));
        body.extend_from_slice(&url_items);
        body.extend_from_slice(&call_tail);
        let mut extra_tail = abi::word_from_usize(1).to_vec();
        extra_tail.extend_from_slice(extra);
        extra_tail.resize(64, 0);
        body.extend_from_slice(&extra_tail);

        let data = with_selector(OFFCHAIN_LOOKUP, body);
        assert_eq!(classify_revert(&data), Some(Revert::OffchainLookup));
        let lookup = decode_offchain_lookup(&data).unwrap();
        assert_eq!(lookup.sender, UNIVERSAL_RESOLVER);
        assert_eq!(lookup.urls, urls.map(|u| Ok(u.to_owned())));
        assert_eq!(lookup.call_data, call_data);
        assert_eq!(lookup.callback, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(lookup.extra_data, extra);
    }

    #[test]
    fn result_data_must_be_whole_words() {
        let data = abi::encode(&[Token::Dynamic(b"x"), Token::Word([0; 32])]);
        assert!(decode_result(&[Kind::Bytes, Kind::Address], &data).is_ok());
        assert_eq!(
            decode_result(&[Kind::Bytes, Kind::Address], &data[..data.len() - 1]),
            Err(ResultError::InvalidLength)
        );
    }

    #[test]
    fn reverse_mismatch_names() {
        let data = with_selector(
            REVERSE_ADDRESS_MISMATCH,
            abi::encode(&[Token::Dynamic(b"vitalik.eth"), Token::Dynamic(b"")]),
        );
        assert_eq!(
            reverse_mismatch_claimed_name(&data).as_deref(),
            Some("vitalik.eth")
        );
        let empty = with_selector(
            REVERSE_ADDRESS_MISMATCH,
            abi::encode(&[Token::Dynamic(b""), Token::Dynamic(b"")]),
        );
        assert_eq!(reverse_mismatch_claimed_name(&empty), None);
    }

    #[test]
    fn name_systems_by_suffix() {
        assert_eq!(NameSystem::for_name("Foo.WEI"), NameSystem::Wns);
        assert_eq!(NameSystem::for_name("foo.gwei"), NameSystem::Gns);
        assert_eq!(NameSystem::for_name("foo.eth"), NameSystem::Ens);
    }
}
