//! The Safe deployment Freedom creates Safes with (design 0016, "Which
//! Safes"): Safe 1.4.1's canonical `SafeL2` singleton, `SafeProxyFactory`
//! and `CompatibilityFallbackHandler`, the same on every chain
//! (safe-deployments 1.37.66, `assets/v1.4.1/`, Gnosis's deployment the
//! canonical one), and the factory's proxy creation code, as the reference
//! pins them (`safe-executor.js`'s `PINNED_DEPLOYMENTS`, #1066).
//!
//! The code is a constant of the canonical factory: it is embedded once in
//! the factory's runtime code, whose keccak256 is the code hash
//! safe-deployments lists. `vectors/safe.json`'s `constants` records each
//! of these, and this crate's tests check every link.

/// The Safe contracts' version.
pub const SAFE_VERSION: &str = "1.4.1";

/// Gnosis, the one chain Freedom's Safes are on.
pub const CHAIN_ID: u64 = 100;

/// `SafeL2` 1.4.1, `0x29fcB43b46531BcA003ddC8FCB67FFE91900C762`.
pub const SINGLETON: [u8; 20] = bytes("29fcb43b46531bca003ddc8fcb67ffe91900c762");

/// `SafeProxyFactory` 1.4.1, `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67`.
pub const PROXY_FACTORY: [u8; 20] = bytes("4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67");

/// `CompatibilityFallbackHandler` 1.4.1,
/// `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99`.
pub const FALLBACK_HANDLER: [u8; 20] = bytes("fd0732dc9e303f09fcef3a7388ad10a83459ec99");

/// The factory's `proxyCreationCode()`: the `SafeProxy` creation code, 486
/// bytes, which a Safe's CREATE2 init code starts with.
pub const PROXY_CREATION_CODE: [u8; 486] = bytes(concat!(
    "608060405234801561001057600080fd5b506040516101e63803806101e683398181016040526020",
    "81101561003357600080fd5b8101908080519060200190929190505050600073ffffffffffffffff",
    "ffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156100",
    "ca576040517f08c379a0000000000000000000000000000000000000000000000000000000008152",
    "6004018080602001828103825260228152602001806101c460229139604001915050604051809103",
    "90fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff0219169083",
    "73ffffffffffffffffffffffffffffffffffffffff1602179055505060ab806101196000396000f3",
    "fe608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e00000000",
    "00000000000000000000000000000000000000000000000060003514156050578060005260206000",
    "f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea2",
    "64697066735822122003d1488ee65e08fa41e58e888a9865554c535f2c77126a82cb4c0f917f3144",
    "1364736f6c63430007060033496e76616c69642073696e676c65746f6e2061646472657373207072",
    "6f7669646564",
));

/// keccak256 of [`PROXY_CREATION_CODE`].
pub const PROXY_CREATION_CODE_HASH: [u8; 32] =
    bytes("1856e0ee08399d74e0ea0b03adca210aeade6f748969ac023cdcb4dd62dcaf5f");

/// The sentinel, `0x…01`, that heads and ends Safe's linked lists of owners
/// (`OwnerManager`'s `SENTINEL_OWNERS`) and modules (`ModuleManager`'s
/// `SENTINEL_MODULES`): `setup` refuses it as an owner, and an empty module
/// list is the sentinel pointing at itself.
pub const SENTINEL: [u8; 20] = {
    let mut sentinel = [0u8; 20];
    sentinel[19] = 1;
    sentinel
};

/// Lowercase hex digits as bytes, at compile time only: a digit outside
/// `0-9a-f` reads as zero, and text of the wrong length fails the build.
/// The tests compare each constant with the vectors.
pub(crate) const fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    const fn nibble(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => 0,
        }
    }
    let hex = hex.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proxy_code_hashes_to_its_pinned_hash() {
        assert_eq!(
            fc_evm::keccak256(&PROXY_CREATION_CODE),
            PROXY_CREATION_CODE_HASH
        );
    }

    #[test]
    fn the_addresses_are_the_checksummed_ones() {
        assert_eq!(
            fc_evm::checksum_address(&SINGLETON),
            "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"
        );
        assert_eq!(
            fc_evm::checksum_address(&PROXY_FACTORY),
            "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"
        );
        assert_eq!(
            fc_evm::checksum_address(&FALLBACK_HANDLER),
            "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"
        );
    }
}
