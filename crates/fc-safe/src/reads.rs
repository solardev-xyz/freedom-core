//! The Safe's setup as the chain has it (design 0016, "Chain reads" and
//! "Owners, threshold and setup"): the eight reads, what each one sends,
//! their answers decoded, and [`check_setup`], which compares them with the
//! record and finds what was changed outside Freedom.
//!
//! The crate does no I/O: 0005's chain machine makes the reads, each one
//! verified, and passes their answers in (SAFE-2's S1). The slots and calls
//! are Safe 1.4.1's (safe-smart-account `v1.4.1`, `bf943f80`), which
//! `SafeL2` inherits from `Safe`:
//! - **the singleton**, storage slot 0: `Singleton`'s `singleton`, "the first
//!   declared variable", "stored alone (uses a full word)"
//!   (`common/Singleton.sol`), which `SafeProxy` delegates to
//!   (`proxies/SafeProxy.sol`);
//! - **the owners**, `getOwners()`: `OwnerManager`'s list, from its
//!   sentinel (`base/OwnerManager.sol`);
//! - **the threshold**, `getThreshold()` (the same file);
//! - **the guard**, storage slot `GUARD_STORAGE_SLOT`,
//!   keccak256(`"guard_manager.guard.address"`), which `setGuard` writes
//!   whole (`base/GuardManager.sol`);
//! - **the fallback handler**, storage slot `FALLBACK_HANDLER_STORAGE_SLOT`,
//!   keccak256(`"fallback_manager.handler.address"`), which `setup` and
//!   `setFallbackHandler` write whole (`base/FallbackManager.sol`);
//! - **the modules**, `getModulesPaginated(0x1, 1)` (`base/ModuleManager.sol`):
//!   with none enabled it answers an empty page and the sentinel as `next`
//!   (`setupModules` points the sentinel at itself), and `enableModule`
//!   links a module at the head, so any enabled one is on the first page;
//! - **the nonce**, `nonce()`: `Safe`'s `uint256 public nonce`
//!   (`Safe.sol`);
//! - and **the code** at the Safe's address, `eth_getCode`: none means the
//!   Safe isn't deployed.
//!
//! The decoders take only the encodings Solidity gives these functions:
//! a uint256 or a storage word is 32 bytes, an `address[]` is the offset
//! `0x20`, its count and its addresses with nothing after them, and
//! `getModulesPaginated`'s `(address[], address)` is the offset `0x40`,
//! `next`, the count and the addresses. Anything else is a [`ReadError`],
//! never a panic.

use std::fmt;

use fc_evm::U256;

use crate::constants::{FALLBACK_HANDLER, SENTINEL, SINGLETON, bytes};
use crate::{ReadError, ReadProblem, Setup, address_word};

/// `nonce()`'s selector.
pub const NONCE_SELECTOR: [u8; 4] = [0xaf, 0xfe, 0xd0, 0xe0];

/// `getOwners()`'s selector.
pub const GET_OWNERS_SELECTOR: [u8; 4] = [0xa0, 0xe6, 0x7e, 0x2b];

/// `getThreshold()`'s selector.
pub const GET_THRESHOLD_SELECTOR: [u8; 4] = [0xe7, 0x52, 0x35, 0xb8];

/// `getModulesPaginated(address,uint256)`'s selector.
pub const GET_MODULES_PAGINATED_SELECTOR: [u8; 4] = [0xcc, 0x2f, 0x84, 0x52];

/// The singleton's storage slot: 0.
pub const SINGLETON_SLOT: [u8; 32] = [0; 32];

/// `GuardManager`'s `GUARD_STORAGE_SLOT`,
/// keccak256(`"guard_manager.guard.address"`).
pub const GUARD_SLOT: [u8; 32] =
    bytes("4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8");

/// `FallbackManager`'s `FALLBACK_HANDLER_STORAGE_SLOT`,
/// keccak256(`"fallback_manager.handler.address"`).
pub const FALLBACK_HANDLER_SLOT: [u8; 32] =
    bytes("6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5");

const WORD: usize = 32;

/// One of the eight reads a Safe's setup check rests on, each to the Safe's
/// own address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Read {
    Code,
    Singleton,
    Owners,
    Threshold,
    Guard,
    Handler,
    Modules,
    Nonce,
}

impl Read {
    /// The eight, in the order to make them: the code first, which decides
    /// whether the rest mean anything, and the nonce last. The reads aren't
    /// pinned to one block, so a SafeTx is built on a nonce read after the
    /// setup it was checked against.
    pub const ALL: [Read; 8] = [
        Read::Code,
        Read::Singleton,
        Read::Owners,
        Read::Threshold,
        Read::Guard,
        Read::Handler,
        Read::Modules,
        Read::Nonce,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Read::Code => "code",
            Read::Singleton => "singleton",
            Read::Owners => "owners",
            Read::Threshold => "threshold",
            Read::Guard => "guard",
            Read::Handler => "handler",
            Read::Modules => "modules",
            Read::Nonce => "nonce",
        }
    }

    /// What the read sends to the Safe's address.
    pub fn query(self) -> Query {
        match self {
            Read::Code => Query::Code,
            Read::Singleton => Query::Storage(SINGLETON_SLOT),
            Read::Guard => Query::Storage(GUARD_SLOT),
            Read::Handler => Query::Storage(FALLBACK_HANDLER_SLOT),
            Read::Owners => Query::Call(GET_OWNERS_SELECTOR.to_vec()),
            Read::Threshold => Query::Call(GET_THRESHOLD_SELECTOR.to_vec()),
            Read::Nonce => Query::Call(NONCE_SELECTOR.to_vec()),
            Read::Modules => {
                // getModulesPaginated(SENTINEL_MODULES, 1).
                let mut data = GET_MODULES_PAGINATED_SELECTOR.to_vec();
                data.extend(address_word(&SENTINEL));
                data.extend(U256::from_u64(1).to_be_bytes());
                Query::Call(data)
            }
        }
    }
}

impl fmt::Display for Read {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A read's request, to the Safe's address: the chain machine adds the
/// address and the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// `eth_getCode`.
    Code,
    /// `eth_call` with this calldata.
    Call(Vec<u8>),
    /// `eth_getStorageAt` at this slot, sent as all 32 bytes (Colibri's
    /// prover refuses a shorter slot: design 0014, "What the service
    /// serves").
    Storage([u8; 32]),
}

impl Query {
    /// The JSON-RPC method.
    pub fn method(&self) -> &'static str {
        match self {
            Query::Code => "eth_getCode",
            Query::Call(_) => "eth_call",
            Query::Storage(_) => "eth_getStorageAt",
        }
    }
}

/// The eight reads' answers: each one's `result`, as bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answers<'a> {
    pub code: &'a [u8],
    pub singleton: &'a [u8],
    pub owners: &'a [u8],
    pub threshold: &'a [u8],
    pub guard: &'a [u8],
    pub handler: &'a [u8],
    pub modules: &'a [u8],
    pub nonce: &'a [u8],
}

impl<'a> Answers<'a> {
    /// Each read's answer from `answer`.
    pub fn from_fn(mut answer: impl FnMut(Read) -> &'a [u8]) -> Self {
        Answers {
            code: answer(Read::Code),
            singleton: answer(Read::Singleton),
            owners: answer(Read::Owners),
            threshold: answer(Read::Threshold),
            guard: answer(Read::Guard),
            handler: answer(Read::Handler),
            modules: answer(Read::Modules),
            nonce: answer(Read::Nonce),
        }
    }

    pub fn get(&self, read: Read) -> &'a [u8] {
        match read {
            Read::Code => self.code,
            Read::Singleton => self.singleton,
            Read::Owners => self.owners,
            Read::Threshold => self.threshold,
            Read::Guard => self.guard,
            Read::Handler => self.handler,
            Read::Modules => self.modules,
            Read::Nonce => self.nonce,
        }
    }
}

/// What differs from the Safe Freedom made (design 0016, "Owners, threshold
/// and setup"), in the order [`check_setup`] lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Change {
    /// Slot 0 isn't `SafeL2` 1.4.1's address, alone in its word.
    Singleton,
    /// The owners, as a set, aren't the record's.
    Owners,
    /// The threshold isn't the record's.
    Threshold,
    /// A guard is set.
    Guard,
    /// The fallback handler isn't the canonical one.
    Handler,
    /// A module is enabled, or the module list isn't one `setup` makes.
    Module,
}

impl Change {
    pub fn name(self) -> &'static str {
        match self {
            Change::Singleton => "singleton",
            Change::Owners => "owners",
            Change::Threshold => "threshold",
            Change::Guard => "guard",
            Change::Handler => "handler",
            Change::Module => "module",
        }
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A Safe's setup against its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupCheck {
    /// No code at the address: the Safe isn't deployed, and there is no
    /// setup on chain to compare. Once its address is checked
    /// ([`Setup::check_address`]) its setup at deployment is the record's,
    /// which CREATE2 derives the address from; the reference sends and
    /// signs messages only for a Safe marked deployed (`safe-transactions.js`,
    /// `safe-messages.js`), and so do SAFE-2's methods.
    NotDeployed,
    /// Deployed with the record's setup, and its nonce.
    Unchanged { nonce: U256 },
    /// Deployed, and changed outside Freedom (`safe_changed`): what
    /// changed, in [`Change`]'s order, at least one.
    Changed(Vec<Change>),
}

/// `getModulesPaginated`'s answer: one page and the pointer past it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModulesPage {
    pub modules: Vec<[u8; 20]>,
    pub next: [u8; 20],
}

impl ModulesPage {
    /// Whether the first page says no module is enabled: empty, with the
    /// sentinel as `next`, as Safe 1.4.1 answers for a list `setup` made
    /// and no module joined.
    pub fn none_enabled(&self) -> bool {
        self.modules.is_empty() && self.next == SENTINEL
    }
}

/// Compares the eight reads' `answers` with the record's `setup` (design
/// 0016, "Owners, threshold and setup"): `SafeL2` 1.4.1 in slot 0, the
/// record's owners as a set, its threshold, no guard, the canonical
/// fallback handler and no module. Each answer must be verified first,
/// which is the caller's.
///
/// - No code: [`SetupCheck::NotDeployed`], whatever the others answered.
/// - Another singleton: the calls' answers are another contract's, so they
///   aren't read, and [`SetupCheck::Changed`] names the singleton (and the
///   guard and handler, if they changed too).
/// - Otherwise every answer is decoded, and one that isn't its encoding is
///   a [`ReadError`].
pub fn check_setup(setup: &Setup, answers: &Answers<'_>) -> Result<SetupCheck, ReadError> {
    if answers.code.is_empty() {
        return Ok(SetupCheck::NotDeployed);
    }
    let singleton = decode_slot(Read::Singleton, answers.singleton)?;
    let guard = decode_slot(Read::Guard, answers.guard)?;
    let handler = decode_slot(Read::Handler, answers.handler)?;
    let mut changed = Vec::new();
    if guard != [0; 32] {
        changed.push(Change::Guard);
    }
    if handler != address_word(&FALLBACK_HANDLER) {
        changed.push(Change::Handler);
    }
    if singleton != address_word(&SINGLETON) {
        changed.push(Change::Singleton);
        changed.sort();
        return Ok(SetupCheck::Changed(changed));
    }
    let owners = decode_owners(answers.owners)?;
    let threshold = decode_uint(Read::Threshold, answers.threshold)?;
    let modules = decode_modules(answers.modules)?;
    let nonce = decode_uint(Read::Nonce, answers.nonce)?;
    if !same_set(&owners, setup.owners()) {
        changed.push(Change::Owners);
    }
    if threshold != U256::from_u64(setup.threshold() as u64) {
        changed.push(Change::Threshold);
    }
    if !modules.none_enabled() {
        changed.push(Change::Module);
    }
    changed.sort();
    Ok(if changed.is_empty() {
        SetupCheck::Unchanged { nonce }
    } else {
        SetupCheck::Changed(changed)
    })
}

/// A uint256 answer (`nonce()`, `getThreshold()`): one word.
pub fn decode_uint(read: Read, answer: &[u8]) -> Result<U256, ReadError> {
    let word = one_word(read, answer)?;
    U256::from_be_slice(&word).ok_or(ReadError::new(read, ReadProblem::Length))
}

/// A storage word (`eth_getStorageAt`): 32 bytes.
pub fn decode_slot(read: Read, answer: &[u8]) -> Result<[u8; 32], ReadError> {
    one_word(read, answer)
}

/// `getOwners()`'s `address[]`.
pub fn decode_owners(answer: &[u8]) -> Result<Vec<[u8; 20]>, ReadError> {
    let read = Read::Owners;
    let words = words(read, answer)?;
    let (_, list) = split(read, words, 1)?;
    addresses(read, list)
}

/// `getModulesPaginated`'s `(address[] array, address next)`.
pub fn decode_modules(answer: &[u8]) -> Result<ModulesPage, ReadError> {
    let read = Read::Modules;
    let words = words(read, answer)?;
    let (head, list) = split(read, words, 2)?;
    let next = head
        .get(1)
        .ok_or(ReadError::new(read, ReadProblem::Length))?;
    Ok(ModulesPage {
        next: address(read, next)?,
        modules: addresses(read, list)?,
    })
}

fn one_word(read: Read, answer: &[u8]) -> Result<[u8; 32], ReadError> {
    answer
        .try_into()
        .map_err(|_| ReadError::new(read, ReadProblem::Length))
}

type Words<'a> = &'a [[u8; 32]];

/// The answer as whole words.
fn words(read: Read, answer: &[u8]) -> Result<Words<'_>, ReadError> {
    match answer.as_chunks::<WORD>() {
        (words, []) => Ok(words),
        _ => Err(ReadError::new(read, ReadProblem::Length)),
    }
}

/// A tuple whose first member is an `address[]` and whose other members are
/// words: its `head` words, the first the array's offset, which is where
/// Solidity puts it, right after the head; then the array's count and
/// words, which must be all that is left.
fn split(read: Read, words: Words<'_>, head: usize) -> Result<(Words<'_>, Words<'_>), ReadError> {
    let length = || ReadError::new(read, ReadProblem::Length);
    let (head_words, rest) = words.split_at_checked(head).ok_or_else(length)?;
    if head_words.first() != Some(&fc_naming::abi::word_from_usize(head * WORD)) {
        return Err(ReadError::new(read, ReadProblem::Offset));
    }
    let (count, list) = rest.split_first().ok_or_else(length)?;
    let (high, low) = count.split_at(WORD - 8);
    let low: [u8; 8] = low.try_into().map_err(|_| length())?;
    let count = usize::try_from(u64::from_be_bytes(low)).map_err(|_| length())?;
    if high.iter().any(|b| *b != 0) || count != list.len() {
        return Err(length());
    }
    Ok((head_words, list))
}

fn addresses(read: Read, words: Words<'_>) -> Result<Vec<[u8; 20]>, ReadError> {
    words.iter().map(|word| address(read, word)).collect()
}

/// An address word: its high 12 bytes zero.
fn address(read: Read, word: &[u8; 32]) -> Result<[u8; 20], ReadError> {
    let (high, low) = word.split_at(WORD - 20);
    if high.iter().any(|b| *b != 0) {
        return Err(ReadError::new(read, ReadProblem::Address));
    }
    low.try_into()
        .map_err(|_| ReadError::new(read, ReadProblem::Address))
}

/// Whether `found` holds exactly `record`'s owners, each once, in any
/// order.
fn same_set(found: &[[u8; 20]], record: &[[u8; 20]]) -> bool {
    let mut found = found.to_vec();
    let mut record = record.to_vec();
    found.sort_unstable();
    record.sort_unstable();
    found == record
}
