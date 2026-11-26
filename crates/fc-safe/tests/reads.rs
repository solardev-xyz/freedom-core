//! The setup reads (design 0016, "Chain reads"; SAFE-2's S0): what each read
//! sends, as Safe 1.4.1's contracts define it, and [`check_setup`] against
//! the answers a Safe as Freedom made it gives, with each part of its setup
//! changed in turn, and with answers that aren't their encoding.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use fc_evm::{U256, keccak256, parse_address, to_hex};
use fc_naming::abi::{self, Token, word_from_address, word_from_usize};
use fc_safe::constants::{FALLBACK_HANDLER, PROXY_CREATION_CODE, SENTINEL, SINGLETON};
use fc_safe::reads::{
    FALLBACK_HANDLER_SLOT, GET_MODULES_PAGINATED_SELECTOR, GET_OWNERS_SELECTOR,
    GET_THRESHOLD_SELECTOR, GUARD_SLOT, ModulesPage, NONCE_SELECTOR, Query, SINGLETON_SLOT,
    decode_modules, decode_owners, decode_slot, decode_uint,
};
use fc_safe::{
    Answers, Change, MAX_NONCE, Read, ReadError, ReadProblem, Setup, SetupCheck, check_setup,
};

const A: [u8; 20] = [0xa1; 20];
const B: [u8; 20] = [0xb2; 20];
const C: [u8; 20] = [0xc3; 20];
const D: [u8; 20] = [0xd4; 20];
const MODULE: [u8; 20] = [0xe5; 20];

fn address(text: &str) -> [u8; 20] {
    parse_address(text).unwrap()
}

/// `SafeProxy`'s runtime code: what its constructor returns from the
/// factory's proxy creation code (`CODECOPY` of 0xab bytes from 0x119).
fn proxy_code() -> Vec<u8> {
    PROXY_CREATION_CODE[0x119..0x119 + 0xab].to_vec()
}

fn uint(n: U256) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}

/// `address[]` as Solidity returns it, through fc-naming's encoder.
fn owners_answer(owners: &[[u8; 20]]) -> Vec<u8> {
    let words: Vec<[u8; 32]> = owners.iter().map(word_from_address).collect();
    abi::encode(&[Token::Words(&words)])
}

/// `(address[] array, address next)` as Solidity returns it.
fn modules_answer(modules: &[[u8; 20]], next: &[u8; 20]) -> Vec<u8> {
    let words: Vec<[u8; 32]> = modules.iter().map(word_from_address).collect();
    abi::encode(&[Token::Words(&words), Token::Word(word_from_address(next))])
}

type Chain = BTreeMap<Read, Vec<u8>>;

/// What the eight reads answer for `setup`, deployed as Freedom deploys it
/// and never changed, at `nonce`: the owners in the order `setupOwners`
/// links them, the record's.
fn honest(setup: &Setup, nonce: U256) -> Chain {
    BTreeMap::from([
        (Read::Code, proxy_code()),
        (Read::Singleton, word_from_address(&SINGLETON).to_vec()),
        (Read::Owners, owners_answer(setup.owners())),
        (
            Read::Threshold,
            uint(U256::from_u64(setup.threshold() as u64)),
        ),
        (Read::Guard, vec![0; 32]),
        (Read::Handler, word_from_address(&FALLBACK_HANDLER).to_vec()),
        (Read::Modules, modules_answer(&[], &SENTINEL)),
        (Read::Nonce, uint(nonce)),
    ])
}

fn check(setup: &Setup, chain: &Chain) -> Result<SetupCheck, ReadError> {
    check_setup(setup, &Answers::from_fn(|read| chain[&read].as_slice()))
}

fn one_of_two() -> Setup {
    Setup::new(vec![A, B], 1).unwrap()
}

fn two_of_three() -> Setup {
    Setup::new(vec![A, B, C], 2).unwrap()
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4].try_into().unwrap()
}

#[test]
fn the_queries_are_safe_141s() {
    // The selectors, from Safe 1.4.1's ABI (safe-deployments' safe_l2.json).
    assert_eq!(NONCE_SELECTOR, selector("nonce()"));
    assert_eq!(GET_OWNERS_SELECTOR, selector("getOwners()"));
    assert_eq!(GET_THRESHOLD_SELECTOR, selector("getThreshold()"));
    assert_eq!(
        GET_MODULES_PAGINATED_SELECTOR,
        selector("getModulesPaginated(address,uint256)")
    );
    // The slots: the singleton first, the managers' named slots.
    assert_eq!(SINGLETON_SLOT, [0; 32]);
    assert_eq!(GUARD_SLOT, keccak256(b"guard_manager.guard.address"));
    assert_eq!(
        FALLBACK_HANDLER_SLOT,
        keccak256(b"fallback_manager.handler.address")
    );
    // Design 0016's abbreviations of each.
    assert!(to_hex(&GUARD_SLOT).starts_with("0x4a20"));
    assert!(to_hex(&GUARD_SLOT).ends_with("34c8"));
    assert!(to_hex(&FALLBACK_HANDLER_SLOT).starts_with("0x6c9a"));
    assert!(to_hex(&FALLBACK_HANDLER_SLOT).ends_with("18d5"));

    let queries: BTreeMap<Read, Query> = Read::ALL.iter().map(|r| (*r, r.query())).collect();
    assert_eq!(queries.len(), 8);
    assert_eq!(Read::ALL[0], Read::Code);
    assert_eq!(Read::ALL[7], Read::Nonce);
    assert_eq!(queries[&Read::Code], Query::Code);
    assert_eq!(queries[&Read::Singleton], Query::Storage(SINGLETON_SLOT));
    assert_eq!(queries[&Read::Guard], Query::Storage(GUARD_SLOT));
    assert_eq!(
        queries[&Read::Handler],
        Query::Storage(FALLBACK_HANDLER_SLOT)
    );
    assert_eq!(
        queries[&Read::Owners],
        Query::Call(GET_OWNERS_SELECTOR.to_vec())
    );
    assert_eq!(
        queries[&Read::Threshold],
        Query::Call(GET_THRESHOLD_SELECTOR.to_vec())
    );
    assert_eq!(queries[&Read::Nonce], Query::Call(NONCE_SELECTOR.to_vec()));
    // getModulesPaginated(0x1, 1), byte for byte.
    let Query::Call(modules) = &queries[&Read::Modules] else {
        panic!("the modules read is a call");
    };
    assert_eq!(
        to_hex(modules),
        format!("0xcc2f8452{:0>64}{:0>64}", "1", "1")
    );
    let mut expected = GET_MODULES_PAGINATED_SELECTOR.to_vec();
    expected.extend(abi::encode(&[
        Token::Word(word_from_address(&SENTINEL)),
        Token::Word(word_from_usize(1)),
    ]));
    assert_eq!(*modules, expected);

    let methods: BTreeMap<Read, &str> = queries.iter().map(|(r, q)| (*r, q.method())).collect();
    for (read, method) in methods {
        let expected = match read {
            Read::Code => "eth_getCode",
            Read::Singleton | Read::Guard | Read::Handler => "eth_getStorageAt",
            _ => "eth_call",
        };
        assert_eq!(method, expected, "{read}");
    }
    let names: BTreeSet<&str> = Read::ALL.iter().map(|r| r.name()).collect();
    assert_eq!(names.len(), 8);
}

#[test]
fn an_unchanged_setup_passes() {
    for setup in [one_of_two(), two_of_three()] {
        for nonce in [
            U256::ZERO,
            U256::from_u64(7),
            U256::from_u64(MAX_NONCE),
            U256::MAX,
        ] {
            assert_eq!(
                check(&setup, &honest(&setup, nonce)),
                Ok(SetupCheck::Unchanged { nonce }),
                "{} owners, nonce {}",
                setup.owners().len(),
                nonce.to_decimal()
            );
        }
        // The owners are a set: in any order (an owner added and removed
        // again moves to the head of the list).
        let mut owners = setup.owners().to_vec();
        for _ in 0..owners.len() {
            owners.rotate_left(1);
            let mut chain = honest(&setup, U256::from_u64(3));
            chain.insert(Read::Owners, owners_answer(&owners));
            assert_eq!(
                check(&setup, &chain),
                Ok(SetupCheck::Unchanged {
                    nonce: U256::from_u64(3)
                })
            );
            owners.reverse();
            chain.insert(Read::Owners, owners_answer(&owners));
            assert!(matches!(
                check(&setup, &chain),
                Ok(SetupCheck::Unchanged { .. })
            ));
        }
    }
}

/// One read's answer replaced.
fn with(setup: &Setup, read: Read, answer: Vec<u8>) -> Chain {
    let mut chain = honest(setup, U256::from_u64(5));
    chain.insert(read, answer);
    chain
}

fn changed(setup: &Setup, chain: &Chain) -> Vec<Change> {
    match check(setup, chain) {
        Ok(SetupCheck::Changed(changes)) => changes,
        other => panic!("not changed: {other:?}"),
    }
}

#[test]
fn each_change_is_named() {
    let word = |address: &[u8; 20]| word_from_address(address).to_vec();
    let mut high_bits = word_from_address(&SINGLETON);
    high_bits[0] = 1;
    let mut guard_high = [0u8; 32];
    guard_high[0] = 1;
    for setup in [one_of_two(), two_of_three()] {
        let owners = setup.owners().to_vec();
        let threshold = setup.threshold() as u64;
        let cases: Vec<(&str, Read, Vec<u8>, Change)> = vec![
            // The singleton.
            (
                "Safe 1.4.1, not L2",
                Read::Singleton,
                word(&address("0x41675C099F32341bf84BFc5382aF534df5C7461a")),
                Change::Singleton,
            ),
            (
                "SafeL2 1.3.0",
                Read::Singleton,
                word(&address("0x3E5c63644E683549055b9Be8653de26E0B4CD36E")),
                Change::Singleton,
            ),
            ("none", Read::Singleton, vec![0; 32], Change::Singleton),
            (
                "SafeL2 1.4.1 with a high bit set",
                Read::Singleton,
                high_bits.to_vec(),
                Change::Singleton,
            ),
            // The owners.
            (
                "one swapped",
                Read::Owners,
                owners_answer(&[&owners[1..], &[D]].concat()),
                Change::Owners,
            ),
            (
                "one added",
                Read::Owners,
                owners_answer(&[&owners[..], &[D]].concat()),
                Change::Owners,
            ),
            (
                "one removed",
                Read::Owners,
                owners_answer(&owners[1..]),
                Change::Owners,
            ),
            (
                "one twice",
                Read::Owners,
                owners_answer(&[&owners[..], &owners[..1]].concat()),
                Change::Owners,
            ),
            ("none", Read::Owners, owners_answer(&[]), Change::Owners),
            // The threshold.
            (
                "one more",
                Read::Threshold,
                uint(U256::from_u64(threshold + 1)),
                Change::Threshold,
            ),
            (
                "one less",
                Read::Threshold,
                uint(U256::from_u64(threshold - 1)),
                Change::Threshold,
            ),
            (
                "the widest",
                Read::Threshold,
                uint(U256::MAX),
                Change::Threshold,
            ),
            // The guard.
            ("a guard", Read::Guard, word(&MODULE), Change::Guard),
            (
                "a high bit",
                Read::Guard,
                guard_high.to_vec(),
                Change::Guard,
            ),
            // The fallback handler.
            ("removed", Read::Handler, vec![0; 32], Change::Handler),
            ("another", Read::Handler, word(&MODULE), Change::Handler),
            (
                "1.3.0's",
                Read::Handler,
                word(&address("0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4")),
                Change::Handler,
            ),
            // The modules.
            (
                "one module",
                Read::Modules,
                modules_answer(&[MODULE], &SENTINEL),
                Change::Module,
            ),
            (
                "two modules, the first page",
                Read::Modules,
                modules_answer(&[MODULE], &MODULE),
                Change::Module,
            ),
            (
                "an uninitialized list",
                Read::Modules,
                modules_answer(&[], &[0; 20]),
                Change::Module,
            ),
            (
                "an empty page and a next",
                Read::Modules,
                modules_answer(&[], &MODULE),
                Change::Module,
            ),
        ];
        for (what, read, answer, change) in cases {
            assert_eq!(
                changed(&setup, &with(&setup, read, answer)),
                vec![change],
                "{read}: {what} ({} owners)",
                owners.len()
            );
        }
    }
}

#[test]
fn several_changes_are_all_named() {
    let setup = two_of_three();
    let mut chain = honest(&setup, U256::from_u64(1));
    chain.insert(Read::Owners, owners_answer(&[A, B, D]));
    chain.insert(Read::Threshold, uint(U256::from_u64(1)));
    assert_eq!(
        changed(&setup, &chain),
        vec![Change::Owners, Change::Threshold]
    );
    chain.insert(Read::Modules, modules_answer(&[MODULE], &SENTINEL));
    chain.insert(Read::Guard, word_from_address(&MODULE).to_vec());
    chain.insert(Read::Handler, vec![0; 32]);
    assert_eq!(
        changed(&setup, &chain),
        vec![
            Change::Owners,
            Change::Threshold,
            Change::Guard,
            Change::Handler,
            Change::Module
        ]
    );
    // With another singleton, its calls' answers aren't read: the storage
    // words are still compared.
    chain.insert(Read::Singleton, vec![0; 32]);
    assert_eq!(
        changed(&setup, &chain),
        vec![Change::Singleton, Change::Guard, Change::Handler]
    );
}

#[test]
fn another_singletons_answers_are_not_read() {
    let setup = one_of_two();
    let mut chain = honest(&setup, U256::ZERO);
    chain.insert(Read::Singleton, word_from_address(&MODULE).to_vec());
    for read in [Read::Owners, Read::Threshold, Read::Modules, Read::Nonce] {
        chain.insert(read, vec![0xff; 7]);
    }
    assert_eq!(changed(&setup, &chain), vec![Change::Singleton]);
    for read in [Read::Owners, Read::Threshold, Read::Modules, Read::Nonce] {
        chain.insert(read, Vec::new());
    }
    assert_eq!(changed(&setup, &chain), vec![Change::Singleton]);
}

#[test]
fn no_code_is_not_deployed() {
    let setup = one_of_two();
    // What an account with no code answers: empty calls, zero slots.
    let mut chain: Chain = Read::ALL.iter().map(|r| (*r, Vec::new())).collect();
    for read in [Read::Singleton, Read::Guard, Read::Handler] {
        chain.insert(read, vec![0; 32]);
    }
    assert_eq!(check(&setup, &chain), Ok(SetupCheck::NotDeployed));
    // Whatever the others answered, read before or after a deployment.
    let mut chain = honest(&setup, U256::from_u64(4));
    chain.insert(Read::Code, Vec::new());
    assert_eq!(check(&setup, &chain), Ok(SetupCheck::NotDeployed));
    chain.insert(Read::Owners, vec![1, 2, 3]);
    assert_eq!(check(&setup, &chain), Ok(SetupCheck::NotDeployed));
}

fn error(read: Read, problem: ReadProblem) -> Result<SetupCheck, ReadError> {
    Err(ReadError { read, problem })
}

#[test]
fn malformed_answers_are_typed_errors() {
    use ReadProblem::{Address, Length, Offset};
    let setup = two_of_three();
    let word = |n: usize| word_from_usize(n).to_vec();
    let dirty = {
        let mut word = word_from_address(&A);
        word[11] = 1;
        word.to_vec()
    };
    let honest_owners = owners_answer(setup.owners());
    let honest_modules = modules_answer(&[], &SENTINEL);
    let mut cases: Vec<(Read, Vec<u8>, ReadProblem)> = Vec::new();
    // A word: 32 bytes exactly.
    for read in [
        Read::Singleton,
        Read::Guard,
        Read::Handler,
        Read::Threshold,
        Read::Nonce,
    ] {
        for length in [0, 1, 20, 31, 33, 64] {
            cases.push((read, vec![0; length], Length));
        }
    }
    // getOwners' address[].
    let owners = |parts: &[Vec<u8>]| parts.concat();
    cases.extend([
        (Read::Owners, Vec::new(), Length),
        (Read::Owners, word(0x20), Length),
        (Read::Owners, owners(&[word(0x20), word(1)]), Length),
        (
            Read::Owners,
            owners(&[word(0x40), word(0), word(0)]),
            Offset,
        ),
        (Read::Owners, owners(&[word(0), word(0)]), Offset),
        (
            Read::Owners,
            owners(&[word(0x20), word(3), word_from_address(&A).to_vec()]),
            Length,
        ),
        (
            Read::Owners,
            owners(&[word(0x20), vec![0xff; 32], word_from_address(&A).to_vec()]),
            Length,
        ),
        (
            Read::Owners,
            owners(&[word(0x20), word(1), dirty.clone()]),
            Address,
        ),
        (
            Read::Owners,
            owners(&[honest_owners.clone(), vec![0; 32]]),
            Length,
        ),
        (
            Read::Owners,
            owners(&[honest_owners.clone(), vec![0]]),
            Length,
        ),
        (
            Read::Owners,
            honest_owners[..honest_owners.len() - 1].to_vec(),
            Length,
        ),
    ]);
    // A count whose high bytes are set but whose low 8 bytes are right.
    let mut wide_count = word(setup.owners().len());
    wide_count[0] = 1;
    cases.push((
        Read::Owners,
        owners(&[word(0x20), wide_count, honest_owners[64..].to_vec()]),
        Length,
    ));
    // getModulesPaginated's (address[], address).
    let modules = owners;
    cases.extend([
        (Read::Modules, Vec::new(), Length),
        (Read::Modules, owners(&[word(0x40), word(1)]), Length),
        (
            Read::Modules,
            modules(&[word(0x20), word(1), word(0)]),
            Offset,
        ),
        (
            Read::Modules,
            modules(&[word(0x40), dirty.clone(), word(0)]),
            Address,
        ),
        (
            Read::Modules,
            modules(&[word(0x40), word(1), word(1)]),
            Length,
        ),
        (
            Read::Modules,
            modules(&[word(0x40), word(1), word(1), dirty.clone()]),
            Address,
        ),
        (
            Read::Modules,
            modules(&[honest_modules.clone(), vec![0; 32]]),
            Length,
        ),
        (
            Read::Modules,
            honest_modules[..honest_modules.len() - 1].to_vec(),
            Length,
        ),
    ]);
    for (read, answer, problem) in cases {
        assert_eq!(
            check(&setup, &with(&setup, read, answer.clone())),
            error(read, problem),
            "{read}: {}",
            to_hex(&answer)
        );
    }
}

#[test]
fn the_decoders_read_what_solidity_returns() {
    let owners = [A, B, C, D];
    assert_eq!(decode_owners(&owners_answer(&owners)), Ok(owners.to_vec()));
    assert_eq!(decode_owners(&owners_answer(&[])), Ok(vec![]));
    assert_eq!(
        decode_modules(&modules_answer(&[MODULE, A], &B)),
        Ok(ModulesPage {
            modules: vec![MODULE, A],
            next: B
        })
    );
    let none = decode_modules(&modules_answer(&[], &SENTINEL)).unwrap();
    assert!(none.none_enabled());
    assert!(
        !decode_modules(&modules_answer(&[MODULE], &SENTINEL))
            .unwrap()
            .none_enabled()
    );
    assert_eq!(decode_uint(Read::Nonce, &uint(U256::MAX)), Ok(U256::MAX));
    assert_eq!(decode_slot(Read::Guard, &GUARD_SLOT), Ok(GUARD_SLOT));
    let refusal = decode_uint(Read::Threshold, &[0; 31]).unwrap_err();
    assert_eq!(refusal.problem.kind(), "length");
    assert_eq!(
        refusal.to_string(),
        "the Safe's threshold read answered a length its encoding doesn't have"
    );
}

/// Every prefix of each honest answer, and each of its bytes changed, ends
/// in an answer or a typed error.
#[test]
fn no_answer_panics() {
    let setup = two_of_three();
    let base = honest(&setup, U256::from_u64(9));
    for read in Read::ALL {
        let answer = &base[&read];
        for cut in 0..answer.len() {
            let _ = check(&setup, &with(&setup, read, answer[..cut].to_vec()));
        }
        for at in 0..answer.len() {
            for flip in [0x01, 0x80, 0xff] {
                let mut bent = answer.clone();
                bent[at] ^= flip;
                let _ = check(&setup, &with(&setup, read, bent));
            }
        }
    }
    // Lengths that aren't any encoding's, of every byte.
    for length in 0..200 {
        for fill in [0x00, 0x01, 0x20, 0x40, 0xff] {
            let chain: Chain = Read::ALL.iter().map(|r| (*r, vec![fill; length])).collect();
            let _ = check(&setup, &chain);
        }
    }
}
