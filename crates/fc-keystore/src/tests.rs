//! The secrets file's changes and refusals, and the trait's flow over a
//! key store kept in memory (a test double: no backend is faked outside
//! tests).

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::*;

/// A counter RNG: each draw differs, and `fail` makes it fail.
struct TestRng {
    next: u64,
    fail: bool,
}

#[derive(Debug)]
struct TestRngError;

impl std::fmt::Display for TestRngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("test rng")
    }
}

impl std::error::Error for TestRngError {}

impl rand_core::TryRng for TestRng {
    type Error = TestRngError;

    fn try_next_u32(&mut self) -> Result<u32, TestRngError> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, TestRngError> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), TestRngError> {
        if self.fail {
            return Err(TestRngError);
        }
        self.next += 1;
        // splitmix64, so draws look unrelated.
        let mut state = self.next;
        for chunk in dst.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for TestRng {}

fn rng() -> TestRng {
    TestRng {
        next: 0,
        fail: false,
    }
}

fn name(text: &str) -> EntryName {
    EntryName::new(text).unwrap()
}

fn vault_binding(digest: &str) -> Binding {
    Binding::new([("vault_sha256", digest)]).unwrap()
}

fn key(byte: u8) -> WrapKey {
    WrapKey::take(&mut [byte; 32])
}

fn id(byte: u8) -> ItemId {
    ItemId::from_bytes([byte; 16])
}

fn sealed(backend: Backend, policy: Policy, item: ItemId) -> Sealed {
    let blob = backend
        .keeps_blob()
        .then(|| Blob::new(vec![0xd0; 200]).unwrap());
    Sealed::new(backend, policy, item, blob).unwrap()
}

fn put<'a>(entry: &str, binding: Binding, secret: &'a [u8]) -> Put<'a> {
    Put {
        name: name(entry),
        binding,
        secret,
    }
}

/// The file's text reads back as the same file.
fn round_trips(file: &SecretsFile) {
    let text = file.text();
    assert_eq!(
        SecretsFile::parse(text.as_bytes()).as_ref(),
        Ok(file),
        "{text}"
    );
}

/// A file with one committed Keychain key under `policy`, holding
/// `quick-unlock`.
fn enrolled(policy: Policy) -> SecretsFile {
    let mut rng = rng();
    SecretsFile::new()
        .begin_create(policy, Backend::MacosKeychain, id(1))
        .unwrap()
        .commit(
            &sealed(Backend::MacosKeychain, policy, id(1)),
            &key(1),
            None,
            Some(put("quick-unlock", vault_binding("aa"), b"password")),
            &mut rng,
        )
        .unwrap()
}

#[test]
fn an_empty_file_has_one_text() {
    let file = SecretsFile::new();
    assert_eq!(
        file.text(),
        "{\n  \"version\": 1,\n  \"keys\": {},\n  \"forget\": [],\n  \"entries\": {}\n}"
    );
    round_trips(&file);
    assert_eq!(file.count(), 0);
}

#[test]
fn create_commit_and_open() {
    let file = enrolled(Policy::Unattended);
    round_trips(&file);
    let quick = name("quick-unlock");
    assert_eq!(file.entry_key(&quick), Some(Policy::Unattended));
    let secret = file.open(&quick, &vault_binding("aa"), &key(1)).unwrap();
    assert_eq!(secret.expose(), b"password");
    assert_eq!(
        file.key(Policy::Unattended),
        Some(sealed(Backend::MacosKeychain, Policy::Unattended, id(1)))
    );
    assert_eq!(file.pending(Policy::Unattended), None);
    assert_eq!(file.count(), 1);
}

#[test]
fn an_entry_under_another_name_binding_or_key_is_refused() {
    let file = enrolled(Policy::Unattended);
    let quick = name("quick-unlock");
    assert_eq!(
        file.open(&quick, &vault_binding("aa"), &key(2)).err(),
        Some(OpenError::Refused)
    );
    assert_eq!(
        file.open(&quick, &vault_binding("bb"), &key(1)).err(),
        Some(OpenError::OtherBinding)
    );
    assert_eq!(
        file.open(&name("other"), &vault_binding("aa"), &key(1))
            .err(),
        Some(OpenError::NoEntry)
    );
    // The entry's bytes moved to another name, or given another binding,
    // in the file itself, don't open.
    let mut moved = file.clone();
    let entry = moved.entries.remove(&quick).unwrap();
    moved.entries.insert(name("quick-unlock-2"), entry.clone());
    assert_eq!(
        moved
            .open(&name("quick-unlock-2"), &vault_binding("aa"), &key(1))
            .err(),
        Some(OpenError::Refused)
    );
    let mut rebound = file.clone();
    rebound.entries.get_mut(&quick).unwrap().binding = vault_binding("bb");
    assert_eq!(
        rebound.open(&quick, &vault_binding("bb"), &key(1)).err(),
        Some(OpenError::Refused)
    );
    let mut flipped = file.clone();
    flipped.entries.get_mut(&quick).unwrap().sealed[0] ^= 1;
    assert_eq!(
        flipped.open(&quick, &vault_binding("aa"), &key(1)).err(),
        Some(OpenError::Refused)
    );
}

#[test]
fn a_replace_rewraps_and_records_the_old_key() {
    let mut r = rng();
    let file = enrolled(Policy::Unattended)
        .put(
            Policy::Unattended,
            &key(1),
            put("rpc-api-key.alchemy", Binding::empty(), b"k-123"),
            &mut r,
        )
        .unwrap();
    let begun = file
        .begin_create(Policy::Unattended, Backend::MacosKeychain, id(2))
        .unwrap();
    round_trips(&begun);
    assert_eq!(begun.count(), 2);
    let new = sealed(Backend::MacosKeychain, Policy::Unattended, id(2));
    assert_eq!(
        begun.commit(&new, &key(2), None, None, &mut r),
        Err(Refused::KeyNeeded)
    );
    assert_eq!(
        begun.commit(&new, &key(2), Some(&key(9)), None, &mut r),
        Err(Refused::EntryRefused)
    );
    let replaced = begun
        .commit(&new, &key(2), Some(&key(1)), None, &mut r)
        .unwrap();
    round_trips(&replaced);
    assert_eq!(replaced.key(Policy::Unattended), Some(new));
    assert_eq!(
        replaced.forget_list(),
        [sealed(Backend::MacosKeychain, Policy::Unattended, id(1))]
    );
    assert_eq!(replaced.count(), 2);
    for (entry, binding, secret) in [
        ("quick-unlock", vault_binding("aa"), &b"password"[..]),
        ("rpc-api-key.alchemy", Binding::empty(), b"k-123"),
    ] {
        assert_eq!(
            replaced
                .open(&name(entry), &binding, &key(2))
                .unwrap()
                .expose(),
            secret
        );
        assert_eq!(
            replaced.open(&name(entry), &binding, &key(1)).err(),
            Some(OpenError::Refused)
        );
    }
    let done = replaced.forgotten(id(1));
    assert!(done.forget_list().is_empty());
    assert_eq!(done.forgotten(id(7)), done);
}

#[test]
fn commit_refusals() {
    let mut r = rng();
    let begun = SecretsFile::new()
        .begin_create(Policy::Unattended, Backend::MacosKeychain, id(1))
        .unwrap();
    // A first key with nothing to put under it.
    assert_eq!(
        begun.commit(
            &sealed(Backend::MacosKeychain, Policy::Unattended, id(1)),
            &key(1),
            None,
            None,
            &mut r
        ),
        Err(Refused::NoEntry)
    );
    // Another item, policy or backend than the pending one.
    for other in [
        sealed(Backend::MacosKeychain, Policy::Unattended, id(2)),
        sealed(Backend::MacosKeychain, Policy::UserPresence, id(1)),
        sealed(Backend::SecretService, Policy::Unattended, id(1)),
    ] {
        assert_eq!(
            begun.commit(
                &other,
                &key(1),
                None,
                Some(put("quick-unlock", Binding::empty(), b"p")),
                &mut r
            ),
            Err(Refused::NotPending)
        );
    }
    // A secret out of its bounds.
    for secret in [&b""[..], &[0u8; MAX_SECRET_BYTES + 1]] {
        assert_eq!(
            begun.commit(
                &sealed(Backend::MacosKeychain, Policy::Unattended, id(1)),
                &key(1),
                None,
                Some(put("quick-unlock", Binding::empty(), secret)),
                &mut r
            ),
            Err(Refused::SecretSize)
        );
    }
    let mut failing = TestRng {
        next: 0,
        fail: true,
    };
    assert_eq!(
        begun.commit(
            &sealed(Backend::MacosKeychain, Policy::Unattended, id(1)),
            &key(1),
            None,
            Some(put("quick-unlock", Binding::empty(), b"p")),
            &mut failing
        ),
        Err(Refused::Randomness)
    );
}

#[test]
fn put_and_remove() {
    let mut r = rng();
    let file = enrolled(Policy::Unattended);
    assert_eq!(
        file.put(
            Policy::UserPresence,
            &key(1),
            put("bee-password", Binding::empty(), b"x"),
            &mut r
        ),
        Err(Refused::NoKey)
    );
    let both = file
        .begin_create(Policy::UserPresence, Backend::MacosKeychain, id(2))
        .unwrap()
        .commit(
            &sealed(Backend::MacosKeychain, Policy::UserPresence, id(2)),
            &key(2),
            None,
            Some(put("export", Binding::empty(), b"y")),
            &mut r,
        )
        .unwrap();
    round_trips(&both);
    assert_eq!(
        both.put(
            Policy::UserPresence,
            &key(2),
            put("quick-unlock", vault_binding("aa"), b"z"),
            &mut r
        ),
        Err(Refused::OtherKey)
    );
    // The same name under the same key is replaced.
    let replaced = both
        .put(
            Policy::Unattended,
            &key(1),
            put("quick-unlock", vault_binding("bb"), b"new"),
            &mut r,
        )
        .unwrap();
    assert_eq!(
        replaced
            .open(&name("quick-unlock"), &vault_binding("bb"), &key(1))
            .unwrap()
            .expose(),
        b"new"
    );
    // The last entry under a key takes the key with it.
    let removed = replaced.remove(&name("quick-unlock")).unwrap();
    round_trips(&removed);
    assert_eq!(removed.key(Policy::Unattended), None);
    assert_eq!(
        removed.forget_list(),
        [sealed(Backend::MacosKeychain, Policy::Unattended, id(1))]
    );
    assert_eq!(removed.remove(&name("quick-unlock")), Err(Refused::NoEntry));
    assert!(removed.key(Policy::UserPresence).is_some());
}

#[test]
fn the_fifth_item_is_refused_and_changes_nothing() {
    let file = enrolled(Policy::Unattended);
    let file = file
        .begin_create(Policy::Unattended, Backend::MacosKeychain, id(2))
        .unwrap()
        .begin_create(Policy::UserPresence, Backend::MacosKeychain, id(3))
        .unwrap();
    // An earlier pending item of the policy moves into `forget`.
    let full = file
        .begin_create(Policy::UserPresence, Backend::MacosKeychain, id(4))
        .unwrap();
    round_trips(&full);
    assert_eq!(full.count(), MAX_ITEMS);
    assert_eq!(
        full.forget_list(),
        [sealed(Backend::MacosKeychain, Policy::UserPresence, id(3))]
    );
    assert_eq!(
        full.pending(Policy::UserPresence),
        Some((Backend::MacosKeychain, id(4)))
    );
    // Replacing the earlier pending item of a policy is a fifth too.
    for policy in Policy::ALL {
        assert_eq!(
            full.begin_create(policy, Backend::MacosKeychain, id(5)),
            Err(Refused::ForgetBacklog)
        );
    }
    // Once a forget succeeds there is room again.
    let room = full.forgotten(id(3));
    assert!(
        room.begin_create(Policy::UserPresence, Backend::MacosKeychain, id(5))
            .is_ok()
    );
    // An id the file names already is refused.
    assert_eq!(
        room.begin_create(Policy::UserPresence, Backend::MacosKeychain, id(1)),
        Err(Refused::Named)
    );
}

#[test]
fn settle_moves_pending_items_and_drops_dpapi_ones() {
    let file = enrolled(Policy::Unattended)
        .begin_create(Policy::Unattended, Backend::MacosKeychain, id(2))
        .unwrap()
        .begin_create(Policy::UserPresence, Backend::Dpapi, id(3))
        .unwrap();
    round_trips(&file);
    let settled = file.settle();
    round_trips(&settled);
    assert_eq!(settled.pending(Policy::Unattended), None);
    assert_eq!(settled.pending(Policy::UserPresence), None);
    assert!(settled.key(Policy::Unattended).is_some());
    assert_eq!(
        settled.forget_list(),
        [sealed(Backend::MacosKeychain, Policy::Unattended, id(2))]
    );
    assert_eq!(settled.settle(), settled);
}

#[test]
fn dpapi_keeps_its_blob_and_no_record() {
    let mut r = rng();
    let dpapi = |item| sealed(Backend::Dpapi, Policy::Unattended, item);
    let file = SecretsFile::new()
        .begin_create(Policy::Unattended, Backend::Dpapi, id(1))
        .unwrap()
        .commit(
            &dpapi(id(1)),
            &key(1),
            None,
            Some(put("bee-password", Binding::empty(), b"pw")),
            &mut r,
        )
        .unwrap();
    round_trips(&file);
    assert_eq!(file.key(Policy::Unattended), Some(dpapi(id(1))));
    let replaced = file
        .begin_create(Policy::Unattended, Backend::Dpapi, id(2))
        .unwrap()
        .commit(&dpapi(id(2)), &key(2), Some(&key(1)), None, &mut r)
        .unwrap();
    round_trips(&replaced);
    assert!(replaced.forget_list().is_empty());
    assert_eq!(replaced.count(), 1);
    let removed = replaced.remove(&name("bee-password")).unwrap();
    assert_eq!(removed, SecretsFile::new());
}

#[test]
fn foreign_records_are_dropped() {
    let mut file = enrolled(Policy::Unattended)
        .remove(&name("quick-unlock"))
        .unwrap();
    file.forget.push(file::Forget {
        backend: Backend::SecretService,
        policy: Policy::UserPresence,
        item: id(9),
    });
    round_trips(&file);
    let mac = file.drop_foreign(Some(Backend::MacosKeychain));
    assert_eq!(
        mac.forget_list(),
        [sealed(Backend::MacosKeychain, Policy::Unattended, id(1))]
    );
    assert!(file.drop_foreign(None).forget_list().is_empty());
}

#[test]
fn a_nonce_is_never_reused_under_a_key() {
    /// Repeats one draw, then counts.
    struct Repeat {
        draws: usize,
        repeat: usize,
    }
    impl rand_core::TryRng for Repeat {
        type Error = TestRngError;
        fn try_next_u32(&mut self) -> Result<u32, TestRngError> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, TestRngError> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), TestRngError> {
            self.draws += 1;
            let value = self.draws.saturating_sub(self.repeat) as u8;
            dst.fill(value);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Repeat {}
    let file = SecretsFile::new()
        .begin_create(Policy::Unattended, Backend::MacosKeychain, id(1))
        .unwrap();
    let commit = |rng: &mut Repeat| {
        file.commit(
            &sealed(Backend::MacosKeychain, Policy::Unattended, id(1)),
            &key(1),
            None,
            Some(put("a", Binding::empty(), b"1")),
            rng,
        )
    };
    let one = commit(&mut Repeat {
        draws: 0,
        repeat: usize::MAX,
    })
    .unwrap();
    // Every later draw repeats the first nonce: refused after four draws.
    let mut stuck = Repeat {
        draws: 0,
        repeat: usize::MAX,
    };
    assert_eq!(
        one.put(
            Policy::Unattended,
            &key(1),
            put("b", Binding::empty(), b"2"),
            &mut stuck
        ),
        Err(Refused::Randomness)
    );
    assert_eq!(stuck.draws, 4);
    // A repeat, then a fresh one: the fresh one is used.
    let mut once = Repeat {
        draws: 0,
        repeat: 1,
    };
    let two = one
        .put(
            Policy::Unattended,
            &key(1),
            put("b", Binding::empty(), b"2"),
            &mut once,
        )
        .unwrap();
    assert_eq!(once.draws, 2);
    round_trips(&two);
}

#[test]
fn the_largest_file_is_within_the_bound() {
    let mut r = rng();
    let big = "\"".repeat(MAX_BINDING_VALUE_BYTES);
    let members: Vec<String> = (0..MAX_BINDING_MEMBERS)
        .map(|n| format!("{}{n}", "m".repeat(MAX_BINDING_NAME_BYTES - 1)))
        .collect();
    let binding = Binding::new(members.iter().map(|m| (m.as_str(), big.as_str()))).unwrap();
    let mut file = SecretsFile::new()
        .begin_create(Policy::UserPresence, Backend::MacosKeychain, id(1))
        .unwrap()
        .commit(
            &sealed(Backend::MacosKeychain, Policy::UserPresence, id(1)),
            &key(1),
            None,
            Some(put(
                &format!("e{:0>63}", 0),
                binding.clone(),
                &[0u8; MAX_SECRET_BYTES],
            )),
            &mut r,
        )
        .unwrap();
    for n in 1..MAX_ENTRIES {
        file = file
            .put(
                Policy::UserPresence,
                &key(1),
                put(
                    &format!("e{n:0>63}"),
                    binding.clone(),
                    &[0u8; MAX_SECRET_BYTES],
                ),
                &mut r,
            )
            .unwrap();
    }
    assert_eq!(
        file.put(
            Policy::UserPresence,
            &key(1),
            put("f", Binding::empty(), b"1"),
            &mut r
        ),
        Err(Refused::Entries)
    );
    // Three more items: the most the file names.
    let file = file
        .begin_create(Policy::UserPresence, Backend::MacosKeychain, id(2))
        .unwrap()
        .begin_create(Policy::Unattended, Backend::MacosKeychain, id(3))
        .unwrap()
        .begin_create(Policy::Unattended, Backend::MacosKeychain, id(4))
        .unwrap();
    assert_eq!(file.count(), MAX_ITEMS);
    let text = file.text();
    assert!(text.len() <= MAX_FILE_BYTES, "{}", text.len());
    round_trips(&file);
}

#[test]
fn names_and_bindings_are_in_form() {
    for good in ["a", "quick-unlock", "rpc-api-key.alchemy", "bee_password2"] {
        assert!(EntryName::new(good).is_some(), "{good}");
    }
    let long = "a".repeat(MAX_NAME_BYTES + 1);
    for bad in ["", "0a", "Quick", "a b", "a/b", "é", "a\0", long.as_str()] {
        assert!(EntryName::new(bad).is_none(), "{bad:?}");
    }
    assert!(Binding::new([("a", "x"), ("a", "y")]).is_none());
    assert!(Binding::new([("A", "x")]).is_none());
    assert!(Binding::new([("a", "")]).is_none());
    assert!(Binding::new([("a", "\n")]).is_none());
    assert!(Binding::new([("a", "é")]).is_none());
    let five: Vec<String> = (0..5).map(|n| format!("m{n}")).collect();
    assert!(Binding::new(five.iter().map(|m| (m.as_str(), "x"))).is_none());
    let binding = Binding::new([("b", "say \"hi\" \\"), ("a", "1")]).unwrap();
    assert_eq!(binding.canonical(), r#"{"a":"1","b":"say \"hi\" \\"}"#);
    assert_eq!(binding.get("b"), Some("say \"hi\" \\"));
    assert_eq!(Binding::empty().canonical(), "{}");
    assert_eq!(
        associated_data(&name("q"), &binding),
        b"freedom-secrets/1\0q\0{\"a\":\"1\",\"b\":\"say \\\"hi\\\" \\\\\"}".to_vec()
    );
}

// ---------------------------------------------------------------------------
// Random sequences: every change keeps the file in form, within its bounds,
// and every entry opening under its key.

#[test]
fn random_sequences_keep_every_invariant() {
    let mut r = rng();
    let mut choose = rng();
    let mut pick = |n: u64| -> u64 {
        let mut bytes = [0u8; 8];
        rand_core::TryRng::try_fill_bytes(&mut choose, &mut bytes).unwrap();
        u64::from_le_bytes(bytes) % n
    };
    for _ in 0..40 {
        let mut file = SecretsFile::new();
        // What each committed key and entry should hold.
        let mut keys: BTreeMap<Policy, u8> = BTreeMap::new();
        let mut secrets: BTreeMap<String, (Policy, Vec<u8>)> = BTreeMap::new();
        let mut next_id = 1u8;
        for _ in 0..30 {
            let policy = Policy::ALL[pick(2) as usize];
            let backend = Backend::ALL[pick(3) as usize];
            let entry = ["a", "b", "c"][pick(3) as usize];
            let result = match pick(6) {
                0 => {
                    next_id += 1;
                    file.begin_create(policy, backend, id(next_id))
                }
                1 => match file.pending(policy) {
                    Some((backend, item)) => {
                        let new_key = item.as_bytes()[0];
                        let secret = vec![new_key; 3];
                        let old = keys.get(&policy).map(|k| key(*k));
                        let put = (!secrets.contains_key(entry)).then(|| Put {
                            name: name(entry),
                            binding: Binding::empty(),
                            secret: &secret,
                        });
                        let out = file.commit(
                            &sealed(backend, policy, item),
                            &key(new_key),
                            old.as_ref(),
                            put,
                            &mut r,
                        );
                        if out.is_ok() {
                            keys.insert(policy, new_key);
                            if !secrets.contains_key(entry) {
                                secrets.insert(entry.to_owned(), (policy, secret.clone()));
                            }
                        }
                        out
                    }
                    None => continue,
                },
                2 => match keys.get(&policy) {
                    Some(k) => {
                        let secret = vec![pick(255) as u8 + 1; 5];
                        let out = file.put(
                            policy,
                            &key(*k),
                            Put {
                                name: name(entry),
                                binding: Binding::empty(),
                                secret: &secret,
                            },
                            &mut r,
                        );
                        if out.is_ok() {
                            secrets.insert(entry.to_owned(), (policy, secret));
                        }
                        out
                    }
                    None => continue,
                },
                3 => {
                    let out = file.remove(&name(entry));
                    if let Ok(next) = &out
                        && let Some((policy, _)) = secrets.remove(entry)
                        && next.key(policy).is_none()
                    {
                        keys.remove(&policy);
                    }
                    out
                }
                4 => {
                    let next = file.settle();
                    Ok(next)
                }
                _ => match file.forget_list().first() {
                    Some(record) => Ok(file.forgotten(record.item())),
                    None => continue,
                },
            };
            if let Ok(next) = result {
                file = next;
            }
            assert!(file.count() <= MAX_ITEMS);
            round_trips(&file);
            for policy in Policy::ALL {
                assert_eq!(file.key(policy).is_some(), keys.contains_key(&policy));
                assert_eq!(file.key(policy).is_some(), file.has_entries(policy));
            }
            for (entry, (policy, secret)) in &secrets {
                assert_eq!(file.entry_key(&name(entry)), Some(*policy));
                let opened = file
                    .open(&name(entry), &Binding::empty(), &key(keys[policy]))
                    .unwrap();
                assert_eq!(opened.expose(), secret.as_slice());
            }
            assert_eq!(file.entry_names().count(), secrets.len());
        }
    }
}

// ---------------------------------------------------------------------------
// The trait's flow, over a key store kept in memory.

#[derive(Default)]
struct MemoryStore {
    items: RefCell<BTreeMap<ItemId, [u8; 32]>>,
    rng: RefCell<Option<TestRng>>,
}

impl KeyStore for MemoryStore {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: Some(Backend::MacosKeychain),
            unattended: true,
            user_presence: false,
        }
    }

    fn create(&self, policy: Policy, label: &Label) -> Result<(WrapKey, Sealed), KeyStoreError> {
        if !self.capabilities().offers(policy) {
            return Err(KeyStoreError::Unavailable);
        }
        let mut rng = self.rng.borrow_mut();
        let key = WrapKey::random(rng.get_or_insert_with(rng_fn))
            .map_err(|_| KeyStoreError::Backend(BackendError::new("rng")))?;
        self.items.borrow_mut().insert(label.item(), *key.expose());
        let sealed = Sealed::new(Backend::MacosKeychain, policy, label.item(), None)
            .map_err(|_| KeyStoreError::Backend(BackendError::new("form")))?;
        Ok((key, sealed))
    }

    fn open(&self, sealed: &Sealed, _reason: Option<Reason>) -> Result<WrapKey, KeyStoreError> {
        let mut bytes = *self
            .items
            .borrow()
            .get(&sealed.item())
            .ok_or(KeyStoreError::NotFound)?;
        Ok(WrapKey::take(&mut bytes))
    }

    fn forget(&self, sealed: &Sealed) -> Result<(), KeyStoreError> {
        self.items.borrow_mut().remove(&sealed.item());
        Ok(())
    }
}

fn rng_fn() -> TestRng {
    TestRng {
        next: 1000,
        fail: false,
    }
}

#[test]
fn the_flow_over_a_key_store() {
    let store = MemoryStore::default();
    let mut r = rng();
    let caps = store.capabilities();
    assert!(caps.offers(Policy::Unattended));
    assert!(!caps.offers(Policy::UserPresence));
    let backend = caps.backend.unwrap();

    // Enroll: pending first, then create, then commit with the entry.
    let item = ItemId::random(&mut r).unwrap();
    let file = SecretsFile::new()
        .begin_create(Policy::Unattended, backend, item)
        .unwrap();
    let (wrap, sealed_key) = store.create(Policy::Unattended, &Label::new(item)).unwrap();
    let file = file
        .commit(
            &sealed_key,
            &wrap,
            None,
            Some(put("quick-unlock", vault_binding("aa"), b"pw")),
            &mut r,
        )
        .unwrap();
    drop(wrap);

    // Unlock: open the key the file names, then the entry.
    let opened = store
        .open(
            &file.key(Policy::Unattended).unwrap(),
            Some(Reason::QuickUnlock),
        )
        .unwrap();
    assert_eq!(
        file.open(&name("quick-unlock"), &vault_binding("aa"), &opened)
            .unwrap()
            .expose(),
        b"pw"
    );

    // Replace: create, commit (re-wrap), then forget the old item.
    let item2 = ItemId::random(&mut r).unwrap();
    let file = file
        .begin_create(Policy::Unattended, backend, item2)
        .unwrap();
    let (wrap2, sealed2) = store
        .create(Policy::Unattended, &Label::new(item2))
        .unwrap();
    let file = file
        .commit(&sealed2, &wrap2, Some(&opened), None, &mut r)
        .unwrap();
    let mut file = file;
    for record in file.forget_list() {
        store.forget(&record).unwrap();
        file = file.forgotten(record.item());
    }
    assert_eq!(store.items.borrow().len(), 1);
    assert_eq!(
        store.open(&sealed_key, None).err(),
        Some(KeyStoreError::NotFound)
    );
    // A forget of a missing item is success.
    assert!(store.forget(&sealed_key).is_ok());

    // A crash after create, before commit: the next open settles it.
    let item3 = ItemId::random(&mut r).unwrap();
    let crashed = file
        .begin_create(Policy::Unattended, backend, item3)
        .unwrap();
    store
        .create(Policy::Unattended, &Label::new(item3))
        .unwrap();
    let mut file = crashed.settle();
    for record in file.forget_list() {
        store.forget(&record).unwrap();
        file = file.forgotten(record.item());
    }
    // The key store holds only the key in use, and the file no record.
    let held: Vec<ItemId> = store.items.borrow().keys().copied().collect();
    assert_eq!(held, [item2]);
    assert!(file.forget_list().is_empty());
    assert_eq!(file.count(), 1);
}
