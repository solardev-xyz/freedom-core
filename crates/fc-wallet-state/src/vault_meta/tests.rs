use super::*;

fn meta(text: &str) -> VaultMeta {
    VaultMeta::load(text.as_bytes()).expect("readable")
}

fn s(text: &str) -> JsValue {
    JsValue::string(text)
}

const A: &str = "0x8ba1f109551bD432803012645Ac136ddd64DBA72";
const B: &str = "0xB1B1B1B1b1B1b1b1b1B1B1B1B1b1b1B1b1b1B1B1";

#[test]
fn hardware_index_is_the_larger_of_counter_and_high_water() {
    let none = r#"{"derivedWallets": [{"index": 0}]}"#;
    assert_eq!(meta(none).next_hardware_index(), Some(HARDWARE_INDEX_BASE));
    let stale = r#"{"derivedWallets": [{"index": 0}, {"index": 1000004}], "nextHardwareWalletIndex": 1000001}"#;
    assert_eq!(meta(stale).next_hardware_index(), Some(1_000_005.0));
    let ahead = r#"{"derivedWallets": [{"index": 1000004}], "nextHardwareWalletIndex": 1000009}"#;
    assert_eq!(meta(ahead).next_hardware_index(), Some(1_000_009.0));
    let below = r#"{"derivedWallets": [{"index": 3}], "nextHardwareWalletIndex": 5}"#;
    assert_eq!(meta(below).next_hardware_index(), Some(HARDWARE_INDEX_BASE));
    let fraction = r#"{"derivedWallets": [], "nextHardwareWalletIndex": 1000007.5}"#;
    assert_eq!(
        meta(fraction).next_hardware_index(),
        Some(HARDWARE_INDEX_BASE)
    );
    assert_eq!(VaultMeta::none().next_hardware_index(), None);
}

#[test]
fn mnemonic_index_skips_hardware_and_taken_indices() {
    let wallets = |text: &str| wallet_list(&fc_json::parse(text).unwrap());
    assert_eq!(
        next_mnemonic_index(&wallets(r#"{"derivedWallets": []}"#)),
        0.0
    );
    assert_eq!(
        next_mnemonic_index(&wallets(
            r#"{"derivedWallets": [{"index": 0}, {"index": 4}]}"#
        )),
        5.0
    );
    assert_eq!(
        next_mnemonic_index(&wallets(
            r#"{"derivedWallets": [{"index": 0}, {"index": 1000000}]}"#
        )),
        1.0
    );
    assert_eq!(
        next_mnemonic_index(&wallets(
            r#"{"derivedWallets": [{"index": 999999}, {"index": 1000000}, {"index": 1000001}]}"#
        )),
        1_000_002.0
    );
    assert_eq!(
        next_mnemonic_index(&wallets(r#"{"derivedWallets": [{"index": -4}]}"#)),
        0.0
    );
}

#[test]
fn add_mnemonic_derives_the_next_index() {
    let mut m = meta(
        r#"{"derivedWallets": [{"index": 0, "name": "Main Wallet"}, {"index": 1000000, "type": "ledger"}]}"#,
    );
    let mut asked = None;
    let done = m
        .add_mnemonic(true, &s(""), |index| {
            asked = Some(index);
            Ok::<_, ()>(Some(A.to_owned()))
        })
        .unwrap();
    assert_eq!(asked, Some(1.0));
    assert!(done.wrote);
    assert_eq!(
        done.value.stringify(),
        format!(r#"{{"index":1,"name":"Wallet 2","address":"{A}"}}"#)
    );
    let locked = m.add_mnemonic(true, &s("x"), |_| Ok::<_, ()>(None));
    assert_eq!(locked, Err(Failed::Refused(Refusal::new(MUST_UNLOCK))));
    assert_eq!(
        m.add_mnemonic(false, &s("x"), |_| Err(())),
        Err(Failed::Refused(Refusal::new(MUST_UNLOCK)))
    );
    assert_eq!(
        m.add_mnemonic(true, &s("x"), |_| Err::<Option<String>, _>(7)),
        Err(Failed::Derive(7))
    );
}

#[test]
fn address_checks_stay_matched() {
    let mut m = meta(
        r#"{"derivedWallets": [{"index": 1000000, "type": "ledger", "addressCheck": "bogus"}]}"#,
    );
    let check =
        |m: &mut VaultMeta, matched| m.record_address_check(Device::Ledger, 1_000_000.0, matched);
    assert_eq!(
        check(&mut m, false),
        Changed {
            value: Some(MISMATCHED),
            wrote: true
        }
    );
    assert_eq!(
        check(&mut m, false),
        Changed {
            value: Some(MISMATCHED),
            wrote: false
        }
    );
    assert_eq!(
        check(&mut m, true),
        Changed {
            value: Some(MATCHED),
            wrote: true
        }
    );
    assert_eq!(
        check(&mut m, false),
        Changed {
            value: Some(MATCHED),
            wrote: false
        }
    );
    assert_eq!(
        check(&mut m, true),
        Changed {
            value: Some(MATCHED),
            wrote: false
        }
    );
    let other = m.record_address_check(Device::Remote, 1_000_000.0, true);
    assert_eq!(
        other,
        Changed {
            value: None,
            wrote: false
        }
    );
}

#[test]
fn removing_the_active_wallet_resets_it() {
    let text =
        r#"{"derivedWallets": [{"index": 0}, {"index": 1}, {"index": 2}], "activeWalletIndex": 2}"#;
    let mut m = meta(text);
    m.remove(1.0, &[]).unwrap();
    assert_eq!(m.active_index(), 2.0);
    let done = m.remove(2.0, &[]).unwrap();
    assert_eq!(
        done.value,
        Removal {
            index: 2.0,
            safe: false
        }
    );
    assert_eq!(m.active_index(), 0.0);
    let mut unset = meta(r#"{"derivedWallets": [{"index": 0}, {"index": 1}]}"#);
    unset.remove(1.0, &[]).unwrap();
    assert_eq!(
        unset.value().unwrap().get("activeWalletIndex"),
        Some(&JsValue::Number(0.0))
    );
    assert_eq!(
        m.remove(0.0, &[]).unwrap_err().message,
        "Cannot delete the main wallet (index 0)"
    );
}

#[test]
fn removal_refusals() {
    let text = r#"{"derivedWallets": [{"index": 0}, {"index": 1000000, "type": "ledger"},
        {"index": 1000001, "type": "safe", "name": "S", "owners": [0, 1000000]}]}"#;
    let m = meta(text);
    let owner = m.check_remove(1_000_000.0, &[]).unwrap_err();
    assert_eq!(
        owner.message,
        "This account is an owner of \"S\" \u{2014} delete that Safe account first"
    );
    assert_eq!(
        m.check_remove(1_000_001.0, &[]).unwrap(),
        Removal {
            index: 1_000_001.0,
            safe: true
        }
    );
    let origins: Vec<String> = ["a", "b", "c", "d", "e"]
        .iter()
        .map(|o| format!("https://{o}"))
        .collect();
    let used = m.check_remove(1_000_001.0, &origins).unwrap_err();
    assert_eq!(
        used.code,
        Some(codes::SWARM_PUBLISHER_IDENTITY_WALLET_IN_USE)
    );
    assert!(
        used.message
            .contains("https://a, https://b, https://c and 2 more."),
        "{}",
        used.message
    );
    let three = m.check_remove(1_000_001.0, &origins[..3]).unwrap_err();
    assert!(
        three.message.contains("https://c. Switch"),
        "{}",
        three.message
    );
    assert_eq!(
        m.check_remove(5.0, &origins).unwrap_err().message,
        "Wallet with index 5 does not exist"
    );
}

fn safe(
    m: &mut VaultMeta,
    owners: &str,
    threshold: f64,
    salt: JsValue,
) -> Result<Changed<JsValue>, Refusal> {
    let owners = fc_json::parse(owners).unwrap();
    m.add_safe(
        &s(""),
        SafeParams {
            address: &s(B),
            owners: &owners,
            threshold: &JsValue::Number(threshold),
            salt_nonce: &salt,
        },
    )
}

#[test]
fn safe_presets_and_owners() {
    let text = r#"{"derivedWallets": [{"index": 0}, {"index": 1}, {"index": 2},
        {"index": 1000000, "type": "ledger", "name": "L", "addressCheck": "matched"},
        {"index": 1000001, "type": "remote", "name": "P"},
        {"index": 1000002, "type": "toString", "name": "T"}]}"#;
    let mut m = meta(text);
    let preset = "A Safe needs 1 of 2 or 2 of 3 owners";
    assert_eq!(
        safe(&mut m, "[0, 1]", 2.0, s("1")).unwrap_err().message,
        preset
    );
    assert_eq!(
        safe(&mut m, "[0, 1, 2]", 1.0, s("1")).unwrap_err().message,
        preset
    );
    assert_eq!(
        safe(&mut m, "[0]", 1.0, s("1")).unwrap_err().message,
        preset
    );
    assert_eq!(
        safe(&mut m, "[0, 1, 2, 1000000]", 2.0, s("1"))
            .unwrap_err()
            .message,
        preset
    );
    assert_eq!(
        safe(&mut m, "[1, 1]", 1.0, s("1")).unwrap_err().message,
        "Duplicate owner accounts"
    );
    assert_eq!(
        safe(&mut m, "[0, 1, 0]", 2.0, s("1")).unwrap_err().message,
        "Duplicate owner accounts"
    );
    assert_eq!(
        safe(&mut m, r#"[0, "1"]"#, 1.0, s("1"))
            .unwrap_err()
            .message,
        "Owner wallet index 1 does not exist"
    );
    let unchecked = safe(&mut m, "[0, 1000001]", 1.0, s("1")).unwrap_err();
    assert_eq!(unchecked.code, Some(codes::REMOTE_ACCOUNT_UNCHECKED));
    let prototype = safe(&mut m, "[0, 1000002]", 1.0, s("1")).unwrap_err();
    assert_eq!(prototype.message, "check.unchecked is not a function");
    assert_eq!(
        safe(&mut m, "[0, 1]", 1.0, s("01a")).unwrap_err().message,
        "Invalid Safe salt nonce"
    );
    assert_eq!(
        safe(&mut m, "[0, 1]", 1.0, JsValue::Number(1.0))
            .unwrap_err()
            .message,
        "Invalid Safe salt nonce"
    );
    let done = safe(&mut m, "[1000000, 0, 2]", 2.0, s("0012")).unwrap();
    assert_eq!(done.value.get("name"), Some(&s("Safe 1")));
    assert_eq!(done.value.get("index"), Some(&JsValue::Number(1_000_003.0)));
    let again = safe(&mut m, "[0, 2]", 1.0, s("3")).unwrap_err();
    assert_eq!(
        again.message,
        "This account is already in your wallet list as \"Safe 1\""
    );
    let not_owner = safe(&mut m, "[0, 1000003]", 1.0, s("3")).unwrap_err();
    assert_eq!(not_owner.message, "A Safe cannot own another Safe");
}

#[test]
fn duplicates_are_case_insensitive() {
    let m = meta(&format!(
        r#"{{"derivedWallets": [{{"index": 0, "name": "M", "address": "{}"}}]}}"#,
        A.to_lowercase()
    ));
    let err = m.check_device_addable(Kind::Remote, &s(A)).unwrap_err();
    assert_eq!(
        err.message,
        "This account is already in your wallet list as \"M\""
    );
    assert!(m.check_device_addable(Kind::Remote, &s(B)).is_ok());
    assert!(m.check_device_addable(Kind::Remote, &s(&A[2..])).is_ok());
    assert_eq!(
        m.check_device_addable(Kind::Ledger, &s("nope"))
            .unwrap_err()
            .message,
        "Invalid Ledger account address"
    );
    let mut numeric = meta(r#"{"derivedWallets": [{"index": 0, "address": 5}]}"#);
    let thrown = numeric.add_remote(&s(""), &s(A)).unwrap_err();
    assert_eq!(
        thrown.message,
        "wallet.address.toLowerCase is not a function"
    );
    assert!(
        m.find_by_address(&s(&A.to_uppercase().replacen("0X", "0x", 1)))
            .is_some()
    );
    assert!(m.find_by_address(&s(B)).is_none());
}

#[test]
fn deployed_mark_replaces_a_legacy_one() {
    let mut m = meta(
        r#"{"derivedWallets": [{"index": 1000000, "type": "safe", "deployed": {"5": true, "1": {"verified": true}}}]}"#,
    );
    assert_eq!(
        m.record(1_000_000.0)
            .unwrap()
            .get("deployed")
            .unwrap()
            .stringify(),
        r#"{"1":true}"#
    );
    m.mark_safe_deployed(1_000_000.0, 5.0).unwrap();
    let deployed = m
        .record(1_000_000.0)
        .unwrap()
        .get("deployed")
        .unwrap()
        .stringify();
    assert_eq!(deployed, r#"{"1":true,"5":true}"#);
    let stored = m
        .value()
        .unwrap()
        .get("derivedWallets")
        .unwrap()
        .as_array()
        .unwrap()[0]
        .get("deployed")
        .unwrap()
        .stringify();
    assert_eq!(stored, r#"{"1":{"verified":true},"5":{"verified":true}}"#);
    assert_eq!(
        m.mark_safe_deployed(1.0, 5.0).unwrap_err().message,
        "Wallet 1 is not a Safe account"
    );
}

#[test]
fn list_writes_only_its_lazy_init() {
    let mut m = meta(r#"{"activeWalletIndex": 4}"#);
    let first = m
        .list(|_| -> Result<_, ()> { panic!("no derivation for the default list") })
        .unwrap();
    assert!(first.wrote);
    assert_eq!(m.active_index(), 0.0);
    let second = m
        .list(|indices| Ok::<_, ()>(Some(vec![(indices[0], A.to_owned())])))
        .unwrap();
    assert!(!second.wrote);
    assert_eq!(second.value[0].get("address"), Some(&s(A)));
    assert_eq!(
        VaultMeta::none().list(|_| Err(())).unwrap(),
        Changed {
            value: Vec::new(),
            wrote: false
        }
    );
}

#[test]
fn device_names() {
    let mut m = meta(r#"{"derivedWallets": [{"index": 0}]}"#);
    let added = m.add_remote(&s(" \u{feff}Mine\u{a0}"), &s(A)).unwrap();
    assert_eq!(added.value.get("name"), Some(&s("Mine")));
    let auto = m.add_remote(&JsValue::Null, &s(B)).unwrap();
    assert_eq!(auto.value.get("name"), Some(&s("Phone 2")));
    assert_eq!(auto.value.get("index"), Some(&JsValue::Number(1_000_001.0)));
    let typed = m
        .add_device(
            Kind::Ledger,
            &JsValue::Number(5.0),
            &s(&A[2..]),
            &JsValue::Null,
        )
        .unwrap_err();
    assert_eq!(typed.message, "(name || \"\").trim is not a function");
}

#[test]
fn shape() {
    let unreadable = |text: &str| VaultMeta::load(text.as_bytes()).unwrap_err();
    assert_eq!(unreadable("[]"), Unreadable::NotObject);
    assert_eq!(unreadable("\u{feff}{}"), Unreadable::NotJson);
    assert_eq!(
        unreadable(r#"{"derivedWallets": 1}"#),
        Unreadable::WalletsNotArray
    );
    assert_eq!(
        unreadable(r#"{"derivedWallets": [1]}"#),
        Unreadable::RecordNotObject
    );
    assert_eq!(
        unreadable(r#"{"derivedWallets": [{"index": "1"}]}"#),
        Unreadable::IndexNotInteger
    );
    assert_eq!(
        unreadable(r#"{"activeWalletIndex": true}"#),
        Unreadable::ActiveNotInteger
    );
    assert_eq!(
        unreadable(r#"{"derivedWallets": [{"index": 1, "type": "safe", "owners": {}}]}"#),
        Unreadable::OwnersNotArray
    );
    assert!(
        VaultMeta::load(
            r#"{"derivedWallets": [{"index": 1, "type": "remote", "owners": {}}]}"#.as_bytes()
        )
        .is_ok()
    );
    assert!(
        VaultMeta::load(r#"{"derivedWallets": 0, "activeWalletIndex": null}"#.as_bytes()).is_ok()
    );
    let at = format!(r#"{{"p": "{}"}}"#, "x".repeat(MAX_FILE_BYTES - 9));
    assert_eq!(at.len(), MAX_FILE_BYTES);
    assert!(VaultMeta::load(at.as_bytes()).is_ok());
    assert_eq!(
        unreadable(&format!(r#"{{"p": "{}"}}"#, "x".repeat(MAX_FILE_BYTES - 8))),
        Unreadable::TooLarge
    );
}

#[test]
fn new_vault_and_migration() {
    let mut m = VaultMeta::none();
    assert!(
        m.migrate_addresses(A, B)
            == Changed {
                value: (),
                wrote: false
            }
    );
    m.new_vault(false, 1_762_000_000_000, A, B).unwrap();
    assert_eq!(
        m.text().unwrap(),
        format!(
            "{{\n  \"userKnowsPassword\": false,\n  \"createdAt\": \"2025-11-01T12:26:40.000Z\",\n  \"addresses\": {{\n    \"userWallet\": \"{A}\",\n    \"beeWallet\": \"{B}\"\n  }}\n}}"
        )
    );
    assert!(!m.migrate_addresses(B, A).wrote);
    let mut old = meta(r#"{"addresses": 0, "x": 1}"#);
    assert!(old.migrate_addresses(A, B).wrote);
    assert!(old.text().unwrap().starts_with("{\n  \"addresses\": {"));
    assert_eq!(
        m.new_vault(true, i64::MAX, A, B).unwrap_err().message,
        "Invalid time value"
    );
}
