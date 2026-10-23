#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use serde_json::{Value, json};

/// RFC 8032's first Ed25519 test key: its secret seed and the node ID of
/// its public key (`d75a9801…511a`), computed independently: base58btc over
/// the multicodec `ed01` and the key, after a `z`.
const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_NID: &str = "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

struct Fixed(u8);

/// Makes a request's params for a fresh identity.
type Case = Box<dyn Fn(&Identity) -> String>;
/// Puts something at `keys/radicle`.
type Make = Box<dyn Fn(&Path)>;

impl rand_core::TryRng for Fixed {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from(self.0))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from(self.0))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(self.0);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Fixed {}

fn seed() -> [u8; 32] {
    hex(RFC8032_SEED).try_into().unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn recipient_of(identity: &Identity) -> [u8; 32] {
    STANDARD
        .decode(identity.recipient())
        .unwrap()
        .try_into()
        .unwrap()
}

/// What the core would send: `key` sealed to the service's recipient.
fn sealed_params(identity: &Identity, key: &[u8; 32]) -> String {
    let sealed = fc_seal::seal(&recipient_of(identity), key, &mut Fixed(9)).unwrap();
    json!({ "sealed": {
        "enc": STANDARD.encode(sealed.enc),
        "ciphertext": STANDARD.encode(sealed.ciphertext),
    } })
    .to_string()
}

fn home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn code(result: Result<Value, Failure>) -> ErrorCode {
    result.unwrap_err().0.code
}

#[test]
fn the_recipient_is_32_bytes_of_base64_and_fresh_per_start() {
    let home = home();
    let a = Identity::new(home.path()).unwrap();
    let b = Identity::new(home.path()).unwrap();
    assert_eq!(recipient_of(&a).len(), 32);
    assert_ne!(a.recipient(), b.recipient());
}

#[test]
fn a_sealed_key_gives_its_identity() {
    let home = home();
    let identity = Identity::new(home.path()).unwrap();
    let params = sealed_params(&identity, &seed());
    assert!(!identity.known());
    let result = identity.establish(Some(&params)).unwrap();
    assert_eq!(
        result,
        json!({
            "did": format!("did:key:{RFC8032_NID}"),
            "nid": RFC8032_NID,
            "ephemeral": false,
        })
    );
    assert!(identity.known());
    assert_eq!(identity.with(NodeIdentity::holds_key), Some(true));
    assert_eq!(identity.with(|i| i.nid.clone()).unwrap(), RFC8032_NID);
}

#[test]
fn a_second_call_is_invalid_and_keeps_the_identity() {
    let home = home();
    let identity = Identity::new(home.path()).unwrap();
    identity
        .establish(Some(&sealed_params(&identity, &seed())))
        .unwrap();
    let again = identity.establish(Some(&json!({ "ephemeral": true }).to_string()));
    assert_eq!(code(again), ErrorCode::InvalidArgument);
    assert_eq!(identity.with(|i| i.nid.clone()).unwrap(), RFC8032_NID);
}

#[test]
fn a_ciphertext_that_doesnt_open_is_bad_sealed_key_and_the_one_attempt() {
    let home = home();
    let tampered = |identity: &Identity| {
        let mut params: Value = serde_json::from_str(&sealed_params(identity, &seed())).unwrap();
        let ct = params["sealed"]["ciphertext"].as_str().unwrap().to_owned();
        let mut bytes = STANDARD.decode(ct).unwrap();
        bytes[0] ^= 1;
        params["sealed"]["ciphertext"] = STANDARD.encode(bytes).into();
        params.to_string()
    };
    let other = Identity::new(home.path()).unwrap();
    let to_other = sealed_params(&other, &seed());
    let cases: Vec<Case> = vec![
        Box::new(tampered),
        // Sealed to another start's key.
        Box::new(move |_| to_other.clone()),
        Box::new(|_| json!({ "sealed": { "enc": "!!", "ciphertext": "AA==" } }).to_string()),
        Box::new(|i| {
            let mut p: Value = serde_json::from_str(&sealed_params(i, &seed())).unwrap();
            p["sealed"]["enc"] = STANDARD.encode([1u8; 31]).into();
            p.to_string()
        }),
        Box::new(|i| {
            let mut p: Value = serde_json::from_str(&sealed_params(i, &seed())).unwrap();
            let ct = STANDARD
                .decode(p["sealed"]["ciphertext"].as_str().unwrap())
                .unwrap();
            p["sealed"]["ciphertext"] = STANDARD.encode(&ct[..47]).into();
            p.to_string()
        }),
    ];
    for (i, case) in cases.iter().enumerate() {
        let identity = Identity::new(home.path()).unwrap();
        let params = case(&identity);
        assert_eq!(
            code(identity.establish(Some(&params))),
            ErrorCode::BadSealedKey,
            "case {i}"
        );
        assert!(!identity.known());
        // The key for this start is gone: even the right ciphertext can't
        // open now.
        let right = sealed_params(&identity, &seed());
        assert_eq!(
            code(identity.establish(Some(&right))),
            ErrorCode::InvalidArgument,
            "case {i}"
        );
    }
}

#[test]
fn a_throwaway_key_is_fresh_each_start_and_marked_ephemeral() {
    let home = home();
    let params = json!({ "ephemeral": true }).to_string();
    let a = Identity::new(home.path()).unwrap();
    let b = Identity::new(home.path()).unwrap();
    let ra = a.establish(Some(&params)).unwrap();
    let rb = b.establish(Some(&params)).unwrap();
    assert_eq!(ra["ephemeral"], true);
    assert_ne!(ra["nid"], rb["nid"]);
    assert_eq!(
        ra["did"].as_str().unwrap(),
        format!("did:key:{}", ra["nid"].as_str().unwrap())
    );
    // Nothing was written under the home.
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn the_form_must_be_exactly_one_of_the_two() {
    let home = home();
    for params in [
        json!({}),
        json!({ "ephemeral": false }),
        json!({ "ephemeral": true, "sealed": { "enc": "", "ciphertext": "" } }),
        json!({ "ephemeral": true, "other": 1 }),
        json!({ "sealed": { "enc": "", "ciphertext": "", "other": 1 } }),
        json!({ "ephemeral": "true" }),
        json!([]),
    ] {
        let identity = Identity::new(home.path()).unwrap();
        assert_eq!(
            code(identity.establish(Some(&params.to_string()))),
            ErrorCode::InvalidArgument,
            "{params}"
        );
    }
    let identity = Identity::new(home.path()).unwrap();
    assert_eq!(code(identity.establish(None)), ErrorCode::InvalidArgument);
}

/// Anything at `keys/radicle` refuses the start before the ciphertext is
/// opened: the right ciphertext, a throwaway request, each refused.
#[test]
fn anything_at_the_key_file_is_key_file_present() {
    let make: Vec<(&str, Make)> = vec![
        (
            "file",
            Box::new(|keys: &Path| std::fs::write(keys.join("radicle"), b"x").unwrap()),
        ),
        (
            "directory",
            Box::new(|keys: &Path| std::fs::create_dir(keys.join("radicle")).unwrap()),
        ),
        #[cfg(unix)]
        (
            "dangling symlink",
            Box::new(|keys: &Path| {
                std::os::unix::fs::symlink(keys.join("missing"), keys.join("radicle")).unwrap();
            }),
        ),
    ];
    for (what, make) in make {
        for ephemeral in [false, true] {
            let home = home();
            let keys = home.path().join("keys");
            std::fs::create_dir(&keys).unwrap();
            make(&keys);
            let identity = Identity::new(home.path()).unwrap();
            let params = if ephemeral {
                json!({ "ephemeral": true }).to_string()
            } else {
                sealed_params(&identity, &seed())
            };
            assert_eq!(
                code(identity.establish(Some(&params))),
                ErrorCode::KeyFilePresent,
                "{what}, ephemeral {ephemeral}"
            );
            assert!(!identity.known());
        }
    }
}

#[test]
fn no_key_file_where_keys_isnt_a_directory_or_is_missing() {
    let home = home();
    assert!(!key_file_present(home.path()));
    std::fs::create_dir(home.path().join("keys")).unwrap();
    assert!(!key_file_present(home.path()));
    std::fs::write(home.path().join("keys").join("radicle.pub"), b"x").unwrap();
    assert!(!key_file_present(home.path()));
    let other = self::home();
    std::fs::write(other.path().join("keys"), b"a file").unwrap();
    assert!(!key_file_present(other.path()));
}

#[test]
fn nothing_prints_the_key() {
    let home = home();
    let identity = Identity::new(home.path()).unwrap();
    identity
        .establish(Some(&sealed_params(&identity, &seed())))
        .unwrap();
    let printed = identity.with(|i| format!("{i:?}")).unwrap();
    assert!(!printed.contains(&RFC8032_SEED[..16]));
    assert!(printed.contains(RFC8032_NID));
}
