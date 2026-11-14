//! The macOS Keychain's `Unattended` backend (design 0013, "Backends and
//! dependencies"): a generic-password item in the default keychain (the
//! login keychain), which keeps the 32-byte wrapping key and finds it by
//! its id.
//!
//! - **Its access list** is the one the Keychain gives an item it adds
//!   without one: the calling application's, here the signature of
//!   `freedom-cored`, the binary the helper runs. That binary opens and
//!   removes it without asking.
//! - **Never a prompt:** user interaction is off for the helper's whole
//!   life (`SecKeychainSetUserInteractionAllowed`). A call that would ask
//!   (another binary's item, a locked keychain) fails instead, and the
//!   helper answers `denied`; nothing blocks on a dialog until main's
//!   deadline.
//! - **Added, never updated:** an item already under the id is
//!   `backend`/`duplicate`, never overwritten. Each `create` draws a fresh
//!   128-bit id, so that is never a key in use.
//! - **The calls** are `security-framework`'s (0013 picks it, pinned
//!   exactly): `SecItemAdd`, `SecItemCopyMatching` and `SecItemDelete`.
//!   Its unsafe stays inside it. Core Foundation keeps its own copies of
//!   the key, which it frees unwiped: the helper exits right after.

use core_foundation::data::CFData;
use fc_keystore::{BackendError, ItemId, KeyStoreError, Policy};
use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass, Location};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
};
use zeroize::Zeroizing;

use super::Answer;
use super::helper::OsStore;

/// The items' service: every Freedom key-store item has it, and the item's
/// id as its account.
const SERVICE: &str = "baby.freedom.keystore";
/// What Keychain Access shows as the item's name.
const LABEL: &str = "Freedom key store";

// The OSStatus codes the answer tells apart (Security/SecBase.h).
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
const ERR_SEC_READ_ONLY: i32 = -25292;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_NO_SUCH_KEYCHAIN: i32 = -25294;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_NO_DEFAULT_KEYCHAIN: i32 = -25307;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

/// The login keychain, through `security-framework`.
pub struct Keychain;

impl OsStore for Keychain {
    fn create(&self, policy: Policy, item: ItemId, key: &[u8; 32]) -> Result<(), Answer> {
        unattended(policy)?;
        let _quiet = quiet()?;
        let mut add = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(key),
        });
        add.set_service(SERVICE)
            .set_account_name(item.hex())
            .set_label(LABEL)
            .set_location(Location::DefaultFileKeychain);
        add.add().map_err(|e| answer(e.code()))
    }

    fn open(&self, policy: Policy, item: ItemId) -> Result<Zeroizing<[u8; 32]>, Answer> {
        unattended(policy)?;
        let _quiet = quiet()?;
        let data = Zeroizing::new(
            generic_password(PasswordOptions::new_generic_password(SERVICE, &item.hex()))
                .map_err(|e| answer(e.code()))?,
        );
        // Anything but 32 bytes isn't a key this backend made.
        let mut key = Zeroizing::new([0u8; 32]);
        if data.len() != key.len() {
            return Err(Answer::failed(KeyStoreError::Invalidated, "item_form"));
        }
        key.copy_from_slice(&data);
        Ok(key)
    }

    fn forget(&self, policy: Policy, item: ItemId) -> Result<(), Answer> {
        unattended(policy)?;
        let _quiet = quiet()?;
        delete_generic_password_options(PasswordOptions::new_generic_password(SERVICE, &item.hex()))
            .map_err(|e| answer(e.code()))
    }
}

/// Only `Unattended` here: `UserPresence` needs the data protection
/// keychain and an entitlement (PRF-1c's spike). The helper checks first;
/// this is the backend's own refusal.
fn unattended(policy: Policy) -> Result<(), Answer> {
    match policy {
        Policy::Unattended => Ok(()),
        Policy::UserPresence => Err(Answer::failed(KeyStoreError::Unavailable, "unsupported")),
    }
}

/// User interaction off until the guard drops: a call that would show a
/// dialog fails with `errSecInteractionNotAllowed` instead.
fn quiet() -> Result<security_framework::os::macos::keychain::KeychainUserInteractionLock, Answer> {
    SecKeychain::disable_user_interaction().map_err(|e| answer(e.code()))
}

/// The answer for an OSStatus.
fn answer(status: i32) -> Answer {
    match status {
        ERR_SEC_ITEM_NOT_FOUND => Answer::Failed {
            error: KeyStoreError::NotFound,
            reason: None,
        },
        ERR_SEC_USER_CANCELED => Answer::Failed {
            error: KeyStoreError::Cancelled,
            reason: None,
        },
        ERR_SEC_AUTH_FAILED => Answer::failed(KeyStoreError::Denied, "auth_failed"),
        // Another binary's item, or a locked keychain: either would have
        // asked.
        ERR_SEC_INTERACTION_NOT_ALLOWED => {
            Answer::failed(KeyStoreError::Denied, "interaction_not_allowed")
        }
        ERR_SEC_NOT_AVAILABLE | ERR_SEC_NO_SUCH_KEYCHAIN | ERR_SEC_NO_DEFAULT_KEYCHAIN => {
            Answer::failed(KeyStoreError::Unavailable, "no_keychain")
        }
        ERR_SEC_READ_ONLY => Answer::failed(KeyStoreError::Unavailable, "read_only"),
        ERR_SEC_DUPLICATE_ITEM => Answer::failed(
            KeyStoreError::Backend(BackendError::new("duplicate")),
            "duplicate",
        ),
        _ => Answer::failed(
            KeyStoreError::Backend(BackendError::new("status")),
            "status",
        ),
    }
}
