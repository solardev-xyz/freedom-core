//! The method table (design 0001, "Messages"; #101): every method
//! `freedom-cored` serves, with the callers it accepts, whether it writes
//! the user's identity data, and the deadline the core applies to it.
//!
//! The core checks a request against this table once, before it dispatches
//! anything: a method the table doesn't list is unknown, and a caller the
//! table doesn't list for it is refused with `forbidden`. A new method is
//! therefore unreachable until it has a row, and its callers are explicit:
//! nothing is allowed by default.
//!
//! [`schema_json`] renders the table as `protocol/schema.json`, which is
//! committed; a test fails when the two differ, and freedom-browser checks
//! its proxy table against the file.

use crate::message::CallerKind;

/// Which callers a method accepts (design 0001, "Caller context").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Callers {
    /// Main itself only (`shell`): the handshake, shutdown, reconciliation
    /// and the temporary `compat.*` exports, never a renderer channel.
    Shell,
    /// The browser UI (`chrome`) and main itself (`shell`).
    ChromeOrShell,
}

impl Callers {
    pub fn allow(self, caller: CallerKind) -> bool {
        match (self, caller) {
            (_, CallerKind::Page) => false,
            (Callers::Shell, CallerKind::Shell) => true,
            (Callers::Shell, CallerKind::Chrome) => false,
            (Callers::ChromeOrShell, CallerKind::Chrome | CallerKind::Shell) => true,
        }
    }

    fn names(self) -> &'static [&'static str] {
        match self {
            Callers::Shell => &["shell"],
            Callers::ChromeOrShell => &["chrome", "shell"],
        }
    }
}

/// The deadline the core applies to a method (design 0001, "Deadlines,
/// cancellation and commit").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deadline {
    /// Answered at once, on the loop or its thread: no deadline.
    Immediate,
    /// The vault queue's: 30 s from admission, queue time included.
    Vault,
    /// A naming or chain session's: 120 s, or the caller's shorter
    /// `deadline_ms` where the method takes one (designs 0004 and 0005).
    Session,
}

impl Deadline {
    /// The default, in milliseconds; `None` when answered at once.
    pub fn default_ms(self) -> Option<u64> {
        match self {
            Deadline::Immediate => None,
            Deadline::Vault => Some(30_000),
            Deadline::Session => Some(120_000),
        }
    }
}

/// One row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Method {
    pub name: &'static str,
    pub callers: Callers,
    /// Whether it writes the user's identity data (the vault file, node
    /// identities): design 0001's mutations, serialized and reconcilable.
    pub mutates: bool,
    pub deadline: Deadline,
}

const fn row(name: &'static str, callers: Callers, mutates: bool, deadline: Deadline) -> Method {
    Method {
        name,
        callers,
        mutates,
        deadline,
    }
}

use Callers::{ChromeOrShell as CS, Shell as SHELL};
use Deadline::{Immediate as NOW, Session as SESSION, Vault as VAULT};

/// Every method, in `core.hello`'s capability order, then the `chain.*`
/// methods.
pub const METHODS: &[Method] = &[
    row("core.hello", SHELL, false, NOW),
    row("core.shutdown", SHELL, false, NOW),
    row("vault.status", CS, false, NOW),
    row("vault.lock", CS, false, NOW),
    row("vault.touch", CS, false, NOW),
    row("vault.unlock", CS, false, VAULT),
    row("vault.verify_password", CS, false, VAULT),
    row("vault.change_password", CS, true, VAULT),
    row("vault.delete", CS, true, VAULT),
    row("vault.export_mnemonic", CS, false, VAULT),
    row("vault.export_private_key", CS, false, VAULT),
    row("vault.create", CS, true, VAULT),
    row("vault.import", CS, true, VAULT),
    row("vault.reconcile", SHELL, false, VAULT),
    row("nodes.write_identity", CS, true, VAULT),
    row("nodes.op_status", SHELL, false, VAULT),
    // Design 0008, "The sealed release": the Radicle node key, sealed to the
    // Radicle service. Main's own: no renderer channel reaches it.
    row("nodes.seal_radicle_key", SHELL, false, NOW),
    row("keys.generate_mnemonic", CS, false, NOW),
    row("keys.validate_mnemonic", CS, false, NOW),
    row("keys.addresses", CS, false, NOW),
    row("keys.radicle_did", CS, false, NOW),
    row("compat.private_key", SHELL, false, NOW),
    row("compat.bee_wallet_key", SHELL, false, NOW),
    row("compat.publisher_key", SHELL, false, NOW),
    row("sign.transaction", CS, false, NOW),
    row("sign.message", CS, false, NOW),
    row("sign.typed_data", CS, false, NOW),
    row("swarm.sign_soc", CS, false, NOW),
    row("typed_data.hash", CS, false, NOW),
    row("naming.configure", CS, false, NOW),
    row("naming.availability", CS, false, NOW),
    row("naming.resolve_content", CS, false, SESSION),
    row("naming.resolve_address", CS, false, SESSION),
    row("naming.resolve_reverse", CS, false, SESSION),
    row("naming.resolve_tezos", CS, false, SESSION),
    row("naming.invalidate_content", CS, false, NOW),
    row("naming.invalidate_tezos", CS, false, NOW),
    row("dweb.open", SHELL, false, SESSION),
    row("chain.configure", CS, false, NOW),
    row("chain.availability", CS, false, NOW),
    row("chain.request", CS, false, SESSION),
    row("chain.fee_quote", CS, false, SESSION),
    row("chain.fee_reference", CS, false, SESSION),
    row("chain.broadcast", CS, false, SESSION),
    row("chain.html", CS, false, SESSION),
];

/// The row for `name`, if the core serves it.
pub fn method(name: &str) -> Option<&'static Method> {
    METHODS.iter().find(|m| m.name == name)
}

/// What the table says of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed(&'static Method),
    /// The core serves no such method (`unknown_method`).
    Unknown,
    /// The method exists, but not for this caller (`forbidden`).
    Forbidden,
}

/// Checks a request's method and caller against the table.
pub fn admit(name: &str, caller: CallerKind) -> Admission {
    match method(name) {
        None => Admission::Unknown,
        Some(row) if row.callers.allow(caller) => Admission::Allowed(row),
        Some(_) => Admission::Forbidden,
    }
}

/// `protocol/schema.json`: the table as JSON, one method per line.
pub fn schema_json() -> String {
    let mut out = String::from("{\n  \"protocol\": ");
    out.push_str(&crate::PROTOCOL_VERSION.to_string());
    out.push_str(",\n  \"methods\": [\n");
    for (i, m) in METHODS.iter().enumerate() {
        let callers: Vec<String> = m
            .callers
            .names()
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect();
        let deadline = m
            .deadline
            .default_ms()
            .map_or("null".to_owned(), |ms| ms.to_string());
        out.push_str(&format!(
            "    {{ \"name\": \"{}\", \"callers\": [{}], \"mutates\": {}, \"deadline_ms\": {} }}",
            m.name,
            callers.join(", "),
            m.mutates,
            deadline
        ));
        out.push_str(if i + 1 < METHODS.len() { ",\n" } else { "\n" });
    }
    out.push_str("  ]\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_core_is_shell_only() {
        for (i, m) in METHODS.iter().enumerate() {
            assert!(
                METHODS[i + 1..].iter().all(|n| n.name != m.name),
                "{} twice",
                m.name
            );
        }
        for name in [
            "core.hello",
            "core.shutdown",
            "vault.reconcile",
            "dweb.open",
        ] {
            assert_eq!(
                admit(name, CallerKind::Chrome),
                Admission::Forbidden,
                "{name}"
            );
            assert!(matches!(
                admit(name, CallerKind::Shell),
                Admission::Allowed(_)
            ));
        }
        for m in METHODS {
            assert_eq!(admit(m.name, CallerKind::Page), Admission::Forbidden);
            if m.name.starts_with("compat.") {
                assert_eq!(m.callers, Callers::Shell, "{}", m.name);
            }
        }
        assert_eq!(
            admit("vault.unlock", CallerKind::Chrome),
            Admission::Allowed(&METHODS[5])
        );
        assert_eq!(
            admit("compat.secret", CallerKind::Shell),
            Admission::Unknown
        );
    }

    #[test]
    fn the_committed_schema_is_current() {
        let committed = include_str!("../../../protocol/schema.json");
        assert!(
            committed == schema_json(),
            "protocol/schema.json is stale; regenerate it with:\n  \
             FC_PROTOCOL_WRITE_SCHEMA=1 cargo test -p fc-protocol write_schema_when_asked\n\
             expected:\n{}",
            schema_json()
        );
    }

    /// With `FC_PROTOCOL_WRITE_SCHEMA=1`, writes the file: run this test by
    /// name when the table changes, then the one above passes.
    #[test]
    fn write_schema_when_asked() {
        if std::env::var_os("FC_PROTOCOL_WRITE_SCHEMA").is_some() {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../protocol/schema.json");
            std::fs::write(path, schema_json()).unwrap();
        }
    }
}
