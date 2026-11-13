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
    /// Main itself only (`shell`): the handshake, shutdown and
    /// reconciliation, never a renderer channel.
    Shell,
    /// The browser UI (`chrome`) and main itself (`shell`).
    ChromeOrShell,
    /// A page (`page`, with its `PageContext`) as well: the rows 0011 left
    /// for 0012 (design 0012, "PageContext"). The method checks what each
    /// caller may do (a page kind's token only under `page`, a wallet
    /// kind's never).
    PageChromeOrShell,
    /// A page only, for its own key (design 0012, API: `approval.check`,
    /// `approval.touch`).
    Page,
    /// A page, for its own key, and main itself (design 0012, API:
    /// `approval.grant`, main's for a Swarm manifest's projection).
    PageOrShell,
}

impl Callers {
    pub fn allow(self, caller: CallerKind) -> bool {
        match (self, caller) {
            (Callers::PageChromeOrShell, _) => true,
            (Callers::Page, caller) => caller == CallerKind::Page,
            (Callers::PageOrShell, caller) => caller != CallerKind::Chrome,
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
            Callers::PageChromeOrShell => &["page", "chrome", "shell"],
            Callers::Page => &["page"],
            Callers::PageOrShell => &["page", "shell"],
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
    /// A verified fetch's, to its head: 360 s, or main's `deadline_ms`
    /// (design 0009, Bounds: time to the head). After the head there is
    /// none.
    Head,
}

impl Deadline {
    /// The default, in milliseconds; `None` when answered at once.
    pub fn default_ms(self) -> Option<u64> {
        match self {
            Deadline::Immediate => None,
            Deadline::Vault => Some(30_000),
            Deadline::Session => Some(120_000),
            Deadline::Head => Some(360_000),
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
    /// The protocol version from which the core serves it: 1, or
    /// [`crate::PROTOCOL_VERSION_STREAMS`] for the methods whose bodies are
    /// streams (design 0009). On an older connection it is unknown; the
    /// core now speaks only protocol 2, so it serves every row.
    pub since: u32,
}

const fn row(name: &'static str, callers: Callers, mutates: bool, deadline: Deadline) -> Method {
    Method {
        name,
        callers,
        mutates,
        deadline,
        since: crate::PROTOCOL_VERSION,
    }
}

/// A row served from protocol 2 on.
const fn row_v2(name: &'static str, callers: Callers, mutates: bool, deadline: Deadline) -> Method {
    Method {
        since: crate::PROTOCOL_VERSION_STREAMS,
        ..row(name, callers, mutates, deadline)
    }
}

use Callers::{
    ChromeOrShell as CS, Page as PAGE, PageChromeOrShell as PCS, PageOrShell as PS, Shell as SHELL,
};
use Deadline::{Head as HEAD, Immediate as NOW, Session as SESSION, Vault as VAULT};

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
    // Design 0012: a page signs as `page`, with its `PageContext`, and an
    // authorization is checked when one is present (APR-3).
    row("sign.transaction", PCS, false, NOW),
    row("sign.message", PCS, false, NOW),
    row("sign.typed_data", PCS, false, NOW),
    row("swarm.sign_soc", PCS, false, NOW),
    row("typed_data.hash", CS, false, NOW),
    row("naming.configure", CS, false, NOW),
    row("naming.availability", CS, false, NOW),
    row("naming.resolve_content", CS, false, SESSION),
    row("naming.resolve_address", CS, false, SESSION),
    row("naming.resolve_reverse", CS, false, SESSION),
    row("naming.resolve_tezos", CS, false, SESSION),
    row("naming.invalidate_content", CS, false, NOW),
    row("naming.invalidate_tezos", CS, false, NOW),
    // Design 0012, API: approval tokens and Safe approvals (APR-3).
    row("approval.issue", PCS, false, NOW),
    row("approval.discard", PCS, false, NOW),
    row("approval.spend", PCS, false, NOW),
    row("approval.end", PCS, false, NOW),
    // Design 0012, API: the grant stores (APR-3b). Reads from APR-3; each
    // file's writes from its move step (`grant_moved`), `not_moved` before.
    row("approval.check", PAGE, false, NOW),
    row("approval.grant", PS, false, NOW),
    row("approval.revoke", PCS, false, NOW),
    row("approval.touch", PAGE, false, NOW),
    row("approval.grants", CS, false, NOW),
    row("approval.forget_account", SHELL, false, NOW),
    row("dweb.open", SHELL, false, SESSION),
    // Design 0009: verified fetches, whose bodies stream; protocol 2 only.
    row_v2("dweb.verify", SHELL, false, HEAD),
    row_v2("dweb.forget", SHELL, false, NOW),
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

/// Checks a request's method and caller against the table, on a
/// connection at `protocol`: a method served only from a later version is
/// unknown.
pub fn admit(name: &str, caller: CallerKind, protocol: u32) -> Admission {
    match method(name) {
        Some(row) if row.since > protocol => Admission::Unknown,
        None => Admission::Unknown,
        Some(row) if row.callers.allow(caller) => Admission::Allowed(row),
        Some(_) => Admission::Forbidden,
    }
}

/// `protocol/schema.json`: the table as JSON, one method per line. A
/// method served only from a later version than `protocol` carries its
/// own `"protocol"`.
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
        let since = if m.since > crate::PROTOCOL_VERSION {
            format!(", \"protocol\": {}", m.since)
        } else {
            String::new()
        };
        out.push_str(&format!(
            "    {{ \"name\": \"{}\", \"callers\": [{}], \"mutates\": {}, \"deadline_ms\": {}{} }}",
            m.name,
            callers.join(", "),
            m.mutates,
            deadline,
            since
        ));
        out.push_str(if i + 1 < METHODS.len() { ",\n" } else { "\n" });
    }
    out.push_str("  ]\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2: u32 = crate::PROTOCOL_VERSION_STREAMS;

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
                admit(name, CallerKind::Chrome, V2),
                Admission::Forbidden,
                "{name}"
            );
            assert!(matches!(
                admit(name, CallerKind::Shell, V2),
                Admission::Allowed(_)
            ));
        }
        // A page reaches only design 0012's rows.
        let page_callers = [
            Callers::PageChromeOrShell,
            Callers::Page,
            Callers::PageOrShell,
        ];
        for m in METHODS {
            let page = admit(m.name, CallerKind::Page, V2);
            if page_callers.contains(&m.callers) {
                assert!(matches!(page, Admission::Allowed(_)), "{}", m.name);
            } else {
                assert_eq!(page, Admission::Forbidden, "{}", m.name);
            }
        }
        let page_rows: Vec<&str> = METHODS
            .iter()
            .filter(|m| page_callers.contains(&m.callers))
            .map(|m| m.name)
            .collect();
        assert_eq!(
            page_rows,
            [
                "sign.transaction",
                "sign.message",
                "sign.typed_data",
                "swarm.sign_soc",
                "approval.issue",
                "approval.discard",
                "approval.spend",
                "approval.end",
                "approval.check",
                "approval.grant",
                "approval.revoke",
                "approval.touch",
            ]
        );
        // Design 0012, API: who reaches each grant method.
        for (name, page, chrome, shell) in [
            ("approval.check", true, false, false),
            ("approval.grant", true, false, true),
            ("approval.revoke", true, true, true),
            ("approval.touch", true, false, false),
            ("approval.grants", false, true, true),
            ("approval.forget_account", false, false, true),
        ] {
            for (caller, allowed) in [
                (CallerKind::Page, page),
                (CallerKind::Chrome, chrome),
                (CallerKind::Shell, shell),
            ] {
                assert_eq!(
                    matches!(admit(name, caller, V2), Admission::Allowed(_)),
                    allowed,
                    "{name} {caller:?}"
                );
            }
        }
        assert_eq!(
            admit("vault.unlock", CallerKind::Chrome, V2),
            Admission::Allowed(&METHODS[5])
        );
        assert_eq!(
            admit("vault.secret", CallerKind::Shell, V2),
            Admission::Unknown
        );
    }

    /// Design 0009: the streamed methods exist from protocol 2 on; below it
    /// the table calls them unknown (the core no longer speaks 1).
    #[test]
    fn the_streamed_methods_are_protocol_2() {
        for name in ["dweb.verify", "dweb.forget"] {
            assert_eq!(
                admit(name, CallerKind::Shell, 1),
                Admission::Unknown,
                "{name}"
            );
            assert!(matches!(
                admit(name, CallerKind::Shell, V2),
                Admission::Allowed(Method { since: 2, .. })
            ));
            assert_eq!(admit(name, CallerKind::Chrome, V2), Admission::Forbidden);
        }
        // Every other method is the same at either version.
        for m in METHODS.iter().filter(|m| m.since == 1) {
            assert_eq!(
                admit(m.name, CallerKind::Shell, 1),
                admit(m.name, CallerKind::Shell, V2),
                "{}",
                m.name
            );
        }
        assert_eq!(
            method("dweb.verify").map(|m| m.deadline.default_ms()),
            Some(Some(360_000))
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
