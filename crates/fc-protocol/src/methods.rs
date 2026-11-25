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
    /// The browser UI only (`chrome`): a call behind a prompt main shows
    /// the user first, which main's own work (`shell`) never has (design
    /// 0013, API: quick unlock's calls after main's Touch ID prompt).
    Chrome,
    /// A page (`page`, with its `PageContext`) as well: the rows 0011 left
    /// for 0012 (design 0012, "PageContext"). The method checks what each
    /// caller may do (a page kind's token presented only under `page`, a
    /// wallet kind's never).
    PageChromeOrShell,
    /// A page only, for its own key (design 0012, API: `approval.check`,
    /// `approval.touch`, `approval.radicle_write`, `approval.remember`).
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
            (Callers::Chrome, caller) => caller == CallerKind::Chrome,
        }
    }

    fn names(self) -> &'static [&'static str] {
        match self {
            Callers::Shell => &["shell"],
            Callers::ChromeOrShell => &["chrome", "shell"],
            Callers::Chrome => &["chrome"],
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
    /// A page's EIP-1193 request (design 0012, "fc-eip1193 and
    /// approval.request"; `fc_eip1193::Budget`): no overall deadline while
    /// one of its own `approval.request`s is open, a session's 120 s in all
    /// outside them, and each I/O step its own deadline within that. Main's
    /// hang watchdog skips the request while main answers one of its
    /// prompts.
    Steps,
    /// A Swarm request's (design 0015, "Methods main calls"; SWM-4, D5):
    /// 300 s, or the caller's shorter `deadline_ms` (a page's own timer,
    /// 60 s or 300 s by today's list).
    Swarm,
    /// No total deadline, only idle bounds (design 0015, D5 and D13): a
    /// picked file may be large, so `swarm.publish` and `swarm.body` end
    /// only when a stream or an ask makes no progress for 60 s. Unlike
    /// [`Deadline::Immediate`], the request may run for as long as it
    /// progresses, so `schema.json` writes it apart from `null`
    /// ([`Deadline::schema_value`]).
    Idle,
}

impl Deadline {
    /// The default total deadline, in milliseconds; `None` when answered
    /// at once, or when only idle bounds end the request
    /// ([`Deadline::Idle`]).
    pub fn default_ms(self) -> Option<u64> {
        match self {
            Deadline::Immediate | Deadline::Idle => None,
            Deadline::Vault => Some(30_000),
            Deadline::Session => Some(120_000),
            Deadline::Head => Some(360_000),
            Deadline::Steps => Some(120_000),
            Deadline::Swarm => Some(300_000),
        }
    }

    /// Its `deadline_ms` in `schema.json`: the default in milliseconds,
    /// `null` when answered at once, and `"idle"` when only idle bounds end
    /// the request, so main's table tells it from an immediate method,
    /// whose hang watchdog is a short total one.
    pub fn schema_value(self) -> String {
        match (self, self.default_ms()) {
            (Deadline::Idle, _) => "\"idle\"".to_owned(),
            (_, Some(ms)) => ms.to_string(),
            (_, None) => "null".to_owned(),
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
    Chrome as CHROME, ChromeOrShell as CS, Page as PAGE, PageChromeOrShell as PCS,
    PageOrShell as PS, Shell as SHELL,
};
use Deadline::{
    Head as HEAD, Immediate as NOW, Session as SESSION, Steps as STEPS, Swarm as SWARM,
    Vault as VAULT,
};

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
    // Design 0013, "The re-wrap" and API: the vault password in the core's
    // key store. Enroll is main's own (`shell`), with the password it
    // unsealed; the rest are the chrome's alone, after main's Touch ID
    // prompt, which main's own work never has. The secrets file isn't the
    // vault, and nothing reconciles them: not 0001's mutations.
    row("quick_unlock.enroll", SHELL, false, VAULT),
    row("quick_unlock.unlock", CHROME, false, VAULT),
    row("quick_unlock.export_mnemonic", CHROME, false, VAULT),
    row("quick_unlock.export_private_key", CHROME, false, VAULT),
    row("quick_unlock.status", CHROME, false, NOW),
    row("quick_unlock.disable", CHROME, false, VAULT),
    // Design 0013, "RPC API keys" (PRF-5h): the keys reach only main; the
    // chrome sees presence, and sets or removes a key.
    row("secrets.rpc_api_keys", SHELL, false, VAULT),
    row("secrets.rpc_api_key_status", CS, false, VAULT),
    row("secrets.set_rpc_api_key", CS, true, VAULT),
    row("secrets.remove_rpc_api_key", CS, true, VAULT),
    // Design 0013, "Callers of the store methods" (PRF-5c-1): a write the
    // chrome causes today with no check in main between is the chrome's
    // too; one that follows main's own check (a device read, the phone's
    // proof, a Safe's predicted address, a verified deployment) is main's.
    row("accounts.list", CS, false, VAULT),
    row("accounts.meta", CS, false, VAULT),
    row("accounts.active", CS, false, VAULT),
    row("accounts.add_mnemonic", CS, true, VAULT),
    row("accounts.add_ledger", SHELL, true, VAULT),
    row("accounts.add_remote", SHELL, true, VAULT),
    row("accounts.record_address_check", SHELL, true, VAULT),
    row("accounts.add_safe", SHELL, true, VAULT),
    row("accounts.mark_safe_deployed", SHELL, true, VAULT),
    row("accounts.set_active", CS, true, VAULT),
    row("accounts.rename", CS, true, VAULT),
    row("accounts.remove", CS, true, VAULT),
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
    // authorization is checked when one is present (APR-3). A SOC is a
    // page's or main's own: the chrome lost it at SWM-4 (design 0015's
    // amendment to 0002), and the row goes at SWM-9.
    row("sign.transaction", PCS, false, NOW),
    row("sign.message", PCS, false, NOW),
    row("sign.typed_data", PCS, false, NOW),
    row("swarm.sign_soc", PS, false, NOW),
    row("typed_data.hash", CS, false, NOW),
    row("naming.configure", CS, false, NOW),
    row("naming.availability", CS, false, NOW),
    row("naming.resolve_content", CS, false, SESSION),
    row("naming.resolve_address", CS, false, SESSION),
    row("naming.resolve_reverse", CS, false, SESSION),
    row("naming.resolve_tezos", CS, false, SESSION),
    row("naming.invalidate_content", CS, false, NOW),
    row("naming.invalidate_tezos", CS, false, NOW),
    // Design 0012, API: approval tokens and Safe approvals (APR-3). From
    // APR-7 a page mints no token: the core mints the page kinds itself, on
    // an approve answer to its own `approval.request`.
    row("approval.issue", CS, false, NOW),
    row("approval.discard", PCS, false, NOW),
    row("approval.spend", PCS, false, NOW),
    row("approval.end", PCS, false, NOW),
    // Design 0012, API: the grant stores (APR-3b). Reads from APR-3; each
    // file's writes from its move step (`grant_moved`), `not_moved` before.
    row("approval.check", PAGE, false, NOW),
    row("approval.grant", PS, false, NOW),
    row("approval.revoke", PCS, false, NOW),
    row("approval.touch", PAGE, false, NOW),
    // Design 0012, "A page's Radicle write" (#372): R-6 counted in the core,
    // for a page's own key; no other caller reaches it.
    row("approval.radicle_write", PAGE, false, NOW),
    row("approval.grants", CS, false, NOW),
    row("approval.forget_account", SHELL, false, NOW),
    // Design 0012, "A device send's rule" (#373): a page presents its own
    // receipt; no other caller reaches it.
    row("approval.remember", PAGE, false, NOW),
    // Design 0012, "Phone jobs" (PHN-1): a job from a checked
    // authorization, as `sign.*` checks it; its answer read on the job's
    // chain before the reply.
    row("phone.job", PCS, false, NOW),
    row("phone.sent", PCS, false, NOW),
    row("phone.result", PCS, false, SESSION),
    // Design 0012, "x402" (X402-1): main's own, as its x402 interception
    // is; no renderer channel reaches them.
    row("x402.authorize", SHELL, false, NOW),
    row("x402.settle", SHELL, false, NOW),
    // Core #392: a cap's narrowing, from the activity pane (or main); a
    // page names no cap of its own (Q11 keys a cap on the seller).
    row("x402.update", CS, false, NOW),
    // Design 0013, "Pending Safe transactions" (PRF-5f): no channel
    // returns or writes the file; the chrome gets main's projections.
    // Reads from the start; writes once `safe_pending` is in
    // `store_moved`, `not_moved` before.
    row("safe_pending.get", SHELL, false, NOW),
    row("safe_pending.set", SHELL, false, NOW),
    row("safe_pending.clear", SHELL, false, NOW),
    row("safe_pending.list", SHELL, false, NOW),
    // Design 0013, "Payment history" (PRF-5g-2): the chrome reads and
    // clears (`payments:get-recent`, `:get-count`, `:get-by-id`,
    // `:clear`, `x402:get-receipts`); the writes and the repoll's are
    // main's own. `not_moved` until `payments` is in `store_moved`.
    row("payments.append", SHELL, false, NOW),
    row("payments.update", SHELL, false, NOW),
    row("payments.mark_confirmed", SHELL, false, NOW),
    row("payments.mark_failed", SHELL, false, NOW),
    row("payments.mark_dropped", SHELL, false, NOW),
    row("payments.set_dropped_seen", SHELL, false, NOW),
    row("payments.pending", SHELL, false, NOW),
    row("payments.get_recent", CS, false, NOW),
    row("payments.get_by_id", CS, false, NOW),
    row("payments.get_count", CS, false, NOW),
    row("payments.clear", CS, false, NOW),
    // Design 0013, "The intent journal" (PRF-5e-3): main's send paths
    // only; no channel reaches the records. Reads from the start; writes
    // once `intents` is in `store_moved`, `not_moved` before.
    row("intents.commit", SHELL, false, NOW),
    row("intents.handoff", SHELL, false, NOW),
    row("intents.outcome", SHELL, false, NOW),
    row("intents.settle", SHELL, false, NOW),
    row("intents.void", SHELL, false, NOW),
    row("intents.retire", SHELL, false, NOW),
    row("intents.track", SHELL, false, NOW),
    row("intents.withdraw_origin", SHELL, false, NOW),
    row("intents.compact", SHELL, false, NOW),
    row("intents.get", SHELL, false, NOW),
    row("intents.by_key", SHELL, false, NOW),
    row("intents.held", SHELL, false, NOW),
    row("intents.list", SHELL, false, NOW),
    row("intents.held_nonces", SHELL, false, NOW),
    row("intents.usage", SHELL, false, NOW),
    row("intents.void_refusal", SHELL, false, NOW),
    // Design 0012, "fc-eip1193 and approval.request" (APR-5): a page's
    // EIP-1193 request, run by the core's dispatcher; no other caller
    // reaches it.
    row("eip1193.request", PAGE, false, STEPS),
    row("dweb.open", SHELL, false, SESSION),
    // Design 0009: verified fetches, whose bodies stream; protocol 2 only.
    row_v2("dweb.verify", SHELL, false, HEAD),
    row_v2("dweb.forget", SHELL, false, NOW),
    // Design 0015 (SWM-4, D5): a page's `window.swarm` request, run by the
    // core's swarm thread under the `swarm` deadline; no other caller
    // reaches it. Its answer is whole: the bodies that stream are its own
    // asks' (`shell.swarm_api`, `shell.swarm_part`) and `swarm.body`'s.
    row("swarm.request", PAGE, false, SWARM),
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
        let deadline = m.deadline.schema_value();
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
            "quick_unlock.enroll",
            "dweb.open",
            "x402.authorize",
            "x402.settle",
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
        // A cap's narrowing (#392): the activity pane and main, never a page.
        for (caller, admitted) in [
            (CallerKind::Chrome, true),
            (CallerKind::Shell, true),
            (CallerKind::Page, false),
        ] {
            let admission = admit("x402.update", caller, V2);
            assert_eq!(
                matches!(admission, Admission::Allowed(_)),
                admitted,
                "{caller:?}"
            );
        }
        // A page reaches only design 0012's rows, and design 0015's
        // `swarm.request`.
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
                "approval.discard",
                "approval.spend",
                "approval.end",
                "approval.check",
                "approval.grant",
                "approval.revoke",
                "approval.touch",
                "approval.radicle_write",
                "approval.remember",
                "phone.job",
                "phone.sent",
                "phone.result",
                "eip1193.request",
                "swarm.request",
            ]
        );
        // Design 0012, API: who reaches each grant method, and
        // `approval.issue`, which no page reaches from APR-7; and design
        // 0015's `swarm.sign_soc`.
        for (name, page, chrome, shell) in [
            ("approval.issue", false, true, true),
            ("approval.check", true, false, false),
            ("approval.grant", true, false, true),
            ("approval.revoke", true, true, true),
            ("approval.touch", true, false, false),
            ("approval.radicle_write", true, false, false),
            ("approval.grants", false, true, true),
            ("approval.forget_account", false, false, true),
            ("approval.remember", true, false, false),
            ("eip1193.request", true, false, false),
            // Design 0015 (SWM-4): the chrome signs no SOC; a page's
            // `window.swarm` request is the page's alone (D5).
            ("swarm.sign_soc", true, false, true),
            ("swarm.request", true, false, false),
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
        // Design 0013, "Callers of the store methods": the chrome reads and
        // clears the payment history; its writes are main's alone.
        for (name, chrome) in [
            ("payments.append", false),
            ("payments.update", false),
            ("payments.mark_confirmed", false),
            ("payments.mark_failed", false),
            ("payments.mark_dropped", false),
            ("payments.set_dropped_seen", false),
            ("payments.pending", false),
            ("payments.get_recent", true),
            ("payments.get_by_id", true),
            ("payments.get_count", true),
            ("payments.clear", true),
        ] {
            for (caller, allowed) in [
                (CallerKind::Page, false),
                (CallerKind::Chrome, chrome),
                (CallerKind::Shell, true),
            ] {
                assert_eq!(
                    matches!(admit(name, caller, V2), Admission::Allowed(_)),
                    allowed,
                    "{name} {caller:?}"
                );
            }
        }
        // Design 0013, "Callers of the store methods": who reaches each
        // `accounts.*` method. A page reaches none.
        for (name, chrome) in [
            ("accounts.list", true),
            ("accounts.meta", true),
            ("accounts.active", true),
            ("accounts.add_mnemonic", true),
            ("accounts.add_ledger", false),
            ("accounts.add_remote", false),
            ("accounts.record_address_check", false),
            ("accounts.add_safe", false),
            ("accounts.mark_safe_deployed", false),
            ("accounts.set_active", true),
            ("accounts.rename", true),
            ("accounts.remove", true),
        ] {
            for (caller, allowed) in [
                (CallerKind::Page, false),
                (CallerKind::Chrome, chrome),
                (CallerKind::Shell, true),
            ] {
                assert_eq!(
                    matches!(admit(name, caller, V2), Admission::Allowed(_)),
                    allowed,
                    "{name} {caller:?}"
                );
            }
        }
        // Design 0013, "Callers of the store methods": `safe_pending.*`
        // is main's alone; no channel returns or writes the file.
        for name in [
            "safe_pending.get",
            "safe_pending.set",
            "safe_pending.clear",
            "safe_pending.list",
        ] {
            assert_eq!(method(name).unwrap().callers, SHELL, "{name}");
            for (caller, allowed) in [
                (CallerKind::Page, false),
                (CallerKind::Chrome, false),
                (CallerKind::Shell, true),
            ] {
                assert_eq!(
                    matches!(admit(name, caller, V2), Admission::Allowed(_)),
                    allowed,
                    "{name} {caller:?}"
                );
            }
        }
        // Design 0013, "Callers of the store methods": `intents.*` is
        // main's alone (its send paths), every write and read.
        let intents: Vec<&str> = METHODS
            .iter()
            .map(|m| m.name)
            .filter(|name| name.starts_with("intents."))
            .collect();
        assert_eq!(intents.len(), 16, "{intents:?}");
        for name in intents {
            assert_eq!(method(name).unwrap().callers, SHELL, "{name}");
            for (caller, allowed) in [
                (CallerKind::Page, false),
                (CallerKind::Chrome, false),
                (CallerKind::Shell, true),
            ] {
                assert_eq!(
                    matches!(admit(name, caller, V2), Admission::Allowed(_)),
                    allowed,
                    "{name} {caller:?}"
                );
            }
        }
        // Design 0013, API: who reaches each quick-unlock method. Enroll is
        // main's own; the rest are the chrome's, behind main's Touch ID
        // prompt; a page reaches none.
        let quick: Vec<&str> = METHODS
            .iter()
            .map(|m| m.name)
            .filter(|name| name.starts_with("quick_unlock."))
            .collect();
        assert_eq!(
            quick,
            [
                "quick_unlock.enroll",
                "quick_unlock.unlock",
                "quick_unlock.export_mnemonic",
                "quick_unlock.export_private_key",
                "quick_unlock.status",
                "quick_unlock.disable",
            ]
        );
        for name in quick {
            let enroll = name == "quick_unlock.enroll";
            for (caller, allowed) in [
                (CallerKind::Page, false),
                (CallerKind::Chrome, !enroll),
                (CallerKind::Shell, enroll),
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

    /// Design 0015 (SWM-4, D5): the Swarm kinds. `swarm` is 300 s; idle
    /// only has no total deadline, as an immediate method, but `schema.json`
    /// writes it apart from one, and every value it writes is distinct.
    #[test]
    fn the_swarm_deadline_kinds() {
        assert_eq!(Deadline::Swarm.default_ms(), Some(300_000));
        assert_eq!(Deadline::Idle.default_ms(), None);
        assert_eq!(Deadline::Immediate.default_ms(), None);
        assert_eq!(Deadline::Idle.schema_value(), r#""idle""#);
        assert_eq!(Deadline::Immediate.schema_value(), "null");
        assert_eq!(Deadline::Swarm.schema_value(), "300000");
        assert_eq!(Deadline::Head.schema_value(), "360000");
        // Each kind but `steps`, which writes a session's 120 s as main's
        // table has it, writes its own value, and each parses as JSON.
        let kinds = [
            Deadline::Immediate,
            Deadline::Vault,
            Deadline::Session,
            Deadline::Head,
            Deadline::Swarm,
            Deadline::Idle,
        ];
        for (i, a) in kinds.iter().enumerate() {
            let value: serde_json::Value = serde_json::from_str(&a.schema_value()).unwrap();
            assert!(
                value.is_null() || value.is_u64() || value == "idle",
                "{a:?}"
            );
            for b in &kinds[i + 1..] {
                assert_ne!(a.schema_value(), b.schema_value(), "{a:?} {b:?}");
            }
        }
        assert_eq!(
            Deadline::Steps.schema_value(),
            Deadline::Session.schema_value()
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
