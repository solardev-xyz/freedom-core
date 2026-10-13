//! Trust labels, as JSON in today's key order. Endpoints are written as
//! references, `{"ref":"<endpoint>"}`, which main substitutes with their
//! hosts (design 0005, Replies): `''` is dropped from `agreed`,
//! `dissented` and `queried`; Colibri's `prover` keeps it.

use super::config::{Prover, number_text, quote};
use super::error::Fallback;

/// An endpoint reference.
pub(crate) fn reference(endpoint: &str) -> String {
    format!("{{\"ref\":{}}}", quote(endpoint))
}

/// A list of endpoint references.
pub(crate) fn refs(endpoints: &[String]) -> String {
    let items: Vec<String> = endpoints.iter().map(|e| reference(e)).collect();
    format!("[{}]", items.join(","))
}

fn quorum_label(k: usize, m: f64, achieved: bool) -> String {
    format!(
        "{{\"k\":{k},\"m\":{},\"achieved\":{achieved}}}",
        number_text(m)
    )
}

/// A quorum's agreement.
pub(crate) fn quorum_trust(
    agreed: &[String],
    dissented: &[String],
    queried: &[String],
    m: f64,
) -> String {
    format!(
        "{{\"level\":\"verified\",\"method\":\"quorum\",\"block\":null,\"agreed\":{},\"dissented\":{},\"queried\":{},\"quorum\":{}}}",
        refs(agreed),
        refs(dissented),
        refs(queried),
        quorum_label(queried.len(), m, true)
    )
}

/// `directResponse`'s label: one endpoint's answer, or a quorum member's
/// reused with the round's evidence.
pub(crate) fn direct_trust(
    user_configured: bool,
    url: &str,
    evidence: Option<&Fallback>,
) -> String {
    let level = if user_configured {
        "user-configured"
    } else {
        "unverified"
    };
    let (agreed, dissented, queried, quorum) = match evidence {
        Some(fallback) => (
            refs(&fallback.agreed),
            refs(&fallback.dissented),
            refs(&fallback.queried),
            quorum_label(fallback.k, fallback.m, false),
        ),
        None => {
            let one = refs(&[url.to_owned()]);
            (
                one.clone(),
                "[]".to_owned(),
                one,
                quorum_label(1, 1.0, false),
            )
        }
    };
    format!(
        "{{\"level\":\"{level}\",\"method\":\"direct\",\"block\":null,\"agreed\":{agreed},\"dissented\":{dissented},\"queried\":{queried},\"quorum\":{quorum}}}"
    )
}

/// Colibri's label: the prover, and its proof.
pub(crate) fn colibri_trust(prover: Option<&Prover>) -> String {
    let (prover_ref, list, proof) = match prover {
        Some(prover) => (
            reference(&prover.endpoint),
            refs(std::slice::from_ref(&prover.endpoint)),
            if prover.zk {
                "ZK sync-committee proof"
            } else {
                "Sync-committee proof"
            },
        ),
        None => (
            "\"\"".to_owned(),
            "[]".to_owned(),
            "ZK sync-committee proof",
        ),
    };
    format!(
        "{{\"level\":\"verified\",\"method\":\"colibri\",\"prover\":{prover_ref},\"proof\":\"{proof}\",\"block\":null,\"agreed\":{list},\"dissented\":[],\"queried\":{list},\"quorum\":{}}}",
        quorum_label(1, 1.0, true)
    )
}
