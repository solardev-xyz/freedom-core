//! The Safe's setup, read and checked (design 0016, "Chain reads" and
//! "Owners, threshold and setup"; SAFE-2's S1): the eight reads `fc-safe`
//! lists, each made through the chain machine as one of the core's own
//! reads ([`In::Internal`](crate::chain::In::Internal)), each answer
//! required `verified`, and `fc-safe`'s [`check_setup`] on them. S3 to S5
//! run it ([`Evidence::start`]) before each owner's signature and before
//! execution, and sign nothing on any [`Outcome`] but
//! [`Outcome::Unchanged`]. S2's `safe.status`, which signs nothing, runs
//! it without the nonce ([`Evidence::start_status`]) and reports the
//! outcome as data ([`Outcome::state`]), never as a refusal.
//!
//! - **Verified, or nothing is signed:** an answer is evidence only when
//!   the chain machine labels it `verified` by 0005's rules: a verifier's
//!   proof, or a quorum of at least two distinct endpoints that agree
//!   (deviations `singleton-quorum` and `endpoint-dedup`). One endpoint's
//!   answer isn't, whatever it says: Direct's, a quorum's of m = 1, or
//!   Direct's after a quorum only one endpoint answered. On Gnosis,
//!   Colibri proves the code and the slots but no call (main's #1046), so
//!   the four calls rest on the quorum (or Myotis), and without two
//!   agreeing endpoints every check is unverified. Colibri also takes only
//!   two reads of one route at once (the router's
//!   `MAX_COLIBRI_IN_FLIGHT_PER_ROUTE`), so of the three slots read
//!   together, one goes on to the quorum.
//! - **The order:** the code first, alone, which decides whether the rest
//!   mean anything; then the six setup reads at once; then the nonce, once
//!   all six have answered, since the reads aren't pinned to one block
//!   (`fc_safe::Read::ALL`). Each step that decides ends the check there:
//!   no code, verified, is [`Outcome::NotDeployed`], and a code or setup
//!   read that isn't verified ends it before the nonce is read. A status
//!   check ([`Scope::Status`]) stops after the six: it reads no nonce, so
//!   none can fail it, and its unchanged answer is
//!   [`Outcome::SetupUnchanged`].
//! - **A read that can't be used** is [`Outcome::Unverified`]: a failed
//!   read (a reverted `eth_call`, a node's other error, a transport
//!   failure, the machine's own refusal or deadline), an answer with no
//!   result or one that isn't hex, and one `check_setup` can't decode
//!   ([`fc_safe::ReadError`]). `SafeL2` 1.4.1's view functions never revert
//!   and answer in one encoding, so none of these is evidence of the
//!   Safe's setup. Nothing is kept: the next check reads again.
//! - **Under another singleton,** verified in slot 0, the calls answer for
//!   another contract, which `check_setup` doesn't compare: the singleton
//!   alone decides, [`Outcome::Changed`], whatever the calls answered and
//!   whether or not they were verified. The guard and the handler, the
//!   proxy's own storage, are named with it when their reads are verified
//!   and show them changed, as `check_setup` names them.
//! - **Tags:** each read's tag has [`SAFE_TAG`] set and the page sends'
//!   bit ([`crate::eip1193::SEND_TAG`]) clear, so the event loop can route
//!   its reply here (S2 does); a phone payment's count up from 1. A reply
//!   for a tag the check isn't waiting for changes nothing.

use std::collections::BTreeMap;

use fc_evm::{U256, parse_bytes, to_hex};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_safe::constants::{CHAIN_ID, SINGLETON};
use fc_safe::reads::{Answers, Change, Query, Read, SetupCheck, check_setup, decode_slot};
use fc_safe::{ReadProblem, Setup};
use serde::Deserialize;
use serde_json::json;
use serde_json::value::RawValue;

use crate::log;
use crate::phone::ChainRead;

/// The bit that marks a Safe check's chain reads' tags.
pub const SAFE_TAG: u64 = 1 << 62;

/// `safe_unverified`'s text (design 0016, "Chain reads").
pub const UNVERIFIED_TEXT: &str = "Freedom couldn't verify this Safe on Gnosis, so it won't sign. \
     Try again, or add an RPC provider in Settings.";

/// `safe_changed`'s text (design 0016, "Owners, threshold and setup").
pub const CHANGED_TEXT: &str =
    "This Safe was changed outside Freedom, so Freedom can't sign for it.";

/// The six setup reads, made together once the code is in.
const SETUP: [Read; 6] = [
    Read::Singleton,
    Read::Owners,
    Read::Threshold,
    Read::Guard,
    Read::Handler,
    Read::Modules,
];

/// Whether a chain read's reply is a Safe check's.
pub fn is_safe_tag(tag: u64) -> bool {
    tag & SAFE_TAG != 0 && tag & crate::eip1193::SEND_TAG == 0
}

/// The Safe checks' tags: [`SAFE_TAG`] and a count below it.
#[derive(Debug, Default)]
pub struct Tags {
    next: u64,
}

impl Tags {
    pub fn next(&mut self) -> u64 {
        let tag = SAFE_TAG | self.next;
        self.next = (self.next + 1) & (SAFE_TAG - 1);
        tag
    }
}

/// Which reads a check makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// All eight, the nonce last: before each owner's signature and
    /// before execution (S3 to S5).
    Signing,
    /// The code and the six setup reads, and no nonce: `safe.status`'s,
    /// which signs nothing and shows no nonce (S2).
    Status,
}

/// Why a read isn't evidence of the Safe's setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Answered, but not labelled `verified`: one endpoint's answer.
    Unverified,
    /// The read failed: a reverted call, a node's other error, the
    /// sources' failure, or the chain machine's own.
    Failed,
    /// It failed at or after its deadline.
    PastDue,
    /// Verified, but no answer this read has: no result, or not hex
    /// (`None`), or not Safe 1.4.1's encoding (`check_setup`'s problem).
    Unreadable(Option<ReadProblem>),
}

impl Why {
    pub fn name(self) -> &'static str {
        match self {
            Why::Unverified => "unverified",
            Why::Failed => "failed",
            Why::PastDue => "past_due",
            Why::Unreadable(None) => "unreadable",
            Why::Unreadable(Some(problem)) => problem.kind(),
        }
    }
}

/// What the reads show, for S2 to S5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No code at the Safe's address, verified: it isn't deployed, and has
    /// no setup on chain to compare.
    NotDeployed,
    /// Deployed with the record's setup, as the reads see it now
    /// (0016, "What the setup check can't see"), and its nonce, read last.
    Unchanged { nonce: U256 },
    /// The same, from a check that reads no nonce ([`Scope::Status`]):
    /// never a step that signs.
    SetupUnchanged,
    /// Changed outside Freedom (`safe_changed`): what changed, in
    /// [`Change`]'s order, at least one.
    Changed(Vec<Change>),
    /// A read that isn't evidence (`safe_unverified`): the first, in the
    /// reads' order, and why.
    Unverified { read: Read, why: Why },
}

impl Outcome {
    /// The refusal of a step that signs (design 0016, API): `safe_changed`
    /// or `safe_unverified`, `invalid_argument` with `data.safe`. `None`
    /// for [`Outcome::Unchanged`] and [`Outcome::SetupUnchanged`], and for
    /// [`Outcome::NotDeployed`], which the step refuses `not_deployed`
    /// itself (`methods::NOT_DEPLOYED_TEXT`). S3 to S5 call it.
    pub fn refusal(&self) -> Option<ErrorBody> {
        let (text, safe) = match self {
            Outcome::Changed(_) => (CHANGED_TEXT, "changed"),
            Outcome::Unverified { .. } => (UNVERIFIED_TEXT, "unverified"),
            Outcome::NotDeployed | Outcome::Unchanged { .. } | Outcome::SetupUnchanged => {
                return None;
            }
        };
        Some(ErrorBody::new(ErrorCode::InvalidArgument, text).with_data(json!({ "safe": safe })))
    }

    /// The outcome as `safe.status`'s `setup` reports it, data for the
    /// board (design 0016, API): `{ state }`, one of `unchanged`,
    /// `changed` with what changed (`changed`, [`Change`]'s names in its
    /// order), `unverified` with the first read that isn't evidence and
    /// why (`read`, `why`), or `not_deployed` (no code, verified).
    pub fn state(&self) -> serde_json::Value {
        match self {
            Outcome::Unchanged { .. } | Outcome::SetupUnchanged => json!({ "state": "unchanged" }),
            Outcome::Changed(changes) => json!({
                "state": "changed",
                "changed": changes.iter().map(|change| change.name()).collect::<Vec<_>>(),
            }),
            Outcome::Unverified { read, why } => json!({
                "state": "unverified",
                "read": read.name(),
                "why": why.name(),
            }),
            Outcome::NotDeployed => json!({ "state": "not_deployed" }),
        }
    }
}

/// Where a check stands after a reply.
pub enum Progress {
    /// Other reads are still out, or the reply wasn't this check's.
    Waiting,
    /// The next reads, for the chain thread.
    Reads(Vec<ChainRead>),
    /// The outcome: no read is out.
    Done(Outcome),
}

/// What a read gave: its verified answer's bytes, or why there is none.
type Answer = Result<Vec<u8>, Why>;

/// One check of a Safe's setup against its record, in flight.
pub struct Evidence {
    scope: Scope,
    safe: [u8; 20],
    setup: Setup,
    deadline_ms: u64,
    /// The reads out, by tag.
    out: BTreeMap<u64, Read>,
    answers: BTreeMap<Read, Answer>,
}

enum Next {
    Reads(&'static [Read]),
    Done(Outcome),
}

impl Evidence {
    /// The check of the Safe at `safe` against its record's `setup`, each
    /// read with `deadline_ms`: the check, and its first read. The caller
    /// has checked the address against the record (`Setup::check_address`).
    /// S3 to S5 call it.
    pub fn start(
        safe: [u8; 20],
        setup: Setup,
        deadline_ms: u64,
        tags: &mut Tags,
    ) -> (Self, Vec<ChainRead>) {
        Self::begin(Scope::Signing, safe, setup, deadline_ms, tags)
    }

    /// The same check without the nonce ([`Scope::Status`]), for
    /// `safe.status`: its unchanged answer is [`Outcome::SetupUnchanged`].
    pub fn start_status(
        safe: [u8; 20],
        setup: Setup,
        deadline_ms: u64,
        tags: &mut Tags,
    ) -> (Self, Vec<ChainRead>) {
        Self::begin(Scope::Status, safe, setup, deadline_ms, tags)
    }

    fn begin(
        scope: Scope,
        safe: [u8; 20],
        setup: Setup,
        deadline_ms: u64,
        tags: &mut Tags,
    ) -> (Self, Vec<ChainRead>) {
        let mut evidence = Evidence {
            scope,
            safe,
            setup,
            deadline_ms,
            out: BTreeMap::new(),
            answers: BTreeMap::new(),
        };
        let reads = evidence.send(&[Read::Code], tags);
        (evidence, reads)
    }

    /// Whether the read tagged `tag` is this check's, and still out.
    #[cfg(test)]
    pub fn waits_for(&self, tag: u64) -> bool {
        self.out.contains_key(&tag)
    }

    /// The chain thread's reply to read `tag` (its whole payload, and
    /// whether it failed at or after its deadline): the check's next step.
    pub fn answered(
        &mut self,
        tag: u64,
        payload: &[u8],
        past_due: bool,
        tags: &mut Tags,
    ) -> Progress {
        let Some(read) = self.out.remove(&tag) else {
            return Progress::Waiting;
        };
        self.answers.insert(read, answer(payload, past_due));
        if !self.out.is_empty() {
            return Progress::Waiting;
        }
        match self.next() {
            Next::Reads(reads) => Progress::Reads(self.send(reads, tags)),
            Next::Done(outcome) => {
                logged(&outcome);
                Progress::Done(outcome)
            }
        }
    }

    fn send(&mut self, reads: &[Read], tags: &mut Tags) -> Vec<ChainRead> {
        reads
            .iter()
            .map(|&read| {
                let tag = tags.next();
                self.out.insert(tag, read);
                chain_read(&self.safe, read, tag, self.deadline_ms)
            })
            .collect()
    }

    /// With every read out answered: the next ones, or the outcome.
    fn next(&self) -> Next {
        let code = match self.answers.get(&Read::Code) {
            None => return Next::Reads(&[Read::Code]),
            Some(Err(why)) => {
                return Next::Done(Outcome::Unverified {
                    read: Read::Code,
                    why: *why,
                });
            }
            Some(Ok(code)) => code,
        };
        if code.is_empty() {
            return Next::Done(Outcome::NotDeployed);
        }
        if !self.answers.contains_key(&Read::Singleton) {
            return Next::Reads(&SETUP);
        }
        if let Some(changed) = self.another_singleton() {
            return Next::Done(changed);
        }
        if let Some(unverified) = self.unverified(&SETUP) {
            return Next::Done(unverified);
        }
        if self.scope == Scope::Signing && !self.answers.contains_key(&Read::Nonce) {
            return Next::Reads(&[Read::Nonce]);
        }
        Next::Done(self.judged())
    }

    /// A verified read's answer.
    fn verified(&self, read: Read) -> Option<&[u8]> {
        match self.answers.get(&read) {
            Some(Ok(bytes)) => Some(bytes),
            _ => None,
        }
    }

    /// The first of `reads` that isn't evidence.
    fn unverified(&self, reads: &[Read]) -> Option<Outcome> {
        reads
            .iter()
            .find_map(|&read| match self.answers.get(&read) {
                Some(Err(why)) => Some(Outcome::Unverified { read, why: *why }),
                _ => None,
            })
    }

    /// Under a verified singleton other than `SafeL2` 1.4.1: `Changed`,
    /// naming the singleton, and the guard and the handler as
    /// `check_setup` names them when both are verified and decode. The
    /// calls aren't compared, so their answers aren't passed.
    fn another_singleton(&self) -> Option<Outcome> {
        let singleton = self.verified(Read::Singleton)?;
        let word = decode_slot(Read::Singleton, singleton).ok()?;
        if word == fc_naming::abi::word_from_address(&SINGLETON) {
            return None;
        }
        let named = match (
            self.verified(Read::Code),
            self.verified(Read::Guard),
            self.verified(Read::Handler),
        ) {
            (Some(code), Some(guard), Some(handler)) => check_setup(
                &self.setup,
                &Answers {
                    code,
                    singleton,
                    owners: &[],
                    threshold: &[],
                    guard,
                    handler,
                    modules: &[],
                    nonce: &[],
                },
            )
            .ok(),
            _ => None,
        };
        Some(Outcome::Changed(match named {
            Some(SetupCheck::Changed(changes)) => changes,
            _ => vec![Change::Singleton],
        }))
    }

    /// All the scope's reads in: `check_setup` on the verified answers. A
    /// status check reads no nonce, so `check_setup` is given a zero word
    /// in its place, which always decodes and is never reported.
    fn judged(&self) -> Outcome {
        const NO_NONCE: [u8; 32] = [0; 32];
        if let Some(unverified) = self.unverified(&Read::ALL) {
            return unverified;
        }
        let answers = Answers::from_fn(|read| match (read, self.scope) {
            (Read::Nonce, Scope::Status) => &NO_NONCE,
            _ => self.verified(read).unwrap_or(&[]),
        });
        match check_setup(&self.setup, &answers) {
            Ok(SetupCheck::NotDeployed) => Outcome::NotDeployed,
            Ok(SetupCheck::Unchanged { nonce }) => match self.scope {
                Scope::Signing => Outcome::Unchanged { nonce },
                Scope::Status => Outcome::SetupUnchanged,
            },
            Ok(SetupCheck::Changed(changes)) => Outcome::Changed(changes),
            Err(error) => Outcome::Unverified {
                read: error.read,
                why: Why::Unreadable(Some(error.problem)),
            },
        }
    }
}

/// A refusal's line: the read and why, or what changed; never the Safe's
/// address or an answer.
fn logged(outcome: &Outcome) {
    match outcome {
        Outcome::Unverified { read, why } => log::warn(
            "safe setup unverified",
            json!({ "read": read.name(), "why": why.name() }),
        ),
        Outcome::Changed(changes) => log::warn(
            "safe setup changed",
            json!({ "changed": changes.iter().map(|c| c.name()).collect::<Vec<_>>() }),
        ),
        Outcome::NotDeployed | Outcome::Unchanged { .. } | Outcome::SetupUnchanged => {}
    }
}

/// Read `read` of the Safe at `safe`, at `latest`, last in its params as
/// Colibri requires of an account read (design 0014).
fn chain_read(safe: &[u8; 20], read: Read, tag: u64, deadline_ms: u64) -> ChainRead {
    let address = to_hex(safe);
    let query = read.query();
    let params = match &query {
        Query::Code => format!(r#"["{address}","latest"]"#),
        Query::Storage(slot) => format!(r#"["{address}","{}","latest"]"#, to_hex(slot)),
        Query::Call(data) => format!(
            r#"[{{"to":"{address}","data":"{}"}},"latest"]"#,
            to_hex(data)
        ),
    };
    ChainRead {
        tag,
        chain_id: CHAIN_ID,
        method: query.method(),
        params,
        deadline_ms,
    }
}

/// A read's reply, as the chain thread writes it (design 0005, Replies):
/// `{ result: { result?, source, verified, … } }`, or `{ error }`.
#[derive(Deserialize)]
struct Reply<'a> {
    #[serde(borrow, default)]
    result: Option<ReadResult<'a>>,
}

#[derive(Deserialize)]
struct ReadResult<'a> {
    /// The node's result, raw; absent when it was `undefined`.
    #[serde(borrow, default)]
    result: Option<&'a RawValue>,
    verified: bool,
}

/// What a reply's `payload` gives: the verified answer's bytes, or why
/// there is none. Only a verified answer is read further.
fn answer(payload: &[u8], past_due: bool) -> Answer {
    let failed = if past_due { Why::PastDue } else { Why::Failed };
    let Ok(Reply {
        result: Some(result),
    }) = serde_json::from_slice::<Reply<'_>>(payload)
    else {
        return Err(failed);
    };
    if !result.verified {
        return Err(Why::Unverified);
    }
    let text = result
        .result
        .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())
        .ok_or(Why::Unreadable(None))?;
    parse_bytes(&text, "result").map_err(|_| Why::Unreadable(None))
}

#[cfg(test)]
mod tests;
