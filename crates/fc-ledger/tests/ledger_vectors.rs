//! Every case of vectors/ledger.json through the core's operations (design
//! 0016, LDG-1): the core's APDUs byte for byte, and its result from the
//! recorded answers, deviations as their rows in the design's table say.
//!
//! A case's answers are replayed in order wherever the core sends the APDU
//! the reference did. Where a deviation makes the core send another one
//! (`app-check`'s `B0 01` for a transaction or a message, the pieces of a
//! type 2 at a chain ID the reference can't parse, `chain-id-width`, the
//! values `field-pieces` cuts differently), the scripted device of
//! `formats.device` answers it; nowhere else.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use fc_evm::{Transaction, checksum_address, decode_signed, to_hex};
use fc_ledger::{Failed, LedgerCode, Refusal, Signed};
use serde_json::Value;

/// A case's end, as the vectors write it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum End {
    Accounts(Vec<(String, String)>),
    Added(String, String),
    Raw(String),
    Signature(String),
    Code(String),
}

fn recorded_end(case: &Value) -> End {
    let result = &case["result"];
    if result["status"] == "error" {
        return End::Code(result["code"].as_str().unwrap().to_owned());
    }
    let pair = |v: &Value| {
        (
            v["path"].as_str().unwrap().to_owned(),
            v["address"].as_str().unwrap().to_owned(),
        )
    };
    if let Some(accounts) = result.get("accounts") {
        return End::Accounts(accounts.as_array().unwrap().iter().map(pair).collect());
    }
    if let Some(wallet) = result.get("wallet") {
        let (path, address) = pair(wallet);
        return End::Added(path, address);
    }
    if let Some(raw) = result.get("raw") {
        return End::Raw(raw.as_str().unwrap().to_owned());
    }
    if let Some(signature) = result.get("signature") {
        return End::Signature(signature.as_str().unwrap().to_owned());
    }
    // x402: the payload @x402/evm built around the signature.
    let payload: Value = serde_json::from_str(result["payload"].as_str().unwrap()).unwrap();
    End::Signature(payload["payload"]["signature"].as_str().unwrap().to_owned())
}

fn core_end(done: &Result<Signed, fc_ledger::Failure>) -> End {
    match done {
        Ok(Signed::Accounts(accounts)) => End::Accounts(
            accounts
                .iter()
                .map(|a| (a.path.to_string(), checksum_address(&a.address)))
                .collect(),
        ),
        Ok(Signed::Added(a)) => End::Added(a.path.to_string(), checksum_address(&a.address)),
        Ok(Signed::Transaction(tx)) => End::Raw(to_hex(&tx.raw)),
        Ok(Signed::Signature(signature)) => End::Signature(to_hex(signature)),
        Err(failure) => End::Code(failure.code.as_str().to_owned()),
    }
}

fn marks(case: &Value) -> BTreeSet<String> {
    let mut marks: BTreeSet<String> = case["also"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| m.as_str().unwrap().to_owned())
        .collect();
    if let Some(deviation) = case["deviation"].as_str() {
        marks.insert(deviation.to_owned());
    }
    marks
}

/// The recorded answers, then the scripted device where the core leaves
/// the reference's stream.
struct Replay<'a> {
    recorded: &'a [Value],
    cursor: usize,
    diverged: bool,
    device: Device,
    /// The core's APDUs the scripted device answered.
    filled: Vec<usize>,
    /// Main couldn't open the device (`device.open`).
    unopened: bool,
}

impl Replay<'_> {
    fn reply(&mut self, index: usize, apdu: &[u8]) -> Owned {
        if self.unopened {
            return Owned::Failed(Failed::NotFound);
        }
        let device = self.device.answer(apdu);
        if !self.diverged {
            if let Some(exchange) = self.recorded.get(self.cursor) {
                let theirs = unhex(exchange["apdu"].as_str().unwrap());
                // address-from-device: the reference's E0 02 00 00 is the
                // core's E0 02 01 00, the device's answer the same.
                let display = theirs[..4] == [0xe0, 0x02, 0x00, 0x00]
                    && apdu[..4] == [0xe0, 0x02, 0x01, 0x00]
                    && theirs[4..] == apdu[4..];
                if theirs == apdu || display {
                    self.cursor += 1;
                    if exchange.get("thrown").is_some() {
                        return Owned::Failed(Failed::Disconnected);
                    }
                    let answer = unhex(exchange["answer"].as_str().unwrap());
                    return relay(index, apdu, Answer::Bytes(answer));
                }
            }
            // app-check: the reference reads B0 01 for typed data only.
            if apdu == [0xb0, 0x01, 0x00, 0x00, 0x00] {
                self.filled.push(index);
                return relay(index, apdu, device);
            }
            self.diverged = true;
        }
        self.filled.push(index);
        relay(index, apdu, device)
    }
}

/// The deviation a refusal implements, and its bound as the grammar file's
/// reason words it.
fn refusal_mark(refusal: &Refusal) -> (&'static str, Option<String>) {
    match refusal {
        Refusal::Path(_) => ("path-strict", None),
        Refusal::EmptyMessage => ("empty-message", None),
        Refusal::TypedData(_) => ("name-ascii", None),
        Refusal::TooLarge(bound) => (
            "device-bounds",
            Some(match bound {
                fc_ledger::bounds::Bound::Definition(n) => format!("an APDU's data of {n} bytes"),
                fc_ledger::bounds::Bound::Name(n) => format!("a name of {n} characters"),
                fc_ledger::bounds::Bound::ArrayEntries(n) => format!("an array of length of {n}"),
                fc_ledger::bounds::Bound::FixedSize(n) => format!("a fixed size of {n}"),
                other => format!("{other}"),
            }),
        ),
        other => panic!("a refusal no vector makes: {other}"),
    }
}

/// The address text of a recorded `E0 02` answer.
fn answered_address(case: &Value) -> String {
    let answer = unhex(case["exchanges"][0]["answer"].as_str().unwrap());
    let text = std::str::from_utf8(&answer[67..107]).unwrap();
    checksum_address(&fc_evm::parse_address(&format!("0x{text}")).unwrap())
}

#[test]
fn every_case() {
    let grammar = grammar();
    let honest: BTreeMap<&str, Vec<&str>> = grammar["honest"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            (
                h["case"].as_str().unwrap(),
                h["apdus"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap())
                    .collect(),
            )
        })
        .collect();
    let refused: BTreeMap<&str, (&str, &str)> = grammar["refused"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["case"].as_str().unwrap(),
                (
                    r["deviation"].as_str().unwrap(),
                    r["reason"].as_str().unwrap(),
                ),
            )
        })
        .collect();
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    let mut checked = 0;
    for case in cases() {
        let id = case["id"].as_str().unwrap();
        let marks = marks(case);
        for mark in &marks {
            *tally.entry(mark.clone()).or_default() += 1;
        }
        let op = operation(case);
        // Refused before the first APDU: the grammar file's refusals.
        if let Some((deviation, reason)) = refused.get(id) {
            let refusal = op
                .err()
                .unwrap_or_else(|| panic!("{id}: the core sent APDUs"));
            let (mark, words) = refusal_mark(&refusal);
            assert_eq!(mark, *deviation, "{id}: {refusal}");
            assert!(marks.contains(mark), "{id}: {mark} unmarked");
            if let Some(words) = words {
                assert_eq!(&words, reason, "{id}");
            }
            assert_eq!(
                refusal.code().map(LedgerCode::as_str),
                match mark {
                    "device-bounds" => Some("LEDGER_TOO_LARGE"),
                    "empty-message" => Some("LEDGER_EMPTY_MESSAGE"),
                    _ => None,
                },
                "{id}"
            );
            checked += 1;
            continue;
        }
        let mut op = op.unwrap_or_else(|e| panic!("{id}: refused: {e}"));
        let recorded = case["exchanges"].as_array().unwrap();
        let mut replay = Replay {
            recorded,
            cursor: 0,
            diverged: false,
            device: device_for(case),
            filled: Vec::new(),
            unopened: case["device"].get("open").is_some(),
        };
        let run = run(&mut op, |index, apdu| replay.reply(index, apdu));
        let ours: Vec<String> = run.apdus.iter().map(|a| hex(a)).collect();
        let theirs: Vec<&str> = recorded
            .iter()
            .map(|e| e["apdu"].as_str().unwrap())
            .collect();
        let end = core_end(&run.done);
        let mut want = recorded_end(case);

        // The stream.
        if let Some(stream) = honest.get(id) {
            assert_eq!(ours, *stream, "{id}: not the grammar's honest stream");
        }
        if replay.unopened {
            // Main fails the first APDU before any device holds it.
            assert_eq!((ours.len(), theirs.len()), (1, 0), "{id}");
        } else if marks.is_empty() {
            assert_eq!(ours, theirs, "{id}: the APDUs");
            assert!(replay.filled.is_empty(), "{id}: answers no recording gave");
        } else {
            let leaves = marks.contains("chain-id-width") || marks.contains("field-pieces");
            for index in &replay.filled {
                assert!(
                    leaves
                        || (marks.contains("app-check") && run.apdus[*index][..2] == [0xb0, 0x01]),
                    "{id}: APDU {index} answered by the script"
                );
            }
            // The core's stream is its stream for this request, fault-free,
            // up to where the case ends it.
            let clean = run_device(&mut operation(case).unwrap(), &mut device_for(case));
            assert!(
                clean.apdus.starts_with(&run.apdus),
                "{id}: not a prefix of the core's own stream"
            );
        }
        // The core reads every answer the reference was sent, but where a
        // deviation ends it sooner.
        let sooner = marks.contains("key-check")
            || marks.contains("blind-typed-data")
            || (marks.contains("app-check") && case["device"]["app"]["name"] != "Ethereum");
        if !replay.diverged && !replay.unopened {
            if sooner {
                assert!(replay.cursor <= recorded.len(), "{id}");
            } else {
                assert_eq!(replay.cursor, recorded.len(), "{id}: answers left over");
            }
        }

        // The result, deviations as their rows say.
        if marks.contains("address-from-device")
            && matches!(&want, End::Added(..) | End::Code(_))
            && (matches!(want, End::Added(..))
                || want == End::Code("LEDGER_ADDRESS_MISMATCH".into()))
        {
            // The device's address at the path, shown on it, whatever the
            // chrome sent.
            want = End::Added(
                case["request"]["path"].as_str().unwrap().to_owned(),
                answered_address(case),
            );
        }
        if marks.contains("app-check") && case["device"]["app"]["name"] != "Ethereum" {
            want = End::Code("LEDGER_ETH_APP_NOT_OPEN".into());
        }
        if marks.contains("signature-check") {
            want = End::Code("LEDGER_BAD_SIGNATURE".into());
        }
        if marks.contains("blind-typed-data") {
            // A 6D00 anywhere but the first E0 1A: today's mapping.
            want = End::Code("LEDGER_ETH_APP_NOT_OPEN".into());
        }
        if marks.contains("key-check") {
            // An address text that isn't its key's: a faulty answer.
            want = End::Code("LEDGER_UNKNOWN".into());
        }
        if marks.contains("chain-id-width") {
            // Signed, v read from the bound chain ID.
            let End::Raw(raw) = &end else {
                panic!("{id}: {end:?}")
            };
            let tx = Transaction::from_json(&case["request"]["tx"]).unwrap();
            let decoded = decode_signed(&unhex(raw)).unwrap();
            assert_eq!(*decoded.digest(), tx.prepare().unwrap().digest(), "{id}");
            assert_eq!(
                decoded.signer().unwrap(),
                account(&case["record"]).address,
                "{id}"
            );
            if tx.tx_type() == 0 {
                let v = tx
                    .chain_id()
                    .checked_add(tx.chain_id())
                    .unwrap()
                    .checked_add(&fc_evm::U256::from_u64(35 + u64::from(decoded.y_parity())))
                    .unwrap();
                assert_eq!(decoded.v(), Some(v), "{id}");
            }
            want = end.clone();
        }
        if marks.contains("no-device") {
            // Main's failed: not_found, where the reference's NoDevice is
            // LEDGER_UNKNOWN.
            want = End::Code("LEDGER_DEVICE_NOT_FOUND".into());
        }
        assert_eq!(end, want, "{id}");
        checked += 1;
    }
    assert_eq!(checked, 432);
    // Every deviation of the file's list is marked where it says.
    for (deviation, entry) in ledger()["deviations"].as_object().unwrap() {
        let listed = entry["cases"].as_array().map_or(0, Vec::len);
        assert_eq!(
            tally.get(deviation).copied().unwrap_or(0),
            listed,
            "{deviation}"
        );
    }
}

/// The cases with no deviation are the reference's exactly; each confirm
/// flag is the grammar's `waits`.
#[test]
fn the_user_confirms_only_where_the_rows_wait() {
    for case in cases() {
        let id = case["id"].as_str().unwrap();
        let Ok(mut op) = operation(case) else {
            continue;
        };
        let mut device = device_for(case);
        let run = run_device(&mut op, &mut device);
        let last = run.apdus.len() - 1;
        for (index, (apdu, confirm)) in run.apdus.iter().zip(&run.confirms).enumerate() {
            let waits = match apdu[..4] {
                [0xe0, 0x02, 0x01, 0x00] | [0xe0, 0x0c, _, _] => true,
                [0xe0, 0x04, ..] | [0xe0, 0x08, ..] => index == last,
                _ => false,
            };
            assert_eq!(*confirm, waits, "{id}: {}", hex(apdu));
        }
    }
}
