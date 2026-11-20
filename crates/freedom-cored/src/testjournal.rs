//! `freedom-cored test-journal --dir <dir> --name <name> [--max-bytes <n>]`:
//! fc-store's JSON Lines journal driven from stdin, so the interop harness
//! (`vectors/generator/interop.test.js`, design 0013's PRF-5d) has the
//! reference's `readJournal` read files the core wrote, crashes included.
//! Only builds with the `testhooks` feature compile it (build.rs refuses
//! them outside debug and test builds), and it runs only with
//! `FREEDOM_CORED_TEST_METHODS` set; otherwise `test-journal` is an unknown
//! subcommand. No store uses it: the intent methods come with PRF-5e-3.
//!
//! Each stdin line is one operation, as JSON; each gets one line on stdout,
//! `{"ok":true,"size":<bytes>,…}` or `{"ok":false,"error":<code>}`:
//! - `{"op":"open"}`, answered with the records it read (each as its
//!   `JSON.stringify` text), the damaged lines' numbers and the torn tail;
//! - `{"op":"append","record":{…}}` and `{"op":"compact","records":[…]}`,
//!   each with `fail`, the steps that fail (`write`, `fsync`, `truncate`,
//!   `rename`, `flush`), and `crash`, the step before which the process
//!   exits at once (exit code 86), with nothing cleaned up;
//! - `{"op":"move_aside","tag":"…"}`, answered with the name it moved to.
//!
//! Records are read with `fc_json` (V8's `JSON.parse`), as the store's
//! records will be.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use fc_json::JsValue;
use fc_store::journal::{self, Journal};
use fc_store::{Hooks, Step};

/// The exit code of a crash a test asked for.
const CRASHED: u8 = 86;

struct Injected {
    fail: Vec<String>,
    crash: Option<String>,
}

impl Hooks for Injected {
    fn fails(&self, step: Step) -> bool {
        if self.crash.as_deref() == Some(step.name()) {
            let _ = std::io::stdout().flush();
            std::process::exit(i32::from(CRASHED));
        }
        self.fail.iter().any(|s| s == step.name())
    }
}

fn injected(op: &JsValue) -> Injected {
    let fail = op
        .get("fail")
        .and_then(JsValue::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(|s| s.as_str().map(str::to_owned))
        .collect();
    let crash = op.get("crash").and_then(|s| s.as_str().map(str::to_owned));
    Injected { fail, crash }
}

/// Runs the subcommand; its exit code.
pub fn run(mut args: impl Iterator<Item = std::ffi::OsString>) -> u8 {
    let (mut dir, mut name, mut max_bytes) = (None, None, journal::DEFAULT_MAX_BYTES);
    while let Some(flag) = args.next() {
        let Some(value) = args.next().and_then(|v| v.into_string().ok()) else {
            return 64;
        };
        match flag.to_str() {
            Some("--dir") => dir = Some(PathBuf::from(value)),
            Some("--name") => name = Some(value),
            Some("--max-bytes") => match value.parse() {
                Ok(n) => max_bytes = n,
                Err(_) => return 64,
            },
            _ => return 64,
        }
    }
    let (Some(dir), Some(name)) = (dir, name) else {
        return 64;
    };
    let mut journal = Journal::new(&dir, &name, max_bytes);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return 74 };
        let answer = match fc_json::parse(&line) {
            Ok(op) => step(&mut journal, &op),
            Err(_) => serde_json::json!({ "ok": false, "error": "bad_op" }),
        };
        if writeln!(stdout, "{answer}")
            .and_then(|()| stdout.flush())
            .is_err()
        {
            return 74;
        }
    }
    0
}

fn step(journal: &mut Journal, op: &JsValue) -> serde_json::Value {
    let hooks = injected(op);
    let outcome = match op.get("op").and_then(JsValue::as_str) {
        Some("open") => journal.open().map(|read| {
            serde_json::json!({
                "records": read.parsed.records.iter().map(JsValue::stringify).collect::<Vec<_>>(),
                "corrupt": read.parsed.corrupt.iter().map(|c| c.line).collect::<Vec<_>>(),
                "tornTail": read.parsed.torn_tail,
                "unterminated": read.parsed.unterminated,
            })
        }),
        Some("append") => {
            let record = op.get("record").cloned().unwrap_or(JsValue::Null);
            journal
                .append(&record, &hooks)
                .map(|()| serde_json::json!({}))
        }
        Some("compact") => {
            let records = op
                .get("records")
                .and_then(JsValue::as_array)
                .unwrap_or(&[])
                .to_vec();
            journal
                .compact(&records, &hooks)
                .map(|()| serde_json::json!({}))
        }
        Some("move_aside") => {
            let tag = op.get("tag").and_then(JsValue::as_str).unwrap_or("aside");
            journal.move_aside(tag).map(|moved| {
                let moved =
                    moved.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
                serde_json::json!({ "moved": moved })
            })
        }
        _ => return serde_json::json!({ "ok": false, "error": "bad_op" }),
    };
    match outcome {
        Ok(mut answer) => {
            answer["ok"] = true.into();
            answer["size"] = journal.size().into();
            answer
        }
        Err(e) => serde_json::json!({ "ok": false, "error": e.code() }),
    }
}
