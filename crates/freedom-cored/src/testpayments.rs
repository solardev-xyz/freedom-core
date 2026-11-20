//! `freedom-cored test-payments --dir <dir>`: the `payments.*` methods
//! driven from stdin, through the same [`Store`] `serve` uses, so the
//! interop harness (`vectors/generator/interop.test.js`, design 0013's
//! PRF-5g-2) has the reference's payment-history.js read the database the
//! core wrote, and the core read the reference's. `<dir>` is the root, as
//! the hello's `grant_root` once `payments` is named: the database opens at
//! the first method, and the `x402-receipts.json` import runs then. Only
//! builds with the `testhooks` feature compile it (build.rs refuses them
//! outside debug and test builds), and it runs only with
//! `FREEDOM_CORED_TEST_METHODS` set; otherwise `test-payments` is an unknown
//! subcommand.
//!
//! Each stdin line is one request, `{"method":"payments.…","params":{…},
//! "now":<ms>}` (`now` the wall clock the method reads), read with
//! `fc_json`; each gets one line on stdout, `{"ok":<result>}` or
//! `{"error":<the error body>}`.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use fc_json::JsValue;

use crate::payments_store::Store;

/// Runs the subcommand; its exit code.
pub fn run(mut args: impl Iterator<Item = std::ffi::OsString>) -> u8 {
    let mut dir = None;
    while let Some(flag) = args.next() {
        let Some(value) = args.next() else {
            return 64;
        };
        match flag.to_str() {
            Some("--dir") => dir = Some(PathBuf::from(value)),
            _ => return 64,
        }
    }
    let Some(dir) = dir else {
        return 64;
    };
    let mut store = Store::new();
    store.configure(dir.clone(), dir);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return 74 };
        let Ok(request) = fc_json::parse(&line) else {
            return 65;
        };
        let method = request
            .get("method")
            .and_then(JsValue::as_str)
            .unwrap_or("");
        let params = request.get("params").map(JsValue::stringify);
        let now = match request.get("now") {
            Some(JsValue::Number(n)) if *n >= 0.0 && n.fract() == 0.0 => {
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "a whole, non-negative test clock"
                )]
                let now = *n as u64;
                now
            }
            _ => return 65,
        };
        let answer = match store.request(method, params.as_deref(), now) {
            Ok(result) => format!("{{\"ok\":{}}}", result.get()),
            Err(body) => match serde_json::to_string(&body) {
                Ok(body) => format!("{{\"error\":{body}}}"),
                Err(_) => return 70,
            },
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
