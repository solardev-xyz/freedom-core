//! COL-2 (design 0014): every COL-1 trace, replayed through the native,
//! verifier-only C core.
//!
//! `vectors/colibri.json` records each call the reference made into the
//! WASM build of the C core (3.0.3, version 196611): method support,
//! context creation, the freshness bound, each step's status text
//! verbatim, every answer and error, frees, decodes, verifications, and the
//! store's gets, sets and deletes. This test makes the same calls, with the
//! same inputs, into the native C core and requires the same outputs: each
//! status text byte for byte (its request pointers renumbered as the
//! recorder renumbered them), each method type, each decode, the store
//! operations each call makes, and the store at the end.
//!
//! Each case runs in a child process of its own (this binary again, with
//! `FREEDOM_COLIBRID_REPLAY_CASE` set), as the reference loaded a fresh WASM
//! instance for each: the C core keeps its caches, storage hooks and clock in
//! process globals. The clock is fixed at each request's recorded instant,
//! as the reference fixed it. A case that starts from another case's final
//! store gets the bytes that case's own replay left.
//!
//! `cargo test --test replay -- <substring>` runs the cases whose id
//! contains the substring.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use colibri_stateless::{
    PendingRequest, ProverMode, RpcCtx, Step, Storage, Verifier, decode_proof,
    get_current_version_number, get_method_support, register_storage, set_fixed_time,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

const CASE_ENV: &str = "FREEDOM_COLIBRID_REPLAY_CASE";
const STORES_ENV: &str = "FREEDOM_COLIBRID_REPLAY_STORES";
/// The version number the traces were recorded with (3.0.3).
const CLIENT_VERSION: u32 = 196_611;

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let outcome = match std::env::var(CASE_ENV) {
        Ok(id) => run_case(&id),
        Err(_) => run_all(),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_vectors() -> Result<Value> {
    let path = repo_root().join("vectors/colibri.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| format!("missing `{name}` in {}", short(value)))
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| format!("`{name}` is not a string in {}", short(value)))
}

fn number(value: &Value, name: &str) -> Result<u64> {
    let v = field(value, name)?;
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| format!("`{name}` is not an unsigned number in {}", short(value)))
}

fn short(value: &Value) -> String {
    let mut s = value.to_string();
    if s.len() > 300 {
        let mut end = 300;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push('…');
    }
    s
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

// --- The parent: one child per case ------------------------------------

fn run_all() -> Result<()> {
    let vectors = load_vectors()?;
    let reference = field(&vectors, "reference")?;
    if number(reference, "client_version")? != u64::from(CLIENT_VERSION) {
        return Err(format!(
            "the vectors' client_version is not {CLIENT_VERSION}"
        ));
    }
    let native = get_current_version_number();
    if native != CLIENT_VERSION {
        return Err(format!(
            "the native C core reports version {native}, not {CLIENT_VERSION}"
        ));
    }

    let filters: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let cases = field(&vectors, "cases")?
        .as_array()
        .ok_or("`cases` is not a list")?;
    let mut order: Vec<&Value> = Vec::new();
    let mut placed: HashSet<&str> = HashSet::new();
    // Sources of warm stores first. A case runs if its id matches a filter,
    // or if a case that runs starts from its store.
    let wanted: HashSet<&str> = {
        let mut set: HashSet<&str> = HashSet::new();
        for case in cases {
            let id = text(case, "id")?;
            if filters.is_empty() || filters.iter().any(|f| id.contains(f.as_str())) {
                let mut cur = Some(case);
                while let Some(c) = cur {
                    set.insert(text(c, "id")?);
                    cur = match c
                        .get("store")
                        .and_then(|s| s.get("from"))
                        .and_then(Value::as_str)
                    {
                        Some(from) => cases
                            .iter()
                            .find(|x| x.get("id").and_then(Value::as_str) == Some(from)),
                        None => None,
                    };
                }
            }
        }
        set
    };
    let mut remaining: VecDeque<&Value> = cases
        .iter()
        .filter(|c| {
            c.get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| wanted.contains(id))
        })
        .collect();
    let mut stalled = 0;
    while let Some(case) = remaining.pop_front() {
        let from = case
            .get("store")
            .and_then(|s| s.get("from"))
            .and_then(Value::as_str);
        if from.is_some_and(|f| !placed.contains(f)) {
            remaining.push_back(case);
            stalled += 1;
            if stalled > remaining.len() {
                return Err(format!(
                    "no case can start: {} wait for a store",
                    remaining.len()
                ));
            }
            continue;
        }
        stalled = 0;
        placed.insert(text(case, "id")?);
        order.push(case);
    }

    let stores =
        std::env::temp_dir().join(format!("freedom-colibrid-replay-{}", std::process::id()));
    std::fs::create_dir_all(&stores).map_err(|e| format!("{}: {e}", stores.display()))?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut failed: Vec<String> = Vec::new();
    let mut failed_ids: HashSet<String> = HashSet::new();
    // The largest of each measure, by kind of case (request or checkpoint),
    // with the case that reached it.
    let mut peaks: BTreeMap<(String, String), (u64, String)> = BTreeMap::new();
    let mut crashed: Vec<String> = Vec::new();
    for case in &order {
        let id = text(case, "id")?;
        let from = case
            .get("store")
            .and_then(|s| s.get("from"))
            .and_then(Value::as_str);
        if let Some(f) = from.filter(|f| failed_ids.contains(*f)) {
            println!("skipped {id}: its store's case {f} failed");
            failed.push(format!("{id}: skipped, its store's case {f} failed"));
            failed_ids.insert(id.to_string());
            continue;
        }
        let output = Command::new(&exe)
            .env(CASE_ENV, id)
            .env(STORES_ENV, &stores)
            .output()
            .map_err(|e| format!("{id}: spawn: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let trapped_at = stdout.lines().find_map(|l| l.strip_prefix(TRAP_STEP));
        if let Some(step) = trapped_at.filter(|_| died_of_stack_exhaustion(&output.status, &stderr))
        {
            // 0014: the service ends #750's case "in an error or a crash,
            // never a result"; the C core recursed past the stack at the step
            // where the reference trapped.
            let first = stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            match check_crashed_trap(case, &stores, id, step) {
                Ok(()) => {
                    println!(
                        "ok {id}: the native step at trace[{step}] ran out of stack where the reference trapped ({}; {first}); no metrics",
                        output.status
                    );
                    crashed.push(id.to_string());
                }
                Err(e) => {
                    println!("FAILED {id}: died at its trap step, but {e}");
                    failed.push(format!("{id}: {e}"));
                    failed_ids.insert(id.to_string());
                }
            }
            continue;
        }
        if output.status.success() {
            println!("ok {id}");
            let kind = text(case, "kind")?.to_string();
            // A case's own notes (a trap that ended in an error).
            for line in stdout.lines().filter(|l| l.starts_with(&format!("{id}: "))) {
                println!("  {line}");
            }
            // Exactly one record with every measure: none may go missing.
            let records: Vec<&str> = stdout
                .lines()
                .filter_map(|l| l.strip_prefix(METRICS))
                .collect();
            let [line] = records.as_slice() else {
                return Err(format!("{id}: {} metrics records, not one", records.len()));
            };
            let metrics: Map<String, Value> =
                serde_json::from_str(line).map_err(|e| format!("{id}: metrics: {e}"))?;
            let mut names: Vec<&str> = metrics.keys().map(String::as_str).collect();
            names.sort_unstable();
            if names != METRIC_NAMES {
                return Err(format!("{id}: metrics {names:?}, not {METRIC_NAMES:?}"));
            }
            for (name, value) in metrics {
                let value = match value.as_u64() {
                    Some(value) => value,
                    // Only Linux reports peak memory to the process itself.
                    None if name == "peak_rss_kib"
                        && value.is_null()
                        && !cfg!(target_os = "linux") =>
                    {
                        continue;
                    }
                    None => return Err(format!("{id}: metric {name} is {value}")),
                };
                let peak = peaks
                    .entry((kind.clone(), name))
                    .or_insert((0, String::new()));
                if value > peak.0 {
                    *peak = (value, id.to_string());
                }
            }
        } else {
            let tail: String = stderr
                .chars()
                .rev()
                .take(4000)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            println!("FAILED {id} ({}):\n{tail}", output.status);
            failed.push(format!("{id}: {}", output.status));
            failed_ids.insert(id.to_string());
        }
    }
    let _ = std::fs::remove_dir_all(&stores);
    println!(
        "\npeaks over the passing cases (0014, Budgets); none from the {} that died at their trap step ({}):",
        crashed.len(),
        crashed.join(", ")
    );
    for ((kind, name), (value, id)) in &peaks {
        println!("  {kind:<10} {name:<16} {value:>10}  ({id})");
    }
    println!("\n{} cases, {} failed", order.len(), failed.len());
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("failed:\n  {}", failed.join("\n  ")))
    }
}

// --- The child: one case ------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum StoreOp {
    Get {
        key: String,
        value: Option<(usize, String)>,
    },
    Set {
        key: String,
        len: usize,
        sha256: String,
    },
    Del {
        key: String,
    },
}

#[derive(Default)]
struct StoreState {
    entries: BTreeMap<String, Vec<u8>>,
    log: Vec<StoreOp>,
    /// While set, each operation is also appended here as it happens, in
    /// the vector's form: a step that may kill the process (#750's) leaves
    /// its operations for the parent to check.
    journal: Option<std::fs::File>,
    journal_error: Option<String>,
}

impl StoreState {
    fn record(&mut self, op: StoreOp) {
        if let Some(file) = self.journal.as_mut() {
            let mut line = store_op_json(&op).to_string();
            line.push('\n');
            if let Err(e) = std::io::Write::write_all(file, line.as_bytes()) {
                self.journal_error.get_or_insert(e.to_string());
            }
        }
        self.log.push(op);
    }
}

/// A store operation in the vector's form (`store_get`, `store_set`,
/// `store_del`), which `recorded_store_op` reads back.
fn store_op_json(op: &StoreOp) -> Value {
    match op {
        StoreOp::Get { key, value: None } => {
            serde_json::json!({ "op": "store_get", "key": key, "found": false })
        }
        StoreOp::Get {
            key,
            value: Some((len, sha)),
        } => {
            serde_json::json!({ "op": "store_get", "key": key, "bytes": len, "sha256": sha })
        }
        StoreOp::Set { key, len, sha256 } => {
            serde_json::json!({ "op": "store_set", "key": key, "bytes": len, "sha256": sha256 })
        }
        StoreOp::Del { key } => serde_json::json!({ "op": "store_del", "key": key }),
    }
}

/// The C core's store for one case: a map, and every operation on it.
#[derive(Clone, Default)]
struct ReplayStore(Arc<Mutex<StoreState>>);

impl ReplayStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, StoreState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Storage for ReplayStore {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut state = self.lock();
        let value = state.entries.get(key).cloned();
        let summary = value.as_ref().map(|v| (v.len(), sha256_hex(v)));
        state.record(StoreOp::Get {
            key: key.to_string(),
            value: summary,
        });
        value
    }

    fn set(&self, key: &str, value: &[u8]) {
        let mut state = self.lock();
        state.record(StoreOp::Set {
            key: key.to_string(),
            len: value.len(),
            sha256: sha256_hex(value),
        });
        state.entries.insert(key.to_string(), value.to_vec());
    }

    fn delete(&self, key: &str) {
        let mut state = self.lock();
        state.record(StoreOp::Del {
            key: key.to_string(),
        });
        state.entries.remove(key);
    }
}

fn recorded_store_op(op: &Value) -> Result<StoreOp> {
    let key = text(op, "key")?.to_string();
    Ok(match text(op, "op")? {
        "store_get" => {
            if op.get("found").and_then(Value::as_bool) == Some(false) {
                StoreOp::Get { key, value: None }
            } else {
                let len = usize::try_from(number(op, "bytes")?).map_err(|e| e.to_string())?;
                StoreOp::Get {
                    key,
                    value: Some((len, text(op, "sha256")?.to_string())),
                }
            }
        }
        "store_set" => StoreOp::Set {
            key,
            len: usize::try_from(number(op, "bytes")?).map_err(|e| e.to_string())?,
            sha256: text(op, "sha256")?.to_string(),
        },
        "store_del" => StoreOp::Del { key },
        other => return Err(format!("not a store op: {other}")),
    })
}

/// The recorder's request numbering (vectors/generator/colibri.js,
/// `reqIndex`): a pointer gets the next index the first time it is seen,
/// and again when the C core reuses it after its request was answered.
#[derive(Default)]
struct RequestIndex {
    by_pointer: HashMap<u64, u64>,
    answered: HashSet<u64>,
    next: u64,
}

impl RequestIndex {
    fn index(&mut self, pointer: u64) -> u64 {
        match self.by_pointer.get(&pointer) {
            Some(index) if !self.answered.contains(index) => *index,
            _ => {
                let index = self.next;
                self.next += 1;
                self.by_pointer.insert(pointer, index);
                index
            }
        }
    }
}

/// A native status text as the recorder wrote the reference's: each
/// `"req_ptr": "<pointer>"` (the native API writes pointers as strings,
/// the WASM build as numbers) becomes `"req_ptr": <index>`.
fn renumber(status: &str, pointers: &[u64], index: &mut RequestIndex) -> Result<String> {
    const KEY: &str = "\"req_ptr\": ";
    let indices: HashMap<u64, u64> = pointers.iter().map(|p| (*p, index.index(*p))).collect();
    let mut out = String::with_capacity(status.len());
    let mut rest = status;
    let mut seen = 0;
    while let Some(at) = rest.find(KEY) {
        out.push_str(&rest[..at + KEY.len()]);
        rest = &rest[at + KEY.len()..];
        let quoted = rest.starts_with('"');
        let body = if quoted { &rest[1..] } else { rest };
        let digits = body.bytes().take_while(u8::is_ascii_digit).count();
        let pointer: u64 = body[..digits]
            .parse()
            .map_err(|e| format!("req_ptr in {status}: {e}"))?;
        let mapped = indices
            .get(&pointer)
            .ok_or_else(|| format!("req_ptr {pointer} is not one of the step's requests"))?;
        out.push_str(&mapped.to_string());
        rest = &body[digits..];
        if quoted {
            rest = rest
                .strip_prefix('"')
                .ok_or_else(|| format!("unterminated req_ptr in {status}"))?;
        }
        seen += 1;
    }
    out.push_str(rest);
    if seen != pointers.len() {
        return Err(format!(
            "{seen} req_ptr in a step with {} requests",
            pointers.len()
        ));
    }
    Ok(out)
}

enum Ctx {
    Rpc(RpcCtx),
    Verify(Verifier),
}

impl Ctx {
    fn execute(&mut self) -> Result<(Step<'_>, String)> {
        match self {
            Ctx::Rpc(ctx) => ctx.execute_with_status(),
            Ctx::Verify(ctx) => ctx.execute_with_status(),
        }
        .map_err(|e| format!("execute: {e}"))
    }
}

fn prover_mode(mode: u64) -> Result<ProverMode> {
    Ok(match mode {
        0 => ProverMode::Local,
        1 => ProverMode::Remote,
        2 => ProverMode::Hybrid,
        3 => ProverMode::Proxy,
        4 => ProverMode::LightClient,
        other => return Err(format!("unknown prover mode {other}")),
    })
}

/// Bodies by SHA-256: the fixtures' files, flipped copies of them and
/// scripted texts, as the case's fetches name them.
struct Bodies {
    dir: PathBuf,
    flips: HashMap<String, (usize, String)>,
    scripted: HashMap<String, Vec<u8>>,
}

impl Bodies {
    fn for_case(case: &Value) -> Result<Self> {
        let mut flips = HashMap::new();
        let mut scripted = HashMap::new();
        for op in field(case, "trace")?
            .as_array()
            .ok_or("`trace` is not a list")?
        {
            let Some(reply) = op.get("reply") else {
                continue;
            };
            let Some(derived) = reply.get("derived") else {
                continue;
            };
            let sha = text(reply, "sha256")?.to_string();
            if let Some(offset) = derived.get("flip") {
                let offset = usize::try_from(offset.as_u64().ok_or("flip offset")?)
                    .map_err(|e| e.to_string())?;
                flips.insert(sha, (offset, text(derived, "of")?.to_string()));
            } else if derived.get("scripted").and_then(Value::as_bool) == Some(true) {
                scripted.insert(sha, text(derived, "body")?.as_bytes().to_vec());
            }
        }
        Ok(Self {
            dir: repo_root().join("vectors/fixtures/colibri/bodies"),
            flips,
            scripted,
        })
    }

    fn get(&self, sha: &str, len: usize) -> Result<Vec<u8>> {
        let bytes = if let Some(body) = self.scripted.get(sha) {
            body.clone()
        } else if let Some((offset, of)) = self.flips.get(sha) {
            let mut bytes = self.file(of)?;
            let byte = bytes
                .get_mut(*offset)
                .ok_or_else(|| format!("flip offset {offset} past {of}"))?;
            *byte ^= 1;
            bytes
        } else {
            self.file(sha)?
        };
        if bytes.len() != len || sha256_hex(&bytes) != sha {
            return Err(format!(
                "body {sha}: {} bytes, digest {}",
                bytes.len(),
                sha256_hex(&bytes)
            ));
        }
        Ok(bytes)
    }

    fn file(&self, sha: &str) -> Result<Vec<u8>> {
        let path = self.dir.join(format!("{sha}.bin"));
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if sha256_hex(&bytes) != sha {
            return Err(format!("{}: digest differs", path.display()));
        }
        Ok(bytes)
    }
}

fn store_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

fn check_entries(entries: &BTreeMap<String, Vec<u8>>, recorded: &Value, what: &str) -> Result<()> {
    let recorded = recorded
        .as_object()
        .ok_or_else(|| format!("{what} is not an object"))?;
    let native: Map<String, Value> = entries
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                serde_json::json!({ "bytes": v.len(), "sha256": sha256_hex(v) }),
            )
        })
        .collect();
    if &native != recorded {
        return Err(format!(
            "{what} differs:\n  native:    {}\n  reference: {}",
            Value::Object(native),
            Value::Object(recorded.clone())
        ));
    }
    Ok(())
}

fn run_case(id: &str) -> Result<()> {
    let vectors = load_vectors()?;
    let cases = field(&vectors, "cases")?
        .as_array()
        .ok_or("`cases` is not a list")?;
    let case = cases
        .iter()
        .find(|c| c.get("id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| format!("no case {id}"))?;
    let stores = PathBuf::from(std::env::var_os(STORES_ENV).ok_or("no store directory")?);
    let requests = field(case, "requests")?
        .as_array()
        .ok_or("`requests` is not a list")?;
    let bodies = Bodies::for_case(case)?;

    let store = ReplayStore::default();
    if let Some(seed) = case.get("store").filter(|s| !s.is_null()) {
        let from = text(seed, "from")?;
        let path = store_path(&stores, from);
        let saved: BTreeMap<String, String> = serde_json::from_str(
            &std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?,
        )
        .map_err(|e| e.to_string())?;
        let entries = saved
            .into_iter()
            .map(|(k, v)| Ok((k, from_hex(&v)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        check_entries(
            &entries,
            field(seed, "entries")?,
            &format!("the store {from} left"),
        )?;
        store.lock().entries = entries;
    }
    register_storage(store.clone());

    let trace = field(case, "trace")?
        .as_array()
        .ok_or("`trace` is not a list")?;
    let mut ctxs: HashMap<u64, Ctx> = HashMap::new();
    let mut index = RequestIndex::default();
    let mut expected_store: Vec<StoreOp> = Vec::new();
    let mut max_step = Duration::ZERO;
    let mut i = 0;
    while i < trace.len() {
        let op = &trace[i];
        let pos = i;
        let at = |e: String| format!("{id}: trace[{pos}] {}: {e}", short(op));
        let name = text(op, "op").map_err(at)?;
        match name {
            "store_get" | "store_set" | "store_del" => {
                expected_store.push(recorded_store_op(op).map_err(at)?);
                i += 1;
                continue;
            }
            "request" => {
                let n = usize::try_from(number(op, "index").map_err(at)?)
                    .map_err(|e| at(e.to_string()))?;
                let clock = number(
                    requests
                        .get(n)
                        .ok_or_else(|| at("no such request".into()))?,
                    "clock",
                )
                .map_err(at)?;
                set_fixed_time(Some(clock / 1000));
            }
            "checkpoint" => {
                let first = requests.first().ok_or_else(|| at("no request".into()))?;
                set_fixed_time(Some(number(first, "clock").map_err(at)? / 1000));
            }
            "fetch" | "main_fetch" => {}
            "method_type" => {
                let chain = number(op, "chain").map_err(at)?;
                let params = text(op, "params").map_err(at)?;
                let flags = u32::try_from(number(op, "flags").map_err(at)?)
                    .map_err(|e| at(e.to_string()))?;
                let native =
                    get_method_support(chain, text(op, "method").map_err(at)?, Some(params), flags)
                        .map_err(|e| at(e.to_string()))? as u64;
                let recorded = number(op, "type").map_err(at)?;
                if native != recorded {
                    return Err(at(format!(
                        "method type {native}, the reference's {recorded}"
                    )));
                }
            }
            "create" => {
                let ctx = RpcCtx::new(
                    text(op, "method").map_err(at)?,
                    text(op, "params").map_err(at)?,
                    number(op, "chain").map_err(at)?,
                    u32::try_from(number(op, "prover_flags").map_err(at)?)
                        .map_err(|e| at(e.to_string()))?,
                    u32::try_from(number(op, "verify_flags").map_err(at)?)
                        .map_err(|e| at(e.to_string()))?,
                    prover_mode(number(op, "mode").map_err(at)?).map_err(at)?,
                )
                .map_err(|e| at(format!("create: {e}")))?;
                ctxs.insert(number(op, "ctx").map_err(at)?, Ctx::Rpc(ctx));
            }
            "min_latest_block_ts" => {
                let ts = number(op, "ts").map_err(at)?;
                match ctxs.get_mut(&number(op, "ctx").map_err(at)?) {
                    Some(Ctx::Rpc(ctx)) => ctx.set_min_latest_block_ts(ts),
                    _ => return Err(at("no such RPC context".into())),
                }
            }
            "verify_create" => {
                if !field(op, "witness_keys").map_err(at)?.is_null() {
                    return Err(at("witness keys aren't replayed".into()));
                }
                let len = usize::try_from(number(op, "bytes").map_err(at)?)
                    .map_err(|e| at(e.to_string()))?;
                let proof = bodies
                    .get(text(op, "sha256").map_err(at)?, len)
                    .map_err(at)?;
                let checkpoint = field(op, "trusted_checkpoint").map_err(at)?.as_str();
                let mut ctx = Verifier::new(
                    &proof,
                    text(op, "method").map_err(at)?,
                    text(op, "args").map_err(at)?,
                    number(op, "chain").map_err(at)?,
                    checkpoint,
                    u32::try_from(number(op, "flags").map_err(at)?)
                        .map_err(|e| at(e.to_string()))?,
                )
                .map_err(|e| at(format!("verify_create: {e}")))?;
                ctx.set_min_latest_block_ts(number(op, "min_latest_block_ts").map_err(at)?);
                ctxs.insert(number(op, "ctx").map_err(at)?, Ctx::Verify(ctx));
            }
            "decode" => {
                let len = usize::try_from(number(op, "bytes").map_err(at)?)
                    .map_err(|e| at(e.to_string()))?;
                let proof = bodies
                    .get(text(op, "sha256").map_err(at)?, len)
                    .map_err(at)?;
                let native = decode_proof(&proof)
                    .map(|s| serde_json::json!({ "chars": s.encode_utf16().count(), "sha256": sha256_hex(s.as_bytes()) }))
                    .unwrap_or(Value::Null);
                // Deviation `checked-decode`: the service's decode checks the
                // proof first, so the design's result, not the reference's.
                let recorded =
                    if case.get("deviation").and_then(Value::as_str) == Some("checked-decode") {
                        field(field(case, "design").map_err(at)?, "decode").map_err(at)?
                    } else {
                        field(op, "result").map_err(at)?
                    };
                if &native != recorded {
                    return Err(at(format!("decoded {native}, the reference {recorded}")));
                }
            }
            "free" | "verify_free" => {
                if ctxs.remove(&number(op, "ctx").map_err(at)?).is_none() {
                    return Err(at("no such context".into()));
                }
            }
            "step" | "verify" => {
                let n = number(op, "ctx").map_err(at)?;
                let ctx = ctxs
                    .get_mut(&n)
                    .ok_or_else(|| at("no such context".into()))?;
                if let Some(trap) = op.get("trap") {
                    // The reference's WASM build trapped in this step (#750:
                    // a hash in no block, F-6). 0014: "The service must end it
                    // in an error or a crash, never a result". The parent
                    // accepts a crash only after this marker, and only of
                    // stack exhaustion; here an error status passes. Either
                    // way the step's store operations and the final store
                    // are checked (`check_trap_store`): the parent reads them
                    // from the journal if the process dies.
                    let before: BTreeMap<String, String> = store
                        .lock()
                        .entries
                        .iter()
                        .map(|(k, v)| (k.clone(), to_hex(v)))
                        .collect();
                    let saved = serde_json::json!({ "step": pos, "before": before });
                    std::fs::write(trap_path(&stores, id), saved.to_string())
                        .map_err(|e| at(e.to_string()))?;
                    let journal = std::fs::File::create(journal_path(&stores, id))
                        .map_err(|e| at(e.to_string()))?;
                    store.lock().journal = Some(journal);
                    println!("{TRAP_STEP}{pos}");
                    std::io::Write::flush(&mut std::io::stdout()).map_err(|e| at(e.to_string()))?;
                    let started = Instant::now();
                    let (_, status) = ctx.execute().map_err(at)?;
                    max_step = max_step.max(started.elapsed());
                    let native = {
                        let mut state = store.lock();
                        state.journal = None;
                        if let Some(e) = state.journal_error.take() {
                            return Err(at(format!("the trap step's journal: {e}")));
                        }
                        std::mem::take(&mut state.log)
                    };
                    let recorded = std::mem::take(&mut expected_store);
                    check_trap_store(&native, &recorded).map_err(at)?;
                    let parsed: Value =
                        serde_json::from_str(&status).map_err(|e| at(e.to_string()))?;
                    if parsed.get("status").and_then(Value::as_str) != Some("error") {
                        return Err(at(format!(
                            "the reference trapped ({trap}); the native step returned {status}"
                        )));
                    }
                    println!(
                        "{id}: the reference trapped ({trap}); the native step ended in an error: {status}"
                    );
                    i += 1;
                    continue;
                }
                let started = Instant::now();
                let (step, status) = ctx.execute().map_err(at)?;
                max_step = max_step.max(started.elapsed());
                check_store(&store, &mut expected_store).map_err(at)?;
                let mut pending: HashMap<u64, PendingRequest<'_>> = HashMap::new();
                let pointers: Vec<u64> = match &step {
                    Step::Pending { requests } => requests.iter().map(|r| r.req_ptr).collect(),
                    _ => Vec::new(),
                };
                let renumbered = renumber(&status, &pointers, &mut index).map_err(at)?;
                let recorded = text(op, "status").map_err(at)?;
                if renumbered != recorded {
                    return Err(at(format!(
                        "status differs:\n  native:    {renumbered}\n  reference: {recorded}"
                    )));
                }
                if let Step::Pending { requests } = step {
                    for request in requests {
                        pending.insert(index.index(request.req_ptr), request);
                    }
                }
                // The answers, up to the next operation on a context: every
                // pending step in the vectors is answered before one.
                while let Some(next) = trace.get(i + 1) {
                    let next_name = text(next, "op").map_err(at)?;
                    let at_next =
                        |e: String| format!("{id}: trace[{}] {}: {e}", i + 1, short(next));
                    match next_name {
                        "response" | "error" => {
                            check_store(&store, &mut expected_store).map_err(at_next)?;
                            let req = number(next, "req").map_err(at_next)?;
                            let node = u16::try_from(number(next, "node").map_err(at_next)?)
                                .map_err(|e| at_next(e.to_string()))?;
                            let request = pending
                                .remove(&req)
                                .ok_or_else(|| at_next(format!("request {req} isn't pending")))?;
                            index.answered.insert(req);
                            if next_name == "response" {
                                let len = usize::try_from(number(next, "bytes").map_err(at_next)?)
                                    .map_err(|e| at_next(e.to_string()))?;
                                let sha = text(next, "sha256").map_err(at_next)?;
                                // An answer no fetch served (the checkpoint
                                // check builds its own) carries its bytes.
                                let body = if let Some(inline) =
                                    next.get("body").and_then(Value::as_str)
                                {
                                    inline.as_bytes().to_vec()
                                } else if let Some(hex) =
                                    next.get("body_hex").and_then(Value::as_str)
                                {
                                    from_hex(hex).map_err(at_next)?
                                } else {
                                    bodies.get(sha, len).map_err(at_next)?
                                };
                                if body.len() != len || sha256_hex(&body) != sha {
                                    return Err(at_next(format!(
                                        "answer body: {} bytes, digest {}",
                                        body.len(),
                                        sha256_hex(&body)
                                    )));
                                }
                                request.set_response(&body, node);
                            } else {
                                request.set_error(text(next, "error").map_err(at_next)?, node);
                            }
                        }
                        "fetch" | "main_fetch" => {}
                        "store_get" | "store_set" | "store_del" => {
                            expected_store.push(recorded_store_op(next).map_err(at_next)?);
                        }
                        _ => break,
                    }
                    i += 1;
                }
                // Requests left unanswered stay pending in the C core and
                // come back in its next step.
                drop(pending);
                i += 1;
                continue;
            }
            "response" | "error" => return Err(at("an answer outside a step's answers".into())),
            other => return Err(at(format!("unknown op {other}"))),
        }
        check_store(&store, &mut expected_store).map_err(at)?;
        i += 1;
    }
    check_store(&store, &mut expected_store).map_err(|e| format!("{id}: at the end: {e}"))?;
    drop(ctxs);

    let entries = std::mem::take(&mut store.lock().entries);
    // A private case's store is in memory (no `store_after`).
    if let Some(after) = case.get("store_after").filter(|v| !v.is_null()) {
        check_entries(&entries, after, "the final store").map_err(|e| format!("{id}: {e}"))?;
    }
    let saved: BTreeMap<&String, String> = entries.iter().map(|(k, v)| (k, to_hex(v))).collect();
    let path = store_path(&stores, id);
    std::fs::write(
        &path,
        serde_json::to_vec(&saved).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;

    // What 0014's budgets are measured from ("Budgets": twice the peak over
    // the vectors): read by the parent from this line.
    let metrics = serde_json::json!({
        "peak_rss_kib": peak_rss_kib(),
        "max_step_ms": max_step.as_millis(),
        "max_store_value": entries.values().map(Vec::len).max().unwrap_or(0),
        "store_total": entries.values().map(Vec::len).sum::<usize>(),
    });
    println!("{METRICS}{metrics}");
    Ok(())
}

const METRICS: &str = "METRICS ";
/// The measures each case reports, sorted.
const METRIC_NAMES: [&str; 4] = [
    "max_step_ms",
    "max_store_value",
    "peak_rss_kib",
    "store_total",
];
const TRAP_STEP: &str = "TRAP-STEP ";

/// Whether a child died of stack exhaustion: Rust's guard-page handler and
/// ASan both say so on stderr; Windows ends the process with
/// STATUS_STACK_OVERFLOW.
fn died_of_stack_exhaustion(status: &std::process::ExitStatus, stderr: &str) -> bool {
    const STATUS_STACK_OVERFLOW: u32 = 0xC000_00FD;
    let windows = status
        .code()
        .is_some_and(|c| c as u32 == STATUS_STACK_OVERFLOW);
    let reported = !status.success()
        && status.code() != Some(1)
        && (stderr.contains("has overflowed its stack")
            || stderr.contains("fatal runtime error: stack overflow")
            || stderr.contains("AddressSanitizer: stack-overflow"));
    windows || reported
}

/// The process's peak resident memory, where the OS reports it to the
/// process itself without a system call std lacks (Linux: `VmHWM`).
fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn trap_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.trap.json"))
}

fn journal_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.trap-ops.jsonl"))
}

/// The store operations of a step where the reference trapped (#750). The
/// recursion that ran out of WASM's stack runs to another depth natively, so
/// its reads repeat another number of times: the reads, as a set, must be the
/// reference's, and the writes and deletes exactly the reference's, in order.
fn check_trap_store(native: &[StoreOp], recorded: &[StoreOp]) -> Result<()> {
    let writes = |ops: &[StoreOp]| -> Vec<StoreOp> {
        ops.iter()
            .filter(|op| !matches!(op, StoreOp::Get { .. }))
            .cloned()
            .collect()
    };
    let reads = |ops: &[StoreOp]| -> Vec<StoreOp> {
        let mut out: Vec<StoreOp> = ops
            .iter()
            .filter(|op| matches!(op, StoreOp::Get { .. }))
            .cloned()
            .collect();
        out.sort_by_key(|op| format!("{op:?}"));
        out.dedup();
        out
    };
    if writes(native) != writes(recorded) {
        return Err(format!(
            "the trap step's writes differ:\n  native:    {:?}\n  reference: {:?}",
            writes(native),
            writes(recorded)
        ));
    }
    if reads(native) != reads(recorded) {
        return Err(format!(
            "the trap step's reads differ:\n  native:    {:?}\n  reference: {:?}",
            reads(native),
            reads(recorded)
        ));
    }
    Ok(())
}

/// A case whose child died of stack exhaustion at its trap step: the step's
/// store operations from the journal, checked as `check_trap_store` checks
/// them, and the store they leave against the recorded final store, which
/// is saved for any case that starts from it.
fn check_crashed_trap(case: &Value, stores: &Path, id: &str, step: &str) -> Result<()> {
    let step: usize = step
        .trim()
        .parse()
        .map_err(|e| format!("trap step {step}: {e}"))?;
    let trace = field(case, "trace")?
        .as_array()
        .ok_or("`trace` is not a list")?;
    if trace.get(step).and_then(|op| op.get("trap")).is_none() {
        return Err(format!("trace[{step}] is not a trap"));
    }
    let mut first = step;
    while first > 0 && text(&trace[first - 1], "op")?.starts_with("store_") {
        first -= 1;
    }
    let recorded = trace[first..step]
        .iter()
        .map(recorded_store_op)
        .collect::<Result<Vec<_>>>()?;
    let saved: Value = serde_json::from_str(
        &std::fs::read_to_string(trap_path(stores, id))
            .map_err(|e| format!("the trap snapshot: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    if number(&saved, "step")? != step as u64 {
        return Err("the trap snapshot is of another step".into());
    }
    let mut entries = field(&saved, "before")?
        .as_object()
        .ok_or("the trap snapshot's store is not an object")?
        .iter()
        .map(|(k, v)| Ok((k.clone(), from_hex(v.as_str().ok_or("not hex")?)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let journal = std::fs::read_to_string(journal_path(stores, id))
        .map_err(|e| format!("the trap journal: {e}"))?;
    let mut native = Vec::new();
    for line in journal.lines() {
        // The process may die inside the store callback, mid-line: only an
        // unterminated last line may be cut off.
        match serde_json::from_str::<Value>(line) {
            Ok(op) => native.push(recorded_store_op(&op)?),
            Err(_) if !journal.ends_with('\n') && journal.lines().last() == Some(line) => {}
            Err(e) => return Err(format!("the trap journal: {e}")),
        }
    }
    check_trap_store(&native, &recorded)?;
    // Writes are the reference's (above); the journal can't carry their bytes,
    // so a write the reference made isn't replayed into the final store.
    if native.iter().any(|op| !matches!(op, StoreOp::Get { .. })) {
        return Err("a trap step that writes can't be checked from its journal".into());
    }
    if let Some(after) = case.get("store_after").filter(|v| !v.is_null()) {
        check_entries(&entries, after, "the final store")?;
    }
    let saved: BTreeMap<&String, String> = entries.iter().map(|(k, v)| (k, to_hex(v))).collect();
    std::fs::write(
        store_path(stores, id),
        serde_json::to_vec(&saved).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    entries.clear();
    Ok(())
}

/// The store operations the native C core made since the last check must
/// be the ones the reference made, in order.
fn check_store(store: &ReplayStore, expected: &mut Vec<StoreOp>) -> Result<()> {
    let native = std::mem::take(&mut store.lock().log);
    let recorded = std::mem::take(expected);
    if native != recorded {
        let first = native
            .iter()
            .zip(&recorded)
            .position(|(a, b)| a != b)
            .unwrap_or(native.len().min(recorded.len()));
        return Err(format!(
            "store operations differ at {first} ({} native, {} recorded):\n  native:    {:?}\n  reference: {:?}",
            native.len(),
            recorded.len(),
            native.get(first),
            recorded.get(first)
        ));
    }
    Ok(())
}
