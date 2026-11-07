# 0014: The Colibri verifier process

**Status:** proposed. Roadmap item 3.3: Colibri leaves Electron main's WASM workers for its C core in a confined process of its own. Builds on [0001](0001-freedom-cored.md) (frames, deadlines, hardening), [0004](0004-naming-sessions.md) and [0005](0005-chain-data.md) (the `shell.verified` Colibri operations, the fault, capacity and #752 rules), [0007](0007-ipfs-service.md) and [0008](0008-radicle-service.md) (the service pattern), [0009](0009-dweb-verification.md) (streams in both directions) and [0010](0010-service-confinement.md) (confinement). Nothing here is built yet. The user decides the [open questions](#open-questions).

**The references:**
- **freedom-browser** at `e670715d` (`integration/rust-core`; the files below are unchanged since `f47ac5c1`, the first reading), in `src/main/`:
  - `ens/colibri-runtime.js` (224 lines), `ens/colibri-worker.js` (204), `ens/colibri-worker-host.js` (403) and `ens/colibri-resolver.js` (271): about 1.1k lines;
  - their callers: `core/chain-verified.js` (0005's executor), `core/naming-verified.js` (0004's), `myotis/checkpoint-verifier.js` and `myotis/checkpoint-verifier-worker.js`;
  - `core/service-client.js` (main's chain I/O pool), `core/naming-shell.js` (the session fetch and its redirect rule) and `networks/network-registry.js` (which prover URLs it accepts);
  - `package.json` (the pin, `files`, `asarUnpack`).
- **`@corpus-core/colibri-stateless` 3.0.3**, the npm tarball, in `cjs/`: `index.js` (the client and its request loop), `http.js` (the fetches), `strategy.js`, `types.js`, `runtime_wasm.js`, `chains.generated.js` (the default hosts), and `c4w.wasm`.
- **Upstream:** `corpus-core/colibri-stateless` (formerly `corpus-core/c4`; default branch `dev`) at tag `v3.0.3`, `2c65ae6e`: `README.md`, `CMakeLists.txt`, `libs/`, `src/api/colibri.h` (the C API), `src/api/colibri_common.c`, `src/util/state.c`, `src/chains/chains.cmake`, `src/chains/eth/verifier/`, `src/chains/eth/server/` (license headers only), `src/server/LICENSE.POLYFORM`, and `bindings/rust/` (crate `colibri-stateless` 0.1.0).
- **freedom-core** at `14148f25` (`main`; the crates below are unchanged since `152da6ce`, the first reading): `fc-service` (`conn.rs`, `confine/`, `network.rs`), `fc-protocol` (`stream.rs`), `fc-chain` (`methods.rs`, `machine/faults.rs`), and `services/freedom-radicled/src/confine.rs`.

## Summary

- **Today** Colibri runs as WASM inside Electron main: one worker thread per chain for chain data and ENS, and a throwaway worker per Myotis checkpoint check. Its fetches use Node's `fetch` in the worker, so the session's proxy and Tor settings don't apply. Its WASM memory can grow to 2 GiB inside main's process. A trap stopped killing main only once a V8 flag was set (#453).
- **The process (proposed):** `freedom-colibrid`, a service on `fc-service` like `freedom-ipfsd` and `freedom-radicled`.
  - Main spawns one persistent process per chain that has a prover, when that chain first needs Colibri, and a one-shot process for each checkpoint check.
  - Browser-wide, at most 3 persistent processes, 2 checkpoint processes and 6 chain directories exist at once. Main retires idle processes, and at the limit a request gets `Colibri service busy` and falls to its next source ([How many](#how-many)).
  - It confines itself under 0010 with `Network::Offline`: no socket of any kind. It reads and writes only its chain's cache directory.
  - It talks to main only over stdin and stdout. It binds no port and serves no loopback HTTP.
- **HTTP through main:** the C core is already sans-I/O: each step returns the data it needs. The service asks main for each piece with `shell.colibri_fetch`, naming a server *type*, a verb, a path and a payload, never a URL.
  - Main admits only the request shapes the open operation allows ([The fetch contract](#the-fetch-contract)) and refuses the rest.
  - Main picks the servers and fetches through the session's network stack. It reserves the body's maximum from a browser-wide pool before reading, reads the body whole, and streams it to the service over the pipe ([Bodies](#bodies)).
- **The build ([Q20](#open-questions)):** upstream's Rust crate pulls in tokio and reqwest, and its build script downloads prebuilt archives when it can't run CMake. The choice is between working through public upstream PRs (proposed: small PRs that gate the HTTP client behind a feature and make the build offline and pinned, with a pinned fork commit until they are released) and keeping a vendored copy of the C sources in this repository.
- **The protocol:** the core's side doesn't change. 0005's `{ colibri: "request" }` and 0004's `{ colibri: "resolve" }` and `{ colibri: "reverse" }` keep their wire shape and outcomes, and the core's fault, capacity and #752 rules stay as they are. What changes is what main runs for them: a client of the service instead of the WASM worker host. A step marker tells main which request was inside the C core when a process died. That attribution is step-local and best-effort: it is the process's own evidence, which a taken-over process could forge, and a crash that surfaces after its step has ended names nobody ([The step marker](#the-step-marker)).
- **The proof:** `vectors/colibri.json`, recorded from the JS reference through a recording runtime around the real `c4w.wasm`. The native build must reproduce every step's status text byte for byte, every data request and every storage write.
- **Running it:** budgets per process (memory, open requests, bodies, storage) and browser-wide (processes, resident memory, directories, main's fetch pool), a kill one second past a request's deadline while it is inside the C core, lazy restarts with 0007's back-off, and a recycle above the memory budget.
- **The migration, COL-1 to COL-6:** vectors, the native build, fc-service's service-to-main requests, the service, the browser's client behind a flag, then the switch and the removal of the WASM workers. The default-host question must be decided before COL-1, since COL-1's fixtures and COL-5's tests depend on it. Whether to ship only the native service or keep WASM for one release is [Q19](#open-questions).
- **Found while checking the code:** through Colibri, the reference answers `eth_gasPrice`, `eth_feeHistory` and any read at a `pending` or `earliest` block without a proof, and the router labels the answer verified ([F-1](#facts-found-while-checking-the-code)). It is being fixed in the browser's router and in `fc-chain` (freedom-browser #1046, freedom-core #276).

## Goals and non-goals

**Goals**
- **A verifier fault can't take main down,** whatever the fault: a memory error, an abort, a spin or a memory blow-up.
- **No network and no files of its own:** the verifier reaches the network only through main's fetches, which admit only the requests its open operations allow ([The fetch contract](#the-fetch-contract)). It reaches files only through its cache directory. What a taken-over verifier can still do with those fetches is listed as a [residual](#what-a-taken-over-verifier-keeps).
- **Colibri's fetches obey the session:** proxy, Tor, the endpoint policy and the onion gate, as 0005's `shell.rpc` does.
- **Parity** with the WASM adapter, shown by vectors, with every [deviation](#deviations) listed.
- **Bounded resources,** per process and browser-wide, with a defined result when a bound is reached. Today only the V8 heap of each worker is bounded.

**Non-goals**
- **The core's routing and naming rules** (0004, 0005). They stay as they are, apart from F-1's fix.
- **Colibri's verification rules.** Soundness is upstream's. The vectors pin us to the reference's behavior, and a soundness fix arrives with a version bump.
- **A local or hybrid prover, OP-Stack chains, and mobile.** Mobile links Colibri in-process through its own bindings.
- **Myotis.** It is already a separate process.
- **Confining the service on Windows beyond 0010's first step.** Files and network stay `unavailable` there until 0010's WIN-2.

## Today

### How main runs Colibri

- **One worker per chain** (`colibri-worker-host.js`). It owns that chain's clients and the verifier's disk store at `<userData>/colibri` (`:77–81`). Each client is `new Colibri({ chainId, prover: [proverUrl], zk_proof, privacy_mode: 'basic', proofStrategy: Strategy.VerifiedOnly, max_latest_age_seconds: 60 })` (`colibri-worker.js:130–137`).
- **The resource limits** are the worker's V8 heap: 256 MiB old generation, 32 MiB young, 4 MiB stack (`colibri-worker-host.js:59–63`). WASM memory isn't V8 heap, so they don't bound it. `c4w.wasm` declares 277 pages (17.3 MiB) at start and a maximum of 32,768 (2 GiB).
- **A trap retires the instance.** `colibri-runtime.js` sets `--wasm-enforce-bounds-checks` (`:72`), because in Electron's main process an out-of-bounds access was a SIGSEGV rather than a `RuntimeError` (#453). After a trap it builds a fresh instance and refuses calls on the old one (`guardRuntime`), and the host replaces the worker.
- **A stuck worker is killed.** At a request's deadline the host pings the worker. With no pong within 1 s it terminates it (`STUCK_PROBE_MS`, `colibri-worker-host.js:57`). A worker that answers is waiting on the network and keeps the request until 60 s past the deadline (`ABANDONED_MS`, `:58`): "Colibri's own fetches carry no timeout".
- **Bystanders** (#750): requests on a replaced worker that didn't cause it are sent once more to a fresh worker, and a bystander that still fails carries `colibriBystander`, so the router's fault backoff doesn't count it (`colibri-worker-host.js:22–46`, `stuckCulprit`). The culprit of a stuck worker is a guess when several requests were on it.
- **The native add-on is off.** Colibri 2.0.5 added an N-API add-on that Electron's `node` export condition picked, and it segfaulted main while verifying an `eth_call` proof. `C4_DISABLE_NATIVE=1` keeps the WASM build (`colibri-runtime.js:1–37`).
- **The callers:**
  - **chain data:** `chain-verified.js:245` runs `{ colibri: "request" }` through `requestViaColibri`, and classes its errors: a revert with hex data, `capacity` by message pattern, and `fault` by `isColibriFault` (`:91–99`), which matches `RuntimeError`, the trap texts and `Colibri worker replaced`;
  - **ENS:** `naming-verified.js:148` and `:159` run `resolveCallViaColibri` and `resolveReverseViaColibri`, which drive ethers' `BrowserProvider` over a client in the worker, with main's bounded CCIP fetch (`colibri-resolver.js:170–174`) and one client rebuild and retry when the error text looks like a network failure (`retryableColibriError`, `:76`);
  - **Myotis checkpoints:** `checkpoint-verifier-worker.js` fetches a proof from the prover itself (at most 4 MiB, `:10`), decodes it (`decode_proof`, `:355`) and verifies it (`verifyProof`, `:361`) on a memory store, with Colibri's `fetch` intercepted so that the checkpoint root it asks for is the one a quorum of checkpoint servers agreed on. The worker has 128 MiB of heap (`checkpoint-verifier.js:187`) and 90 s (`:6`).

### What Colibri fetches, and from where

- **The loop.** `C4Client.rpc` (`cjs/index.js:226`) creates a context, then repeats: run a step (`executeRpcCtx`); on `pending`, fetch every data request of the round at once (`handle_request`, `cjs/http.js:147`) and hand each answer or error back (`reqSetResponse`, `reqSetError`); on `success`, `revert` or `error`, stop.
- **A data request** has a type (`prover`, `beacon_api`, `checkpointz` or `eth_rpc`), a method, a path relative to a server, an optional JSON payload, an encoding, an `exclude_mask` of servers already tried, and optional `ttl` and `delay` (`src/api/colibri_common.c:230–247`).
- **The servers** come from the type (`cjs/http.js:151–168`):
  - `prover`: the configured prover;
  - `beacon_api`: the client's `beacon_apis`, then the prover;
  - `checkpointz`: `checkpointz`, then `beacon_apis`, then the prover;
  - `eth_rpc`: the client's `rpcs`.
- **The client keeps the package's default hosts.** `colibri-worker.js` passes only `prover`, so `rpcs`, `beacon_apis` and `checkpointz` keep the defaults of `chains.generated.js` (`cjs/index.js:89`). For mainnet that is four RPC hosts, three beacon APIs and seven checkpoint servers, run by corpus.core and third parties (`chains.generated.js:6–30`). The verifier asks for light-client updates and bootstraps (`sync_committee_state.c:201`, `:301`) and for checkpoint roots (`:709`) when its stored state needs them.
- **Each fetch** is the worker's `globalThis.fetch` (`cjs/http.js:187`): Node's, not the session's. It has no timeout and no body cap. A failure's text names the URL and the payload, and an HTTP error's text carries the whole response body.

### Facts found while checking the code

1. **F-1: unproven answers labelled verified.** The C core treats `eth_gasPrice` and `eth_feeHistory` as unproofable, and also any proofable method asked at a `pending` or `earliest` block (`eth_verify.c:141–154`, `:209–249`). For those it sends the JSON-RPC call to the `eth_rpc` servers and returns the answer as a success (`rpc_handle_unproofable`, `colibri_common.c:522–579`). `Strategy.VerifiedOnly` doesn't stop it (`OnlyProofStrategy`, `cjs/strategy.js:74`). The router asks Colibri for both methods and any block tag (`fc-chain/src/methods.rs:54` mirrors it), and labels Colibri's answers `verified: true`. So such a read is one public RPC's word, from a host the user never configured, shown as verified. Found by reading the code; COL-1's vectors show it running.
   - **Being fixed:** freedom-browser #1046 (PR #1048 into `main`, #1049 into `integration/rust-core`) puts the rule into main's router. freedom-core #276 (PR #279) ports it into `fc-chain` as a reference patch on its replay vectors.
   - Under that rule, Colibri isn't asked for `eth_gasPrice` or `eth_feeHistory`, or for a read whose block parameter is `pending`, `earliest` or not a string. The next source answers, under its own label.
   - Once those land, the router never sends these reads to the adapter. The service's own refusal ([Methods main calls](#methods-main-calls)) stays as a second guard, and COL-1's vectors pin what the adapter itself does.
2. **F-2: hosts the user didn't configure.** Even a user who set their own prover reaches the package's default beacon, checkpoint and RPC hosts (above).
3. **F-3: unused native add-ons ship.** Nothing in `package.json`'s `files` excludes the package's `prebuilds/`, and `asarUnpack` takes every `*.node`. So a build carries all five platforms' `colibri_native.node` (7.2 MiB together), which nothing loads.
4. **F-4: the ZK fallback is silent and sticky.** On an error containing `zk sync proof`, the client turns ZK off for the rest of its life and retries (`cjs/index.js:261–265`; upstream issue #369). The trust label still reads `ZK sync-committee proof`, since the core takes it from configuration (0004, 0005).
5. **F-5: the store is unbounded.** `createDiskStorage` joins the C core's key to the directory without checking it, and nothing bounds a value's size or the directory's (`colibri-worker.js:84–109`).
6. **F-6: the unknown-hash trap isn't reported upstream.** Upstream's issue list has no report of #750's out-of-bounds access on a hash the prover hasn't seen.
7. **F-7: upstream's build has four traps for us** ([The build](#the-build-q20)): the version number comes from `git describe`, the CMake tree is written into the source checkout, the prebuilt download is unverified, and third-party sources are fetched by tag.
8. **F-8: upstream's license labels disagree.**
   - The README makes everything except `src/server/` MIT (`README.md:259–269`), so `src/chains/eth/server/` is MIT by that text.
   - At `v3.0.3`, 12 of that directory's 32 files carry `SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0`. Of the rest, 5 say MIT and 15 carry no identifier. Two OP files had the same mismatch before #401.
   - No build of ours compiles any of them, and COL-2's gate checks that ([Licenses](#licenses)).

## Threat model

Stage 1 trusts main (0001). The attacker here controls the verifier's input: a malicious or compromised prover, beacon API or checkpoint server, or a page choosing what to ask (an unknown transaction hash, a contract whose code the EVM will run). Their goal is a memory error in the C or C++ code (the verifier, blst, evmone) that crashes, exhausts or takes over the process that runs it.

| Threat | Today: WASM workers in main | With `freedom-colibrid` |
|---|---|---|
| A memory error the input triggers | stays inside the instance's linear memory; WASM can't run injected native code; an access past that memory is a trap | native code: it can be taken over. The process boundary and 0010 contain it: no socket of its own, no file but its cache, no new process, no local IPC but main's pipe. On Windows only "no new process" until WIN-2. What it keeps is main's fetch contract ([below](#what-a-taken-over-verifier-keeps)) |
| The verifier crashes | main survives only because of a V8 flag. #453 killed the browser before it, and an Electron change could again | the service exits; main and the core run on |
| Memory | up to 2 GiB of WASM memory per worker inside main's address space | a budget per process; running out kills the service |
| CPU | a spinning step holds a core in main's process until the deadline plus 1 s; network waits hold their slot up to 60 s more | the same kill, of a process at lower priority; network waits end at the deadline |
| Network policy | Node's fetch: no proxy, no Tor, no endpoint policy | main's session stack, as `shell.rpc` |
| Where requests go | whatever request the instance returns, on the hosts of the four lists: any verb (`fetch_from_servers` only upper-cases it, `cjs/http.js:29`), any path, any payload, redirects followed anywhere, no body cap | the same hosts, named by type, and only the shapes the open operation allows ([The fetch contract](#the-fetch-contract)). Main builds the URL, the verb and every header, and caps each body |
| A taken-over verifier uses main's fetches | n/a: WASM can't run injected code (a damaged instance's requests are still fetched as given, as above) | within the contract only, while one of its operations is open. It keeps the free fields. Residual ([below](#what-a-taken-over-verifier-keeps)) |
| A taken-over verifier lies | possible in WASM too | unchanged. Isolation doesn't make answers more trustworthy |
| A taken-over verifier names a culprit | n/a: a trap is main's engine's own evidence | it can forge or clear its step markers, so a fault can land on the wrong request. The effect is #752's backoff of one method on one chain, never an answer. Residual |
| A taken-over verifier poisons its cache (forged sync-committee keys that later verifications trust) | possible: the store is reached from the instance | possible within its own chain's directory only; cleared after repeated crashes. Residual |
| Request data leaking | to main and to the hosts above | the same, and a taken-over process can also put what it holds (its operations' params, its cache) into the free fields, to that type's hosts. Residual |

**What changes for the worse:** WASM traps on every access past its linear memory. A native build traps only where an access reaches unmapped memory, so some accesses WASM catches become silent misreads natively. #750's unknown-hash case, which runs for seconds before WASM traps, may behave differently. The mitigations: a hardened build (stack protector, `_FORTIFY_SOURCE=3`, control-flow protection where the target has it), a sanitizer job over every vector in CI (COL-2), a fuzz target for the proof decoder and verifier (COL-4), and #752's rule, which keeps the router from asking Colibri about transactions it can't prove. [Options weighed](#options-weighed) lists the WASM-in-a-process alternative.

**Not covered:** a compromised main; same-user processes (0010); root, admin and the kernel; upstream soundness bugs. Upstream has open outside PRs whose titles describe verifier binding checks (#396, #399, #400, #402, #404, #405, opened 13–22 October, unmerged at `v3.0.3`).

### What a taken-over verifier keeps

The fetch contract is the whole of its reach. Within it, a process running injected code can still:
- **pick the entries:** ask for any entry its open operations admit, as often as the fetch budgets allow (64 open per process, 1,024 per request);
- **fill the free fields:** sync periods, slots, block roots, the prover GET's block, the prover POST's `c4` and `last_block_hash`, and the state reads' addresses and slots, each of the entry's form and length. Main can't tell an honest value from one chosen to carry data, so a few bytes per fetch can reach that type's hosts;
- **choose among the servers:** `exclude_mask` skips servers in the type's list, so it can aim a fetch at one of them, a configured loopback prover included (`network-registry.js:253–256` accepts https or loopback provers);
- **hold its operations open** until their deadlines, and its body reservations with them.

It can't send another verb, path shape, header or host, or anything while it has no open operation, or reuse one operation's binding for another.

## The process

### Spawn

- **One persistent process per chain:** `freedom-colibrid serve --chain <id> --data-dir <userData>/colibri/<id> --lock-dir <dir> --parent-pid <pid>`.
  - Main spawns it on the chain's first Colibri request, as today's host spawns a worker, and keeps it running until it has been idle for 10 minutes or the browser-wide limit needs its place ([How many](#how-many)).
  - It serves chain data and, for chain 1, ENS.
- **One one-shot process per checkpoint check:** `freedom-colibrid checkpoint --chain <id> --parent-pid <pid>`. It keeps its store in memory, takes no lock and has no directory, like 0007's ephemeral process. It serves one `colibri.checkpoint` and exits.
- **No `--network`:** the service has none, so `hello` reports `network: "offline"`.
- **As 0007 for the rest:** the binary from `<resources>/freedom-colibrid/` (`FREEDOM_COLIBRID_PATH` only when not packaged), the scrubbed environment, `colibri.hello` within 10 s, 0001's hardening, and the exit codes.
- **Lower priority:** main lowers the process's scheduling priority after the spawn (`os.setPriority`: 10 on Linux and macOS, below normal on Windows), so a long verification doesn't compete with the browser.
- **Nothing listens.** The service binds no port and serves no loopback HTTP; its only channel is main's pipe.

### How many

The registry takes user chains and prover coverage with no bound on their number, so one process per prover-backed chain needs a browser-wide bound. Main's limit of 8 Colibri operations (0004) bounds active work, not idle processes.
- **Persistent processes:** at most 3 live at once, browser-wide.
  - **Idle retirement:** a process with no open request for 10 minutes is sent `colibri.shutdown` and exits 0. That isn't a fault and starts no back-off.
  - **At the limit,** for a chain with no live process: main retires the least recently used idle process and spawns the new one once it has exited.
  - **If none is idle,** the request fails at once with `Colibri service busy`, built as `Colibri service unavailable` is. It is neither a fault nor a capacity failure, nothing counts it toward restarts or the backoff, and the read falls to its next source. The request holds its slot until that answer, as physical completion requires.
  - **A recycle** ([Crashes](#crashes-overruns-and-restarts)) counts toward the limit until the old process exits. Main spawns the successor at once if the limit has room, by retiring an idle process if it must; otherwise when the old one exits. Until then, that chain's new requests get `Colibri service busy`.
- **Checkpoint processes:** at most 2 at once (one per Myotis chain today). A third check fails at once with `CHECKPOINT_UNAVAILABLE`, main's class for a check that couldn't run.
- **Resident memory:** at most 3 × 256 + 2 × 128 = 1,024 MiB of budget browser-wide. Each process holds to its own budget as [Budgets](#budgets) says: it reads its memory after each step, and an OS-enforced hard limit is Q17.
- **Directories:** at most 6 chain directories under `<userData>/colibri/`, so 384 MiB of store at most.
  - Main sets each directory's modification time when it spawns that chain's process.
  - Before a spawn would make a seventh directory, main deletes the oldest directory whose process isn't live. It is a cache, and that chain bootstraps again.
- **Main's fetch pool** is browser-wide too ([Bodies](#bodies)).
- **The test** (COL-5) walks 7 chains with scripted provers, in sequence and in parallel. It checks:
  - never more than 3 live processes or 6 directories;
  - idle retirement exits 0, with no fault and no bystander;
  - with every live process busy, a new chain's request gets `Colibri service busy` at once;
  - the requests already open complete physically, and their slots are held until their replies.

### Confinement

0010's `confine`, after the lock and before `hello`, with:
- `network: Network::Offline`: on Linux seccomp refuses `socket` for every family (`seccomp.rs:177–186`); on macOS the Seatbelt profile grants no network; on Windows `network` is `unavailable` (`job.rs:75–79`);
- `read_write`: the chain's directory alone, nothing for the checkpoint process;
- `read_only`: nothing beyond the system's own (`/proc/self`, the cgroup files, the random devices);
- `resolver: Resolver::None`, `refer: false`, `min_abi: 1`, `interface_index: false`;
- `descriptors`: the lock and the directory.

Every part exists in `fc-service` today. fc-service's own confinement tests and a freedom-ipfsd test (`tests/store_confined.rs`) already confine with `Offline`. No Radicle process does yet: no one-shot import process exists, and freedom-radicled confines with its configured direct or SOCKS policy (`services/freedom-radicled/src/confine.rs`).

**Main's check before each spawn** (0010, step 7) covers the chain's directory, which lies in the profile's `userData`. Its protected roots don't change.

### Inside the process

- **Plain threads, no async runtime:** fc-service's connection threads, and one *verifier thread* that makes every call into the C core. The C core keeps process-wide caches, some without a lock (`src/util/json_validate.c:272`), so one thread per process makes those calls. That is today's concurrency too: one single-threaded WASM instance per chain.
- **A request** is a context in the C core. It runs one step at a time on the verifier thread, then waits for main's answers to its data requests while other requests step.
- **No clock in the C core:** the freshness bound (`now − 60 s`) comes from main in each request, as the JS binding computes it (`cjs/index.js:135`).
- **Fixed flags:** PAP (`privacy_mode: 'basic'`), verified-only, remote prover mode, the 60 s freshness window, as `colibri-worker.js` pins them. ZK is per client.
- **Panics:** the service's own Rust code forbids them (AGENTS rule 6). An abort in the C core ends the process like a crash.

### The store and the lifetime lock

- **One directory per chain,** `<userData>/colibri/<id>/`, the persistent process's only grant. Today's flat files in `<userData>/colibri/` are left alone; they are a cache, and each chain bootstraps once (deviation `storage-per-chain`). This also keeps the native build from reading the WASM build's files, whose BLS keys are stored in blst's in-memory form (`BLS_DESERIALIZE`, `sync_committee_state.c:632–646`).
- **Writes** are a temporary file, fsync and rename, with stale temporary files swept at start. Today's `createDiskStorage` writes a temporary file and renames it, and sweeps at start, but doesn't fsync (`colibri-worker.js:84–109`). The fsync is new.
- **Bounds:** a key is `[A-Za-z0-9_]{1,100}`; a value at most 1 MiB (a sync committee is 49,152 bytes); a directory at most 64 MiB. A write past a bound fails, and the C core sees a failed write.
- **The lock:** fc-service's gate, keyed by the chain's directory, so a replacement never writes while its predecessor still can. Today a draining worker and its replacement share the store.
- **What it holds:** public chain data alone, under two kinds of key, `states_<chain>` and `sync_<chain>_<period>` (`sync_committee_state.c`), and nothing a request names. So private windows share it, as they do today.
- **No other store:** the C core is built with its own file store off (`FILE_STORAGE`, which writes to the working directory), and the service gives it its store before `hello`.
- **0013's move:** `colibri/` isn't in 0013's list of entries that move into `<profile>/freedom/`. As a cache it can join the list, or be left and rebuilt ([Amendments](#amendments)).

## The build (Q20)

### What upstream has

- **A C core built with CMake** (C and C++17: evmone is C++).
  - **Licensed MIT except `src/server/`,** which is PolyForm Noncommercial 1.0.0 or commercial (`README.md:259–269`, `src/server/LICENSE.POLYFORM`). By that text `src/chains/eth/server/` is MIT, though 12 of its files carry PolyForm headers (F-8).
  - **`HTTP_SERVER=ON` alone builds** `src/server/` (`src/CMakeLists.txt:37`) and the chains' server handlers under `src/chains/*/server/`: `add_server_handler` returns without `HTTP_SERVER` (`src/chains/chains.cmake:350`).
  - Upstream relabelled two OP files that carried PolyForm by mistake after an outside report (issue #401, closed 19 October, PR #403).
- **Third-party code**, fetched by CMake's `FetchContent` at build time by tag: blst `v0.3.13` (Apache-2.0), evmone `v0.23.0` and intx `v0.15.0` (Apache-2.0), libtommath and mcl where enabled, zstd `v1.5.6` for OP chains (BSD or GPLv2); and `libs/crypto` in the tree (MIT).
- **A C API usable without WASM** (`src/api/colibri.h`): `c4_create_rpc_ctx`, `c4_rpc_execute_json_status`, `c4_req_set_response`, `c4_req_set_error`, `c4_free_rpc_ctx`, the verify and decode calls, `c4_get_method_support`, `c4_set_storage_config` and `c4_get_current_version_number`. It is sans-I/O: a step returns the data it needs as JSON.
- **A Rust crate,** `bindings/rust` (0.1.0), with two layers:
  - safe context types (`RpcCtx`, `Verifier`) over the C API, and `unsafe fn` answers (`req_set_response`, `req_set_error`), unsafe because they take the C core's request pointer as an integer;
  - a high-level `Colibri` client that fetches with reqwest on tokio. tokio, reqwest, futures and async-trait are unconditional dependencies (`Cargo.toml:41–45`); only the OP module is a feature (`op`, default on).
- **Its build script** (`build.rs`) links archives from `COLIBRI_LIB_DIR`; or, inside an upstream checkout, runs CMake with `CURL`, `CLI` and `HTTP_SERVER` off (`:212–216`), writing the CMake tree into the checkout (`build-rust/<target>`, `:187`); or else downloads a prebuilt archive from GitHub releases with `curl`, unverified (`:333–393`).
- **The version number** provers route proofs by comes from `git describe` at configure time (`CMakeLists.txt:27`), or from `C4_VERSION`. A Cargo git checkout need not carry the tags, and a vendored copy has no `.git` at all, so a build that doesn't set `C4_VERSION` can report the wrong version, and a prover then sends a proof format the verifier can't read.

### Option A: public upstream PRs

Three small PRs upstream, each useful to other users of the crate:
1. **An `http` feature, on by default,** around the high-level client and its error variant, so `default-features = false` drops tokio, reqwest, futures and async-trait;
2. **An offline, reproducible build:** no download unless asked for, the CMake tree under `OUT_DIR` (or a set directory), `C4_VERSION` from the crate's own version, and `FetchContent` pinned by commit with a hash, or overridable from local sources;
3. **A safe answer API:** pending requests as values tied to their context's lifetime, so a caller can answer one without `unsafe`.

Filing two public issues, F-1 (`VerifiedOnly` answering unproofable methods without a proof) and F-6 (the unknown-hash trap), is a separate question, and either option can file them ([Open questions](#open-questions)).

Until they are released, `freedom-colibrid` depends on a fork under `solardev-xyz` at a pinned commit, as `freedom-radicled` depends on libradicle.
- **Cost:** upstream review time, and a fork to keep until then. Upstream fixed an outside license report and the feature it asked for within a day (issue #401, opened 18 October; PR #403, merged 19 October), and has open outside PRs.
- **Our code:** with PR 3, no `unsafe` in this repository. Without it, one small module with `#[allow(unsafe_code)]` for the two answer calls, which AGENTS rule 6 must name, like `freedom-radicled`'s one call.
- **CI:** CMake and a C++17 compiler on the three OSes' runners, the fork's sources fetched by Cargo, and `FetchContent`'s sources pinned.

### Option B: a vendored copy

The C core at `v3.0.3` and its third-party sources copied into `services/freedom-colibrid/vendor/`, with their licenses, built by our `build.rs` through the `cmake` crate, with our own bindings to the dozen C functions the service calls.
- **Cost:**
  - our own FFI module with `unsafe` (an AGENTS rule 6 exception, each call with a `SAFETY` comment, as `fc-sys`);
  - every upstream release copied and re-checked by hand, CMake's generated chain headers included (`src/chains/chains.cmake:50`, `:116`);
  - about 47k lines of C and headers in `src/` outside the server, the CLI and the ZK prover (93 source files) plus `libs/crypto`, blst, evmone and intx in our tree.
- **Gain:** nothing upstream needs to agree to; full control of flags and pins.

### Licenses

Both options build with `HTTP_SERVER` off, so nothing under `src/server/` is compiled. COL-2's license gate checks that against the build's **compiled-source manifest**: every source CMake compiles, from its compile commands, and every header the compiler's dependency files list. The build fails if:
- **anything under `src/server/` is compiled,** whatever its header says;
- **anything under `src/chains/eth/server/` is compiled.** It is MIT by the README, but its headers are mixed (F-8), and the verifier needs none of it;
- **the notice audit fails:** a compiled source or listed header carries an SPDX identifier or license text that isn't one the notices file lists (MIT, Apache-2.0, and the third parties' own). A header naming PolyForm anywhere fails it.

`src/util/version.c`, which is MIT, prints `License: PolyForm Noncommercial 1.0.0` from `c4_print_version`, which only the server and the CLIs call. The service never calls it.

The notices file gains blst, evmone and intx (Apache-2.0), `libs/crypto` (MIT) and Colibri (MIT). `CHAIN_OP` is off: Freedom verifies no OP chain, and zstd stays out.

### Proposed

**Option A**, if Q20's answer is public upstream PRs; Option B if it is a vendored copy. Either way, `freedom-colibrid` is its own Cargo workspace (`services/freedom-colibrid`), as `freedom-ipfsd` is: its own lockfile, `cargo deny` policy and notices, sharing `fc-protocol` and `fc-service` by path. Its release follows freedom-ipfsd's in `RELEASING.md`.

## The protocol

On fc-service's connection, at the version services speak, with fc-protocol's two-way streams (0009) turned on for this service only. 0009's rule that a service connection keeps one role changes for it ([Amendments](#amendments)).

### Methods main calls

| Method | Params | Result |
|---|---|---|
| `colibri.hello` | fc-service's | fc-service's, plus `colibri_version` (`3.0.3`), `client_version` (196611), `chain_id`, `build` (`op`, `zk`, flags) and `confinement` |
| `colibri.request` | `{ client, zk, method, params, min_latest_block_ts, deadline_ms }` | `{ status: "success", result? }`, `{ status: "revert", data }` or `{ status: "error", error }` |
| `colibri.forget` | `{ client }` | `{}` |
| `colibri.checkpoint` | `{ min_latest_block_ts, deadline_ms }` (one-shot process only) | `{ decoded, result }` or `{ status: "error", stage, error }` |
| `colibri.stats` | `{}` | open requests, steps run, resident memory, store size |
| `colibri.shutdown` | fc-service's | |

- **`client`** is main's id for one client (a chain, a prover and its ZK setting). The service keeps per client only F-4's sticky ZK-off flag. The prover's URL stays in main.
- **`params`** is the caller's JSON text, as 0005 passes it.
- **`result`** is the C core's result text, embedded raw, as 0005's replies do. It is absent when the status has none, which main reads as `undefined`.
- **`error`** is the C core's error text, at most 2,000 UTF-16 units, as `serializeError` cuts it today.
- **Refusals:** `busy` (budgets, or a step marker that couldn't be written: [The step marker](#the-step-marker)), `too_large`, `cancelled`, `invalid_argument`.
- **Unproven reads are refused** before any context exists, with the C core's own text, `Method <m> is not supported` (deviation `colibri-unproofable`, F-1). That covers a method `c4_get_method_support` doesn't class as proofable, and a block parameter that is `pending`, `earliest` or not a string, the rule #1048 and #279 put into the routers. The router doesn't send these once those land; the refusal guards any other caller.
- **`colibri.checkpoint`** fetches the proof through main ([Requests the service makes](#requests-the-service-makes)), decodes it, verifies it on the memory store, and returns the decoded proof's JSON with the result. `stage` says where it failed (`decode` or `verify`), so main keeps its own classes: `CHECKPOINT_UNAVAILABLE` for a proof that doesn't decode; for one that doesn't verify, a transport error it saw, `CHECKPOINT_STALE` for `proof for latest too old`, `CHECKPOINT_MISMATCH` otherwise (`checkpoint-verifier-worker.js:353–368`). Main's evidence checks on the decoded proof stay in main.

### Requests the service makes

| Method | Params | Main does | Reply |
|---|---|---|---|
| `shell.colibri_fetch` | `{ request, type, method, path, payload?, accept, exclude_mask, max_age? }` | one data request, checked against [the fetch contract](#the-fetch-contract) | a head `{ node, bytes }` and the body as a stream, or `{ error }` |

- **`request`** names main's open `colibri.request` or `colibri.checkpoint` on this process. Main refuses a fetch for anything else, and a fetch whose shape that operation doesn't allow.
- **`type`:** `prover`, `beacon_api`, `checkpointz` or `eth_rpc`; on a checkpoint process, `checkpointz`, `beacon_api` or `checkpoint_proof`.
- **`method`** is the C core's verb, `get` or `post`. Main sends the verb the contract's entry has; anything else is refused.
- **`delay`** stays in the service: it waits before sending the fetch, as `handle_request` waits.
- **The head's `bytes`** is the body's exact length: main has read it whole before the head goes ([Bodies](#bodies)).
- **The body** comes as 0009's stream, from main to the service, with a 128 KiB window. The service reserves exactly `bytes` from its own bodies budget before granting credit. A head it can't reserve is answered with `busy`, which the C core sees as a failed fetch (`Colibri fetch busy`).
- **A body that doesn't match its head**, more bytes than `bytes` or fewer at its `end`, fails that fetch with `Colibri body length mismatch`. The connection, its other streams and its control frames go on.
- **`error`** is the text the C core gets (`c4_req_set_error`).

### The step marker

**The marker:**
- **Before each call into the C core for one request** (a step, an answer, a decode or verify, a free), the verifier thread queues the event `colibri.step { request }`. It waits until the writer has put it in the pipe, at most 1 s. Main reads a written marker even if the process dies right after.
- **No marker, no call.** If the marker isn't written within the 1 s, the verifier thread doesn't enter the C core. The request ends with the refusal `busy`, sent once the writer can, and main builds it as `Colibri service busy`. Its context is freed later, under its own marker, or at exit.
- **The step ends** with `colibri.stepped { request }`, queued as the call returns and before any frame the step caused (its fetches, its reply). Every step has this clearing event, even one that asks for nothing new.

**What main concludes:**
- **A death inside a step**, after a `colibri.step` and before its `colibri.stepped`, names that request as the culprit. Main reads the pipe to its end first. Every other open request is a bystander.
- **A kill** 1 s past a request's deadline names that step's request, the same way.
- **A death outside any step** names nobody. That covers a crash between calls, in the service's own code, after a step's clearing event, or in a process-wide call.
  - Every open request is a bystander, sent once more to the next process.
  - No outcome carries `fault`.
  - The death counts toward "three exits within 60 s that name no culprit", which stops restarts for that chain, and toward the directory clear after three in a row ([Crashes](#crashes-overruns-and-restarts)).
- **Forged or out-of-order markers** are protocol errors. Main kills the process and names nobody. That covers:
  - a `colibri.step` that names no open request of this process, or comes while another step is open;
  - a `colibri.stepped` that doesn't name the open step's request.

**What the attribution is, and isn't:**
- **Step-local:** it names the request whose call was running when the process died, not the request whose input did the damage. Today's WASM trap is step-local in the same way.
- **Best-effort:** native memory corruption need not crash where it happens. It can return from its step, clear the marker, and crash later in another request's call (that request is named) or between calls (nobody is named), or never crash at all. A taken-over process can also forge, withhold or clear its markers ([Threat model](#threat-model)).

**How the evidence differs from today's:**
- **Today:** a trap is raised synchronously by main's own engine, inside the very call that made the bad access, as a `RuntimeError` or the trap texts. The instance can't fake one in another request's call or hide one. Every access past linear memory traps there. A stuck worker's culprit is guessed from methods.
- **With the service:** the evidence is the process's own markers plus its death.
  - Some of today's traps become deaths outside any step, which name nobody.
  - Some become faults named on a later request, and some become silent misreads.
  - A spin is now named exactly.
- **What 0005 and #752 receive** keeps its form: `fault: true` on the culprit's outcome, through `Colibri worker replaced: <reason>`, which `isColibriFault` matches. Bystanders carry `colibriBystander`, and deaths outside a step put `fault` on no outcome.
- **What changes is the set of outcomes** that carry `fault`, which is this best-effort set. The core's algorithm, thresholds and capability are unchanged. The worst a wrong attribution does is start #752's cooldown for one method on one chain, which sends that method to its next source. The no-culprit stop bounds a process that keeps dying without naming anyone.

### Cancel and deadlines

- **A cancel** of a request that waits on fetches cancels them, frees its context and replies `cancelled`. A request inside a step is cancelled when the step returns.
- **A request past its deadline** that waits on fetches is cancelled by main. Today it waits up to 60 s more (deviation `colibri-deadline`).
- **A step still running 1 s past its request's deadline:** main kills the process. That request is the culprit. 1 s is today's `STUCK_PROBE_MS`.
- **A request with no caller deadline** (ENS through ethers) gets today's 60 s (`DEFAULT_DEADLINE_MS`).
- **Physical completion** (0005): main's promise settles on the service's reply or the process's death, never earlier, so the core's slots are held as today.

### What main builds from an answer

Main rebuilds what the package's client returns or throws today, so everything downstream is unchanged:
- **success:** the result, or `undefined`;
- **revert:** `ProviderRpcError(3, 'execution reverted', data)`, as `throwRevert`;
- **error:** `ProviderRpcError.createError` of the text (`cjs/types.js:38–58`), whose message is `Error in rpc call <method><JSON.stringify(params)> : <text>`. The code comes from three rules, applied in order:
  - **4200** when the text starts with `Method ` and ends with ` is not supported` (`:47`);
  - **4900** when the text contains one of three case-sensitive substrings (`:50`): `HTTP error!`, `All nodes failed` or `Failed to fetch`. Nothing else counts as transport: `Request to <url> failed: fetch failed`, Node's own failure text, contains none of them;
  - **otherwise -32603.** The error's own numeric code would win, but a text from the service has none.
  - **Tested:** COL-5's contract suite checks the adapter against each rule byte for byte, near misses included (`failed to fetch`, `fetch failed`);
- **the culprit of a death:** `ColibriWorkerError('Colibri worker replaced: <reason>')`, the text `isColibriFault` matches;
- **a bystander:** sent once more to the next process with what is left of its deadline; if it fails again, its error carries `colibriBystander`, as today;
- **no process** (a restart's back-off, or restarts stopped): `Colibri service unavailable`, which matches neither the fault pattern nor the retry pattern;
- **the browser-wide limit, or a marker that couldn't be written:** `Colibri service busy`, built the same way.

### What the core sees

Nothing new. `chain-verified.js` and `naming-verified.js` keep their code; `colibri-resolver.js` keeps its clients, its retry and its ethers provider, and requires `colibri-service.js` where it required `colibri-worker-host.js`; the new module exports the same `createClient` and `ensureWorker`. The core's `colibri_faults` capability, its backoff (`fc-chain/src/machine/faults.rs`), the capacity bit and #752's ordering apply unchanged. The `fault` bit keeps its form, but the evidence behind it is the step marker's, not a synchronous trap ([How the evidence differs](#the-step-marker)).

## Every WASM call, mapped

| Today | With the service |
|---|---|
| `new Colibri({ chainId, prover, zk_proof, … })` in the worker | a `client` id in `colibri.request`; the flags fixed in the service; the prover in main |
| `Colibri.register_storage(disk)` → `registerStorage` | the service's store on its directory, given to `c4_set_storage_config` before `hello` |
| `client.request` → `OnlyProofStrategy` → `rpc()` | `colibri.request` |
| ↳ `attemptInitialConnection` → `rpc('eth_chainId', [], LOCAL)`, once per client | not reproduced: no data request, nothing the caller sees (deviation `no-initial-chain-id`) |
| ↳ `getMethodType` (`_c4w_get_method_type`) | `c4_get_method_support`, which now also refuses (F-1) |
| ↳ `createRpcCtx`, `rpcCtxSetMinLatestBlockTs` | `c4_create_rpc_ctx`, `c4_rpc_set_min_latest_block_ts` |
| ↳ `executeRpcCtx` (`_c4w_execute_rpc_ctx`) | a step, after `colibri.step` |
| ↳ `handle_request` → `fetch_from_servers` → Node `fetch` | `shell.colibri_fetch`; main's session fetch |
| ↳ `reqSetResponse`, `reqSetError` | `c4_req_set_response`, `c4_req_set_error`, from main's reply |
| ↳ `freeRpcCtx` | `c4_free_rpc_ctx` at the end, a cancel, or shutdown |
| ↳ the ZK fallback (`index.js:261`) | the same, per client |
| ↳ `createError`, `throwRevert` | main, from the status |
| `client.destroy()` (`destroy` message) | `colibri.forget` |
| `ping` / `pong` | gone: the step marker (`colibri.step`, `colibri.stepped`) |
| `setRuntimeResetListener`, `trap`, the runtime's retirement | gone: a fault ends the process |
| checkpoint: `register_storage(Map)` | the one-shot process's memory store |
| checkpoint: the prover fetch, `decode_proof` (`_c4w_decode_proof`) | `colibri.checkpoint`: a `checkpoint_proof` fetch, then decode |
| checkpoint: `verifyProof` (`_c4w_create_verify_ctx`, `_c4w_verify_proof`, `_c4w_free_verify_ctx`) and its intercepted `fetch` | inside `colibri.checkpoint`; main answers its `checkpointz` fetches from the quorum |
| `clientVersion` from `package.json` (196611) | `c4_get_current_version_number()`, in `hello`; main refuses another than its pin's |
| unused: the prover context, `_c4w_set_checkpoint`, `_c4w_reset_caches`, the proxy URLs, witness keys | not exposed |

## Main's fetches

For `shell.colibri_fetch`, main does what `fetch_from_servers` does, through the session, but only for the request shapes the open operation allows.

### The fetch contract

Today the worker fetches whatever request the WASM instance returns. `fetch_from_servers` upper-cases the verb (`cjs/http.js:29`), joins any path to the type's servers (`:5–14`), sends any payload and follows redirects anywhere. Main replaces that with a closed table of **entries**. It checks each fetch against the entries the fetch's operation allows, and refuses anything else.

**The entries,** from what the 3.0.3 verifier asks for:

| Entry | Type | Verb | Path | Payload | `accept`, `max_age` | Body at most |
|---|---|---|---|---|---|---|
| `proof` | `prover` | POST | empty | an object with `method`, `params`, `version` (the pin's 196611), and optionally `c4` (the client state, hex), `zk_proof` (`true`, a ZK client only), `include_code`, `logs_completeness` (`true`) and `last_block_hash` (32-byte hex), and nothing else (`pap_req.c:35–38`, `state.c:72–96`) | `ssz`, none | 16 MiB |
| `proof_get` | `prover` | GET | `proof/<m>/<block>/196611/<std\|zk>/0x<hex>`: `<m>` `eth_getBlockHeader`, `eth_getBlockByNumber` or `eth_getBlockReceipts`; `<block>` a block tag or `0x` hex; the hex the client state; no query (`prover_cache_url.c:35`, `:98–101`) | none | `ssz`, 1 to 86,400 | 16 MiB |
| `tx_cache` | `prover` | GET | `tx_cache?max_blocks=<n>` or `tx_cache?from_block=<n>&max_blocks=<n>` (`verify_pap_tx.c:63–70`) | none | `ssz`, 1 to 86,400 | 16 MiB |
| `lc_updates` | `beacon_api` | GET | `eth/v1/beacon/light_client/updates?start_period=<n>&count=<n>` (`sync_committee_state.c:201`) | none | `ssz`, none | 16 MiB |
| `lc_bootstrap` | `beacon_api` | GET | `eth/v1/beacon/light_client/bootstrap/0x<64 hex>` (`:301`) | none | `ssz`, none | 1 MiB |
| `finality` | `checkpointz` | GET | `eth/v1/beacon/states/head/finality_checkpoints` (`:235`) | none | `json`, none | 64 KiB |
| `block_root` | `checkpointz` | GET | `eth/v1/beacon/blocks/<n>/root` (`:709`) | none | `json`, none | 64 KiB |
| `state_read` | `eth_rpc` | POST | empty | JSON-RPC 2.0, `id` 1: `eth_getCode` `[address, "latest"]` (`eth_account.c:141`), `eth_getProof` `[address, [slot], "latest"]` or `eth_getStorageAt` `[address, slot, "latest"]` (`call_ctx.c:142–144`) | `json`, none | 1 MiB |
| `checkpoint_proof` | `checkpoint_proof` | main's own | none from the service: main fetches the checkpoint proof from the prover, as `checkpoint-verifier-worker.js` does today | none | main's | 4 MiB |
| `checkpoint_root` | `checkpointz` (checkpoint process) | GET | the one path today's interception admits, answered from main's quorum (origin, `GET`, the path, at most 8) | none | `json`, none | 64 KiB |

- **`<n>`** is a decimal integer within 32 bits (64 for blocks and slots), with no sign and no leading zero.
- **Hex** has its fixed length where it has one. `c4`, and the client state in `proof_get`, are the client state: at most 41 bytes (`sync_committee.h:39`).
- **The table is pinned by COL-1:** the generator checks that every request the reference makes, in every case, matches an entry the case's operation allows, and fails otherwise. It also records each entry's largest body. The body numbers above are provisional, and COL-2's rule for budgets applies to them.
- **Not admitted:**
  - `rpc_handle_unproofable`'s pass-through of the caller's own call (`colibri_common.c:522–579`): the service refuses those reads first (F-1);
  - the PAP send path (`verify_pap_tx.c:325`): the router sends no write to Colibri;
  - the oblivious-node and proxy fields: not exposed.

**What each operation allows** (main derives it from the open operation, never from the service):
- **`colibri.request { method, params }`:**
  - the entries COL-1 records for that method, and no others;
  - in `proof`, a `method` and `params` equal to the operation's own (compared as parsed JSON), or one of the sub-proofs COL-1 records for that method (`eth_getBlockHeader`, `eth_getBlockReceipts`, the transaction lookup's block proof: `call_ctx.c:589`, `verify_pap_tx.c:210–313`), with params of that sub-proof's form;
  - in `proof_get`, `zk` only on a ZK client;
  - the `beacon_api` and `checkpointz` entries for any method, since they concern the chain's sync state, not the request.
- **`colibri.checkpoint`:** `checkpoint_proof` once, then `checkpoint_root`.
- **The binding is per request:**
  - a fetch names one open request of its own process;
  - a request that has ended (replied, cancelled, past its deadline) admits nothing;
  - one request's binding never admits another's method or params.

**What main builds** (the service sends none of it):
- **The URL:** `joinPath(server, path)`, with a path that matched an entry: relative, with no scheme, no leading `/`, no `//`, no `.` or `..` segment, no `%`, no `\`, no control character and no query beyond the entry's own, in its order.
- **The verb:** the entry's.
- **The headers:** `Accept` from the entry, `Content-Type: application/json` with a payload, and `Cache-Control: max-age=<max_age>` only on an entry that takes one. The session adds its own, as for `shell.rpc`.
- **The payload:** `JSON.stringify` of its parse, at most 64 KiB.

**The servers** come from main's table by type, never from the service:
- **`prover`:** the registry's first prover for the chain, https or loopback (`network-registry.js:253–256`);
- **`beacon_api`, `checkpointz`, `eth_rpc`:** as the [default-host question](#open-questions), decided before COL-1, says. Under its proposed answer that is the package's lists for the chain, which main holds as a table that a vector pins (F-2), in `handle_request`'s order (`cjs/http.js:151–168`).
- **For a checkpoint process,** `beacon_api` has no server, as today.
- **`exclude_mask`** only skips servers. Its bits must be within the list's length.

**Redirects:**
- **A GET** follows at most 3 redirects (301, 302, 303, 307, 308). Each `Location` must resolve to the same server's origin and to a path the same entry admits, and each hop passes the endpoint policy and the onion gate.
- **A POST follows none.**
- **Any other 3xx** is that server's failure, `HTTP error! Status: <n>, Details: redirect refused`, and the next server is tried. Today Node follows up to 20 redirects to any host (deviation `fetch-contract`).

**A refused fetch** is answered `{ error: "Colibri fetch refused" }`, which the C core sees as a failed fetch. Main logs it at `warn` with the chain, the type and the rule it broke, never the path or the payload.
- Main doesn't kill the process for it. The contract already bounds what the process can reach, and a taken-over process can stay inside it, so a kill would add nothing.
- **The refusal tests** (COL-5, with a scripted service), each refused and none sent:
  - absolute paths (`https://…`, `http://…`) and scheme-relative ones (`//host/…`);
  - a leading `/`, dot segments, `%2f`, `%2e`, a backslash, a control character, and an unknown query key or order;
  - cross-type requests, such as a beacon path as `prover` or a `proof` payload as `eth_rpc`;
  - verbs other than the entry's: `put`, `delete`, `GET`, `get ` and an empty one;
  - a payload with an extra key, a wrong `version`, `zk_proof` on a non-ZK client, or an over-long `c4`;
  - out-of-contract redirects: to another origin, to another entry's path, a fourth hop, any redirect of a POST, and an https-to-http downgrade;
  - cross-operation reuse: request A's id with request B's method or params, an ended request's id, another process's request id, and a fetch when no operation is open;
  - an `exclude_mask` bit past the list.

### Bodies

**Main reserves before reading.** Before main sends a request to a server, it reserves the entry's maximum from **main's Colibri fetch pool**.
- The pool is 128 MiB, browser-wide, and held by `colibri-service.js` for every `freedom-colibrid` process, persistent or checkpoint. 128 MiB is 8 bodies of 16 MiB, one per Colibri operation main runs at once (0004). COL-1's recordings show how many bodies a round holds at once, and COL-2's budget rule then applies to the pool too.
- It is separate from 0005's chain I/O pool (192 MiB, `service-client.js:90`), which bounds what main holds for the core's connection. Colibri's fetches can't starve the core's replies, or the reverse.
- **No room:** the fetch isn't sent. The service gets `{ error: "Colibri fetch pool full" }`, which the C core sees as a failed fetch. The request ends in an error, neither a fault nor capacity, and the read falls to its next source.
- **Control frames don't use the pool:** credit, cancels, small replies and `colibri.step` go on while it is full, as 0005's pool rules have it.

**Main reads the body whole before the head goes,** as `fetch_from_servers` does (`blob()`, `cjs/http.js:57`), and as failing over to the next server needs. It counts the decoded bytes:
- **`Content-Length` is a hint only.** A declared length over the entry's maximum fails that server before the body is read. A missing one changes nothing.
- **Compressed bodies:** Chromium's network stack decodes them. The count and the maximum are of decoded bytes, so a small body that inflates past the maximum stops there.
- **Chunked bodies** are counted like a body with no length.
- **Past the maximum,** the read is aborted and that server fails with `Request to <url> failed: response over <n> bytes`. The next server is tried under the same reservation.
- **A body that ends before its declared length** fails in the network stack, so that server fails and the next is tried.
- **An endless body** stops at the maximum. **A slow body** ends at the request's deadline, when main cancels the request (deviation `colibri-deadline`).
- **A cancel** aborts the read and releases the reservation at once. If the body is already on its way to the service, main ends the stream with `cancelled`.

**Then the head** `{ node, bytes }`, with the exact decoded length, and the body on 0009's stream.
- Main's reservation shrinks to `bytes` at the head. It is released as the service's credit takes the bytes, or when the stream ends or is cancelled.
- The service reserves exactly `bytes` before it grants credit ([Requests the service makes](#requests-the-service-makes)).

**The tests,** each also checking that the reservation is released and that credit, cancels and other requests' frames go on:
- **COL-5, main against scripted servers:** a missing `Content-Length`; a declared one too large, and one that lies low; a gzip and a brotli body that inflate past the maximum; a chunked body; an endless body; a body that trickles until the deadline; a cancel mid-body and one mid-stream; the pool exhausted by parallel fetches while control frames still flow; a body whose length differs from its declared one.
- **COL-4, the service against a scripted main:** a stream longer than its head's `bytes` and one shorter at `end` (`Colibri body length mismatch`); a head it can't reserve (`busy`).

### The rest

- **The order:** servers in turn, skipping those `exclude_mask` names; the first success wins, and its index is `node`.
- **Through the session:** the proxy and Tor apply, with the endpoint policy and the onion gate on every hop, as for `shell.rpc` (0005). The request's deadline bounds every attempt.
- **Error texts** are written as `fetch_from_servers` writes them (`HTTP error! Status: <n>, Details: <body>`, `Request to <url> failed: <reason>`, `All nodes failed`).
  - URLs are replaced by `<url>`, as `colibri-resolver.js` already does for its logs, and texts are cut to 2,000 units (deviation `fetch-error-text`).
  - A transport failure's reason is Node's `fetch failed`, whatever the session's stack said, so `createError` and `retryableColibriError` see today's text.

## Budgets

The numbers below hold until COL-2 measures the native build. It replaces each with twice the peak it sees over the vectors and the ENS e2e suite, or keeps it, whichever is larger.

| What | Persistent process | Checkpoint process |
|---|---|---|
| open requests | 16 (main sends at most 8: 0004's bound per verifier) | 1 |
| fetches open | 64 per process; 1,024 per request in all | the same |
| a fetched body | the entry's maximum ([The fetch contract](#the-fetch-contract)), 16 MiB at most | 4 MiB (the proof), 64 KiB otherwise |
| bodies in flight | 32 MiB: the head's exact `bytes` reserved before credit | 8 MiB, the same way |
| store | 1 MiB a value, 64 MiB a directory | memory, counted in resident memory |
| resident memory | 256 MiB, then a [recycle](#crashes-overruns-and-restarts) | 128 MiB, then the check fails |
| time | a step 1 s past its request's deadline | 90 s in all (today's) |

**Browser-wide** ([How many](#how-many), [Bodies](#bodies)):

| What | Bound | At the bound |
|---|---|---|
| persistent processes | 3 live; idle ones retired after 10 minutes | the least recently used idle one is retired; none idle: `Colibri service busy` |
| checkpoint processes | 2 at once | `CHECKPOINT_UNAVAILABLE` |
| resident memory | 3 × 256 + 2 × 128 = 1,024 MiB of budgets | each process's own rule |
| chain directories | 6, so 384 MiB of store | the oldest one without a live process is deleted |
| main's Colibri fetch pool | 128 MiB, each fetch reserving its entry's maximum before it is sent | `Colibri fetch pool full`, a failed fetch |

- **Resident memory** is read by the service after each step (`/proc/self/statm`, `task_info` on macOS). It can't bound the C core's allocations as they happen. A hard limit by the OS is user question Q17, shared with 0007.
- **A reply over 0001's message cap** is `too_large`, as 0005 says.

## Crashes, overruns and restarts

- **A crash** is an exit main didn't ask for, other than 64, 74, 75 and 77, as in 0007. Main reads the pipe to its end. If the death was inside a step, main fails that step's request with the fault text; every other open request is a bystander, resent once ([The step marker](#the-step-marker)).
- **Restarts are lazy:** the next request spawns a process, after 0.5 s, 2 s, then 10 s following abnormal exits (0007's back-off), reset after 60 s without one. Requests during the back-off get `Colibri service unavailable` and fall through to the next source.
- **Crashes a request caused don't stop restarts.** The core's backoff already throttles each method on each chain: two faults within 60 s start a cooldown of 60 s, then 5 min, then 15 min.
- **Three exits within 60 s that name no culprit** stop restarts for that chain until a configuration change or the next launch. A death outside any step and a kill for a protocol error (a forged marker included) name no culprit.
- **Three abnormal exits in a row with no answer between them** clear the chain's directory before the next spawn: it is a cache, and a damaged entry would crash every process that loads it.
- **A recycle:** above its memory budget a process refuses new requests (`busy`, which main sends to the successor), finishes its open ones, and exits 0. Main spawns the successor at once when the browser-wide limit has room ([How many](#how-many)). A recycle is no fault.
- **Logs:** main logs each crash, kill, recycle, retirement, refused fetch and stop at `warn` with the chain and the reason, never a request's params.

## Vectors

`vectors/colibri.json`, from `vectors/generator/colibri.js`, as the other generators: the reference checkout at a pinned commit, its installed packages, nothing reimplemented (AGENTS rule 5).
- **A recording runtime.** `colibri-runtime.js` already installs its own runtime provider. The generator wraps it and records every call with its arguments and return: method support, context creation, every step's status text verbatim, every answer and error, frees, decodes, and the store's gets, sets and deletes (keys, sizes and SHA-256 of values).
- **Scripted worlds:** `globalThis.fetch` stubbed, answering from recorded server responses in `vectors/fixtures/colibri/`, captured once from the live provers as the browser's `capture.cjs` captures checkpoints, with each request recorded (URL, method, headers, body, and any redirect a live server gave). The client is configured with the servers main's table gives each type, under the [default-host](#open-questions) answer, so that answer comes before COL-1. The clock is fixed, so the freshness bound is too. Stores start empty or seeded.
- **Cases,** for chains 1 and 100:
  - every method the router sends Colibri: account and storage reads, code, blocks with and without transactions, mined transactions and receipts, `eth_blockNumber`, `eth_maxPriorityFeePerGas`, `eth_estimateGas`, `eth_call`;
  - ENS through `resolveCallViaColibri` and `resolveReverseViaColibri`: contenthash, address, reverse, a proven `ResolverNotFound`, an `OffchainLookup` revert and its CCIP callback;
  - failures: a flipped byte in each proof, a stale proof, a server failing before another answers (`exclude_mask`, `node`), every server failing, an HTTP error with a body, the ZK fallback;
  - store: a cold start's bootstrap and a warm start;
  - the checkpoint: both captures in `docs/audits/evidence/colibri-v3-2026-09/captures`, a flipped proof, a v2 proof;
  - F-1: `eth_gasPrice`, `eth_feeHistory`, reads at `pending` and at `earliest`, and a read with an EIP-1898 block object (which 3.0.3 reads as `latest`: #279), each marked `deviation: colibri-unproofable`. These pin the adapter itself: the router stops sending them with #1048 and #279, whose own vectors cover the routing;
  - #750: an unknown-hash receipt, which traps in WASM. The service must end it in an error or a crash, never a result.
- **The fetch contract:** the generator checks every recorded request against main's table ([The fetch contract](#the-fetch-contract)) for its case's operation, and fails on one that matches no allowed entry. It records each entry's largest body.
- **What the native build must match:** each step's status text byte for byte (the request pointer replaced by its index), the data requests in their rounds, the store's writes, and the version number. Through main's client: each adapter outcome (result, or error with name, code, message and data).
- **Where the deviations show:** cases marked with their deviation id record the reference's outcome and the design's.

## Deviations

| Id | Today | With the service |
|---|---|---|
| `colibri-unproofable` | the adapter answers unproofable methods and `pending`/`earliest` reads from a public RPC without proof, and a non-string block as `latest`; the router labels them verified (F-1; the router stops asking with #1048 and #279) | refused before any context: `Method <m> is not supported` |
| `colibri-deadline` | a request waiting on the network keeps its slot up to 60 s past its deadline, then fails as a fault and takes its worker's other requests with it | cancelled at its deadline; not a fault; nothing else ends |
| `colibri-culprit` | a trap names its call's request; a stuck worker's culprit is guessed from methods, and several suspects of mixed methods name nobody | the step marker names the request whose call was running, best-effort; a death outside any step names nobody |
| `colibri-session-fetch` | Node's fetch: no proxy, Tor, endpoint policy, timeout or body cap | main's session fetch with them; each body within its entry's maximum, reserved from main's Colibri fetch pool before it is sent, and `Colibri fetch pool full` when the pool can't |
| `fetch-contract` | any request the instance returns is fetched: any verb, path and payload on the type's hosts, redirects followed anywhere | only the entries the open operation allows; GET redirects within the server's origin and the entry, at most 3; POST none; anything else `Colibri fetch refused` |
| `colibri-processes` | a worker per chain, with no bound on their number | at most 3 persistent and 2 checkpoint processes, idle ones retired, `Colibri service busy` at the limit |
| `fetch-error-text` | a fetch error names the URL and payload, and carries the whole error body | URLs as `<url>`, at most 2,000 units |
| `no-initial-chain-id` | a local `eth_chainId` context on each client's first request | none |
| `storage-per-chain` | one flat directory for every chain; unchecked keys; no size bound | a directory per chain, checked keys, bounds; at most 6 directories |

## Migration (Q19)

**Before the steps:**
- **F-1's fix** is in review on its own, outside the COL steps: freedom-browser #1048 and #1049 (#1046), and freedom-core #279 (#276).
- **The default-host question** ([Open questions](#open-questions)) is decided before COL-1 starts. Its answer fixes main's server table, the fetch contract's servers, COL-1's fixtures and recorded requests, the privacy rows of the threat model, and COL-5's contract and proxy tests. Deciding it later would redo all of them.

| Step | Where | What | Done when |
|---|---|---|---|
| COL-1 | core `main` | `vectors/colibri.json`, its generator and fixtures | the default-host question is decided first; `generate.js check` passes; damaged copies fail it (`check.test.js`); every case above is present; every recorded request matches an entry its operation allows |
| COL-2 | core `main` | the native build in `services/freedom-colibrid` (a library and a test harness, no service yet), by the Q20 answer; the measured budgets as an amendment here | CI on Linux, macOS and Windows runs every COL-1 trace through the native C core and matches it; the version number is 196611; the license gate passes on the compiled-source manifest (nothing under `src/server/` or `src/chains/eth/server/`, and the notice audit: [Licenses](#licenses)); an ASan and UBSan job runs every trace, #750's included, clean; any difference or sanitizer finding stops the step and is reported |
| COL-3 | core `main` | `fc-service`: requests from a service to main, two-way streams for a service that turns them on, and an event the sender waits to see written, with an error to the sender when the write doesn't finish within its wait | fc-service's tests; `vectors/streams.json` gains a service's two-way cases; freedom-ipfsd and freedom-radicled unchanged, and their connections still refuse incoming stream frames |
| COL-4 | core `main` | `freedom-colibrid`: the methods, confinement, the store, budgets and its release | the vectors through the binary with a scripted main, on three OSes; confined, `socket` and a file outside the grant are refused (Linux, macOS); test hooks: a crash in a step names that request, a spin is killed and named, a recycle is no fault; the step marker: a held writer times the marker out and the C core isn't entered (`busy`), a death before `colibri.stepped` names the request, a death after it names nobody; a stream longer or shorter than its head (`Colibri body length mismatch`) while other streams and control frames go on; every budget's refusal; a fuzz target for the decoder and verifier in `fuzz/` |
| COL-5 | browser `integration/rust-core` | `colibri-service.js` with `colibri-worker-host.js`'s interface, main's fetches with the fetch contract and the Colibri fetch pool, the browser-wide bounds, the checkpoint path, the binary's pin and fetch, the license audit; behind a development switch, WASM still the default; the default-host question decided first | the Colibri suites (`colibri-worker-host`, `colibri-resolver`, `chain-verified`, `naming-verified`, `checkpoint-verifier-worker`) pass against both backends as one contract suite, deviations marked; the ENS e2e suite (`ENS_COLIBRI_E2E=1`) passes on the service; the checkpoint captures verify through the one-shot process; with a session proxy set, every Colibri fetch goes through it; the fetch contract's refusal tests and the body tests ([Main's fetches](#mains-fetches)); the 7-chain walk ([How many](#how-many)); with a scripted service, forged markers (an unknown or ended request, a second `colibri.step` while one is open, a `colibri.stepped` for another request) kill the process and name nobody, and a death after a clearing event names nobody; `createError`'s three rules byte for byte |
| COL-6 | browser `integration/rust-core` | the service by default; then the WASM path removed: `colibri-runtime.js`, `colibri-worker.js`, `colibri-worker-host.js` and their tests, the package and its pin, `C4_DISABLE_NATIVE`, the V8 flag if nothing else needs it, the license entries | `git grep colibri-stateless` finds only the changelog and docs; the unit and e2e suites pass on three OSes; the app loses the package (`c4w.wasm`, 1.37 MB, and F-3's 7.2 MiB of add-ons) |

- **Q19, native only:** COL-6 switches and removes in one release.
- **Q19, keep WASM for one release:** COL-6 switches, with a setting that brings the WASM workers back for one release, and the removal follows in the next. Cost: two backends tested in every PR of that release, and the package kept.

## Amendments

Once decided:
- **0004 and 0005:** their *Verified operations* tables say main runs the Colibri operations through `freedom-colibrid` (0014), and that the verifiers' own networking (their non-goal, roadmap 3.3) is settled here for Colibri. 0005's *Colibri* section says that `fault: true` then rests on the step marker's step-local, best-effort evidence ([The step marker](#the-step-marker)), with the same form and the same backoff.
- **0009:** *Streams in the core*'s rule that service connections keep one role each gains `freedom-colibrid`'s exception: main sends it fetched bodies, and it sends main none.
- **0010:** *What each service needs* gains `freedom-colibrid`: its chain's directory read-write, nothing read-only beyond the system's, no network; the checkpoint process nothing. Its tests cover it as they cover the others.
- **0013:** *What moves* gains `colibri/`, a cache that may be dropped instead of moved.
- **AGENTS.md:** rule 6 names the service's answer module, if Option A's PR 3 isn't taken, or for Option B.

## Options weighed

- **Main drives the C core step by step,** the service a pure state machine (`open`, `step`, `answer`): no change to `fc-service`, and attribution from main's own evidence, since main sends each step. But bodies from main would need requests over 1 MiB or a new way to stream into a request, and the loop would stay in JavaScript.
- **The core as the client:** the core opens no process and no socket (0001), and main already spawns every service and runs 0010's checks before each spawn.
- **One process for every chain:** fewer processes, but one chain's crash takes the other's requests with it, and one thread serves both. Today each chain has its own worker.
- **One process per request:** the strongest isolation, and attribution without a marker, at a process start and a store load per request, and no shared cache.
- **The WASM build in a process:** keeps WASM's bounds and adds the process. `c4w.wasm` is an Emscripten build whose imports are JavaScript, so it needs Node (Electron as Node), which 0010 can't confine, or a WASI build upstream doesn't ship, run under wasmtime. The fallback if COL-2 finds the native build less safe than WASM in a way the hardening can't answer.
- **Keeping the flat store:** no bootstrap after the switch, but every chain's process could write every chain's keys, and the native build would read the WASM build's BLS key files, whose format is the build's.
- **Main streaming each body to the service as it arrives,** instead of reading it whole first: less held in main, but the head couldn't carry an exact length, the service would have to reserve the entry's maximum itself, and failing over to the next server after part of a body had gone would need a way to take it back. `fetch_from_servers` reads each body whole too, and the pool bounds what main holds.
- **Upstream's high-level client with our own `RequestHandler`:** it still compiles tokio and reqwest, and its loop isn't the JS reference's.

## Open questions

1. **Default hosts (F-2): keep the package's built-in hosts, or reach only the configured prover?** This must be decided **before COL-1 and COL-5**. The answer fixes main's server table and the fetch contract's servers, the client COL-1 records with and its fixtures, the privacy rows of the threat model, and COL-5's contract and proxy tests.
   - **Keep the built-in hosts:** the package's beacon, checkpoint and RPC hosts for each chain, as today. They are now reached through the session (proxy, Tor, endpoint policy) and only in the contract's shapes.
   - **Only the configured prover:** every type goes to the prover. The package's own order already ends with it (`cjs/http.js:151–168`), and `eth_rpc` goes to the prover's `unverified_rpc`, as the package does when it is given no RPC list (`cjs/http.js:167`). A cold start then depends on the prover serving light-client updates, bootstraps and checkpoint roots, and may be slower or fail where it doesn't.
   - *Proposed: keep the built-in hosts for this design. Moving to the prover alone can be its own later change, with its own fixtures and vectors.*
2. **Q19: ship only the native service, or keep WASM for one release?**
   - **Native only:** COL-6 switches to the service and removes the WASM path in one release.
   - **Keep WASM for one release:** COL-6 switches, with a setting that brings the WASM workers back, and the removal follows in the next release. That costs two backends tested in every PR of that release, and the package kept.
   - *Proposed: native only, once COL-5's contract suite and the ENS e2e suite pass on the service on three OSes. The WASM path's main risk, a crash of main, is the one this design removes.*
3. **Q20: work through public upstream PRs, or keep a vendored copy?**
   - **Public upstream PRs:** three small PRs on Colibri upstream (an `http` feature, an offline pinned build, a safe answer API), with a pinned fork commit until they are released ([Option A](#option-a-public-upstream-prs)).
   - **A vendored copy:** the C sources copied into this repository, with our own `unsafe` bindings and every upstream release re-checked by hand ([Option B](#option-b-a-vendored-copy)).
   - *Proposed: public upstream PRs.*
4. **May we file two public issues upstream, for F-1 and F-6?** This is separate from Q20: either build path can file them, or neither.
   - **F-1:** `VerifiedOnly` answers unproofable methods and `pending`/`earliest` reads without a proof.
   - **F-6:** the out-of-bounds access on a transaction hash the prover hasn't seen (#750).
   - Our own fix for F-1 doesn't depend on the answer: it is in review in the browser and the core.
   - *Proposed: yes, both, in plain factual text.*
