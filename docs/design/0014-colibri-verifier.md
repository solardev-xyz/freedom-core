# 0014: The Colibri verifier process

**Status:** proposed. Roadmap item 3.3: Colibri leaves Electron main's WASM workers for its C core in a confined process of its own. Builds on [0001](0001-freedom-cored.md) (frames, deadlines, hardening), [0004](0004-naming-sessions.md) and [0005](0005-chain-data.md) (the `shell.verified` Colibri operations, the fault, capacity and #752 rules), [0007](0007-ipfs-service.md) and [0008](0008-radicle-service.md) (the service pattern), [0009](0009-dweb-verification.md) (streams in both directions) and [0010](0010-service-confinement.md) (confinement). Nothing here is built yet. The user decides the [open questions](#open-questions).

**The references:**
- **freedom-browser** at `f47ac5c1` (`integration/rust-core`), in `src/main/`:
  - `ens/colibri-runtime.js` (224 lines), `ens/colibri-worker.js` (204), `ens/colibri-worker-host.js` (403) and `ens/colibri-resolver.js` (271): about 1.1k lines;
  - their callers: `core/chain-verified.js` (0005's executor), `core/naming-verified.js` (0004's), `myotis/checkpoint-verifier.js` and `myotis/checkpoint-verifier-worker.js`;
  - `package.json` (the pin, `files`, `asarUnpack`).
- **`@corpus-core/colibri-stateless` 3.0.3**, the npm tarball, in `cjs/`: `index.js` (the client and its request loop), `http.js` (the fetches), `strategy.js`, `types.js`, `runtime_wasm.js`, `chains.generated.js` (the default hosts), and `c4w.wasm`.
- **Upstream:** `corpus-core/colibri-stateless` (formerly `corpus-core/c4`; default branch `dev`) at tag `v3.0.3`, `2c65ae6e`: `CMakeLists.txt`, `libs/`, `src/api/colibri.h` (the C API), `src/api/colibri_common.c`, `src/chains/eth/verifier/`, and `bindings/rust/` (crate `colibri-stateless` 0.1.0).
- **freedom-core** at `152da6ce` (`main`): `fc-service` (`conn.rs`, `confine/`, `network.rs`), `fc-protocol` (`stream.rs`), `fc-chain` (`methods.rs`, `machine/faults.rs`).

## Summary

- **Today** Colibri runs as WASM inside Electron main: one worker thread per chain for chain data and ENS, and a throwaway worker per Myotis checkpoint check. Its fetches use Node's `fetch` in the worker, so the session's proxy and Tor settings don't apply. Its WASM memory can grow to 2 GiB inside main's process. A trap stopped killing main only once a V8 flag was set (#453).
- **The process (proposed):** `freedom-colibrid`, a service on `fc-service` like `freedom-ipfsd` and `freedom-radicled`.
  - Main spawns one persistent process per chain that has a prover, when that chain first needs Colibri, and a one-shot process for each checkpoint check.
  - It confines itself under 0010 with `Network::Offline`: no socket of any kind. It reads and writes only its chain's cache directory.
  - It talks to main only over stdin and stdout. It binds no port and serves no loopback HTTP.
- **HTTP through main:** the C core is already sans-I/O: each step returns the data it needs. The service asks main for each piece with `shell.colibri_fetch`, naming a server *type* and a path, never a URL. Main picks the servers, fetches through the session's network stack, and streams the body back.
- **The build ([Q20](#open-questions)):** upstream's Rust crate pulls in tokio and reqwest, and its build script downloads prebuilt archives when it can't run CMake. Proposed: small public PRs upstream that gate the HTTP client behind a feature and make the build offline and pinned, with a pinned fork commit until they are released. If the user says no, a vendored build of the C sources in this repository.
- **The protocol:** the core's side doesn't change. 0005's `{ colibri: "request" }` and 0004's `{ colibri: "resolve" }` and `{ colibri: "reverse" }` keep their wire shape and outcomes, and the core's fault, capacity and #752 rules stay as they are. What changes is what main runs for them: a client of the service instead of the WASM worker host. A step marker tells main exactly which request was inside the C core when a process died, so a crash names its culprit, as a WASM trap does today.
- **The proof:** `vectors/colibri.json`, recorded from the JS reference through a recording runtime around the real `c4w.wasm`. The native build must reproduce every step's status text byte for byte, every data request and every storage write.
- **Running it:** budgets per process (memory, open requests, bodies, storage), a kill one second past a request's deadline while it is inside the C core, lazy restarts with 0007's back-off, and a recycle above the memory budget.
- **The migration, COL-1 to COL-6:** vectors, the native build, fc-service's service-to-main requests, the service, the browser's client behind a flag, then the switch and the removal of the WASM workers. Whether WASM may go with no fallback release is [Q19](#open-questions).
- **Found while checking the code:** through Colibri, the reference answers `eth_gasPrice`, `eth_feeHistory` and any read at a `pending` or `earliest` block without a proof, and the router labels the answer verified ([F-1](#facts-found-while-checking-the-code)). Its fix shouldn't wait for this design.

## Goals and non-goals

**Goals**
- **A verifier fault can't take main down,** whatever the fault: a memory error, an abort, a spin or a memory blow-up.
- **No network and no files of its own:** the verifier reaches the network only through main's fetches and the files only through its cache directory.
- **Colibri's fetches obey the session:** proxy, Tor, the endpoint policy and the onion gate, as 0005's `shell.rpc` does.
- **Parity** with the WASM adapter, shown by vectors, with every [deviation](#deviations) listed.
- **Bounded resources** with a defined result when a bound is reached. Today only the V8 heap of each worker is bounded.

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
2. **F-2: hosts the user didn't configure.** Even a user who set their own prover reaches the package's default beacon, checkpoint and RPC hosts (above).
3. **F-3: unused native add-ons ship.** Nothing in `package.json`'s `files` excludes the package's `prebuilds/`, and `asarUnpack` takes every `*.node`. So a build carries all five platforms' `colibri_native.node` (7.2 MiB together), which nothing loads.
4. **F-4: the ZK fallback is silent and sticky.** On an error containing `zk sync proof`, the client turns ZK off for the rest of its life and retries (`cjs/index.js:261–265`; upstream issue #369). The trust label still reads `ZK sync-committee proof`, since the core takes it from configuration (0004, 0005).
5. **F-5: the store is unbounded.** `createDiskStorage` joins the C core's key to the directory without checking it, and nothing bounds a value's size or the directory's (`colibri-worker.js:84–109`).
6. **F-6: the unknown-hash trap isn't reported upstream.** Upstream's issue list has no report of #750's out-of-bounds access on a hash the prover hasn't seen.
7. **F-7: upstream's build has four traps for us** ([The build](#the-build-q20)): the version number comes from `git describe`, the CMake tree is written into the source checkout, the prebuilt download is unverified, and third-party sources are fetched by tag.

## Threat model

Stage 1 trusts main (0001). The attacker here controls the verifier's input: a malicious or compromised prover, beacon API or checkpoint server, or a page choosing what to ask (an unknown transaction hash, a contract whose code the EVM will run). Their goal is a memory error in the C or C++ code (the verifier, blst, evmone) that crashes, exhausts or takes over the process that runs it.

| Threat | Today: WASM workers in main | With `freedom-colibrid` |
|---|---|---|
| A memory error the input triggers | stays inside the instance's linear memory; WASM can't run injected native code; an access past that memory is a trap | native code: it can be taken over. The process boundary and 0010 contain it: no network, no file but its cache, no new process, no local IPC but main's pipe. On Windows only "no new process" until WIN-2 |
| The verifier crashes | main survives only because of a V8 flag. #453 killed the browser before it, and an Electron change could again | the service exits; main and the core run on |
| Memory | up to 2 GiB of WASM memory per worker inside main's address space | a budget per process; running out kills the service |
| CPU | a spinning step holds a core in main's process until the deadline plus 1 s; network waits hold their slot up to 60 s more | the same kill, of a process at lower priority; network waits end at the deadline |
| Network policy | Node's fetch: no proxy, no Tor, no endpoint policy | main's session stack, as `shell.rpc` |
| Where requests go | any path on the hosts of the four lists, with no body cap | the same hosts, named by type; main checks each URL's origin and caps each body |
| A taken-over verifier lies | possible in WASM too | unchanged. Isolation doesn't make answers more trustworthy |
| A taken-over verifier poisons its cache (forged sync-committee keys that later verifications trust) | possible: the store is reached from the instance | possible within its own chain's directory only; cleared after repeated crashes. Residual |
| Request data leaking | to main and to the hosts above | the same: the service has no other way out |

**What changes for the worse:** WASM traps on every access past its linear memory. A native build traps only where an access reaches unmapped memory, so some accesses WASM catches become silent misreads natively. #750's unknown-hash case, which runs for seconds before WASM traps, may behave differently. The mitigations: a hardened build (stack protector, `_FORTIFY_SOURCE=3`, control-flow protection where the target has it), a sanitizer job over every vector in CI (COL-2), a fuzz target for the proof decoder and verifier (COL-4), and #752's rule, which keeps the router from asking Colibri about transactions it can't prove. [Options weighed](#options-weighed) lists the WASM-in-a-process alternative.

**Not covered:** a compromised main; same-user processes (0010); root, admin and the kernel; upstream soundness bugs. Upstream has open outside PRs whose titles describe verifier binding checks (#396, #399, #400, #402, #404, #405, opened 13–22 October, unmerged at `v3.0.3`).

## The process

### Spawn

- **One persistent process per chain:** `freedom-colibrid serve --chain <id> --data-dir <userData>/colibri/<id> --lock-dir <dir> --parent-pid <pid>`.
  - Main spawns it on the chain's first Colibri request, as today's host spawns a worker, and keeps it running.
  - It serves chain data and, for chain 1, ENS.
- **One one-shot process per checkpoint check:** `freedom-colibrid checkpoint --chain <id> --parent-pid <pid>`. It keeps its store in memory, takes no lock and has no directory, like 0007's ephemeral process. It serves one `colibri.checkpoint` and exits.
- **No `--network`:** the service has none, so `hello` reports `network: "offline"`.
- **As 0007 for the rest:** the binary from `<resources>/freedom-colibrid/` (`FREEDOM_COLIBRID_PATH` only when not packaged), the scrubbed environment, `colibri.hello` within 10 s, 0001's hardening, and the exit codes.
- **Lower priority:** main lowers the process's scheduling priority after the spawn (`os.setPriority`: 10 on Linux and macOS, below normal on Windows), so a long verification doesn't compete with the browser.
- **Nothing listens.** The service binds no port and serves no loopback HTTP; its only channel is main's pipe.

### Confinement

0010's `confine`, after the lock and before `hello`, with:
- `network: Network::Offline`: on Linux seccomp refuses `socket` for every family (`seccomp.rs:177–186`); on macOS the Seatbelt profile grants no network; on Windows `network` is `unavailable` (`job.rs:75–79`);
- `read_write`: the chain's directory alone, nothing for the checkpoint process;
- `read_only`: nothing beyond the system's own (`/proc/self`, the cgroup files, the random devices);
- `resolver: Resolver::None`, `refer: false`, `min_abi: 1`, `interface_index: false`;
- `descriptors`: the lock and the directory.

Every part exists in `fc-service` today: the Radicle import and a freedom-ipfsd test already confine with `Offline`.

**Main's check before each spawn** (0010, step 7) covers the chain's directory, which lies in the profile's `userData`. Its protected roots don't change.

### Inside the process

- **Plain threads, no async runtime:** fc-service's connection threads, and one *verifier thread* that makes every call into the C core. The C core keeps process-wide caches, some without a lock (`src/util/json_validate.c:272`), so one thread per process makes those calls. That is today's concurrency too: one single-threaded WASM instance per chain.
- **A request** is a context in the C core. It runs one step at a time on the verifier thread, then waits for main's answers to its data requests while other requests step.
- **No clock in the C core:** the freshness bound (`now − 60 s`) comes from main in each request, as the JS binding computes it (`cjs/index.js:135`).
- **Fixed flags:** PAP (`privacy_mode: 'basic'`), verified-only, remote prover mode, the 60 s freshness window, as `colibri-worker.js` pins them. ZK is per client.
- **Panics:** the service's own Rust code forbids them (AGENTS rule 6). An abort in the C core ends the process like a crash.

### The store and the lifetime lock

- **One directory per chain,** `<userData>/colibri/<id>/`, the persistent process's only grant. Today's flat files in `<userData>/colibri/` are left alone; they are a cache, and each chain bootstraps once (deviation `storage-per-chain`). This also keeps the native build from reading the WASM build's files, whose BLS keys are stored in blst's in-memory form (`BLS_DESERIALIZE`, `sync_committee_state.c:632–646`).
- **Writes** are a temporary file, fsync and rename, with stale temporary files swept at start, as `createDiskStorage` does.
- **Bounds:** a key is `[A-Za-z0-9_]{1,100}`; a value at most 1 MiB (a sync committee is 49,152 bytes); a directory at most 64 MiB. A write past a bound fails, and the C core sees a failed write.
- **The lock:** fc-service's gate, keyed by the chain's directory, so a replacement never writes while its predecessor still can. Today a draining worker and its replacement share the store.
- **What it holds:** public chain data alone, under two kinds of key, `states_<chain>` and `sync_<chain>_<period>` (`sync_committee_state.c`), and nothing a request names. So private windows share it, as they do today.
- **No other store:** the C core is built with its own file store off (`FILE_STORAGE`, which writes to the working directory), and the service gives it its store before `hello`.
- **0013's move:** `colibri/` isn't in 0013's list of entries that move into `<profile>/freedom/`. As a cache it can join the list, or be left and rebuilt ([Amendments](#amendments)).

## The build (Q20)

### What upstream has

- **A C core built with CMake** (C and C++17: evmone is C++), MIT-licensed except `src/server/` and `src/chains/eth/server/` (PolyForm Noncommercial or commercial), which only `HTTP_SERVER=ON` builds. Upstream relabelled two OP files that carried PolyForm by mistake after an outside report (issue #401, closed 19 October, PR #403).
- **Third-party code**, fetched by CMake's `FetchContent` at build time by tag: blst `v0.3.13` (Apache-2.0), evmone `v0.23.0` and intx `v0.15.0` (Apache-2.0), libtommath and mcl where enabled, zstd `v1.5.6` for OP chains (BSD or GPLv2); and `libs/crypto` in the tree (MIT).
- **A C API usable without WASM** (`src/api/colibri.h`): `c4_create_rpc_ctx`, `c4_rpc_execute_json_status`, `c4_req_set_response`, `c4_req_set_error`, `c4_free_rpc_ctx`, the verify and decode calls, `c4_get_method_support`, `c4_set_storage_config` and `c4_get_current_version_number`. It is sans-I/O: a step returns the data it needs as JSON.
- **A Rust crate,** `bindings/rust` (0.1.0), with two layers:
  - safe context types (`RpcCtx`, `Verifier`) over the C API, and `unsafe fn` answers (`req_set_response`, `req_set_error`), unsafe because they take the C core's request pointer as an integer;
  - a high-level `Colibri` client that fetches with reqwest on tokio. tokio, reqwest, futures and async-trait are unconditional dependencies (`Cargo.toml:41–45`); only the OP module is a feature (`op`, default on).
- **Its build script** (`build.rs`) links archives from `COLIBRI_LIB_DIR`; or, inside an upstream checkout, runs CMake with `CURL`, `CLI` and `HTTP_SERVER` off (`:212–216`), writing the CMake tree into the checkout (`build-rust/<target>`, `:187`); or else downloads a prebuilt archive from GitHub releases with `curl`, unverified (`:333–393`).
- **The version number** provers route proofs by comes from `git describe` at configure time (`CMakeLists.txt:27`), or from `C4_VERSION`. A Cargo git checkout need not carry the tags, and a vendored copy has no `.git` at all, so a build that doesn't set `C4_VERSION` can report the wrong version, and a prover then sends a proof format the verifier can't read.

### Option A: upstream feature-gating (Q20 yes)

Three small PRs upstream, each useful to other users of the crate:
1. **An `http` feature, on by default,** around the high-level client and its error variant, so `default-features = false` drops tokio, reqwest, futures and async-trait;
2. **An offline, reproducible build:** no download unless asked for, the CMake tree under `OUT_DIR` (or a set directory), `C4_VERSION` from the crate's own version, and `FetchContent` pinned by commit with a hash, or overridable from local sources;
3. **A safe answer API:** pending requests as values tied to their context's lifetime, so a caller can answer one without `unsafe`.

And two issues: F-1 (`VerifiedOnly` answering unproofable methods without a proof) and F-6 (the unknown-hash trap).

Until they are released, `freedom-colibrid` depends on a fork under `solardev-xyz` at a pinned commit, as `freedom-radicled` depends on libradicle.
- **Cost:** upstream review time, and a fork to keep until then. Upstream fixed an outside license report and the feature it asked for within a day (issue #401, opened 18 October; PR #403, merged 19 October), and has open outside PRs.
- **Our code:** with PR 3, no `unsafe` in this repository. Without it, one small module with `#[allow(unsafe_code)]` for the two answer calls, which AGENTS rule 6 must name, like `freedom-radicled`'s one call.
- **CI:** CMake and a C++17 compiler on the three OSes' runners, the fork's sources fetched by Cargo, and `FetchContent`'s sources pinned.

### Option B: a vendored C build (Q20 no)

The C core at `v3.0.3` and its third-party sources copied into `services/freedom-colibrid/vendor/`, with their licenses, built by our `build.rs` through the `cmake` crate, with our own bindings to the dozen C functions the service calls.
- **Cost:**
  - our own FFI module with `unsafe` (an AGENTS rule 6 exception, each call with a `SAFETY` comment, as `fc-sys`);
  - every upstream release copied and re-checked by hand, CMake's generated chain headers included (`src/chains/chains.cmake:50`, `:116`);
  - about 47k lines of C and headers in `src/` outside the server, the CLI and the ZK prover (93 source files) plus `libs/crypto`, blst, evmone and intx in our tree.
- **Gain:** nothing upstream needs to agree to; full control of flags and pins.

### Licenses

Both options build with `HTTP_SERVER` off, so no PolyForm file is compiled. COL-2 checks it: the build fails if a compiled source's header names PolyForm. The notices file gains blst, evmone and intx (Apache-2.0), `libs/crypto` (MIT) and Colibri (MIT). `CHAIN_OP` is off: Freedom verifies no OP chain, and zstd stays out.

### Proposed

**Option A**, if Q20 is yes; Option B otherwise. Either way, `freedom-colibrid` is its own Cargo workspace (`services/freedom-colibrid`), as `freedom-ipfsd` is: its own lockfile, `cargo deny` policy and notices, sharing `fc-protocol` and `fc-service` by path. Its release follows freedom-ipfsd's in `RELEASING.md`.

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
- **Refusals:** `busy` (budgets), `too_large`, `cancelled`, `invalid_argument`. A method the C core can't prove for these params is refused before any context exists, with the C core's own text, `Method <m> is not supported` (deviation `colibri-unproofable`, F-1).
- **`colibri.checkpoint`** fetches the proof through main ([Requests the service makes](#requests-the-service-makes)), decodes it, verifies it on the memory store, and returns the decoded proof's JSON with the result. `stage` says where it failed (`decode` or `verify`), so main keeps its own classes: `CHECKPOINT_UNAVAILABLE` for a proof that doesn't decode; for one that doesn't verify, a transport error it saw, `CHECKPOINT_STALE` for `proof for latest too old`, `CHECKPOINT_MISMATCH` otherwise (`checkpoint-verifier-worker.js:353–368`). Main's evidence checks on the decoded proof stay in main.

### Requests the service makes

| Method | Params | Main does | Reply |
|---|---|---|---|
| `shell.colibri_fetch` | `{ request, type, method, path, payload?, accept, exclude_mask, max_age? }` | one data request, [as below](#mains-fetches) | a head `{ node, bytes }` and the body as a stream, or `{ error }` |

- **`request`** names main's open `colibri.request` or `colibri.checkpoint`. Main refuses a fetch for anything else.
- **`type`:** `prover`, `beacon_api`, `checkpointz` or `eth_rpc`; on a checkpoint process, `checkpointz`, `beacon_api` or `checkpoint_proof`.
- **`delay`** stays in the service: it waits before sending the fetch, as `handle_request` waits.
- **The body** comes as 0009's stream, from main to the service, with a 128 KiB window. The service reserves the head's `bytes` before granting credit, and answers a head it can't reserve with `busy`, which the C core sees as a failed fetch.
- **`error`** is the text the C core gets (`c4_req_set_error`).

### The step marker

- **Before each call into the C core that can run long** (a step, a decode), the verifier thread queues the event `colibri.step { request }` and waits until the writer has written it, at most 1 s.
- **Written means in the pipe:** main reads it even if the process dies right after.
- **A step ends** when that request's next frame comes: a fetch or its reply.
- **So when a process dies,** main reads its pipe to the end and knows which request, if any, was in a step. That one is the culprit; every other request on the process is a bystander. A death with no open step, or after a marker that wasn't written in time, names nobody.
- **Today** a trap names its request exactly, and a stuck worker's culprit is guessed. The marker makes both exact.

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
- **error:** `ProviderRpcError.createError` of the text (`cjs/types.js:38`): code 4200 for `Method … is not supported`, 4900 for transport texts, otherwise -32603, and the message `Error in rpc call <method><params> : <text>`;
- **the culprit of a death:** `ColibriWorkerError('Colibri worker replaced: <reason>')`, the text `isColibriFault` matches;
- **a bystander:** sent once more to the next process with what is left of its deadline; if it fails again, its error carries `colibriBystander`, as today;
- **no process** (a restart's back-off, or restarts stopped): `Colibri service unavailable`, which matches neither the fault pattern nor the retry pattern.

### What the core sees

Nothing new. `chain-verified.js` and `naming-verified.js` keep their code; `colibri-resolver.js` keeps its clients, its retry and its ethers provider, and requires `colibri-service.js` where it required `colibri-worker-host.js`; the new module exports the same `createClient` and `ensureWorker`. The core's `colibri_faults` capability, its backoff (`fc-chain/src/machine/faults.rs`), the capacity bit and #752's ordering apply unchanged.

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
| `ping` / `pong` | gone: the step marker |
| `setRuntimeResetListener`, `trap`, the runtime's retirement | gone: a fault ends the process |
| checkpoint: `register_storage(Map)` | the one-shot process's memory store |
| checkpoint: the prover fetch, `decode_proof` (`_c4w_decode_proof`) | `colibri.checkpoint`: a `checkpoint_proof` fetch, then decode |
| checkpoint: `verifyProof` (`_c4w_create_verify_ctx`, `_c4w_verify_proof`, `_c4w_free_verify_ctx`) and its intercepted `fetch` | inside `colibri.checkpoint`; main answers its `checkpointz` fetches from the quorum |
| `clientVersion` from `package.json` (196611) | `c4_get_current_version_number()`, in `hello`; main refuses another than its pin's |
| unused: the prover context, `_c4w_set_checkpoint`, `_c4w_reset_caches`, the proxy URLs, witness keys | not exposed |

## Main's fetches

For `shell.colibri_fetch`, main does what `fetch_from_servers` does, through the session:
- **The servers** by type, as `handle_request` picks them: the client's prover from the registry, then the package's default lists for the chain, which main holds as a table that a vector pins (F-2, [open question](#open-questions)). For a checkpoint process: `checkpointz` is answered by main's quorum, as today's intercepted `fetch` is, with its checks (origin, `GET`, the path, at most 8 requests); `checkpoint_proof` is main's own proof fetch, 4 MiB at most; `beacon_api` has no server, as today.
- **The order:** servers in turn, skipping those `exclude_mask` names; the first success wins, and its index is `node`.
- **The request:** the method in upper case; `Accept` by encoding; `Content-Type` and the payload as `JSON.stringify` of its parse, when there is one; `Cache-Control: max-age=<max_age>`.
- **The checks:** the path at most 8 KiB with no control character, the URL `joinPath(server, path)` with the server's origin, the payload at most 64 KiB of valid JSON, `exclude_mask` a 32-bit integer, `max_age` 1 to 86,400.
- **Through the session:** the proxy and Tor apply, with the endpoint policy and the onion gate on every redirect hop, as for `shell.rpc` (0005).
- **Bounds:** a body at most 16 MiB; the request's deadline bounds every attempt.
- **Error texts** as `fetch_from_servers` writes them, with URLs replaced by `<url>`, as `colibri-resolver.js` already does for its logs, and cut to 2,000 units (deviation `fetch-error-text`). `retryableColibriError`'s pattern reads the parts that stay.

## Budgets

The numbers below hold until COL-2 measures the native build. It replaces each with twice the peak it sees over the vectors and the ENS e2e suite, or keeps it, whichever is larger.

| What | Persistent process | Checkpoint process |
|---|---|---|
| open requests | 16 (main sends at most 8: 0004's bound per verifier) | 1 |
| fetches open | 64 per process; 1,024 per request in all | the same |
| a fetched body | 16 MiB | 4 MiB (the proof), 64 KiB otherwise |
| bodies in flight | 32 MiB, reserved before credit | 8 MiB |
| store | 1 MiB a value, 64 MiB a directory | memory, counted in resident memory |
| resident memory | 256 MiB, then a [recycle](#crashes-overruns-and-restarts) | 128 MiB, then the check fails |
| time | a step 1 s past its request's deadline | 90 s in all (today's) |

- **Resident memory** is read by the service after each step (`/proc/self/statm`, `task_info` on macOS). It can't bound the C core's allocations as they happen. A hard limit by the OS is user question Q17, shared with 0007.
- **A reply over 0001's message cap** is `too_large`, as 0005 says.

## Crashes, overruns and restarts

- **A crash** is an exit main didn't ask for, other than 64, 74, 75 and 77, as in 0007. Main reads the pipe to its end, fails the culprit with the fault text, and resends its bystanders once.
- **Restarts are lazy:** the next request spawns a process, after 0.5 s, 2 s, then 10 s following abnormal exits (0007's back-off), reset after 60 s without one. Requests during the back-off get `Colibri service unavailable` and fall through to the next source.
- **Crashes a request caused don't stop restarts.** The core's backoff already throttles each method on each chain: two faults within 60 s start a cooldown of 60 s, then 5 min, then 15 min.
- **Three exits within 60 s that name no culprit** stop restarts for that chain until a configuration change or the next launch.
- **Three abnormal exits in a row with no answer between them** clear the chain's directory before the next spawn: it is a cache, and a damaged entry would crash every process that loads it.
- **A recycle:** above its memory budget a process refuses new requests (`busy`, which main sends to the successor), finishes its open ones, and exits 0. Main spawns the successor at once. A recycle is no fault.
- **Logs:** main logs each crash, kill, recycle and stop at `warn` with the chain and the reason, never a request's params.

## Vectors

`vectors/colibri.json`, from `vectors/generator/colibri.js`, as the other generators: the reference checkout at a pinned commit, its installed packages, nothing reimplemented (AGENTS rule 5).
- **A recording runtime.** `colibri-runtime.js` already installs its own runtime provider. The generator wraps it and records every call with its arguments and return: method support, context creation, every step's status text verbatim, every answer and error, frees, decodes, and the store's gets, sets and deletes (keys, sizes and SHA-256 of values).
- **Scripted worlds:** `globalThis.fetch` stubbed, answering from recorded server responses in `vectors/fixtures/colibri/`, captured once from the live provers as the browser's `capture.cjs` captures checkpoints, with each request recorded (URL, method, headers, body). The clock is fixed, so the freshness bound is too. Stores start empty or seeded.
- **Cases,** for chains 1 and 100:
  - every method the router sends Colibri: account and storage reads, code, blocks with and without transactions, mined transactions and receipts, `eth_blockNumber`, `eth_maxPriorityFeePerGas`, `eth_estimateGas`, `eth_call`;
  - ENS through `resolveCallViaColibri` and `resolveReverseViaColibri`: contenthash, address, reverse, a proven `ResolverNotFound`, an `OffchainLookup` revert and its CCIP callback;
  - failures: a flipped byte in each proof, a stale proof, a server failing before another answers (`exclude_mask`, `node`), every server failing, an HTTP error with a body, the ZK fallback;
  - store: a cold start's bootstrap and a warm start;
  - the checkpoint: both captures in `docs/audits/evidence/colibri-v3-2026-09/captures`, a flipped proof, a v2 proof;
  - F-1: `eth_gasPrice`, `eth_feeHistory`, a read at `pending`, each marked `deviation: colibri-unproofable`;
  - #750: an unknown-hash receipt, which traps in WASM. The service must end it in an error or a crash, never a result.
- **What the native build must match:** each step's status text byte for byte (the request pointer replaced by its index), the data requests in their rounds, the store's writes, and the version number. Through main's client: each adapter outcome (result, or error with name, code, message and data).
- **Where the deviations show:** cases marked with their deviation id record the reference's outcome and the design's.

## Deviations

| Id | Today | With the service |
|---|---|---|
| `colibri-unproofable` | unproofable methods and `pending`/`earliest` reads are answered from a public RPC without proof, labelled verified (F-1) | refused before any context: `Method <m> is not supported` |
| `colibri-deadline` | a request waiting on the network keeps its slot up to 60 s past its deadline, then fails as a fault and takes its worker's other requests with it | cancelled at its deadline; not a fault; nothing else ends |
| `colibri-culprit` | a stuck worker's culprit is guessed from methods; several suspects of mixed methods name nobody | the step marker names it |
| `colibri-session-fetch` | Node's fetch: no proxy, Tor, endpoint policy, timeout or body cap | main's session fetch with them |
| `fetch-error-text` | a fetch error names the URL and payload, and carries the whole error body | URLs as `<url>`, at most 2,000 units |
| `no-initial-chain-id` | a local `eth_chainId` context on each client's first request | none |
| `storage-per-chain` | one flat directory for every chain; unchecked keys; no size bound | a directory per chain, checked keys, bounds |

## Migration (Q19)

**Ahead of the steps: F-1's fix,** in the core: `fc-chain` stops asking Colibri for `eth_gasPrice` and `eth_feeHistory`, and for a read whose block tag is `pending` or `earliest`, with replay vectors marked `deviation: colibri-unproofable`. It is a trust-label fix and doesn't wait for this design's decision.

| Step | Where | What | Done when |
|---|---|---|---|
| COL-1 | core `main` | `vectors/colibri.json`, its generator and fixtures | `generate.js check` passes; damaged copies fail it (`check.test.js`); every case above is present |
| COL-2 | core `main` | the native build in `services/freedom-colibrid` (a library and a test harness, no service yet), by the Q20 decision; the measured budgets as an amendment here | CI on Linux, macOS and Windows runs every COL-1 trace through the native C core and matches it; the version number is 196611; no PolyForm source is compiled; an ASan and UBSan job runs every trace, #750's included, clean; any difference or sanitizer finding stops the step and is reported |
| COL-3 | core `main` | `fc-service`: requests from a service to main, two-way streams for a service that turns them on, and an event the sender waits to see written | fc-service's tests; `vectors/streams.json` gains a service's two-way cases; freedom-ipfsd and freedom-radicled unchanged, and their connections still refuse incoming stream frames |
| COL-4 | core `main` | `freedom-colibrid`: the methods, confinement, the store, budgets and its release | the vectors through the binary with a scripted main, on three OSes; confined, `socket` and a file outside the grant are refused (Linux, macOS); test hooks: a crash in a step names that request, a spin is killed and named, a recycle is no fault; every budget's refusal; a fuzz target for the decoder and verifier in `fuzz/` |
| COL-5 | browser `integration/rust-core` | `colibri-service.js` with `colibri-worker-host.js`'s interface, main's fetches, the checkpoint path, the binary's pin and fetch, the license audit; behind a development switch, WASM still the default | the Colibri suites (`colibri-worker-host`, `colibri-resolver`, `chain-verified`, `naming-verified`, `checkpoint-verifier-worker`) pass against both backends as one contract suite, deviations marked; the ENS e2e suite (`ENS_COLIBRI_E2E=1`) passes on the service; the checkpoint captures verify through the one-shot process; with a session proxy set, every Colibri fetch goes through it |
| COL-6 | browser `integration/rust-core` | the service by default; then the WASM path removed: `colibri-runtime.js`, `colibri-worker.js`, `colibri-worker-host.js` and their tests, the package and its pin, `C4_DISABLE_NATIVE`, the V8 flag if nothing else needs it, the license entries | `git grep colibri-stateless` finds only the changelog and docs; the unit and e2e suites pass on three OSes; the app loses the package (`c4w.wasm`, 1.37 MB, and F-3's 7.2 MiB of add-ons) |

- **Q19 yes:** COL-6 switches and removes in one release.
- **Q19 no:** COL-6 switches, with a setting that brings the WASM workers back for one release, and the removal follows in the next. Cost: two backends tested in every PR of that release, and the package kept.

## Amendments

Once decided:
- **0004 and 0005:** their *Verified operations* tables say main runs the Colibri operations through `freedom-colibrid` (0014), and that the verifiers' own networking (their non-goal, roadmap 3.3) is settled here for Colibri.
- **0009:** *Streams in the core*'s rule that service connections keep one role each gains `freedom-colibrid`'s exception: main sends it fetched bodies, and it sends main none.
- **0010:** *What each service needs* gains `freedom-colibrid`: its chain's directory read-write, nothing read-only beyond the system's, no network; the checkpoint process nothing. Its tests cover it as they cover the others.
- **0013:** *What moves* gains `colibri/`, a cache that may be dropped instead of moved.
- **AGENTS.md:** rule 6 names the service's answer module, if Q20's PR 3 isn't taken or for Option B.

## Options weighed

- **Main drives the C core step by step,** the service a pure state machine (`open`, `step`, `answer`): no change to `fc-service` and exact attribution for free. But bodies from main would need requests over 1 MiB or a new way to stream into a request, and the loop would stay in JavaScript.
- **The core as the client:** the core opens no process and no socket (0001), and main already spawns every service and runs 0010's checks before each spawn.
- **One process for every chain:** fewer processes, but one chain's crash takes the other's requests with it, and one thread serves both. Today each chain has its own worker.
- **One process per request:** the strongest isolation and exact attribution without a marker, at a process start and a store load per request, and no shared cache.
- **The WASM build in a process:** keeps WASM's bounds and adds the process. `c4w.wasm` is an Emscripten build whose imports are JavaScript, so it needs Node (Electron as Node), which 0010 can't confine, or a WASI build upstream doesn't ship, run under wasmtime. The fallback if COL-2 finds the native build less safe than WASM in a way the hardening can't answer.
- **Keeping the flat store:** no bootstrap after the switch, but every chain's process could write every chain's keys, and the native build would read the WASM build's BLS key files, whose format is the build's.
- **Upstream's high-level client with our own `RequestHandler`:** it still compiles tokio and reqwest, and its loop isn't the JS reference's.

## Open questions

1. **Q19, no fallback:** May the native Colibri service replace WASM Colibri with no release that keeps WASM as a fallback? *Proposed: yes, once COL-5's contract suite and the ENS e2e suite pass on the service on three OSes. A fallback release costs two tested backends, and the WASM path's main risk, a crash of main, is the one this design removes.*
2. **Q20, upstream:** May we open public PRs on Colibri upstream for the build changes, and file issues for F-1 and F-6? *Proposed: yes: three small PRs (an `http` feature, an offline pinned build, a safe answer API) and two issues. Otherwise a vendored build in this repository, with our own `unsafe` bindings.*
3. **Default hosts (F-2):** Should Colibri reach only the prover you configured, instead of also the package's built-in beacon, checkpoint and RPC hosts? *Proposed: keep today's lists until COL-6, then decide; reaching only the prover may slow a cold start or make it fail when the prover can't serve light-client data.*
