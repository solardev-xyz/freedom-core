# 0015: The `window.swarm` backend in the core

**Status:** proposed. Roadmap item 4.6: the Swarm provider's backend leaves Electron main for `freedom-cored`. Builds on [0001](0001-freedom-cored.md) (the process, frames, deadlines, durable writes), [0002](0002-signing.md) (`swarm.sign_soc`, key references), [0005](0005-chain-data.md) (requests the core makes of main), [0007](0007-ipfs-service.md) (stdio only, the stream frames), [0009](0009-dweb-verification.md) (protocol 2's streams in both directions, the hashing pool, `fc-swarm`'s checks), [0011](0011-page-requests.md) (page requests: the attested key, documents, sizes and tickets, PRQ-7), [0012](0012-approvals.md) (the Swarm grants in the core) and [0013](0013-profiles.md) (`fc-store`, set A). It answers 0006's *Later designs* bullet for 4.6, and 0012's "advised until 0015" for a page's SOCs. The work is the Rust core under Electron: nothing here assumes a Chromium move, and nothing needs a change to the Swarm node. Nothing here is built yet. The user decides the [open questions](#open-questions).

**The references:**
- **freedom-browser** at `b39bf724` (`integration/rust-core`):
  - `src/main/swarm/`: `swarm-provider-ipc.js` (2,240 lines), `feed-store.js` (1,084), `permission-manifests.js` (761), `publish-service.js` (507), `feed-service.js` (482), `messaging-service.js` (417), `chunk-service.js` (355), `swarm-permissions.js` (345), `publish-history.js` (301), `gsoc-miner.js` (266) with `gsoc-miner-worker.js` (46), `subscription-registry.js` (244), `swarm-service.js` (234), `stamp-service.js` (114), `swarm-signer.js` (113), and three small helpers: about 7.6k lines, tests apart (0006 counted 6.7k);
  - the page side: `webview-preload.js` (`window.swarm`, 1806–1956), the chrome's `src/renderer/lib/swarm-provider.js` (415) and `wallet/swarm-connect.js` (the prompts);
  - bee-js's other users: `agent/swarm-publication-controller.js`, `agent/swarm-postage-readiness.js`, `adblock/update-manager.js`, `gateway-offer.js`; the node's own reads in `swarm/ant-storage-api.js`; the guard, `swarm/ant-api-guard.js` and `swarm/ant-api-main-dials.js`; 0009's executor, `core/dweb-shell.js` and `dweb/plan-executor.js`;
  - the page API, `docs/swarm-provider-api.md`;
  - SW-1: #950 on main (`d63fae37`), merged into integration with SEC-3c's adaptation (#1020, `499b3a42`: #89's refusal first).
- **`@ethersphere/bee-js` 13.2.0**, the lockfile's pin, from the npm tarball (the reference checkout has 13.1.0 installed; every file read here is the same in both): `utils/{http,headers,tar,tar-uploader,tar-writer,collection.node,stamps}.js`, `api/{bzz,bytes,chunk,soc,feed,tag,pss,stamp}.js`, `modules/messaging.js`, `feed/index.js`; and its `@ethersphere/core-sdk` 0.2.2 (`ChunkSplitter`, `getStampEffectiveBytes`).
- **freedom-core** at `de97fc9b` (`main`): `fc-swarm` (`lib.rs`, `verify.rs`, `tree.rs`, `manifest.rs`), `fc-protocol` (`methods.rs`, `stream.rs`), `freedom-cored/src/dweb/` (the thread and its hashing pool), designs 0001–0013, and 0014 as proposed in #274.

## Summary

- **Today** every `window.swarm` method runs in main (`executeSwarmMethod`, `swarm-provider-ipc.js:390`) over bee-js. bee-js brings its own HTTP stack: no deadline, no cancel, no body cap, and no proxy or Tor for a remote node (#360). Main keeps three stores, decides which key signs what, and asks the core to sign each SOC with `swarm.sign_soc`, naming the key and the identifier itself.
- **Ownership (proposed):** the core takes the method rules (validation in today's order, the grant and identity checks, the SW-1 rule), the three stores (0013's set A), every signature for a page, the choice of postage batch, building what goes to the node (the tar, the chunk tree, the SOC) and GSOC mining. Main keeps what belongs to a tab or a socket: the prompts, the documents (0011), the subscriptions and their WebSockets, message delivery, the node's lifecycle and readiness, and reading the user's own files for `freedom://publish`.
- **Node access:** the core asks main for each node call with `shell.swarm_api`: a method and a path from a closed set, never a URL. Main makes the call on the node's transport, as 0009's `shell.dweb_get` does: loopback for the bundled node, the session's network stack for a remote one, with the onion gate and the Ant guard. The core binds no port and opens no socket. The API is the Bee-compatible one that today's bundled node (`antd`) and an external Bee both serve; 0015 uses no Ant-only route.
- **Uploads** of up to 50 MiB stream: page → main (0011's ticketed request) → the core (`shell.swarm_part`, main's stream under the core's credit) → main (`swarm.body`, the core's stream) → the node. The core holds two 128 KiB windows and a small chunker state per upload, whatever its size, and runs at most four at once.
- **What streaming buys:** the core hashes what passes. A feed entry over one chunk then wraps the core's own root chunk, not the one the node sends back, and the node's reference for a `/bytes` or chunk upload is checked against the core's.
- **bee-js leaves main.** [Every call is mapped](#every-bee-js-call-mapped): uploads, feeds, SOCs and messaging to the core; stamp lists to the core's normalizer; main's own reads (the agent's chain-state checks, the ad-block list) to `ant-storage-api.js`'s client on the same transport.
- **GSOC mining** moves to a mining thread in the core: bee-js's exact search (keys from `0xb33`, at most 65,535 candidates), today's budgets per site, one job at a time, 15 s as a backstop only. Estimated under 0.1 s for a typical topic and under 2 s at the cap; SWM-2 measures both.
- **SW-1 in the core:** the core checks a raw SOC's identity against its own store in the same step as the signature, and computes every feed identifier itself. So no main bug can sign a page's SOC under another site's identity, and 0012's "a page's Swarm SOC: advised until 0015" becomes enforced.
- **The proof:** `vectors/swarm.json` from the JS reference: the browser's real modules over a recording fake node. Every method's outcome, every request bee-js sends (tar bytes included), the stores' bytes, the batch choices, GSOC signers and chunk-tree roots.
- **Steps SWM-1 to SWM-9:** vectors; `fc-swarm`'s write side; the provider crate; the core's thread and methods; main's executor; the stores through the core; the methods through the core behind a switch; main's own Swarm calls without bee-js; the switch and the removals.
- **Found while checking the code** ([Facts](#facts-found-while-checking-the-code)): any page can make main download a whole feed entry of any size before its read budget is charged (F-1); on Windows, `publishFiles` sends nested paths with backslashes (F-2); bee-js's tar writer cuts long non-ASCII file names (F-3); feed entries have no size limit (F-4). F-1, F-2 and F-4 have small browser fixes that shouldn't wait for this design.

## Goals and non-goals

**Goals**
- **The core decides and signs for pages:** what a site may do, with which key, over which bytes. Main's word stays only where 0012 leaves it: that the user approved.
- **Parity** with today's methods, results, errors and stores, shown by vectors from the JS reference, with every [deviation](#deviations) listed.
- **Bounded:** every node call has a deadline and a body cap, uploads stream under credit, and mining has a fixed bound.
- **Node calls obey the session:** proxy, Tor and the onion gate for a remote node, as 0009's pieces do.
- **No bee-js in main,** and no new listener anywhere.

**Non-goals**
- **The page-request path** (0011: who asked, documents, sizes, where prompts are drawn) and **the grant rules** (0012: `swarm-permissions.json`, auto-approve). 0015 uses both.
- **Where the stores live and how they are written** (0013). 0015 designs their methods.
- **The Swarm node.** Ant is left aside for now (the user, 2026-11-06): no change to `antd`, no Ant-only route, no new node feature. Its loopback API stays as it is ([What today's node needs](#what-todays-node-needs)).
- **Publish setup** (`publish-setup-service.js`: storage bought and extended through Ant's `/v0/storage/*`, the chequebook, readiness). It stays main's; the core only asks it whether the node can publish.
- **Checking a `/bzz` upload's manifest.** The node builds it, and its reference stays the node's word ([Options weighed](#options-weighed)).
- **A streamed page API** (a `Blob` or `ReadableStream` argument): [Q22](#open-questions).

## Today

### The methods

Twenty-one methods (`KNOWN_METHODS`, `swarm-provider-ipc.js:145–167`; the file is `spi` below). Today a request goes page → preload → chrome → main; 0011's PRQ-7 makes it page → main.

| Group | Methods | Main's work and node calls |
|---|---|---|
| Access | `requestAccess`, `getCapabilities` | the grant; `getCapabilities` also asks the publish pre-flight |
| Publish | `publishData`, `publishFiles`, `publishChunk`, `getUploadStatus` | validation, the pre-flight, a history row, `GET /stamps` (twice when no usable batch has room), then `POST /bzz?name=…`, `POST /bzz` with a tar, or `POST /chunks`; `GET /tags/<uid>` for the status |
| Reads, no grant | `readChunk`, `readData`, `readSingleOwnerChunk`, `readFeedEntry`, `listFeeds` | a read budget per site (`READ_BUDGETS`, `spi:93–104`: 600 requests and 5 MiB a minute for a connected site, 120 and 512 KiB otherwise), `GET /node` as a 5 s probe, then `GET /chunks/<ref>`, `GET /bytes/<ref>` or `GET /feeds/<owner>/<topic>`; `listFeeds` reads only the store |
| Feeds and SOCs | `createFeed`, `updateFeed`, `writeFeedEntry`, `writeSingleOwnerChunk`, `getSigningIdentity` | the feed grant, the site's identity, `swarm.sign_soc`, then `POST /feeds/<owner>/<topic>` (the feed's manifest) or `POST /soc/<owner>/<id>?sig=…` (Node's `fetch`, `chunk-service.js:83–126`); index lookups by `GET /feeds` and `GET /chunks` |
| Messaging | `getMessagingIdentity`, `sendPss`, `sendGsoc`, `subscribe`, `unsubscribe` | the messaging grant, `GET /addresses`, `POST /pss/send/<topic>/<targets>?recipient=…`, GSOC mining in a worker then `POST /soc/…`, and WebSockets to `/pss/subscribe/<topic>` and `/gsoc/subscribe/<address>` (Node's `WebSocket`, `messaging-service.js:289–313`) |

- **Limits** (`LIMITS`, `spi:70–85`): data 10 MiB; files 50 MiB in all and at most 100; paths 100 UTF-8 bytes; chunks 4,096 bytes; messages 4,000 bytes; PSS targets 2 or 3 bytes; 32 subscriptions per site. The plan's "50 MB" is 50 MiB, 52,428,800 bytes.
- **Automatic approvals:** ten methods may run under a site's auto-approve rule (`AUTO_APPROVABLE_METHODS`, `spi:210–221`). The chrome says which path a request took (`meta.approval`), and main refuses an automatic one from a tab in Agent custody (`agentCustodyRefusal`, `spi:223–233`).
- **The page's timer:** 300 s for the publishes, sends, feed and SOC writes, the two identities, `subscribe` and `readData`; 60 s for the rest (`webview-preload.js:1832–1844`). Main doesn't stop when the page gives up.
- **Private windows** get no `window.swarm` (`webview-preload.js:1915–1921`).
- **`publishFiles` goes through the disk:** main writes the files into a profile temp directory and uploads it with bee-js's `uploadFromDirectory` (`publish-service.js:239–261`, `:163–185`). That is why `validateVirtualPath` refuses Windows device names and trailing dots (`spi:643–704`). Each file's `contentType` is taken and ignored: the node types a tar entry by its extension (`publish-service.js:229–238`).

### The stores

| File | What | Written |
|---|---|---|
| `swarm-feeds.json` | `{ version: 2, nextPublisherKeyIndex, origins: { [key]: { activeIdentityId, identities, feedGranted, grantedAt, feeds } } }` (`feed-store.js:8–27`) | temp file and rename, no fsync; a file that doesn't parse is copied aside and replaced by an empty store (`feed-store.js:334–405`) |
| `swarm-manifest-grants.json` | `{ version: 1, records }`: each site's permission-manifest decisions and receipts (`permission-manifests.js:19–100`) | a `.bak` copy, a temp file and a rename, no fsync |
| `publish-history.sqlite` | table `publishes`, `user_version` 1, WAL (`publish-history.js:50–79`) | better-sqlite3; rows left `uploading` are swept to `failed` at open; no bound on rows |
| `swarm-permissions.json` | the connection grant and auto-approve flags | 0012's |

- **Identities:** `bee-wallet`, the node's wallet key, which every site shares by construction; or `app-scoped`, a publisher key at `m/44'/73406'/<n>'/0/0`, its index allocated from `nextPublisherKeyIndex`. A stored `ethereum-wallet` identity loads and fails on use (#89).
- **A feed** is `(owner, topic)`. Its topic is `keccak256(utf8(key + "/" + name))` (`feed-service.js:75–77`), and a name may not contain `/`. Freedom writes only sequence feeds. The plan's "epochs" are main's navigation epochs (`navEpoch`, `spi:1901–1919`), not Swarm epoch feeds.
- **Writes to one topic** wait for each other, in main only (`withWriteLock`, `feed-service.js:21–41`).

### Signing

- `swarm-signer.js` resolves an identity to a key reference (`bee_wallet`, or `publisher` with its index) and its owner address, asks the core for `swarm.sign_soc { key, identifier, payload, span }`, and checks the answer with bee-js and ethers (`swarm-signer.js:41–73`).
- The core computes the chunk address from the payload (0002), so it never signs a chunk that doesn't exist. But **main chooses the key and the identifier**: any `bee_wallet` or `publisher` key, for any 32 bytes.
- A feed entry over one chunk is uploaded through `POST /bytes`; main then downloads the root chunk the node names and has the core sign a SOC wrapping it (`feed-service.js:372–386`). The signature covers whatever root chunk the node returned.

### SW-1

In `handleWriteSingleOwnerChunk` (`spi:1013–1095`), after the params and the feed grant: #89's refusal of a stored `ethereum-wallet` identity first (`unavailableIdentityError`), then SW-1 (`spi:1041–1056`). The active identity is shared, and the raw SOC refused (4100, `data.reason: "shared_identity"`), unless it is `app-scoped`, has a numeric publisher key index, and no other site's identity holds that index (`isIdentitySharedWithOtherOrigins`, `feed-store.js:555–585`). `bee-wallet` is always shared. Then come the signer (which needs the unlocked vault) and the node's readiness. The prompt keeps Allow off for a raw SOC under a shared identity (`swarm-connect.js:112–130`).

**Why:** a raw SOC's identifier is the page's to choose. Under a key other sites sign with, it could be another site's feed entry, `keccak256(topic ‖ index)`, written as that owner. Feeds are safe under a shared key, since their topics carry the site's key.

### Facts found while checking the code

1. **F-1: any page can make main download a whole feed entry, of any size, before its read budget is charged.** `swarm_readFeedEntry` needs no grant. It charges one request, downloads the entry, and only then charges its bytes (`spi:1605–1621`). The download is whole and uncapped: at an explicit index, the SOC and then `GET /bytes` of the chunk it wraps, joined by the node (`feed-service.js:112–125`); the latest entry, whatever `GET /feeds` answers. bee-js reads either body into one buffer, with no cap and no deadline (`utils/http.js:54–57`, `:116–121`). A feed is any `(topic, owner)` the page names, and anyone can publish one SOC that wraps the root chunk of a large file already on Swarm. Every request passes the budget's check before any bytes are charged, so a page can start 120 such reads at once each minute, and main fetches and holds the file for each. `swarm_readData` doesn't have the gap: it reads the root chunk's span and reserves the size first (`spi:956–1007`). Found by reading the code. **Fix now:** read the SOC first and reserve from its span, as `readData` does.
2. **F-2: on Windows, nested `publishFiles` paths reach the node with backslashes.** bee-js builds the tar's names with the platform's `path.join` (`utils/collection.node.js:24–41`), so the temp directory's `assets/app.js` becomes `assets\app.js` on Windows, and an `indexDocument` below the top level doesn't match. Found by reading the code; not run on Windows. **Fix now:** upload the page's files with `publishCollection` (`publish-service.js:197–225`), which keeps the page's own paths and needs no temp directory.
3. **F-3: bee-js's tar writer cuts long non-ASCII names.** `splitPath` counts a path's UTF-16 units, while `createHeader` writes the name into 100 bytes (`utils/tar.js:53–116`). A name of at most 100 units but more than 100 UTF-8 bytes is cut silently: a 64-character name of 124 bytes came out as 100 bytes, its extension lost (run against the reference's bee-js). `window.swarm` can't hit it (paths are at most 100 bytes), but a `freedom://publish` directory and the agent's collections can. Upstream's bug; the core's tar writer counts bytes.
4. **F-4: feed entries have no size limit.** `swarm_writeFeedEntry` checks the data's type, never its size (`spi:1438–1530`). The API document leaves the limit to the node (`docs/swarm-provider-api.md:573–580`). A site with the feed grant and its auto-approve rule can upload any amount through it, past `publishData`'s 10 MiB. **Fix now:** the 10 MiB of `maxDataBytes`, with `payload_too_large`.
5. **F-5: an explicit-index feed write reads a 500 as a free index.** The overwrite check takes any 404 or 500 as "no entry" (`feed-service.js:355–366` with `isNotFoundError`, `:60–61`), while the head probe in the same file treats a 500 as unknown (`:137–147`). A node that can't fetch an existing entry lets the write go ahead at its index.
6. **F-6 (known, #360):** bee-js, the SOC upload, the reachability probe and the subscriptions' WebSockets use Node's own network stack, so a remote node gets no proxy and no Tor (`swarm-service.js:21–23`, `spi:2168–2172`).
7. **F-7 (known, 0006):** no `window.swarm` call to the node has a deadline or a cancel, apart from the 5 s probe and the 10 s tag read.

## Threat model

Stage 1 trusts main (0001). The attackers here are a page (any page reaches the reads; a granted site reaches the writes), a Swarm node that lies (an external node, or the bundled one taken over), and main's own bugs.

| Threat | Today | With 0015 |
|---|---|---|
| A main bug signs a page's SOC under another site's key or identifier | possible: main names both to `swarm.sign_soc` | the core picks the key from its own store by the page's key, and computes every feed identifier; a raw SOC only under an exclusive identity |
| A raw SOC overwrites another site's feed entry under a shared key | refused in main since #950 | refused by the core, in the same step as the signature, on its own store |
| A page exhausts main's memory with a read | F-1 | the core reserves the budget first and caps the node's body |
| A page uploads past the limits | F-4 | feed entries bounded at 10 MiB |
| A page burns CPU with new GSOC topics | a worker in main; up to ~5 s per topic; per-site budgets | the core's mining thread: the same budgets, one job at a time, a fixed candidate bound |
| A node lies about an upload's reference | taken as is; a feed entry's wrap signs the node's root chunk | `/bytes` and chunk references checked, the wrap built from the core's own root; a `/bzz` manifest stays the node's word |
| A call reaches the node's admin routes | bee-js can call any route | the core names only the [closed set](#shellswarm_api): no buying, chequebook, wallet or stake route. A core bug can spend postage on uploads, nothing else |
| A remote node's traffic leaves the session's policy | Node's `fetch` and `WebSocket`: no proxy, no Tor (F-6) | HTTP through the session's stack; the WebSockets stay as they are ([open question 4](#open-questions)) |
| Bulk data beside the vault | none in the core | credit windows; the swarm thread apart from the vault loop; a test pins `vault.lock` under two uploads and a mining job (0009's gate) |
| A crash mid-request | main's crash kills every request | a core restart ends the running Swarm requests; their history rows are `failed` at the next start, as today's sweep does; chunks the node already took stay, as when main dies today |

**What stays open:** the user's decision is main's word (0012). A `/bzz` manifest and a feed's latest entry are the node's word. A compromised main can do anything (0001). The subscriptions' sockets keep Node's stack.

**What gets worse:** an upload's bytes cross the pipe twice more, and the core shares its process with them; credit bounds what it holds, and 0009 estimated that the pipe is not the bottleneck. A core restart now ends uploads too. Hashing a 10 MiB feed entry costs the core about 0.1 s (an estimate).

## Ownership

### What moves into the core

- **Request validation:** every method's checks, in today's order, with today's codes, reasons and texts, so the first failing check gives the same error.
- **The rules:** the connection grant and the auto-approve flags (0012's store, read in the core), the feed and messaging grants, Agent custody for automatic approvals (0012's `agent`), the read budgets, the tag ownership map, the per-topic write order, the SW-1 rule.
- **The stores:** `swarm-feeds.json`, `swarm-manifest-grants.json` and `publish-history.sqlite` (0013's set A), with their methods for the chrome and the internal pages ([Methods main calls](#methods-main-calls)). The permission manifests' parsing, decisions and projection move with their store; main still fetches the manifest and shows its prompt.
- **Signing:** every SOC for a page, under the Bee wallet key, a publisher key, or a mined GSOC key.
- **Building what goes to the node:** batch choice from the node's `/stamps`, the tar, the chunk tree, SOC bodies, headers and queries; the node's answers read back (tags, feed indexes, errors).
- **GSOC mining.**

### What stays in main

- **The prompts** and where they are drawn (0011's approvals document), and the answer `user` or `auto` that main reports.
- **The documents** (0011): who asked, navigation, delivery. 0011's records replace `navEpoch`.
- **Subscriptions:** the WebSockets to `/pss/subscribe` and `/gsoc/subscribe`, their reconnects, the 32-per-site bound and message delivery (`messaging-service.js:289–403`, `subscription-registry.js`). The core can't hold a socket. It validates, checks the grant and derives the key to subscribe to.
- **The node:** its lifecycle (`ant-manager.js`), the pre-flight's readiness (`publish-setup-service.js`), publish setup, the Ant guard, and the transport to it.
- **Files on disk:** `freedom://publish` picks and reads the user's files, and streams them to the core.
- **The vault auto-lock timer's reset** after a successful write, as `spi:448–497` does today.

## The protocol

### Methods main calls

| Method | Callers | Params → result |
|---|---|---|
| `swarm.request` | page | `{ method, params, approval, deadline_ms }` → `{ result }` or `{ error: { code, message, data? } }`, today's shapes. For `swarm_subscribe`, `{ subscribe: { kind, key } }`, which main opens. `swarm_unsubscribe` never reaches the core |
| `swarm.publish` | shell | main's own uploads: `{ kind: "data" \| "file" \| "collection", parts, name?, content_type?, index_document?, encrypt?, pin, deferred, history? }` → `{ reference, tag_uid, batch, bytes }` |
| `swarm.feed` | shell | main's own feeds (the agent's): `{ op: "create" \| "update", key: { kind: "bee_wallet" }, topic, reference?, min_index? }` → `feed-service.js`'s results |
| `swarm.stamps` | chrome, shell | `{ id? }` → the node's batches, or one of them, as main reads them today (bee-js's `mapPostageBatch` fields Freedom uses, with `exists` and `propagating`) |
| `swarm.upload_status` | chrome, shell | `{ tag_uid }` → `normalizeTag`'s object (`publish-service.js:74–98`) |
| `swarm.identities` | chrome, shell | `{ op, … }`, one op per IPC handler of `feed-store.js:966–1050` → today's shapes |
| `swarm.history` | chrome, shell | `{ op: "list" \| "clear" \| "remove", id? }` → today's rows (`rowToEntry`) |
| `swarm.manifest` | shell | `{ op: "check" \| "decide" \| "list" \| "revoke", … }`; `check` takes the manifest's bytes (at most 8 KiB, `permission-manifests.js:20`) as main fetched them → display data and a token, as today |
| `swarm.body` | shell | `{ for }` → a head `{ bytes }`, then the body of the core's pending `shell.swarm_api` request `for`, as a stream |

- **`approval`** is `"user"` (main's prompt was answered) or `"auto"` (a standing rule). `auto` is admitted only when the grant's flag for the method's type is on and `agent` is false; otherwise `agent_custody` as today, or 4100 `no_rule`, which only a main bug reaches.
- **`deadline_ms`** is the page's own timer, 60 s or 300 s by today's list. A new deadline kind, `swarm`: 300 s, or the caller's shorter `deadline_ms`. `swarm.publish` has no total deadline (a picked file may be large), only the idle bound below.
- **No new event.** 0012's `approval.changed` tells main of a revoked grant, and main ends that key's subscriptions, as `onRevoke` does today (`spi:2219`).
- **Name checks:** main checks a name's IPNS binding before it sends the request (0011). The core checks again with 0012's `transport_key` after each wait on the node and before each effect (a signature, an upload, a store write).

### Requests the core makes

| Method | Params | Main does | Reply |
|---|---|---|---|
| `shell.swarm_api` | `{ for, method, path, query, headers, body, max_bytes, stream }` | one node call on the node's transport ([Node access](#node-access)) | `{ status, status_text, headers, body_base64 }` whole, or `{ status, status_text, headers }` and a stream; or `{ failed }` |
| `shell.swarm_part` | `{ for, part }` | streams one payload part of request `for` from what it holds: the page's IPC value, or a file it opened for `freedom://publish` | a head `{ bytes }`, then the bytes |
| `shell.swarm_ready` | `{ for, check: "publish" \| "reachable" }` | `getPublishReadiness()`, or the 5 s `GET /node` probe | `{ ok: true }` or `{ ok: false, reason }`, today's reasons |

- **`for`** is the envelope ID of a live `swarm.request` or `swarm.publish`. Main uses that request's backend, session and signal, so the core can't send a call to another node or session. A `for` that has ended is refused; it is a race, not a fault.
- **`body`** is absent, `{ base64 }` (at most 64 KiB), or `{ stream: <bytes> }`. With a stream, main sends `swarm.body { for: <this request's ID> }` and pipes the core's answer into the node's request.
- **Read strictly both ways,** as 0009 reads `shell.dweb_get`: an unknown member, a value of another type, a path outside the set, a header outside the set or past its bound, a status outside 100–599, or base64 that doesn't decode is `invalid_argument` from main and a protocol error in the core.

### Main's encoding of a request

Requests stay within one frame (0005), so bulk bytes can't ride in `params`. And the validators read JavaScript types (`typeof`, `Number.isInteger`, `Array.isArray`, key order, `undefined` against `null`, BigInt), which JSON loses. So main sends `params` in a typed form, which the vectors' `formats` define:
- **Bytes:** each value `normalizeBytes` accepts (`Buffer`, `Uint8Array`, `ArrayBuffer`, `{ type: 'Buffer', data: [...] }`, `spi:706–721`) where a method reads bytes (`data`, `files[i].bytes`) becomes `{ bytes: n, base64 }` up to 64 KiB, or `{ bytes: n, part: k }`, which the core pulls with `shell.swarm_part`.
- **A string** where a method reads data is its UTF-8, as `Buffer.from(s, 'utf-8')` makes it (a lone surrogate becomes U+FFFD, as today), marked as a string.
- **Everything else** is a tagged value: strings (lone surrogates as escapes, which `fc-json` reads, 0005), numbers with `-0`, NaN and the infinities, BigInts, `undefined`, arrays, and objects as key-value lists in their order. The core counts lengths in UTF-16 units where today's code reads `length`, and in UTF-8 bytes where it reads `Buffer.byteLength`.
- **0011's walk** has already refused what it doesn't take (a `Map`, a `Date`, another typed array) and bounded the request's size.

### Streams

0009's rule holds: a stream is the body of a response, sent by whichever side answers.
- **Into the core:** `shell.swarm_part`'s parts, and `shell.swarm_api`'s bodies with `stream: true` (`/bytes` reads). Main's abort codes are 0009's for its pieces: `cancelled`, `stalled`, `body_stream_error`.
- **Out of the core:** `swarm.body`, one per streaming upload. The core ends it with `cancelled`, `internal`, or `body_stream_error` when a part it was copying failed.
- **0007's rules per stream:** the head first, a 128 KiB window, data frames of 1 to 65,536 bytes, exactly one terminal.
- **The global bound:** the core's incoming Swarm streams take credit from their own allowance of 4 MiB, apart from the dweb thread's 16 MiB (0009). Outgoing, at most 4 `swarm.body` streams, 512 KiB of windows.
- `fc-protocol`'s `Codes` and `vectors/streams.json` gain the new methods' allowed and refused pairs.

### Deadlines and cancel

- **A request's node calls** share its deadline. Each streamed body also has 0009's idle bound, 60 s with credit outstanding and no bytes.
- **Main cancels** a `swarm.request` when its document goes (0011) or the page's timer ends. The core then cancels its open `shell.*` requests and streams, and answers `cancelled`. Nothing more is signed, uploaded or written after the cancel. A history row ends `failed` with the text `cancelled`.
- **An upload cut off** after the node took part of it leaves those chunks with the node, as a page closing does today. There is no rollback on Swarm.

## Node access

### `shell.swarm_api`

The closed set, checked in main before any dial. Hex is lowercase; `<owner>` 40 hex, `<ref>`, `<topic>` and `<id>` 64 hex.

| Method | Path and query | Body | Reply |
|---|---|---|---|
| GET | `/chunks/<ref>` | — | whole, at most 4,104 bytes |
| GET | `/bytes/<ref>` | — | a stream, at most `max_bytes` |
| GET | `/feeds/<owner>/<topic>` | — | whole, at most `max_bytes`; with `swarm-only-root-chunk: true` for an index lookup |
| GET | `/tags/<uid>`, `/addresses` | — | whole, at most 64 KiB |
| GET | `/stamps`, `/stamps/<batch>` | — | whole, at most 1 MiB |
| POST | `/bzz?name=<name>` | one file | whole JSON, at most 64 KiB |
| POST | `/bzz` | a tar | the same |
| POST | `/bytes`, `/chunks` | raw; `span ‖ payload` | the same |
| POST | `/soc/<owner>/<id>?sig=<130 hex>` | `span ‖ payload`, at most 4,104 bytes | the same |
| POST | `/feeds/<owner>/<topic>` | — | the same |
| POST | `/pss/send/<topic>/<4 or 6 hex>?recipient=<66 hex>` | at most 4,000 bytes | the same |

- **Request headers,** each at most once: `content-type`, `swarm-postage-batch-id`, `swarm-pin`, `swarm-deferred-upload`, `swarm-collection`, `swarm-index-document`, `swarm-only-root-chunk`, `range` for `/bytes` (0009's walk), and `swarm-encrypt` for `swarm.publish` only. Their values are the vectors'; transport headers (`content-length`, `transfer-encoding`) are main's.
- **Reply headers** the core reads: `content-type`, `content-length`, `swarm-tag`, `swarm-feed-index` and `swarm-feed-index-next`; at most 8, each name and value at most 8 KiB.
- **Error bodies** are read up to 64 KiB. The core builds each call site's text from them as today, so the page reads the same messages: bee-js's `<status_text>: <body>`, with a JSON body as `JSON.stringify(JSON.parse(body))` makes it (`utils/http.js:90–107`; `fc-json`'s JavaScript-compatible text, as 0008's reads use), and the SOC upload's own `SOC upload failed (<status>): <body>` (`chunk-service.js:114`).
- **`failed`** is 0009's closed set: `unreachable`, `error`, `aborted`, `too_large`. Each maps to the text the reference gives that class.
- **Never:** any other route. No `/stamps/<amount>/<depth>`, `/stamps/topup`, `/chequebook`, `/wallet`, `/stake` or `/v0/*`.

### The transport

- **The node's transport, as 0009's pieces use it** (`plan-executor.js`, `dweb-shell.js`): undici on loopback for the bundled node; for a remote external node, the session's stack (`net.request`) with its proxy, Tor and the onion gate.
- **POST is new on that path.** The Ant guard lets a frameless GET or HEAD of an announced URL through (`ant-api-main-dials.js`, `ant-api-guard.js:28–38`). Main's POSTs to a remote node would go through `session.webRequest` and be cancelled, so an announcement names its method too, and the guard lets through exactly that method to exactly that URL. Today's POSTs don't meet the guard only because bee-js uses Node's stack.
- **A body** is pulled from the core only as the node takes it; main holds at most one window per stream (0007's ring).
- **Main's own reads** (`ant-storage-api.js`'s `antRequest`, for readiness, setup and the agent) move onto the same transport in SWM-8. That closes F-6 for every HTTP call to the node.

### What today's node needs

The bundled `antd` serves its HTTP API on a loopback TCP port (1633 by default), without authentication, with admin routes beside the content routes (`ant-api-guard.js:5–11`). Main and Chromium reach it there, and the guard keeps pages off it. It is the node's design, outside this one and left as it is.

0015 makes it no worse. It adds no port and no listener; the core never learns the URL. Main's calls narrow from anything bee-js can send to the closed set, and no renderer gets a new way to the port. A node that later offered a pipe or an authenticated API would change main's transport only, not the core.

## Uploads

### The path

```
page ──IPC (0011 ticket)──▶ main ──shell.swarm_part (stream)──▶ core
                             │                                   │ checks, tar, chunk tree
node ◀──POST (transport)─────┤◀───────swarm.body (stream)────────┘
```

1. Main holds the page's request (0011 charges it and grants the ticket) and sends `swarm.request` with each file's size and part number.
2. The core validates, in today's order; asks `shell.swarm_ready { check: "publish" }`; adds the history row; reads `/stamps` once and chooses the batch.
3. The core sends `shell.swarm_api` for `POST /bzz` with `body: { stream: n }`. Main answers with `swarm.body`, and the core writes the body as it pulls each part with `shell.swarm_part`.
4. The node answers `{ reference }` and `swarm-tag`. The core updates the row, records the tag's owner, and answers.

### Building the body

- **The tar** is bee-js's `TarStream` byte for byte (`utils/tar.js`): ustar headers with mode `0000777`, owner and group `0001750`, the modification time from the core's clock, the checksum and type `0`; padding to 512 bytes; 1,024 zero bytes at the end. Entries are in the page's order, under the page's paths with `/`. A long name splits by UTF-8 bytes, or takes a GNU long-link entry as bee-js does past 100 units (F-3 fixed).
- **One file** (`publishData`, and a picked file for `freedom://publish`) is its bytes, with `name` in the query and the headers `bee.file.upload` sends (`api/bzz.js:19–40`): `content-type`, the batch, `swarm-pin: true`, and `swarm-deferred-upload` false for `publishData`, true for files and collections, as today.
- **The chunk tree** is Swarm's: leaves of 4,096 bytes, intermediate chunks of up to 128 references, each span the length below it, with no erasure coding and no encryption. It matches core-sdk's `ChunkSplitter`, which the vectors pin. The core builds it for a feed entry over one chunk, and for the address of a `publishChunk`.

### What the core checks

- **A feed entry over one chunk:** the core streams it to `POST /bytes`, computes the root chunk as the bytes pass, and refuses the write if the node's reference differs. The SOC wraps the core's root chunk. Today's second round trip, `GET /chunks` for the root (`feed-service.js:377`), goes.
- **A chunk:** the core computes its address and checks the node's.
- **A `/bzz` upload:** nothing beyond the answer's form. The node builds the manifest.
- **An encrypted upload** (the agent's private drafts, `swarm-encrypt: true`): nothing; the node picks the keys.

### Bounds

- **Sizes** stay today's: 10 MiB of data, 50 MiB and 100 files, paths of 100 bytes ([Q22](#open-questions)). Feed entries get the 10 MiB (F-4).
- **At most four uploads stream at once** in the core; the rest wait their turn. 0011 already lets main take only two page uploads at once across the browser.
- **Per upload:** one incoming and one outgoing window of 128 KiB, the chunker's leaf buffer and up to 128 references per level (at most seven levels below 2^64 bytes, so under 33 KiB), and one tar header: about 300 KiB.
- **Credit goes in only when it can go out:** the core grants credit on a part only while its `swarm.body` window has room. A node that stops reading holds one window in each direction, and the idle bound ends the upload after 60 s.
- **Main** holds the page's IPC value until the request ends (0011's charge) and one ring per stream. `normalizeBytes`'s copy of a `Uint8Array` and the temp directory go, so a 50 MiB upload costs main one copy fewer.

## Feeds, SOCs and SW-1

- **Feed writes** (`updateFeed`, `writeFeedEntry`): the core computes the topic from the page's key and the feed's name, the index from the node's answers (or the page's explicit index), and the identifier `keccak256(topic ‖ index as 8 bytes, big-endian)`. A page never names the identifier of a feed write. The key is the feed's identity recorded at creation, else the active one (`getFeedIdentity`, `spi:1204–1216`).
- **Index lookups** ask `GET /feeds` with `swarm-only-root-chunk: true`, as 0009's feed pieces do, and take the next index as `swarm-feed-index` + 1, today's own fallback (`feed-service.js:223–235`). Today the lookup downloads the latest payload whole just to learn its index. A 404 falls back to today's head probe over `GET /chunks` (`probeFeedHead`, `feed-service.js:170–187`). Writes to one topic go one at a time in the swarm thread.
- **Raw SOCs** (`writeSingleOwnerChunk`): the SW-1 rule, unchanged, in today's place in the order: after the params, the feed grant and #89's refusal; before the vault and the node. The swarm thread applies every store change, and holds them while a raw SOC is between its SW-1 check and its signature. So no identity can become shared in between, as it could today between main's check and the core's signature. 0012's table row for a page's SOC becomes **enforced**.
- **Keys:** a publisher key signs only inside `swarm.request`, for the page key whose identity holds its index. `swarm.feed` takes only the Bee wallet key (main's own feeds). A mined GSOC key signs only GSOC messages.
- **`swarm.sign_soc`** loses `chrome` at SWM-4: nothing in the chrome calls it, and main calls it as `shell` (`vault-backend.js:55–63`). It goes at SWM-9, once nothing calls it.
- **Reads:** `readChunk` and `readSingleOwnerChunk` check the chunk with `fc-swarm::verify` (an address, or a SOC's signature and address), as bee-js's `unmarshal*` does in main today. `readData` joins through 0009's verified file walk, its pieces as `shell.swarm_api` GETs, where today the node's `/bytes` join is taken on its length. A feed entry at an explicit index reads its SOC, reserves the budget from the span (as `readData` does), then joins. The latest entry stays the node's answer, as today, with `max_bytes` set to the room left in the site's read window (F-1 fixed).

## Messaging and GSOC mining

- **PSS:** the core validates and checks the grant, chooses the batch (a full mutable batch allowed, as today: `selectMessageBatch`, `messaging-service.js:232–238`), and sends `POST /pss/send/…`. The node mines the trojan chunk, as today.
- **GSOC:** the identifier is `keccak256(utf8(topic))` and the target `keccak256(utf8("freedom-gsoc-v1:" + topic))` (`messaging-service.js:38–54`), frozen. The core mines the signer, builds the chunk, signs the SOC with the mined key, and sends `POST /soc/…`. The page gets the address, never the key, as today. A mined key is public by construction (anyone mines the same one from the topic) and holds nothing of the vault.
- **Subscribe:** the core validates, checks the grant and derives the key (the GSOC address, or the PSS topic's hash) and answers `{ subscribe: { kind, key } }`. Main opens the socket and binds it to the document.

**Mining, in the core:**
- **Where:** a mining thread in `freedom-cored`. It is arithmetic on public inputs, with no parser of untrusted structure, so it needs no process of its own.
- **The search is bee-js's** (`modules/messaging.js:154–168`): private keys `0xb33 + i` for `i` below 65,535; the first whose SOC address shares at least 12 leading bits with the target wins; none is `gsoc_mining_failed`, as today. Same inputs, same signer, so every existing room keeps its address.
- **Time:** bee-js needs about 5 s for all 65,535 candidates on Electron's Node (`gsoc-miner.js:24–26`). In Rust, a candidate is one point step (the generator added to the last key's point gives the next key's) and two Keccak hashes. About 4,096 candidates are expected: estimated under 0.1 s, and under 2 s at the cap. SWM-2 measures both on three OSes.
- **Budgets, today's:** 16 new topics a minute per site (`messaging-service.js:108–109`), a cache of 128 topics (`:86`), a second request for a topic in flight joining the first, and fair turns across sites (`gsoc-miner.js:9–22`). One job at a time, so mining takes at most one CPU core. At most 256 jobs wait; beyond that, `busy`. A job past 15 s (`gsoc-miner.js:34`) is a bug and ends `gsoc_mining_timeout`.

## Every bee-js call, mapped

| bee-js in main | Node call | Replaced by |
|---|---|---|
| `file.upload` (`publish-service.js:121`, `:148`) | `POST /bzz?name=` | the core: `swarm.request` (`publishData`), `swarm.publish` (`freedom://publish`'s data and file) |
| `collection.uploadFromDirectory` (`:180`), `collection.upload` (`:216`) | `POST /bzz` with a tar | the core's tar writer: `swarm.request` (`publishFiles`), `swarm.publish` (a picked directory, read by main; the agent's collections) |
| `tag.get` (`:284`) | `GET /tags/<uid>` | the core: `getUploadStatus`, `swarm.upload_status` |
| `chunk.upload`, `makeContentAddressedChunk` (`chunk-service.js:130–133`, `:285`; `swarm-signer.js:50`) | `POST /chunks` | the core (`fc-swarm`) |
| `chunk.download`, `unmarshalContentAddressedChunk`, `unmarshalSingleOwnerChunk`, `calculateSingleOwnerChunkAddress` (`chunk-service.js:146–324`; `feed-service.js:115–140`; `messaging-service.js:160`) | `GET /chunks/<ref>` | the core: `fc-swarm::verify` |
| `data.download` (`chunk-service.js:257`; `feed-service.js:121`) | `GET /bytes/<ref>` | the core: 0009's file walk |
| `data.upload` (`feed-service.js:376`) | `POST /bytes` | the core, with its own root |
| `feed.createManifest` (`:264`), `feed.makeReader().downloadPayload` (`:304`, `:351`, `:409`, `:461`) | `POST`/`GET /feeds/<owner>/<topic>` | the core |
| `messaging.pssSend` (`messaging-service.js:252`), `gsocSend` (`:265`), `gsocMine` (`gsoc-miner-worker.js:22`) | `POST /pss/send`, `POST /soc` | the core and its mining thread |
| `connectivity.getNodeAddresses` (`messaging-service.js:225`) | `GET /addresses` | the core (`getMessagingIdentity`) |
| `stamp.getAll` (`stamp-service.js:80`, `swarm-service.js:142`) | `GET /stamps` | the core: `swarm.stamps`, and batch choice inside each write |
| `stamp.get` (`agent/swarm-postage-readiness.js:66`, `:91`) | `GET /stamps/<id>` | the core: `swarm.stamps { id }`, the same normalizer |
| `stamp.getGlobal`, `status.getChainState` (`agent/swarm-postage-readiness.js:91–92`) | `GET /batches/<id>`, `/chainstate` | main: `ant-storage-api.js`'s client, the raw JSON, with the fields the agent reads mapped as bee-js maps them |
| `data.download` (`agent/swarm-publication-controller.js:243`) | `GET /bytes/<ref>` | main: the same client, its body discarded (a reachability check) |
| `data.downloadReadable` (`adblock/update-manager.js:98–99`) | `GET /bytes/<ref>`, streamed | main: the same client, streamed, with today's deadline |
| `readFeedPayload` and `Topic.fromString` for the ad-block list's feed (`adblock/update-manager.js:81–86`) | `GET /feeds/<owner>/<topic>` | main: the same client; the topic as `keccak256(utf8(…))` with ethers, which main already loads |
| `Topic` (`spi:39`) | — | goes with the provider |
| `Reference` decoding `bah5…` CIDs (`gateway-offer.js:43–91`) | — | a small decoder in main (multibase base32, Swarm's two codecs, the Keccak multihash), with vectors from bee-js's `Reference` |
| `PrivateKey`, `Identifier`, `EthAddress`, `FeedIndex`, `Bytes` (types) | — | gone with their modules |

## In the core

### Crates

- **`fc-swarm`** (logic, exists) gains the write side: the chunk tree, the tar writer, feed topics and identifiers, update payloads, SOC bodies, and `gsoc::mine(target, identifier, proximity)` with its fixed bound.
- **`fc-swarm-provider`** (logic, new): the method machines, sans-I/O. Each machine asks for what it needs (a node call, a part, a readiness answer, a store read or write, a signature, the clock) and is handed the answer. It holds validation and texts, the rules and SW-1, batch choice (`selectBestBatch`, `swarm-service.js:140–213`, over bee-js's `mapPostageBatch` arithmetic, IEEE doubles included), tag and error mapping (`nodeWriteError`, `mapChunkReadError`, `isBatchNotYetKnownError`), and the three stores' codecs and rules. 0012's `fc-approval` supplies the connection grant. It builds for iOS and Android, as AGENTS rule 2 requires.
- **`freedom-cored`** runs them on a **swarm thread** beside naming's, chain's and dweb's, with the **mining thread** beside it. Chunk-tree hashing goes to 0009's hashing pool. The stores go through 0013's `fc-store` (durable writes, today's text byte for byte, SQLite through `rusqlite` with the schema kept, one writer).

### Budgets

| What | Bound (proposed) |
|---|---|
| Running `swarm.request` and `swarm.publish` | 64; 256 wait; beyond that `busy`: 4900 with `data.reason: "busy"` |
| Outstanding `shell.swarm_api` | 64 |
| Uploads streaming | 4 |
| The swarm thread's memory for requests and bodies | 32 MiB, reserved before use, apart from the stores |
| `swarm-feeds.json` | 16 MiB; a write past it refused (`store_full`) |
| `swarm-manifest-grants.json` | 1 MiB, the same way |
| `publish-history.sqlite` | 10,000 rows; the oldest finished rows go first |
| Mining | one job at a time; 256 waiting |

Today none of these exist. SWM-4 measures the uploads and replaces the numbers if needed.

## Vectors

`vectors/swarm.json`, generated from the JS reference (AGENTS rule 5) by `vectors/generator/swarm.js`, with the harness `naming.json` uses: the browser's own modules at the pin, Electron stubbed, no reference code copied. Global `fetch` and `WebSocket` are a recording fake node with scripted answers, the clock is fixed, and signatures come from bee-js's own signer with the test keys of `keys.json`.
- **`methods`:** each method, with params in the typed form, the stores before, the grants, the approval path and the scripted node. It records the result or error; every node request (method, path, query, headers, and the body's bytes, or its length and SHA-256); the stores' text after; the history rows. Tables of bad params, one failing check per case, pin the order of checks.
- **`bodies`:** the tars bee-js writes for `window.swarm`'s path forms; single-file uploads; the `/bytes` path of a large feed entry; SOC, chunk and PSS bodies.
- **`trees`:** core-sdk's `ChunkSplitter` roots and root chunks over seeded data of 0, 1, 4,095, 4,096, 4,097, 524,288, 524,289 bytes and 10 MiB.
- **`stamps`:** `mapPostageBatch` over recorded `/stamps` answers (usable, propagating, full immutable, full mutable, missing fields), and `selectBestBatch` with each option over them.
- **`feeds`:** topics, identifiers, update payloads, the index runs of `resolveNextIndex` and `probeFeedHead` over scripted nodes.
- **`gsoc`:** `gsocMine`'s signers and addresses for topics (empty, Unicode, at 256 bytes), and at higher proximities, so the cap and the failure are covered.
- **`errors`:** bee-js's error texts for statuses, reason phrases and bodies (JSON, text, empty, past 64 KiB), with `nodeWriteError`'s and `mapChunkReadError`'s mappings.
- **`stores`:** `swarm-feeds.json` and `swarm-manifest-grants.json` after each operation, the v1 migration, a file that doesn't parse; `publish-history.sqlite`'s rows and schema.
- **Deviations** are marked (`deviation: <id>`), with the reference's own outcome beside the core's.

`generate.js check` passes, and `check.test.js`'s damaged copies fail it.

## Deviations

| Id | Today | With the core |
|---|---|---|
| `feed-read-bound` | a feed entry of any size downloaded before the budget is charged (F-1) | reserved from the span first, or cut at the window's room |
| `feed-entry-bound` | no size limit (F-4) | 10 MiB, `payload_too_large` with `limit` and `actual` |
| `tar-paths` | the temp directory's listing order; backslashes on Windows (F-2); names cut by bee-js (F-3) | the page's order and paths; names counted in bytes |
| `feed-wrap-root` | the SOC wraps the root chunk the node sends back | the core's own root; a different node reference refused |
| `reference-check` | `publishChunk` answers its own address and ignores the node's; a `/bytes` upload's reference is taken as the node gives it (a SOC's is already checked, `chunk-service.js:120–123`) | both checked; a mismatch is -32603 `The Swarm node returned another reference` |
| `read-data-verified` | `/bytes` joined by the node, its length checked | 0009's verified walk; bad data is `chunk_type_mismatch` |
| `index-check-500` | a 500 at an explicit index reads as free (F-5) | unknown: the write fails with the node's error |
| `index-probe` | the latest payload downloaded whole to learn its index | the root chunk only |
| `stamps-one-read` | `GET /stamps` once or twice per write | once |
| `deadlines` | none (F-7) | the page's timer; a 60 s idle bound on streams; cancel when the document goes |
| `busy` | none | 4900, `reason: "busy"` |
| `session-transport` | Node's `fetch` for every HTTP call (F-6) | the node's transport |
| `transport-error-text` | undici's message for each failure | one text per failure class |
| `history-bound` | no bound | 10,000 rows |
| `store-writes` | temp file and rename, no fsync | 0001's durable write (0013) |

## Changes from today

What a page can see. Everything else stays: the methods, params, results, error codes, reasons and texts, the limits, the prompts.
- A feed entry over 10 MiB is refused (`payload_too_large`).
- A feed read that can't fit the site's read window is refused before the download (`data_too_large` or `rate_limited`).
- `readData` checks every chunk.
- Nested `publishFiles` paths work on Windows, and entries go in the page's order.
- A request stops at the page's own timeout and when its document goes: nothing more is uploaded, signed or sent.
- `busy` when the core's Swarm queue is full.
- A node that answers with the wrong reference for a chunk or a large feed entry gets the write refused.
- An explicit-index feed write fails when the node can't say whether the index is taken.
- A transport failure's message is one fixed text for each kind of failure.

## Migration

**Ahead of the steps,** in the browser on `integration/rust-core`: F-1's fix (read the SOC first, reserve from its span), F-2's (`publishCollection` for `publishFiles`) and F-4's (the 10 MiB bound). Each is small, and none waits for this design. F-3 is upstream's (bee-js), and goes away for Freedom with SWM-8.

| Step | Where | What | Depends | Done when |
|---|---|---|---|---|
| SWM-1 | core | `vectors/swarm.json`, its generator and fixtures | — | `generate.js check` passes; damaged copies fail it; every case above is present |
| SWM-2 | core | `fc-swarm`'s write side: the chunk tree, the tar writer, feed identifiers and payloads, SOC bodies, GSOC mining | SWM-1 | `trees`, `bodies`, `feeds` and `gsoc` pass byte for byte; mining at the cap measured on Linux, macOS and Windows CI and recorded here, a failure past 2 s reported |
| SWM-3 | core | `fc-swarm-provider`: the machines, validation, the rules and SW-1, batch choice, the stores' codecs | SWM-1; APR-2 (`fc-approval`'s Swarm grants) | `methods`, `stamps`, `errors` and `stores` pass; SW-1's cases (Bee wallet, a shared index, an exclusive index, a missing index, #89's identity first) give today's errors in today's order; a property test shows no machine names a path outside the set; iOS and Android builds pass |
| SWM-4 | core | the swarm and mining threads; the methods and `shell.swarm_*` requests; `swarm.body`; the deadline kind; budgets; the stores through `fc-store`; `chrome` off `swarm.sign_soc`; a release | SWM-2, SWM-3; PRF-5 (`fc-store`) | every vector over the pipe against a scripted main; a 50 MiB `publishFiles` of 100 files streams with the core's resident memory up less than 4 MiB; `vault.lock` answered within 0009's gate during two uploads and a mining job; a cancel at each step leaves no `shell.*` request open and nothing signed or uploaded after it; every malformed reply is a protocol error; a stalled node ends an upload after 60 s idle |
| SWM-5 | browser | main's executor (`core/swarm-shell.js`): the closed set, POST on the node's transport, the guard's method-bound announcements, `shell.swarm_part` from held requests and picked files, `shell.swarm_ready`; the pin; behind a switch, nothing moved | SWM-4's release | the executor's suite: a path, header or body outside the set refused before a dial; with a remote node and a session proxy, every call goes through the proxy; an announced POST passes the guard, and the same POST to another URL, another method, or from a frame doesn't; a node that stops reading holds one window in main; against the bundled node, an index lookup with `swarm-only-root-chunk` returns `swarm-feed-index` |
| SWM-6 | browser | the stores through the core, one writer: `feed-store.js`, the manifest store and `publish-history.js` become clients of `swarm.identities`, `swarm.manifest` and `swarm.history`; the JS provider uses them | SWM-5; APB-3 (`swarm-permissions.json` in the core); 0013's PRF-6 pattern | each module's suite against the core; an `fs` spy shows main opens none of the three files; **rollback:** the reference modules read what the core wrote and see the same state |
| SWM-7 | browser | `window.swarm` through the core behind the switch: main's dispatcher (0011's PRQ-7) sends `swarm.request`; subscriptions open what the core derives; the GSOC worker idle | SWM-6; PRQ-7; APR-3 (`PageContext.agent`) | the provider suites (`swarm-provider-ipc`, `feed-service`, `chunk-service`, `messaging-service`, `publish-service`) pass against both backends as one contract suite, deviations marked; e2e on three OSes against the bundled node: `publishFiles` with nested paths gives the same reference as the JS backend on Linux and macOS, and its nested files resolve on Windows; F-1's and F-4's cases refused before any download or upload; SW-1's cases through the pipe; a document that navigates mid-upload stops it |
| SWM-8 | browser | main's own Swarm calls without bee-js: `freedom://publish` (`swarm.publish`, `swarm.upload_status`, `swarm.stamps`), the agent's publication controller and postage readiness, `stamp-service.js`, the ad-block list, `gateway-offer.js`; `ant-storage-api.js` on the node's transport | SWM-7 | each module's suite; the agent publication e2e; `git grep "@ethersphere/bee-js" src/` finds only the provider's JS backend; a `freedom://publish` directory with a 124-byte name keeps it (F-3) |
| SWM-9 | browser, then core | the core's backend by default; then the JS backend removed (bee-js's parts of `publish-service.js`, `chunk-service.js`, `feed-service.js`, messaging's sends, `gsoc-miner.js` and its worker, `swarm-service.js`'s client, `swarm-signer.js`), bee-js out of `package.json`, the lockfile and the license audit; then `swarm.sign_soc` removed from the core | SWM-8 shipped; Q21 | `git grep bee-js` finds only the changelog and docs; unit and e2e suites on three OSes; the core answers `swarm.sign_soc` with `unknown_method` |

**Rollback:** each core step is additive until the browser step that uses it. SWM-6 is one-writer, so going back past it needs the reference modules to read the core's files, which its rollback test shows. Before SWM-9, the switch turns the JS backend back on.

## Amendments

Once decided:
- **0011:** PRQ-7's dispatcher sends `swarm.request`. Its size table gives `swarm_writeFeedEntry` `publishData`'s class (10 MiB plus 64 KiB, a ticket), to match F-4's bound. The two uploads' charges lose `normalizeBytes`'s copy.
- **0012:** *What the core enforces*: a page's Swarm SOC is enforced from SWM-7. The manifest's projection is written inside the core, no longer as `shell` through `approval.grant`.
- **0013:** set A's Swarm stores have their methods here, and move with the others at PRF-9.
- **0009:** *Streams in the core*'s list of streaming methods gains `shell.swarm_part`, `shell.swarm_api` with `stream: true`, and `swarm.body`, with their abort codes.
- **0002:** `swarm.sign_soc` loses `chrome` at SWM-4 and goes at SWM-9.
- **0006:** its *Later designs* bullet for 4.6 points here.

## Options weighed

- **Main keeps building uploads** in its own JS, and posts the page's bytes itself; the core validates and signs only. No bytes through the core, but no root or reference check, a feed entry's wrap still signs the node's root chunk, and the tar and chunk logic stay in JavaScript, which mobile can't use.
- **The core chunks everything and uploads chunks** (`POST /chunks` one by one, or the node's chunk-stream socket): every reference the core's own, manifests included. But about 13,000 requests per 50 MiB, a manifest builder that must match the node's byte for byte, and a WebSocket main would have to run. A later step, if publishes are to be verified as 0009's reads are.
- **Request bodies as streams in `fc-protocol`:** one envelope fewer per upload than `swarm.body`, but it breaks 0009's rule that a stream is a response body, and its rule on whose ID space a stream's ID belongs to.
- **A Swarm service process:** isolation for little parsing of untrusted input (JSON params, chunks the core already checks for 0009), at the cost of a process that needs the core's keys and stores anyway. 0009 made the same call for its verifier.
- **The core talks to the node directly:** the core opens no socket (0001), a remote node needs the session's proxy and Tor, and the guard watches main's dials.
- **Mining in main without bee-js,** or in a process of its own: either keeps a second copy of the search outside the shared crates, for arithmetic that needs no isolation.
- **A Swarm token kind** in 0012's model, binding a prompt's answer to the request: closer to 0012's dApp signatures, but 0012 leaves Swarm on main's word in Stage 1, and the prompts' moves (0011's APS) come first.
- **The latest feed entry checked:** the core could ask the node for the head's index, read that SOC by address and check it. But the page's result is today whatever `GET /feeds` answers, which for a legacy `ts ‖ ref` update the node may resolve further (`feed-service.js:149–160`), so the result could change. Bounded instead.

## Open questions

1. **Q21, the API:** Must `window.swarm` keep its exact API and prompts? *Proposed: yes: the same methods, params, results, errors and prompts, with only the [changes listed](#changes-from-today).*
2. **Q22, the size:** Is 50 MB still right per publish once uploads stream through the core? *Proposed: keep 50 MiB. The core's and main's second copies go, but the page still hands main the whole upload in one message; a larger limit needs a page API that streams, which is a new API.*
3. **Feed entries:** May the core cap a feed entry at 10 MiB, the same as `publishData`, where today there is no cap? *Proposed: yes, now, as F-4's browser fix.*
4. **Subscriptions over a proxy:** Message subscriptions to a remote node go around your proxy and Tor today; should Freedom refuse them while a proxy or Tor is on? *Proposed: yes, until main can carry WebSockets through the session; a remote node behind a proxy then has no subscriptions.*
