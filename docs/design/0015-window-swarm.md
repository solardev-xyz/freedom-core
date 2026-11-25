# 0015: The `window.swarm` backend in the core

**Status:** proposed. Roadmap item 4.6: the Swarm provider's backend leaves Electron main for `freedom-cored`. Builds on [0001](0001-freedom-cored.md) (the process, frames, deadlines, durable writes), [0002](0002-signing.md) (`swarm.sign_soc`, key references), [0005](0005-chain-data.md) (requests the core makes of main, main's pool), [0007](0007-ipfs-service.md) (stdio only, the stream frames), [0009](0009-dweb-verification.md) (protocol 2's streams in both directions, the hashing pool, `fc-swarm`'s checks), [0011](0011-page-requests.md) (page requests: the attested key, documents, sizes and tickets, PRQ-7), [0012](0012-approvals.md) (the Swarm grants in the core) and [0013](0013-profiles.md) (`fc-store`, set A). It answers 0006's *Later designs* bullet for 4.6, and, for a page's SOCs, 0012's "main names the key and the identifier until 0015": 0012 already enforces them from APR-4, by the page's Swarm grant. The work is the Rust core under Electron: nothing here assumes a Chromium move, and nothing needs a change to the Swarm node. Nothing here is built yet. The user decides the [open questions](#open-questions), and each answer is due before the step whose contract it changes ([Migration](#migration)). Question 3 was decided on 2026-11-10, and Q21, Q22 and question 4 on 2026-11-24, all as proposed; question 4 with the user's condition that Freedom says so whenever it applies ([Messaging](#messaging-and-gsoc-mining)).

**The references:**
- **freedom-browser** at `b39bf724` (`integration/rust-core`); the Swarm files are the same at today's `e670715d`:
  - `src/main/swarm/`: `swarm-provider-ipc.js` (2,240 lines), `feed-store.js` (1,084), `permission-manifests.js` (761), `publish-service.js` (507), `feed-service.js` (482), `messaging-service.js` (417), `chunk-service.js` (355), `swarm-permissions.js` (345), `publish-history.js` (301), `gsoc-miner.js` (266) with `gsoc-miner-worker.js` (46), `subscription-registry.js` (244), `swarm-service.js` (234), `stamp-service.js` (114), `swarm-signer.js` (113), and three small helpers: about 7.6k lines, tests apart (0006 counted 6.7k);
  - the page side: `webview-preload.js` (`window.swarm`, 1806–1956), the chrome's `src/renderer/lib/swarm-provider.js` (415) and `wallet/swarm-connect.js` (the prompts);
  - bee-js's other users: `agent/swarm-publication-controller.js`, `agent/swarm-postage-readiness.js`, `adblock/update-manager.js`, `gateway-offer.js`; the node's own reads in `swarm/ant-storage-api.js`; the guard, `swarm/ant-api-guard.js` and `swarm/ant-api-main-dials.js`; 0009's executor, `core/dweb-shell.js` and `dweb/plan-executor.js`;
  - the page API, `docs/swarm-provider-api.md`;
  - SW-1: #950 on main (`d63fae37`), merged into integration with SEC-3c's adaptation (#1020, `499b3a42`: #89's refusal first);
  - the fixes for F-1, F-2 and F-5: #1056 (into main, head `28fe269b`) and #1057 (into integration, head `4b91bd27`), both open: `feed-service.js`'s metered feed reads and `feedEntryExists`, and `publishFilesFromContent` through `publishCollection`; since their first round, a one-chunk entry is held to its wrapped span, and a feed write refuses only an empty payload itself, telling a page's fault from a node's answer by `reason`.
- **`@ethersphere/bee-js` 13.2.0**, the lockfile's pin (integrity `sha512-GAl6xkAW…`), read from the registry's tarball, which has that integrity: `utils/{http,headers,error,tar,tar-uploader,tar-writer,collection.node,stamps}.js`, `api/{bzz,bytes,chunk,soc,feed,tag,pss,stamp}.js`, `modules/messaging.js`, `feed/index.js`; and its `@ethersphere/core-sdk` 0.2.2 (`ChunkSplitter`, `getStampEffectiveBytes`).
  - **The reference checkout has 13.1.0 installed, and it is not the same.** Eleven `dist/cjs` files differ. Three are on the provider's path:
    - `utils/http.js`: 13.2.0's `throwHttpError` reads an error body as text and then parses it as JSON, where 13.1.0 decoded it by the call's response type. So at an array-buffer call site (chunk and `/bytes` downloads) the error's data and message differ, and with them `isChunkNotFoundError`: a 500 `read chunk failed` from `GET /chunks` is `chunk_not_found` under 13.2.0 and a node error under 13.1.0 ([Vectors](#vectors));
    - `modules/messaging.js`: `gsocSubscribe` takes options for the node's SOC fields. The mining loop is the same;
    - `utils/error.js`: the error classes set `name`.
  - The other files listed are the same in both. The vectors are made against 13.2.0 only ([Vectors](#vectors)).
- **freedom-core** at `dbd43de7` (`main`): `fc-swarm` (`lib.rs`, `verify.rs`, `tree.rs`, `manifest.rs`), `fc-protocol` (`methods.rs`, `stream.rs`), `freedom-cored/src/dweb/` (the thread and its hashing pool), designs 0001–0013, and [0014](0014-colibri-verifier.md) (proposed, #274: its fetch contract and main's Colibri fetch pool, which this design's [call grammar](#the-operation-grammar) and [Swarm I/O pool](#mains-swarm-io-pool) follow).

## Summary

- **Today** every `window.swarm` method runs in main (`executeSwarmMethod`, `swarm-provider-ipc.js:390`) over bee-js. bee-js brings its own HTTP stack: no deadline, no cancel, no body cap, and no proxy or Tor for a remote node (#360). Main keeps three stores, decides which key signs what, and asks the core to sign each SOC with `swarm.sign_soc`, naming the key and the identifier itself.
- **Ownership (proposed):** the core takes the method rules (validation in today's order, the grant and identity checks, the SW-1 rule), the three stores (0013's set A), every signature for a page, the choice of postage batch, building what goes to the node (the tar, the chunk tree, the SOC) and GSOC mining. Main keeps what belongs to a tab or a socket: the prompts, the documents (0011), the subscriptions and their WebSockets, message delivery, the node's lifecycle and readiness, and reading the user's own files for `freedom://publish`.
- **Node access:** the core asks main for each node call with `shell.swarm_api`, never with a URL. Main admits a call only if the live operation it serves allows it at that operation's current step: a [normative grammar](#the-operation-grammar) of route forms, bound values, headers, body forms and lengths, reply caps, streaming, and the number and order of calls. A permission-free read can't publish, read stamps or send a message, and reaches only the chunks its own reference, feed index or file tree names. Where an address follows from a reply main itself returned, main computes it and holds the core to it. Main makes the call on the node's transport, as 0009's `shell.dweb_get` does: loopback for the bundled node, the session's network stack for a remote one, with the onion gate and the Ant guard. The core binds no port and opens no socket. The API is the Bee-compatible one that today's bundled node (`antd`) and an external Bee both serve; 0015 uses no Ant-only route.
- **Memory in main:** whole node replies are paid for before the dial from a [Swarm I/O pool](#mains-swarm-io-pool) of 64 MiB in main, which counts the body, its base64 and the serialized reply at once; streams take a fixed charge; a full pool is `busy`. The core reserves its own copies, by a [stated lifecycle](#the-swarm-threads-memory), before it asks. #1056 and #1057 bound one site's feed reads; the pool bounds every site and every reply.
- **Uploads** of up to 50 MiB stream: page → main (0011's ticketed request) → the core (`shell.swarm_part`, main's stream under the core's credit) → main (`swarm.body`, the core's stream) → the node. The core holds two 128 KiB windows and a small chunker state per upload, whatever its size, and runs at most four at once.
- **What streaming buys:** the core hashes what passes. A feed entry over one chunk then wraps the core's own root chunk, not the one the node sends back, and the node's reference for a `/bytes` or chunk upload is checked against the core's.
- **bee-js leaves main.** [Every call is mapped](#every-bee-js-call-mapped): uploads, feeds, SOCs and messaging to the core; stamp lists to the core's normalizer; main's own reads (the agent's chain-state checks, the ad-block list) to `ant-storage-api.js`'s client on the same transport.
- **GSOC mining** moves to one mining lane in the core: bee-js's exact search (keys from `0xb33`, at most 65,535 candidates), run in batches of 256 candidates with the job's deadline and cancel checked between batches, so a job stops within one batch and the lane goes on. Today's budgets stay (16 new topics a minute per site, a cache of 128, joins, fair turns, 15 s a job). New: at most 16 jobs waiting per site and 256 in all, then `busy`. Measured by SWM-2 on three OSes: at most 26 ms for a topic at proximity 12 and 198 ms at the cap ([Messaging and GSOC mining](#messaging-and-gsoc-mining)).
- **SW-1 in the core:** the core checks a raw SOC's identity against its own store in today's place, checks again in the step that sends the signature, and holds every identity change that could make it shared until the vault answers. It computes every feed identifier itself. So no main bug can sign a page's SOC under another site's identity. 0012 already enforces a page's SOC from APR-4, under `page` with the page's Swarm grant checked by the core, but main still names the key and the identifier; here the core chooses both. A [deterministic interleaving gate](#sw-1-in-the-core) tests it.
- **The proof:** `vectors/swarm.json` from the JS reference at bee-js 13.2.0 exactly: the browser's real modules over a recording fake node. Every method's outcome, every request bee-js sends (tar bytes included), the stores' bytes, the batch choices, GSOC signers and chunk-tree roots.
- **Steps SWM-1 to SWM-9:** vectors; `fc-swarm`'s write side; the provider crate; the core's thread and methods; main's executor; the stores through the core; the methods through the core behind a switch; main's own Swarm calls without bee-js; the switch and the removals.
- **Found while checking the code** ([Facts](#facts-found-while-checking-the-code)): any page could make main download a whole feed entry of any size before its read budget was charged (F-1); on Windows, `publishFiles` sent nested paths with backslashes (F-2); an explicit-index feed write read a 500 as a free index (F-5). #1056 and #1057 fix all three. Feed entries had no size limit (F-4): [question 3](#open-questions) decided the 10 MiB cap, which #1233 brought to browser main but not yet to `integration/rust-core`. bee-js's tar writer cuts long non-ASCII file names (F-3), the publisher index counter is trusted as stored (F-8), and bee-js sends a PSS recipient in a form the bundled node refuses (F-9, #1062).

## Goals and non-goals

**Goals**
- **The core decides and signs for pages:** what a site may do, with which key, over which bytes. Main's word stays only where 0012 leaves it: that the user approved.
- **Parity** with today's methods, results, errors and stores, shown by vectors from the JS reference, with every [deviation](#deviations) listed.
- **Bounded:** every node call has a deadline and a body cap, is paid for before it's made in main and in the core, and is one the live operation allows; uploads stream under credit; and mining stops within a fixed amount of work.
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
- **`publishFiles` goes through the disk:** main writes the files into a profile temp directory and uploads it with bee-js's `uploadFromDirectory` (`publish-service.js:239–261`, `:163–185`). That is why `validateVirtualPath` refuses Windows device names and trailing dots (`spi:643–704`). Each file's `contentType` is taken and ignored: the node types a tar entry by its extension (`publish-service.js:229–238`). #1057 uploads through `publishCollection` instead (F-2); the path rules stay. *At SWM-1's reference (PRQ-7c):* a page's `publishData` and `publishFiles` go through main's `page-upload.js` instead, over Node's own `http` with the bytes main holds and its own tar writer, making the requests bee-js made; SWM-1's vectors check that its tar equals bee-js's for every page path. `freedom://publish` and the agent still use bee-js (`publish-service.js`).

### The stores

| File | What | Written |
|---|---|---|
| `swarm-feeds.json` | `{ version: 2, nextPublisherKeyIndex, origins: { [key]: { activeIdentityId, identities, feedGranted, grantedAt, feeds } } }` (`feed-store.js:8–27`) | temp file and rename, no fsync; a file that doesn't parse is copied aside, and the empty store that replaces it is written at the next change (`feed-store.js:334–405`) |
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

In `handleWriteSingleOwnerChunk` (`spi:1013–1095`), after the params and the feed grant: #89's refusal of a stored `ethereum-wallet` identity first (`unavailableIdentityError`), then SW-1 (`spi:1041–1056`). The active identity is shared, and the raw SOC refused (4100, `data.reason: "shared_identity"`), unless it is `app-scoped`, has a numeric publisher key index, and no other site's identity holds that index (`isIdentitySharedWithOtherOrigins`, `feed-store.js:555–585`). `bee-wallet` is always shared. Then come the signer (which needs the unlocked vault), the node's readiness, and in `writeSingleOwnerChunk` the signature, the batch and the upload (`chunk-service.js:283–303`). The prompt keeps Allow off for a raw SOC under a shared identity (`swarm-connect.js:112–130`).

**Why:** a raw SOC's identifier is the page's to choose. Under a key other sites sign with, it could be another site's feed entry, `keccak256(topic ‖ index)`, written as that owner. Feeds are safe under a shared key, since their topics carry the site's key.

**Where a shared index comes from:** no chrome or page path gives a second site an index another site holds. Allocation takes `nextPublisherKeyIndex` and increments it, and `setOriginEntry`'s explicit index has no caller. A shared app-scoped index comes from stored data: a store from before #950, or one edited by hand (F-8).

### Facts found while checking the code

1. **F-1: any page could make main download a whole feed entry, of any size, before its read budget was charged.** `swarm_readFeedEntry` needs no grant. It charged one request, downloaded the entry, and only then charged its bytes (`spi:1605–1621`). The download was whole and uncapped: at an explicit index, the SOC and then `GET /bytes` of the chunk it wraps, joined by the node (`feed-service.js:112–125`); the latest entry, whatever `GET /feeds` answered. bee-js reads either body into one buffer, with no cap and no deadline (`utils/http.js:54–57`, `:116–121`). A feed is any `(topic, owner)` the page names, and anyone can publish one SOC that wraps the root chunk of a large file already on Swarm. Every request passed the budget's check before any bytes were charged, so a page could start 120 such reads at once each minute, and main fetched and held the file for each. `swarm_readData` didn't have the gap: it reads the root chunk's span and reserves the size first (`spi:956–1007`). Found by reading the code. **Fixed** by #1056 and #1057: an explicit index's SOC is read and charged first, and the entry's size from its span is reserved before `/bytes`, whose join is held to it; the latest entry is reserved from its declared length, or piece by piece as it streams, and cancelled past the budget. What it leaves for the core is in [Main's Swarm I/O pool](#mains-swarm-io-pool).
2. **F-2: on Windows, nested `publishFiles` paths reached the node with backslashes.** bee-js builds the tar's names with the platform's `path.join` (`utils/collection.node.js:24–41`), so the temp directory's `assets/app.js` became `assets\app.js` on Windows, and an `indexDocument` below the top level didn't match. Found by reading the code; not run on Windows. **Fixed** by #1056 and #1057: `publishFiles` uploads with `publishCollection` (`publish-service.js:197–225`), under the page's own paths, in the page's order, with no temp directory.
3. **F-3: bee-js's tar writer cuts long non-ASCII names.** `splitPath` counts a path's UTF-16 units, while `createHeader` writes the name into 100 bytes (`utils/tar.js:53–116`). A name of at most 100 units but more than 100 UTF-8 bytes is cut silently: a 64-character name of 124 bytes came out as 100 bytes, its extension lost (run against the reference's bee-js). `window.swarm` can't hit it (paths are at most 100 bytes), but a `freedom://publish` directory and the agent's collections can. Upstream's bug; the core's tar writer counts bytes.
4. **F-4: feed entries have no size limit.** `swarm_writeFeedEntry` checks the data's type, never its size (`spi:1438–1530`). The API document leaves the limit to the node (`docs/swarm-provider-api.md:573–580`). A site with the feed grant and its auto-approve rule can upload any amount through it, past `publishData`'s 10 MiB. **Decided** ([question 3](#open-questions), 2026-11-10): the 10 MiB of `maxDataBytes`, with `payload_too_large`, a page-visible change. #1233 fixed it on browser main (#1053); `integration/rust-core`, the reference, doesn't have it yet.
5. **F-5: an explicit-index feed write read a 500 as a free index.** The overwrite check took any 404 or 500 as "no entry" (`feed-service.js:355–366` with `isNotFoundError`, `:60–61`), while the head probe in the same file treats a 500 as unknown (`:137–147`). A node that couldn't fetch an existing entry let the write go ahead at its index. **Fixed** by #1056 and #1057: `feedEntryExists` reads only the entry's SOC and checks it against its address. Only a 404 frees the index; a 500, a timeout or a malformed answer refuses the write with -32603.
6. **F-6 (known, #360):** bee-js, the SOC upload, the reachability probe and the subscriptions' WebSockets use Node's own network stack, so a remote node gets no proxy and no Tor (`swarm-service.js:21–23`, `spi:2168–2172`).
7. **F-7 (known, 0006):** no `window.swarm` call to the node has a deadline or a cancel, apart from the 5 s probe and the 10 s tag read. #1057's metered reads have none either. *Since PRQ-7c and #1199 (at SWM-1's reference):* a page's uploads go through `page-upload.js`, which gives up after 60 s with no byte of the body moving or 300 s without an answer, and stops on the request's signal; a chunk or feed write stops at 300 s (`PAGE_WRITE_MS`) or when main answers the page. Reads still have no deadline.
8. **F-8: the publisher index counter is trusted as stored.** `createAppScopedIdentity` takes `nextPublisherKeyIndex` as the new index (`feed-store.js:650–675`), and loading a v2 store checks only that the counter is a non-negative integer (`:267–290`), not that it is past every stored index. A store whose counter is at or below a held index hands that index to the next site, which makes both shared. Freedom never writes such a store; an edited or merged file can. Not reachable from a page or the chrome. Found by reading the code. The core allocates past every stored index ([SW-1 in the core](#sw-1-in-the-core)).
9. **F-9: bee-js sends a PSS recipient the bundled node refuses.** `sendPss` requires a compressed key (`^0[23]` and 64 hex, `spi:1755–1760`). bee-js's `pssSend` turns it into a `PublicKey`, which holds the 64 bytes x ‖ y, and puts `String(key)` in the query (`modules/messaging.js:74–79`, `api/pss.js:10–18`): 128 hex, with no SEC1 prefix. Ant v0.5.77, the release the browser pins, reads `recipient` with `PublicKey::from_sec1_bytes`, which takes 33 or 65 bytes, and answers anything else 400 `invalid recipient public key` (`ant-gateway/src/retrieval.rs:999–1010`). So `window.swarm.sendPss` fails against the bundled node. Found by reading bee-js 13.2.0 and Ant's source at its tag, and by running core-sdk's `PublicKey` from the reference's install (a 66-hex key gives a 128-hex query value); not run against a node. The provider's tests mock `pssSend`. The core sends the page's compressed key. **Fixed** at SWM-1's reference by #1062, so the recipient is parity, not a deviation; only the 128-hex form stays a forbidden call.

## Threat model

Stage 1 trusts main (0001). The attackers here are a page (any page reaches the reads; a granted site reaches the writes), a Swarm node that lies (an external node, or the bundled one taken over), and main's own bugs.

| Threat | Today | With 0015 |
|---|---|---|
| A main bug signs a page's SOC under another site's key or identifier | possible: main names both to `swarm.sign_soc` | the core picks the key from its own store by the page's key, and computes every feed identifier; a raw SOC only under an exclusive identity |
| A raw SOC overwrites another site's feed entry under a shared key | refused in main since #950, with a gap between main's check and the core's signature | refused by the core: checked in today's place, checked again in the step that sends the signature, identity changes held until the vault answers ([SW-1](#sw-1-in-the-core)) |
| A page exhausts main's memory with reads | F-1; per site, fixed by #1057; nothing bounds all sites together, nor the other whole replies | the core reserves the site's budget and its own memory first; main's Swarm I/O pool bounds every reply it holds, for all sites |
| A page uploads past the limits | F-4 | feed entries bounded at 10 MiB (question 3) |
| A page burns CPU with new GSOC topics | a worker in main; up to ~5 s per topic; per-site budgets; an unbounded queue | one mining lane: today's budgets, a bounded queue, a job stopped within one batch of its deadline or cancel |
| A node lies about an upload's reference | taken as is; a feed entry's wrap signs the node's root chunk | `/bytes` and chunk references checked, the wrap built from the core's own root; a `/bzz` manifest stays the node's word |
| A core bug uses a live request for other node calls | bee-js can call any route | main admits only the calls the live operation allows at its step ([grammar](#the-operation-grammar)): a read reaches only its own chunk, bytes or feed route, at the addresses main derives (the page's reference, a feed entry's SOC and wrapped chunk, the data children of the tree main returned, by 0009's rules); a write only its own upload, once, with the body form and length main derives, and a feed write's probes and SOC at the identifier main computes. No route outside the forms: no buying, chequebook, wallet or stake route. Left to a core bug ([what main can't bind](#what-main-cant-bind)): which owner a site's own feed has, a GSOC's mined owner, the signatures, the bytes of the bodies it builds (of the right length, on the right route), and the batch it picks |
| A remote node's traffic leaves the session's policy | Node's `fetch` and `WebSocket`: no proxy, no Tor (F-6) | HTTP through the session's stack; subscriptions to a remote node refused while a proxy or Tor is on, and the user told ([question 4](#open-questions)) |
| Bulk data beside the vault | none in the core | credit windows; the swarm thread apart from the vault loop; a test pins `vault.lock` under two uploads and a mining job (0009's gate) |
| A crash mid-request | main's crash kills every request | a core restart ends the running Swarm requests; their history rows are `failed` at the next start, as today's sweep does; chunks the node already took stay, as when main dies today |

**What stays open:** the user's decision is main's word (0012). A `/bzz` manifest, a feed's latest entry and a feed entry's `/bytes` join are the node's word. A compromised main can do anything (0001). Until main can carry a WebSocket through the session, a remote node has no subscriptions while a proxy or Tor is on (question 4).

**What gets worse:** an upload's bytes cross the pipe twice more, and the core shares its process with them; credit bounds what it holds, and 0009 estimated that the pipe is not the bottleneck. A core restart now ends uploads too. Hashing a 10 MiB feed entry costs the core about 0.1 s (an estimate). Under heavy load, reads and writes that today would all run can get `busy`.

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
- **Subscriptions:** the WebSockets to `/pss/subscribe` and `/gsoc/subscribe`, their reconnects, the 32-per-site bound and message delivery (`messaging-service.js:289–403`, `subscription-registry.js`), and their refusal while a proxy or Tor is on ([Messaging](#messaging-and-gsoc-mining), question 4). The core can't hold a socket. It validates, checks the grant and derives the key to subscribe to.
- **The node:** its lifecycle (`ant-manager.js`), the pre-flight's readiness (`publish-setup-service.js`), publish setup, the Ant guard, and the transport to it.
- **Which node calls a request may make:** the [grammar](#the-operation-grammar), checked on every call, and the [Swarm I/O pool](#mains-swarm-io-pool).
- **Files on disk:** `freedom://publish` picks and reads the user's files, and streams them to the core.
- **The vault auto-lock timer's reset** after a successful write, as `spi:448–497` does today.

## The protocol

### Methods main calls

| Method | Callers | Params → result |
|---|---|---|
| `swarm.request` | page | `{ method, params, approval, deadline_ms }` → `{ result }` or `{ error: { code, message, data? } }`, today's shapes. For `swarm_subscribe`, `{ subscribe: { kind, key } }`, which main opens. `swarm_unsubscribe` never reaches the core |
| `swarm.publish` | shell | main's own uploads: `{ kind: "data" \| "file" \| "collection", parts, name?, content_type?, index_document?, encrypt?, batch?, pin, deferred, history? }` → `{ reference, tag_uid, batch, bytes }` |
| `swarm.feed` | shell | main's own feeds (the agent's): `{ op: "create" \| "update", key: { kind: "bee_wallet" }, topic, reference?, min_index?, batch? }` → `feed-service.js`'s results |
| `swarm.stamps` | chrome, shell | `{ id? }` → the node's batches, or one of them, as main reads them today (bee-js's `mapPostageBatch` fields Freedom uses, with `exists` and `propagating`) |
| `swarm.upload_status` | chrome, shell | `{ tag_uid }` → `normalizeTag`'s object (`publish-service.js:74–98`) |
| `swarm.identities` | chrome, shell | `{ op, … }`, one op per IPC handler of `feed-store.js:966–1050` → today's shapes |
| `swarm.history` | chrome, shell | `{ op: "list" \| "clear" \| "remove", id? }` → today's rows (`rowToEntry`) |
| `swarm.manifest` | shell | `{ op: "check" \| "decide" \| "list" \| "revoke", … }`; `check` runs the reference's legacy and backoff checks first, then asks main for the manifest at a `bzz:` address, and only then takes the bytes main fetched (at most 8 KiB, `permission-manifests.js:20`) → display data and a token, as today. Main never fetches for a URL that isn't `bzz:`, or when the backoff holds; the exchange's shape is SWM-4's |
| `swarm.body` | shell | `{ for }` → a head `{ bytes }`, then the body of the core's pending `shell.swarm_api` request `for`, as a stream |

- **`approval`** is `"user"` (main's prompt was answered) or `"auto"` (a standing rule). `auto` is admitted only when the grant's flag for the method's type is on and `agent` is false; otherwise `agent_custody` as today, or `not_auto_approved` from the guard, where the reference checks them (after the method's last wait, at its effect: after the readiness check and `/stamps` for an upload, after the signer's owner for `getSigningIdentity`, at once for `createFeed`'s existing feed), not at the start: a rule turned off or custody taken between main's check and the hand-off reaches the core (`send-pss-rule-off-before-send`, `send-pss-rule-custody-before-send`).
- **`deadline_ms`** is the page's own timer, 60 s or 300 s by today's list. A new deadline kind, `swarm`: 300 s, or the caller's shorter `deadline_ms`. `swarm.publish` has no total deadline (a picked file may be large), only the idle bound below.
- **No new event.** 0012's `approval.changed` tells main of a revoked grant, and main ends that key's subscriptions, as `onRevoke` does today (`spi:2219`).
- **Name checks:** main checks a name's IPNS binding before it sends the request (0011). The core checks again with 0012's `transport_key` after each wait on the node and before each effect (a signature, an upload, a store write), reading each fact live, in the reference's order: the name's binding, then Agent custody and the rule (only when a rule approved the request), then the document's key, then the connection.

### Requests the core makes

| Method | Params | Main does | Reply |
|---|---|---|---|
| `shell.swarm_api` | `{ for, form, method, path, query, headers, body, max_bytes, stream, feed?, tree? }` | one node call of a [form](#shellswarm_api) the [grammar](#the-operation-grammar) allows `for` at its step, on the node's transport ([Node access](#node-access)) | `{ status, status_text, headers, body_base64 }` whole, or `{ status, status_text, headers }` and a stream; or `{ failed }` |
| `shell.swarm_part` | `{ for, part }` | streams one payload part of request `for` from what it holds: the page's IPC value, or a file it opened for `freedom://publish` | a head `{ bytes }`, then the bytes |
| `shell.swarm_ready` | `{ for, check: "publish" \| "reachable" \| "subscribe" }` | `getPublishReadiness()`; the 5 s `GET /node` probe; or, for `subscribe`, the probe after the [proxy check](#messaging-and-gsoc-mining) | `{ ok: true }` or `{ ok: false, reason }`, today's reasons |

- **`for`** is the envelope ID of a live `swarm.request`, `swarm.publish`, `swarm.feed`, `swarm.stamps` or `swarm.upload_status`: the **parent**. Main uses that request's backend, session and signal, so the core can't send a call to another node or session. And main admits only the calls the parent's [row](#the-operation-grammar) allows at its step. A `for` that has ended is refused; it is a race, not a fault.
- **`form`** names the call's row in [the forms](#shellswarm_api); `method` and `path` must be that row's.
- **`tree`** is `{ length, depth }` on every `chunk` call under `readData` after the root: the logical length and the depth the walk gives the occurrence it fetches. Main admits it only for an unfetched occurrence of that address at that length and depth ([values main derives](#values-main-derives-from-its-own-replies)).
- **`feed`** is `{ owner, index }` on a `chunk` call under a feed row: the feed update the core asks for. Main builds that update's address from it and the row's topic, and the call's `path` must be that address ([values main derives](#values-main-derives-from-its-own-replies)).
- **`body`** is absent, `{ base64 }` (at most 64 KiB), or `{ stream: <bytes> }`, as the form says. With a stream, main sends `swarm.body { for: <this request's ID> }` and pipes the core's answer into the node's request.
- **`shell.swarm_part`** names only a part of the parent's own params, each at most once. **`shell.swarm_ready`** comes once per parent, with the check its row names, before any `shell.swarm_api`.
- **Read strictly both ways,** as 0009 reads `shell.dweb_get`: an unknown member, a value of another type, a form, path, query or header outside its row or past its bound, a status outside 100–599, or base64 that doesn't decode is `invalid_argument` from main and a protocol error in the core.

### Main's encoding of a request

Requests stay within one frame (0005), so bulk bytes can't ride in `params`. And the validators read JavaScript types (`typeof`, `Number.isInteger`, `Array.isArray`, key order, `undefined` against `null`, BigInt), which JSON loses. So main sends `params` in a typed form, which the vectors' `formats` define:
- **Bytes:** each value `normalizeBytes` accepts (`Buffer`, `Uint8Array`, `ArrayBuffer`, `{ type: 'Buffer', data: [...] }`, `spi:706–721`) where a method reads bytes (`data`, `files[i].bytes`) becomes `{ bytes: n, base64 }` up to 64 KiB, or `{ bytes: n, part: k }`, which the core pulls with `shell.swarm_part`.
- **A string** where a method reads data is its UTF-8, as `Buffer.from(s, 'utf-8')` makes it (a lone surrogate becomes U+FFFD, as today), marked as a string.
- **Everything else** is a tagged value: strings (lone surrogates as escapes, which `fc-json` reads, 0005), numbers with `-0`, NaN and the infinities, BigInts, `undefined`, arrays, and objects as key-value lists in their order. The core counts lengths in UTF-16 units where today's code reads `length`, and in UTF-8 bytes where it reads `Buffer.byteLength`.
- **0011's walk** has already refused what it doesn't take (a `Map`, a `Date`, another typed array) and bounded the request's size.

### Streams

0009's rule holds: a stream is the body of a response, sent by whichever side answers.
- **Into the core:** `shell.swarm_part`'s parts, and `shell.swarm_api`'s bodies with `stream: true` (`/bytes` and a latest feed entry). Main's abort codes are 0009's for its pieces, `cancelled`, `stalled` and `body_stream_error`, plus `too_large` for a `shell.swarm_api` body past its `max_bytes`.
- **Out of the core:** `swarm.body`, one per streaming upload. The core ends it with `cancelled`, `internal`, or `body_stream_error` when a part it was copying failed.
- **0007's rules per stream:** the head first, a 128 KiB window, data frames of 1 to 65,536 bytes, exactly one terminal.
- **The global bound:** the core's incoming Swarm streams take credit from their own allowance of 4 MiB, apart from the dweb thread's 16 MiB (0009). Outgoing, at most 4 `swarm.body` streams, 512 KiB of windows.
- `fc-protocol`'s `Codes` and `vectors/streams.json` gain the new methods' allowed and refused pairs.

### Deadlines and cancel

- **A request's node calls** share its deadline. Each streamed body also has 0009's idle bound, 60 s with credit outstanding and no bytes; a whole body has the same 60 s without a byte ([Reading a body](#mains-swarm-io-pool)).
- **Main cancels** a `swarm.request` when its document goes (0011) or the page's timer ends. The core then cancels its open `shell.*` requests and streams, and answers `cancelled`. Nothing more is signed, uploaded or written after the cancel. A history row ends `failed` with the text `cancelled`.
- **An upload cut off** after the node took part of it leaves those chunks with the node, as a page closing does today. There is no rollback on Swarm.

## Node access

### `shell.swarm_api`

Each call names one **form**. Main checks the call against its row before any dial, and [the grammar](#the-operation-grammar) says which forms a parent may use, when, how often and with which values. Hex is lowercase, as bee-js's `Reference`, `Topic` and `EthAddress` write it, and a value bound from the page's params is lowercased first, `<x>` included, as `swarm-provider-ipc.js` lowercases the targets before `sendPss` (`spi:1801`). `<a>`, `<t>`, `<id>` and `<b>` are 64 hex; `<o>` is 40 hex; `<uid>` is a decimal integer from 1 to 2^53 − 1 with no leading zero; `<x>` is 4 or 6 hex.

| Form | Method and path | Query | Request headers | Body | Reply |
|---|---|---|---|---|---|
| `chunk` | `GET /chunks/<a>` | — | — | — | whole, at most 4,201 bytes (a SOC: 32 + 65 + 8 + 4,096); under a feed row, with `feed` |
| `bytes` | `GET /bytes/<a>` | — | `range: bytes=<s>-<e>` (decimal, `s` ≤ `e`), or none, as the row says | — | a stream, at most `max_bytes` |
| `feed_head` | `GET /feeds/<o>/<t>` | — (in particular, no `Swarm-Only-Root-Chunk` query) | `swarm-only-root-chunk: true` | — | whole, at most 4,201 bytes; the core reads only its headers |
| `feed_latest` | `GET /feeds/<o>/<t>` | — | — | — | a stream, at most `max_bytes` |
| `tag` | `GET /tags/<uid>` | — | — | — | whole JSON, at most 64 KiB |
| `addresses` | `GET /addresses` | — | — | — | whole JSON, at most 64 KiB |
| `stamps` | `GET /stamps` | — | — | — | whole JSON, at most 1 MiB |
| `stamp` | `GET /stamps/<b>` | — | — | — | whole JSON, at most 64 KiB |
| `bzz_file` | `POST /bzz` | `name=<n>` | `content-type`, `swarm-postage-batch-id: <b>`, `swarm-pin: true`, `swarm-deferred-upload: true` or `false`; `swarm-encrypt: true` under `swarm.publish` only | one file: `{ base64 }` or `{ stream }` | whole JSON, at most 64 KiB |
| `bzz_tar` | `POST /bzz` | — | `content-type: application/x-tar`, `swarm-collection: true`, `swarm-postage-batch-id`, `swarm-pin: true`, `swarm-deferred-upload: true`, `swarm-index-document: <p>` or none; `swarm-encrypt: true` under `swarm.publish` only | a tar: `{ stream }` | the same |
| `bytes_up` | `POST /bytes` | — | `content-type: application/octet-stream`, `swarm-postage-batch-id` | `{ stream }` | the same |
| `chunk_up` | `POST /chunks` | — | `content-type: application/octet-stream`, `swarm-postage-batch-id`, `swarm-pin: true`, `swarm-deferred-upload: false` | span ‖ payload, 9 to 4,104 bytes: `{ base64 }` | the same |
| `soc_up` | `POST /soc/<o>/<id>` | `sig=<130 hex>` | `content-type: application/octet-stream`, `swarm-postage-batch-id`; `swarm-pin: true` and `swarm-deferred-upload: false` for `writeSingleOwnerChunk` only | span ‖ payload, 9 to 4,104 bytes: `{ base64 }` | the same |
| `feed_manifest` | `POST /feeds/<o>/<t>` | — | `swarm-postage-batch-id` | — | the same |
| `pss_send` | `POST /pss/send/<t>/<x>` | `recipient=<66 hex>`, a compressed key (F-9) | `content-type: application/octet-stream`, `swarm-postage-batch-id` | the message, at most 4,000 bytes: `{ base64 }` | the same |

- **Values:** `<n>` is the operation's file name, form-encoded as `URLSearchParams` encodes it; `<p>` the index document's path; `content-type` on `bzz_file` the operation's. A query takes only its row's names, once each, in that order.
- **Why `feed_head` uses the header:** Ant reads `swarm-only-root-chunk` as a request header and ignores an unknown query key (`download_feed`, `ant-gateway/src/retrieval.rs:4387` at v0.5.77; recorded at v0.5.71 in `vectors/dweb-verify.json`, where the header form returns the root chunk, 1,064 bytes, and the plain form the content). bee-js 13.2.0's own `probeFeed` sends it as a query (`api/feed.js:46–55`), which Ant ignores, so it would download the whole entry; Freedom never calls `probeFeed`. The core sends the header, as 0009's verifier does, and the query form is refused.
- **No retrieval headers:** `chunk` and `bytes` carry none of 0009's three (`swarm-chunk-retrieval-timeout`, `swarm-redundancy-strategy`, `swarm-redundancy-fallback-mode`): bee-js sends none for these calls today, so `readData`'s walk doesn't either.
- **Request headers:** only the row's, each at most once, at the row's values. Main adds bee-js's `accept: application/json, text/plain, */*`, `accept-encoding: identity` (as #1057 does, so a declared length is the decoded one), and the transport's own (`content-length`, `transfer-encoding`). A call with any other header is refused. Values are byte strings, as Node's fetch reads them: a page's value with a character past U+00FF fails the request as it does in the reference ([freedom-browser#1328](https://github.com/solardev-xyz/freedom-browser/issues/1328)), and main sends each character in U+0080–U+00FF as one byte.
- **Reply headers** the core reads: `content-type`, `content-length`, `swarm-tag`, `swarm-feed-index` and `swarm-feed-index-next`; at most 8, each name at most 64 bytes and each value at most 1 KiB. The reason phrase is at most 1 KiB. Past either, the call fails `error`.
- **Error statuses:** for any form, a status outside 200–299 is answered whole, its body read up to 8 KiB, never as a stream. Nodes answer errors with short JSON; 8 KiB keeps #1057's 4,096 bytes and bounds what an error can make main hold.
- **Error texts:** the core builds each call site's text as the reference does, so the page reads the same messages:
  - **bee-js 13.2.0's `throwHttpError`** (`utils/http.js:90–107`), for every bee-js call, an array-buffer download included: the body as text (`Response.text()`: UTF-8 with U+FFFD for a bad sequence, a leading BOM dropped). Empty, the message is `<status_text>`. Otherwise it is `<status_text>: <m>`, where `m` is the text's `JSON.parse` when that is a string, `JSON.stringify` of it when it is another value, and the text itself when it doesn't parse (`fc-json`'s JavaScript-compatible text, as 0008's reads use). The error's data is the parsed value, which `isChunkNotFoundError` reads;
  - **#1057's latest-feed reader** (`fetchNode`, `feed-service.js`): the first 4,096 bytes as `Buffer.toString('utf8')`, a BOM kept and a sequence cut at the 4,096th byte replaced, then the same rule;
  - **the SOC upload's own** `SOC upload failed (<status>): <body, else status_text, else "Bee rejected request">` (`chunk-service.js:83–126`);
  - **`page-upload.js`'s**, for a page's `publishData` and `publishFiles` since PRQ-7c: the body as `Buffer.toString('utf8')`, a BOM kept, its JSON in `JSON.stringify`'s form, `HTTP <status>` when the status has no reason phrase, and its own text for a redirect.
  - In bee-js, a body whose JSON is the empty string gives the bare status text.
  - An error body nested deeper than 64 levels fails `error`, as a skipped value does ([JSON replies](#json-replies)); JavaScript parses any depth.
  - The core gets at most 8 KiB of an error body. bee-js reads the whole of it, so a longer body's text can differ (deviation `error-body-bound`).
- **`failed`** is 0009's closed set plus `busy` and `stopped`: `unreachable`, `error`, `aborted`, `too_large`, `busy` and `stopped`. `stopped` is main with no node to dial after a readiness answer (the node stopped, or its URL went): -32603 `Swarm node is not ready`, the reference's text (`publish-service.js:155`, `swarm-service.js:28`), at any call. The first three map to the text the reference gives that class. `too_large` is the read's own text where the reference has one, and -32603 `Swarm node reply too large` elsewhere: a feed entry past `max_bytes` is `data_too_large`, as #1057 gives it; a feed entry's `bytes` past its span is #1057's `Node returned more than N bytes for a N-byte feed entry`; `readData`'s leaf stream past its size is `Node returned more than N bytes for a N-byte blob`, the streamed form of `chunk-service.js`'s own text; a `chunk` reply past its cap under `readChunk` or `readSingleOwnerChunk` is that read's `chunk_type_mismatch`; a feed's SOC past its cap is `Swarm node reply too large`. `busy` is 4900 `busy`.
- **Never:** any other route. No `/stamps/<amount>/<depth>`, `/stamps/topup`, `/chequebook`, `/wallet`, `/stake` or `/v0/*`.

### The operation grammar

**Main derives each parent's allowed calls** from what main itself knows, never from the core: the parent's method or kind and the params main sent, the page's key (0011), and its own record of the calls it has admitted for that parent. The table is normative. `B` is 5 MiB, the larger read budget's `maxBytes`. "Span" is 8 bytes, little-endian. "The data" is the page's (or main's) bytes for the method, UTF-8 for a string.

| Parent | Ready | Calls, in order | Main binds |
|---|---|---|---|
| `readChunk` | `reachable` | `chunk` ×1 | `<a>` = `params.reference` |
| `readSingleOwnerChunk` | `reachable` | `chunk` ×1 | `<a>` = `params.address`, or, without it, keccak256(`params.identifier` ‖ `params.owner`) |
| `readData` | `reachable` | `chunk` ×1 (the root); then, only when the root's size `n` is over 4,096 bytes, 0009's walk, at most 8 open at once: `chunk` at most 2 + 2⌈B / 4,096⌉ in all (intermediate chunks, and a leaf fetched again when it fails its check), and `bytes` at most once, the leaves' stream | the root's and `bytes`' `<a>` = `params.reference`; `n` from the span of the root chunk main returned, as `dataSizeFromSpan` reads it, at most B; `bytes` only with `range: bytes=0-<n − 1>` and `max_bytes` = `n`; every later `chunk`, with its `tree`, an unfetched occurrence of a data child of an intermediate chunk main returned for this request, by 0009's geometry ([below](#values-main-derives-from-its-own-replies)) |
| `readFeedEntry` with `index` | `reachable` | `chunk` ×1 (the SOC, with `feed`); then, only when the size in its wrapped span is over 4,096 bytes, `bytes` ×1 | the SOC's `<a>` = keccak256(keccak256(`<t>` ‖ `params.index` as 8 bytes, big-endian) ‖ `<o>`), `<t>` as for the latest entry, `<o>` = `params.owner`, else the `feed.owner` the core names (its store's); `bytes`' `<a>` = the address of the chunk that SOC wraps, which main computes from the `span ‖ payload` it returned (bytes 97 on), without a `range`, its `max_bytes` = the size in that span, as `dataSizeFromSpan` reads it, at most B |
| `readFeedEntry`, latest | `reachable` | `feed_latest` ×1 | `<t>` = `params.topic`, or keccak256(utf8(key + "/" + `params.name`)); `<o>` = `params.owner` when it is truthy (`read-feed-name-owner-empty` sends `""` and reads its own feed); `max_bytes` at most B |
| `getUploadStatus` | — | `tag` ×1 | `<uid>` = `params.tagUid` |
| `getMessagingIdentity` | `reachable` | `addresses` ×1 | — |
| `publishData` | `publish` | `stamps` ×1, then `bzz_file` ×1 | `<n>` = `params.name`, else `data`; `content-type` = `params.contentType`; `swarm-deferred-upload: false`; the body exactly the data's length |
| `publishFiles` | `publish` | `stamps` ×1, then `bzz_tar` ×1 | `swarm-index-document` = `params.indexDocument`, else `index.html` when a top-level file has that name, else none; the body at most T(files) |
| `publishChunk` | `publish` | `stamps` ×1, then `chunk_up` ×1 | the body = span ‖ the data |
| `writeSingleOwnerChunk` | `publish` | `stamps` ×1, then `soc_up` ×1 | `<id>` = `params.identifier`; the body = span ‖ the data |
| `createFeed` | `publish` | `stamps` ×1, then `feed_manifest` ×1 | `<t>` = keccak256(utf8(key + "/" + `params.name`)) |
| `updateFeed` | `publish` | `stamps` ×1; `feed_head` ×1; after its 404 or 500 (`isNotFoundError`), `chunk` at most 81 (today's head probe, with `feed`); then `soc_up` ×1 | `<t>` as for `createFeed`; one `<o>` throughout, fixed by `feed_head`; each probe `chunk` at the SOC address of the index the probe asks next; `soc_up`'s `<id>` = keccak256(`<t>` ‖ the next index as 8 bytes, big-endian); the body = span ‖ an 8-byte timestamp ‖ `params.reference`: 48 bytes, or 80 for an encrypted reference |
| `writeFeedEntry` | `publish` | `stamps` ×1; with `index`, `chunk` ×1 (with `feed`), else `feed_head` ×1 and, after its 404 or 500, `chunk` at most 81 (with `feed`); for data over 4,096 bytes `bytes_up` ×1; then `soc_up` ×1 | `<t>` as for `createFeed`; one `<o>` throughout, fixed by the first call that names it; the existence `chunk` at the SOC address of `params.index`, and each probe `chunk` at the SOC address of the index the probe asks next; `soc_up`'s `<id>` = keccak256(`<t>` ‖ the write's index as 8 bytes, big-endian); `bytes_up`'s body exactly the data's length; `soc_up`'s body = span ‖ the data for data of 4,096 bytes or less, else a root chunk whose address is the `reference` main returned from `bytes_up` |
| `sendPss` | `publish` | `stamps` ×1, then `pss_send` ×1 | `<t>` = keccak256(utf8(`params.topic`)); `<x>` = `params.targets`, lowercased; `recipient` = `params.recipient`, lowercased (the compressed key, F-9); the body = the message |
| `sendGsoc` | `publish` | `stamps` ×1, then `soc_up` ×1 | `<id>` = keccak256(utf8(`params.topic`)); the body = span ‖ the message |
| `subscribe` | `subscribe` | none | — |
| `getCapabilities` | `publish` | none | — |
| `requestAccess`, `getSigningIdentity`, `listFeeds` | — | none | — |
| `swarm.publish` `data`, `file` | — | `stamps` ×1, then `bzz_file` ×1 | `<n>` = `name`, else `data` for `data`; `content-type` = `content_type`, else `text/plain` for `data` and `application/octet-stream` for `file`, as `publish-service.js` and bee-js's `uploadFile` default them; `swarm-deferred-upload` = `deferred` (today false for `data`, true for `file`); `swarm-encrypt` only when `encrypt`; the body exactly the part's length |
| `swarm.publish` `collection` | — | `stamps` ×1, then `bzz_tar` ×1 | `swarm-index-document` = `index_document`, else `index.html` when a top-level part has that name; `swarm-encrypt` only when `encrypt`; the body at most T(parts) |
| `swarm.feed` `create` | — | `stamps` ×1, then `feed_manifest` ×1 | `<t>` = `topic` |
| `swarm.feed` `update` | — | as `updateFeed` | as `updateFeed`, with `<t>` = `topic`, the next index at least `min_index`, and the body ending in `reference` |
| `swarm.stamps` | — | `stamps` ×1, or `stamp` ×1 with `id` | `<b>` = `id` |
| `swarm.upload_status` | — | `tag` ×1 | `<uid>` = `tag_uid` |

T(files) = 1,024 + Σ (1,024 + ⌈name's bytes / 512⌉ × 512 + ⌈size / 512⌉ × 512): a header, room for a long-name entry, and the body, each padded to 512 bytes, then the two zero blocks. It is an upper bound, which the core's exact tar never passes.

**A given batch:** `swarm.publish` and `swarm.feed` may name their `batch`, as the agent passes `batchId` today (`swarm-publication-controller.js:128`, `:594`, `:787`; `publish-service.js:114`, `feed-service.js:289`). Then the row's `stamps` is left out, and the upload's `swarm-postage-batch-id` must be that batch. Without one, it is the batch the core chose; main doesn't check which listed batch that is, which would mean parsing `/stamps` in main.

#### Values main derives from its own replies

Some addresses follow from what main itself returned to the core in this request. Main computes them and admits only them:
- **A feed update's address:** `keccak256(keccak256(<t> ‖ index as 8 bytes, big-endian) ‖ <o>)`, from the row's topic, the parent's owner and the index. A feed `chunk` call carries `feed: { owner, index }`. Main checks the owner (the page's `owner`, or the one the parent's first call fixed) and the index, builds the address, and requires `path` to be it.
- **Which index:** an explicit read or write takes `params.index`. A write without one takes its index the way today's `resolveNextIndex` does, from the answers main returned:
  - a 2xx `feed_head` gives its `swarm-feed-index-next`, as bee-js reads it: a reply without it or without `swarm-feed-index` is bee-js's error;
  - a 404 or 500 gives the head probe. Main replays `probeFeedHead` over its own answers: index 0, then 1, 2, 4, … while they exist, then the halving between the last found and the first missing, at most 81 reads, the reference's longest run (SWM-1's vectors measure it). Each probe `chunk` must be at the next index of that run. The run's end gives the head + 1, or 0 for none;
  - `updateFeed` through `swarm.feed` takes the larger of that and `min_index`.

  So the final `soc_up`'s `<id>` is `keccak256(<t> ‖ that index)`, and its `<o>` the parent's owner.
- **A wrapped chunk's address:** for an explicit-index read, the content address of the chunk the SOC wraps: its `span ‖ payload`, from byte 97 of the SOC main returned. For a large feed write, `soc_up`'s body must be the root chunk whose address is the `reference` in `bytes_up`'s reply. Main computes these with a small BMT function (ethers' keccak256, 128 hashes per chunk), held to `vectors/swarm.json`'s chunk addresses.
- **The file tree's data children:** under `readData`, main admits only the chunks 0009's walk can ask for, by 0009's own rules (*Files*), the ones `fc_swarm::tree` implements:
  - **Each entry carries a logical length.** The root's is its own decoded span (`decode_span`: a top byte past 128 is the level and is cleared). A child's comes from its parent's geometry, never from its own span: the first children each cover `branch` bytes, the smallest `4096 · b^k` that leaves the last no more than that, and the last the rest. `b` is 128, or 119, 107, 97 or 39 at levels 1 to 4.
  - **Depth, as 0009's walk counts it** (`fc-dweb`'s `Tree`, `MAX_LEVELS` = 8): the root is at depth 0, and a child one deeper than its parent. A child that isn't a leaf is fetched only below depth 8; at depth 8 the walk ends `unverifiable` instead, so main never admits it. A leaf may sit at depth 8, and be fetched again after a failed check.
  - **Only an entry whose logical length is over 4,096 bytes is an intermediate.** When main returns its chunk, main reads it as `tree::intermediate` does: it drops the trailing all-zero references (padding), takes the chunk's parity count from its own span (Bee's `ReferenceCount` and parity tables), and keeps only the data references before them. It adds each data child of positive logical length to the set, with that length and its depth, leaving out a child that isn't a leaf at depth 8. A chunk that `intermediate` would refuse adds nothing, and the core refuses it too.
  - **A logical leaf adds nothing,** whatever its own span says. Its chunk is fetched again only after its check failed in the `/bytes` stream.
  - **Parity references never enter the set.** The walk never reads them: a node that recovered a chunk from parities serves the original, which checks against the original address (0009).
  - **Occurrences, not addresses:** 0009's walk keeps each child position with its own address, logical length, start and depth, and reads each occurrence under its own length and depth: an intermediate parsed by its own geometry, its children one level deeper; a leaf checked against its own length (`fc_swarm::tree`; `fc-dweb`'s `Frame`, `Want` and `Ahead`, keyed by start and depth). One valid chunk can sit at two positions with two lengths, or at two depths, and the walk accepts that. So main keeps occurrences, keyed by address, logical length and depth, each with its count of unfetched slots: repeated content (the full leaves of a file of zeros) is one key with many slots, and one address at two lengths or two depths is two keys. Each later `chunk` call names its occurrence in `tree: { length, depth }`. Main admits it only for an unfetched slot of that key, takes one slot, and, when the length is over 4,096 bytes, reads the chunk it returns under that length and adds its children at the next depth.
  - **Why the start can be left out:** `readData` reads the whole file, so the walk's range is `[0, n)`, and children split their parent's length exactly; every child of positive length is inside the range. Of what the walk keeps per position, only the range test uses the start, and here it admits every such child. The rest (the cursor, the lookahead, which fetch blocks, how many are in flight, the checked chunks it reuses) orders, limits and saves calls, and never adds one. So two slots of one key give the same chunk, the same length and the same depth, hence the same children: which is fetched first doesn't matter.
  - **Each slot is fetched at most once,** so the calls are at most the slots.
  - **The bound:** at most 2,562 slots, 2 + 2⌈B / 4,096⌉, the row's call cap. Bee's and Ant's trees for B = 5 MiB have at most about 1,320 data children (1,280 leaves, at most 34 intermediates at level 4, Ant's lone-reference wrappers), so honest content stays under half of it. A tree that would pass it is refused by the core's walk first, which counts the same children under the same cap (`unverifiable`, read as bad data: `read-data-verified`). Main keeps the set as a JavaScript `Map` from address and logical length to the count of unfetched slots, charged at 256 bytes a slot (the key string with its depth, the numbers and the table entry, rounded up; about 119 bytes measured under Electron 44's V8): 640 KiB, reserved from the [Swarm I/O pool](#mains-swarm-io-pool) when the walk starts.
  - **Held to the same vectors:** main's tree reader, about a hundred lines of JavaScript, is tested on `vectors/dweb-verify.json`'s `files` (their trees, data leaves and parities at every redundancy level, Ant's lone-reference wrappers, a leaf whose own span differs from its logical length) and `vectors/swarm.json`'s `trees`. The core still checks every chunk.

#### What main can't bind

These stay the core's word, and a core bug can choose them:
- **A site's own feed owner** where the page names none: the owner of `createFeed`'s manifest, a feed read by name, a feed write, and a raw SOC. They come from the core's identity store. One request still reaches one feed, and an address it reads is a hash of that owner, so a core bug can read or write another owner's update of the site's own topic, never an arbitrary chunk.
- **A GSOC's mined owner:** finding it is the search the core runs.
- **The signatures** in `sig`.
- **The bytes of bodies the core builds** (a tar, a `/bytes` upload, a SOC's payload where the page's bytes aren't the payload), which main holds only to their form and length.
- **The batch** the core chose.

**The rules:**
- **Order and phase:** main records each call it admits for a parent. A call is admitted only as the next its row allows, and only after the row's ready check answered `ok`. One call at a time per parent, except `readData`'s eight.
- **Counts** are the row's. A call past them is refused.
- **Values:** where the row binds a value, the call carries exactly it, including the addresses and indexes main works out from its own replies ([below](#values-main-derives-from-its-own-replies)). Where it can't (an owner the core read from its own store), the first call that names `<o>` fixes it for the parent: one feed per request.
- **Bodies:** the form's kind (`{ base64 }` or `{ stream }`) and the row's length. A base64 body made of the page's own bytes must equal them, byte for byte.
- **`max_bytes`:** at most the form's cap and the row's bound. Main reads no more than the smaller.
- **`swarm.body`** comes once per streaming call, for that call only.
- **After the parent ends** (replied, cancelled, past its deadline), nothing is admitted for it.
- **A refused call** is answered `invalid_argument` with `data: { rule }` (`form`, `order`, `count`, `value`, `header`, `query`, `body` or `ended`), before any dial. Main logs it at `warn` with the parent's method, its step and the rule, never a path, value or body, and refuses every later call of that parent. The core's machine ends that request with -32603 `Internal error`. Main doesn't kill the core: as with 0014's refused fetch, the grammar already bounds what it can reach.
- **One source:** the grammar is data, `vectors/swarm-grammar.json`: the forms, the rows, and for each row its **honest** calls, which must be admitted, and its **forbidden alternatives**, which must be refused. SWM-1's generator checks every request the reference records against it, SWM-3 checks the core's machines and runs both lists, and main's executor suite reads the same file and runs both lists, as `stream-vectors.test.js` reads `streams.json`.
- **The honest calls** include, for each row, every request the reference makes that the core keeps, at the edges: an SOC read by `params.address` and by owner and identifier; `params.reference`, `params.targets` and an address in upper case, sent lowercased; a feed entry of exactly 4,096 bytes (no `bytes_up`) and one of 4,097; a `readData` root of 4,096 bytes (no walk) and one of 4,097; a head probe after a 404 and after a 500, up to its 81st read, over heads of none, 0, 1, 2^k and 2^k − 1; a `min_index` past the head; a feed read by name with no `owner`; an erasure-coded `readData` tree at each level whose data intermediates are fetched, and a leaf fetched again after a failed check; one chunk at two positions with two logical lengths, fetched once at each, as an intermediate parsed under each geometry and as a leaf checked against each length; one chunk at one length at depths 6 and 7, both fetched, the depth-6 copy's intermediate child (at depth 7) admitted; a leaf at depth 8 fetched again (no honest splitter writes these depths inside `readData`'s 5 MiB, but a node can serve a chain of lone-reference wrappers, as Ant writes one, to any depth within it); an upload with the parent's own `batch` and no `stamps`; `bzz_file` with each default content type; `index.html` as the default index document.
- **The forbidden alternatives** are each row's nearest wrong call: the reference's requests the core drops (an unranged `bytes` under `readData`; `GET /chunks` after a `/bytes` upload; a second `/stamps`; a whole `feed_latest` for an index lookup); the 128-hex PSS recipient, bee-js's form before #1062; an 82nd head-probe read; the query form `?Swarm-Only-Root-Chunk=true` for `feed_head`; a `range` other than `bytes=0-<n − 1>`, or a `max_bytes` other than `n`; a `bytes` for an entry of 4,096 bytes or less; a retrieval header on `chunk` or `bytes`; another address than `params.address`; a `swarm-postage-batch-id` other than the parent's `batch` when it named one; a feed read's `bytes` at another address than the wrapped chunk's; a feed `chunk` whose `path` isn't the address main builds from `feed`, or whose `feed` names another owner than the parent's or another index than `params.index` or the probe's next; a `soc_up` with another `<id>` or `<o>` than main derives; a large feed write's `soc_up` whose root isn't `bytes_up`'s `reference`; a `readData` `chunk` at a parity address, at the all-zero padding address, at a slot inside a logical leaf whose own span is large, at a zero-length child (an intermediate with more references than its length needs), at an address no returned chunk names, or more times than the tree names it; a `tree.length` or `tree.depth` the tree doesn't give that address; one address at two lengths fetched twice under one of them; the depth-7 copy's intermediate child, at depth 8; any intermediate at depth 8; and upper-case `<x>`.

**The refusal tests** (SWM-5, against a scripted core), each refused before any dial and logged with its rule:
- **Cross-operation:**
  - under `readChunk`: each other form (`POST /bzz`, `GET /stamps`, `GET /addresses`, `POST /soc`, `POST /pss/send`, `feed_latest`);
  - under `publishData`: `bzz_tar`, `chunk_up`, a `swarm-collection` header;
  - under `writeSingleOwnerChunk`: `feed_manifest` and `bytes_up`;
  - under `getUploadStatus`: another tag than the page's;
  - under `swarm.stamps`: any write;
  - one parent's `for` with a call only another parent's row has.
- **Cross-phase:**
  - an upload before its `stamps`, and a second `stamps`;
  - a call before the ready check, or after one that answered `ok: false`;
  - a feed write's `soc_up` before its index lookup, or before its `bytes_up`;
  - a `bytes_up` for a feed entry of 4,096 bytes or less;
  - a second upload, and an 82nd probe `chunk`;
  - a call while another of the same parent is open;
  - any call after the parent ended.
- **Values:** another reference, identifier, topic, recipient or target than the row binds; a second `<o>` or `<t>` within one request; `swarm-encrypt` under `swarm.request`, or under `swarm.publish` without `encrypt`; `swarm-deferred-upload: true` for `publishData`; another `content-type` than the page's.
- **Bodies:** a length other than the row's; base64 bytes that differ from the page's; `{ stream }` where the row has `{ base64 }`, and the reverse; a `max_bytes` past the form's cap.
- **Parts and bodies:** another request's part, one part twice, a `swarm.body` for a call that doesn't stream, or a second one.
- **Every honest call and forbidden alternative** of `swarm-grammar.json`, admitted and refused as listed.

### Main's Swarm I/O pool

Main holds what it reads from the node until the core takes it. One **Swarm I/O pool** of 64 MiB, browser-wide, held by `core/swarm-shell.js`, bounds it. It is apart from 0005's chain I/O pool (192 MiB) and 0014's Colibri fetch pool (128 MiB), so a page's Swarm reads can't starve the core's chain replies or Colibri's fetches, nor the reverse. `b64(m)` below is 4⌈m / 3⌉.
- **Reserved before the dial.** A whole call reserves `m + 2 × b64(m) + 16 KiB`, `m` the larger of its `max_bytes` and 8 KiB (an error body's cap): the decoded body, its base64 and the serialized reply, every copy counted at once, since JavaScript frees them at the collector's pace. A 1 MiB `/stamps` call reserves 3.7 MiB; a chunk, 45 KiB. A stream reserves 256 KiB when it opens, a part, a streamed body or a `swarm.body` alike: its window, the frame being built, and the transport's buffer. That also covers a streaming call's error, which comes whole.
- **Shrunk, then released.** Once a whole body is read, its charge shrinks to the same sum over its real length. It is released when the reply's last byte is written to the pipe, or when the call is cancelled and its reply dropped. A stream's charge goes at its terminal.
- **No room:** the call isn't sent. It is answered `{ failed: "busy" }`, which the page sees as 4900 `busy`.
- **Exempt:** control frames (credit, `cancel`, `abort`, `end`), `shell.swarm_ready` answers, `{ failed }` and `invalid_argument` answers, and stream heads. Each is small, and the 64 outstanding calls bound them. They go on while the pool is full, as 0005's do.
- **Results for pages:** a `swarm.request` result of 64 KiB or more (a read's data) is charged twice its serialized length, fragment by fragment as it arrives, until main hands it to the page. One main can't charge is dropped, and the page gets 4900 `busy`. The core sends no more at once than [its own memory](#the-swarm-threads-memory) holds.
- **Main's replies to the core:** `service-client.js` charges `shell.swarm_*` replies to this pool, not to the chain I/O pool ([Amendments](#amendments)).

**Reading a body,** as 0014's fetches do:
- **Decoded bytes count.** Main asks with `accept-encoding: identity`, and the stack decodes anything else. `max_bytes` and the charge are of decoded bytes, so a small compressed body that inflates past `max_bytes` stops there.
- **`Content-Length` is a hint.** A declared length over `max_bytes` fails a whole call `too_large` before the body is read. A stream gets the reply's head, then ends with the abort code `too_large` before any piece, so the core checks the head first and reports the declared length (#1057's `actual`; a latest feed entry's index headers are checked before it, as the reference does). A missing one changes nothing, and a chunked body is read as one without a length. One that lies low is stopped at `max_bytes`; a body that ends short of its declared length fails in the stack (`error`).
- **Past `max_bytes`:** a whole read is aborted, `too_large`; a stream ends with the abort code `too_large`.
- **Slow bodies:** a whole body that gets no byte for 60 s fails `error`, as a stream's idle bound does. Any read ends at its request's deadline, when the core cancels it.
- **Cancel** aborts the dial or the read, ends an open stream with `cancelled`, and releases the charge once nothing of it is held.

**What #1056 and #1057 leave for the core.** They bound a feed read for one site: the explicit index from its span before `/bytes`, the latest entry from its declared length or piece by piece, each held to that size. That closes F-1 for a site. Left:
- **Nothing bounds all sites together.** Each site's window bounds that site only, and main still makes each read's base64 result, a third more. Many sites can hold their windows at once.
- **The other whole bodies** (`/stamps`, tags, addresses, upload results, and the error bodies of bee-js's calls) are still read whole, with no cap.
- **No deadline or cancel:** `fetchNode` and bee-js's calls take no signal, so a slow node holds a read and its reservation until it answers.
- **The node's join** of a feed entry is held to its length, not checked.
- **Node's own `fetch`** (F-6).

The core keeps their semantics byte for byte: the vectors pin a commit with #1057. It adds the rest: its own reservations, this pool, deadlines, the session's transport, and 0009's walk for `readData`. A feed entry's join stays the node's, held to its span as #1057 holds it.

**The tests** (SWM-5, main against a scripted core and a scripted node), each also checking that the pool returns to zero and that credit, cancels and other calls' frames go on:
- **Concurrent maximum calls:** whole calls at their caps (`/stamps` of 1 MiB, and chunks) until their charges would pass 64 MiB, with streamed reads and upload bodies beside them. The pool never passes 64 MiB; a call that doesn't fit gets `busy` and nothing is dialed for it.
- **Exhaustion:** the core stops reading its pipe, so replies wait unwritten until the pool is full. A new call is `busy`, while `shell.swarm_ready` answers, credit, `cancel` and stream heads still go out.
- **Bodies:**
  - a missing `Content-Length`; one over `max_bytes`, refused before the body; one that lies low, stopped at `max_bytes`; one that lies high, `error` at the short end;
  - a chunked body; a gzip body sent despite `identity`, inflating past `max_bytes`;
  - a body that trickles: the 60 s idle bound, and the deadline;
  - error bodies: empty, JSON, text, and past 8 KiB (cut).
- **Peaks:** the largest whole reply's base64 and serialized copies measured against its charge, and resident memory sampled through 64 concurrent maximum calls.
- **Cancel:** mid-dial, mid-body, mid-stream, and after the reply is serialized but before it is written. Each charge is released once nothing of it is held.

### The transport

- **The node's transport, as 0009's pieces use it** (`plan-executor.js`, `dweb-shell.js`): undici on loopback for the bundled node; for a remote external node, the session's stack (`net.request`) with its proxy, Tor and the onion gate.
- **POST is new on that path.** The Ant guard lets a frameless GET or HEAD of an announced URL through (`ant-api-main-dials.js`, `ant-api-guard.js:28–38`). Main's POSTs to a remote node would go through `session.webRequest` and be cancelled, so an announcement names its method too, and the guard lets through exactly that method to exactly that URL. Today's POSTs don't meet the guard only because bee-js uses Node's stack.
- **A body** is pulled from the core only as the node takes it; main holds at most one window per stream (0007's ring).
- **Main's own reads** (`ant-storage-api.js`'s `antRequest`, for readiness, setup and the agent) move onto the same transport in SWM-8. That closes F-6 for every HTTP call to the node.
- **WebSockets** stay on Node's stack: main can't carry one through the session yet ([question 4](#open-questions)).

### What today's node needs

The bundled `antd` serves its HTTP API on a loopback TCP port (1633 by default), without authentication, with admin routes beside the content routes (`ant-api-guard.js:5–11`). Main and Chromium reach it there, and the guard keeps pages off it. It is the node's design, outside this one and left as it is.

0015 makes it no worse. It adds no port and no listener; the core never learns the URL. Main's calls narrow from anything bee-js can send to the calls each operation allows, and no renderer gets a new way to the port. A node that later offered a pipe or an authenticated API would change main's transport only, not the core.

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

- **The tar** is bee-js's `TarStream` byte for byte (`utils/tar.js`): ustar headers with mode `0000777`, owner and group `0001750`, the modification time from the core's clock, the checksum and type `0`; padding to 512 bytes; 1,024 zero bytes at the end. Entries are in the page's order, under the page's paths with `/`, as #1057's `publishCollection` writes them. A long name splits by UTF-8 bytes, or takes a GNU long-link entry as bee-js does past 100 units (F-3 fixed).
- **One file** (`publishData`, and a picked file for `freedom://publish`) is its bytes, with `name` in the query and the headers `bee.file.upload` sends (`api/bzz.js:19–40`): `content-type`, the batch, `swarm-pin: true`, and `swarm-deferred-upload` false for `publishData`, true for files and collections, as today.
- **The chunk tree** is Swarm's: leaves of 4,096 bytes, intermediate chunks of up to 128 references, each span the length below it, with no erasure coding and no encryption. It matches core-sdk's `ChunkSplitter`, which the vectors pin. The core builds it for a feed entry over one chunk, and for the address of a `publishChunk`.

### What the core checks

- **A feed entry over one chunk:** the core streams it to `POST /bytes`, computes the root chunk as the bytes pass, and refuses the write if the node's reference differs. The SOC wraps the core's root chunk. Today's second round trip, `GET /chunks` for the root (`feed-service.js:377`), goes.
- **A chunk:** the core computes its address and checks the node's.
- **A `/bzz` upload:** nothing beyond the answer's form. The node builds the manifest.
- **An encrypted upload** (the agent's private drafts, `swarm-encrypt: true`): nothing; the node picks the keys.

### Bounds

- **Sizes** stay today's: 10 MiB of data, 50 MiB and 100 files, paths of 100 bytes ([Q22](#open-questions)). Feed entries get the 10 MiB (question 3, F-4).
- **At most four uploads stream at once** in the core; the rest wait their turn. Only a streamed body takes a place; a body the params carry goes whole, as `{ base64 }`. 0011 already lets main take only two page uploads at once across the browser.
- **Per upload:** one incoming and one outgoing window of 128 KiB, the chunker's leaf buffer and up to 128 references per level (at most eight levels below 2^64 bytes, so about 36 KiB; three at 50 MiB), and one tar header: about 300 KiB.
- **Credit goes in only when it can go out:** the core grants credit on a part only while its `swarm.body` window has room. A node that stops reading holds one window in each direction, and the idle bound ends the upload after 60 s.
- **Main** holds the page's IPC value until the request ends (0011's charge) and one ring per stream, each charged to the [Swarm I/O pool](#mains-swarm-io-pool). `normalizeBytes`'s copy of a `Uint8Array` goes, so a 50 MiB upload costs main one copy fewer; the temp directory already went with #1057.

## Feeds, SOCs and SW-1

- **Feed writes** (`updateFeed`, `writeFeedEntry`): the core computes the topic from the page's key and the feed's name, the index from the node's answers (or the page's explicit index), and the identifier `keccak256(topic ‖ index as 8 bytes, big-endian)`. A page never names the identifier of a feed write. The key is the feed's identity recorded at creation, else the active one (`getFeedIdentity`, `spi:1204–1216`).
- **Index lookups** ask `GET /feeds` with `swarm-only-root-chunk: true`, as 0009's feed pieces do, and take the next index from `swarm-feed-index-next`, as today's `resolveNetworkNextIndex` does through bee-js, which requires that header and `swarm-feed-index` (`feed-service.js:483–498`; its `+ 1` fallback never runs). Today the lookup downloads the latest payload whole just to learn its index. A 404 or a 500 falls back to today's head probe over `GET /chunks` (`probeFeedHead`, at most 81 reads), as `isNotFoundError` reads the lookup today. An explicit index is checked as #1057's `feedEntryExists` checks it: its SOC only, and only a 404 frees it. Writes to one topic go one at a time in the swarm thread.
- **Keys:** a publisher key signs only inside `swarm.request`, for the page key whose identity holds its index. `swarm.feed` takes only the Bee wallet key (main's own feeds). A mined GSOC key signs only GSOC messages.
- **`swarm.sign_soc`** loses `chrome` at SWM-4: nothing in the chrome calls it. Main calls it as `shell` for its own SOCs (`vault-backend.js:55–63`), and from 0012's APB-3 as `page` for a page's, with its `PageContext` and `{ swarm }`, never as `shell`. It goes at SWM-9, once nothing calls it.
- **Reads:** `readChunk` and `readSingleOwnerChunk` check the chunk by bee-js's and core-sdk's own rules (an address, or a SOC's signature and address), as `unmarshal*` does in main today, over `fc-swarm::verify`'s hashes. 0009's rules are stricter, and would refuse chunks the reference returns: bee-js refuses an empty content-addressed payload, recovers a SOC's owner the way core-sdk does (any `v`, a high `s`), and treats the replicas owner like any other. A SOC's address still binds its owner, so every SOC accepted is signed by the owner its address names. `readData` reads through 0009's verified file walk, its pieces as `shell.swarm_api` GETs, where today the node's whole `/bytes` join is taken on its length. That walk reads the leaves as one ranged `GET /bytes` stream and checks each 4 KiB leaf against the address its verified parent names before using it (0009, *Leaves*). A leaf that fails is fetched once as `/chunks/<address>`. So the ranged `bytes` in the `readData` row is the verified leaf stream; the reference's unranged join is the deviation `read-data-verified`, refused to the core. A feed entry is read as #1057 reads it: at an explicit index, its SOC, charged once read, then the size from its span reserved before `GET /bytes`, which streams and is held to exactly that size; the latest entry streamed, reserved from its declared length or as it comes, its `max_bytes` the site's `maxBytes`.

### SW-1 in the core

`writeSingleOwnerChunk` keeps today's order: the params, the feed grant, #89's refusal, SW-1, the vault, the readiness check, then the signature, the batch and the upload.
- **The check** stays in today's place, with today's cases and errors.
- **The re-check:** in today's order the vault and the readiness check come between the check and the signature, and either can take seconds. So the swarm thread runs SW-1 again, with the feed-grant check, the name's binding and the document's key, in the step that hands the signature to the vault. If any fails now, the request ends with the error that check gives, and nothing is signed. Custody and the rule are checked again before the upload, with the rest of the guard in the reference's order, as the reference does (`write-feed-rule-custody-before-write` records it signing after custody changed and refusing at the upload). "The vault" is an ask for the key's owner; a locked vault gives the reference's text for each key mode, and a switch to another exclusive identity before the signature asks for the new key's owner and checks again.
- **The hold:** from that re-check until the vault answers, the swarm thread defers every store change that could change the re-check's answer:
  - another site's identity taking the publisher index (a set with an explicit index, which the store's API keeps for parity and no method calls today);
  - a change of the site's active identity (activate, or create or ensure with `activate`);
  - a revoke of the site's feed grant.

  Every store change goes through the swarm thread, so none lands in between. Deferred changes apply in their order once the hold ends. Other store writes go on.
- **The boundary is the signature.** The vault answers in milliseconds, and the hold ends then, or at the request's cancel or deadline if earlier. A signature that arrives after a cancel is dropped, and nothing is uploaded. Once a signature exists, the upload goes ahead, as one made just before the change would.
- **A deferred change whose write fails** fails for its own caller with the store's error, and the store stays as it was: 0013's rule changes memory only after the durable write.
- **Allocation never repeats an index** (F-8): the core allocates the larger of `nextPublisherKeyIndex` and one past every stored index, so it can't hand out a held index and needs no hold (deviation `index-allocation`).
- So no identity can become shared between the check that passes and the signature, as it can today between main's check and the core's signature. 0012's table row for a page's SOC, enforced from APR-4 by the page's Swarm grant, no longer has main name the key and the identifier.

**The interleaving gate:** SWM-3 on the machine, which is sans-I/O so every interleaving is a fixed script, and SWM-4 again through the pipe, with the swarm thread's pause points as test hooks. The vault counts signatures and the node counts `POST /soc`. Each case is deterministic:
- **The change wins:** pause a raw SOC after its first SW-1 check; another site takes its index; resume. 4100 `shared_identity`, no signature, no upload. The same for a switch of the site's active identity to a shared one, and for a revoke of the grant (today's no-grant error).
- **The change waits:** pause after the re-check, with the vault's answer held back. The other site's change doesn't complete and writes nothing. Release the vault: every held change applies as the signature ends the hold, before the SOC's batch read and upload. An index or identity change leaves the signed SOC to be uploaded, and the site's next raw SOC is refused; a held revoke makes the upload's guard refuse that SOC, as it refuses one signed just before a revoke.
- **Cancel during the hold:** the deferred change completes at once, the late signature is dropped, and nothing is uploaded.
- **A write failure during the hold:** the deferred change's write fails, so its caller gets the store's error, the store is unchanged, and the next raw SOC passes. Another store write that fails during the hold leaves the hold and the SOC as they were.
- **Allocation:** with the counter at or below the held index, an allocation during the hold takes a fresh index and isn't deferred.
- **The deadline** passing during the hold ends it as a cancel does.

## Messaging and GSOC mining

- **PSS:** the core validates and checks the grant, chooses the batch (a full mutable batch allowed, as today: `selectMessageBatch`, `messaging-service.js:232–238`), and sends `POST /pss/send/…`. The node mines the trojan chunk, as today.
- **GSOC:** the identifier is `keccak256(utf8(topic))` and the target `keccak256(utf8("freedom-gsoc-v1:" + topic))` (`messaging-service.js:38–54`), frozen. The core mines the signer, builds the chunk, signs the SOC with the mined key, and sends `POST /soc/…`. The page gets the address, never the key, as today. A mined key is public by construction (anyone mines the same one from the topic) and holds nothing of the vault.
- **Subscribe:** the core validates and checks the grant, asks `shell.swarm_ready { check: "subscribe" }` where today's code probes reachability, derives the key (the GSOC address, or the PSS topic's hash) and answers `{ subscribe: { kind, key } }`. Main opens the socket and binds it to the document.
- **Subscriptions over a proxy** ([question 4](#open-questions), decided 2026-11-24: refused, and the user told):
  - for a node not on loopback while the session has a proxy or Tor on, main answers the `subscribe` check `{ ok: false, reason: "proxy-or-tor" }` without dialing. The page gets today's unavailable shape: 4900, message `Node not available: proxy-or-tor`, `data: { reason: "proxy-or-tor" }`;
  - main checks again just before it opens the socket, since a GSOC topic can be mined meanwhile, and refuses with the same error. No WebSocket is opened;
  - when a proxy or Tor comes on, main ends the open subscriptions to such a node as a revoked grant ends them (`subscriptionRegistry.cancelByOrigin`), and doesn't reconnect them;
  - a loopback node, the bundled one included, is unaffected;
  - **the user is told,** the user's condition on the answer. How is the coordinator's call, which the user may veto:
    - a refusal, or a subscription ended this way, shows a notice in the chrome, once per site per session: "Live messages from <site> are off while Tor is on: they would go around it to your external Swarm node" ("your proxy" when it's the proxy);
    - while the Swarm node is one the refusal covers (an external node not on loopback, by the same test) and a proxy or Tor is on, the Nodes panel says "Live messages are off while Tor is on: they would go around it to your external node", as it shows the node's other conditions;
    - Settings > Nodes says the same under the external Swarm node, on the same condition. An external node on loopback (the field's own `http://127.0.0.1:1633`) still subscribes, so neither line shows for it.

**Mining, in the core:**
- **Where:** one **mining lane**, a thread in `freedom-cored`. It is arithmetic on public inputs, with no parser of untrusted structure, so it needs no process of its own ([Options weighed](#options-weighed)).
- **The search is bee-js's** (`modules/messaging.js:154–168`, the same in 13.1.0 and 13.2.0): private keys `0xb33 + i` for `i` below 65,535; the first whose SOC address shares at least 12 leading bits with the target wins; none is `gsoc_mining_failed`, as today. Same inputs, same signer, so every existing room keeps its address.
- **In batches:** `fc-swarm::gsoc::Miner` holds the search's state (the next candidate and its point), and `step(n)` tries at most `n` candidates and returns `found(i)`, `more` or `exhausted`. The lane runs a job 256 candidates at a time. Between batches it checks the job's cancel and its deadline on the core's clock. Each candidate costs the same fixed work, and a batch tries at most 256 of them: it returns early at a match, and otherwise runs to its 256th. So a batch's worst case is bounded and doesn't depend on the input, estimated under 10 ms. A job therefore ends within one batch of its deadline or its cancel, and the lane takes the next job then. `gsoc::mine`, the whole search in one call, is the same search, for the vectors.
- **Time:** bee-js needs about 5 s for all 65,535 candidates on Electron's Node (`gsoc-miner.js:24–26`). In Rust, a candidate is one point step (the generator added to the last key's point gives the next key's) and two Keccak hashes. About 4,096 candidates are expected: estimated under 0.1 s, and under 2 s at the cap. SWM-2 measures a batch and both cases on three OSes.
- **Measured (SWM-2, #477, CI run 45417799574; `fc-swarm` built optimized, `gsoc_timing`):**

  | | Linux x86_64 | macOS aarch64 | Windows x86_64 | Estimate |
  |---|---|---|---|---|
  | A batch of 256, median / slowest | 0.77 / 0.81 ms | 0.34 / 0.74 ms | 0.76 / 0.98 ms | 10 ms |
  | The cap, 65,535 candidates (`Miner::step` / `mine`) | 197 / 197 ms | 89 / 88 ms | 198 / 198 ms | 2 s |
  | Proximity 12, slowest of 16 topics | 26 ms | 11 ms | 26 ms | 0.1 s |

  Every figure is well inside its estimate. The 1 s stuck-batch watchdog is over a thousand times a batch's time.
- **Today's budgets, kept** (`messaging-service.js:83–144`, `gsoc-miner.js:1–28`):
  - 16 new topics a minute per site; a job that fails counts, while cache hits and joins are free;
  - a cache of 128 topics;
  - a second request for a topic in flight joins the first, and its site becomes an owner of the queued job;
  - fair turns: one queue per site, served round-robin, one job per turn;
  - one job at a time, so mining takes at most one CPU core;
  - 15 s per job from its dispatch (`MINE_TIMEOUT_MS`), then `gsoc_mining_timeout` with today's text. Today the worker is terminated at that point.

  Today nothing bounds the queue: `mineSigner` queues every job, and there is no `busy`.
- **New limits:**
  - at most 16 jobs waiting per site and 256 in all; past either, `busy` (4900, `data.reason: "busy"`), and nothing is mined for it;
  - a waiter's cancel or deadline ends only its own wait. The job stops at the next batch when its last waiter has gone;
  - **a batch that doesn't return:** a watchdog on the swarm thread marks the lane stuck after 1 s on one batch, a hundred times its estimate. The job ends `gsoc_mining_failed` (`GSOC mining failed: mining lane stuck`), and a new lane thread takes the queue. The stuck thread can't be stopped safely, so it is left, and its answer, if any, is dropped. A second stuck lane in one start turns mining off until the core restarts: jobs end `gsoc_mining_failed`. Only a bug reaches this, since a batch's work is bounded.
- **The tests:**
  - **SWM-2:** `step` over any split into batches finds the same signer as one `mine` call and as bee-js (the `gsoc` vectors), and no `step(n)` tries more than `n` candidates;
  - **SWM-4,** on the lane with the core's test hooks (its clock and a delay per batch):
    - **a forced-slow job:** a delay per batch pushes a job past 15 s. It ends `gsoc_mining_timeout` within one batch of the 15 s, and the next queued job then runs and succeeds;
    - **cancel:** the only waiter's cancel stops the job within one batch, and the next job starts. With two waiters (a join), one cancel leaves the job running for the other;
    - **saturation:** one site's 17th waiting job and the 257th in all get `busy`, and nothing is mined for them; another site's jobs are still admitted within its own 16 while the queue has room;
    - **fairness:** today's `gsoc-miner.test.js` order cases (round-robin, a join taking a turn of its own) pass against the lane;
    - **recovery:** after a timeout, a cancel and a stuck batch (a hook that blocks it), the next job runs on a working lane and gives bee-js's signer. A second stuck batch turns mining off with `gsoc_mining_failed`;
    - `vault.lock` is answered within 0009's gate while the lane mines.

## Every bee-js call, mapped

| bee-js in main | Node call | Replaced by |
|---|---|---|
| `file.upload` (`publish-service.js:121`, `:148`) | `POST /bzz?name=` | the core: `swarm.request` (`publishData`), `swarm.publish` (`freedom://publish`'s data and file) |
| `collection.uploadFromDirectory` (`:180`), `collection.upload` (`:216`) | `POST /bzz` with a tar | the core's tar writer: `swarm.request` (`publishFiles`), `swarm.publish` (a picked directory, read by main; the agent's collections) |
| `tag.get` (`:284`) | `GET /tags/<uid>` | the core: `getUploadStatus`, `swarm.upload_status` |
| `chunk.upload`, `makeContentAddressedChunk` (`chunk-service.js:130–133`, `:285`; `swarm-signer.js:50`) | `POST /chunks` | the core (`fc-swarm`) |
| `chunk.download`, `unmarshalContentAddressedChunk`, `unmarshalSingleOwnerChunk`, `calculateSingleOwnerChunkAddress` (`chunk-service.js:146–324`; `feed-service.js:115–140`; `messaging-service.js:160`) | `GET /chunks/<ref>` | the core: the reference's rules over `fc-swarm::verify`'s hashes ([Reads](#feeds-socs-and-sw-1)) |
| `data.download` (`chunk-service.js:257`; `feed-service.js:121`), `data.downloadReadable` (#1057's feed reads) | `GET /bytes/<ref>` | the core: 0009's file walk for `readData`; a held stream for a feed entry |
| `data.upload` (`feed-service.js:376`) | `POST /bytes` | the core, with its own root |
| `feed.createManifest` (`:264`), `feed.makeReader().downloadPayload` (`:304`, `:351`, `:409`, `:461`), #1057's `fetchNode` | `POST`/`GET /feeds/<owner>/<topic>` | the core |
| `messaging.pssSend` (`messaging-service.js:252`), `gsocSend` (`:265`), `gsocMine` (`gsoc-miner-worker.js:22`) | `POST /pss/send`, `POST /soc` | the core and its mining lane |
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

- **`fc-swarm`** (logic, exists) gains the write side: the chunk tree, the tar writer, feed topics and identifiers, update payloads, SOC bodies, and GSOC mining: `gsoc::Miner` with `step(n)`, and `gsoc::mine(target, identifier, proximity)`, both within the fixed bound.
- **`fc-swarm-provider`** (logic, new): the method machines, sans-I/O. Each machine asks for what it needs (a node call, a part, a readiness answer, a store read or write, a signature, the clock) and is handed the answer. It holds validation and texts, the rules and SW-1 (with the re-check and the hold), batch choice (`selectBestBatch`, `swarm-service.js:140–213`, over bee-js's `mapPostageBatch` arithmetic, IEEE doubles included; powers of two with an integer exponent are exact, and a batch whose `depth` or `bucketDepth` isn't an integer, which zod's `number` admits but no node sends, is refused, so no fractional power is computed (deviation `batch-depth`)), tag and error mapping (`nodeWriteError`, `mapChunkReadError`, `isBatchNotYetKnownError`), the three stores' codecs and rules, and the charge each call needs ([below](#the-swarm-threads-memory)). 0012's `fc-approval` supplies the connection grant. It builds for iOS and Android, as AGENTS rule 2 requires.
- **`freedom-cored`** runs them on a **swarm thread** beside naming's, chain's and dweb's, with the **mining lane** beside it. Chunk-tree hashing goes to 0009's hashing pool. The stores go through 0013's `fc-store` (durable writes, today's text byte for byte, SQLite through `rusqlite` with the schema kept, one writer).

### The swarm thread's memory

The swarm thread's 64 MiB is reserved before use: when a request is admitted, and before each call that brings bytes in. `b64(m)` is 4⌈m / 3⌉.
- **A request:** 64 KiB when it is admitted (its params, state and texts); for an upload, 300 KiB more when it starts ([Bounds](#bounds)); for a mining job, 4 KiB.
- **A whole call,** reserved before its `shell.swarm_api` goes, and never less than 512 KiB, since any call can bring an error body and [its transcoding](#json-replies):
  - a binary body (`chunk`, `feed_head`): `m + 2 × b64(m) + 16 KiB`, `m` the form's cap;
  - a JSON body (`stamps`, `stamp`, `tag`, `addresses`, an upload's result): `4m + 2 × b64(m) + 16 KiB + E × 256 B`, `E` the reply type's element cap below, the fourth `m` for a schema refusal's text ([JSON replies](#json-replies));
  - the parts: the reply as it is reassembled (`b64(m) + 16 KiB`), its parsed base64 text (`b64(m)`), the decoded bytes (`m`) and, for JSON, what the [typed reader](#json-replies) keeps (`2m + E × 256 B`). Each copy is dropped as the next is made. The charge counts them all at once.
- **A streamed read for a page:** `n + 2 × b64(n) + 16 KiB`, where `n` is what the read may hold, and at least 512 KiB for an error: the size reserved from the site's budget for an explicit index, or the room left in its window for the latest entry. That covers the bytes as they come, the result's base64 and the serialized reply.
- **The reader** takes the reply's bound from the request's entry, `b64(m) + 16 KiB`, so a fragmented reply never grows past its reservation. A longer one is a protocol error; main sends none.
- **Released:**
  - a call's charge when the step that consumes its reply ends;
  - a read's charge once its reply to `swarm.request` is written to the pipe;
  - a request's base at its end;
  - a cancelled call's charge only once main's answer has been read and dropped, or its stream's terminal has come: a cancel doesn't stop a reply already sent (0001).
- **No room:** the reservation waits, first in first out, until its request's deadline, and then the request ends `busy`. A request waiting holds only its base. The largest charge, a 5 MiB read at 18.4 MiB, always fits.
- **Incoming stream credit** stays the 4 MiB allowance ([Streams](#streams)). The bytes it admits land in the charges above.

**The tests** (SWM-4, the binary against a scripted main):
- **Concurrent maximum reads:** eight connected sites each read a 5 MiB feed entry at once, four the latest entry and four at an explicit index. The charges never pass 64 MiB, the reads that don't fit wait and then complete in order, and resident memory stays within the charges plus the process's base.
- **Reassembly:** a fragmented 1 MiB `/stamps` reply is reassembled within its reservation; one longer than its bound is a protocol error.
- **Dense JSON:** eight 1 MiB `/stamps` replies at once, each one of the adversarial shapes in [JSON replies](#json-replies), parsed while the memory is sampled. Resident memory stays within their charges plus the process's base.
- **Cancel** at each stage: before the reply, mid-stream, and with the reply in flight. Each charge is released only once main's answer is consumed.

#### JSON replies

The core never parses a node's reply into a generic JSON value: a dense array of `m / 2` scalars would cost one value-sized element each, many times `m`. Each JSON reply type has a **typed reader** instead. It reads the bytes once, keeps only the fields the core uses, skips every other value without keeping it, and stops at fixed caps:
- **What it can hold:** the strings it keeps, each a copy of bytes from the reply, so at most `m` together; the parser's scratch for one escaped string, at most `m`; and at most `E` elements of at most 256 bytes each, numbers and flags read as JavaScript reads them (IEEE doubles, `fc-json`'s rules). That is the `2m + E × 256 B` above.
- **Its caps,** past which the call fails `too_large` (deviation `reply-bounds`):

  | Reply | Kept | `E` | Its charge at the form's cap |
  |---|---|---|---|
  | `/stamps` (1 MiB) | per batch, the fields `mapPostageBatch` reads, its label as it came, and `exists` and `propagating` (the batch choice reads both); for a reply bee-js's schema refuses, each field's type, for the refusal's text | 4,096 batches | 7.7 MiB |
  | `/stamps/<b>` (64 KiB) | one batch, the same fields | 1 | 0.5 MiB (the floor) |
  | `/tags/<uid>` (64 KiB) | `normalizeTag`'s fields | 1 | 0.5 MiB (the floor) |
  | `/addresses` (64 KiB) | `overlay`, `ethereum`, `publicKey` and `pssPublicKey` as they came (core-sdk's transform runs on each, and can throw), every field's type for zod's issues, and up to 512 `underlay` elements that aren't strings (an index and a type, 8 B each; past 512 their issues can't fit the refusal's 64 KiB); the underlay's strings skipped | 1 | 0.5 MiB (the floor): the four strings are within the kept strings' `m` and the refusal's text within the fourth `m`; the 512 entries (4 KiB) and the refusal's issue list (at most 378 issues of 80 B, 40 KiB as allocated) fit in the 69 KiB the floor holds above `4m + 2 × b64(m) + 16 KiB + 256 B` |
  | an upload's result (64 KiB) | `reference` | 1 | 0.5 MiB (the floor) |

- **Skipped values** cost nothing kept: the reader counts their nesting, at most 64 deep, past which the call fails `error`, and keeps no element of them.
- **A repeated key** keeps the last value, as `JSON.parse` does, overwriting in place.
- **A reply bee-js's schema refuses** (zod 4, `GetAllPostageBatchesResponse` and the tag and address schemas) reaches the page as the `ZodError`'s message, through `nodeWriteError` as -32603 (`publish-data-stamps-malformed`). That text is `JSON.stringify(issues, null, 2)`, about 200 bytes for each field of the wrong type, so 4,096 empty batches would give some 8 MiB. The core writes the same text, held to the reply form's own cap (1 MiB for `/stamps`, 64 KiB for the others), and past it the call fails `too_large` (deviation `reply-bounds`). The charges above include it.
- **A JSON reply that doesn't parse,** where the reference shows V8's `SyntaxError` text (bee-js's reads: `/stamps`, `/stamps/<b>`, `/tags/<uid>`, `/addresses`, and the results of the uploads bee-js makes; and `chunk-service.js`'s SOC upload, which parses its success reply with `Response.json()`), fails `error` with -32603 `Swarm node reply is not valid JSON` (deviation `reply-syntax`). Where the reference gives its own text, the core keeps it: a page's upload result that isn't JSON is `page-upload.js`'s `The node answered the upload with no reference` (`publish-data-node-not-json`).
- **Error bodies,** at most 8 KiB, are the one reply whose whole value matters: the page's text is `JSON.stringify` of its parse, and `isChunkNotFoundError` reads its `message`. A transcoder writes that text as it reads, holding only the text and each open object's keys and members until the object closes, so a repeated key keeps its first place and its last value, as `JSON.parse` gives them. The text can be 5.25 times the body, because `JSON.stringify` writes a number in full below 10^21 (`1e20` becomes 21 digits; 8 KiB of `[1e20,…]` gives 36,037 bytes). Each open object's members are held with an index of their keys, each key twice, at most about 250 bytes a member with the allocators' slack, and an 8 KiB body has at most about 1,400 members. So the transcoding holds well under 512 KiB, the floor above, and SWM-4's memory gate measures it.
- **The tests** (SWM-3 on the readers; SWM-4's memory gate): replies at each cap and one past it; a 1 MiB dense array of `0,` under an unknown key; 4,096 minimal batches; one batch whose label is the whole reply; nesting at 64 and 65; a key repeated through the whole reply; and error bodies that are dense arrays, deep objects, repeated keys and lone surrogates, against `JSON.stringify(JSON.parse(text))`. Each reader's kept bytes are measured against its charge, and SWM-4 runs eight such `/stamps` replies at once with resident memory within the charges.

### Budgets

| What | Bound (proposed) |
|---|---|
| Running `swarm.request` and `swarm.publish` | 64; 256 wait; beyond that `busy`: 4900 with `data.reason: "busy"` for a page's `swarm.request`, the protocol error `busy` for `swarm.publish` (SWM-4, D5) |
| Every other parent that asks main, the node or the vault: `swarm.feed`, `swarm.stamps`, `swarm.upload_status`, `swarm.manifest`'s `check`, and `swarm.identities`' ops that read owners (SWM-4, D5) | in the same 64 and 256; beyond that the protocol error `busy`. The other store ops (`swarm.history`, `swarm.manifest`'s `list`, `decide` and `revoke`, `swarm.identities`' other ops) take no place in the gate: they run in the swarm thread's order, and a change SW-1's hold defers (an activation, a revoke, an index taken) waits for the hold's end, which the vault's answer, a cancel or the deadline bounds |
| Outstanding `shell.swarm_api` | 64 |
| Uploads streaming | 4 |
| The swarm thread's memory for requests and bodies | 64 MiB, reserved before use ([above](#the-swarm-threads-memory)), apart from the stores |
| Main's Swarm I/O pool | 64 MiB, reserved before the dial ([Main's Swarm I/O pool](#mains-swarm-io-pool)) |
| `swarm-feeds.json` | 16 MiB; a write past it refused (`store_full`: -32603 `Swarm feed store is full`); a file past it at load is kept aside as one that doesn't parse |
| `swarm-manifest-grants.json` | 1 MiB, the same way; a file past it at load is unreadable, and the `.bak` copy is read instead |
| `publish-history.sqlite` | 10,000 rows, trimmed after each insert and at open: finished rows first, oldest first, then the oldest others, never the row just inserted (a clock set back would make it the oldest), so the table never holds more |
| Mining | one lane; batches of 256 candidates; 16 jobs waiting per site and 256 in all, then `busy`; a stuck batch's watchdog at 1 s |

Today's code has none of these. Its own budgets stay as they are: the read budgets, the 16 new topics a minute, the 128-topic cache, the 32 subscriptions per site and 15 s per mining job. SWM-4 measures the uploads, the reads and the mining, and replaces the numbers if needed.

## Vectors

`vectors/swarm.json`, generated from the JS reference (AGENTS rule 5) by `vectors/generator/swarm.js`, with the harness `naming.json` uses: the browser's own modules at the pin, Electron stubbed, no reference code copied. Global `fetch` and `WebSocket` are a recording fake node with scripted answers, the clock is fixed, and signatures come from bee-js's own signer with the test keys of `keys.json`.
- **The reference** is the browser at an `integration/rust-core` commit that has #1057, with bee-js 13.2.0 exactly, as its lockfile pins. CI's vectors job checks that commit out fresh and installs it with `npm ci --ignore-scripts` from its own lockfile, as for every vector file. The generator asserts `@ethersphere/bee-js` 13.2.0 and `@ethersphere/core-sdk` 0.2.2 from their installed `package.json` (`packageVersion`) and records both in `meta`. So a checkout with another install, like the reference checkout's 13.1.0, fails rather than generating. No bee-js code is taken or run from outside that install.
- **`methods`:** each method, through main's page dispatcher (`src/main/page/page-swarm.js`, loaded whole, with only its UI and core boundaries scripted), with params in the typed form, the stores before, the grants, the approval path (the prompt shown or the rule that applied, auto-approve and its absence, Agent custody, the rechecks just before an effect) and the scripted node. It records the result or error; every node request (method, path, query, headers, and the body's bytes, or its length and SHA-256); the stores' text after; the history rows. Tables of bad params, one failing check per case, pin the order of checks.
- **The grammar** (`vectors/swarm-grammar.json`, written from [the table](#the-operation-grammar)): the generator checks every request each case records against its operation's row. It fails on any that matches no row and isn't one of a named deviation's requests: the reference's second `/stamps` read, its whole `/feeds` download for an index, its `GET /chunks` after a `/bytes` upload, and `readData`'s whole `/bytes`. `sendPss`'s 128-hex recipient isn't among them: the reference has #1062, so it is a forbidden call like any other. It also writes each row's honest calls and forbidden alternatives into the file ([the rules](#the-operation-grammar)).
- **`bodies`:** the tars bee-js writes for `window.swarm`'s path forms; single-file uploads; the `/bytes` path of a large feed entry; SOC, chunk and PSS bodies.
- **`trees`:** core-sdk's `ChunkSplitter` roots and root chunks over seeded data of 0, 1, 4,095, 4,096, 4,097, 524,288, 524,289 bytes and 10 MiB.
- **`stamps`:** `mapPostageBatch` over recorded `/stamps` answers (usable, propagating, full immutable, full mutable, missing fields), and `selectBestBatch` with each option over them.
- **`feeds`:** topics, identifiers, update payloads, the index runs of `resolveNextIndex` and `probeFeedHead` over scripted nodes, `feedEntryExists`' answers (404, 500, 503, a timeout, a chunk that isn't the SOC), and #1057's metered reads: a SOC charged, a span past `maxBytes`, a join longer or shorter than its span, a declared length past the budget or what is left of it, a body without one cut mid-way, a one-chunk entry held to its wrapped span; and a feed write's empty payload, refused before anything is signed.
- **`gsoc`:** `gsocMine`'s signers and addresses for topics (empty, Unicode, at 256 bytes), and at higher proximities, so the cap and the failure are covered.
- **`errors`,** from bee-js 13.2.0:
  - `throwHttpError`'s texts and data for statuses and reason phrases, over bodies that are a JSON object, a JSON string, `null`, a number, text, empty, whitespace, a BOM, bad UTF-8, and past 8 KiB;
  - at a JSON call site and at an array-buffer one (chunk and `/bytes` downloads), the sites where 13.1.0 would differ;
  - `isChunkNotFoundError` over them: a 500 `read chunk failed` from `GET /chunks` is `chunk_not_found`;
  - #1057's `fetchNode` texts (4,096 bytes, `Buffer.toString`), and `uploadSingleOwnerChunk`'s `SOC upload failed (…)`;
  - `nodeWriteError`'s and `mapChunkReadError`'s mappings.
- **`stores`:** `swarm-feeds.json` and `swarm-manifest-grants.json` after each operation, the v1 migration, a file that doesn't parse; `publish-history.sqlite`'s rows and schema.
- **Deviations** are marked (`deviation: <id>`), with the reference's own outcome beside the core's.

`generate.js check` passes, and `check.test.js`'s damaged copies fail it.

## Deviations

Against the reference pin, which has #1057. F-1's and F-5's first deviations (`feed-read-bound`, `index-check-500`) are gone: the reference itself now does what the core does.

| Id | Today | With the core |
|---|---|---|
| `feed-entry-bound` | no size limit (F-4) at the reference pin; browser main has #1233's cap, which `integration/rust-core` doesn't yet | 10 MiB, `payload_too_large` with `limit` and `actual` (question 3) |
| `tar-paths` | a name of over 100 UTF-8 bytes cut by bee-js (F-3): `swarm.publish` collections only, since a page's paths are at most 100 bytes | names counted in bytes |
| `feed-wrap-root` | the SOC wraps the root chunk the node sends back | the core's own root; a different node reference refused |
| `reference-check` | `publishChunk` answers its own address and ignores the node's; a `/bytes` upload's reference is taken as the node gives it (a SOC's is already checked, `chunk-service.js:120–123`); a GSOC send's isn't | all checked, a GSOC send's against its SOC address too; a mismatch is -32603 `The Swarm node returned another reference` |
| `read-data-verified` | `/bytes` joined by the node, unranged, its length checked | 0009's verified walk: chunks, and the leaves as one ranged `/bytes` stream, each leaf checked; bad data, a tree of more than 2,562 data children, and one deeper than 0009's eight levels are `chunk_type_mismatch` |
| `read-pieces` | a latest feed read without a declared length is reserved per network read, so after a refusal what stays charged depends on how the body arrived | reserved per data frame from main; what stays charged differs by less than one piece |
| `index-probe` | the latest payload downloaded whole to learn its index | the root chunk only |
| `index-allocation` | allocation trusts `nextPublisherKeyIndex` (F-8) | past every stored index |
| `stamps-one-read` | `GET /stamps` once or twice per write | once |
| `deadlines` | none for reads (F-7); a page's upload has `page-upload.js`'s 60 s and 300 s bounds, and a chunk or feed write 300 s | the page's timer; a 60 s idle bound on bodies; cancel when the document goes; for a request with no total deadline, 300 s for a whole node reply and 60 s without progress for each other ask of main (SWM-4, D13) |
| `busy` | none | 4900, `reason: "busy"`: the core's queue, its memory at a request's deadline, main's Swarm I/O pool, or the mining queue |
| `reply-bounds` | bee-js reads any reply whole | each form's cap, reply headers and the reason phrase bounded; past a cap, `too_large` |
| `error-body-bound` | bee-js reads a whole error body for its text | the text from the first 8 KiB |
| `reply-syntax` | V8's `SyntaxError` text for a JSON reply bee-js or the SOC uploader reads that doesn't parse | -32603 `Swarm node reply is not valid JSON` |
| `batch-depth` | a batch's sizes from a fractional `depth` or `bucketDepth` (`2 ** depth`, V8's `pow`) | the batch refused: -32603 `Swarm node reply has a non-integer batch depth` |
| `session-transport` | Node's `fetch` for every HTTP call (F-6) | the node's transport |
| `transport-error-text` | undici's message for each failure | one text per failure class |
| `subscribe-proxy` (question 4) | a subscription to a remote node goes around the proxy and Tor | refused while a proxy or Tor is on: 4900 `Node not available: proxy-or-tor`; open ones end; the user is told |
| `history-bound` | no bound | 10,000 rows, trimmed after each insert and at open (finished rows first, oldest first), never the row just inserted |
| `history-blobs` | a BLOB cell, which no writer makes, comes back from better-sqlite3 as a `Buffer`: a pass-through column answers it as is; `started_at` and a truthy `completed_at` go through `new Date(value)`, which reads the Buffer's text, so they give an ISO time or throw by its bytes (`X'30'` is 2000-01-01, `X'61'` throws) | every BLOB cell is refused, and the read that meets it fails, as a bad timestamp's does; the core writes none, so a page's bytes `name`, which the reference binds as a BLOB, is written as NULL |
| `store-shapes` | a store file it loads but then fails on (a manifest record of the wrong shape, a string `revision` concatenated), or a v2 feed map that isn't an object of objects kept as it is | read as a file that doesn't parse (manifests: the `.bak` copy, else unreadable); the feed map rebuilt as the reference's sanitizer does |
| `store-refusal` | a refused change can leave the in-memory store changed (a refused label keeps its publisher index taken) | a refused change changes nothing (0013: memory changes only after the durable write) |
| `own-keys` | a feed name that is a key of `Object.prototype` reads the inherited property: `toString` gives an empty "existing" feed (`createFeed` answers `bzz://undefined`), and a `__proto__` feed is never saved ([freedom-browser#1327](https://github.com/solardev-xyz/freedom-browser/issues/1327)) | every name is an own key: an ordinary feed |
| `history-retry` | a history update that throws in the handler's `try` is followed by the `catch`'s failed update; one that throws in the `catch` (a failure's own update) leaves the row `uploading` | the last update that fails is followed once by the failed update with the write's error, after a failure's own update too, so the row ends `failed`; the page's answer is the reference's |
| `legacy-dates` | `Date.parse` of a legacy timestamp, V8's own formats and local time included | ECMAScript's date-time string format as V8 reads it: a date alone as UTC, or a date and time with `Z` or an offset (`T` and `Z` in either case, `±HH:mm` or `±HHmm`, any fraction, a day up to 31 running into the next month, as V8 does); a time without an offset, V8's own formats and anything else are no date, so the import takes the open's time |
| `tag-owners-bound` | an upload's tag owner is forgotten only when a page polls the tag done, so a page that never polls grows the map | at most 4,096, the oldest forgotten first; a forgotten tag answers `tag_ownership_mismatch`, as another site's does |
| `store-writes` | temp file and rename, no fsync | 0001's durable write (0013) |

## Changes from today

What a page can see, against the reference pin with #1057. Everything else stays: the methods, params, results, error codes, reasons and texts, the limits, the prompts.
- A feed entry over 10 MiB is refused (`payload_too_large`), as question 3 decided; browser main already does so since #1233.
- `readData` checks every chunk.
- A request stops at the page's own timeout and when its document goes: nothing more is uploaded, signed or sent.
- `busy` when the core's Swarm queue, its memory, main's Swarm I/O pool or the mining queue is full.
- A node reply past its form's cap fails the call.
- A node that answers with the wrong reference for a chunk or a large feed entry gets the write refused.
- A transport failure's message is one fixed text for each kind of failure, and an error body's text comes from its first 8 KiB.
- While a proxy or Tor is on, `subscribe` to a node not on loopback is refused with 4900 `Node not available: proxy-or-tor` (`data.reason: "proxy-or-tor"`), and open subscriptions to it end when either comes on (question 4). The user is told: a notice once per site per session, and a line in the Nodes panel and in Settings > Nodes.

## Migration

**Before the steps:**
- **The user's answers come first, each before the step it changes:**
  - **Q21 and Q22 before SWM-1.** Q21 decides which outcomes the vectors pin as parity and which as deviations. Q22 decides the largest vectors (50 MiB, 100 files) and so SWM-4's memory proof.
  - **Question 3 (feed entries), decided 2026-11-10:** the browser fix is #1233, on browser main; SWM-1's `feed-entry-bound` cases follow the answer.
  - **Question 4 (subscriptions), decided 2026-11-24:** SWM-7 builds the refusal, the notices and their tests.
- **#1057 merged into `integration/rust-core` before SWM-1,** so the reference pin has F-1's, F-2's and F-5's fixes.
- **F-4's fix** is #1233 (#1053), on browser main, not yet in `integration/rust-core`. F-3 is upstream's (bee-js), and goes away for Freedom with SWM-8.

| Step | Where | What | Depends | Done when |
|---|---|---|---|---|
| SWM-1 | core | `vectors/swarm.json`, `vectors/swarm-grammar.json`, the generator and fixtures | Q21, Q22, question 3; #1057 in the pin | `generate.js check` passes against bee-js 13.2.0 and refuses any other installed version; damaged copies fail it; every case above is present; every recorded request matches the grammar or a named deviation; the methods run through `page-swarm.js`, so custody, rules, prompts and rechecks are recorded; the dependency files the vectors load are digested |
| SWM-2 | core | `fc-swarm`'s write side: the chunk tree, the tar writer, feed identifiers and payloads, SOC bodies, GSOC mining (`Miner`, `mine`) | SWM-1 | `trees`, `bodies`, `feeds` and `gsoc` pass byte for byte; `step` over any split gives `mine`'s signer and never tries more than asked; a batch and mining at the cap measured on Linux, macOS and Windows CI and recorded here, a batch past 10 ms or a cap past 2 s reported |
| SWM-3 | core | `fc-swarm-provider`: the machines, validation, the rules and SW-1, batch choice, the stores' codecs, each call's charge | SWM-1; APR-2 (`fc-approval`'s Swarm grants) | `methods`, `stamps`, `errors` and `stores` pass; SW-1's cases (Bee wallet, a shared index, an exclusive index, a missing index, #89's identity first) give today's errors in today's order; the [interleaving gate](#sw-1-in-the-core) passes on the machine; a property test over every vector's node and random node answers shows every call each machine makes matches its method's row at its step in `swarm-grammar.json`, and no machine reaches a form or value another method's row alone allows; iOS and Android builds pass |
| SWM-4 | core | the swarm thread and the mining lane; the methods and `shell.swarm_*` requests; `swarm.body`; the deadline kind; budgets and the [memory lifecycle](#the-swarm-threads-memory); the stores through `fc-store`; `chrome` off `swarm.sign_soc`; a release | SWM-2, SWM-3; PRF-5 (`fc-store`) | every vector over the pipe against a scripted main; a 50 MiB `publishFiles` of 100 files streams with the core's resident memory up less than 4 MiB; the memory tests and the mining lane's tests above pass; the interleaving gate passes through the pipe; `vault.lock` answered within 0009's gate during two uploads and a mining job; a cancel at each step leaves no `shell.*` request open, nothing signed or uploaded after it, and no charge held; every malformed reply is a protocol error; a stalled node ends an upload after 60 s idle |
| SWM-5 | browser | main's executor (`core/swarm-shell.js`): the forms and the grammar, the Swarm I/O pool, POST on the node's transport, the guard's method-bound announcements, `shell.swarm_part` from held requests and picked files, `shell.swarm_ready`; the pin; behind a switch, nothing moved | SWM-4's release | the executor's suite: the [refusal tests](#the-operation-grammar) and the [pool tests](#mains-swarm-io-pool); the grammar read from the pinned core's `swarm-grammar.json`; main's tree reader on `dweb-verify.json`'s `files` and `swarm.json`'s `trees`; with a remote node and a session proxy, every call goes through the proxy; an announced POST passes the guard, and the same POST to another URL, another method, or from a frame doesn't; a node that stops reading holds one window in main; against the bundled node, an index lookup with `swarm-only-root-chunk` returns `swarm-feed-index` |
| SWM-6 | browser | the stores through the core, one writer: `feed-store.js`, the manifest store and `publish-history.js` become clients of `swarm.identities`, `swarm.manifest` and `swarm.history`; the JS provider uses them | SWM-5; APB-3 (`swarm-permissions.json` in the core); 0013's PRF-6 pattern | each module's suite against the core; an `fs` spy shows main opens none of the three files; **rollback:** the reference modules read what the core wrote and see the same state |
| SWM-7 | browser | `window.swarm` through the core behind the switch: main's dispatcher (0011's PRQ-7) sends `swarm.request`; subscriptions open what the core derives, with question 4's rule; the GSOC worker idle | SWM-6; PRQ-7; APR-3 (`PageContext.agent`); question 4 | the provider suites (`swarm-provider-ipc`, `feed-service`, `chunk-service`, `messaging-service`, `publish-service`) pass against both backends as one contract suite, deviations marked; e2e on three OSes against the bundled node: `publishFiles` with nested paths gives the same reference as the JS backend, and its nested files resolve; a feed read past the site's window refused before its body is held, and F-4's case refused before any upload; SW-1's cases through the pipe; a document that navigates mid-upload stops it; **subscriptions:** with a remote node and a proxy or Tor on, `subscribe` gets 4900 `proxy-or-tor` and a spy on the WebSocket constructor sees no socket, a proxy turned on ends an open one without a reconnect, and a loopback node still subscribes; the notice shows once per site per session, for a refusal and for an ended subscription, and the Nodes panel and Settings > Nodes say why while it applies: for a remote external node with a proxy or Tor on, and never for an external node on loopback |
| SWM-8 | browser | main's own Swarm calls without bee-js: `freedom://publish` (`swarm.publish`, `swarm.upload_status`, `swarm.stamps`), the agent's publication controller and postage readiness, `stamp-service.js`, the ad-block list, `gateway-offer.js`; `ant-storage-api.js` on the node's transport | SWM-7 | each module's suite; the agent publication e2e; `git grep "@ethersphere/bee-js" src/` finds only the provider's JS backend; a `freedom://publish` directory with a 124-byte name keeps it (F-3) |
| SWM-9 | browser, then core | the core's backend by default; then the JS backend removed (bee-js's parts of `publish-service.js`, `chunk-service.js`, `feed-service.js`, messaging's sends, `gsoc-miner.js` and its worker, `swarm-service.js`'s client, `swarm-signer.js`), bee-js out of `package.json`, the lockfile and the license audit; then `swarm.sign_soc` removed from the core | SWM-8 shipped | `git grep bee-js` finds only the changelog and docs; unit and e2e suites on three OSes; the core answers `swarm.sign_soc` with `unknown_method` |

**Rollback:** each core step is additive until the browser step that uses it. SWM-6 is one-writer, so going back past it needs the reference modules to read the core's files, which its rollback test shows. Before SWM-9, the switch turns the JS backend back on.

## Amendments

Once decided:
- **0011:** PRQ-7's dispatcher sends `swarm.request`. Its size table gives `swarm_writeFeedEntry` `publishData`'s class (10 MiB plus 64 KiB, a ticket), to match F-4's bound (question 3). The two uploads' charges lose `normalizeBytes`'s copy.
- **0012:** *What the core enforces*: a page's Swarm SOC, enforced from APR-4 by the page's Swarm grant, has its key and identifier chosen by the core from SWM-7, no longer named by main. The manifest's projection is written inside the core, no longer as `shell` through `approval.grant`.
- **0013:** set A's Swarm stores have their methods here, and move with the others at PRF-9.
- **0009:** *Streams in the core*'s list of streaming methods gains `shell.swarm_part`, `shell.swarm_api` with `stream: true`, and `swarm.body`, with their abort codes, `too_large` among them for `shell.swarm_api`.
- **0005:** *Main's pool*: `service-client.js` charges `shell.swarm_*` replies to the Swarm I/O pool, not the chain I/O pool.
- **0002:** `swarm.sign_soc` loses `chrome` at SWM-4 and goes at SWM-9.
- **0006:** its *Later designs* bullet for 4.6 points here.

**2026-11-25, SWM-4's decisions:** the coordinator's technical calls, proposed, which the user may veto. Planning SWM-4 against freedom-cored as it stands settled these before the step's PRs:
- **D1, live facts are asked, not read.** The guards' name binding, document key and custody are one ask, answered from the swarm thread by a naming check (when `PageContext.transport_key` binds) and then `approval.recheck` to main, as 0012's APR-5 does for Ethereum. SWM-3's synchronous reads of them become this ask, at every guard and at the reference's three `afterEffect` checks, before state kept under the page's key: an upload's tag owner, a new feed's record and a feed's updated reference (`swarm-provider-ipc.js:924`, `:1537`, `:1633`), where custody is left out as `afterEffect` leaves it. History rows, the request's outcome, and the hold's release and deferred changes take no live check, as in the reference. D11's pipe cases include a navigation and a name move between an upload and its record.
- **D2, the Swarm grants are shared.** The loop's grants keep `swarm-permissions.json`, behind a handle both the loop and the swarm thread lock for short sections; the manifest projections' writes send `approval.changed` from the swarm thread after its reply. `swarm.request` needs the grant moved (`not_moved` otherwise).
- **D3, one store name.** `store_moved` names the three Swarm stores together, `swarm_stores`, since SWM-6 moves them together and SW-1 couples them. Before it, every store-touching `swarm.*` call answers `not_moved`.
- **D4, streams are routed per owner.** Each stream mark finds its owner in a route table (dweb by default), registered before the request reaches the writer; Swarm gets 32 stream slots (4 MiB of 128 KiB windows) and its share of the queued-stream bound; the reader refuses a fragmented reply past its request's bound, `b64(m) + 16 KiB`.
- **D5, the protocol surface.** Rows: `swarm.request` (page, deadline `swarm`), `swarm.publish` (shell, idle only), `swarm.feed` (shell, `swarm`), `swarm.stamps` and `swarm.upload_status` (chrome and shell, `swarm`), `swarm.identities` and `swarm.history` (chrome and shell, immediate), `swarm.manifest` (shell, immediate), `swarm.body` (shell, idle only). New deadline kinds `swarm` (300 s, or the caller's shorter `deadline_ms`) and idle-only; abort code `too_large`, legal only on `shell.swarm_api` streams; results always in the typed form (`result_typed`, `error_typed`), which carries bytes, BigInt and `undefined`; admission's `busy` is 4900 with `data.reason: "busy"` inside `{ error }` for a page's `swarm.request`, and the protocol error `busy` for a shell or chrome caller (*Budgets* lists which methods share the gate); `swarm_unsubscribe` is `invalid_argument`. A malformed reply from main ends the connection, as 0001 and 0009 make it; a machine's protocol outcome becomes that.
- **D6, the manifest fetch is a core request.** `swarm.manifest`'s `check` asks main `shell.swarm_manifest { for, url }`, answered `{ status, body_base64 }` (at most 8 KiB + 1) or `{ failed }`, so the check's state stays inside one request.
- **D7, `swarm.identities`' ops** are one per IPC handler plus page-swarm.js's prompt ops (`getOriginIdentityStateWithOwners`, `previewAppScopedIdentity`, `createAppScopedIdentityAt`, `ensureAntWalletIdentity`, `activateIdentity`, `grantFeedAccess`) as shell-only ops, and `getEthereumWalletIdentityReferences` for `accounts.remove`; owners come from the vault.
- **D8, the ICU order.** `getEthereumWalletIdentityReferences` sorts with ICU root collation, ported for the printable ASCII that permission keys use; anything else sorts by code unit, a named deviation. Generator cases pin it.
- **D9, a hashing pool of the swarm thread's own.** 0009's pool moves to a crate-level module, and the swarm thread gets its own two-thread pool, for `readData`'s leaf checks; the upload chunker stays on the swarm thread (*SWM-3's feed and SOC writes*).
- **D10, the legacy `publish-history.json`** lives in the app's user-data directory, outside a moved profile's grant; 0017's legacy hand-over carries it, as it carries `x402-receipts.json`.
- **D11, one core plays every case.** The pipe tests run one core and reset the swarm thread between cases through test hooks (its world, its clock, a held vault answer, signature and mining hooks), and a hook makes "another site takes the index", which no method does.
- **D12, main's own methods get vectors.** The generator gains cases for `swarm.publish`, `.feed`, `.stamps`, `.upload_status`, `.identities`, `.history` and `.manifest` from the reference's services and IPC handlers; until then SWM-4 tests them against the grammar's scenarios, `bodies` and `stores`.
- **D13, nothing waits without bound.** A request with no total deadline (idle-only or immediate) waits at most 60 s for memory, and each ask it makes of main has a bound of its own: 60 s without progress (an answer, a head, a frame or credit) for `shell.swarm_ready`, `shell.swarm_api`, `shell.swarm_part` and its `swarm.body`, beside main's idle bound; 60 s in all for `shell.swarm_manifest`, past main's own fetch bounds (the reference's body idle is 15 s). A whole `shell.swarm_api` call shows the core no progress while main reads its body, so under such a parent it has a total bound instead, 300 s, past main's 60 s body idle: a node that sends a whole reply slower than that fails `error` where the reference waits (deviation `deadlines`). Past its bound the core cancels the ask, which the method reads as `failed: error`, and releases the parent's admission and the ask's charge, unless bytes of it are held, which free as they drain. The ask keeps its slot among the core's 256 outstanding requests until main's terminal answer, which is read within its request's bound and dropped, as a cancelled request's is today; a cancelled ask main doesn't answer within 60 s of the cancel ends the connection, as a peer that breaks the protocol does.
- **D14, two clocks.** History rows, budgets and tag owners take wall time; deadlines and the mining lane take the monotonic clock. The test clock drives both.
- **D15, the vault checks a page's SOC again.** The vault's Swarm signing re-runs 0012's page-SOC decision before it signs, though the machine already checked.

**2026-11-25, SWM-3's messaging:** the coordinator's technical calls, proposed, which the user may veto. Building the Messaging machines, the mining lane and the grammar property test (SWM-3 part 3d) against SWM-1's vectors found:
- **`auto` is admitted by the guard, where the reference admits it,** not refused at the start: the vectors record a rule turned off, and custody taken, between main's check and the hand-off, answered `not_auto_approved` and `agent_custody` from the guard, after the method's last wait (*Methods main calls*). Every method follows it: the publish methods, the feed and SOC writes and `getSigningIdentity` admit `auto` at their guards too, each at the reference's point, so no method answers `no_rule`.
- **A send runs the guard twice:** where the reference runs it (before mining and `/stamps`), and after `/stamps`, as after every wait on the node.
- **The mining lane's order** is the cache, a join, the new-topic budget, then the queue bounds, so a `busy` refusal still counts as a new topic. A join is `busy` when the joiner's own queue is full. A cancelled job's signer isn't cached. Mining off answers `GSOC mining failed: mining is off until the core restarts`; a timeout and exhaustion keep the reference's texts.
- **The `/addresses` reader** keeps each field's type and the `ethereum` and `publicKey` strings, so it gives zod's issues and core-sdk's throws, within the 64 KiB reply.
- **A GSOC send's reference is checked** against its SOC address (`reference-check`), which bee-js doesn't do.
- **Subscription limits stay main's:** 32 per site, the node's 1013 close, the establish timeout.
- **"`params.owner` when given" means a truthy owner,** which SWM-5's executor must follow.
- **The property test** plays every methods case of every machine with seeded random answers from main and the node, and checks each node call as main's executor will: the form, the row's shape and every bound value. Its `readData` check admits a later chunk at any address an earlier returned chunk names, within the bounds, and leaves 0009's full occurrence geometry to the walk's own tests.
- **Left out:** `subscribe-no-page`, as `write-soc-no-page`: a `swarm.request` always has a page.

**2026-11-25, SWM-3's feed and SOC writes:** the coordinator's technical calls, proposed, which the user may veto. Building the feed and SOC writes, SW-1 and the interleaving gate (SWM-3 part 3c) against SWM-1's vectors found:
- **The re-check before the signature** covers SW-1, the feed grant, the name's binding and the document's key; custody and the rule wait for the upload's guard, as in the reference (*SW-1 in the core*). It comes after the history row, whose insert is a wait. "The vault" is an ask for the key's owner.
- **Every held change lands as the signature ends the hold,** before the SOC's batch read and upload: a revoke makes the upload's guard refuse that SOC; an index or identity change leaves the signed SOC to be uploaded, and refuses the site's next one (*The change waits*).
- **One write to a topic at a time:** a request holds its topic's turn until it ends; the queue of waiting requests is SWM-4's.
- **SWM-4 must apply feed-store writes in order:** each finishes before the swarm thread takes the next store change, which the hold relies on.
- **A full feed store** is -32603 `Swarm feed store is full` (`store_full`, *Budgets*).
- **A streamed body's chunk tree is hashed on the swarm thread** as each 64 KiB frame passes, not on 0009's hashing pool: about 16 leaves a frame, so no frame holds the thread long.
- **The 10 MiB feed-entry bound** applies after the data's type check, where #1233 puts it.
- **`bytes_up`'s `swarm-tag`** is read as bee-js reads it, so a malformed one fails the write with bee-js's text.
- **`write-soc-no-page`** stays out of the core's cases: the reference's no-page path, which a `swarm.request` (always a page's) can't take.
- **Vector marks fixed:** `write-feed-explicit-index-timeout` is the page's timer (`deadlines`), and both `no-feed-grant` cases carry `index-probe`, as their lookup's request does.
- **`getEthereumWalletIdentityReferences`'s ICU order** isn't reached by these five methods; it stays open for `swarm.identities` (SWM-4).

**2026-11-25, SWM-3's publish:** the coordinator's technical calls, proposed, which the user may veto. Building the Publish machines (SWM-3 part 3b) against SWM-1's vectors found:
- **A node that stops after the readiness answer** reaches the core as `failed: stopped`, answered with the reference's `Swarm node is not ready`; `publish-data-node-stopped-after-ready` pins it, its history row failed with that text.
- **The re-checks before an effect** read the name's binding, custody, the document's key and the connection live, in the reference's order (*Name checks*).
- **Header values are byte strings,** as in the reference: a page's `indexDocument` or `contentType` past U+00FF fails, and one in U+0080–U+00FF goes out as one byte, not UTF-8. The core keeps it for parity; freedom-browser#1328 reports it.
- **History rows:** the insert answers with its rowid, and the trim is its own write. A request that ends without its machine ends its row `failed`, with `cancelled`, `busy` or `Internal error` as the error and the clock at its last answer as `completed_at`, also when it ends while the row's insert is still in flight (the row is trimmed and failed once the insert answers). A last update that fails is followed once by the failed update, as the reference's `catch` does, and after a failure's own update too, which the reference leaves `uploading` (`history-retry`). A page's `name` is stored as better-sqlite3 stores it in a TEXT column (a BigInt as its decimal text), except bytes, which the core writes as NULL (`history-blobs`).
- **Only a streamed body takes an upload's place** (300 KiB charged); a body the params carry goes whole.
- **An upload's answer** past 64 KiB is `Swarm node reply too large`, and one nested past 64 levels fails as `error`. A success before the whole body went keeps `page-upload.js`'s text.
- **Failures with no reference text:** a part main can't stream is -32603 `Internal error`. `page-upload.js`'s 60 s stall and 300 s answer bounds are main's idle bound and the page's timer (`deadlines`), so their texts never reach the page.
- **A chunk upload's reference** in 128-hex or CID form isn't decoded: it is another reference (`reference-check`).
- **Tag owners are bounded** (`tag-owners-bound`).
- **No case among the four methods marks** `deadlines`, `busy` or `batch-depth`; `error-body-bound` is reached through the `errors` section.

**2026-11-25, SWM-3's reads:** the coordinator's technical calls, proposed, which the user may veto. Building the method framework, Access and the Reads (SWM-3 part 3a) against SWM-1's vectors found:
- **The next index is `swarm-feed-index-next`,** not `swarm-feed-index` + 1. bee-js requires both headers, so the reference's `+ 1` fallback never runs, and `index-run-latest-no-next` pins the error for a missing one. Main derives the same value from its own answer, so a node whose two headers disagree no longer makes main refuse the write's `soc_up`.
- **`too_large` has a text per site** ([`shell.swarm_api`](#shellswarm_api)): the reference's own where it has one, `Swarm node reply too large` elsewhere. `readData`'s leaf stream past its size, which no vector reaches, takes the streamed form of `chunk-service.js`'s length text.
- **A declared length past `max_bytes`** reaches the core: a stream gets its head before the `too_large` abort, so #1057's `actual` and the reference's order of checks hold.
- **Transport texts** (`transport-error-text`): `unreachable` is `fetch failed`, `error` is `fetch failed: other side closed`, and `aborted` is `This operation was aborted`, undici's own.
- **The walk's own chunk reads aren't charged to the site's read budget,** so `readData`'s budget results are the reference's, which charges the joined bytes. A short stream keeps the reference's length text.
- **Chunk checks follow the reference** (*Reads*), not 0009's stricter rules, which would refuse chunks the reference returns. The core recovers a SOC's owner with `k256`, at fc-evm's version.
- **Main's side, as the tests script it:** a pre-flight that throws is answered `node-stopped`; the core reads its own grants, so `read-chunk-grants-unavailable` reads on the connected budget with the same answer; a keyless document's key is `""`; `feed_latest`'s `max_bytes` is the site's `maxBytes`.
- **`read-data-redundancy-level-span`'s root was wrong:** a plain two-leaf root with level 1 written into its span, which no Bee writes and the walk refuses. It is now design 0009's `file-4097-rs1`, Bee's own level-1 split, and the core reads it through the walk as the reference does.

**2026-11-25, SWM-3's stores:** the coordinator's technical calls, proposed, which the user may veto. Building the stores' codecs (SWM-3 part 2) against SWM-1's vectors found:
- **The manifest check is two steps:** the legacy and backoff checks, then main's fetch of a `bzz:` manifest, then the decision, so the backoff still saves fetches.
- **A file that doesn't parse** is copied aside, and its empty replacement written at the next change, as the reference does.
- **Reads have the stores' bounds too:** a feed store past 16 MiB is kept aside; a manifest store past 1 MiB falls back to its `.bak`.
- **`history-bound` trims** after each insert and at open, finished rows first, and never takes the row just inserted.
- **New deviations:**
  - `store-shapes`: files the reference loads and then fails on;
  - `store-refusal`: a refused change changes nothing;
  - `own-keys`: feed names like `toString` and `__proto__`, a reference bug filed as freedom-browser#1327;
  - `legacy-dates`: only ECMAScript's date-time string format is a date, a date alone or a time with an offset;
  - `history-blobs`: a row with a BLOB cell fails the read.
- **The manifest check's committed-URL guard** computes a permission key from a URL with the reference's `getPermissionKey` rules. That is the only key the core derives; every grant key is still 0011's, as main gives it (0012).
- **`getEthereumWalletIdentityReferences`** sorts with ICU's `localeCompare`; it stays with part 3, which must port that order or name a deviation.
- **Vector gaps:** closed by the `stores` cases for the five new deviations (`feeds-refused-label-keeps-index`, `feeds-load-feed-maps-kept`, `manifest-load-record-shape`, `manifest-load-string-revision`, `feeds-own-key-read`, `feeds-own-key-proto-write`, `history-json-legacy-dates`, and three `history-blob-*`), each with the core's answer as a value. `generate.js` runs with `TZ=UTC`, so the reference's local-time readings are the same on every machine. `createFeed`'s `bzz://undefined` for a `toString` feed (`own-keys`) still has no methods case.

**2026-11-25, SWM-3's first findings:** the coordinator's technical calls, proposed, which the user may veto. Building the batch choice, the node errors and the `/stamps` reader against SWM-1's vectors found:
- **bee-js's schema refusal reaches the page:** the `/stamps` reader also keeps each field's type, and the refusal's text is held to the form's cap (`reply-bounds`). `/stamps`' charge is 7.7 MiB.
- **The error transcoder can write 5.25 times its body,** not four times, and holds each open object's members. The floor for an error body is 512 KiB, not 32 KiB, for every call.
- **`page-upload.js` is a fourth error-text site,** and error bodies share the 64-level nesting bound.
- **A JSON reply that doesn't parse,** where the reference shows V8's `SyntaxError` text, gets one fixed text (`reply-syntax`); `page-upload.js`'s own text for a page's upload stays.
- **The reader keeps `exists` and `propagating`,** which the batch choice reads.
- **A non-integer batch depth** is refused (`batch-depth`): zod admits one, and computing `2 ** depth` for it as V8 does would need V8's own `pow`. No node sends one.
- **Every whole call reserves at least 512 KiB,** the error floor, so the 64 KiB JSON forms' charges are 0.5 MiB.
- **Vector gaps,** for a later vectors change: `stamps.select`'s nine cases where the reference reads `/stamps` twice don't carry `stamps-one-read`; no `errors` case reaches `fetchNode`'s own text (every one is a 500, which `readFeedPayload` reads as an empty feed); and the two new deviations, `reply-syntax` (a `/stamps` reply and an SOC upload's success reply that aren't JSON) and `batch-depth`, have no case yet.

**2026-11-24, SWM-1's findings:** the coordinator's technical calls, proposed, which the user may veto. Building the vectors against the reference (`integration/rust-core` at `dea09d2f`) found:
- **#1062 is in the reference:** `sendPss` sends the compressed key, so `pss-recipient` is parity, not a deviation. The 128-hex form stays a forbidden call.
- **The head probe reads at most 81 chunks,** not 82. The grammar's cap follows the reference, and an 82nd read is forbidden.
- **A page's uploads go through `page-upload.js`** (PRQ-7c), not bee-js, with the reference's own bounds (#1199). F-7 and `deadlines` say so; reads still have none.
- **The approval path is main's page dispatcher's** (`page-swarm.js`): the methods run through it, so Q21's prompts are pinned.
- **The deep-tree and zero-length cases stay** in `readData`'s grammar: no honest splitter writes them inside 5 MiB, but a node's lone-reference wrappers reach any depth, and an over-full intermediate has zero-length children.

## Options weighed

- **Main keeps building uploads** in its own JS, and posts the page's bytes itself; the core validates and signs only. No bytes through the core, but no root or reference check, a feed entry's wrap still signs the node's root chunk, and the tar and chunk logic stay in JavaScript, which mobile can't use.
- **The core chunks everything and uploads chunks** (`POST /chunks` one by one, or the node's chunk-stream socket): every reference the core's own, manifests included. But about 13,000 requests per 50 MiB, a manifest builder that must match the node's byte for byte, and a WebSocket main would have to run. A later step, if publishes are to be verified as 0009's reads are.
- **Request bodies as streams in `fc-protocol`:** one envelope fewer per upload than `swarm.body`, but it breaks 0009's rule that a stream is a response body, and its rule on whose ID space a stream's ID belongs to.
- **A Swarm service process:** isolation for little parsing of untrusted input (JSON params, chunks the core already checks for 0009), at the cost of a process that needs the core's keys and stores anyway. 0009 made the same call for its verifier.
- **The core talks to the node directly:** the core opens no socket (0001), a remote node needs the session's proxy and Tor, and the guard watches main's dials.
- **One global route set** instead of the grammar: simpler for main, but a live request of any kind could then make any call in the set, so a permission-free read could publish or send a message on a core bug.
- **Charging 0005's chain I/O pool** with Swarm's replies: one pool fewer, but a page's Swarm reads could then starve the core's chain replies. 0014 keeps Colibri's fetches apart for the same reason.
- **Mining in main without bee-js:** keeps a second copy of the search outside the shared crates.
- **Mining in a disposable process,** as today's worker is: a kill frees the lane at any moment. But it needs a service binary, its confinement and a spawn after each failure, for arithmetic whose batches are bounded anyway. The batched lane stops within one batch, and a stuck batch, which only a bug makes, gets a new lane.
- **A Swarm token kind** in 0012's model, binding a prompt's answer to the request: closer to 0012's dApp signatures, but 0012 checks a page's Swarm grant itself and leaves only a prompt's answer (`user`) on main's word in Stage 1, and the prompts' moves (0011's APS) come first.
- **The latest feed entry checked:** the core could ask the node for the head's index, read that SOC by address and check it. But the page's result is today whatever `GET /feeds` answers, which for a legacy `ts ‖ ref` update the node may resolve further (`feed-service.js:149–160`), so the result could change. Bounded instead.

## Open questions

1. **Q21, the API:** Must `window.swarm` keep its exact API and prompts? *Proposed: yes: the same methods, params, results, errors and prompts, with only the [changes listed](#changes-from-today).* *Needed before:* SWM-1, whose vectors pin it. **Decided 2026-11-24: as proposed.**
2. **Q22, the size:** Is 50 MB still right per publish once uploads stream through the core? *Proposed: keep 50 MiB. The core's and main's second copies go, but the page still hands main the whole upload in one message; a larger limit needs a page API that streams, which is a new API.* *Needed before:* SWM-1, whose largest vectors and SWM-4's memory proof follow it. **Decided 2026-11-24: as proposed,** 50 MiB and 100 files per publish.
3. **Feed entries:** May the core cap a feed entry at 10 MiB, the same as `publishData`, where today there is no cap? *Proposed: yes, now, as F-4's browser fix (#1053).* *Needed before:* #1053, and SWM-1. **Decided 2026-11-10: as proposed.** #1233 fixed it on browser main; no fix has landed in the `integration/rust-core` reference, so SWM-1's vectors record the cap as `feed-entry-bound`.
4. **Subscriptions over a proxy:** Message subscriptions to a remote node go around your proxy and Tor today; should Freedom refuse them while a proxy or Tor is on? *Proposed: yes, until main can carry WebSockets through the session. A page then gets 4900 `Node not available: proxy-or-tor`, and a remote node behind a proxy has no subscriptions. If no, they keep going around the proxy, as today.* *Needed before:* SWM-7. **Decided 2026-11-24: as proposed, with the user told whenever it applies** (the user's condition): a notice once per site per session, and a line in the Nodes panel and in Settings > Nodes ([Messaging](#messaging-and-gsoc-mining)).
