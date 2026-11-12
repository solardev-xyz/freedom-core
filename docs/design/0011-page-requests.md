# 0011: Page requests and the approval surface

**Status:** decided (the user, 2026-11-07 and 2026-11-08): open questions 1–4, which [Open questions](#open-questions) records. Roadmap items 2.3 (page provider calls go straight to main) and 2.8 step 1 (a trusted approval surface). Builds on [0001](0001-freedom-cored.md) (the threat model, and the caller context that reserves `page` for Phase 2) and [0002](0002-signing.md) (signing, its approval tokens, and the signed view of #88). Design 0012 follows: grants, tokens and the EIP-1193 dispatcher in the core (`fc-eip1193`). Nothing here is built yet.

**The references:**
- **freedom-browser** at `f19705ad` (`integration/rust-core`):
  - the page side: `src/main/webview-preload.js` (the providers' bridges, the sub-frame return, the private-window guard);
  - the chrome side, in `src/renderer/lib/`: `dapp-provider.js`, `swarm-provider.js`, `radicle-provider.js`, `guest-main-frame.js`, `tabs.js` (`committedDisplayUrl`), `url-utils.js` (`applyDnsNameIdentity`), `wallet/dapp-connect.js`, `wallet/dapp-prompt-guard.js`, `wallet/dapp-tx.js`, `wallet/chain-switcher.js`;
  - main, in `src/main/`: `swarm/swarm-provider-ipc.js`, `radicle/radicle-provider-ipc.js`, `wallet/wallet-ipc.js` (`requesterBelongsTo`, `dnsNameServesIpnsGuest`, `authorizeSigning`, `wallet:confirm-signing`), `wallet/signing-confirmation.js`, `wallet/agent-tab-custody.js`, `ipc-sender-policy.js`, `webcontents-setup.js`, `private/private-windows.js`, `agent/ipc.js`, and the chrome's `preload.js`;
  - `src/shared/origin-utils.js` (`getPermissionKey`), main's copy of the key rules.
- **The spike** `b58441b1` on `codex/package-webview-runtime` ("compose wallet as shell surface view"): `src/main/trusted-wallet-surface.js` and `src/main/windows/shell-window.js`.
- **Electron's API** as `electron.d.ts` types it, checked in 44.7.0 (integration's `package.json` asks for `^45.2.1`): `IpcMainInvokeEvent.senderFrame`, a `WebFrameMain` or null ("May be `null` if accessed after the frame has either navigated or been destroyed"), and `WebFrameMain`'s `frameTreeNodeId`, `detached`, `parent` and `send`.
- **Electron's IPC** on its `45-x-y` branch: `shell/browser/electron_api_ipc_handler_impl.cc`, where `Message` and `Invoke` turn a message's arguments into JS values (`gin::ConvertToV8`) before any handler runs, with no size check.
- **`fc-protocol`:** `CallerKind::Page` and `PageContext { origin, top_origin, frame, navigation }` (`crates/fc-protocol/src/message.rs`), which no method accepts yet (`methods.rs`, `Callers::allow`).

## Summary

- **Today** a page's `window.ethereum`, `window.swarm` and `window.radicle` requests go page → preload → `sendToHost` → the chrome renderer → main. The chrome decides who asked: it keys the request on its own record of the tab's committed URL, shows the prompt, asks main for the approval token, and names the site to main. Three gaps follow:
  - **The chrome names the site.** `swarm:provider-execute` and `radicle:provider-execute` take `origin`, and how the request was approved, from the chrome (`swarm-provider-ipc.js:12–31`), and `dapp:grant-permission` grants any site it names. A compromised chrome renderer can act as any site.
  - **The chrome mints the approval.** `wallet:confirm-signing` issues an O-7 token for whatever the chrome sends (`wallet-ipc.js:621–643`). The token binds the signature to a request, not to the user's click, so a compromised chrome can sign anything.
  - **One frame, two documents.** `guest-main-frame.js` keeps sub-frames out, but can't tell two documents of the main frame apart (its lines 29–40).
- **The way in:** the preload invokes main directly (`page:request`). The chrome no longer sees page requests.
- **The attested requester:** main derives who asked from the IPC event's `senderFrame`: the guest, its window, the committed URL and its key, private or not. The key rules are today's (`getPermissionKey`), dweb names, ENS over IPNS and onchain `web3://` included.
- **Documents:** main numbers each committed main-frame navigation, and the preload binds a random nonce to its document with its first message. A request from a document that has gone is refused. This closes `guest-main-frame.js`'s gap.
- **Sub-frames:** the top frame only, as today, now enforced by main ([open question 1](#open-questions), decided).
- **Handles:** a prompt is a handle main issued. The chrome presents the handle and returns a decision. It never names a site. Approval tokens bind the handle and the attested key.
- **Tokens for page requests** come only from main, for a live request. From PRQ-5 the chrome's `wallet:confirm-signing` refuses the kinds that serve pages, and APS-3 closes the wallet's own.
- **Events** (`accountsChanged`, `chainChanged`, Swarm messages, Radicle seed status) go from main to the guest's document, never through the chrome. Each carries the document's nonce, and the preload drops one that isn't its own.
- **Agent custody** is read live, when a standing rule would answer and again just before the effect.
- **The dispatcher** moves from the chrome into main's JS first. `fc-eip1193` follows in 0012.
- **The approvals document (2.8 step 1):** one per window, a `WebContentsView` above the chrome, with its own preload. Main mints approval tokens only for decisions made there: first for dApp prompts, then for the wallet's own. Much of what it shows comes from the page, so it shows it as text only, from a closed schema, under a strict CSP.
- **Bounds:** a size limit on each request, checked by the preload and again by main as the request arrives, and byte and count budgets across every document, charged for every copy main holds of a request. Large uploads take turns, on one-use tickets bound to their document.
- **The threat model:** a compromised chrome renderer or a compromised sub-frame. Main stays trusted (0001).
- **Migration:** nine browser PRs for the requests (PRQ-1 to PRQ-9), then three for the approvals document (APS-1 to APS-3), each with the tests that prove its refusals.

## Goals and non-goals

**Goals**
- **Main decides who asked,** from Chromium's own record of the sending frame, never from a string a renderer sends.
- **No request outlives its document:** no prompt, token, reply or event reaches a document other than the one that asked.
- **The chrome only renders prompts:** it never names a site, never writes a grant and never mints an approval for a page's request. After APS it mints no approval at all.
- **The same page-facing API:** `window.ethereum`, `window.swarm` and `window.radicle` keep their methods, errors and events. [Changes from today](#changes-from-today) lists the exceptions.
- **One step at a time:** each PR moves one group of methods and can be reverted on its own.

**Non-goals**
- **A compromised main.** Stage 1 trusts main (0001). It holds the dispatcher, the grants and the tokens.
- **Policy in the core.** Grants, auto-approve rules and token checks stay in main's JS. 0012 moves them, amending 0002's non-goal. In the core, 0011 only fixes what `PageContext`'s fields mean.
- **x402.** Its 402 prompts and `x402:approve` belong to the browser's SEC-1 fix and to 0012.
- **A compromised page.** A page whose renderer is compromised acts as its own site, as today. Where Chromium puts two sites in one process, a compromised process can act as either. 0011 doesn't change that.
- **The wallet panel's own management** (accounts, exports, settings) stays in the chrome. 2.8's later step takes it up.
- **2.8 step 2:** a summary the core produces, shown in a surface no web renderer drives.

## Today

**The path:**
1. The page's provider posts a message to its own window. The preload's bridge forwards it with `ipcRenderer.sendToHost` (`webview-preload.js:1760–1803` for Ethereum, `1923–1956` for Swarm, `2074–2107` for Radicle). The Ethereum bridge also sends `window.location.origin`, which the chrome ignores.
2. The chrome's `ipc-message` listener drops anything not from the guest's current main frame (`dapp-provider.js:729–759`, `guest-main-frame.js`).
3. The chrome keys the request on the tab's `committedDisplayUrl` (`tabs.js:427–430`) through `getPermissionKey`. A DNS-named ENS site, loaded as `ipns://<key>`, is mapped back to its name from the chrome's `knownEnsNames` (`applyDnsNameIdentity`, `url-utils.js:496`).
4. The chrome runs the method:
   - reads through `wallet.requestChain`, on the chain the chrome selected (`wallet/chain-switcher.js:218`);
   - prompts in the wallet sidebar, one at a time per window (`wallet/dapp-prompt-guard.js`); the sidebar opens for a background tab's request too (`wallet/dapp-connect.js:311`);
   - grants through `dapp:grant-permission`, tokens through `wallet:confirm-signing`;
   - Swarm and Radicle through `swarm:provider-execute` and `radicle:provider-execute`, with the key it computed.
5. The chrome replies with `webview.send`, unless the tab navigated meanwhile (a generation per webview, `dapp-provider.js:39–49`).

**What main checks:**
- **Signing** needs an O-7 token, or main's own reading of the site's auto-approve rule. For the rule, `requesterBelongsTo` checks that the named guest belongs to the sending chrome window and that its URL keys to the named site (`wallet-ipc.js:239–264`). For an `ipns://` guest it resolves the DNS name itself (`dnsNameServesIpnsGuest`, `276–290`).
- **Swarm and Radicle** trust the chrome's `origin` and `meta` (`swarm-provider-ipc.js:12–31` and `2194–2198`; `radicle-provider-ipc.js:412`). Swarm cross-checks the guest's URL only when it delivers a subscription message (`1911–1930`), and counts navigations per guest (`navEpoch`, `1866–1891`).
- **Agent custody:** no auto-approval for a tab the agent holds (`agent-tab-custody.js`), read at the moment each check decides.

**Sub-frames.** Main turns on `nodeIntegrationInSubFrames` for tab webviews, so that iframes get the ad-block scriptlets (`webcontents-setup.js:254`). The preload returns before the providers in a sub-frame (`webview-preload.js:590`), and the chrome drops a sub-frame's provider message. A compromised sub-frame holds `ipcRenderer`, but the sender policy lets a webview call only the channels its preload uses (`ipc-sender-policy.js`), and the provider channels aren't among them.

**Private windows** get no providers. The preload reads the window's status from its boot switch (`webview-preload.js:645–649`). Main checks nothing, since no provider call reaches main from a page.

**What a compromised chrome renderer can do today.** The sender policy lets the chrome call every channel (`ipc-sender-policy.js:20`, `272`). So it can:
- call `swarm:provider-execute` or `radicle:provider-execute` as any site, with `meta.approval: 'user'`: publish, write feeds, send messages, seed and sign Radicle writes, with no prompt;
- grant any site and turn on its auto-approve rules (`dapp:grant-permission`, `swarm:set-auto-approve` and the rest; the chrome's `preload.js:1058–1119`);
- mint a token for any payload and sign it (`wallet:confirm-signing`, then the signing handlers);
- read every page request, answer it, and send events into any guest (`webview.send`);
- run script in any guest it hosts (`webview.executeJavaScript`, which `find-bar.js:342` uses).

## Threat model

The attackers are a compromised chrome renderer (`renderer/index.html`) and a compromised sub-frame of a tab. Main is trusted (0001). Pages are hostile as ever: a page chooses what its requests contain and how many it sends. The chrome renderer holds the privileged preload and parses what pages control: titles, favicons, URLs and request data. One renderer bug in any of these makes it the attacker. The approvals document is a new renderer that also shows what pages control (a message, typed data, file names), so it is held to the rules in [Rendering a page's data](#rendering-a-pages-data).

| The attacker wants to | Today | After PRQ-9 | After APS-3 |
|---|---|---|---|
| Act as a site it doesn't host (chrome) | Yes: it names the site | No: main derives the site from the sending frame | No |
| Approve a real page request without the user (chrome) | Yes | Yes: the chrome still decides | No: only the approvals document decides |
| Sign a payload no page asked for (chrome) | Yes: `wallet:confirm-signing` | Only through the wallet's own kinds (`wallet-send`, a `safe-send` with no site, the three intent kinds, `executor-send`): from PRQ-5 main alone mints the kinds that serve pages | No: tokens only on the approvals document's decisions |
| Write or widen a grant (chrome) | Yes | No: main writes grants from decisions | No |
| Make a hosted page ask, and get it approved (chrome) | Yes | Yes | Every prompt reaches the user; standing rules still answer ([What stays open](#what-stays-open)) |
| Ask as the top page (sub-frame) | No: the chrome drops it | No: main refuses it | No |
| Reach the document that replaced the one that asked (either) | Yes: a late message passes `guest-main-frame.js` | No: the document's nonce | No |
| Forge an event into a page (chrome) | Yes | Yes (`webview.send`), with no authority gained | The same |
| Run script in the approvals document through a request's data (page) | No such document | No such document | No: text only, from a closed schema, under a strict CSP |
| Make main hold more requests and bytes than it can afford (page) | Yes: no bound on requests in flight | No: a size per request, and budgets across every document ([Bounds](#bounds)) | No |

### What stays open

- **The chrome can still script the pages it hosts.** A `<webview>`'s embedder can run script in its guest, and main then sees a genuine request from that page. After APS, every prompt this causes reaches the user in the approvals document, but a standing rule answers without one: "always allow" signing, a contract rule, a Swarm or Radicle auto-approve. Closing it needs the tabs out of the chrome's hands: a guard on the guest's script entry points (which depends on how this Electron version works inside, may miss an entry point, and has to be retested on every Electron upgrade), tabs as views main owns, which the spike's branch plans (`research/shell-compositor-webcontentsview-architecture.md`), or Chromium. The user accepts this gap for now and notes tabs as views main owns for later ([open question 4](#open-questions)).
- **Denial of service.** The chrome can hide tabs, drop badges and refuse to switch to the tab that asks. The approvals panel itself is main's.
- **Spoofing.** The chrome and pages can draw a lookalike prompt in their own areas. After APS a decision there counts for nothing, but a vault password typed into a fake is lost. The panel's fixed place and its input rules ([The approvals document](#the-approvals-document)) are the defence.

## The way in

Four channels between a tab's preload and main replace the provider channels through the chrome: the three requests sent with `sendToHost`, and the responses and events the chrome sends back with `webview.send`.

| Channel | Direction | Payload | Notes |
|---|---|---|---|
| `page:hello` | preload → main (`send`) | `{ nonce }` | Once per document, before the providers are injected ([Documents](#documents)) |
| `page:request` | preload → main (`invoke`) | `{ nonce, provider, method, params, ticket }` | `provider` is `ethereum`, `swarm` or `radicle`. `ticket` only for a large request. Answers `{ result }` or `{ error }` |
| `page:reserve` | preload → main (`invoke`) | `{ nonce, method, bytes }` | Only before a request over 1 MiB. Answers `{ ticket }` when its turn comes, or `{ error }`. The ticket is opaque, bound to its document and spent once ([Large requests](#large-requests)) |
| `page:event` | main → preload (`WebFrameMain.send`) | `{ nonce, provider, event, data }` | `nonce` is the target document's. The preload drops an event whose nonce isn't its own ([Events](#events)) |

- **The preload** keeps the page-facing providers and their `postMessage` protocol, and maps each page request id to its `invoke`. It sends nothing from the page's own `location`. The page's scripts never see the nonce: it lives in the preload's isolated world.
- **The sender policy** (`ipc-sender-policy.js`) gets a tier for `page:hello`, `page:reserve` and `page:request`: a `webview` sender whose `senderFrame` is its main frame and isn't an internal page. Unlike every other channel, these refuse the chrome, which has no page to speak for.
- **In flight across a navigation:** main checks the document again before it replies, and sends no reply to a document that has gone. Work already started, such as an upload or a broadcast, finishes, as today.
- **Bounds:** the preload measures each request before it sends it, and main measures it again as it arrives and charges it for every copy it will make, before it keeps or copies anything ([Bounds](#bounds)).

## The attested requester

For every `page:hello`, `page:reserve` and `page:request`, main builds the requester from the IPC event, in this order, and refuses at the first step that fails. A reservation is checked as a request is: a private window, a preview, a sub-frame, a replaced document or a URL off its transport key gets no ticket ([Large requests](#large-requests)).

1. **A tab:** `event.sender` is a live `webview` webContents whose host is a chrome window (`isChromeIndexUrl` of its `hostWebContents`' main frame). Agent automation pages, which run in hidden windows with no preload (`webcontents-setup.js:190–201`), the PDF worker and every other webContents are refused.
2. **Not private:** `isPrivateWebContents(event.sender)` is false (`private-windows.js:103`). Main refuses whatever the preload did, so a private page with a compromised renderer gets nothing either.
3. **Not a preview:** the committed URL isn't `freedom-preview:`.
4. **The top frame:** `event.senderFrame` is not null, not `detached`, and is `event.sender.mainFrame` ([Sub-frames](#sub-frames)).
5. **The current document:** the request's nonce is the one bound to the frame's current document ([Documents](#documents)).
6. **The transport key:** `senderFrame.url`'s key, by the rules in [Keys](#keys) and with no name binding, must equal the record's `transportKey`. The permission key the request then acts under is the record's `key`, which differs only for a DNS name over IPNS ([Names over IPNS](#names-over-ipns)).

The record main keeps per document:

| Field | From |
|---|---|
| `guest` | `event.sender.id` |
| `window` | the hosting chrome window's id |
| `frame` | `senderFrame.frameTreeNodeId`: global in the browser, fixed for the frame's life, never reused |
| `navigation` | main's document number ([Documents](#documents)) |
| `nonce` | the hello's nonce ([Documents](#documents)) |
| `url` | the committed URL |
| `transportKey` | the committed URL's own key by the rules in [Keys](#keys), with no name binding: `ipns://<key>` for a DNS name over IPNS. Fixed for the document's life. Step 6 compares it with the live frame URL's |
| `key` | the permission key: the transport key, the DNS name a binding verified, or none. Grants, rules and prompts use it |
| `topKey` | the top frame's key: equal to `key` under the top-frame policy |
| `agent` | `isAgentPage(event.sender)` at the hello (`agent-tab-custody.js`). For logs and tests only: no decision reads it ([Agent custody](#agent-custody)) |
| `chain` | an onchain app's own chain, or none |

### Keys

Main applies today's rules (`origin-utils.js:75–139`) to the committed URL. The table gives `key`. `transportKey` is the same in every row but `ipns://<key>`, where it is always `ipns://<key>`.

| Committed URL | Key | Notes |
|---|---|---|
| `https://app.example/x` | `https://app.example` | `http:` alike |
| `bzz://name.eth/x`, `ipfs://name.eth/x`, `ipns://name.eth/x` | `name.eth` | A dweb page keeps its dweb URL, name included (`wallet-ipc.js:230–232`) |
| `bzz://<reference>/x`, `ipfs://<cid>/x` | `bzz://<reference>`, `ipfs://<cid>` | Path-insensitive |
| `ipns://<key>/x` | `ipns://<key>`, or the DNS name bound to it | [Names over IPNS](#names-over-ipns) |
| `rad://<rid>/x` | `rad://<rid>` | |
| `web3://0x….eip155-<id>/x` | `web3://0x…`, or `web3://0x…:<id>` off mainnet | `chain` is `<id>`. `eth_chainId` answers it, a switch to another chain is refused, and `chainChanged` is never sent (`dapp-provider.js:197–216`, `656–665`) |

**Three changes from today's keys:**
- **Opaque URLs get no key.** When a URL's origin is `null`, `getPermissionKey` returns the whole URL (`origin-utils.js:130–134`), so a `data:`, `about:` or `view-source:` page is keyed on its full URL today. Main gives it no key.
- **Freedom's own pages get no key and no `window.ethereum`.** Internal pages already lack `window.swarm` and `window.radicle` (freedom-browser#432), and none uses `window.ethereum`. The onchain gate (`onchain-unverified.html`) takes its target's identity in the chrome (`committedDisplayUrl` follows `getOnchainInterstitialTarget`, `tabs.js:858–864`). Main keys it on its own URL, so on nothing.
- **A document without a key** gets the read methods, and `eth_accounts` answers empty. Every site method (connect, sign, send, the Swarm and Radicle writes) is refused, as a keyless page's is today: "This page has no address to connect from yet" (`dapp-provider.js:247`).

### Names over IPNS

A DNS name with an ENS contenthash (`example.com`) loads as `ipns://<key>`, since `ipns://example.com` means DNSLink. Its URL carries the key, not the name. Today the chrome maps the key back to the name, and main checks the name against its own resolution only for auto-approve.

**Proposed: a name binding.**
- When the chrome loads `ipns://<key>` for a DNS name, it first tells main: `page:bind-name { guest, name, key }`.
- Main holds it for that guest's next main-frame commit. If that commit's URL is `ipns://<key>` with exactly that key, main resolves the name itself, as `dnsNameServesIpnsGuest` does (the resolver's base58 form, or the base36 `libp2p-key` form, compared exactly). If the name answers the key, the document's `key` is the name. Otherwise it's `ipns://<key>`.
- **Two keys, never mixed.** The document's `transportKey` stays `ipns://<key>`, and step 6 of [the attested requester](#the-attested-requester) compares the live frame URL with it. Grants, standing rules and prompts use `key`, the name.
- The binding lasts while the guest's commits stay on that IPNS key: reloads and links within the site keep it.
- **Checked at every use of the name.** A name can move to other content at any time. So before a method uses anything held under the name's key (a grant, a standing rule, a new grant written for the name, the site's feeds, tags, identity or subscriptions), main resolves the name again and compares the answer with `transportKey`. [Which methods check the name](#which-methods-check-the-name) classifies every provider method and event. The unsigned effects are included: a Swarm publish or a Radicle seed under the name's auto-approve rule uses the name's authority as much as a signature does.
- **After every wait.** The resolution itself is awaited, so after it returns main checks again that the document is current and its frame URL still keys to `transportKey`, as `requesterBelongsTo` does today. When anything else is awaited before the effect (a prompt, a vault unlock, a fee check, the core's view of typed data), main resolves the name and checks the document once more, just before the effect: the grant written, the signature, the send, the publish, the message or the node action.
- The resolution is the core's naming, as today's auto-approve check uses. It answers from the core's cache while it holds the name's record, so the check is cheap to repeat.
- **A name that no longer answers the key** ends the binding. The request is refused with nothing done (`eth_accounts` answers empty; a send already broadcast after a passing check is the one exception, [After a waiting signature or send](#the-prompt-protocol)), the document's later site methods are refused as a keyless document's are, and its subscriptions end. A new commit can bind again, through a fresh `page:bind-name`.
- A compromised chrome can only bind a name whose ENS record serves that key: the same content, and the outcome today's check accepts.

### Which methods check the name

Every method a provider serves, and every event, has exactly one class, in one closed table that main's dispatchers read. A method with no row is refused (`4200`, or the provider's own unknown-method error) before anything runs, and a dispatcher can't serve a method without a row. The classes:
- **Name-revalidated:** the method reads or changes something held under the key: a grant, its account, chain, rules or last-used time, or the site's feeds, tags, signing identity, subscriptions or seed-status events. Main resolves the name before the method's first use of it, and again after every later wait, as above. When the name no longer answers, the binding ends, and the method answers as it would for a keyless document: `eth_accounts` empty, every other method refused with nothing done, except a send already broadcast after a passing check, whose hash still goes back ([After a waiting signature or send](#the-prompt-protocol)).
- **Permission-free:** the method answers from public data. The key picks at most a rate or a routing hint, neither of which is authority. It runs on the document's key as it stands, with no resolution.
- **Exempt, revocation only:** the method only gives up the site's own authority, which narrows it. It runs with no resolution.
- **Refused:** it never runs, for any caller.

| Provider | Methods | Class | What the key is used for |
|---|---|---|---|
| ethereum | `eth_chainId`, `net_version` | Permission-free | Nothing: the selected chain, or an onchain app's own |
| ethereum | The other 23 of `READ_ONLY_METHODS` (`dapp-provider.js:74–100`) | Permission-free | A routing hint: the core's router gets it as `origin` (`core/chain-driver.js:403`) |
| ethereum | `eth_accounts` | Name-revalidated | It reveals the granted account |
| ethereum | `eth_requestAccounts` | Name-revalidated | The grant, read or written, and its last-used time |
| ethereum | `wallet_switchEthereumChain` | Name-revalidated | It writes the grant's chain (`updateLastUsed(permissionKey, requestedChainId)`, `dapp-provider.js:689`), and it sets the selected chain and sends `chainChanged` (`693–698`) |
| ethereum | `eth_sendTransaction`, `personal_sign`, `eth_signTypedData_v4`, from a Safe account too | Name-revalidated | The grant's account, its rules, and the key a token binds |
| ethereum | `eth_sign` | Refused | Nothing: it answers `4200`, as today (`dapp-provider.js:379`) |
| swarm | `swarm_readChunk`, `swarm_readData`, `swarm_readSingleOwnerChunk` | Permission-free | A rate: the read budget's bucket, and whether it is a connected site's (`getReadBudget`, `swarm-provider-ipc.js:317`) |
| swarm | `swarm_requestAccess`, `swarm_getCapabilities` | Name-revalidated | The grant (`getCapabilities` reports whether there is one) |
| swarm | `swarm_publishData`, `swarm_publishFiles`, `swarm_publishChunk` | Name-revalidated | The grant, its auto-approve rule, and the publish history |
| swarm | `swarm_getUploadStatus` | Name-revalidated | The tag's owner (`tagOwnership`, `swarm-provider-ipc.js:824`) |
| swarm | `swarm_createFeed`, `swarm_updateFeed`, `swarm_writeFeedEntry`, `swarm_writeSingleOwnerChunk`, `swarm_getSigningIdentity` | Name-revalidated | The feed grant and the site's own signing identity (`getOriginEntry`) |
| swarm | `swarm_readFeedEntry`, `swarm_listFeeds` | Name-revalidated | The site's feed records: a feed read by `name` takes its topic and owner from them (`swarm-provider-ipc.js:1559–1570`) |
| swarm | `swarm_getMessagingIdentity`, `swarm_subscribe`, `swarm_sendPss`, `swarm_sendGsoc` | Name-revalidated | The grant and the messaging grant |
| swarm | `swarm_unsubscribe` | Exempt, revocation only | It ends one of the document's own subscriptions |
| radicle | `radicle_requestAccess`, `radicle_getCapabilities`, `radicle_getNodeStatus`, `radicle_listSeededRepos` | Name-revalidated | The grant (`unavailableReason`, `radicle-provider-ipc.js:132`) and its last-used time (`312`), and the signing grant, which shows the node id (`170`) |
| radicle | `radicle_seed`, `radicle_unseed`, `radicle_sync`, `radicle_getSeedStatus` | Name-revalidated | The grant, the node auto-approve rule, and the site's seed-status events |
| radicle | `radicle_getIdentity`, `radicle_createIssue`, `radicle_commentIssue`, `radicle_editIssueState`, `radicle_commentPatch` | Name-revalidated | The signing grant |
| radicle | `radicle_disconnect` | Exempt, revocation only | It revokes the site's own grants (`radicle-provider-ipc.js:338`) |
| events | `accountsChanged`; Swarm's `connect`, `disconnect` and `message`; Radicle's `connect`, `disconnect` and `seedStatus` | Name-revalidated, before each delivery to a name-keyed document | They carry the account, the grant's changes (Radicle emits `connect` after access is granted and `disconnect` after it is revoked, `radicle-provider.js:170–176`, `194–204`), the subscription's messages, the site's repositories |
| events | `chainChanged`; Ethereum's `connect` and `disconnect` | Permission-free | They carry the selected chain and nothing of the key's |

- **One class per method,** whatever its params: `swarm_readFeedEntry` checks the name even when it names a feed by `topic`.
- **The check costs little.** The resolution answers from the core's cache while it holds the name's record, and a document with no name binding has nothing to resolve.

### PageContext

Main fills `fc-protocol`'s `PageContext` from the record:

| Field | Value |
|---|---|
| `origin` | `key`: a permission key (`name.eth`, `web3://0x…:100`, `https://app.example`), not an RFC 6454 origin |
| `top_origin` | `topKey` |
| `frame` | the frame's `frameTreeNodeId` |
| `navigation` | the document number |

- A document without a key has no `PageContext`, and none of its site methods reach the core.
- **Until 0012 nothing sends it.** No core method accepts `page` (`methods.rs`, `Callers::allow`), and main's core calls for a page's request keep the caller kinds they have today (`service-client.js` defaults to `chrome`). 0012 admits `page` on the methods whose grants the core checks.
- 0012 may also need the Agent-custody flag, which `PageContext` doesn't carry.

## Documents

`guest-main-frame.js` names a frame by its `[processId, routingId]`. The pair survives a same-process navigation, so a message the old document sent late is taken as the new one's. Main closes this with a number per document and a nonce the document itself holds.

- **A number per commit.** Main listens to each tab guest's `did-frame-navigate`. For the main frame, it takes the next number from one counter for the whole main process (never reused while main runs), records the committed URL and its key, and clears the nonce. Same-document navigations (`did-navigate-in-page`: a fragment, `pushState`) keep the document and its number.
- **Error pages are no document.** Electron 45 commits a network error page (`chrome-error://chromewebdata/`) with `did-fail-provisional-load`, not `did-frame-navigate`, and the preload runs in it, with the failed URL as its frame's URL; numbering it would key it to whatever site failed to load. So when a main-frame `did-fail-provisional-load` reports a committed error page (the error isn't `ERR_ABORTED`, it names the live main frame by `processId` and `routingId`, and that frame shows the failed URL), main ends the current document and starts none. The error page is unnumbered: its hello and every request are refused (`no-document`), reads included. The replacement also consumes a pending name binding and ends the active one, so a later commit on the same IPNS key isn't bound to the name until the chrome binds it again ([Names over IPNS](#names-over-ipns)). An aborted or superseded load, which leaves the old document committed, ends nothing; an HTTP error status commits through `did-frame-navigate` and is numbered as usual (PRQ-1).
- **The nonce.** The preload makes 16 random bytes when it runs, as it makes the EIP-6963 uuid today (`webview-preload.js:628`), and sends `page:hello { nonce }` before it injects the providers, so before any page script can run.
- **Binding.** Main binds the first hello it gets for the current number, from the main frame, and ignores every later one.
- **Every request** carries the nonce. Main serves it only when the nonce is the current document's. A late request from the previous document carries the previous nonce and is refused (`navigated`), as is any request before the hello.
- **Every event** carries the target document's nonce too, and the preload drops one that isn't its own ([Events](#events)).
- **A page restored from a back/forward cache** keeps its old preload, which then sends a fresh hello with a new nonce on `pageshow` with `persisted`. PRQ-1 found that Electron 45 doesn't: `pageshow.persisted` was false after back and forward.
- **The one assumption:** main sees the commit before the new document's hello. The probe of 2026-09-28 found that the embedder gets `did-frame-navigate` before any message from the new document, one sent at preload time included (`guest-main-frame.js:21–27`). PRQ-1 repeats it in main, in real Electron. If it ever fails, the hello lands on the old number and is ignored, and the new document's requests are refused: the page loses its wallet, and nothing is misattributed.
- **What it doesn't stop:** a compromised renderer can reuse a nonce it holds, but only from its own process: for its own site, as today.
- **It replaces** the chrome's generations per webview, `guest-main-frame.js`, and Swarm's `navEpoch`.

## Sub-frames

**Decided: the top frame only,** as today, now enforced by main. `senderFrame` must be the guest's main frame (step 4 above), and the sender policy's tier checks the same. The preload still returns before the providers in a sub-frame, and main never sends a `page:event` to one. An iframe inside a dApp, such as a widget or a swap embed, has no wallet. The dApp can talk to it with `postMessage` and make the request itself.

**The alternative, considered and not chosen ([open question 1](#open-questions)): providers in sub-frames, under their own key.**
- The preload installs the providers in every frame, and main accepts a sub-frame's request, with `key` from the frame's own URL and `topKey` from the top frame's.
- Grants keyed on the frame's own key, so an embed connected once is connected on every site that embeds it; or keyed on the pair, so each embedding site asks again. The pair is safer and asks more often.
- Prompts name both: "swap.example, inside news.example".
- Events go to each frame by its own key, and documents are numbered per frame, not per tab.
- The costs: main tracks every frame's commits, and a page can embed a site the user trusts to make that site's prompts appear.

## Requests and handles

- **Every request** gets a record in main: the requester, the method, the time. Reads complete without the chrome.
- **A prompt is a handle:** 32 random bytes in hex, issued by main and scoped to the window that hosts the guest. The chrome gets the handle and what to show, and answers with the handle and a decision. Nothing the chrome sends names a site, a guest or a payload to sign.
- **One pending wallet prompt per document.** A document's second wallet request while its first is pending gets `-32002` ("Another wallet request is already pending"), and the dApp can retry. Swarm and Radicle keep their own limits on their prompts. `dapp-prompt-guard.js` keeps one per window today; now that background tabs wait, a per-window rule would let a waiting background tab refuse the tab in front.
- **One prompt shown per window:** the oldest pending prompt of the guest in front, of any kind. The rest wait in order of arrival, each on its tab's badge and in the window's count. When the shown prompt closes, the same guest's next one shows. When another guest comes to the front, the shown prompt is hidden (`page:prompt-hidden`) and keeps its place, and the new guest's oldest shows. Which prompt is shown is main's state, changed before main tells the renderer: **a decision counts only for the handle main shows at that moment,** so a click already in flight for a prompt main has hidden is refused and does nothing. A prompt shown again starts its input delay again ([Rendering a page's data](#rendering-a-pages-data)).
- **A handle closes** when it's decided, when its document goes (a navigation, or the guest destroyed), when its window closes, or when a prompt that has never shown reaches its deadline. Its badge and its place in the count go with it, and a later report that its tab is in front shows nothing. A decision on a closed handle is refused, and main tells the chrome the handle closed.
- **One deadline, main's.** From a method's step, the preload runs no page-world timer for it, and the page's promise is answered only by main. Today's timers (`webview-preload-ethereum-inject.js`, `webview-preload.js`) start before the request reaches main, so a second timer in main would always end later, and the page could give up while its prompt can still show.
  - **Until its prompt shows,** a request keeps its method's time limit today: 300 s for `eth_sendTransaction` and the Swarm and Radicle methods today's timers give 300 s, 60 s for the rest, counted from its arrival in main. At it, main answers "Request timed out", closes the handle (`expired`) and drops any late result, so a prompt the user never saw can't appear, or take effect, after the page has been told it failed.
  - **Once shown,** a prompt has no deadline, hidden again or not: the user can take their time, and the page waits for the decision, its document going or its window closing. Today the page's timer rejects while the prompt stays open, and an approval after it still takes effect.
  - The token a decision mints keeps today's two minutes.

## The prompt protocol

**Before APS,** from PRQ-4 on, between main and the chrome:

| Message | Direction | Payload |
|---|---|---|
| `page:prompt` | main → chrome | `{ handle, guest, kind, site, view }` |
| `page:decide` | chrome → main (`invoke`) | `{ handle, approve, choices }`. Answers `{ ok }`, or why not |
| `page:prompt-closed` | main → chrome | `{ handle, reason }`, the reason one of `decided`, `navigated`, `closed`, `cancelled`, `expired` |
| `page:prompt-hidden` | main → chrome | `{ handle }`: hide a shown prompt, whose guest has left the front. It keeps its place, and `page:prompt` shows it again |
| `page:prompt-pending` | main → chrome | `{ handle, guest }`: a handle opened, for the tab's badge and the wallet button's count. Both count every open handle, shown or not, until `page:prompt-closed` |
| `page:foreground` | chrome → main (`send`) | `{ guest }`: the guest now in front of this window, sent when the window's first tab shows and at every tab switch |

- **`site`** is main's: `{ key, label }`, the key as the address bar shows it. The chrome shows it unchanged.
- **`view`** is what to show, built by main: a transaction's fields and the fee check's verdict, typed data and messages as the core's view (#88), the account and the chain. The chrome renders it. Much of it is the page's choice, checked for form and size but still hostile: [What a prompt shows](#what-a-prompt-shows) classifies every field.
- **`kind`:** one per today's prompt. `eth.connect`, `eth.send`, `eth.sign`, `eth.safe_message`, and `eth.safe_send` for a site's Safe transaction board (PRQ-5); `swarm.connect`, `swarm.publish`, `swarm.feed`, `swarm.messaging`, `swarm.manifest`; `radicle.connect`, `radicle.node`, `radicle.sign`; and `vault.unlock`, when a request needs the vault unlocked.
- **`choices`:** only what the kind lets the user pick. The account for a connect, "always allow" where today's prompt offers it, the fee acknowledgement for a send.
- **`guest`** lets the chrome show which tab asked, and switch to it.
- **`page:foreground`** is accepted only from that window's chrome (the sender policy's chrome tier) and only for a live guest that window hosts; anything else is ignored. Main keeps one guest in front per window, none until the first report. A report only chooses which pending prompt shows. Which tab is in front is the chrome's to say: main doesn't own the tabs ([open question 4](#open-questions)).

**Approval tokens.** Today the chrome asks `wallet:confirm-signing` for a token of any of `signing-confirmation.js`'s ten kinds, with an account and a payload of its choosing (`wallet-ipc.js:621–643`). From PRQ-5 the kinds that serve page requests have one issuer, inside main:
- **The page kinds:** `dapp-send`, `sign-message`, `sign-typed-data`, `safe-message`, and a `safe-send` that names a site (a dApp's transaction from a Safe account, `wallet/dapp-tx.js:819`).
- **The internal issuer** is the dispatcher's. It mints a token of a page kind only on an approval of an open handle, shown at that moment, whose request record is live. It takes the handle and the attested key from that record, and the account and the payload from the request main holds, never from a caller. The token never leaves main: the dispatcher spends it.
- **The chrome's `wallet:confirm-signing` refuses the page kinds** from PRQ-5 on. It goes on minting the wallet's own six (`wallet-send`, a `safe-send` with no site, `intent-resend`, `intent-replace`, `intent-close`, `executor-send`) until APS-3.
- **The auto-approve route moves too.** The signing handlers refuse the chrome's `{ autoApprove, webContentsId }` authorization for the page kinds. The dispatcher reads the site's rule itself, for the request record's key, with [Agent custody](#agent-custody) read live.

A page kind's binding gains two fields, both from the record:
- **the handle,** so a token answers one prompt;
- **the attested key,** so a token minted for one site's request can't sign another's. A `dapp-send` token binds a site today, but the chrome supplies it (`signing-confirmation.js`, "What a token binds"). Now it is the requester's.

The dispatcher checks the document again before it spends the token. If the document has gone, the token is refused and burnt.

**Device steps** keep today's paths after the decision. A Ledger signs in main. A phone account's job goes to the chrome's openlv session through main's bridge, which accepts answers only from the chrome it sent the job to and checks every signature against the account (`wallet/remote/bridge.js`). Roadmap 2.7 moves the job into the core.

**After a waiting signature or send.** A signer can take a long time (a Ledger, a phone, the core), and a name can move off its IPNS key meanwhile. So after every waiting signature or send, main checks the name and the requester's key again, and any grant write that follows (an "always allow", a contract rule, a last use) happens in the same run as that check, by the check itself, never after a further await (PRQ-5).
- **A signature** whose check fails is withheld: the page gets the keyless answer. The signature is the effect, and nothing else has happened.
- **A send** is checked at the last point main controls before the transaction leaves, and if the check fails there, nothing is sent:
  - **a vault or Ledger account:** between the signature and the broadcast;
  - **a phone account:** just before main asks the phone, which signs and broadcasts as one operation, so main has no later point;
  - **a site's Safe transaction:** before each step that can execute it. A transaction parked on the Safe board and executed later is checked again at its execution, with the requesting document still live. If the name has moved by then, it isn't executed for the site: the page gets the keyless answer, and the parked transaction stays in the wallet, which the user can execute or discard as a wallet transaction with no site;
  - **the agent service's send:** the same check, inside the service's effect.
- **Once a transaction has gone out** after a passing check, its hash goes back to the requesting document while that document is live, even if the name moves afterwards: the payment happened for the request the user approved, the hash is public, and withholding it could lead a reloaded page to ask for the payment again. The grant writes after the broadcast still need the name.

**Grants.** Main writes a grant from an approval, for the requester's key: the connect's account and chain, an "always allow". A contract rule from a confirmed send is recorded today for the site the chrome names in `rememberAutoApprove` (`wallet-ipc.js:409–420`); it is now recorded for the requester's key. As each kind of prompt moves, main refuses the chrome's grant writes that its decisions make: from PRQ-4 (connecting and switching chains), `dapp:grant-permission` and a chain passed to `dapp:update-last-used`, whose timestamp-only form the unmoved signing paths still use; from PRQ-5 (signing), `dapp:set-signing-auto-approve`; from PRQ-7, `swarm:grant-permission`, `swarm:set-auto-approve` and `swarm:grant-messaging`; from PRQ-8, `radicle:grant-permission`, `radicle:grant-signing` and `radicle:set-auto-approve`. A write whose prompt still runs in the chrome stays open until its step, or the honest prompt would break. Revoking stays open to the chrome, since it narrows.

**After APS** `page:prompt`, `page:prompt-hidden`, `page:decide` and `page:prompt-closed` run between main and the approvals document. The chrome gets only `page:prompt-pending` and `page:prompt-closed`, for the badges and the count, and still sends `page:foreground`. Its `page:decide` is refused.

**Vault unlock.** Today the chrome shows the unlock screen when an auto-approved request finds the vault locked (`dapp-provider.js:332`, `371`). It stays there until APS-2. Then a `vault.unlock` prompt in the approvals document takes the password, and main unlocks.

### What a prompt shows

Every field of a prompt, by where it comes from:

| Field | From | Trust |
|---|---|---|
| `kind`, the handle | main | Main's own |
| The account: its address, label and kind (vault, Ledger, phone, Safe) | main's wallet state | Main's own |
| The chain: its id and name | main: the selected chain, or an onchain app's own | Main's own |
| The fee check's verdict, and the most a send can cost | main and the core (design 0005) | Main's own |
| A warning | the core's view (#88) or main: a code from a fixed list, with fixed text | Main's own. A value a warning quotes is the page's, as below |
| `site`: the key and its label | main: the committed URL, or a name a binding verified | Attested, but the site's owner chose its characters (a lookalike name). Shown as the address bar shows it |
| Which tab asked: its place in the tab strip | the chrome, which owns the tabs | The chrome's. Main's own is which guest asked, and its `site` |
| That tab's title | the page | The page's, unchecked. Shown only marked as the page's, or not at all |
| A page's favicon or any other image | the page | Never shown |
| A transaction: `to`, `value`, `data`, the gas fields | the page | The page's, checked: main's shape checks (an address, a quantity, hex), shown in main's form (a checksummed address, an amount in units) |
| A message (`personal_sign`) | the page | The page's, checked: main's message view decides text or hex |
| Typed data: the domain, the type and field names, the values | the page, through the core's view (#88) | The page's, bounded and put in canonical form by the core |
| A Safe message, or a dApp's Safe transaction | the page | As typed data and transactions |
| Swarm: file names and paths, sizes, content types, a feed's name or topic, a message's target | the page | The page's, checked against `LIMITS` |
| Radicle: a repository id, an issue's title and text, a comment | the page | The page's: the id checked for its form, the text for its size |

- **Only main's own fields are trusted.** Every other field is hostile text, however main checked it, and is rendered as [Rendering a page's data](#rendering-a-pages-data) says.
- **A closed schema.** For each `kind`, the view is a fixed list of these fields, each with a type and a bound: a length for each string, a count for each list, a depth for nesting (the core's typed-data view keeps its own), and at most 256 KiB for the whole view (proposed). Main builds the view to the schema and refuses a request whose view won't fit, as the core refuses a typed-data view too large for one reply today. Whoever renders the view checks it against the same schema.
- **Before APS** the chrome renders it, and a markup bug there is a compromised chrome, as today. The rules matter most for the approvals document, which holds the decision channel.

## Events

Main sends `page:event` with `WebFrameMain.send` on the guest's main frame, and only while that frame's current document is the one the event is for: the same key, and the same number where a subscription is bound to one. To a name-keyed document, an event of a name-revalidated kind ([Which methods check the name](#which-methods-check-the-name)) goes only once the name answers `transportKey` again. If it doesn't, the event isn't sent and the binding ends.

**The nonce in every event.** Main's check isn't enough alone. `WebFrameMain.send` targets a frame, not a document. A frame keeps its `frameTreeNodeId` across navigations, and its `WebFrameMain` across a same-process one, while its document changes. Between main's check and the delivery, the renderer can commit a new document in that frame, and the event then reaches the new document's preload. So every `page:event` carries the target document's nonce, which only main and that document's preload know, and the preload drops an event whose nonce isn't its own, before the page sees anything. The old nonce tells the new document nothing it can use: main refuses it. It doesn't stop a compromised chrome from forging events of its own ([Threat model](#threat-model)): it can script the page, which needs no nonce.

| Provider | Event | When |
|---|---|---|
| ethereum | `accountsChanged` | a grant for the key is written, changed or revoked: to every live document of that key |
| ethereum | `chainChanged` | the chain a document reads changes, through a `wallet_switchEthereumChain` or the user's selection. Never to an onchain app |
| ethereum | `connect`, `disconnect` | as today |
| swarm | `connect`, `disconnect` | a Swarm grant for the key is written or revoked |
| swarm | `message` | a subscription's message, to the document that subscribed. Today's delivery check (`swarm-provider-ipc.js:1911–1930`), keyed on the document |
| radicle | `connect`, `disconnect` | a Radicle grant for the key is written or revoked (today `radicle-provider.js:170–176`, `194–204`) |
| radicle | `seedStatus` | to every live document of the key. Today the chrome loops over its webviews (`radicle-provider.js:83–89`) |

- **The selected chain** is chrome state today (`chain-switcher.js:218`). It moves to main, set by the chrome (`wallet:select-chain`, new) and by a page's `wallet_switchEthereumChain`. A compromised chrome can change it. That isn't an approval, and every prompt shows the chain.
- **Subscriptions** are bound to the document. A navigation ends them, as `did-navigate` does today.

## The dispatcher

- **In main's JS first,** in `src/main/page/`: the requester and documents (`page-documents.js`), the channels and handles (`page-requests.js`), the prompts (`page-prompts.js`), and one dispatcher per provider. They move today's chrome logic (`dapp-provider.js`, `swarm-provider.js`, `radicle-provider.js`) into main, method by method. They call main's existing authorities directly: `wallet-ipc.js`'s handlers, `executeSwarmMethod` and `executeRadicleMethod`, with the attested key in place of the chrome's `origin`.
- **The chrome's provider modules** shrink to rendering prompts.
- **The Identity & Wallet switch** (`enableIdentityWallet`) is read in main. When it's off, every request gets `4900`, as today.
- **Agent custody:** main asks the agent service itself (`handleWalletRequest`, reached through the chrome today, `agent/ipc.js:664–684`). No standing rule answers for a tab in custody ([Agent custody](#agent-custody)).
- **Why JS first:** one move at a time, and the JS becomes the reference. 0012's `fc-eip1193` ports the Ethereum dispatcher, with vectors recorded from it.

### Agent custody

Custody changes while a document lives. The automation takes a tab and the user takes it back, with no navigation (`setAgentPageCustody`, a `WeakSet` in `agent-tab-custody.js`), and today's checks read it at the moment they decide (`requesterBelongsTo`, and Swarm's and Radicle's `agentCustodyRefusal`). So the record's `agent` field, read at the hello, is for logs and tests only, and main reads custody live:
- **When it chooses a standing rule.** Before a standing rule answers a request (an "always allow", a contract rule, a Swarm or Radicle auto-approve, Radicle's signing grant), main reads `isAgentPage(event.sender)`. In custody no rule answers: the request takes the path of a request no rule covers, its prompt or the agent service's own handling, as today.
- **Again just before the effect,** after the last await (a name's resolution, a vault unlock, the fee check, the core's view). A guest that entered custody meanwhile has its auto-approved request refused (`agent_custody`, as Swarm and Radicle answer today), with nothing signed, sent, published or seeded.
- **A user's own decision isn't a standing rule.** A prompt the user answers counts in custody or out, as today's `meta.approval: 'user'` does.
- **The agent service's handling is a prompt too.** A request in custody that goes to the agent service instead of a prompt keeps the prompt's rules: it holds the document's one pending wallet prompt, main's deadline and closing apply to it, and an approval that arrives after its request has closed does nothing. Main checks the name and the requester's key again before the agent service's grant or effect, as after a user's decision (PRQ-4).
- **Leaving custody** lets the rules answer the tab's later requests. A request that went to its prompt because its tab was in custody keeps its prompt: it doesn't turn automatic when custody ends.

## The approvals document

Roadmap 2.8 step 1: a surface for approvals that neither the chrome renderer nor a page can drive.

- **One per chrome window,** created with the window: a `WebContentsView` added to the window's `contentView` above the chrome's own view, hidden until it has something to show.
- **Its own document and preload:** `renderer/approvals/approvals.html` and `approvals-preload.js`, both packaged. `sandbox: true`, `contextIsolation`, no Node, no `webviewTag`, no `nodeIntegrationInSubFrames`. Its own in-memory partition, which refuses every request but for its own files. Navigation and popups are refused, as `lockChromeWindow` refuses them for the chrome.
- **Sender checks:** main's `approvals:*` handlers accept only that window's view. `event.sender` is the exact webContents main created, `senderFrame` is its main frame, and the URL is the packaged file. The spike checks the sender the same way (`senderMatchesSurface`).
- **Main mints approval tokens only for it.** From APS-2, a decision on a page's handle counts only when it comes from the window's approvals document. The chrome's `wallet:confirm-signing` has refused the page kinds since PRQ-5 ([Approval tokens](#the-prompt-protocol)). From APS-3 it mints none of the wallet's own kinds on its own either: it opens the request in the approvals document, and the token is returned only when the user approves there.
- **What it shows:** the `view` of [the prompt protocol](#the-prompt-protocol), the site's key, and which tab asked, with every field classified in [What a prompt shows](#what-a-prompt-shows).
- **Where:** a panel at the side of the content area, below the toolbar, where the wallet sidebar shows its prompts now. Only approving and rejecting move into it; managing the wallet stays in the sidebar ([open question 2](#open-questions)). The chrome can't paint over a view stacked above it, and a page paints only inside its own guest.
- **Input:** [Rendering a page's data](#rendering-a-pages-data).
- **Background tabs:** a background tab's request waits ([open question 3](#open-questions)). Its tab shows a badge and the wallet button a count, and its prompt opens when the user switches to that tab, so with an honest chrome a prompt always belongs to the page in front.
  - **Main holds it,** from PRQ-4: it sends `page:prompt` (to the chrome before APS-2, to this document after) only while the guest is in front by the chrome's `page:foreground` report, and hides it with `page:prompt-hidden` when the guest leaves the front ([Requests and handles](#requests-and-handles) gives the order, the deadline and when a held prompt closes).
  - **The limit:** this stops a page timing a prompt to appear over another site. A compromised chrome can report the wrong tab in front and bring a prompt up over another page; the prompt still names its `site`.

### Rendering a page's data

The document holds the decision channel, and it shows what a hostile page chose: a message, typed data's names and values, file names, an issue's text. Script that runs in it, through a markup bug, could approve by itself, and a sandbox, a private partition and exact sender checks don't prevent that. So:
- **A closed, bounded schema.** The document accepts only the views of [What a prompt shows](#what-a-prompt-shows), and checks each against its kind's schema before it shows anything. An unknown kind or field, a wrong type, or a value over its bound shows a fixed error, and the prompt can then only be rejected.
- **Text only.** The document is built from fixed templates in its own packaged script. Every value goes in as text (`textContent`), never as markup, a style, a URL, or an attribute a value chooses. Nothing from a page is ever HTML or code: no `innerHTML`, no `eval`, no `new Function`.
- **Encoded for where it shows.** Control characters, and characters that are invisible or change the direction of text (the bidi controls, zero-width characters), show as visible escapes, so a message can't hide text or reorder what's around it. A long value is cut with a visible mark and shown in full in a scrolling text box.
- **A restrictive CSP,** sent by main's handler for the document's partition with the document itself: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-src 'none'; object-src 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'` (proposed). The last two make every markup sink (`innerHTML`, `insertAdjacentHTML`, `document.write`) throw, so a slip in a template fails closed.
- **No links.** No `<a href>`, `<form>`, `<area>`, `<iframe>`, `<object>` or `<img>` is ever built from a value. A URL, such as a site's or a contract's, is shown as text. Nothing in the document navigates or opens a window, and main refuses both anyway.
- **Input.** The panel takes focus when it shows. Clicks and keys do nothing for 500 ms (proposed) after a prompt appears, after its content changes, and after the panel is shown again or moves, so a page can't time a click onto it. Main also refuses an approval that reaches it sooner than 500 ms after the document reported the prompt shown.
- **Enter never approves.** No button is the default, focus starts on Reject, and Enter does nothing on Approve. Approving by keyboard is Space on a focused Approve, after the delay (proposed).

**The spike `b58441b1`** built a trusted wallet surface: a right-hand `WebContentsView` drawer in the package chrome's `ShellWindow`, with a detached `BrowserWindow` as the fallback, its own preload, random channel names per surface, and a strict sender check. 0011 keeps the view, the preload and the sender check, and differs in three ways:
- it hosts approvals, not wallet management;
- it runs sandboxed, where the spike set `sandbox: false`;
- it attaches to the window's `contentView` directly, with no detached window. Integration has no `ShellWindow` compositor, and a separate window can't be told apart from a page's popup.

## Bounds

A count of requests is no bound on memory here. One `swarm_publishFiles` may carry 50 MiB (`LIMITS.maxFilesBytes`, `swarm-provider-ipc.js:64`), so 64 of them from one document would be over 3 GiB. Main bounds bytes as well as counts, across every document.

**What main can't bound.** Electron turns an IPC message's arguments into JS values in main before any handler runs, the sender policy's included (`ElectronApiIPCHandlerImpl::Invoke` and `Message`), and gives main no way to see a message's size first. The only limit before that is Chromium's own cap on one IPC message, and it is above every bound here: a 50 MiB upload passes it today, through `sendToHost`. So a request's bytes reach main's memory once, whatever main then decides. A compromised renderer can make main take that much for each message it sends, on any channel, as it can today: the sender policy runs after the conversion too. What 0011 bounds is what an honest preload sends, which a page's script can't change, and everything main keeps once a request has arrived.

**The rules:**
1. **A size per request.** The two methods that carry data or files may be as large as their own payload limit plus 64 KiB for the rest of the request (`swarm_publishData` 10 MiB, `swarm_publishFiles` 50 MiB, from `LIMITS`). Every other method may be 1 MiB (proposed). [The walk](#the-size-and-the-charge) measures it, the same way in the preload and in main.
2. **Checked before sending.** The preload measures a request before it sends it, and refuses one over its size with the error the method gives an oversized payload today, or `-32005` where it has none. A page's script can't go around the preload.
3. **Checked and charged on arrival.** Main measures again, first thing, and refuses a request over its size. It then charges the request's whole [charge](#the-size-and-the-charge) before it records, copies, queues or validates the request, so every copy main will make of it is paid for before the first is made. Main keeps no reference to a refused request, so its bytes are garbage at once.
4. **Budgets across documents.** Main charges each admitted request's charge and count to its document, its window and the whole browser, and refuses a request when any of the three is full (`-32005`, and nothing runs). A charge ends when the request is answered and main has let go of its payload and of every copy.
5. **Large requests take turns.** A request over 1 MiB (only the two Swarm uploads allow one) needs a ticket, granted two at a time across the browser ([Large requests](#large-requests)).

### The size and the charge

One walk over a request gives two numbers. The preload and main walk the same way, and refuse a request past 10,000 values or 32 levels (proposed).

- **What the walk takes:** strings, numbers, BigInts (below), booleans, `null`, `undefined`, arrays, plain objects, `Uint8Array` and `ArrayBuffer`. Anything else (another typed array, a `DataView`, a `Map`, a `Date`, a `Blob`) is refused as invalid params (`-32602`). No method takes one today: binary data is a `Uint8Array` or an `ArrayBuffer`, as the Swarm API documents it (`docs/swarm-provider-api.md:105`, `460–462`).
- **A BigInt is bounded and counted.** A BigInt is arbitrary precision, so one value could hold any amount of memory. The walk refuses a BigInt whose magnitude needs more than 256 bits (proposed; the widest any method takes today is `swarm_publishChunk`'s `span`, a `u64`, `swarm-provider-ipc.js:267–277`), and counts each one it takes as 32 bytes in the size. Main checks this in the walk, before method validation, so a method's later, narrower check is not what bounds it.
- **A view counts its whole buffer.** Main counts a `Uint8Array` at its buffer's length (`buffer.byteLength`), whatever part of it the view shows. The preload sends a view that doesn't span its buffer as a copy of just its own bytes, so main gets what the preload measured.
- **The size** is compared with the request's limit: the UTF-8 bytes of every string and property name, and the bytes of binary data, as `LIMITS` counts them. The `{ type: 'Buffer', data }` form that `normalizeBytes` also takes is an array of numbers to the walk, so it carries 10,000 bytes at most.
- **The charge** is what main may hold for the request at once: the size times the method's copies (below), plus 128 bytes for each value and each property name (proposed), for its place in the heap, plus 32 KiB for main's own record of the request, which PRQ-2 measured at 6 to 9 KiB; 16 KiB left too little room on CI runners, where one run measured 1.8 KiB over. So 10,000 near-empty values cost at least 1.2 MiB, and 2.4 MiB with a name each, not nothing. 1,024 such requests would need over 1.2 GiB, far past the browser's budget.

**Copies** counts every form of a request's bytes that main can hold at the same time, the IPC value included. The numbers come from today's code paths:

| Method | Copies | What main holds at once |
|---|---|---|
| `swarm_publishFiles` | 2, and 1 MiB of stream buffers | Kept as a margin: since PRQ-7c, main holds the IPC value and sends it to the node itself (`page-upload.js`, in 64 KiB slices with no copy of the body; `normalizeBytes` makes a view of a `Uint8Array`), and PRQ-7c measured a 50 MiB upload's peak at 50.2 MiB. The first count assumed a `normalizeBytes` copy and bee-js's path, whose fetch held about 2.3 copies and reached about 250 MiB, so page uploads left bee-js |
| `swarm_publishData` | 3 | Kept as a margin: the IPC value, sent by `page-upload.js` with no copy of a `Uint8Array`'s bytes, and a string's UTF-8, since V8 may hold the string at two bytes a character where UTF-8 takes one. PRQ-7c measured 10.1 MiB for a 10 MiB `Uint8Array` and 20.2 MiB for a 10 MiB two-byte string |
| Every other method | 24 (proposed) | At most 1 MiB, which main may hold as the IPC value (a string in up to two bytes a character), as JSON for the core or a node (where a control character takes six characters, `\u0001`, and V8 keeps the JSON of a string with any character past U+00FF at two bytes a character too, so twelve bytes), and as that JSON's UTF-8 in a frame or a request body (six): 2 + 12 + 6, rounded up. PRQ-2 measured a peak of 20.03 MiB for a 1 MiB string of control characters held at two bytes a character |

**What the numbers give:**
- the largest `swarm_publishFiles`: 2 × (50 MiB + 64 KiB), 2.4 MiB for the walk's most values and names, 1 MiB of buffers and 32 KiB for the record, about 103.6 MiB;
- the largest `swarm_publishData`: 3 × (10 MiB + 64 KiB), 2.4 MiB and 32 KiB, about 32.7 MiB;
- the largest request of any other method: 24 × 1 MiB, 2.4 MiB and 32 KiB, about 26.5 MiB.

So the budgets are set from the largest upload (all proposed). A document's 128 MiB holds one, with about 24 MiB to spare. A window's 256 MiB holds the two the browser runs at once, from two of its documents, with about 49 MiB to spare. The browser's 384 MiB holds those two and leaves about 177 MiB for everything else.

**Measured, not assumed.** PRQ-2 and PRQ-7 run each method's largest legal request in its worst form: a maximum-size `Uint8Array`, a string V8 holds in two bytes a character, a string of control characters, 10,000 near-empty values. A test hook at each point where main makes or causes a copy, or hands bytes on (`normalizeBytes`, a page upload's 64 KiB slices to the node, the JSON for the core), checks that the charge is already in place, and main's peak for the request, the IPC value and every live copy included, must stay within its charge. A method whose peak passes its charge fails its step: its copies and the budgets are raised together, or its path changed to hold fewer, before the step merges. A path that drops a copy lowers the measured peak, but no bound depends on it: since PRQ-7c `normalizeBytes` makes a view of a `Uint8Array` and `page-upload.js` sends views of the IPC value, and the 2× and 3× copies of the uploads stay as a margin.

**Why charge the copies, not remove them.** A path with no copy can't hold for every form a page may send. A string must become UTF-8 bytes, which is a new allocation. The libraries main hands bytes to can also change what they copy from one version to the next: bee-js's fetch held about 2.3 copies of an upload's body, which is why page uploads moved to `page-upload.js` (PRQ-7c). A measured charge catches that, and a promise of no copies doesn't.

### Large requests

A request over 1 MiB first reserves its turn with `page:reserve { nonce, method, bytes }`. A reservation is an attested request in every way a request is:
- **Checked as a request.** It passes the six steps of [the attested requester](#the-attested-requester). A private window, a preview, a sub-frame, a detached frame, a document with no hello or another nonce, and a URL off its `transportKey` get no ticket. `method` must be one of the two uploads, and `bytes` over 1 MiB and within that method's size, or it's refused (`-32602`). While it waits, it counts as one of its document's requests in the count budgets.
- **One per document.** A document has at most one reservation waiting or holding a ticket, and the browser at most 16 waiting (proposed). Past either, `-32005`. The preload queues its document's other large requests itself, so one page can't hold every turn.
- **Bound to its document.** The waiting entry, and the ticket granted for it, hold the guest, window, frame, navigation and nonce of the record, and the method and bytes of the reservation. The ticket is 32 random bytes made by main and means nothing outside it: main keeps the binding, and the preload only the bytes.
- **Granted in turn.** When one of the two turns is free, main takes the oldest entry whose charge fits its document's, window's and browser's budgets. An entry that doesn't fit keeps its place. Main checks the entry's document again, as the six steps do: the guest live, its window open, the frame the guest's main frame and not detached, the navigation and nonce the current document's, and the frame URL keyed to `transportKey`. Only then is the ticket made and charged, at the most a request of that method and size can be charged: its copies times `bytes`, the walk's largest overhead, and for `swarm_publishFiles` its stream buffers. An entry that fails the check is dropped, and its reservation answered `navigated`, which a document that has gone never sees.
- **Spent once.** A `page:request` that carries a ticket burns it on arrival, before any other check, whether the request is then served or refused: no ticket is presented twice. Main checks the request as it checks every request, and checks the ticket's binding against it: the same guest, window, frame, navigation and nonce, the same method, and a size no more than `bytes`. A mismatch refuses the request (`-32005`) and frees the ticket's charge and turn. A match moves the ticket's charge to the request, with no gap between them, and the turn stays taken until the request is answered.
- **Released** when its document goes, whether it's waiting or granted: a main-frame navigation, the guest destroyed, its window closed. A granted ticket unused for 30 s is released too (proposed). Its turn goes to the next entry.
- **A large request with no ticket,** or with one main doesn't hold, is refused.

### The numbers

| Bound | Value |
|---|---|
| A request's size | `swarm_publishData` and `swarm_publishFiles`: their payload limit plus 64 KiB. Every other method: 1 MiB (proposed) |
| The size walk | 10,000 values, 32 levels (proposed) |
| A request's charge | Its size times its method's copies (`swarm_publishFiles` 2, `swarm_publishData` 3, every other method 24), 128 bytes for each value and property name, 32 KiB for main's record, and 1 MiB of stream buffers for `swarm_publishFiles` (proposed) |
| In flight per document | 64 requests and 128 MiB of charges (proposed). The next gets `-32005` ("limit exceeded", EIP-1474) and doesn't run |
| In flight per window | 256 requests and 256 MiB (proposed) |
| In flight in the browser | 1,024 requests and 384 MiB (proposed) |
| Large requests (over 1 MiB) | 2 at a time in the browser, 1 reservation per document, 16 waiting in the browser (then `-32005`), a ticket unused for 30 s released (proposed) |
| A ticket | 32 random bytes, made by main, spent once |
| A prompt's view | 256 KiB, and each field's own bound ([What a prompt shows](#what-a-prompt-shows)) (proposed) |
| Pending wallet prompts per document | 1. The next request gets `-32002`. One prompt shown per window, as today |
| A request's deadline, until its prompt shows | today's page timer for its method, 300 s or 60 s, now main's alone |
| Hellos per document | 1; later ones are ignored |
| The nonce | 16 random bytes, made by the preload |
| A handle | 32 random bytes, made by main |
| Tokens | today's: two minutes, at most 32 outstanding (`signing-confirmation.js:68`, `72`) |
| The panel's input delay | 500 ms (proposed) |

Per-method bounds stay where they are (`swarm-provider-ipc.js`'s `LIMITS`, and the Radicle provider's), checked after these.

## Migration

One browser PR per step, against `integration/rust-core`, in this order. A step moves its methods: the preload sends them on `page:request`, and every other method keeps today's path until its own step.

| Step | What | The tests that prove it |
|---|---|---|
| PRQ-1 | The attested requester and documents (`page-documents.js`), not yet used | Unit tests for each refusal: not a tab, private, preview, sub-frame, detached, no hello, wrong nonce, navigated. The key of every row in [Keys](#keys), and the name binding: `transportKey` and `key` kept apart, step 6 comparing a name-keyed document's frame URL with `transportKey`, and no decision reading the record's `agent`. In real Electron: main sees the commit before the new document's hello, across same-process, cross-process, reload and back/forward navigations |
| PRQ-2 | `page:hello`, `page:reserve`, `page:request` and `page:event`, the sender-policy tier, handles and delivery, the bounds and tickets, and the method table, run through a test hook; no method moved | **A sub-frame's request refused.** **A page that navigated away refused:** a request sent, the page navigated, the request finished: no reply and no effect. **An event for a replaced document dropped:** main checks the record, a test hook holds the `send`, the frame commits a same-process document of the same key (a reload, a link within the site), and the hook lets the send go: the new document's preload drops it, and its page sees nothing. **The size per request:** a request of exactly its method's size passes, and one byte more is refused by the preload, and by main for a request a test hook sends past the preload, before main records it. **The charge:** for every method, its largest legal request in each worst form (a maximum-size `Uint8Array`, a string V8 holds in two bytes a character, a string of control characters, 10,000 near-empty values): the charge is in place at every copy hook, and main's measured peak, the IPC value and every live copy included, stays within it. 1,024 requests of 10,000 near-empty values each, across documents and windows: admitted only while their charges fit, the rest refused with nothing run. **BigInts:** a BigInt of exactly 256 bits passes the walk and is counted as 32 bytes; one of 257 bits, and one of millions of bits sent past the preload by a test hook, are refused by the walk before main records the request. **The budgets:** documents in two windows, each within its own bound, fill the window's and then the browser's budget; the next request is refused and nothing runs; admission resumes as they finish. **Reservations:** `page:reserve` refused with a wrong nonce, before the hello, from a private window, a preview, a sub-frame and a detached frame, and with a frame URL off its `transportKey`; a document's second reservation refused. A waiting entry dropped when its document navigates, its guest is destroyed or its window closes, its turn going to the next. A granted ticket released on each of the same, and after 30 s unused. A ticket presented twice: the second refused, after a first that was served and after one that was refused. A ticket presented by another document of the same guest, by another guest, for another method, or with more bytes than reserved: refused, the ticket burnt, its charge and turn freed. **The method table:** every method in today's lists (`READ_ONLY_METHODS` and the dispatcher's own in `dapp-provider.js`, Swarm's `KNOWN_METHODS`, Radicle's `METHOD_TIERS`) and every event has exactly one class, and a method with no row is refused before anything runs. Private windows and previews refused, the chrome refused on `page:request`, the per-document bound |
| PRQ-3 | Ethereum reads: `eth_chainId`, `net_version`, `eth_accounts` and the read-only list (`dapp-provider.js:74–100`). The selected chain in main | The same answers as the chrome's, for each method and URL form. An onchain app's chain pinned. A keyless document's reads. A name-keyed document's `eth_accounts` answers empty once the name moves off its IPNS key, and its permission-free reads still answer, with no resolution |
| PRQ-4 | Connecting: `eth_requestAccounts` and `wallet_switchEthereumChain`, with `page:prompt`, `page:prompt-hidden`, `page:decide`, `page:prompt-pending` and `page:foreground`. Main writes the grant, and holds a background tab's prompt | **A forged chrome origin refused:** the chrome's `dapp:grant-permission` refused for every site; a `page:decide` names no site and can't move a grant to another; a decision from another window's chrome refused. One pending wallet prompt per document (`-32002`). **A background tab's prompt waits:** main sends a guest not in front `page:prompt-pending` and no `page:prompt` until the chrome reports its tab in front. A held prompt closes, its badge and count with it, when its document navigates, its tab or window closes, and at its deadline (a test hook delays its delivery to main past today's page timer: it still gets its full deadline, and the page hears only main), after which the page has today's "Request timed out", a later report that its tab is in front shows nothing, and a decision for it is refused with nothing done. **Several tabs:** the tab in front shows its oldest prompt, then its next; a background tab's waiting prompt never refuses or replaces the tab in front's. **Switching away:** with tab A's prompt shown, a report of tab B in front hides it (`page:prompt-hidden`); it keeps its place and gets no deadline, B's oldest shows if it has one, and switching back shows A's again. A decision for A sent after the report of B, before the chrome has hidden A, is refused with nothing done; after switching back, a decision for A counts. Badges and the count follow open handles until `page:prompt-closed`. `page:foreground` from a page, from another window's chrome, or naming a dead guest or another window's guest: ignored. A name that moves off its IPNS key while its connect prompt is open gets no grant. **`wallet_switchEthereumChain` after the name moves off its IPNS key:** refused, the grant's chain and the selected chain unchanged, and no `chainChanged` sent **Grant writes:** a chain passed to `dapp:update-last-used` refused with the grant unchanged, and its timestamp-only form still accepted. **The agent service's handling:** a custody request holds the document's pending wallet prompt (the next request gets `-32002`); it is withdrawn at its deadline, its document's navigation, and its tab's or window's close, after which an Agent approval creates no grant and leaves an existing one unchanged (its account, chain and last use); and the name and the requester's key are checked again just before either effect, a new grant or an update to an existing one. |
| PRQ-5 | Signing: `eth_sendTransaction` (from a Safe account too), `personal_sign`, `eth_signTypedData_v4`, Safe messages. The page kinds reserved to main's issuer; tokens bound to the handle and the attested key; auto-approve read by main | **The chrome mints no page token:** for each of `dapp-send`, `sign-message`, `sign-typed-data`, `safe-message` and a site's `safe-send`, the chrome's `wallet:confirm-signing` is refused, and the handler refuses the chrome's `{ autoApprove, webContentsId }` authorization (a `safe-send` has no rule, and stays refused on that route). Through main's issuer: no token without a live request record; a token minted for handle A refused for handle B, for another key, after its document navigated, and when spent twice. Through main's own reading of the rules: a rule answers only a live request record of its own key. **Custody read live:** a tab that enters custody after its hello gets no standing rule; one that enters custody while an auto-approved request waits (on the name, the vault, the core's view) has that request refused, with nothing signed; one that leaves custody gets the rules for its next request, and a request already at its prompt keeps it. **A name moving off its IPNS key** before the rule is read, during the resolution and while the prompt is open: refused, nothing signed, on both routes **Grant writes:** the chrome's `dapp:set-signing-auto-approve` refused for setting a rule, and still accepted for clearing one. **The agent service's handling:** an Agent-custody send or signature withdrawn at its deadline or close signs and sends nothing when the Agent approves it later, and its name and key are checked again just before the effect. **After a waiting signature or send:** a name that moves during a signer's wait gets the signature withheld, for each account kind. Each send's last check, at its own boundary: a vault or Ledger send whose name moves after signing and before the broadcast sends nothing; a phone send whose name moves before main asks the phone sends nothing, and one whose name moves after main has asked returns the sent hash; a site's Safe transaction whose name moves before any execution step, a parked one included, is not executed for the site and stays in the wallet; the agent service's send whose name moves before its effect sends nothing. For every path that broadcast after a passing check, the hash returns only to its still-live requesting document (a navigated document gets nothing), and no grant write follows a name loss. |
| PRQ-6 | The Ethereum events the chrome still sends: the chain switcher's `chainChanged`, and `accountsChanged` when a grant is revoked or its account changes. A moved method's own events go out from main in its own step | None delivered to a navigated document, another key, a sub-frame or a private window. No `chainChanged` to an onchain app. No `accountsChanged` to a name-keyed document once the name moves off its IPNS key. PRQ-2's replaced-document race, for each event |
| PRQ-7 | `window.swarm` through main: `executeSwarmMethod` takes the attested key, subscriptions are bound to the document, the manifest flow moves | **A forged chrome origin refused:** `swarm:provider-execute` is gone. A message for a navigated document dropped, and PRQ-2's replaced-document race for `message`. **Uploads:** a `swarm_publishFiles` request of exactly its size, its file bytes one 50 MiB `Uint8Array`, passes: its ticket's charge (about 103.6 MiB) is in place before `normalizeBytes` and before the first slice goes to the node, it fits the document's 128 MiB, and main's measured peak, the IPC value and every live copy included, stays within it. One byte more is refused. Three such uploads from three documents of one window run two at a time within the window's 256 MiB, the third waiting for its ticket and granted when one ends. With both turns taken, sixteen more documents' reservations wait and a seventeenth's is refused. `swarm_publishData` at its size, as a `Uint8Array` and as a string V8 holds in two bytes a character, within its charge. PRQ-2's ticket tests, for both uploads. **Custody read live,** as in PRQ-5, for each auto-approvable method. **A name moving off its IPNS key** during a publish and a message sent under the auto-approve rule, and before a subscription's next message: refused or dropped, nothing published or sent. After it has moved, every name-revalidated class refused with nothing done: `swarm_getUploadStatus` (nothing about the tag), a feed created, updated or written, `swarm_readFeedEntry` by name and `swarm_listFeeds` (no feed records), `swarm_getSigningIdentity` and `swarm_writeSingleOwnerChunk` (no identity, nothing signed), `swarm_getMessagingIdentity`, and no `connect`, `disconnect` or `message` event. The permission-free reads still answer, and `swarm_unsubscribe` runs with no resolution **Grant writes:** the chrome's `swarm:grant-permission`, `swarm:set-auto-approve` and `swarm:grant-messaging` refused, and revoking still accepted. |
| PRQ-8 | `window.radicle` through main, in the Radicle slot or after its switch to the service (0008) | As PRQ-7, for `radicle:provider-execute`: custody and a name moving off its IPNS key for seeding, unseeding and the signed writes, and the replaced-document race for `seedStatus`, `connect` and `disconnect`. After the name has moved, no `connect`, `disconnect` or `seedStatus` reaches the document, and every name-revalidated method refused with nothing done: `radicle_sync` and `radicle_getSeedStatus` (nothing fetched, no `seedStatus`), `radicle_getIdentity`, `radicle_getNodeStatus` (no node id), `radicle_getCapabilities` and `radicle_listSeededRepos`. `radicle_disconnect` runs with no resolution **Grant writes:** the chrome's `radicle:grant-permission`, `radicle:grant-signing` and `radicle:set-auto-approve` refused, and revoking still accepted. |
| PRQ-9 | Cleanup: the `sendToHost` provider channels, the chrome's request code, `guest-main-frame.js`, `navEpoch`, the `origin` parameters | The sender-policy test: no provider channel left, and the chrome refused on `page:hello`, `page:reserve` and `page:request` |
| APS-1 | The approvals document behind a flag. Needs PRQ-5 | Its sender check: another webContents, a sub-frame and a navigated view refused. Navigation and popups refused. With the flag on, the chrome's `page:decide` refused. **Its rendering rules:** the CSP on the document's response, and a markup sink throwing under Trusted Types. **Input,** on a test prompt: a click or a key at 0 ms and at 499 ms does nothing, and at 500 ms counts; the delay starts again for a new prompt, a changed one, and the panel shown again; main refuses an approval sooner than 500 ms; Enter on every control never approves |
| APS-2 | dApp prompts in the approvals document; the chrome shows a badge only | A decision from window A's document refused for window B's handle. PRQ-4's waiting and switching cases with the prompt in the document (a late decision for a hidden prompt refused, and one after it shows again counted only once the delay has started again), and the chrome's badges and count following `page:prompt-pending` and `page:prompt-closed`. `vault.unlock` in the document. **Hostile data,** in every field a page chooses, for every dApp kind: markup (`<script>`, `<img src=x onerror=…>`, `<svg onload=…>`), `javascript:` and `data:` URLs, `</style>` and CSS, bidi controls and over-long text show as literal text, add no element to the template, run nothing and make no request (the partition logs none). A view off its schema shows the error and can only be rejected |
| APS-3 | The wallet's own prompts (sends, Safe, intents, executor fees) in the document; `wallet:confirm-signing` mints only on its decision | The chrome's `wallet:confirm-signing` gets no token without the user's decision in the document, for each of the six wallet kinds (PRQ-5 closed the page kinds). Hostile data as in APS-2, for their views |

- **The flag** goes on by default with APS-2, which moves the dApp prompts into the document. Open question 2 is answered.
- **Rollback:** each step reverts on its own, and reverting it puts its methods back on today's path, with the refusals it added. Until PRQ-9 removes it, the old path is still there for every method.

## Changes from today

- Internal pages lose `window.ethereum`, and opaque URLs get no key ([Keys](#keys)).
- `accountsChanged` and `chainChanged` reach every live document of a key. Today the chain switcher tells only the visible tab (`chain-switcher.js:180`, `dapp-provider.js:822–829`).
- A request sent before the document's hello is refused. The preload sends the hello first, so a page never sees this.
- The preload no longer sends `window.location.origin`.
- A DNS-named ENS site keeps its grants through a binding main checked, not through the chrome's `knownEnsNames`, and main checks the name again for every method and event that uses it ([Which methods check the name](#which-methods-check-the-name)), not only for auto-approve.
- A request over its size, or past main's budgets, is refused with `-32005` or the method's own error. A large Swarm upload waits for its turn, and a document's large uploads go one at a time.
- A background tab's wallet request waits for its tab instead of opening the sidebar, and one that waits past its method's time limit is closed with nothing done. The page-world timers go: main answers every moved request, and a shown prompt waits for the user's decision with no timeout on the page's side. A pending prompt is limited per document, not per window ([Requests and handles](#requests-and-handles)).
- A request holding a value the walk doesn't take (another typed array, a `Map`, a `Date`) is refused as invalid params. No method takes one today.

## Options weighed

- **Keep `sendToHost`, and have main cross-check every request,** as `requesterBelongsTo` does for auto-approve. Smaller, but the chrome still sees every request, names the site and decides. It closes none of the three gaps.
- **Frame-scoped IPC** (`webContents.mainFrame.ipc.handle`) instead of one channel with checks. Sub-frames couldn't call it at all, but the main frame's `WebFrameMain` changes with each cross-process navigation, so main would register a handler on every commit and race the new document's first message. One channel with the checks above is simpler to test.
- **A document token that main pushes into the page,** instead of the preload's nonce. It can arrive after the page's first request, so the preload would have to queue, and it depends on main's message reaching the new document and not the old.
- **A name binding through a URL that carries the name,** instead of `page:bind-name`. The site would get a new origin, so its storage would move, and the handlers a new URL form.
- **Approvals in the chrome, with stronger tokens.** Someone still asks for the token, and that would still be the chrome.
- **A separate approvals window** (the spike's fallback). No layering to get right, but the user can't tell it from a page's popup, and it can open behind the browser.
- **Ending every request when custody changes,** instead of reading custody live. Simple to state, but a user taking a tab back would lose its open prompts too.
- **No copies in main,** instead of charging each one. It can't hold for every form a page sends: a string must become UTF-8, and a library main hands bytes to may copy them (bee-js's fetch did). A charge measured against the real path holds whatever the path does; PRQ-7c removed the copies it could and kept the charge.
- **Refusing a large request while another runs,** instead of tickets. Simpler, but a page fails where it could wait, and an honest preload still sends main the payload it then refuses.

## Open questions

1. **Iframes:** should a frame embedded in a dApp have no wallet (the top page only, as today), or `window.ethereum` under its own address?
   - **Decided (the user, 2026-11-07): the top frame only,** as today, now enforced by main. An embedded frame gets no wallet; a dApp that embeds one relays through `postMessage`.
2. **The trusted panel:** should wallet and approval prompts move into a separate panel that pages and the tab strip can't draw into, which changes how and where they look?
   - **Decided (the user, 2026-11-07): the separate panel,** which main controls, where the prompts appear now: beside the content, below the toolbar. Only approving and rejecting move; managing the wallet stays in the sidebar ([The approvals document](#the-approvals-document)).
3. **Background tabs:** should a background tab's prompt open at once, as today, or wait until you switch to that tab?
   - **Decided (the user, 2026-11-07): it waits,** with a badge on its tab and a count on the wallet button, and its prompt opens when the user switches to that tab ([The approvals document](#the-approvals-document)).
4. **Scripted pages:** a compromised browser UI can still run script inside a page it shows, and that page's existing "always allow" rules then answer without asking you. Should we add a fragile guard now, one that depends on how this Electron version works inside, may miss a way in, and has to be retested on every Electron upgrade? Or accept that existing always-allow rules stay usable by a compromised browser UI until main owns the tabs?
   - **Decided (the user, 2026-11-08): accept the gap for now.** No guard on the guest's script entry points. Tabs as views main owns are noted for later; they are off the critical path ([What stays open](#what-stays-open)).
