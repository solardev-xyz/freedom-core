# 0011: Page requests and the approval surface

**Status:** proposed. Roadmap items 2.3 (page provider calls go straight to main) and 2.8 step 1 (a trusted approval surface). Builds on [0001](0001-freedom-cored.md) (the threat model, and the caller context that reserves `page` for Phase 2) and [0002](0002-signing.md) (signing, its approval tokens, and the signed view of #88). Design 0012 follows: grants, tokens and the EIP-1193 dispatcher in the core (`fc-eip1193`). Nothing here is built yet. The user decides the [open questions](#open-questions).

**The references:**
- **freedom-browser** at `eb59ce7d` (`integration/rust-core`):
  - the page side: `src/main/webview-preload.js` (the providers' bridges, the sub-frame return, the private-window guard);
  - the chrome side, in `src/renderer/lib/`: `dapp-provider.js`, `swarm-provider.js`, `radicle-provider.js`, `guest-main-frame.js`, `tabs.js` (`committedDisplayUrl`), `url-utils.js` (`applyDnsNameIdentity`), `wallet/dapp-connect.js`, `wallet/dapp-prompt-guard.js`, `wallet/chain-switcher.js`;
  - main, in `src/main/`: `swarm/swarm-provider-ipc.js`, `radicle/radicle-provider-ipc.js`, `wallet/wallet-ipc.js` (`requesterBelongsTo`, `dnsNameServesIpnsGuest`, `authorizeSigning`, `wallet:confirm-signing`), `wallet/signing-confirmation.js`, `wallet/agent-tab-custody.js`, `ipc-sender-policy.js`, `webcontents-setup.js`, `private/private-windows.js`, `agent/ipc.js`, and the chrome's `preload.js`;
  - `src/shared/origin-utils.js` (`getPermissionKey`), main's copy of the key rules.
- **The spike** `b58441b1` on `codex/package-webview-runtime` ("compose wallet as shell surface view"): `src/main/trusted-wallet-surface.js` and `src/main/windows/shell-window.js`.
- **Electron's API** as `electron.d.ts` types it, checked in 44.7.0 (integration's `package.json` asks for `^45.2.1`): `IpcMainInvokeEvent.senderFrame`, a `WebFrameMain` or null ("May be `null` if accessed after the frame has either navigated or been destroyed"), and `WebFrameMain`'s `frameTreeNodeId`, `detached`, `parent` and `send`.
- **`fc-protocol`:** `CallerKind::Page` and `PageContext { origin, top_origin, frame, navigation }` (`crates/fc-protocol/src/message.rs`), which no method accepts yet (`methods.rs`, `Callers::allow`).

## Summary

- **Today** a page's `window.ethereum`, `window.swarm` and `window.radicle` requests go page → preload → `sendToHost` → the chrome renderer → main. The chrome decides who asked: it keys the request on its own record of the tab's committed URL, shows the prompt, asks main for the approval token, and names the site to main. Three gaps follow:
  - **The chrome names the site.** `swarm:provider-execute` and `radicle:provider-execute` take `origin`, and how the request was approved, from the chrome (`swarm-provider-ipc.js:12–31`), and `dapp:grant-permission` grants any site it names. A compromised chrome renderer can act as any site.
  - **The chrome mints the approval.** `wallet:confirm-signing` issues an O-7 token for whatever the chrome sends (`wallet-ipc.js:621–643`). The token binds the signature to a request, not to the user's click, so a compromised chrome can sign anything.
  - **One frame, two documents.** `guest-main-frame.js` keeps sub-frames out, but can't tell two documents of the main frame apart (its lines 29–40).
- **The way in:** the preload invokes main directly (`page:request`). The chrome no longer sees page requests.
- **The attested requester:** main derives who asked from the IPC event's `senderFrame`: the guest, its window, the committed URL and its key, private or not, in Agent custody or not. The key rules are today's (`getPermissionKey`), dweb names, ENS over IPNS and onchain `web3://` included.
- **Documents:** main numbers each committed main-frame navigation, and the preload binds a random nonce to its document with its first message. A request from a document that has gone is refused. This closes `guest-main-frame.js`'s gap.
- **Sub-frames:** the top frame only, as today, now enforced by main. [Open question 1](#open-questions) asks about the alternative.
- **Handles:** a prompt is a handle main issued. The chrome presents the handle and returns a decision. It never names a site. Approval tokens bind the handle and the attested key.
- **Events** (`accountsChanged`, `chainChanged`, Swarm messages, Radicle seed status) go from main to the guest's document, never through the chrome.
- **The dispatcher** moves from the chrome into main's JS first. `fc-eip1193` follows in 0012.
- **The approvals document (2.8 step 1):** one per window, a `WebContentsView` above the chrome, with its own preload. Main mints approval tokens only for decisions made there: first for dApp prompts, then for the wallet's own.
- **The threat model:** a compromised chrome renderer or a compromised sub-frame. Main stays trusted (0001).
- **Migration:** nine browser PRs for the requests (PRQ-1 to PRQ-9), then three for the approvals document (APS-1 to APS-3), each with the tests that prove its refusals.

## Goals and non-goals

**Goals**
- **Main decides who asked,** from Chromium's own record of the sending frame, never from a string a renderer sends.
- **No request outlives its document:** no prompt, token, reply or event reaches a document other than the one that asked.
- **The chrome only renders prompts:** it never names a site and never writes a grant, and after APS it never mints an approval.
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
1. The page's provider posts a message to its own window. The preload's bridge forwards it with `ipcRenderer.sendToHost` (`webview-preload.js:1751–1794` for Ethereum, `1914–1947` for Swarm, `2065–2098` for Radicle). The Ethereum bridge also sends `window.location.origin`, which the chrome ignores.
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
- **Agent custody:** no auto-approval for a tab the agent holds (`agent-tab-custody.js`).

**Sub-frames.** Main turns on `nodeIntegrationInSubFrames` for tab webviews, so that iframes get the ad-block scriptlets (`webcontents-setup.js:254`). The preload returns before the providers in a sub-frame (`webview-preload.js:590`), and the chrome drops a sub-frame's provider message. A compromised sub-frame holds `ipcRenderer`, but the sender policy lets a webview call only the channels its preload uses (`ipc-sender-policy.js`), and the provider channels aren't among them.

**Private windows** get no providers. The preload reads the window's status from its boot switch (`webview-preload.js:645–649`). Main checks nothing, since no provider call reaches main from a page.

**What a compromised chrome renderer can do today.** The sender policy lets the chrome call every channel (`ipc-sender-policy.js:20`, `272`). So it can:
- call `swarm:provider-execute` or `radicle:provider-execute` as any site, with `meta.approval: 'user'`: publish, write feeds, send messages, seed and sign Radicle writes, with no prompt;
- grant any site and turn on its auto-approve rules (`dapp:grant-permission`, `swarm:set-auto-approve` and the rest; the chrome's `preload.js:1058–1119`);
- mint a token for any payload and sign it (`wallet:confirm-signing`, then the signing handlers);
- read every page request, answer it, and send events into any guest (`webview.send`);
- run script in any guest it hosts (`webview.executeJavaScript`, which `find-bar.js:342` uses).

## Threat model

The attackers are a compromised chrome renderer (`renderer/index.html`) and a compromised sub-frame of a tab. Main is trusted (0001). The chrome renderer holds the privileged preload and parses what pages control: titles, favicons, URLs and request data. One renderer bug in any of these makes it the attacker.

| The attacker wants to | Today | After PRQ-9 | After APS-3 |
|---|---|---|---|
| Act as a site it doesn't host (chrome) | Yes: it names the site | No: main derives the site from the sending frame | No |
| Approve a real page request without the user (chrome) | Yes | Yes: the chrome still decides | No: only the approvals document decides |
| Sign a payload no page asked for (chrome) | Yes: `wallet:confirm-signing` | Yes, through the wallet's own kinds | No: tokens only on the approvals document's decisions |
| Write or widen a grant (chrome) | Yes | No: main writes grants from decisions | No |
| Make a hosted page ask, and get it approved (chrome) | Yes | Yes | Every prompt reaches the user; standing rules still answer ([What stays open](#what-stays-open)) |
| Ask as the top page (sub-frame) | No: the chrome drops it | No: main refuses it | No |
| Reach the document that replaced the one that asked (either) | Yes: a late message passes `guest-main-frame.js` | No: the document's nonce | No |
| Forge an event into a page (chrome) | Yes | Yes (`webview.send`), with no authority gained | The same |

### What stays open

- **The chrome can still script the pages it hosts.** A `<webview>`'s embedder can run script in its guest, and main then sees a genuine request from that page. After APS, every prompt this causes reaches the user in the approvals document, but a standing rule answers without one: "always allow" signing, a contract rule, a Swarm or Radicle auto-approve. Closing it needs the tabs out of the chrome's hands: a guard on the guest's script entry points that relies on Electron's internals, tabs as views main owns, which the spike's branch plans (`research/shell-compositor-webcontentsview-architecture.md`), or Chromium. [Open question 4](#open-questions).
- **Denial of service.** The chrome can hide tabs, drop badges and refuse to switch to the tab that asks. The approvals panel itself is main's.
- **Spoofing.** The chrome and pages can draw a lookalike prompt in their own areas. After APS a decision there counts for nothing, but a vault password typed into a fake is lost. The panel's fixed place and its input rules ([The approvals document](#the-approvals-document)) are the defence.

## The way in

Three channels between a tab's preload and main replace the provider channels through the chrome: the three requests sent with `sendToHost`, and the responses and events the chrome sends back with `webview.send`.

| Channel | Direction | Payload | Notes |
|---|---|---|---|
| `page:hello` | preload → main (`send`) | `{ nonce }` | Once per document, before the providers are injected ([Documents](#documents)) |
| `page:request` | preload → main (`invoke`) | `{ nonce, provider, method, params }` | `provider` is `ethereum`, `swarm` or `radicle`. Answers `{ result }` or `{ error }` |
| `page:event` | main → preload (`WebFrameMain.send`) | `{ provider, event, data }` | Only to the document the event is for ([Events](#events)) |

- **The preload** keeps the page-facing providers and their `postMessage` protocol, and maps each page request id to its `invoke`. It sends nothing from the page's own `location`. The page's scripts never see the nonce: it lives in the preload's isolated world.
- **The sender policy** (`ipc-sender-policy.js`) gets a tier for `page:hello` and `page:request`: a `webview` sender whose `senderFrame` is its main frame and isn't an internal page. Unlike every other channel, these two refuse the chrome, which has no page to speak for.
- **In flight across a navigation:** main checks the document again before it replies, and sends no reply to a document that has gone. Work already started, such as an upload or a broadcast, finishes, as today.
- **Bounds:** [Bounds](#bounds).

## The attested requester

For every `page:hello` and `page:request`, main builds the requester from the IPC event, in this order, and refuses at the first step that fails:

1. **A tab:** `event.sender` is a live `webview` webContents whose host is a chrome window (`isChromeIndexUrl` of its `hostWebContents`' main frame). Agent automation pages, which run in hidden windows with no preload (`webcontents-setup.js:190–201`), the PDF worker and every other webContents are refused.
2. **Not private:** `isPrivateWebContents(event.sender)` is false (`private-windows.js:103`). Main refuses whatever the preload did, so a private page with a compromised renderer gets nothing either.
3. **Not a preview:** the committed URL isn't `freedom-preview:`.
4. **The top frame:** `event.senderFrame` is not null, not `detached`, and is `event.sender.mainFrame` ([Sub-frames](#sub-frames)).
5. **The current document:** the request's nonce is the one bound to the frame's current document ([Documents](#documents)).
6. **The key,** from the URL main recorded at the document's commit, which must still equal `senderFrame.url`'s key, by `getPermissionKey`'s rules ([Keys](#keys)).

The record main keeps per document:

| Field | From |
|---|---|
| `guest` | `event.sender.id` |
| `window` | the hosting chrome window's id |
| `frame` | `senderFrame.frameTreeNodeId`: global in the browser, fixed for the frame's life, never reused |
| `navigation` | main's document number ([Documents](#documents)) |
| `url` | the committed URL |
| `key` | the permission key, or none |
| `topKey` | the top frame's key: equal to `key` under the top-frame policy |
| `agent` | `isAgentPage(event.sender)` (`agent-tab-custody.js`) |
| `chain` | an onchain app's own chain, or none |

### Keys

Main applies today's rules (`origin-utils.js:75–139`) to the committed URL:

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
- Main holds it for that guest's next main-frame commit. If that commit's URL is `ipns://<key>` with exactly that key, main resolves the name itself, as `dnsNameServesIpnsGuest` does (the resolver's base58 form, or the base36 `libp2p-key` form, compared exactly). If the name answers the key, the document's key is the name. Otherwise it's `ipns://<key>`.
- The binding lasts while the guest's commits stay on that IPNS key: reloads and links within the site keep it.
- Before a site method writes a grant or signs, main resolves the name again, as it does today for auto-approve. A name that no longer answers the key ends the binding, and the request is refused.
- A compromised chrome can only bind a name whose ENS record serves that key: the same content, and the outcome today's check accepts.

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
- **The nonce.** The preload makes 16 random bytes when it runs, as it makes the EIP-6963 uuid today (`webview-preload.js:628`), and sends `page:hello { nonce }` before it injects the providers, so before any page script can run.
- **Binding.** Main binds the first hello it gets for the current number, from the main frame, and ignores every later one.
- **Every request** carries the nonce. Main serves it only when the nonce is the current document's. A late request from the previous document carries the previous nonce and is refused (`navigated`), as is any request before the hello.
- **A page restored from a back/forward cache** keeps its old preload, which then sends a fresh hello with a new nonce on `pageshow` with `persisted`. PRQ-1 checks whether Electron restores pages this way at all.
- **The one assumption:** main sees the commit before the new document's hello. The probe of 2026-09-28 found that the embedder gets `did-frame-navigate` before any message from the new document, one sent at preload time included (`guest-main-frame.js:21–27`). PRQ-1 repeats it in main, in real Electron. If it ever fails, the hello lands on the old number and is ignored, and the new document's requests are refused: the page loses its wallet, and nothing is misattributed.
- **What it doesn't stop:** a compromised renderer can reuse a nonce it holds, but only from its own process: for its own site, as today.
- **It replaces** the chrome's generations per webview, `guest-main-frame.js`, and Swarm's `navEpoch`.

## Sub-frames

**Proposed: the top frame only,** as today, now enforced by main. `senderFrame` must be the guest's main frame (step 4 above), and the sender policy's tier checks the same. The preload still returns before the providers in a sub-frame, and main never sends a `page:event` to one. An iframe inside a dApp, such as a widget or a swap embed, has no wallet. The dApp can talk to it with `postMessage` and make the request itself.

**The alternative ([open question 1](#open-questions)): providers in sub-frames, under their own key.**
- The preload installs the providers in every frame, and main accepts a sub-frame's request, with `key` from the frame's own URL and `topKey` from the top frame's.
- Grants keyed on the frame's own key, so an embed connected once is connected on every site that embeds it; or keyed on the pair, so each embedding site asks again. The pair is safer and asks more often.
- Prompts name both: "swap.example, inside news.example".
- Events go to each frame by its own key, and documents are numbered per frame, not per tab.
- The costs: main tracks every frame's commits, and a page can embed a site the user trusts to make that site's prompts appear.

## Requests and handles

- **Every request** gets a record in main: the requester, the method, the time. Reads complete without the chrome.
- **A prompt is a handle:** 32 random bytes in hex, issued by main and scoped to the window that hosts the guest. The chrome gets the handle and what to show, and answers with the handle and a decision. Nothing the chrome sends names a site, a guest or a payload to sign.
- **One open wallet prompt per window,** as `dapp-prompt-guard.js` keeps today. The next request gets `-32002` ("Another wallet request is already pending"), and the dApp can retry. Swarm and Radicle prompts keep their own rules.
- **A handle closes** when it's decided, when its document goes (a navigation, or the guest destroyed), or when its window closes. A decision on a closed handle is refused, and main tells the chrome the handle closed.
- **No expiry on the prompt:** the user can take their time. The token a decision mints keeps today's two minutes.

## The prompt protocol

**Before APS,** from PRQ-4 on, between main and the chrome:

| Message | Direction | Payload |
|---|---|---|
| `page:prompt` | main → chrome | `{ handle, guest, kind, site, view }` |
| `page:decide` | chrome → main (`invoke`) | `{ handle, approve, choices }`. Answers `{ ok }`, or why not |
| `page:prompt-closed` | main → chrome | `{ handle, reason }`, the reason one of `decided`, `navigated`, `closed`, `cancelled` |

- **`site`** is main's: `{ key, label }`, the key as the address bar shows it. The chrome shows it unchanged.
- **`view`** is what to show, built by main: a transaction's fields and the fee check's verdict, typed data and messages as the core's view (#88), the account and the chain. The chrome renders it. Nothing in it comes from the page unchecked.
- **`kind`:** one per today's prompt. `eth.connect`, `eth.send`, `eth.sign`, `eth.safe_message`; `swarm.connect`, `swarm.publish`, `swarm.feed`, `swarm.messaging`, `swarm.manifest`; `radicle.connect`, `radicle.node`, `radicle.sign`; and `vault.unlock`, when a request needs the vault unlocked.
- **`choices`:** only what the kind lets the user pick. The account for a connect, "always allow" where today's prompt offers it, the fee acknowledgement for a send.
- **`guest`** lets the chrome show which tab asked, and switch to it.

**Approval tokens.** On an approval, main mints the token itself with `signing-confirmation.js`, and the dispatcher spends it. A page request's token never leaves main. Its binding gains two fields, both from main's record, never from a caller:
- **the handle,** so a token answers one prompt;
- **the attested key,** so a token minted for one site's request can't sign another's. A `dapp-send` token binds a site today, but the chrome supplies it (`signing-confirmation.js`, "What a token binds"). Now it is the requester's.

The dispatcher checks the document again before it spends the token. If the document has gone, the token is refused and burnt.

**Device steps** keep today's paths after the decision. A Ledger signs in main. A phone account's job goes to the chrome's openlv session through main's bridge, which accepts answers only from the chrome it sent the job to and checks every signature against the account (`wallet/remote/bridge.js`). Roadmap 2.7 moves the job into the core.

**Grants.** Main writes a grant from an approval, for the requester's key: the connect's account and chain, an "always allow". A contract rule from a confirmed send is recorded today for the site the chrome names in `rememberAutoApprove` (`wallet-ipc.js:409–420`); it is now recorded for the requester's key. Once a provider's prompts have moved (PRQ-4, PRQ-7, PRQ-8), main refuses the chrome's grant writes for it: `dapp:grant-permission`, `dapp:set-signing-auto-approve`, `swarm:grant-permission`, `swarm:set-auto-approve`, `swarm:grant-messaging`, `radicle:grant-permission`, `radicle:grant-signing`, `radicle:set-auto-approve`. Revoking stays open to the chrome, since it narrows.

**After APS** the same messages run between main and the approvals document. The chrome gets only `page:prompt-pending { guest }`, for a badge on the tab, and its `page:decide` is refused.

**Vault unlock.** Today the chrome shows the unlock screen when an auto-approved request finds the vault locked (`dapp-provider.js:332`, `371`). It stays there until APS-2. Then a `vault.unlock` prompt in the approvals document takes the password, and main unlocks.

## Events

Main sends `page:event` with `WebFrameMain.send` on the guest's main frame, and only while that frame's current document is the one the event is for: the same key, and the same number where a subscription is bound to one.

| Provider | Event | When |
|---|---|---|
| ethereum | `accountsChanged` | a grant for the key is written, changed or revoked: to every live document of that key |
| ethereum | `chainChanged` | the chain a document reads changes, through a `wallet_switchEthereumChain` or the user's selection. Never to an onchain app |
| ethereum | `connect`, `disconnect` | as today |
| swarm | `connect`, `disconnect` | a Swarm grant for the key is written or revoked |
| swarm | `message` | a subscription's message, to the document that subscribed. Today's delivery check (`swarm-provider-ipc.js:1911–1930`), keyed on the document |
| radicle | `seedStatus` | to every live document of the key. Today the chrome loops over its webviews (`radicle-provider.js:83–89`) |

- **The selected chain** is chrome state today (`chain-switcher.js:218`). It moves to main, set by the chrome (`wallet:select-chain`, new) and by a page's `wallet_switchEthereumChain`. A compromised chrome can change it. That isn't an approval, and every prompt shows the chain.
- **Subscriptions** are bound to the document. A navigation ends them, as `did-navigate` does today.

## The dispatcher

- **In main's JS first,** in `src/main/page/`: the requester and documents (`page-documents.js`), the channels and handles (`page-requests.js`), the prompts (`page-prompts.js`), and one dispatcher per provider. They move today's chrome logic (`dapp-provider.js`, `swarm-provider.js`, `radicle-provider.js`) into main, method by method. They call main's existing authorities directly: `wallet-ipc.js`'s handlers, `executeSwarmMethod` and `executeRadicleMethod`, with the attested key in place of the chrome's `origin`.
- **The chrome's provider modules** shrink to rendering prompts.
- **The Identity & Wallet switch** (`enableIdentityWallet`) is read in main. When it's off, every request gets `4900`, as today.
- **Agent custody:** main asks the agent service itself (`handleWalletRequest`, reached through the chrome today, `agent/ipc.js:664–684`). No standing rule answers for a tab in custody.
- **Why JS first:** one move at a time, and the JS becomes the reference. 0012's `fc-eip1193` ports the Ethereum dispatcher, with vectors recorded from it.

## The approvals document

Roadmap 2.8 step 1: a surface for approvals that neither the chrome renderer nor a page can drive.

- **One per chrome window,** created with the window: a `WebContentsView` added to the window's `contentView` above the chrome's own view, hidden until it has something to show.
- **Its own document and preload:** `renderer/approvals/approvals.html` and `approvals-preload.js`, both packaged. `sandbox: true`, `contextIsolation`, no Node, no `webviewTag`, no `nodeIntegrationInSubFrames`. Its own in-memory partition, which refuses every request but for its own files. Navigation and popups are refused, as `lockChromeWindow` refuses them for the chrome.
- **Sender checks:** main's `approvals:*` handlers accept only that window's view. `event.sender` is the exact webContents main created, `senderFrame` is its main frame, and the URL is the packaged file. The spike checks the sender the same way (`senderMatchesSurface`).
- **Main mints approval tokens only for it.** From APS-2, a decision on a page's handle counts only when it comes from the window's approvals document. From APS-3, the chrome's `wallet:confirm-signing` no longer mints a token on its own: it opens the request in the approvals document, and the token is returned only when the user approves there.
- **What it shows:** the `view` of [the prompt protocol](#the-prompt-protocol), the site's key, and which tab asked. Nothing the page supplies, such as a title or a favicon, unless marked as the page's.
- **Where:** a panel at the side of the content area, below the toolbar, where the wallet sidebar shows its prompts now. Its exact look is the user's call ([open question 2](#open-questions)). The chrome can't paint over a view stacked above it, and a page paints only inside its own guest.
- **Input:** the panel takes focus when it shows. Its buttons ignore clicks and keys for 500 ms after it appears (proposed), so a page can't time a click onto it, and it has no default button, so Enter never approves.
- **Background tabs:** [open question 3](#open-questions).

**The spike `b58441b1`** built a trusted wallet surface: a right-hand `WebContentsView` drawer in the package chrome's `ShellWindow`, with a detached `BrowserWindow` as the fallback, its own preload, random channel names per surface, and a strict sender check. 0011 keeps the view, the preload and the sender check, and differs in three ways:
- it hosts approvals, not wallet management;
- it runs sandboxed, where the spike set `sandbox: false`;
- it attaches to the window's `contentView` directly, with no detached window. Integration has no `ShellWindow` compositor, and a separate window can't be told apart from a page's popup.

## Bounds

| Bound | Value |
|---|---|
| Requests in flight per document | 64 (proposed). The next gets `-32005` ("limit exceeded", EIP-1474) and doesn't run |
| Open wallet prompts per window | 1, as today. The next request gets `-32002` |
| Hellos per document | 1; later ones are ignored |
| The nonce | 16 random bytes, made by the preload |
| A handle | 32 random bytes, made by main |
| Tokens | today's: two minutes, at most 32 outstanding (`signing-confirmation.js:68`, `72`) |
| The panel's input delay | 500 ms (proposed) |

Per-method bounds stay where they are (`swarm-provider-ipc.js`'s `LIMITS`, and the Radicle provider's).

## Migration

One browser PR per step, against `integration/rust-core`, in this order. A step moves its methods: the preload sends them on `page:request`, and every other method keeps today's path until its own step.

| Step | What | The tests that prove it |
|---|---|---|
| PRQ-1 | The attested requester and documents (`page-documents.js`), not yet used | Unit tests for each refusal: not a tab, private, preview, sub-frame, detached, no hello, wrong nonce, navigated. The key of every row in [Keys](#keys), and the name binding. In real Electron: main sees the commit before the new document's hello, across same-process, cross-process, reload and back/forward navigations |
| PRQ-2 | `page:hello`, `page:request` and `page:event`, the sender-policy tier, handles and delivery, run through a test hook; no method moved | **A sub-frame's request refused.** **A page that navigated away refused:** a request sent, the page navigated, the request finished: no reply and no effect. Private windows and previews refused, the chrome refused on `page:request`, the in-flight bound |
| PRQ-3 | Ethereum reads: `eth_chainId`, `net_version`, `eth_accounts` and the read-only list (`dapp-provider.js:74–100`). The selected chain in main | The same answers as the chrome's, for each method and URL form. An onchain app's chain pinned. A keyless document's reads |
| PRQ-4 | Connecting: `eth_requestAccounts` and `wallet_switchEthereumChain`, with `page:prompt` and `page:decide`. Main writes the grant | **A forged chrome origin refused:** the chrome's `dapp:grant-permission` refused for every site; a `page:decide` names no site and can't move a grant to another; a decision from another window's chrome refused. One open prompt per window (`-32002`) |
| PRQ-5 | Signing: `eth_sendTransaction`, `personal_sign`, `eth_signTypedData_v4`, Safe messages. Tokens bound to the handle and the attested key; auto-approve read by main | A token minted for handle A refused for handle B, for another key, after its document navigated, and when spent twice. No auto-approval for a tab in Agent custody. The signing handlers refuse a dApp request's `autoApprove` authorization from the chrome |
| PRQ-6 | The Ethereum events the chrome still sends: the chain switcher's `chainChanged`, and `accountsChanged` when a grant is revoked or its account changes. A moved method's own events go out from main in its own step | None delivered to a navigated document, another key, a sub-frame or a private window. No `chainChanged` to an onchain app |
| PRQ-7 | `window.swarm` through main: `executeSwarmMethod` takes the attested key, subscriptions are bound to the document, the manifest flow moves | **A forged chrome origin refused:** `swarm:provider-execute` is gone. A message for a navigated document dropped |
| PRQ-8 | `window.radicle` through main, in the Radicle slot or after its switch to the service (0008) | As PRQ-7, for `radicle:provider-execute` |
| PRQ-9 | Cleanup: the `sendToHost` provider channels, the chrome's request code, `guest-main-frame.js`, `navEpoch`, the `origin` parameters | The sender-policy test: no provider channel left, and the chrome refused on `page:hello` and `page:request` |
| APS-1 | The approvals document behind a flag. Needs PRQ-5, and open question 2 answered | Its sender check: another webContents, a sub-frame and a navigated view refused. Navigation and popups refused. With the flag on, the chrome's `page:decide` refused |
| APS-2 | dApp prompts in the approvals document; the chrome shows a badge only | A decision from window A's document refused for window B's handle. `vault.unlock` in the document |
| APS-3 | The wallet's own prompts (sends, Safe, intents, executor fees) in the document; `wallet:confirm-signing` mints only on its decision | The chrome's `wallet:confirm-signing` gets no token without the user's decision in the document, for each of the ten kinds |

- **The flag** goes on by default only once the user has answered open question 2.
- **Rollback:** each step reverts on its own. Until PRQ-9 removes it, the old path still works for every method.

## Changes from today

- Internal pages lose `window.ethereum`, and opaque URLs get no key ([Keys](#keys)).
- `accountsChanged` and `chainChanged` reach every live document of a key. Today the chain switcher tells only the visible tab (`chain-switcher.js:180`, `dapp-provider.js:822–829`).
- A request sent before the document's hello is refused. The preload sends the hello first, so a page never sees this.
- The preload no longer sends `window.location.origin`.
- A DNS-named ENS site keeps its grants through a binding main checked, not through the chrome's `knownEnsNames`.

## Options weighed

- **Keep `sendToHost`, and have main cross-check every request,** as `requesterBelongsTo` does for auto-approve. Smaller, but the chrome still sees every request, names the site and decides. It closes none of the three gaps.
- **Frame-scoped IPC** (`webContents.mainFrame.ipc.handle`) instead of one channel with checks. Sub-frames couldn't call it at all, but the main frame's `WebFrameMain` changes with each cross-process navigation, so main would register a handler on every commit and race the new document's first message. One channel with the checks above is simpler to test.
- **A document token that main pushes into the page,** instead of the preload's nonce. It can arrive after the page's first request, so the preload would have to queue, and it depends on main's message reaching the new document and not the old.
- **A name binding through a URL that carries the name,** instead of `page:bind-name`. The site would get a new origin, so its storage would move, and the handlers a new URL form.
- **Approvals in the chrome, with stronger tokens.** Someone still asks for the token, and that would still be the chrome.
- **A separate approvals window** (the spike's fallback). No layering to get right, but the user can't tell it from a page's popup, and it can open behind the browser.

## Open questions

1. **Iframes:** should a frame embedded in a dApp have no wallet (the top page only, as today), or `window.ethereum` under its own address?
2. **The trusted panel:** should wallet and approval prompts move into a separate panel that pages and the tab strip can't draw into, which changes how and where they look?
3. **Background tabs:** should a background tab's prompt open at once, as today, or wait until you switch to that tab?
4. **Scripted pages:** a compromised browser UI can still run script inside a page it shows, so should we add a guard that relies on Electron's internals, or accept this until tabs leave the browser UI's process?
