'use strict';

// Runs one `methods` case of vectors/swarm.json (design 0015, SWM-1): the
// swarm reference's executeSwarmMethod, fresh, over the fake node and the
// case's world, every step recorded.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { FakeNode, fixedDate, splitTree, sha256 } = require('./swarm-node');
const { loadReference, scratchDir } = require('./swarm-world');
const { encode, answer } = require('./swarm-typed');
const { checkStep } = require('./swarm-grammar');

// A request body is written whole up to this length, else as its length and
// SHA-256.
const BODY_INLINE = 8192;

/** content(seed, n): SHA-256(seed ‖ u64_be(i)) for i = 0, 1, …, concatenated and cut. */
const contentCache = new Map();
function content(seed, n) {
  const cached = contentCache.get(seed);
  if (cached && cached.length >= n) return Buffer.from(cached.subarray(0, n));
  const out = Buffer.alloc(n + 32);
  const prefix = Buffer.from(seed, 'utf8');
  const input = Buffer.alloc(prefix.length + 8);
  prefix.copy(input);
  let offset = 0;
  for (let i = 0n; offset < n; i++) {
    input.writeBigUInt64BE(i, prefix.length);
    crypto.hash('sha256', input, 'buffer').copy(out, offset);
    offset += 32;
  }
  const whole = out.subarray(0, n);
  if (n >= 64 * 1024) contentCache.set(seed, whole);
  return Buffer.from(whole);
}

/** A data spec's bytes: `{ utf8 }`, `{ hex }`, `{ base64 }` or `{ seed, length }`. */
function dataOf(spec) {
  if (spec.utf8 !== undefined) return Buffer.from(spec.utf8, 'utf8');
  if (spec.hex !== undefined) return Buffer.from(spec.hex, 'hex');
  if (spec.base64 !== undefined) return Buffer.from(spec.base64, 'base64');
  return Buffer.from(content(spec.seed, spec.length));
}

/** A request body as the vectors write it. */
function bodyRecord(body) {
  if (body.length === 0) return undefined;
  if (body.length <= BODY_INLINE) return { bytes: body.length, base64: body.toString('base64') };
  return { bytes: body.length, sha256: sha256(body) };
}

/**
 * The node's world from a case's declarative `node`:
 * - `stamps`, `addresses`, `tags`, `node`: JSON answers;
 * - `data`: `[{ seed, length } | { utf8 }]`: each stored as its whole chunk
 *   tree (ChunkSplitter's) and served joined from `/bytes/<root>`;
 * - `chunks`: `[{ address, ...spec }]`: raw bytes served at an address;
 * - `entries`: feed updates `[{ key, topic, index, data, wrap? }]`, each a SOC
 *   signed by core-sdk with the test key, `wrap` storing the data's tree and
 *   wrapping its root chunk;
 * - `latest`: `[{ key, topic, reply }]`: GET /feeds' answers;
 * - `rules`: answers tried first.
 */
async function nodeWorld(env, spec = {}, keyOf) {
  const { core } = env;
  const world = {
    // `stamps_label_bytes`: the usable batch, its label that many bytes of `l`.
    stamps: spec.stamps_label_bytes ? { stamps: [require('./swarm-cases').batch({ label: 'l'.repeat(spec.stamps_label_bytes) })] } : spec.stamps,
    addresses: spec.addresses,
    tags: spec.tags,
    node: spec.node,
    chunks: {},
    blobs: {},
    feeds: [],
    feedIndex: {},
    rules: (spec.rules || []).map((rule) => ({ ...rule, reply: replyOf(rule.reply) })),
  };
  const treeOf = async (bytes) => {
    const key = sha256(bytes);
    if (!env.trees.has(key)) env.trees.set(key, await splitTree(core, bytes));
    return env.trees.get(key);
  };
  for (const d of spec.data || []) {
    const bytes = dataOf(d);
    const tree = await treeOf(bytes);
    for (const chunk of tree.chunks) world.chunks[chunk.address] = chunk.wire;
    world.blobs[tree.root.address] = bytes;
  }
  for (const c of spec.chunks || []) world.chunks[c.address] = dataOf(c);
  for (const e of spec.entries || []) {
    const key = keyOf(e.key);
    const topic = env.beeJs.Topic.fromString(e.topic);
    const identifier = feedIdentifier(env, topic, e.index);
    let cac;
    if (e.wrap) {
      const bytes = dataOf(e.data);
      const tree = await treeOf(bytes);
      for (const chunk of tree.chunks) world.chunks[chunk.address] = chunk.wire;
      world.blobs[tree.root.address] = bytes;
      cac = core.makeContentAddressedChunk(tree.root.payload, tree.root.span);
    } else {
      cac = core.makeContentAddressedChunk(dataOf(e.data));
    }
    const soc = cac.toSingleOwnerChunk(identifier, key.privateKey.replace(/^0x/, ''));
    world.chunks[soc.address.toHex()] = Buffer.from(soc.data);
  }
  for (const l of spec.latest || []) {
    const owner = keyOf(l.key).address.slice(2).toLowerCase();
    const topic = env.beeJs.Topic.fromString(l.topic).toHex();
    world.feeds.push({ owner, topic, latest: replyOf(l.reply) });
  }
  for (const p of spec.probes || []) {
    const ownerHex = keyOf(p.key).address.slice(2).toLowerCase();
    const topic = env.beeJs.Topic.fromString(p.topic);
    const table = new Map();
    for (const index of candidateIndexes(p.targets || [])) {
      const id = feedIdentifier(env, topic, index);
      const address = core.makeSOCAddress(id, new core.EthAddress(ownerHex)).toHex();
      world.feedIndex[address] = { owner: ownerHex, index };
      table.set(address, index);
    }
    // A feed whose updates 0 to `head` exist: the probe reads only the
    // status, so a hit answers 105 zero bytes. `probeFail` answers one index
    // with its status.
    if (p.head !== undefined) {
      world.rules.push({
        match: { method: 'GET', prefix: '/chunks/' },
        left: Infinity,
        reply: (request, node) => {
          const index = table.get(request.path.slice('/chunks/'.length));
          if (index === undefined) return node.own(request);
          if (spec.probeFail && spec.probeFail.index === index) {
            return { status: spec.probeFail.status, json: { code: spec.probeFail.status, message: 'read chunk failed' } };
          }
          if (p.head !== null && index <= p.head) return { status: 200, headers: { 'content-type': 'binary/octet-stream' }, body: Buffer.alloc(105) };
          return node.own(request);
        },
      });
    }
  }
  return world;
}

/** The feed identifier keccak256(topic ‖ index as 8 bytes big-endian), by bee-js's own FeedIndex. */
function feedIdentifier(env, topic, index) {
  const feedIndex = env.beeJs.FeedIndex.fromBigInt(BigInt(index));
  return new env.core.Identifier(env.core.keccak256(Buffer.concat([
    Buffer.from(topic.toUint8Array()), Buffer.from(feedIndex.toUint8Array()),
  ])));
}

/**
 * The indexes a feed's probes may ask for: 0 to 300, every power of two to
 * 2^41, and each binary search's points toward the targets: for every j,
 * the target rounded down to a multiple of 2^j, and that plus 2^(j-1). The
 * fake node knows these addresses only to name the index a probe asked for.
 */
function candidateIndexes(targets) {
  const set = new Set();
  for (let i = 0; i <= 300; i++) set.add(i);
  for (let j = 0; j <= 41; j++) set.add(2 ** j);
  for (const t of targets) {
    for (let j = 0; j <= 41; j++) {
      const base = Math.floor(t / 2 ** j) * 2 ** j;
      set.add(base);
      if (j > 0) set.add(base + 2 ** (j - 1));
      set.add(t + 1);
    }
  }
  return [...set].filter((i) => Number.isSafeInteger(i) && i >= 0).sort((a, b) => a - b);
}

/** A scripted reply from its JSON form. */
function replyOf(reply) {
  if (!reply || typeof reply === 'function') return reply;
  const out = { ...reply };
  if (reply.body_utf8 !== undefined) out.body = Buffer.from(reply.body_utf8, 'utf8');
  if (reply.body_hex !== undefined) out.body = Buffer.from(reply.body_hex, 'hex');
  if (reply.body_base64 !== undefined) out.body = Buffer.from(reply.body_base64, 'base64');
  if (reply.body_data !== undefined) out.body = dataOf(reply.body_data);
  if (reply.pieces_hex) out.pieces = reply.pieces_hex.map((p) => Buffer.from(p, 'hex'));
  if (reply.pieces_data) out.pieces = reply.pieces_data.map(dataOf);
  delete out.body_utf8;
  delete out.body_hex;
  delete out.body_base64;
  delete out.body_data;
  delete out.pieces_hex;
  delete out.pieces_data;
  return out;
}

/** Deterministic randomness for subscription ids: 16 bytes from a counter. */
function counterCrypto() {
  let n = 0;
  return {
    ...crypto,
    randomBytes(size) {
      n += 1;
      return crypto.createHash('sha256').update(`swarm vectors random ${n}`).digest().subarray(0, size);
    },
  };
}

// What the page's document is, as page-requests.js attests it: one guest,
// window, frame and navigation for every case, so a case's steps are one
// document's requests.
const GUEST = 1;
const WINDOW = 1;
const FRAME = 1;
const NAVIGATION = 1;

/** The URL a page key's document has (the manifest check reads it). */
function urlOf(key) {
  if (!key) return 'about:blank';
  return /^[a-z][a-z0-9+.-]*:\/\//.test(key) ? `${key}/` : `ens://${key}/`;
}

/**
 * A prompt's answer: the case's next scripted one, else its default. The
 * dispatcher's own `choices` check reads the raw choices, as page-prompts.js
 * does when the chrome decides; a scripted answer it refuses is a bug in the
 * case. An approved vault.unlock opens the identity core's vault, as main's
 * unlock does before it answers the dispatcher.
 */
function answerPrompt(world, events, spec) {
  const { kind, view = {}, choices } = spec;
  const scripted = world.prompts.length ? world.prompts.shift() : null;
  let answer;
  if (scripted) {
    assert.ok(!scripted.kind || scripted.kind === kind, `a scripted ${scripted.kind} answer met a ${kind} prompt`);
    answer = scripted.closed ? { closed: scripted.closed } : { approve: scripted.approve === true, choices: scripted.choices ?? {} };
  } else {
    answer = { approve: true, choices: defaultChoices(kind, view, choices) };
  }
  events.push({ prompt: { kind, view: plainView(view), answer } });
  if (answer.closed) return Promise.resolve({ closed: answer.closed });
  if (!answer.approve) return Promise.resolve({ approve: false, choices: {} });
  const checked = typeof choices === 'function' ? choices(answer.choices) : {};
  assert.ok(checked, `the ${kind} prompt refuses the answer ${JSON.stringify(answer.choices)}`);
  if (kind === 'vault.unlock') world.unlocked = true;
  return Promise.resolve({ approve: true, choices: checked });
}

/**
 * A prompt's default choices: the view's active identity on a feed prompt
 * (its new one where the prompt doesn't offer the active one), "allow" on a
 * manifest consent, and nothing else chosen ("always allow" off).
 */
function defaultChoices(kind, view, choices) {
  if (kind === 'swarm.feed') {
    const active = { identity: view.activeIdentityId };
    return typeof choices === 'function' && choices(active) ? active : { identity: view.newIdentity.id };
  }
  if (kind === 'swarm.manifest') return { outcome: 'allow' };
  return {};
}

const plainView = (view) => JSON.parse(JSON.stringify(view));

/**
 * The context page-requests.js hands a dispatcher, for one step: the
 * attested requester, the prompt (scripted), the PageContext (custody read
 * now), the name and the document's key (holding unless the world says the
 * name moved), events to the document (noted), and the request's signal,
 * which a reply marked abortPage aborts.
 */
function pageContext(world, events, { method, params, key, id }) {
  const controller = new AbortController();
  world.abortPage = () => controller.abort();
  const requester = Object.freeze({ guest: GUEST, window: WINDOW, frame: FRAME, navigation: NAVIGATION, url: urlOf(key), key, topKey: key });
  const state = { after: null };
  const context = Object.freeze({
    id,
    requester,
    provider: 'swarm',
    method,
    params,
    isCurrent: () => true,
    nameHolds: async () => world.nameHolds,
    keylessOnceUnheld: () => {},
    holdsKey: () => world.nameHolds,
    prompt: (spec) => answerPrompt(world, events, spec),
    pageContext: () => ({ origin: key, top_origin: key, frame: FRAME, navigation: NAVIGATION, agent: world.custody }),
    get signal() {
      return controller.signal;
    },
    afterAnswer: (fn) => {
      if (typeof fn === 'function') state.after = fn;
    },
    liveDocuments: () => [requester],
    sendEvent: async (target, event, data) => {
      events.push(event === 'message' ? { delivered: data } : { page_event: { event, data } });
      return { ok: true };
    },
    onDocumentEnded: () => () => {},
    copied: () => {},
  });
  return { context, after: () => state.after };
}

/**
 * Main's page dispatcher (page/page-swarm.js), loaded whole, with only its
 * UI and core boundaries scripted: the guest's webContents (a live guest on
 * the default session), Agent custody (the world's, each read noted) and the
 * setup screen (noted). Its hand-off to the service is observed, not
 * changed: what it hands executeSwarmMethod (the key, a page's meta and how
 * main approved a SOC), the world's changes as the request reaches the
 * service (`at_execute`), and the effect guard's checks and outcome.
 * Everything else is main's own: the grants, the manifest check, the feed
 * store, the origin lock, the vault's state (identity-manager.js), settings.
 */
function dispatchersFor(ref, world, events) {
  const guest = { id: GUEST, isDestroyed: () => false };
  return ref.pageSwarm.createSwarmDispatchers({
    guestContents: (id) => (id === GUEST ? guest : null),
    inCustody: (id) => {
      assert.equal(id, GUEST, 'custody is read for the requesting guest');
      (world.guard ? world.guard.custody : events).push(world.guard ? world.custody : { custody: world.custody });
      return world.custody;
    },
    routeToSetup: (requester, reason) => events.push({ route_to_setup: reason }),
    execute: (method, params, key, meta) => {
      const handed = { key };
      if (meta?.page) {
        handed.page = true;
        if (meta.page.soc) handed.approval = meta.page.soc.approval;
      }
      events.push({ service: handed });
      if (world.atExecute) world.change(world.atExecute);
      if (typeof meta?.page?.effect === 'function') {
        const effect = meta.page.effect;
        meta = { ...meta, page: { ...meta.page, effect: async (run) => {
          const mark = { custody: [] };
          events.push({ effect: mark });
          world.guard = mark;
          let out;
          try {
            out = await effect(() => {
              world.guard = null;
              mark.outcome = 'ran';
              return run();
            });
          } finally {
            world.guard = null;
          }
          if (out?.refused) mark.refused = out.refused;
          if (!mark.custody.length) delete mark.custody;
          return out;
        } } };
      }
      return ref.provider.executeSwarmMethod(method, params, key, meta);
    },
  });
}

/**
 * Runs `fn(ref, node, world)` with the reference loaded fresh over the fake
 * node and the world `spec` scripts (`node`, `feeds`, `manifests`, `grants`,
 * `vault`, `readiness`, `clock`, `nodeStopped`, `origin`, and for the
 * dispatcher `custody`, `prompts`, `at_execute`, `identity_wallet`,
 * `grants_unavailable`, `session`), then tears it all down. The Freedom data
 * directory is read back through `fn`'s `world.dir`.
 */
// The reference's own console lines (swarm-permissions.js and
// permission-manifests.js log there) stay out of the generator's output.
const QUIET = { log() {}, warn() {}, error() {}, info() {} };

async function withReference(env, spec, fn) {
  const dir = scratchDir();
  const consoleWas = { log: console.log, warn: console.warn, error: console.error, info: console.info };
  const clock = { now: spec.clock ?? env.T0 };
  const events = [];
  const node = new FakeNode(env.core, await nodeWorld(env, spec.node, env.keyOf), env.trees);
  const nodeUrl = await node.start();
  const feedsBefore = spec.feeds === undefined || spec.feeds === null ? null
    : (typeof spec.feeds === 'string' ? spec.feeds : JSON.stringify(spec.feeds, null, 2));
  if (feedsBefore !== null) fs.writeFileSync(path.join(dir, 'swarm-feeds.json'), feedsBefore);
  if (spec.manifests !== undefined && spec.manifests !== null) fs.writeFileSync(path.join(dir, 'swarm-manifest-grants.json'), spec.manifests);
  for (const [name, text] of Object.entries(spec.files || {})) fs.writeFileSync(path.join(dir, name), text);
  // Settings: the Identity & Wallet switch, which every window.swarm method
  // reads first (settings-store.js, main's own).
  if (!Object.hasOwn(spec.files || {}, 'settings.json')) {
    fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({ enableIdentityWallet: spec.identity_wallet !== false }));
  }
  // A node elsewhere than loopback (subscribe-proxy): main's service
  // registry names it, and the harness carries its calls to the fake node.
  if (spec.session?.node_url) node.alias = { from: new URL(spec.session.node_url).origin, to: nodeUrl };
  const world = {
    nodeUrl: spec.nodeStopped ? null : (spec.session?.node_url ?? nodeUrl),
    custody: spec.custody === true,
    prompts: [...(spec.prompts || [])],
    atExecute: spec.at_execute,
    grantsLoaded: spec.grants_unavailable !== true,
    nameHolds: true,
    guard: null,
    manifest: spec.manifest,
    readiness: spec.readiness ?? { ok: true },
    unlocked: spec.vault !== 'locked',
    grants: structuredClone(spec.grants ?? env.connected(spec.origin ?? env.ORIGIN)),
    keys: env.keys,
    core: env.core,
    dir,
    clock,
    events,
    crypto: counterCrypto(),
  };
  world.requestCount = () => node.requests.length;
  // A reply marked abortPage aborts the page's request (pageContext). The
  // world changes (Agent custody taken; the site's rule, its messaging grant,
  // its connection or its feed access gone; the name moved; the vault
  // locked) as a node rule's request arrives (its `world`), or as the
  // dispatcher hands the request to the service (`at_execute`).
  node.abortPage = () => world.abortPage?.();
  world.change = (change) => {
    const key = spec.origin ?? env.ORIGIN;
    for (const [what, value] of Object.entries(change)) {
      if (what === 'custody') world.custody = value === true;
      else if (what === 'vault') world.unlocked = value !== 'locked';
      else if (what === 'name') world.nameHolds = value !== 'moved';
      else if (what === 'rule_off') {
        world.grants[key] = { ...world.grants[key], autoApprove: { ...world.grants[key].autoApprove, [value]: false } };
      } else if (what === 'messaging' && value === 'revoked') world.grants[key] = { ...world.grants[key], messaging: false };
      else if (what === 'connection' && value === 'revoked') delete world.grants[key];
      // Main's own feed store, as Settings revokes a site's feed access.
      else if (what === 'feed_access' && value === 'revoked') world.ref.feedStore.revokeFeedAccess(key, { source: 'user' });
      else throw new Error(`no world change ${what}`);
      world.events.push({ world: { [what]: value } });
    }
  };
  node.onWorld = world.change;
  const { RealDate, FixedDate } = fixedDate(clock);
  const undo = node.install();
  globalThis.Date = FixedDate;
  Object.assign(console, QUIET);
  let ref;
  try {
    ref = loadReference(env.checkout, world);
    world.ref = ref;
    return await fn(ref, node, world);
  } finally {
    try {
      ref?.history.closeDb();
      ref?.registry._reset?.();
      ref?.miner.resetForTest?.();
    } finally {
      ref?.restore();
      undo();
      globalThis.Date = RealDate;
      Object.assign(console, consoleWas);
      await node.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
}

/**
 * Runs `spec` and returns its record. `spec.steps` (or one step at the top
 * level): `{ method, params, origin?, page?, clock? }`, `params` a function
 * giving the live value. The world is withReference's.
 */
async function runMethodCase(env, spec) {
  const steps = spec.steps || [{ method: spec.method, params: spec.params, origin: spec.origin }];
  return withReference(env, spec, async (ref, node, world) => {
    const { events, clock, dir } = world;
    ref.provider.registerSwarmProviderIpc();
    const dispatchers = dispatchersFor(ref, world, events);
    const record = { id: spec.id };
    if (spec.session) record.session = sessionOf(ref, node, world, spec.session);
    const out = [];
    for (const [k, step] of steps.entries()) {
      const params = typeof step.params === 'function' ? step.params() : step.params;
      const origin = step.origin ?? spec.origin ?? env.ORIGIN;
      // The feed owner main can't bind (the store's), for the grammar check.
      const feedName = params && typeof params === 'object' ? (params.name ?? params.feedId) : undefined;
      let feedOwner = null;
      try {
        feedOwner = typeof feedName === 'string' ? ref.feedStore.getFeed(origin, feedName)?.owner ?? null : null;
      } catch {
        feedOwner = null;
      }
      const parts = [];
      const typed = encode(params, { dataAt: dataPositions(step.method), parts, seeds: env.seeds });
      const before = node.requests.length;
      const eventsBefore = events.length;
      if (step.clock !== undefined) clock.now = step.clock;
      // A page's request goes through main's dispatcher; a method it has no
      // dispatcher for (page-requests.js refuses those first) and a step
      // marked `page: false` call executeSwarmMethod directly, with no meta.
      const dispatch = typeof step.method === 'string' && step.page !== false ? dispatchers[`swarm:${step.method}`] : undefined;
      let value;
      if (dispatch) {
        const key = spec.keyless ? null : origin;
        const { context, after } = pageContext(world, events, { method: step.method, params, key, id: k + 1 });
        value = await dispatch(context);
        // What the dispatcher queued for once the answer is out (connect).
        if (after()) await after()();
      } else {
        value = await ref.provider.executeSwarmMethod(step.method, params, origin);
      }
      if (world.fatal) throw world.fatal;
      const entry = typeof step.method === 'string' ? { method: step.method } : { method_typed: encode(step.method) };
      if (step.origin && step.origin !== (spec.origin ?? env.ORIGIN)) entry.origin = step.origin;
      if (!dispatch) entry.page = false;
      if (step.clock !== undefined) entry.clock = step.clock;
      entry.params = typed;
      if (parts.length) entry.parts = parts;
      Object.assign(entry, outcomeOf(value, node));
      const raw = node.requests.slice(before);
      const seen = raw.map((r) => ({ ...r, status: r.reply?.status ?? null,
        feed: r.method === 'GET' && r.path.startsWith('/chunks/') ? node.feedIndex.get(r.path.slice(8)) : undefined }));
      const classes = checkStep({ env, caseId: spec.id, step: k, method: step.method, params, origin, feedOwner,
        events: events.slice(eventsBefore), requestsBefore: before }, seen);
      entry.requests = raw.map((r, j) => ({ ...requestRecord(r, node), ...classes[j] }));
      // The replies the grammar's scenarios carry: chunks, and feed lookups' headers.
      raw.forEach((r, j) => {
        if (r.method !== 'GET') return;
        if (r.path.startsWith('/chunks/') && r.replyBody) env.nodeBodies?.set(`${spec.id}/${k}/${j}`, r.replyBody);
        if (r.path.startsWith('/feeds/') && r.replyHeaders) env.nodeBodies?.set(`${spec.id}/${k}/${j}/headers`, r.replyHeaders);
      });
      const stepEvents = events.slice(eventsBefore).map((e) => eventRecord(e));
      if (stepEvents.length) entry.events = stepEvents;
      out.push(entry);
    }
    record.steps = out;
    record.websockets = node.websockets.length ? node.websockets : undefined;
    const feedsPath = path.join(dir, 'swarm-feeds.json');
    record.after = {
      feeds: fs.existsSync(feedsPath) ? fs.readFileSync(feedsPath, 'utf8') : null,
      history: ref.history.getEntries(),
    };
    const backups = fs.readdirSync(dir).filter((name) => name.startsWith('swarm-feeds.') && name !== 'swarm-feeds.json');
    if (backups.length) record.after.feeds_backups = backups.sort();
    // A manifest the check found: the manifest store main wrote.
    const manifestsPath = path.join(dir, 'swarm-manifest-grants.json');
    if (spec.manifest !== undefined && fs.existsSync(manifestsPath)) record.after.manifests = fs.readFileSync(manifestsPath, 'utf8');
    return record;
  });
}

/**
 * The session a subscribe-proxy case states (design 0015, question 4): a
 * proxy or Tor on, the node's kind and URL, the URL classified by main's
 * own test (isLoopbackGatewayUrl), and main's answer to the core's
 * subscribe check by question 4's rule: refused while a proxy or Tor is on
 * and the node isn't on loopback. The reference reads none of it.
 */
function sessionOf(ref, node, world, session) {
  const loopback = ref.load('../ipfs/gateway-transport.js').isLoopbackGatewayUrl(world.nodeUrl);
  const refused = (session.proxy === true || session.tor === true) && !loopback;
  return {
    proxy: session.proxy === true,
    tor: session.tor === true,
    node_kind: session.node_kind,
    node_url: node.normalize(world.nodeUrl),
    node_loopback: loopback,
    subscribe_check: refused ? { ok: false, reason: 'proxy-or-tor' } : { ok: true },
  };
}

/** Which params positions a method reads as data (design 0015, Main's encoding). */
function dataPositions(method) {
  const data = new Set(['swarm_publishData', 'swarm_publishChunk', 'swarm_writeSingleOwnerChunk', 'swarm_writeFeedEntry',
    'swarm_sendPss', 'swarm_sendGsoc']);
  return (p) => {
    if (data.has(method) && p.length === 1 && p[0] === 'data') return 'data';
    if (method === 'swarm_publishFiles' && p.length === 3 && p[0] === 'files' && p[2] === 'bytes') return 'bytes';
    return false;
  };
}

function outcomeOf(value, node) {
  assert.ok(value && typeof value === 'object', 'executeSwarmMethod answers an object');
  const keys = Object.keys(value);
  if ('error' in value) {
    const error = { ...value.error };
    if (typeof error.message === 'string') error.message = node.normalize(error.message);
    return answer('error', error);
  }
  assert.deepEqual(keys, ['result'], `an answer is { result } or { error }: ${keys}`);
  // A large JSON result (listFeeds' list) is written as its JSON text's length and digest.
  const plain = answer('result', value.result);
  const text = plain.result !== undefined ? JSON.stringify(value.result) : undefined;
  if (text !== undefined && text.length > 16384) {
    return { result_digest: { json_length: text.length, sha256: sha256(Buffer.from(text, 'utf8')) } };
  }
  return plain;
}

function requestRecord(r, node) {
  const out = { via: r.via, method: r.method, path: r.path };
  if (r.query.length) out.query = r.query;
  if (r.headers.length) out.headers = r.headers;
  const body = bodyRecord(r.body);
  if (body) out.body = body;
  out.status = r.reply?.status ?? null;
  const feed = r.method === 'GET' && r.path.startsWith('/chunks/') ? node.feedIndex.get(r.path.slice(8)) : undefined;
  if (feed) out.feed = feed;
  return out;
}

function eventRecord(e) {
  if (e.sign_soc) {
    const s = e.sign_soc;
    const payload = Buffer.from(s.payload, 'hex');
    return {
      sign_soc: {
        key: s.key,
        identifier: s.identifier,
        payload: payload.length <= BODY_INLINE ? { bytes: payload.length, hex: s.payload } : { bytes: payload.length, sha256: sha256(payload) },
        ...(s.span !== undefined ? { span: s.span } : {}),
        ...(s.authorization ? { authorization: s.authorization } : {}),
        page: s.page,
      },
    };
  }
  if (e.delivered) return { delivered: encode(e.delivered) };
  return e;
}

module.exports = { runMethodCase, withReference, requestRecord, eventRecord, outcomeOf, content, dataOf, bodyRecord, nodeWorld, replyOf, feedIdentifier, candidateIndexes, urlOf };
