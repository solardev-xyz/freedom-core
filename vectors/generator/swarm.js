'use strict';

// vectors/swarm.json and vectors/swarm-grammar.json (design 0015, SWM-1):
// window.swarm's backend as the swarm reference runs it, at bee-js 13.2.0
// and core-sdk 0.2.2 exactly. The browser's own main-process modules run
// whole over a recording fake node (swarm-node.js), loaded fresh for each
// run with Electron and the identity core stubbed (swarm-world.js), each
// method through main's page dispatcher (page/page-swarm.js) with only its
// UI and core boundaries scripted (swarm-run.js); bee-js and core-sdk
// compute every chunk, tree, SOC, tar and GSOC signer. No reference code is
// copied, and nothing the vectors pin is computed here.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { runMethodCase, content } = require('./swarm-run');
const { splitTree } = require('./swarm-node');
const { testKeys } = require('./swarm-world');
const cases = require('./swarm-cases');
const sections = require('./swarm-sections');
const grammar = require('./swarm-grammar');
const { buildGrammar } = require('./swarm-grammar-file');

const BEE_JS = '13.2.0';
const CORE_SDK = '0.2.2';

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function packageDir(name, from) {
  let dir = path.dirname(require.resolve(name, { paths: [from] }));
  for (;;) {
    const manifest = path.join(dir, 'package.json');
    if (fs.existsSync(manifest) && JSON.parse(fs.readFileSync(manifest, 'utf8')).name === name) return dir;
    const up = path.dirname(dir);
    assert.notEqual(up, dir, `no package.json for ${name}`);
    dir = up;
  }
}

/**
 * The checkout's bee-js and core-sdk, refused unless exactly 13.2.0 and
 * 0.2.2, and the versions of the other packages the vectors name.
 */
function loadPackages(checkout) {
  const beeDir = packageDir('@ethersphere/bee-js', checkout);
  const coreDir = packageDir('@ethersphere/core-sdk', beeDir);
  const cafeDir = packageDir('cafe-utility', beeDir);
  const dirs = { '@ethersphere/bee-js': beeDir, '@ethersphere/core-sdk': coreDir, 'cafe-utility': cafeDir };
  const version = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
  const packages = Object.fromEntries(Object.entries(dirs).map(([name, dir]) => [name, version(dir)]));
  if (packages['@ethersphere/bee-js'] !== BEE_JS || packages['@ethersphere/core-sdk'] !== CORE_SDK) {
    throw new Error(`The swarm vectors are bee-js ${BEE_JS} and core-sdk ${CORE_SDK}'s; ${checkout} has bee-js `
      + `${packages['@ethersphere/bee-js']} and core-sdk ${packages['@ethersphere/core-sdk']}`);
  }
  const ref = createRequire(path.join(checkout, 'package.json'));
  for (const name of ['ethers', 'better-sqlite3']) {
    packages[name] = version(packageDir(name, checkout));
  }
  const beeJs = ref('@ethersphere/bee-js');
  const core = ref('@ethersphere/core-sdk');
  assert.equal(beeJs.ChunkSplitter, core.ChunkSplitter, 'bee-js and the generator must load one core-sdk');
  return { beeJs, core, packages };
}

/**
 * Every installed package file the run loaded, by SHA-256: each JavaScript
 * or JSON file under a node_modules directory in Node's require cache, this
 * thread's and the GSOC workers' (`also`), and each such package's
 * package.json. Keyed `<name>@<version>/<path in the package>`, so the key
 * is the same in any install of that version, wherever it lives (CI links
 * the Radicle reference's). A package whose native addon the run loaded
 * (better-sqlite3's prebuild for this platform) has every addon it ships
 * digested, each platform's, so the list is the same on any machine and the
 * addon this one ran is in it. A changed file fails `check` even at the
 * same version, and so does a file the run starts or stops loading.
 */
function loadedPackageFiles(also = []) {
  const out = new Map();
  const add = (key, digest) => {
    assert.ok(!out.has(key) || out.get(key) === digest, `two installs of ${key} differ`);
    out.set(key, digest);
  };
  for (const file of new Set([...Object.keys(require.cache), ...also])) {
    const native = file.endsWith('.node');
    if (!native && !/\.(c|m)?js$|\.json$/.test(file)) continue;
    const parts = file.split(path.sep);
    const at = parts.lastIndexOf('node_modules');
    if (at < 0) continue;
    const root = parts.slice(0, at + (parts[at + 1]?.startsWith('@') ? 3 : 2)).join(path.sep);
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    const key = `${manifest.name}@${manifest.version}`;
    const digest = (each) => add(`${key}/${path.relative(root, each).split(path.sep).join('/')}`, sha256(fs.readFileSync(each)));
    add(`${key}/package.json`, sha256(fs.readFileSync(path.join(root, 'package.json'))));
    if (native) shippedAddons(root).forEach(digest);
    else digest(file);
  }
  return Object.fromEntries([...out].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

/** Every native addon a package ships (each `.node` file in it, outside its own node_modules). */
function shippedAddons(root) {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const at = path.join(dir, entry.name);
      if (entry.isDirectory() && entry.name !== 'node_modules') walk(at);
      else if (entry.isFile() && entry.name.endsWith('.node')) out.push(at);
    }
  };
  walk(root);
  return out;
}

/** The environment every section shares. */
async function environment(checkout, keysJson) {
  const { beeJs, core, packages } = loadPackages(checkout);
  const keys = testKeys(keysJson);
  const keyOf = (name) => {
    if (name === 'bee') return keys.bee;
    const [, index] = name.split(':');
    const key = keys.publishers.get(Number(index));
    assert.ok(key, `no test key ${name}`);
    return key;
  };
  const seeds = new WeakMap();
  const seeded = (seed, n) => {
    const view = new Uint8Array(content(seed, n));
    seeds.set(view, { seed, length: n });
    return view;
  };
  const roots = new Map();
  const env = {
    checkout, beeJs, core, packages, keys, keyOf, seeds, seeded, trees: new Map(), loadedElsewhere: [],
    T0: cases.T0,
    ORIGIN: cases.ORIGIN,
    connected: (origin) => cases.connected(origin),
    cacAddress: (payload) => core.makeContentAddressedChunk(payload).address.toHex(),
    rootAddress: (data) => {
      const root = roots.get(sha256(data));
      assert.ok(root, 'a root the generator did not prepare (swarm.js, ROOTS)');
      return root;
    },
    socOf: (key, identifier, payload, span) => {
      const cac = core.makeContentAddressedChunk(payload, span);
      const soc = cac.toSingleOwnerChunk(new core.Identifier(identifier), keyOf(key).privateKey.slice(2));
      return { address: soc.address.toHex(), chunk: { address: soc.address.toHex(), hex: Buffer.from(soc.data).toString('hex') } };
    },
    feedSoc: (key, topicString, index, payload, span) => {
      const topic = beeJs.Topic.fromString(topicString);
      const id = require('./swarm-run').feedIdentifier(env, topic, index);
      const cac = core.makeContentAddressedChunk(payload, span);
      const soc = cac.toSingleOwnerChunk(id, keyOf(key).privateKey.slice(2));
      return { address: soc.address.toHex(), hex: Buffer.from(soc.data).toString('hex') };
    },
    firstSubscriptionId: crypto.createHash('sha256').update('swarm vectors random 1').digest().subarray(0, 16).toString('hex'),
  };
  // The roots the cases read by reference, from core-sdk's ChunkSplitter.
  const ROOTS = [
    ...[1, 4095, 4096, 4097, 524288, 524289].map((n) => [`read-data/${n}`, n]),
    ['read-data/5mib', 5 * 1024 * 1024], ['read-data/5mib+1', 5 * 1024 * 1024 + 1], ['read-feed/budget', 520000],
  ];
  for (const [seed, n] of ROOTS) {
    const data = content(seed, n);
    roots.set(sha256(data), (await splitTree(core, data)).root.address);
  }
  // A root whose span's top byte is exactly 128: a real size of 2^63.
  {
    const span = 1n << 63n;
    const payload = Buffer.alloc(64, 7);
    const root = core.makeContentAddressedChunk(payload, span);
    const spanBytes = Buffer.alloc(8);
    spanBytes.writeBigUInt64LE(span);
    env.hugeRoot = { address: root.address.toHex(), chunks: [{ address: root.address.toHex(), hex: Buffer.concat([spanBytes, payload]).toString('hex') }] };
  }
  // A signed SOC, as swarm-signer.js hands it to chunk-service.js's upload.
  {
    const identifier = Buffer.from('42'.repeat(32), 'hex');
    const payload = Buffer.from('a signed chunk');
    const cac = core.makeContentAddressedChunk(payload);
    const soc = cac.toSingleOwnerChunk(new core.Identifier(identifier), keys.bee.privateKey.slice(2));
    env.signedSocFixture = {
      owner: keys.bee.address, identifier, signature: '0x' + soc.signature.toHex(), span: cac.span.toBigInt(), payload,
      socAddress: '0x' + soc.address.toHex(),
    };
  }
  return env;
}

async function buildMethods(env) {
  const out = [];
  for (const spec of cases.methodCases(env)) {
    const started = Date.now();
    const record = await runMethodCase(env, spec);
    if (process.env.SWARM_VECTORS_TIMING) console.error(`${Date.now() - started} ms ${spec.id}`);
    const input = inputOf(spec, env);
    if (record.session) input.session = record.session;
    const entry = { id: spec.id, ...(spec.deviation ? { deviation: spec.deviation.id } : {}), ...input, steps: record.steps };
    if (spec.deviation) {
      entry.core = spec.deviation.core;
      if (spec.deviation.also) entry.also = spec.deviation.also;
      if (spec.deviation.before) entry.core_before = spec.deviation.before;
    }
    if (record.websockets) entry.websockets = record.websockets;
    entry.after = record.after;
    out.push(entry);
  }
  return out;
}

/** A case's world, as the vectors write it. */
function inputOf(spec, env) {
  const origin = spec.origin ?? env.ORIGIN;
  const input = { origin };
  input.grants = spec.grants ?? env.connected(origin);
  input.feeds = spec.feeds === undefined || spec.feeds === null ? null
    : (typeof spec.feeds === 'string' ? spec.feeds : JSON.stringify(spec.feeds, null, 2));
  input.vault = spec.vault ?? 'unlocked';
  if (spec.at_execute) input.at_execute = spec.at_execute;
  input.readiness = spec.readiness ?? { ok: true };
  input.custody = spec.custody === true;
  if (spec.prompts) input.prompts = spec.prompts;
  if (spec.keyless) input.keyless = true;
  if (spec.identity_wallet === false) input.identity_wallet = false;
  if (spec.grants_unavailable) input.grants_unavailable = true;
  if (spec.manifest !== undefined) input.manifest = spec.manifest;
  if (spec.nodeStopped) input.node_stopped = true;
  input.node = spec.node ?? {};
  input.clock = spec.clock ?? env.T0;
  return input;
}

async function buildSwarm(checkout, meta, keysJson, dwebVerify) {
  const env = await environment(checkout, keysJson);
  env.nodeBodies = new Map();
  env.dwebVerify = dwebVerify;
  const blogTopic = env.beeJs.Topic.fromString(`${cases.ORIGIN}/blog`).toHex();
  env.feedAddressFor = (feed) => grammar.feedAddress(env, blogTopic, feed.owner, feed.index);
  env.parityOf = (fileId) => {
    const file = dwebVerify.swarm.files.find((f) => f.id === fileId);
    const wire = Buffer.from(dwebVerify.swarm.chunks[file.root], 'base64');
    const inTree = new Set(file.tree);
    for (let at = 8; at + 32 <= wire.length; at += 32) {
      const ref = wire.subarray(at, at + 32).toString('hex');
      if (!inTree.has(ref) && ref !== '00'.repeat(32)) return ref;
    }
    throw new Error(`${fileId}: no parity reference in its root`);
  };
  // A root whose span carries a redundancy level (top byte 0x81): design
  // 0009's 4,097-byte file at level 1 as Bee split it (dweb-verify.json),
  // its two leaves and three parities, the level cleared when its size is
  // read. The node serves the root and the leaves; the walk reads no parity.
  {
    const file = dwebVerify.swarm.files.find((f) => f.id === 'file-4097-rs1');
    const wire = Buffer.from(dwebVerify.swarm.chunks[file.root], 'base64');
    assert.equal(wire[7], 0x81, `${file.id}: its span carries redundancy level 1`);
    const tree = await splitTree(env.core, content(file.seed, file.size));
    const leaves = tree.chunks.filter((c) => c.address !== tree.root.address);
    assert.deepEqual(leaves.map((c) => c.address), [0, 1].map((i) => wire.subarray(8 + 32 * i, 40 + 32 * i).toString('hex')),
      `${file.id}: its first two references are the plain split's leaves`);
    env.levelRoot = {
      address: file.root,
      size: file.size,
      data: { seed: file.seed, length: file.size },
      chunks: [{ address: file.root, hex: wire.toString('hex') }, ...leaves.map((c) => ({ address: c.address, hex: c.wire.toString('hex') }))],
    };
  }
  const timed = async (name, fn) => {
    const started = Date.now();
    const value = await fn();
    if (process.env.SWARM_VECTORS_TIMING) console.error(`section ${name}: ${Date.now() - started} ms`);
    return value;
  };
  // The GSOC searches run in worker threads beside everything else.
  const gsoc = sections.buildGsoc(env);
  const methods = await timed('methods', () => buildMethods(env));
  const swarm = {
    meta: { ...meta, packages: env.packages, files: null, design: '0015, SWM-1' },
    methods,
    bodies: await timed('bodies', () => sections.buildBodies(env)),
    trees: await timed('trees', () => sections.buildTrees(env)),
    stamps: await timed('stamps', () => sections.buildStamps(env)),
    feeds: await timed('feeds', () => sections.buildFeeds(env, methods)),
    gsoc: await timed('gsoc', () => gsoc),
    errors: await timed('errors', () => sections.buildErrors(env, methods)),
    stores: await timed('stores', () => sections.buildStores(env)),
  };
  // The /bytes path of a large feed entry, as `bodies` writes it: the upload's
  // body (the data), ChunkSplitter's root of it, and the SOC that wraps it.
  for (const update of swarm.feeds) {
    if (update.kind !== 'update' || !update.bytes_upload) continue;
    const tree = env.trees.get(update.bytes_upload.sha256);
    swarm.bodies.push({
      id: `bytes-${update.id.replace(/^update-/, '')}`, kind: 'bytes', from: `feeds/${update.id}`, data: update.data,
      bytes_upload: update.bytes_upload,
      root: { address: tree.root.address, span: tree.root.span.toString(), payload: tree.root.payload.toString('hex') },
      soc_body: update.soc.body,
    });
  }
  swarm.deviations = deviationsOf(swarm);
  const ordered = { meta: swarm.meta, formats: SWARM_FORMATS, deviations: swarm.deviations };
  for (const key of ['methods', 'bodies', 'trees', 'stamps', 'feeds', 'gsoc', 'errors', 'stores']) ordered[key] = swarm[key];
  const grammarFile = await timed('grammar', () => buildGrammar(env, methods, env.nodeBodies, dwebVerify,
    { ...meta, packages: env.packages, design: '0015, SWM-1' }));
  // Every package file the run loaded, now that it has loaded them all.
  ordered.meta.files = loadedPackageFiles(env.loadedElsewhere);
  return { swarm: ordered, grammar: grammarFile };
}

// Design 0015's deviations, each with the cases that record it, or why none can.
const NO_CASE = {
  busy: 'no case: the reference has no queue, memory budget, Swarm I/O pool or mining queue to fill; SWM-4\'s and SWM-5\'s tests make it',
  'session-transport': 'no case: which network stack carries a call doesn\'t change what a page sees from a loopback node; SWM-5 checks the proxy and Tor',
  'store-writes': 'no case: the files\' bytes are the same; the durable write (0001, 0013) is the core\'s',
};
const DEVIATION_IDS = ['feed-entry-bound', 'tar-paths', 'feed-wrap-root', 'reference-check', 'read-data-verified', 'read-pieces',
  'index-probe', 'index-allocation', 'stamps-one-read', 'deadlines', 'busy', 'reply-bounds', 'reply-syntax', 'batch-depth', 'error-body-bound', 'session-transport',
  'transport-error-text', 'subscribe-proxy', 'history-bound', 'history-blobs', 'store-shapes', 'store-refusal', 'own-keys', 'legacy-dates',
  'store-writes'];

function deviationsOf(swarm) {
  const where = Object.fromEntries(DEVIATION_IDS.map((id) => [id, []]));
  for (const section of ['methods', 'bodies', 'feeds', 'errors', 'stores']) {
    for (const entry of swarm[section]) {
      for (const id of [entry.deviation, ...(entry.also || [])]) if (id) where[id].push(`${section}/${entry.id}`);
    }
  }
  for (const part of ['mapped', 'select']) {
    for (const entry of swarm.stamps[part]) if (entry.deviation) where[entry.deviation].push(`stamps/${part}/${entry.id}`);
  }
  for (const c of swarm.methods) {
    for (const step of c.steps) for (const r of step.requests) if (r.deviation && !where[r.deviation].includes(`methods/${c.id}`)) where[r.deviation].push(`methods/${c.id}`);
  }
  return Object.fromEntries(DEVIATION_IDS.map((id) => [id, where[id].length ? { cases: where[id] } : { note: NO_CASE[id] }]));
}

const SWARM_FORMATS = {
  reference: 'freedom-browser at meta.freedomBrowserCommit (integration/rust-core, with #1057 and #1062), its main-process modules loaded whole, '
    + 'over meta.packages: bee-js 13.2.0 and core-sdk 0.2.2 exactly. meta.files is every installed package file the run loaded (Node\'s require '
    + 'cache, the GSOC workers\' included: bee-js, core-sdk, cafe-utility, ethers, better-sqlite3\'s JavaScript, isomorphic-ws and the rest) and each '
    + 'such package\'s package.json, keyed <name>@<version>/<path>, by SHA-256; a package whose native addon the run loaded has every addon it '
    + 'ships digested (better-sqlite3\'s prebuilds, each platform\'s), so the list is the same on any machine. Electron, the identity core (core/vault-backend.js), identity-manager.js\'s own lower modules (profile paths, the node '
    + 'identity guard, the Radicle gate, private files), the grant mirror, the service registry, the publish setup service and the vault timer are '
    + 'the world each case scripts (generator/swarm-world.js); identity-manager.js itself is the reference\'s, so its texts (a locked vault\'s, a '
    + 'bad publisher index\'s) are its own.',
  content: 'content(seed, n): SHA-256(seed ‖ u64_be(i)) for i = 0, 1, …, concatenated and cut to n bytes. A data spec is { utf8 }, { hex }, { base64 } '
    + 'or { seed, length }.',
  keys: 'every signature is core-sdk\'s, under keys.json\'s abandon-12 Bee wallet and publisher keys (public test keys: never fund them).',
  clock: 'Date.now() is the case\'s clock (ms) for the whole run, a step\'s own clock from that step on.',
  node_url: 'the node is a recording fake on loopback; every text names it http://127.0.0.1:1633, or a session\'s node_url.',
  typed: 'params and non-JSON answers: { string }, { string_json } (a string with a lone surrogate, as its JSON text), { string_repeat, count }, { number: String(n) } ("-0", "NaN", '
    + '"Infinity"), { bigint }, { boolean }, { null }, { undefined }, { array } ({ hole } for a hole), { object: [[key, value], …] } in key order; '
    + 'where a method reads data, { bytes, kind, base64 } or { string_bytes, base64 } (a string\'s UTF-8), past 64 KiB { …, part: i } with parts[i] '
    + '= { seed | repeat+count, length, sha256 }; { bytes_elsewhere, kind, base64 } for bytes where no method reads them; in answers, '
    + '{ string_digest: units, sha256 } for a string past 8,192 units. An answer is `result` or `error` when JSON keeps it exactly, else '
    + '`result_typed` or `error_typed`; a JSON result past 16 KiB is `result_digest` { json_length, sha256 }.',
  methods: 'a case: its world (origin, the page key; grants, the Swarm grants by key, their autoApprove the site\'s rules; feeds, '
    + 'swarm-feeds.json\'s text before or null; vault, the identity core\'s, which an approved vault.unlock prompt opens; at_execute, the world\'s '
    + 'changes as the dispatcher hands the request to the service, after its checks (vault: locked, the auto-lock firing; custody; rule_off; '
    + 'name: moved; messaging, connection or feed_access: revoked, the user\'s Settings meanwhile); readiness, getPublishReadiness()\'s answer or '
    + '"throws"; custody, whether the agent holds the tab (Agent custody, read live); prompts, the scripted answers in order ({ kind, approve, '
    + 'choices } or { kind, closed }), a prompt with none approved with its default choices (a feed prompt\'s active identity, or its new one '
    + 'where the prompt doesn\'t offer the active one; "always allow" off); keyless, a document with no key; identity_wallet: false, the '
    + 'Identity & Wallet switch off (settings.json); grants_unavailable, the grant mirror unloaded; manifest, a bzz: document\'s '
    + 'freedom-manifest.json, which main\'s manifest check fetches through the bzz: handler (an https: or ens: document\'s check answers legacy, '
    + 'with no fetch); session, a subscribe-proxy case\'s; node, the '
    + 'fake node\'s declarative state; clock) and its steps. A step goes through main\'s page dispatcher (src/main/page/page-swarm.js, '
    + 'createSwarmDispatchers, loaded whole) with page-requests.js\'s context scripted: the requester attested (one guest, window, frame and '
    + 'navigation, so a case\'s steps are one document\'s), its PageContext, the prompts, the name holding unless the world moves it. Only the '
    + 'dispatcher\'s UI and core boundaries are injected: the guest\'s webContents (live, on the default session), Agent custody (the world\'s) '
    + 'and the setup screen; its hand-off to executeSwarmMethod is observed, never changed. Everything else (the grants through swarm-permissions.js, '
    + 'the manifest check, the feed store, the origin lock, the vault\'s state through identity-manager.js, settings) is main\'s own. A step with '
    + 'page: false calls executeSwarmMethod(method, params, origin) directly, with no meta: a method page-requests.js has no row for (it answers '
    + 'those itself, design 0011) and the service\'s own no-page guards. Each step records the answer, every node request (via fetch or http; '
    + 'method, path, query pairs, the headers the caller set, the body as { bytes, base64 } up to 8 KiB else { bytes, sha256 }, the status, feed { '
    + 'owner, index } for a feed update\'s address, and the grammar\'s verdict: form, ready or deviation), and its events in order: the approval '
    + 'path (custody, each read of Agent custody when a rule could answer; prompt { kind, view, answer }; service { key, page, approval }, what the '
    + 'dispatcher handed executeSwarmMethod: the key, a page\'s meta, how main approved a SOC, auto for the site\'s rule or user for its prompt; '
    + 'effect { custody, outcome: ran | refused }, the guard just before the effect, with its custody reads when a rule answered; world, a change '
    + 'the case scripts), the identity core\'s calls (grant, revoke, touch: the grant mirror\'s writes; sign_soc: the request, its PageContext '
    + 'and authorization), readiness (after_requests node requests in), vault_timer_reset, route_to_setup, page_event (connect) and delivered (a '
    + 'subscription\'s message), manifest_fetch. `after`: swarm-feeds.json\'s text, its backups, the publish history (getEntries()), and for a '
    + 'manifest case swarm-manifest-grants.json\'s text. A case marked deviation '
    + 'records the reference\'s outcome, and `core` the design\'s.',
  session: 'subscribe-proxy\'s world (design 0015, question 4): proxy and tor (on or off), node_kind, node_url (the node main\'s service '
    + 'registry names; a remote one\'s calls reach the fake node), node_loopback (main\'s own isLoopbackGatewayUrl over it, as bzz:\'s transport '
    + 'classifies the Ant node) and subscribe_check, main\'s answer to the core\'s subscribe check (shell.swarm_ready), the core\'s input: '
    + '{ ok: false, reason: proxy-or-tor } while a proxy or Tor is on and the node isn\'t on loopback, else { ok: true }. The reference reads '
    + 'none of it and opens the socket either way (`websockets`), which is the deviation; where the check answers ok it is parity.',
  node: 'stamps, addresses, tags, node: JSON answers (stamps_label_bytes: the usable batch with a label of that many bytes of l); data: blobs stored as their whole ChunkSplitter tree and joined from /bytes; chunks: raw bytes '
    + 'at an address; entries: feed updates, SOCs signed under the named test key ({ key, topic (the topic string), index, data, wrap }); latest: '
    + 'GET /feeds/<o>/<t>\'s reply; probes: the feeds whose updates 0 to head exist (a hit answers 105 zero bytes); probeFail: one index\'s status; '
    + 'rules: replies tried first, { match: { method, path | prefix }, reply: { status, statusText, headers, json | body_utf8 | body_hex | '
    + 'body_base64 | body_data, chunked + pieces_data (each piece reaches the reader as one frame, whatever the socket\'s reads), cutAfterPieces, declare (a Content-Length longer than the body, then the connection cut), '
    + 'hangUp, delayMs, abortPage (the page gives up as this request arrives: the request\'s signal aborts) }, world (a change to the case\'s world '
    + 'as the request arrives: custody, rule_off, name) }. Unmatched, the node answers from what it stores: 404 { code, message } for what it lacks, /bzz with SHA-256 of the '
    + 'body as its reference.',
  bodies: 'write-side.json\'s shapes: tar (page-upload.js\'s, for window.swarm, each equal to bee-js\'s collection upload of the same entries; '
    + 'tar-paths cases are bee-js\'s publishCollection, as freedom://publish uses it), file (publishData\'s request; the body is the data), '
    + 'bytes (a large feed entry\'s POST /bytes body, ChunkSplitter\'s root of it and the SOC upload body that wraps that root), soc '
    + '(core-sdk), chunk (POST /chunks: span ‖ payload and the address), pss (the request; the body is the message).',
  trees: 'core-sdk\'s ChunkSplitter: root, span, root payload, and every chunk\'s count and SHA-256 over address ‖ u64_le(span) ‖ payload by address.',
  stamps: 'mapped: bee-js\'s stamp.getAll over one raw batch (the fields Freedom reads, or the error), and swarm-service.js\'s classification; '
    + 'select: selectBestBatch(size, options) over a /stamps answer, its batch or error, and how many /stamps reads it made; where it made '
    + 'two, deviation stamps-one-read, and `core` gives the core\'s one read, with the same batch or error. A mapped batch with a fractional depth '
    + 'or bucketDepth is deviation batch-depth: `core` is the core\'s refusal.',
  feeds: 'topic and identifier (bee-js), update (feed-service.js\'s updateFeed and writeFeedPayload, write-side.json\'s shape), index_run and '
    + 'entry_exists (from the methods that ran them), metered_read (readFeedPayload over a recording meter: each charge and reserve, refused or not).',
  gsoc: 'bee-js\'s gsocMine (write-side.json\'s shape): the signer\'s index, key, owner and SOC address, or its error.',
  errors: 'http_error: a node error at each call site (bee-js\'s JSON and array-buffer calls, #1057\'s fetchNode, the SOC upload, page-upload.js): '
    + 'the error\'s class, message and data, and isChunkNotFoundError (fetchNode at 500, which readFeedPayload reads as an empty feed, and at '
    + '503, which reaches its own text); past 8 KiB, `core` is the same reader over the first 8,192 bytes '
    + '(error-body-bound). mapping: the method cases that show nodeWriteError\'s and mapChunkReadError\'s mappings.',
  stores: 'feeds: feed-store.js\'s operations from a file\'s text, each result or error, and the files after (backups included); manifests: '
    + 'permission-manifests.js\'s check, decide, useIndividual, disconnect and get over scripted manifests, the grants and files after; history: '
    + 'publish-history.js\'s operations (after a first session\'s, `seeded`, with a BLOB cell written into one of its rows where `blob` says), the '
    + 'schema, pragmas and rows (a BLOB cell as { blob: hex }). Local time is UTC (generate.js sets TZ). A case marked deviation records the '
    + 'reference\'s outcome, and `core` the core\'s: index-allocation\'s as text, history-bound\'s row count, and for the others what the case '
    + 'records, each answer in the form the case\'s own take: feeds `ops` (each operation\'s answer) and `files`; manifests `steps`, '
    + '`grants_after` and `files`, or `load: unreadable` (the core reads neither the file nor a .bak copy: no step reads the store, and nothing is '
    + 'written); history `ops` and `rows`, with `refused` { reason: blob, column } for a read the core refuses (history-blobs). Where the core\'s '
    + 'answers are the reference\'s own over another input, that input is: for store-refusal, the operations but the refused one, whose answer '
    + 'is the reference\'s refusal; for store-shapes, the feed store as the core holds it (`core_before`, each feed map rebuilt as '
    + 'sanitizeV2OriginEntry does) or a manifest file that doesn\'t parse, beside the same .bak copy; for legacy-dates, the legacy file with each '
    + 'timestamp the core doesn\'t take removed.',
};

module.exports = { buildSwarm, environment, loadPackages, BEE_JS, CORE_SDK };
