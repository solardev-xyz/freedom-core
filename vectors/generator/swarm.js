'use strict';

// vectors/swarm.json and vectors/swarm-grammar.json (design 0015, SWM-1):
// window.swarm's backend as the swarm reference runs it, at bee-js 13.2.0
// and core-sdk 0.2.2 exactly. The browser's own main-process modules run
// whole over a recording fake node (swarm-node.js), loaded fresh for each
// run with Electron and the identity core stubbed (swarm-world.js); bee-js
// and core-sdk compute every chunk, tree, SOC, tar and GSOC signer. No
// reference code is copied, and nothing the vectors pin is computed here.

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

// The reference files the vectors rest on, recorded by digest, so that a
// changed install fails `check` even at the same version.
const DIGESTED = {
  '@ethersphere/bee-js': [
    'package.json', 'dist/cjs/index.js', 'dist/cjs/bee.js', 'dist/cjs/utils/http.js', 'dist/cjs/utils/headers.js',
    'dist/cjs/utils/error.js', 'dist/cjs/utils/tar.js', 'dist/cjs/utils/tar-writer.js', 'dist/cjs/utils/tar-uploader.js',
    'dist/cjs/utils/stamps.js', 'dist/cjs/utils/workaround.js', 'dist/cjs/api/bzz.js', 'dist/cjs/api/bytes.js',
    'dist/cjs/api/chunk.js', 'dist/cjs/api/soc.js', 'dist/cjs/api/feed.js', 'dist/cjs/api/tag.js', 'dist/cjs/api/stamp.js',
    'dist/cjs/chunk/soc.js', 'dist/cjs/feed/index.js', 'dist/cjs/feed/identifier.js', 'dist/cjs/modules/messaging.js',
    'dist/cjs/types/schema/stamps.js',
  ],
  '@ethersphere/core-sdk': ['package.json', 'dist/index.cjs'],
  'cafe-utility': ['package.json', 'index.js'],
};

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
 * 0.2.2, and the digests of the files the vectors rest on.
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
  const files = {};
  for (const [name, list] of Object.entries(DIGESTED)) {
    for (const file of list) files[`${name}/${file}`] = sha256(fs.readFileSync(path.join(dirs[name], file)));
  }
  const beeJs = ref('@ethersphere/bee-js');
  const core = ref('@ethersphere/core-sdk');
  assert.equal(beeJs.ChunkSplitter, core.ChunkSplitter, 'bee-js and the generator must load one core-sdk');
  return { beeJs, core, packages, files };
}

/** The environment every section shares. */
async function environment(checkout, keysJson) {
  const { beeJs, core, packages, files } = loadPackages(checkout);
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
    checkout, beeJs, core, packages, files, keys, keyOf, seeds, seeded, trees: new Map(),
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
  // A root whose span carries a redundancy level (top byte 0x81): 8,192
  // bytes in two leaves, the level cleared when its size is read.
  {
    const data = content('read-data/level', 8192);
    const tree = await splitTree(core, data);
    const span = 8192n | (0x81n << 56n);
    const root = core.makeContentAddressedChunk(tree.root.payload, span);
    const spanBytes = Buffer.alloc(8);
    spanBytes.writeBigUInt64LE(span);
    env.levelRoot = {
      address: root.address.toHex(),
      data: { seed: 'read-data/level', length: 8192 },
      chunks: [
        { address: root.address.toHex(), hex: Buffer.concat([spanBytes, tree.root.payload]).toString('hex') },
        ...tree.chunks.filter((c) => c.address !== tree.root.address).map((c) => ({ address: c.address, hex: c.wire.toString('hex') })),
      ],
    };
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
  input.readiness = spec.readiness ?? { ok: true };
  input.approval = spec.approval ?? 'user';
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
    meta: { ...meta, packages: env.packages, files: env.files, design: '0015, SWM-1' },
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
  return { swarm: ordered, grammar: grammarFile };
}

// Design 0015's deviations, each with the cases that record it, or why none can.
const NO_CASE = {
  busy: 'no case: the reference has no queue, memory budget, Swarm I/O pool or mining queue to fill; SWM-4\'s and SWM-5\'s tests make it',
  'session-transport': 'no case: which network stack carries a call doesn\'t change what a page sees from a loopback node; SWM-5 checks the proxy and Tor',
  'store-writes': 'no case: the files\' bytes are the same; the durable write (0001, 0013) is the core\'s',
  'pss-recipient': 'gone at this reference: it has #1062 and sends the compressed key itself (the send-pss cases record 66 hex), so the recipient is parity',
};
const DEVIATION_IDS = ['feed-entry-bound', 'tar-paths', 'feed-wrap-root', 'reference-check', 'read-data-verified', 'pss-recipient', 'read-pieces',
  'index-probe', 'index-allocation', 'stamps-one-read', 'deadlines', 'busy', 'reply-bounds', 'error-body-bound', 'session-transport',
  'transport-error-text', 'subscribe-proxy', 'history-bound', 'store-writes'];

function deviationsOf(swarm) {
  const where = Object.fromEntries(DEVIATION_IDS.map((id) => [id, []]));
  for (const section of ['methods', 'bodies', 'feeds', 'errors', 'stores']) {
    for (const entry of swarm[section]) {
      for (const id of [entry.deviation, ...(entry.also || [])]) if (id) where[id].push(`${section}/${entry.id}`);
    }
  }
  for (const c of swarm.methods) {
    for (const step of c.steps) for (const r of step.requests) if (r.deviation && !where[r.deviation].includes(`methods/${c.id}`)) where[r.deviation].push(`methods/${c.id}`);
  }
  return Object.fromEntries(DEVIATION_IDS.map((id) => [id, where[id].length ? { cases: where[id] } : { note: NO_CASE[id] }]));
}

const SWARM_FORMATS = {
  reference: 'freedom-browser at meta.freedomBrowserCommit (integration/rust-core, with #1057 and #1062), its main-process modules loaded whole, over '
    + 'meta.packages: bee-js 13.2.0 and core-sdk 0.2.2 exactly, each file in meta.files checked by SHA-256. Electron, the identity core, the grant '
    + 'mirror, the service registry, the publish setup service and the vault timer are the world each case scripts (generator/swarm-world.js).',
  content: 'content(seed, n): SHA-256(seed ‖ u64_be(i)) for i = 0, 1, …, concatenated and cut to n bytes. A data spec is { utf8 }, { hex }, { base64 } '
    + 'or { seed, length }.',
  keys: 'every signature is core-sdk\'s, under keys.json\'s abandon-12 Bee wallet and publisher keys (public test keys: never fund them).',
  clock: 'Date.now() is the case\'s clock (ms) for the whole run, a step\'s own clock from that step on.',
  node_url: 'the node is a recording fake on loopback; every text names it http://127.0.0.1:1633.',
  typed: 'params and non-JSON answers: { string }, { string_json } (a string with a lone surrogate, as its JSON text), { string_repeat, count }, { number: String(n) } ("-0", "NaN", '
    + '"Infinity"), { bigint }, { boolean }, { null }, { undefined }, { array } ({ hole } for a hole), { object: [[key, value], …] } in key order; '
    + 'where a method reads data, { bytes, kind, base64 } or { string_bytes, base64 } (a string\'s UTF-8), past 64 KiB { …, part: i } with parts[i] '
    + '= { seed | repeat+count, length, sha256 }; { bytes_elsewhere, kind, base64 } for bytes where no method reads them; in answers, '
    + '{ string_digest: units, sha256 } for a string past 8,192 units. An answer is `result` or `error` when JSON keeps it exactly, else '
    + '`result_typed` or `error_typed`; a JSON result past 16 KiB is `result_digest` { json_length, sha256 }.',
  methods: 'a case: its world (origin, the attested key; grants, the Swarm grants by key; feeds, swarm-feeds.json\'s text before or null; vault; '
    + 'readiness, getPublishReadiness()\'s answer or "throws"; approval, how main approved (user or auto, meta.page.soc.approval); node, the fake '
    + 'node\'s declarative state; clock) and its steps, each executeSwarmMethod(method, params, origin, meta.page as main\'s dispatcher builds it): '
    + 'the answer, every node request (via fetch or http; method, path, query pairs, the headers the caller set, the body as { bytes, base64 } up '
    + 'to 8 KiB else { bytes, sha256 }, the status, feed { owner, index } for a feed update\'s address, and the grammar\'s verdict: form, ready or '
    + 'deviation), and the events (sign_soc: the identity core\'s request; readiness, after_requests node requests in; vault_timer_reset; delivered). '
    + '`after`: swarm-feeds.json\'s text, its backups, and the publish history (getEntries()). A case marked deviation records the reference\'s '
    + 'outcome, and `core` the design\'s.',
  node: 'stamps, addresses, tags, node: JSON answers (stamps_label_bytes: the usable batch with a label of that many bytes of l); data: blobs stored as their whole ChunkSplitter tree and joined from /bytes; chunks: raw bytes '
    + 'at an address; entries: feed updates, SOCs signed under the named test key ({ key, topic (the topic string), index, data, wrap }); latest: '
    + 'GET /feeds/<o>/<t>\'s reply; probes: the feeds whose updates 0 to head exist (a hit answers 105 zero bytes); probeFail: one index\'s status; '
    + 'rules: replies tried first, { match: { method, path | prefix }, reply: { status, statusText, headers, json | body_utf8 | body_hex | '
    + 'body_base64 | body_data, chunked + pieces_data, cutAfterPieces, declare (a Content-Length longer than the body, then the connection cut), '
    + 'hangUp, delayMs, abortPage (the page gives up as this request arrives: meta.page.signal aborts) } }. Unmatched, the node answers from what it stores: 404 { code, message } for what it lacks, /bzz with SHA-256 of the '
    + 'body as its reference.',
  bodies: 'write-side.json\'s shapes: tar (page-upload.js\'s, for window.swarm, each equal to bee-js\'s collection upload of the same entries; '
    + 'tar-paths cases are bee-js\'s publishCollection, as freedom://publish uses it), file (publishData\'s request; the body is the data), '
    + 'bytes (a large feed entry\'s POST /bytes body, ChunkSplitter\'s root of it and the SOC upload body that wraps that root), soc '
    + '(core-sdk), chunk (POST /chunks: span ‖ payload and the address), pss (the request; the body is the message).',
  trees: 'core-sdk\'s ChunkSplitter: root, span, root payload, and every chunk\'s count and SHA-256 over address ‖ u64_le(span) ‖ payload by address.',
  stamps: 'mapped: bee-js\'s stamp.getAll over one raw batch (the fields Freedom reads, or the error), and swarm-service.js\'s classification; '
    + 'select: selectBestBatch(size, options) over a /stamps answer, its batch or error, and how many /stamps reads it made.',
  feeds: 'topic and identifier (bee-js), update (feed-service.js\'s updateFeed and writeFeedPayload, write-side.json\'s shape), index_run and '
    + 'entry_exists (from the methods that ran them), metered_read (readFeedPayload over a recording meter: each charge and reserve, refused or not).',
  gsoc: 'bee-js\'s gsocMine (write-side.json\'s shape): the signer\'s index, key, owner and SOC address, or its error.',
  errors: 'http_error: a node error at each call site (bee-js\'s JSON and array-buffer calls, #1057\'s fetchNode, the SOC upload, page-upload.js): '
    + 'the error\'s class, message and data, and isChunkNotFoundError; past 8 KiB, `core` is the same reader over the first 8,192 bytes '
    + '(error-body-bound). mapping: the method cases that show nodeWriteError\'s and mapChunkReadError\'s mappings.',
  stores: 'feeds: feed-store.js\'s operations from a file\'s text, each result or error, and the files after (backups included); manifests: '
    + 'permission-manifests.js\'s check, decide, useIndividual, disconnect and get over scripted manifests, the grants and files after; history: '
    + 'publish-history.js\'s operations, the schema, pragmas and rows.',
};

module.exports = { buildSwarm, environment, loadPackages, BEE_JS, CORE_SDK };
