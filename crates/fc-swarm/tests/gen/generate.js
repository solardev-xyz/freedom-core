'use strict';

// Known answers for fc-swarm's write side (design 0015, SWM-2), computed by
// @ethersphere/bee-js 13.2.0 and @ethersphere/core-sdk 0.2.2 exactly, never
// by a parallel implementation: the chunk trees by core-sdk's ChunkSplitter,
// the tar bodies by bee-js's collection upload, the feed updates by bee-js's
// feed writer, the SOC bodies by core-sdk's makeSingleOwnerChunk and the GSOC
// signers by bee-js's gsocMine. Uploads go to a recording fake node (global
// fetch), and the clock is fixed for the tar headers.
//
//   node crates/fc-swarm/tests/gen/generate.js <generate|check> --node-modules <dir>
//
// <dir> holds @ethersphere/bee-js and its dependencies, installed without
// scripts (README.md). Both modes refuse any other bee-js or core-sdk
// version. `check` regenerates the answers and fails unless they equal the
// committed file byte for byte.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BEE_JS = '13.2.0';
const CORE_SDK = '0.2.2';
const OUTPUT = path.join(__dirname, '..', 'data', 'write-side.json');
const USAGE = 'Usage: node crates/fc-swarm/tests/gen/generate.js <generate|check> --node-modules <dir>';

// The files each answer rests on, recorded by digest so that a changed
// install fails `check` even at the same version.
const DIGESTED = {
  '@ethersphere/bee-js': [
    'package.json',
    'dist/cjs/utils/tar.js',
    'dist/cjs/utils/tar-writer.js',
    'dist/cjs/utils/tar-uploader.js',
    'dist/cjs/utils/http.js',
    'dist/cjs/api/bzz.js',
    'dist/cjs/api/bytes.js',
    'dist/cjs/api/chunk.js',
    'dist/cjs/api/soc.js',
    'dist/cjs/chunk/soc.js',
    'dist/cjs/feed/index.js',
    'dist/cjs/feed/identifier.js',
    'dist/cjs/modules/messaging.js',
  ],
  '@ethersphere/core-sdk': ['package.json', 'dist/index.cjs'],
  'cafe-utility': ['package.json', 'index.js'],
};

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const b64 = (bytes) => Buffer.from(bytes).toString('base64');

/** content(seed, n): SHA-256(seed ‖ u64_be(i)), concatenated and cut. The
 * same function makes fc-dweb's test content. */
function content(seed, n) {
  const out = Buffer.alloc(n + 32);
  let offset = 0;
  for (let i = 0n; offset < n; i++) {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(i);
    crypto.createHash('sha256').update(seed).update(counter).digest().copy(out, offset);
    offset += 32;
  }
  return new Uint8Array(out.subarray(0, n));
}

/** A case's data: { utf8 } or { seed, length }. */
function dataOf(spec) {
  if (spec.utf8 !== undefined) return new Uint8Array(Buffer.from(spec.utf8, 'utf8'));
  return content(spec.seed, spec.length);
}

/** The directory of the package `name` as Node resolves it from `from`. */
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

function packageVersion(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
}

function loadReference(nodeModules) {
  const beeDir = path.join(path.resolve(nodeModules), '@ethersphere', 'bee-js');
  assert.ok(fs.existsSync(path.join(beeDir, 'package.json')), `no @ethersphere/bee-js under ${nodeModules}`);
  const coreDir = packageDir('@ethersphere/core-sdk', beeDir);
  const cafeDir = packageDir('cafe-utility', beeDir);
  const dirs = { '@ethersphere/bee-js': beeDir, '@ethersphere/core-sdk': coreDir, 'cafe-utility': cafeDir };
  const packages = Object.fromEntries(Object.entries(dirs).map(([name, dir]) => [name, packageVersion(dir)]));
  if (packages['@ethersphere/bee-js'] !== BEE_JS || packages['@ethersphere/core-sdk'] !== CORE_SDK) {
    throw new Error(`The answers are bee-js ${BEE_JS} and core-sdk ${CORE_SDK}'s; ${nodeModules} has bee-js ` +
      `${packages['@ethersphere/bee-js']} and core-sdk ${packages['@ethersphere/core-sdk']}`);
  }
  const files = {};
  for (const [name, list] of Object.entries(DIGESTED)) {
    for (const file of list) files[`${name}/${file}`] = sha256(fs.readFileSync(path.join(dirs[name], file)));
  }
  const beeJs = require(path.join(beeDir, 'dist/cjs/index.js'));
  const core = require(require.resolve('@ethersphere/core-sdk', { paths: [beeDir] }));
  assert.equal(beeJs.ChunkSplitter, core.ChunkSplitter, 'bee-js and this script must load one core-sdk');
  return { beeJs, core, beeDir, packages, files };
}

// ---------------------------------------------------------------------------
// The fake node and the fixed clock
// ---------------------------------------------------------------------------

async function bodyBytes(body) {
  if (body === undefined || body === null) return new Uint8Array(0);
  if (body instanceof Uint8Array) return new Uint8Array(body);
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (typeof body === 'string') return new Uint8Array(Buffer.from(body, 'utf8'));
  if (typeof Blob !== 'undefined' && body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  const parts = [];
  for await (const part of body) parts.push(Buffer.from(part));
  return new Uint8Array(Buffer.concat(parts));
}

/** Runs `fn` with global fetch answering from `answer(request)`; returns
 * fn's result and the requests, in order. */
async function withFakeNode(answer, fn) {
  const realFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(url);
    const request = {
      method: (init.method || 'GET').toUpperCase(),
      path: u.pathname,
      query: Object.fromEntries(u.searchParams.entries()),
      body: await bodyBytes(init.body),
    };
    requests.push(request);
    return answer(request);
  };
  try {
    return { result: await fn(), requests };
  } finally {
    globalThis.fetch = realFetch;
  }
}

const json = (status, value) =>
  new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });

/** Runs `fn` with `new Date()` and `Date.now()` at `ms`. */
async function atTime(ms, fn) {
  const RealDate = globalThis.Date;
  class FixedDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) super(ms);
      else super(...args);
    }
    static now() {
      return ms;
    }
  }
  globalThis.Date = FixedDate;
  try {
    return await fn();
  } finally {
    globalThis.Date = RealDate;
  }
}

const BATCH = 'ba'.repeat(32);
const NODE_URL = 'http://127.0.0.1:1633';

// ---------------------------------------------------------------------------
// Trees: core-sdk's ChunkSplitter
// ---------------------------------------------------------------------------

/** The tree of `data` as ChunkSplitter builds it: the root and every other
 * chunk (onBatch sees every chunk but the root, which bee-js's own
 * streamDirectory relies on). A chunk is `span ‖ payload`, the payload
 * unpadded, as a node stores it. */
async function splitTree(core, data, piece) {
  const chunks = [];
  const splitter = new core.ChunkSplitter(async (batch) => {
    for (const { chunk } of batch) chunks.push(chunk);
    return [];
  });
  for (let offset = 0; offset < data.length; offset += piece) {
    await splitter.append(data.subarray(offset, Math.min(data.length, offset + piece)));
  }
  if (data.length === 0) await splitter.append(data);
  const root = await splitter.finalize();
  const wire = (chunk) => ({
    address: chunk.hash().toUint8Array(),
    span: chunk.span,
    payload: chunk.writer.buffer.subarray(0, chunk.writer.cursor),
  });
  return { root: wire(root), chunks: chunks.map(wire) };
}

/** SHA-256 over every chunk, sorted by address: address ‖ u64_le(span) ‖
 * payload. */
function chunksDigest(chunks) {
  const sorted = [...chunks].sort((a, b) => Buffer.compare(Buffer.from(a.address), Buffer.from(b.address)));
  const h = crypto.createHash('sha256');
  for (const c of sorted) {
    const span = Buffer.alloc(8);
    span.writeBigUInt64LE(c.span);
    h.update(c.address).update(span).update(c.payload);
  }
  return h.digest('hex');
}

const TREE_SIZES = [
  0, 1, 31, 32, 33, 4095, 4096, 4097, 8192, 8193,
  127 * 4096 + 1, 128 * 4096, 128 * 4096 + 1, 129 * 4096, 129 * 4096 + 1,
  256 * 4096 + 1,
  10 * 1024 * 1024, 10 * 1024 * 1024 + 1,
];

async function buildTrees(core) {
  const out = [];
  for (const length of TREE_SIZES) {
    const data = { seed: `tree-${length}`, length };
    // Odd pieces, so ChunkSplitter's appends straddle its leaves.
    const { root, chunks } = await splitTree(core, dataOf(data), 1000);
    out.push({
      id: `tree-${length}`,
      data,
      root: hex(root.address),
      span: Number(root.span),
      payload: hex(root.payload),
      chunks: { count: chunks.length + 1, sha256: chunksDigest([...chunks, root]) },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Bodies: tars through bee-js's collection upload; SOCs through core-sdk
// ---------------------------------------------------------------------------

const MTIME = 1767225600123; // 2026-01-01T00:00:00.123Z
const e60 = 'é'.repeat(60);

const TARS = [
  { id: 'tar-one-file', mtimeMs: MTIME, entries: [{ path: 'index.html', data: { utf8: '<h1>Freedom</h1>\n' } }] },
  {
    id: 'tar-nested',
    mtimeMs: MTIME,
    entries: [
      { path: 'index.html', data: { seed: 'tar-nested/index', length: 700 } },
      { path: 'assets/app.js', data: { seed: 'tar-nested/app', length: 5000 } },
      { path: 'assets/css/site.css', data: { seed: 'tar-nested/css', length: 33 } },
      { path: 'a/b/c/d/e/deep.txt', data: { utf8: 'deep' } },
    ],
  },
  {
    id: 'tar-empty-file',
    mtimeMs: 0,
    entries: [
      { path: 'empty.txt', data: { utf8: '' } },
      { path: 'after.txt', data: { utf8: 'after the empty one' } },
    ],
  },
  {
    id: 'tar-block-sizes',
    mtimeMs: 999,
    entries: [511, 512, 513, 1024].map((n) => ({ path: `f${n}.bin`, data: { seed: `tar-block/${n}`, length: n } })),
  },
  { id: 'tar-name-100', mtimeMs: MTIME, entries: [{ path: `${'n'.repeat(96)}.txt`, data: { utf8: 'a 100-byte name' } }] },
  {
    id: 'tar-name-101-split',
    mtimeMs: MTIME,
    entries: [{ path: `${'d'.repeat(40)}/${'n'.repeat(60)}`, data: { utf8: '101 bytes, split at the slash' } }],
  },
  {
    id: 'tar-prefix-155',
    mtimeMs: MTIME,
    entries: [{ path: `${'p'.repeat(155)}/${'n'.repeat(100)}`, data: { utf8: 'the longest split' } }],
  },
  {
    id: 'tar-rightmost-split',
    mtimeMs: MTIME,
    entries: [{ path: `${'a'.repeat(50)}/${'b'.repeat(50)}/${'c'.repeat(60)}`, data: { utf8: 'rightmost slash' } }],
  },
  {
    id: 'tar-long-name',
    mtimeMs: MTIME,
    entries: [{ path: `${'L'.repeat(120)}.txt`, data: { seed: 'tar-long-name', length: 600 } }],
  },
  {
    id: 'tar-long-path',
    mtimeMs: MTIME,
    entries: [{ path: `${'p'.repeat(156)}/${'q'.repeat(20)}`, data: { utf8: 'prefix past 155' } }],
  },
  {
    id: 'tar-long-path-511',
    mtimeMs: MTIME,
    entries: [{ path: `${'s'.repeat(200)}/${'t'.repeat(200)}/${'u'.repeat(110)}`, data: { utf8: 'a long link of 512 bytes' } }],
  },
  {
    id: 'tar-non-ascii-fits',
    mtimeMs: MTIME,
    entries: [{ path: 'ドキュメント/説明.txt', data: { utf8: 'within 100 bytes' } }],
  },
  {
    id: 'tar-non-ascii-split',
    mtimeMs: MTIME,
    entries: [{ path: `dir-${'é'.repeat(50)}/${'x'.repeat(60)}`, data: { utf8: '115 units: bee-js splits, and both parts fit their bytes' } }],
  },
  {
    id: 'tar-long-link-cut-mid-character',
    mtimeMs: MTIME,
    entries: [{ path: `${'a'.repeat(99)}€€`, data: { utf8: '101 units, a long link; the name stops before the euro' } }],
  },
  {
    id: 'tar-f3-long-non-ascii-name',
    deviation: 'tar-paths',
    mtimeMs: MTIME,
    entries: [{ path: `${e60}.txt`, data: { utf8: '64 units, 124 bytes' } }],
  },
  {
    id: 'tar-f3-nested-non-ascii',
    deviation: 'tar-paths',
    mtimeMs: MTIME,
    entries: [
      { path: 'index.html', data: { utf8: 'first' } },
      { path: `ドキュメント/${'説明書'.repeat(10)}.md`, data: { seed: 'tar-f3-nested', length: 1500 } },
    ],
  },
];

/** The tar bee-js's `bee.collection.upload` sends for `entries`, as
 * publishCollection calls it. */
async function beeTar(beeJs, entries, mtimeMs) {
  const bee = new beeJs.Bee(NODE_URL);
  const collection = entries.map((entry) => {
    const bytes = dataOf(entry.data);
    return { path: entry.path, size: bytes.byteLength, file: new File([bytes], path.posix.basename(entry.path)) };
  });
  const { requests } = await atTime(mtimeMs, () =>
    withFakeNode(() => json(201, { reference: 'ab'.repeat(32) }), () =>
      bee.collection.upload(BATCH, collection, { pin: true, deferred: true })));
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/bzz');
  return requests[0].body;
}

async function buildTars(beeJs) {
  const out = [];
  for (const tar of TARS) {
    const body = await beeTar(beeJs, tar.entries, tar.mtimeMs);
    const entries = tar.entries.map((e) => ({ path: e.path, data: e.data }));
    const record = { id: tar.id, kind: 'tar', mtime_ms: tar.mtimeMs, entries };
    const answer = { length: body.length, sha256: sha256(body), base64: b64(body) };
    if (tar.deviation) {
      // bee-js's bytes, for the record: the core keeps the name (F-3).
      record.deviation = tar.deviation;
      record.reference = answer;
    } else {
      record.body = answer;
    }
    out.push(record);
  }
  return out;
}

// Public test keys: never fund them.
const KEYS = [1, 2, 3].map((n) => hex(crypto.createHash('sha256').update(`fc-swarm write-side test key ${n}`).digest()));

const SOCS = [
  { id: 'soc-1-byte', key: 0, identifier: '00'.repeat(32), data: { utf8: '!' } },
  { id: 'soc-40-bytes', key: 1, identifier: 'ff'.repeat(32), data: { seed: 'soc-40', length: 40 } },
  { id: 'soc-4096-bytes', key: 2, identifier: '0123456789abcdef'.repeat(4), data: { seed: 'soc-4096', length: 4096 } },
  { id: 'soc-wrapped-root', key: 0, identifier: '42'.repeat(32), data: { seed: 'soc-root', length: 64 }, span: '4097' },
  { id: 'soc-wrapped-large-span', key: 1, identifier: '24'.repeat(32), data: { seed: 'soc-root-2', length: 96 }, span: '1048577' },
];

function buildSocs(core) {
  return SOCS.map((c) => {
    const payload = dataOf(c.data);
    const cac = c.span === undefined ? core.makeContentAddressedChunk(payload) : core.makeContentAddressedChunk(payload, BigInt(c.span));
    const soc = cac.toSingleOwnerChunk(c.identifier, KEYS[c.key]);
    const record = { id: c.id, kind: 'soc', key: KEYS[c.key], identifier: c.identifier, data: c.data };
    if (c.span !== undefined) record.span = c.span;
    record.result = {
      span: soc.span.toBigInt().toString(),
      chunk_address: cac.address.toHex(),
      signature: soc.signature.toHex(),
      owner: soc.owner.toHex(),
      address: soc.address.toHex(),
      body: hex(soc.data.toUint8Array ? soc.data.toUint8Array() : soc.data),
    };
    return record;
  });
}

// ---------------------------------------------------------------------------
// Feeds: bee-js's feed writer over the fake node
// ---------------------------------------------------------------------------

const TOPIC_NAMES = ['', 'hello', 'https://example.com/my-feed', 'ünïcødé/日本語/🎉', 't'.repeat(256)];
const INDEXES = ['0', '1', '255', '256', '4294967296', '9007199254740993', '18446744073709551615'];

/** A fake node for feed writes: it stores what it is sent, answers each
 * upload with its reference, and serves a `/bytes` upload's root chunk
 * from `/chunks` as a node stores it (span ‖ references). */
function feedNode(core) {
  const roots = new Map();
  return async (request) => {
    if (request.method === 'POST' && request.path.startsWith('/soc/')) {
      const [, , owner, id] = request.path.split('/');
      return json(201, { reference: core.makeSOCAddress(new core.Identifier(id), new core.EthAddress(owner)).toHex() });
    }
    if (request.method === 'POST' && request.path === '/bytes') {
      const { root } = await splitTree(core, request.body, 4096);
      const span = Buffer.alloc(8);
      span.writeBigUInt64LE(root.span);
      roots.set(hex(root.address), Buffer.concat([span, Buffer.from(root.payload)]));
      return json(201, { reference: hex(root.address) });
    }
    if (request.method === 'GET' && request.path.startsWith('/chunks/')) {
      const chunk = roots.get(request.path.slice('/chunks/'.length));
      if (chunk) return new Response(chunk, { status: 200, headers: { 'content-type': 'application/octet-stream' } });
      return json(404, { code: 404, message: 'Not Found' });
    }
    return json(500, { code: 500, message: `unexpected ${request.method} ${request.path}` });
  };
}

const UPDATES = [
  { id: 'update-reference', form: 'reference', key: 0, topic: 'hello', index: '0', reference: 'cd'.repeat(32), at: 1767225600.75 },
  { id: 'update-reference-at-0', form: 'reference', key: 1, topic: 'https://example.com/my-feed', index: '7', reference: '01'.repeat(32), at: 0 },
  { id: 'update-payload-1', form: 'payload', key: 0, topic: 'hello', index: '1', data: { utf8: 'x' } },
  { id: 'update-payload-utf8', form: 'payload', key: 2, topic: 'ünïcødé/日本語/🎉', index: '2', data: { utf8: 'héllo wörld' }, asString: true },
  { id: 'update-payload-4096', form: 'payload', key: 1, topic: 'hello', index: '3', data: { seed: 'update-4096', length: 4096 } },
  { id: 'update-wrapped-4097', form: 'payload', key: 0, topic: 'hello', index: '4', data: { seed: 'update-4097', length: 4097 } },
  { id: 'update-wrapped-524289', form: 'payload', key: 2, topic: 'big', index: '5', data: { seed: 'update-524289', length: 524289 } },
  { id: 'update-wrapped-1mib', form: 'payload', key: 1, topic: 'big', index: '6', data: { seed: 'update-1mib', length: 1048576 } },
  { id: 'update-payload-empty', form: 'payload', key: 0, topic: 'hello', index: '8', data: { utf8: '' } },
];

async function buildFeedUpdates(beeJs, core) {
  const out = [];
  for (const u of UPDATES) {
    const bee = new beeJs.Bee(NODE_URL);
    const topic = beeJs.Topic.fromString(u.topic);
    const writer = bee.feed.makeWriter(topic, KEYS[u.key]);
    const index = beeJs.FeedIndex.fromBigInt(BigInt(u.index));
    const record = { id: u.id, kind: 'update', form: u.form, key: KEYS[u.key], topic: u.topic, index: u.index };
    let run;
    if (u.form === 'reference') {
      record.reference = u.reference;
      record.at = u.at;
      run = () => writer.upload(BATCH, u.reference, { index, at: u.at });
    } else {
      record.data = u.data;
      const payload = u.asString ? u.data.utf8 : dataOf(u.data);
      run = () => writer.uploadPayload(BATCH, payload, { index });
    }
    let requests;
    try {
      ({ requests } = await withFakeNode(feedNode(core), run));
    } catch (err) {
      record.error = String(err.message);
      out.push(record);
      continue;
    }
    record.requests = requests.map((r) => `${r.method} ${r.path}`);
    const bytes = requests.find((r) => r.method === 'POST' && r.path === '/bytes');
    if (bytes) record.bytes_upload = { length: bytes.body.length, sha256: sha256(bytes.body) };
    const soc = requests.find((r) => r.method === 'POST' && r.path.startsWith('/soc/'));
    const [, , owner, identifier] = soc.path.split('/');
    record.soc = {
      owner,
      identifier,
      sig: soc.query.sig,
      body: hex(soc.body),
      address: core.makeSOCAddress(new core.Identifier(identifier), new core.EthAddress(owner)).toHex(),
    };
    out.push(record);
  }
  return out;
}

function buildFeeds({ beeJs, beeDir }) {
  const identifierModule = require(path.join(beeDir, 'dist/cjs/feed/identifier.js'));
  const topics = TOPIC_NAMES.map((name, i) => ({ id: `topic-${i}`, kind: 'topic', name, topic: beeJs.Topic.fromString(name).toHex() }));
  const identifiers = [];
  for (const [t, name] of [[0, 'hello'], [1, 'ünïcødé/日本語/🎉']]) {
    const topic = beeJs.Topic.fromString(name);
    for (const index of INDEXES) {
      identifiers.push({
        id: `identifier-${t}-${index}`,
        kind: 'identifier',
        topic: topic.toHex(),
        index,
        identifier: identifierModule.makeFeedIdentifier(topic, beeJs.FeedIndex.fromBigInt(BigInt(index))).toHex(),
      });
    }
  }
  return [...topics, ...identifiers];
}

// ---------------------------------------------------------------------------
// GSOC: bee-js's gsocMine
// ---------------------------------------------------------------------------

/** The SOC address of candidate `index`'s key at `identifier`: a target
 * that candidate meets at any proximity. */
function candidateAddress(core, identifier, index) {
  const key = new core.PrivateKey(core.numberToUint256(0xb33n + BigInt(index), 'BE'));
  return core.makeSOCAddress(new core.Identifier(identifier), key.publicKey().address()).toHex();
}

function buildGsoc(beeJs, core) {
  const keccak = (text) => hex(core.keccak256(new TextEncoder().encode(text)));
  const cases = [];
  // Freedom's derivation (design 0015, Messaging): the identifier is
  // keccak256(utf8(topic)), the target keccak256(utf8('freedom-gsoc-v1:' +
  // topic)), mined at proximity 12.
  for (const [name, topic] of [['empty', ''], ['room', 'room'], ['unicode', 'чат/聊天/🎉'], ['256-bytes', 'r'.repeat(256)]]) {
    cases.push({ id: `gsoc-topic-${name}`, topic, target: keccak(`freedom-gsoc-v1:${topic}`), identifier: keccak(topic), proximity: 12 });
  }
  const id = keccak('room');
  const target = keccak('freedom-gsoc-v1:room');
  for (const proximity of [0, 1, 4, 8, 14, 16]) {
    cases.push({ id: `gsoc-proximity-${proximity}`, target, identifier: id, proximity });
  }
  // Higher proximities on another room, whose proximity-12 signer doesn't
  // already meet them.
  for (const proximity of [13, 16]) {
    cases.push({ id: `gsoc-lobby-proximity-${proximity}`, target: keccak('freedom-gsoc-v1:lobby'), identifier: keccak('lobby'), proximity });
  }
  const other = keccak('another identifier');
  cases.push({ id: 'gsoc-exact-1000', target: candidateAddress(core, other, 1000), identifier: other, proximity: 256 });
  cases.push({ id: 'gsoc-near-cap', target: candidateAddress(core, other, 0xfffe), identifier: other, proximity: 24 });
  cases.push({ id: 'gsoc-last-candidate', target: candidateAddress(core, other, 0xfffe), identifier: other, proximity: 256 });
  cases.push({ id: 'gsoc-past-cap', target: candidateAddress(core, other, 0xffff), identifier: other, proximity: 256 });

  const bee = new beeJs.Bee(NODE_URL);
  return cases.map((c) => {
    const record = { ...c };
    try {
      const signer = bee.messaging.gsocMine(c.target, c.identifier, c.proximity);
      const owner = signer.publicKey().address();
      record.result = {
        index: Number(signer.toBigInt() - 0xb33n),
        key: signer.toHex(),
        owner: owner.toHex(),
        address: core.makeSOCAddress(new core.Identifier(c.identifier), owner).toHex(),
      };
    } catch (err) {
      record.error = String(err.message);
    }
    return record;
  });
}

// ---------------------------------------------------------------------------

async function build(reference) {
  const { beeJs, core } = reference;
  const trees = await buildTrees(core);
  const bodies = [...(await buildTars(beeJs)), ...buildSocs(core)];
  const feeds = [...buildFeeds(reference), ...(await buildFeedUpdates(beeJs, core))];
  const gsoc = buildGsoc(beeJs, core);
  return {
    meta: {
      design: '0015, SWM-2',
      generator: 'crates/fc-swarm/tests/gen/generate.js',
      packages: reference.packages,
      files: reference.files,
      content: 'content(seed, n): SHA-256(seed ‖ u64_be(i)) for i = 0, 1, …, concatenated and cut to n bytes',
      keys: 'public test keys: never fund them',
    },
    trees,
    bodies,
    feeds,
    gsoc,
  };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 3 || !['generate', 'check'].includes(args[0]) || args[1] !== '--node-modules') {
    console.error(USAGE);
    process.exit(2);
  }
  const reference = loadReference(args[2]);
  const text = `${JSON.stringify(await build(reference), null, 2)}\n`;
  if (args[0] === 'generate') {
    fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
    fs.writeFileSync(OUTPUT, text);
    console.log(`wrote ${path.relative(process.cwd(), OUTPUT)} (${text.length} bytes)`);
    return;
  }
  const committed = fs.readFileSync(OUTPUT, 'utf8');
  if (committed !== text) {
    const want = JSON.parse(text);
    const have = JSON.parse(committed);
    const differ = [];
    for (const key of Object.keys(want)) {
      if (JSON.stringify(want[key]) === JSON.stringify(have[key])) continue;
      if (!Array.isArray(want[key])) {
        differ.push(key);
        continue;
      }
      const byId = new Map((have[key] || []).map((c) => [c.id, JSON.stringify(c)]));
      for (const c of want[key]) if (byId.get(c.id) !== JSON.stringify(c)) differ.push(`${key}/${c.id}`);
    }
    console.error(`${path.relative(process.cwd(), OUTPUT)} differs from the reference: ${differ.join(', ') || 'formatting'}`);
    process.exit(1);
  }
  console.log(`${path.relative(process.cwd(), OUTPUT)} matches bee-js ${BEE_JS} and core-sdk ${CORE_SDK}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
