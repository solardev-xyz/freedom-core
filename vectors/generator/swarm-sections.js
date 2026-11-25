'use strict';

// vectors/swarm.json's sections beside `methods` (design 0015, SWM-1):
// `trees`, `bodies`, `feeds`, `gsoc`, `stamps`, `errors` and `stores`. Each
// records what the swarm reference, or the bee-js 13.2.0 and core-sdk 0.2.2
// it installs, answers; `trees`, `bodies`, `feeds` and `gsoc` keep the record
// shapes of crates/fc-swarm/tests/data/write-side.json, so fc-swarm replays
// them the same way.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { withReference, content, dataOf, requestRecord, outcomeOf } = require('./swarm-run');
const { splitTree, sha256, hex } = require('./swarm-node');
const { encode, answer } = require('./swarm-typed');
const C = require('./swarm-cases');

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const MiB = 1024 * 1024;

/** An error as the vectors write it: its class, message and the properties the reference reads. */
function errorRecord(err, node) {
  const message = node ? node.normalize(String(err?.message)) : String(err?.message);
  // A message past 8,192 units (an error body's text) is written as its digest.
  const out = { name: err?.name ?? null, ...(message.length > 8192
    ? { message_digest: { units: message.length, sha256: sha256(Buffer.from(message, 'utf8')) } } : { message }) };
  for (const key of ['status', 'statusText', 'code', 'reason', 'limit', 'actual']) {
    if (err && err[key] !== undefined) out[key] = typeof err[key] === 'bigint' ? `${err[key]}n` : err[key];
  }
  if (err && 'responseBody' in err) Object.assign(out, answer('responseBody', err.responseBody));
  if (err?.refusal) Object.assign(out, answer('refusal', err.refusal));
  if (err?.capacity) out.capacity = err.capacity;
  return out;
}

// ---------------------------------------------------------------------------
// trees: core-sdk's ChunkSplitter, as write-side.json records them.

const TREE_SIZES = [0, 1, 4095, 4096, 4097, 524288, 524289, 10 * MiB];

function chunksDigest(chunks) {
  const sorted = [...chunks].sort((a, b) => Buffer.compare(Buffer.from(a.address, 'hex'), Buffer.from(b.address, 'hex')));
  const h = crypto.createHash('sha256');
  for (const c of sorted) {
    const span = Buffer.alloc(8);
    span.writeBigUInt64LE(c.span);
    h.update(Buffer.from(c.address, 'hex')).update(span).update(c.payload);
  }
  return h.digest('hex');
}

async function buildTrees(env) {
  const out = [];
  for (const length of TREE_SIZES) {
    // The 10 MiB tree's data is the feed write's (write-feed/10mib), split once.
    const data = { seed: length === 10 * MiB ? 'write-feed/10mib' : `swarm-tree-${length}`, length };
    const bytes = dataOf(data);
    const key = sha256(bytes);
    if (!env.trees.has(key)) env.trees.set(key, await splitTree(env.core, bytes));
    const tree = env.trees.get(key);
    out.push({
      id: `tree-${length}`,
      data,
      root: tree.root.address,
      span: Number(tree.root.span),
      payload: tree.root.payload.toString('hex'),
      chunks: { count: tree.chunks.length, sha256: chunksDigest(tree.chunks) },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// bodies.

const MTIME = C.T0;
// window.swarm's path forms (paths of at most 100 UTF-8 bytes, `/`-separated).
const TARS = [
  { id: 'tar-one-file', entries: [{ path: 'index.html', data: { utf8: '<h1>Freedom</h1>\n' } }] },
  { id: 'tar-nested', entries: [
    { path: 'index.html', data: { seed: 'swarm-tar/index', length: 700 } },
    { path: 'assets/app.js', data: { seed: 'swarm-tar/app', length: 5000 } },
    { path: 'assets/css/site.css', data: { seed: 'swarm-tar/css', length: 33 } },
    { path: 'a/b/c/d/e/deep.txt', data: { utf8: 'deep' } },
  ] },
  { id: 'tar-empty-file', entries: [{ path: 'empty.txt', data: { utf8: '' } }, { path: 'after.txt', data: { utf8: 'after the empty one' } }] },
  { id: 'tar-block-sizes', entries: [511, 512, 513, 1024].map((n) => ({ path: `f${n}.bin`, data: { seed: `swarm-tar/block/${n}`, length: n } })) },
  { id: 'tar-name-100-ascii', entries: [{ path: `${'n'.repeat(96)}.txt`, data: { utf8: 'a 100-byte name' } }] },
  { id: 'tar-path-100-nested', entries: [{ path: `${'d'.repeat(40)}/${'n'.repeat(59)}`, data: { utf8: '100 bytes with a slash' } }] },
  { id: 'tar-name-100-bytes-non-ascii', entries: [{ path: `${'é'.repeat(48)}abcd`, data: { utf8: '52 units, 100 bytes' } }] },
  { id: 'tar-non-ascii-dirs', entries: [{ path: 'ドキュメント/説明.txt', data: { utf8: 'within 100 bytes' } }] },
  { id: 'tar-page-order', entries: [
    { path: 'z.txt', data: { utf8: 'last by name, first by order' } },
    { path: 'a.txt', data: { utf8: 'second' } },
    { path: 'm/index.html', data: { utf8: 'third' } },
  ] },
  { id: 'tar-mtime-zero', mtimeMs: 0, entries: [{ path: 'epoch.txt', data: { utf8: 'mtime 0' } }] },
];

async function buildBodies(env) {
  const out = [];
  // Tars: page-upload.js's, for window.swarm's publishFiles, taken by the
  // fake node, each checked against bee-js's own collection upload of the
  // same entries, so fc-swarm's tar (bee-js's) is held to window.swarm's.
  for (const tar of TARS) {
    const mtimeMs = tar.mtimeMs ?? MTIME;
    const files = tar.entries.map((e) => ({ path: e.path, bytes: dataOf(e.data) }));
    const body = await withReference(env, { clock: mtimeMs }, async (ref, node, world) => {
      const pageUpload = ref.load('./page-upload.js');
      await pageUpload.uploadCollection(world.nodeUrl, C.BATCH_A, files, {});
      const beeBody = await beeCollectionBody(env, world.nodeUrl, node, files);
      const pageBody = node.requests[0].body;
      assert.ok(Buffer.compare(pageBody, beeBody) === 0, `${tar.id}: page-upload's tar differs from bee-js's`);
      return pageBody;
    });
    out.push({ id: tar.id, kind: 'tar', mtime_ms: mtimeMs, entries: tar.entries, body: { length: body.length, sha256: sha256(body), base64: b64(body) } });
  }
  // F-3 (tar-paths): a freedom://publish collection (publishCollection,
  // bee-js's tar writer) with a name of at most 100 UTF-16 units and more than
  // 100 UTF-8 bytes, which bee-js cuts; the core counts bytes and keeps it.
  for (const tar of [
    { id: 'tar-f3-long-non-ascii-name', entries: [{ path: `${'é'.repeat(60)}.txt`, data: { utf8: '64 units, 124 bytes' } }] },
    { id: 'tar-f3-nested-non-ascii', entries: [{ path: 'index.html', data: { utf8: 'first' } },
      { path: `ドキュメント/${'説明書'.repeat(10)}.md`, data: { seed: 'swarm-tar/f3-nested', length: 1500 } }] },
  ]) {
    const files = tar.entries.map((e) => ({ path: e.path, bytes: dataOf(e.data) }));
    const body = await withReference(env, { clock: MTIME, node: { stamps: C.STAMPS.usable } }, async (ref, node) => {
      await ref.publishService.publishCollection(files);
      return node.requests.find((r) => r.path === '/bzz').body;
    });
    out.push({ id: tar.id, kind: 'tar', deviation: 'tar-paths', mtime_ms: MTIME, entries: tar.entries,
      reference: { length: body.length, sha256: sha256(body), base64: b64(body) },
      core: 'the whole name, behind a GNU long-link entry (the name counted in bytes)' });
  }
  // The 100-file, 50 MiB collection: its length and digest.
  {
    const entries = Array.from({ length: 100 }, (_, i) => ({ path: `files/${String(i).padStart(3, '0')}.bin`,
      data: { seed: `publish-files/50mib/${i}`, length: i === 99 ? 50 * MiB - 99 * 524288 : 524288 } }));
    const files = entries.map((e) => ({ path: e.path, bytes: dataOf(e.data) }));
    const body = await withReference(env, {}, async (ref, node, world) => {
      await ref.load('./page-upload.js').uploadCollection(world.nodeUrl, C.BATCH_A, files, {});
      return node.requests[0].body;
    });
    out.push({ id: 'tar-100-files-50mib', kind: 'tar', mtime_ms: MTIME, entries, body: { length: body.length, sha256: sha256(body) } });
  }
  // Single files: publishData's body is the data, its name in the query.
  for (const [id, data, name, contentType] of [
    ['file-string', { utf8: '<h1>Freedom</h1>' }, undefined, 'text/html'],
    ['file-named', { seed: 'swarm-file/named', length: 5000 }, 'report.pdf', 'application/pdf'],
    ['file-name-unicode', { utf8: 'x' }, 'ñandú & co/?#.txt', 'text/plain'],
    ['file-empty', { utf8: '' }, undefined, 'text/plain'],
    ['file-10mib', { seed: 'publish-data/10mib', length: 10 * MiB }, 'big.bin', 'application/octet-stream'],
  ]) {
    const bytes = dataOf(data);
    const request = await withReference(env, {}, async (ref, node, world) => {
      await ref.load('./page-upload.js').uploadData(world.nodeUrl, C.BATCH_A, bytes, { name, contentType });
      return requestRecord(node.requests[0], node);
    });
    out.push({ id, kind: 'file', data, ...(name !== undefined ? { name } : {}), content_type: contentType, request,
      body: { length: bytes.length, sha256: sha256(bytes) } });
  }
  // SOCs: core-sdk's makeContentAddressedChunk(payload, span).toSingleOwnerChunk(identifier, key),
  // under keys.json's Bee wallet and publisher keys.
  for (const c of [
    { id: 'soc-bee-1-byte', key: 'bee', identifier: '00'.repeat(32), data: { utf8: '!' } },
    { id: 'soc-publisher-0-40-bytes', key: 'publisher:0', identifier: 'ff'.repeat(32), data: { seed: 'swarm-soc/40', length: 40 } },
    { id: 'soc-publisher-1-4096-bytes', key: 'publisher:1', identifier: '0123456789abcdef'.repeat(4), data: { seed: 'swarm-soc/4096', length: 4096 } },
    { id: 'soc-bee-wrapped-root', key: 'bee', identifier: '42'.repeat(32), data: { seed: 'swarm-soc/root', length: 64 }, span: '4097' },
    { id: 'soc-publisher-2-span-past-safe', key: 'publisher:2', identifier: '24'.repeat(32), data: { seed: 'swarm-soc/root-2', length: 96 }, span: '9007199254740993' },
  ]) {
    const key = env.keyOf(c.key).privateKey.slice(2);
    const payload = dataOf(c.data);
    const cac = c.span === undefined ? env.core.makeContentAddressedChunk(payload) : env.core.makeContentAddressedChunk(payload, BigInt(c.span));
    const soc = cac.toSingleOwnerChunk(new env.core.Identifier(c.identifier), key);
    out.push({
      id: c.id, kind: 'soc', key, identifier: c.identifier, data: c.data, ...(c.span !== undefined ? { span: c.span } : {}),
      result: {
        span: soc.span.toBigInt().toString(), chunk_address: cac.address.toHex(), signature: soc.signature.toHex(),
        owner: soc.owner.toHex(), address: soc.address.toHex(), body: hex(soc.data),
      },
    });
  }
  // Chunks: publishChunk's POST /chunks body, span ‖ payload, and the address it answers.
  for (const [id, data, span] of [
    ['chunk-1-byte', { utf8: 'x' }, undefined], ['chunk-4096', { seed: 'swarm-chunk/4096', length: 4096 }, undefined],
    ['chunk-span', { utf8: 'root of something larger' }, 1048576], ['chunk-span-max', { utf8: 'max span' }, '18446744073709551615'],
  ]) {
    const payload = dataOf(data);
    const record = await withReference(env, { node: { stamps: C.STAMPS.usable } }, async (ref, node) => {
      const result = await ref.chunkService.publishChunk(payload, span === undefined ? {} : { span: BigInt(span) });
      return { result, request: node.requests.find((r) => r.path === '/chunks') };
    });
    out.push({ id, kind: 'chunk', data, ...(span !== undefined ? { span: String(span) } : {}),
      body: record.request.body.toString('hex'), address: record.result.reference });
  }
  // PSS: the message is the body; the topic its keccak256, the recipient as given.
  for (const [id, topic, targets, data] of [
    ['pss-hi', 'chat', 'abcd', { utf8: 'hi' }], ['pss-empty', 'chat', 'abcd', { utf8: '' }],
    ['pss-4000', 'Chat 💬', 'abcdef', { seed: 'swarm-pss/4000', length: 4000 }],
  ]) {
    const recipient = env.keyOf('publisher:2').publicKey.slice(2);
    const request = await withReference(env, { node: { stamps: C.STAMPS.usable } }, async (ref, node) => {
      await ref.messagingService.sendPss({ topic, targets, recipient, data: dataOf(data) });
      return requestRecord(node.requests.find((r) => r.path.startsWith('/pss/')), node);
    });
    out.push({ id, kind: 'pss', topic, targets, recipient, data, topic_hash: env.beeJs.Topic.fromString(topic).toHex(), request });
  }
  return out;
}

/** bee-js's own `bee.collection.upload` body for `files`, as publishCollection calls it. */
async function beeCollectionBody(env, url, node, files) {
  const before = node.requests.length;
  const bee = new env.beeJs.Bee(url);
  const collection = files.map((f) => ({ path: f.path, size: f.bytes.byteLength, file: new File([f.bytes], path.posix.basename(f.path)) }));
  await bee.collection.upload(C.BATCH_A, collection, { pin: true, deferred: true });
  return node.requests[before].body;
}

// ---------------------------------------------------------------------------
// feeds.

const TOPIC_NAMES = ['', 'hello', `${C.ORIGIN}/blog`, `${C.ENS}/blog`, 'https://app.example/ünïcødé 日本語 🎉', 't'.repeat(256)];
const INDEXES = ['0', '1', '255', '256', '4294967296', '9007199254740993', '18446744073709551615'];

async function buildFeeds(env, methods) {
  const out = [];
  TOPIC_NAMES.forEach((name, i) => out.push({ id: `topic-${i}`, kind: 'topic', name, topic: env.beeJs.Topic.fromString(name).toHex() }));
  const identifierModule = require(path.join(path.dirname(require.resolve('@ethersphere/bee-js', { paths: [env.checkout] })), 'feed/identifier.js'));
  for (const [t, name] of [[0, `${C.ORIGIN}/blog`], [1, 'https://app.example/ünïcødé 日本語 🎉']]) {
    const topic = env.beeJs.Topic.fromString(name);
    for (const index of INDEXES) {
      out.push({ id: `identifier-${t}-${index}`, kind: 'identifier', topic: topic.toHex(), index,
        identifier: identifierModule.makeFeedIdentifier(topic, env.beeJs.FeedIndex.fromBigInt(BigInt(index))).toHex() });
    }
  }
  // Updates: feed-service.js's own writers, signed by the identity core's
  // stand-in under keys.json's keys, over the fake node.
  const UPDATES = [
    { id: 'update-reference', form: 'reference', key: 'bee', topic: `${C.ORIGIN}/blog`, head: null, reference: C.REF },
    { id: 'update-reference-publisher', form: 'reference', key: 'publisher:1', topic: `${C.ENS}/news`, head: 6, reference: '01'.repeat(32), clock: 0 },
    { id: 'update-payload-1', form: 'payload', key: 'bee', topic: `${C.ORIGIN}/blog`, head: 0, data: { utf8: 'x' } },
    { id: 'update-payload-utf8', form: 'payload', key: 'publisher:2', topic: 'https://app.example/ünïcødé 日本語 🎉', head: 1, data: { utf8: 'héllo wörld' }, asString: true },
    { id: 'update-payload-4096', form: 'payload', key: 'publisher:1', topic: `${C.ORIGIN}/blog`, head: 2, data: { seed: 'swarm-update/4096', length: 4096 } },
    { id: 'update-wrapped-4097', form: 'payload', key: 'bee', topic: `${C.ORIGIN}/blog`, head: 3, data: { seed: 'swarm-update/4097', length: 4097 } },
    { id: 'update-wrapped-524289', form: 'payload', key: 'publisher:2', topic: `${C.ORIGIN}/big`, head: 4, data: { seed: 'swarm-update/524289', length: 524289 } },
    { id: 'update-wrapped-10mib', form: 'payload', key: 'publisher:0', topic: `${C.ORIGIN}/big`, head: 5, data: { seed: 'write-feed/10mib', length: 10 * MiB } },
    { id: 'update-payload-empty', form: 'payload', key: 'bee', topic: `${C.ORIGIN}/blog`, head: 7, data: { utf8: '' } },
    { id: 'update-payload-index', form: 'payload', key: 'bee', topic: `${C.ORIGIN}/blog`, index: 9, data: { utf8: 'at nine' } },
  ];
  for (const u of UPDATES) {
    const signer = { key: u.key };
    const record = { id: u.id, kind: 'update', form: u.form, key: env.keyOf(u.key).privateKey.slice(2), topic: u.topic };
    const nodeSpec = { stamps: C.STAMPS.usable,
      latest: [{ key: u.key, topic: u.topic, reply: { status: 404, json: { code: 404, message: 'Not Found' } } }],
      probes: [{ key: u.key, topic: u.topic, targets: u.head === null || u.head === undefined ? [] : [u.head], head: u.head ?? null }] };
    const result = await withReference(env, { node: nodeSpec, clock: u.clock ?? C.T0 }, async (ref, node, world) => {
      const swarmSigner = await signerFor(ref, env, signer.key);
      let value;
      try {
        if (u.form === 'reference') value = await ref.feedService.updateFeed(swarmSigner, u.topic, u.reference);
        else {
          const payload = u.asString ? u.data.utf8 : dataOf(u.data);
          value = await ref.feedService.writeFeedPayload(swarmSigner, u.topic, payload, u.index !== undefined ? { index: u.index } : {});
        }
      } catch (err) {
        return { error: errorRecord(err, node), requests: node.requests, events: world.events };
      }
      return { value, requests: node.requests, events: world.events };
    });
    if (u.form === 'reference') {
      record.reference = u.reference;
      record.at = Math.floor((u.clock ?? C.T0) / 1000);
    } else {
      record.data = u.data;
      if (u.asString) record.as_string = true;
    }
    record.requests = result.requests.map((r) => `${r.method} ${r.path}`);
    if (result.error) {
      record.error = result.error.message;
      record.reason = result.error.reason;
      record.signed = result.events.some((e) => e.sign_soc);
      out.push(record);
      continue;
    }
    record.index = String(result.value.index);
    const bytes = result.requests.find((r) => r.method === 'POST' && r.path === '/bytes');
    if (bytes) record.bytes_upload = { length: bytes.body.length, sha256: sha256(bytes.body) };
    const soc = result.requests.find((r) => r.method === 'POST' && r.path.startsWith('/soc/'));
    const [, , owner, identifier] = soc.path.split('/');
    record.soc = {
      owner, identifier, sig: new URLSearchParams(soc.query).get('sig'), body: soc.body.toString('hex'),
      address: env.core.makeSOCAddress(new env.core.Identifier(identifier), new env.core.EthAddress(owner)).toHex(),
    };
    out.push(record);
  }
  // Index runs: resolveNextIndex and probeFeedHead, from the methods that ran them.
  for (const c of methods) {
    if (!/^update-feed-(head|latest)/.test(c.id)) continue;
    const step = c.steps[0];
    const probes = step.requests.filter((r) => r.feed).map((r) => ({ index: r.feed.index, status: r.status }));
    const lookup = step.requests.find((r) => r.method === 'GET' && r.path.startsWith('/feeds/'));
    out.push({ id: `index-run-${c.id.slice('update-feed-'.length)}`, kind: 'index_run', method_case: c.id,
      lookup: lookup ? lookup.status : null, probes, ...('result' in step ? { next_index: step.result.index } : outcomeOf(stepAnswer(step), { normalize: (t) => t })) });
  }
  // feedEntryExists' answers, from the explicit-index writes.
  for (const c of methods) {
    if (!c.id.startsWith('write-feed-explicit-index')) continue;
    const step = c.steps[0];
    const read = step.requests.find((r) => r.feed || r.path.startsWith('/chunks/'));
    out.push({ id: `entry-exists-${c.id.slice('write-feed-explicit-index-'.length)}`, kind: 'entry_exists', method_case: c.id,
      chunk_status: read ? read.status : null, ...stepOutcome(step) });
  }
  // #1057's metered reads: readFeedPayload over a recording meter.
  out.push(...await meteredReads(env));
  return out;
}

const stepAnswer = (step) => ('result' in step ? { result: step.result } : { error: step.error });
function stepOutcome(step) {
  const out = {};
  for (const key of ['result', 'result_typed', 'error', 'error_typed']) if (key in step) out[key] = step[key];
  return out;
}

/** A SwarmSigner for a test key, through the reference's own swarm-signer.js. */
async function signerFor(ref, env, name) {
  const signerModule = ref.load('./swarm-signer.js');
  const identity = name === 'bee' ? { mode: 'bee-wallet' } : { mode: 'app-scoped', publisherKeyIndex: Number(name.split(':')[1]) };
  return signerModule.resolveSwarmSigner(identity);
}

async function meteredReads(env) {
  const topicStr = `${C.ORIGIN}/blog`;
  const owner = env.keyOf('bee').address;
  const entries = [
    { key: 'bee', topic: topicStr, index: 0, data: { utf8: 'entry zero' } },
    { key: 'bee', topic: topicStr, index: 2, wrap: true, data: { seed: 'read-feed/4097', length: 4097 } },
    { key: 'bee', topic: topicStr, index: 3, wrap: true, data: { seed: 'read-feed/524289', length: 524289 } },
  ];
  const latest = (reply) => [{ key: 'bee', topic: topicStr, reply }];
  const headers = { 'swarm-feed-index': '0000000000000007', 'swarm-feed-index-next': '0000000000000008' };
  const READS = [
    { id: 'metered-index-inline', index: 0, maxBytes: 524288, left: 524288 },
    { id: 'metered-index-inline-charge-refused', index: 0, maxBytes: 524288, left: 100 },
    { id: 'metered-index-wrapped', index: 2, maxBytes: 524288, left: 524288 },
    { id: 'metered-index-wrapped-reserve-refused', index: 2, maxBytes: 524288, left: 3000 },
    { id: 'metered-index-span-past-max', index: 3, maxBytes: 524288, left: 524288 },
    { id: 'metered-index-span-within-connected', index: 3, maxBytes: 5 * MiB, left: 5 * MiB },
    { id: 'metered-index-join-longer', index: 2, maxBytes: 524288, left: 524288,
      rules: [{ match: { prefix: '/bytes/' }, reply: { status: 200, body_data: { seed: 'read-feed/4097', length: 5000 } } }] },
    { id: 'metered-index-join-shorter', index: 2, maxBytes: 524288, left: 524288,
      rules: [{ match: { prefix: '/bytes/' }, reply: { status: 200, body_data: { seed: 'read-feed/4097', length: 100 } } }] },
    { id: 'metered-index-one-chunk-held-to-span', index: 6, maxBytes: 524288, left: 524288,
      chunks: [env.feedSoc('bee', topicStr, 6, Buffer.from('thirty bytes of payload, held!'), 10n)] },
    { id: 'metered-latest-declared', maxBytes: 524288, left: 524288, latest: latest({ status: 200, headers, body_utf8: 'the latest' }) },
    { id: 'metered-latest-declared-past-max', maxBytes: 524288, left: 524288,
      latest: latest({ status: 200, headers, body_data: { seed: 'metered/latest', length: 524289 } }) },
    { id: 'metered-latest-declared-past-left', maxBytes: 524288, left: 1000,
      latest: latest({ status: 200, headers, body_data: { seed: 'metered/latest', length: 2000 } }) },
    { id: 'metered-latest-pieces', maxBytes: 524288, left: 524288,
      latest: latest({ status: 200, headers, chunked: true, pieces_data: [{ seed: 'metered/p1', length: 40000 }, { seed: 'metered/p2', length: 3 }] }) },
    { id: 'metered-latest-pieces-past-max', maxBytes: 524288, left: 524288,
      latest: latest({ status: 200, headers, chunked: true, pieces_data: [{ seed: 'metered/p1', length: 300000 }, { seed: 'metered/p2', length: 300000 }] }) },
    { id: 'metered-latest-pieces-past-left', maxBytes: 524288, left: 50000,
      latest: latest({ status: 200, headers, chunked: true, pieces_data: [{ seed: 'metered/p1', length: 40000 }, { seed: 'metered/p2', length: 40000 }] }) },
    { id: 'metered-latest-cut-mid-way', maxBytes: 524288, left: 524288,
      latest: latest({ status: 200, headers, chunked: true, pieces_data: [{ seed: 'metered/p1', length: 1000 }], cutAfterPieces: true }) },
    { id: 'metered-latest-declared-longer-than-sent', maxBytes: 524288, left: 524288,
      latest: latest({ status: 200, headers, body_utf8: 'short', declare: 40 }) },
  ];
  const out = [];
  for (const r of READS) {
    const nodeSpec = { entries, latest: r.latest, rules: r.rules, chunks: r.chunks };
    const record = await withReference(env, { node: nodeSpec }, async (ref, node) => {
      const calls = [];
      let left = r.left;
      const refusal = { error: { code: -32602, message: 'Permission-free read budget exceeded', data: { reason: 'rate_limited' } } };
      const meter = {
        maxBytes: r.maxBytes,
        charge: (bytes) => {
          left -= bytes;
          const refused = left < 0;
          calls.push({ charge: bytes, refused });
          return refused ? refusal : null;
        },
        reserve: (bytes) => {
          const refused = bytes > left;
          if (!refused) left -= bytes;
          calls.push({ reserve: bytes, refused });
          return refused ? refusal : null;
        },
      };
      const topic = env.beeJs.Topic.fromString(topicStr);
      let outcome;
      try {
        const value = await ref.feedService.readFeedPayload(owner, topic, r.index, meter);
        outcome = { payload: { length: value.payload.length, sha256: sha256(value.payload) }, index: value.index, next_index: value.nextIndex };
      } catch (err) {
        outcome = { error: errorRecord(err, node) };
      }
      return { calls, outcome, requests: node.requests.map((q) => requestRecord(q, node)) };
    });
    out.push({ id: r.id, kind: 'metered_read', owner, topic: topicStr, ...(r.index !== undefined ? { index: r.index } : {}),
      meter: { maxBytes: r.maxBytes, left: r.left }, node: nodeSpec, ...record });
  }
  return out;
}

// ---------------------------------------------------------------------------
// gsoc: bee-js's gsocMine, as write-side.json records it.

/**
 * The GSOC cases, mined by bee-js's gsocMine in worker threads (the
 * searches to the cap take seconds each): a promise of their records, in
 * case order.
 */
function buildGsoc(env) {
  const { Worker } = require('node:worker_threads');
  const { core } = env;
  const keccak = (text) => hex(core.keccak256(new TextEncoder().encode(text)));
  const candidateAddress = (identifier, index) => {
    const key = new core.PrivateKey(core.numberToUint256(0xb33n + BigInt(index), 'BE'));
    return core.makeSOCAddress(new core.Identifier(identifier), key.publicKey().address()).toHex();
  };
  const cases = [];
  // Freedom's derivation (messaging-service.js): identifier keccak256(utf8(topic)),
  // target keccak256(utf8('freedom-gsoc-v1:' + topic)), proximity 12.
  for (const [name, topic] of [['empty', ''], ['chat', 'chat'], ['room', 'room'], ['unicode', 'чат/聊天/🎉'], ['256-bytes', 'r'.repeat(256)]]) {
    cases.push({ id: `gsoc-topic-${name}`, topic, target: keccak(`freedom-gsoc-v1:${topic}`), identifier: keccak(topic), proximity: 12 });
  }
  const id = keccak('chat');
  const target = keccak('freedom-gsoc-v1:chat');
  for (const proximity of [0, 1, 8, 13]) cases.push({ id: `gsoc-proximity-${proximity}`, target, identifier: id, proximity });
  const other = keccak('another identifier');
  cases.push({ id: 'gsoc-exact-1000', target: candidateAddress(other, 1000), identifier: other, proximity: 256 });
  // The cap: the last candidate found, and the search that finds none.
  cases.push({ id: 'gsoc-last-candidate', target: candidateAddress(other, 0xfffe), identifier: other, proximity: 256 });
  cases.push({ id: 'gsoc-past-cap', target: candidateAddress(other, 0xffff), identifier: other, proximity: 256 });
  const lanes = [cases.slice(0, -2), [cases.at(-2)], [cases.at(-1)]];
  const run = (list) => new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, 'swarm-gsoc-worker.js'), { workerData: { checkout: env.checkout, cases: list } });
    worker.once('message', ({ records, loaded }) => {
      env.loadedElsewhere.push(...loaded);
      resolve(records);
    });
    worker.once('error', reject);
  });
  return Promise.all(lanes.map(run)).then((parts) => parts.flat());
}

// ---------------------------------------------------------------------------
// stamps: bee-js's mapPostageBatch over raw `/stamps` answers, and
// swarm-service.js's selectBestBatch with each option.

const RAW_BATCHES = [
  ['usable', C.batch()],
  ['usable-mutable', C.batch({ immutableFlag: false })],
  ['used-half', C.batch({ utilization: 32, depth: 22, bucketDepth: 16 })],
  ['full-immutable', C.batch({ utilization: 64, depth: 22, bucketDepth: 16 })],
  ['full-mutable', C.batch({ immutableFlag: false, utilization: 16, depth: 20, bucketDepth: 16 })],
  ['propagating', C.batch({ usable: false, propagating: true })],
  ['rejected', C.batch({ usable: false, propagating: false })],
  ['pending-no-flag', C.batch({ usable: false })],
  ['expired', C.batch({ usable: false, exists: false, batchTTL: -1 })],
  ['ttl-zero', C.batch({ batchTTL: 0 })],
  ['ttl-fraction', C.batch({ batchTTL: 1.5 })],
  ['ttl-past-100-years', C.batch({ batchTTL: 4000000000 })],
  ['utilization-ratio', C.batch({ utilizationRatio: 0.25 })],
  ['depth-17', C.batch({ depth: 17 })],
  ['depth-18', C.batch({ depth: 18 })],
  ['label-unicode', C.batch({ label: 'Freedom ✓ storage' })],
  ['batch-id-0x', C.batch({ batchID: `0x${C.BATCH_B}` })],
  ['batch-id-upper', C.batch({ batchID: C.BATCH_C.toUpperCase() })],
  ['missing-label', (({ label, ...rest }) => rest)(C.batch())],
  ['amount-number', C.batch({ amount: 5 })],
  ['extra-fields', C.batch({ extra: true, owner: '0x00' })],
];

const SELECT_SETS = [
  ['usable', C.STAMPS.usable], ['two', C.STAMPS.two], ['none', C.STAMPS.none], ['small', C.STAMPS.small],
  ['pending', C.STAMPS.pending], ['propagating', C.STAMPS.propagating], ['full-mutable', C.STAMPS.fullMutable],
  ['usable-and-propagating', { stamps: [C.batch({ batchID: C.BATCH_B, depth: 18 }), C.batch({ batchID: C.BATCH_C, usable: false, propagating: true, batchTTL: 10 })] }],
  ['full-mutable-and-usable', { stamps: [C.batch({ batchID: C.BATCH_B, immutableFlag: false, utilization: 16, depth: 20, bucketDepth: 16, batchTTL: 9e6 }), C.batch({ batchTTL: 100 })] }],
  ['equal-ttl', { stamps: [C.batch({ batchID: C.BATCH_B }), C.batch({ batchID: C.BATCH_C })] }],
  ['malformed', C.STAMPS.missingLabel],
];
const SELECT_CALLS = [
  ['content-4096', 4096, { requireCapacity: true }],
  ['content-10mib', 10 * MiB, { requireCapacity: true }],
  ['feed-4096', 4096, {}],
  ['message-4096', 4096, { allowFullMutable: true }],
];

async function buildStamps(env) {
  const mapped = [];
  for (const [id, raw] of RAW_BATCHES) {
    const record = await withReference(env, { node: { stamps: { stamps: [raw] } } }, async (ref) => {
      const service = ref.swarmService;
      const classified = {
        usable: service.isUsableStamp(raw), pending: service.isPendingStamp(raw), propagating: service.isPropagatingStamp(raw),
        full_immutable: service.isFullImmutableStamp(raw), key: service.batchIdKey(raw.batchID),
      };
      try {
        const [batch] = await service.getBee().stamp.getAll();
        return { classified, mapped: mappedBatch(batch) };
      } catch (err) {
        return { classified, error: errorRecord(err) };
      }
    });
    mapped.push({ id, raw, ...record });
  }
  const select = [];
  for (const [setId, stamps] of SELECT_SETS) {
    for (const [callId, size, options] of SELECT_CALLS) {
      const record = await withReference(env, { node: { stamps } }, async (ref, node) => {
        try {
          const batch = await ref.swarmService.selectBestBatch(size, options);
          return { result: batch, stamps_reads: node.requests.length };
        } catch (err) {
          return { error: errorRecord(err), stamps_reads: node.requests.length };
        }
      });
      // The core reads /stamps once per write (stamps-one-read): where the
      // reference reads it twice, the core gives the same answer from one.
      const once = record.stamps_reads > 1 ? { deviation: 'stamps-one-read', core: { stamps_reads: 1 } } : {};
      select.push({ id: `${setId}/${callId}`, stamps, size, options, ...record, ...once });
    }
  }
  return { mapped, select };
}

/** The fields of bee-js's mapped batch Freedom reads, as values. */
function mappedBatch(batch) {
  return {
    batchID: batch.batchID.toHex(), utilization: batch.utilization, usable: batch.usable, label: batch.label, depth: batch.depth,
    amount: batch.amount, bucketDepth: batch.bucketDepth, blockNumber: batch.blockNumber, immutableFlag: batch.immutableFlag,
    usage: batch.usage, usageText: batch.usageText, size: batch.size.toBytes(), remainingSize: batch.remainingSize.toBytes(),
    theoreticalSize: batch.theoreticalSize.toBytes(), duration: batch.duration.toSeconds(),
  };
}

// ---------------------------------------------------------------------------
// errors.

const ERROR_BODIES = [
  ['json-object', { json: { code: 500, message: 'read chunk failed' } }],
  ['json-object-nested', { json: { code: 400, message: 'bad', reasons: [{ field: 'x', error: 'y' }] } }],
  ['json-string', { json: 'a JSON string' }],
  ['json-null', { body_utf8: 'null' }],
  ['json-number', { body_utf8: '42' }],
  ['json-true', { body_utf8: 'true' }],
  ['json-array', { body_utf8: '[1,"two",null]' }],
  ['json-duplicate-keys', { body_utf8: '{"message":"first","message":"read chunk failed","code":1}' }],
  ['text', { body_utf8: 'plain text error' }],
  ['empty', { body_utf8: '' }],
  ['whitespace', { body_utf8: '  \n\t ' }],
  ['bom-json', { body_hex: 'efbbbf7b226d657373616765223a2272656164206368756e6b206661696c6564227d' }],
  ['bom-text', { body_hex: 'efbbbf68656c6c6f' }],
  ['bad-utf8', { body_hex: '6869ff2c20c3' }],
  ['lone-surrogate-escape', { body_utf8: '{"message":"\\ud800"}' }],
  ['big-number', { body_utf8: '{"code":12345678901234567890}' }],
  ['past-8kib', { body_data: { seed: 'swarm-error/9000', length: 9000 } }],
  ['past-8kib-json', { body_utf8: JSON.stringify({ message: 'm'.repeat(9000) }) }],
];
const ERROR_STATUSES = [[500, 'Internal Server Error'], [404, 'Not Found'], [400, 'Bad Request'], [503, 'Busy Right Now'], [500, '']];

async function buildErrors(env, methods) {
  const out = [];
  const sites = [
    // bee-js's own calls: a JSON response (GET /stamps) and an array-buffer one (GET /chunks, GET /bytes).
    ['bee-js-json', 'GET', '/stamps', (ref) => ref.swarmService.getBee().stamp.getAll()],
    ['bee-js-arraybuffer', 'GET', `/chunks/${'ab'.repeat(32)}`, (ref) => ref.swarmService.getBee().chunk.download('ab'.repeat(32))],
    ['bee-js-bytes', 'GET', `/bytes/${'ab'.repeat(32)}`, (ref) => ref.swarmService.getBee().data.download('ab'.repeat(32))],
    // #1057's latest-feed reader (fetchNode), reached through readFeedPayload.
    ['fetch-node', 'GET', null, (ref) => ref.feedService.readFeedPayload(env.keyOf('bee').address,
      env.beeJs.Topic.fromString(`${C.ORIGIN}/blog`), undefined, { maxBytes: 524288, charge: () => null, reserve: () => null })],
    // chunk-service.js's SOC upload.
    ['soc-upload', 'POST', null, async (ref) => ref.chunkService.uploadSingleOwnerChunk(ref.swarmService.getBee(), C.BATCH_A,
      env.signedSocFixture, { pin: true, deferred: false })],
    // page-upload.js, window.swarm's publishData.
    ['page-upload', 'POST', '/bzz', (ref, world) => ref.load('./page-upload.js').uploadData(world.nodeUrl, C.BATCH_A, Buffer.from('x'), {})],
  ];
  for (const [site, method, fixedPath, call] of sites) {
    for (const [bodyId, body] of ERROR_BODIES) {
      // fetchNode's own text needs a status readFeedPayload doesn't read as
      // an empty feed (it reads a 404 or a 500 so): a 503 too.
      const statuses = site === 'bee-js-json' ? ERROR_STATUSES : site === 'fetch-node' ? [ERROR_STATUSES[0], ERROR_STATUSES[3]] : [ERROR_STATUSES[0]];
      for (const [status, statusText] of statuses) {
        const match = fixedPath ? { method, path: fixedPath } : { method, prefix: method === 'GET' ? '/feeds/' : '/soc/' };
        const reply = { status, statusText, ...body };
        const record = await withReference(env, { node: { rules: [{ match, reply }] } }, async (ref, node, world) => {
          try {
            await call(ref, world);
            return { outcome: 'no error' };
          } catch (err) {
            const out2 = { error: errorRecord(err, node) };
            if (site.startsWith('bee-js')) out2.chunk_not_found = ref.chunkService.isChunkNotFoundError(err);
            return out2;
          }
        });
        const entry = { id: `${site}/${bodyId}/${status}${statusText ? '' : '-no-reason'}`, kind: 'http_error', site, status, status_text: statusText,
          body: bodyOf(reply), ...record };
        if (bodyId.startsWith('past-8kib')) {
          // The core reads 8 KiB of an error body (error-body-bound): its text
          // is the same reader's over the first 8,192 bytes.
          const cut = bodyBytes(reply).subarray(0, 8192);
          const core = await withReference(env, { node: { rules: [{ match, reply: { status, statusText, body_base64: b64(cut) } }] } },
            async (ref, node, world) => {
              try {
                await call(ref, world);
                return { outcome: 'no error' };
              } catch (err) {
                return { error: errorRecord(err, node) };
              }
            });
          entry.deviation = 'error-body-bound';
          entry.core = core;
        }
        out.push(entry);
      }
    }
  }
  // nodeWriteError's and mapChunkReadError's mappings, as the provider answers.
  const mapping = (fn, re) => ({ kind: 'mapping', function: fn, method_cases: methods.filter((c) => re.test(c.id)).map((c) => c.id) });
  out.push({ id: 'mapping-node-write-error', ...mapping('nodeWriteError',
    /^(publish-(data|files|chunk)-(node-|no-stamps|stamps-)|write-soc-(node-|no-stamps)|create-feed-(node-|no-stamps|stamps-)|update-feed-(node-|no-stamps)|write-feed-(soc-500|bytes-upload-500|no-stamps|explicit-index-(500|503|not-the-soc))|send-(pss|gsoc)-(node-|no-stamps|bad-point|full-mutable))/) });
  out.push({ id: 'mapping-chunk-read-error', ...mapping('mapChunkReadError',
    /^(read-chunk-(not-found|500|wrong|short|node-hangs)|read-data-(not-found|root-wrong|bytes-|join-)|read-soc-(not-found|500|wrong|cac))/) });
  return out;
}

function bodyBytes(reply) {
  if (reply.json !== undefined) return Buffer.from(JSON.stringify(reply.json));
  if (reply.body_utf8 !== undefined) return Buffer.from(reply.body_utf8, 'utf8');
  if (reply.body_hex !== undefined) return Buffer.from(reply.body_hex, 'hex');
  return dataOf(reply.body_data);
}

function bodyOf(reply) {
  const bytes = bodyBytes(reply);
  if (bytes.length <= 1024) return { length: bytes.length, base64: b64(bytes) };
  return { length: bytes.length, sha256: sha256(bytes), ...(reply.body_data ? { data: reply.body_data } : { base64: b64(bytes) }) };
}

// ---------------------------------------------------------------------------
// stores: swarm-feeds.json, swarm-manifest-grants.json, publish-history.sqlite.

async function buildStores(env) {
  const out = [];
  const { identity, feedStore, originEntry, ORIGIN, OTHER, ENS, T0 } = C;
  const bee = identity('bee-wallet');
  const app0 = identity('app-scoped', 0);
  const app1 = identity('app-scoped', 1);
  const eth = identity('ethereum-wallet', 0);
  const json = (value) => JSON.stringify(value, null, 2);
  const topicHex = (o, name) => env.beeJs.Topic.fromString(`${o}/${name}`).toHex();
  const feed = { topic: topicHex(ORIGIN, 'blog'), owner: env.keyOf('bee').address, manifestReference: C.MANIFEST };
  const FEED_RUNS = [
    { id: 'feeds-create-app-scoped-fresh', before: null, ops: [['createAppScopedIdentity', ORIGIN, {}]] },
    { id: 'feeds-create-app-scoped-inactive', before: json(feedStore({ [ORIGIN]: originEntry(bee) })),
      ops: [['createAppScopedIdentity', ORIGIN, { activate: false, label: '  My  label ' }]] },
    { id: 'feeds-create-app-scoped-label-81-bytes', before: null, ops: [['createAppScopedIdentity', ORIGIN, { label: 'é'.repeat(40) + 'x' }]] },
    { id: 'feeds-create-app-scoped-counter-behind', before: json(feedStore({ [OTHER]: originEntry(app0) }, 0)),
      ops: [['createAppScopedIdentity', ORIGIN, {}]], deviation: 'index-allocation',
      core: 'allocates index 1: the larger of nextPublisherKeyIndex (0) and one past every stored index (0)' },
    { id: 'feeds-create-at', before: json(feedStore({}, 3)), ops: [['createAppScopedIdentityAt', ORIGIN, 3, {}], ['createAppScopedIdentityAt', OTHER, 3, {}]] },
    { id: 'feeds-ensure-bee-wallet', before: null, ops: [['ensureAntWalletIdentity', ORIGIN, {}], ['ensureAntWalletIdentity', ORIGIN, { activate: true }]] },
    { id: 'feeds-ensure-bee-wallet-not-active', before: json(feedStore({ [ORIGIN]: originEntry(app0) }, 1)),
      ops: [['ensureAntWalletIdentity', ORIGIN, {}], ['ensureAntWalletIdentity', ORIGIN, { activate: true }]] },
    { id: 'feeds-activate', before: json(feedStore({ [ORIGIN]: originEntry(bee, { identities: [bee, app0, eth] }) }, 1)),
      ops: [['activateIdentity', ORIGIN, 'app-scoped:0'], ['activateIdentity', ORIGIN, 'app-scoped:9'], ['activateIdentity', ORIGIN, eth.id],
        ['activateIdentity', OTHER, 'bee-wallet']] },
    { id: 'feeds-set-feed', before: json(feedStore({ [ORIGIN]: originEntry(bee) })), ops: [
      ['setFeed', ORIGIN, 'blog', { ...feed, identityId: 'bee-wallet' }], ['updateFeedReference', ORIGIN, 'blog', C.REF],
      ['setFeed', ORIGIN, 'blog', { ...feed, manifestReference: 'ab'.repeat(32), identityId: 'app-scoped:0' }],
      ['updateFeedReference', ORIGIN, 'news', C.REF], ['setFeed', OTHER, 'blog', feed]] },
    { id: 'feeds-grants', before: json(feedStore({ [ORIGIN]: originEntry(bee, { feedGranted: false }), [OTHER]: originEntry(eth, { feedGranted: false }) })),
      ops: [['grantFeedAccess', ORIGIN, {}], ['revokeFeedAccess', ORIGIN, {}], ['grantFeedAccess', OTHER, { source: 'manifest' }],
        ['grantFeedAccess', ENS, {}], ['revokeFeedAccess', ENS, {}]] },
    { id: 'feeds-set-origin-entry', before: json(feedStore({}, 2)), ops: [
      ['setOriginEntry', ORIGIN, { identityMode: 'app-scoped' }], ['setOriginEntry', OTHER, { identityMode: 'app-scoped', publisherKeyIndex: 7, feedGranted: true }],
      ['setOriginEntry', ENS, { identityMode: 'bee-wallet' }], ['setOriginEntry', ENS, { identityMode: 'ethereum-wallet' }],
      ['allocatePublisherKeyIndex']] },
    { id: 'feeds-identity-state', before: json(feedStore({
      [ORIGIN]: originEntry(app0, { identities: [bee, app0] }), [OTHER]: originEntry(app1, { identities: [app1, identity('app-scoped', 0)] }),
    }, 2)), ops: [['getOriginIdentityStateWithOwners', ORIGIN], ['getOriginIdentityStateWithOwners', ENS], ['previewAppScopedIdentity', ORIGIN, {}],
      ['getAllOriginEntries'], ['isIdentitySharedWithOtherOrigins', ORIGIN, app0], ['isIdentitySharedWithOtherOrigins', ORIGIN, app1],
      ['isIdentitySharedWithOtherOrigins', ORIGIN, bee], ['isIdentitySharedWithOtherOrigins', ORIGIN, { mode: 'app-scoped', publisherKeyIndex: null }]] },
    { id: 'feeds-identity-state-locked', vault: 'locked', before: json(feedStore({ [ORIGIN]: originEntry(app0) }, 1)),
      ops: [['getOriginIdentityStateWithOwners', ORIGIN]] },
    { id: 'feeds-load-v1', before: json({ version: 1, nextPublisherKeyIndex: 1, origins: {
      [ORIGIN]: { identityMode: 'app-scoped', publisherKeyIndex: 4, feedGranted: true, grantedAt: T0 - 9000, feeds: { blog: { ...feed } } },
      [OTHER]: { identityMode: 'bee-wallet', feeds: { a: { topic: 't' }, b: { ...feed, identityId: 'kept' } } },
      [ENS]: { identityMode: 'ethereum-wallet' },
      'bzz://bad-feeds': { identityMode: 'bee-wallet', feeds: [] },
    } }), ops: [['getAllOriginEntries']] },
    { id: 'feeds-load-v1-counter-invalid', before: json({ version: 1, nextPublisherKeyIndex: -2, origins: {} }), ops: [['getAllOriginEntries']] },
    { id: 'feeds-load-v1-origins-invalid', before: json({ version: 1, origins: [] }), ops: [['getAllOriginEntries']] },
    { id: 'feeds-load-unparseable', before: '{ "version": 2, ', ops: [['getAllOriginEntries'], ['ensureAntWalletIdentity', ORIGIN, {}]] },
    { id: 'feeds-load-unsupported-version', before: json({ version: 3, origins: {} }), ops: [['getAllOriginEntries'], ['ensureAntWalletIdentity', ORIGIN, {}]] },
    { id: 'feeds-load-version-missing', before: json({ origins: {} }), ops: [['getAllOriginEntries']] },
    { id: 'feeds-load-root-array', before: '[]', ops: [['getAllOriginEntries']] },
    { id: 'feeds-load-counter-invalid', before: json({ version: 2, nextPublisherKeyIndex: 1.5, origins: {} }), ops: [['getAllOriginEntries']] },
    { id: 'feeds-load-sanitized', before: json({ version: 2, nextPublisherKeyIndex: 1, origins: {
      [ORIGIN]: { ...originEntry(app0), feeds: { good: feed, bad: 'x' } },
      [OTHER]: { ...originEntry(bee), feeds: [] },
      [ENS]: { activeIdentityId: 'missing', identities: {} },
      'bzz://unknown-mode': { activeIdentityId: 'x', identities: { x: { id: 'x', mode: 'mystery' } } },
      'bzz://eth': originEntry(eth),
    } }), ops: [['getAllOriginEntries'], ['grantFeedAccess', ORIGIN, {}]] },
    { id: 'feeds-load-two-backups', before: '{', files: { 'swarm-feeds.corrupt.json': 'an older backup' }, ops: [['ensureAntWalletIdentity', ORIGIN, {}]] },
  ];
  for (const run of FEED_RUNS) {
    const record = await withReference(env, { feeds: run.before, vault: run.vault, files: run.files }, async (ref, node, world) => {
      const ops = [];
      for (const [op, ...args] of run.ops) {
        const entry = { op, args: encode(args) };
        try {
          Object.assign(entry, answer('result', await ref.feedStore[op](...args)));
        } catch (err) {
          entry.error = errorRecord(err);
        }
        ops.push(entry);
      }
      return { ops, files: dirFiles(world.dir, (name) => name.startsWith('swarm-feeds')) };
    });
    out.push({ id: run.id, kind: 'feeds', ...(run.deviation ? { deviation: run.deviation, core: run.core } : {}), before: run.before,
      ...(run.files ? { before_files: run.files } : {}), ...(run.vault ? { vault: run.vault } : {}), ...record });
  }
  out.push(...await manifestRuns(env));
  out.push(...await historyRuns(env));
  return out;
}

function dirFiles(dir, keep) {
  const files = {};
  for (const name of fs.readdirSync(dir).filter(keep).sort()) files[name] = fs.readFileSync(path.join(dir, name), 'utf8');
  return files;
}

async function manifestRuns(env) {
  const { ORIGIN, identity, feedStore, originEntry } = C;
  const site = `bzz://${'5a'.repeat(32)}`;
  const url = `${site}/index.html`;
  const manifest = (capabilities, extra = {}) => JSON.stringify({ schema: 'freedom-manifest/1', name: 'Freedom Notes', description: 'Notes on Swarm',
    capabilities: { swarm: Object.fromEntries(capabilities.map((c) => [c, { why: `To ${c} your notes` }])) }, ...extra });
  const fetchWith = (text, status = 200) => async () => new Response(text, { status });
  const RUNS = [
    { id: 'manifest-legacy-not-eager', steps: [['check', { eager: false }, manifest(['publish'])]] },
    { id: 'manifest-allow-publish', steps: [['check', { eager: true }, manifest(['publish'])], ['decide', 'allow']] },
    { id: 'manifest-allow-all', feeds: feedStore({}, 0), steps: [['check', { eager: true }, manifest(['publish', 'feeds', 'signing', 'messaging'])], ['decide', 'allow'],
      ['get']] },
    { id: 'manifest-individual', steps: [['check', { eager: true }, manifest(['publish', 'messaging'])], ['decide', 'individual']] },
    { id: 'manifest-deny-first-contact', steps: [['check', { eager: true }, manifest(['publish'])], ['decide', 'deny']] },
    { id: 'manifest-satisfied-by-grant', grants: C.connected(site, { autoApprove: { publish: true, feeds: false, signing: false, messaging: false } }),
      steps: [['check', { eager: true }, manifest(['publish'])]] },
    { id: 'manifest-removed-capability', steps: [['check', { eager: true }, manifest(['publish', 'messaging'])], ['decide', 'allow'],
      ['check', { eager: false }, manifest(['publish'])]] },
    { id: 'manifest-absent-prunes', steps: [['check', { eager: true }, manifest(['publish'])], ['decide', 'allow'], ['check', { eager: false }, 'nope', 404]] },
    { id: 'manifest-invalid-prunes', steps: [['check', { eager: true }, manifest(['publish'])], ['decide', 'allow'], ['check', { eager: false }, '{"schema":"x"}']] },
    { id: 'manifest-unresolved', steps: [['check', { eager: true }, '', 502], ['check', { eager: true }, manifest(['publish'])]] },
    { id: 'manifest-too-large', steps: [['check', { eager: true }, manifest(['publish'], { description: 'd'.repeat(9000) })]] },
    { id: 'manifest-use-individual', steps: [['check', { eager: true }, manifest(['publish', 'feeds'])], ['decide', 'allow'], ['useIndividual', 'feeds'],
      ['useIndividual', 'messaging']] },
    { id: 'manifest-disconnect', steps: [['check', { eager: true }, manifest(['publish'])], ['decide', 'allow'], ['disconnect']] },
    { id: 'manifest-ethereum-wallet-refused', feeds: feedStore({ [site]: originEntry(identity('ethereum-wallet', 0)) }),
      steps: [['check', { eager: true }, manifest(['feeds'])], ['decide', 'allow']] },
    { id: 'manifest-load-from-backup', manifests: '{', files: { 'swarm-manifest-grants.json.bak': JSON.stringify({ version: 1, records: { [site]: {
      managed: {}, acknowledged: { publish: { decision: 'individual', source: 'existing-grant', decidedAt: 1 } }, revision: 1 } } }) },
    steps: [['get'], ['disconnect']] },
  ];
  const out = [];
  for (const run of RUNS) {
    const record = await withReference(env, { grants: run.grants ?? {}, feeds: run.feeds, manifests: run.manifests, files: run.files },
      async (ref, node, world) => {
        const steps = [];
        let token = null;
        for (const [op, ...args] of run.steps) {
          const step = { op };
          try {
            let value;
            if (op === 'check') {
              const [options, text, status] = args;
              step.manifest = text;
              if (status) step.status = status;
              value = await ref.manifests.checkManifest({ origin: site, committedUrl: url, ...options }, { fetchManifest: fetchWith(text, status) });
              if (value.token) {
                token = value.token;
                value = { ...value, token: '(the consent token)' };
              }
              step.options = options;
            } else if (op === 'decide') {
              step.outcome = args[0];
              value = await ref.manifests.decideManifest(token, args[0]);
            } else if (op === 'useIndividual') {
              step.capability = args[0];
              value = await ref.manifests.useIndividual(site, args[0]);
            } else if (op === 'disconnect') {
              value = await ref.manifests.disconnect(site);
            } else if (op === 'get') {
              value = await ref.manifests.getRecord(site);
            }
            Object.assign(step, answer('result', value));
          } catch (err) {
            step.error = errorRecord(err);
          }
          steps.push(step);
        }
        return {
          steps,
          grants_after: world.grants,
          files: dirFiles(world.dir, (name) => name.startsWith('swarm-manifest-grants') || name === 'swarm-feeds.json'),
        };
      });
    out.push({ id: run.id, kind: 'manifests', site, before: run.manifests ?? null, ...(run.files ? { before_files: run.files } : {}),
      grants: run.grants ?? {}, feeds: run.feeds ? JSON.stringify(run.feeds, null, 2) : null, ...record });
  }
  return out;
}

async function historyRuns(env) {
  const out = [];
  const RUNS = [
    { id: 'history-schema-and-rows', ops: [
      ['addEntry', { type: 'data', name: 'Published data', status: 'uploading', origin: C.ORIGIN, bytesSize: 5 }],
      ['updateEntry', 1, { status: 'completed', reference: 'ab'.repeat(32), bzzUrl: `bzz://${'ab'.repeat(32)}`, tagUid: 7, batchIdUsed: C.BATCH_A, bytesSize: 5 }],
      ['addEntry', { type: 'directory', status: 'completed', origin: C.ORIGIN }],
      ['addEntry', {}],
      ['updateEntry', 3, { status: 'failed', errorMessage: 'cancelled' }],
      ['updateEntry', 99, { status: 'failed' }],
      ['getEntries'], ['removeEntry', 2], ['removeEntry', 2], ['getEntries'], ['clearEntries'], ['getEntries']] },
    { id: 'history-sweep-at-open', seed: [['addEntry', { type: 'soc', status: 'uploading', origin: C.ORIGIN }], ['addEntry', { type: 'chunk', status: 'completed' }]],
      ops: [['getEntries']] },
    { id: 'history-json-migration', userData: { 'publish-history.json': JSON.stringify({ entries: [
      { type: 'data', name: 'Old', status: 'completed', reference: 'cd'.repeat(32), bzzUrl: `bzz://${'cd'.repeat(32)}`, timestamp: '2025-06-01T10:00:00.000Z', origin: 'freedom://publish' },
      { type: 'file', timestamp: 'not a date' },
      { name: 'uploading one', status: 'uploading', timestamp: '2025-06-02T10:00:00.000Z' },
    ] }) }, ops: [['getEntries']] },
    { id: 'history-json-already-migrated', userData: { 'publish-history.json': '{"entries":[{"type":"data"}]}', 'publish-history.json.migrated': '{}' }, ops: [['getEntries']] },
    { id: 'history-json-unparseable', userData: { 'publish-history.json': '{' }, ops: [['getEntries']] },
  ];
  // history-bound: the reference keeps every row; the core keeps 10,000, the oldest finished rows going first.
  {
    const record = await withReference(env, {}, async (ref) => {
      for (let i = 0; i < 10001; i++) ref.history.addEntry({ type: 'chunk', status: 'completed', origin: C.ORIGIN, bytesSize: i });
      const rows = ref.history.getDb().prepare('SELECT COUNT(*) AS n, MIN(id) AS first, MAX(id) AS last FROM publishes').get();
      return { rows };
    });
    out.push({ id: 'history-10001-rows', kind: 'history', deviation: 'history-bound', ops: [{ op: 'addEntry', times: 10001,
      args: [{ type: 'chunk', status: 'completed', origin: C.ORIGIN, bytesSize: '<i>' }] }], ...record,
    core: { rows: { n: 10000, first: 2, last: 10001 } } });
  }
  for (const run of RUNS) {
    if (run.seed) {
      // A first session's rows, left `uploading` when it ended.
      run.seedFile = await withReference(env, {}, async (ref, node, world) => {
        for (const [op, arg] of run.seed) ref.history[op](arg);
        ref.history.closeDb();
        return fs.readFileSync(path.join(world.dir, 'publish-history.sqlite')).toString('base64');
      });
    }
    const record = await withReference(env, { files: run.userData, clock: C.T0 + 1000 }, async (ref, node, world) => {
      if (run.seedFile) {
        ref.history.closeDb();
        fs.writeFileSync(path.join(world.dir, 'publish-history.sqlite'), Buffer.from(run.seedFile, 'base64'));
      }
      const ops = [];
      for (const [op, ...args] of run.ops) {
        const entry = { op, args };
        try {
          Object.assign(entry, answer('result', ref.history[op](...args)));
        } catch (err) {
          entry.error = errorRecord(err);
        }
        ops.push(entry);
      }
      const db = ref.history.getDb();
      const schema = db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").all();
      const pragmas = { user_version: db.pragma('user_version', { simple: true }), journal_mode: db.pragma('journal_mode', { simple: true }) };
      const rows = db.prepare('SELECT * FROM publishes ORDER BY id').all();
      return { ops, schema, pragmas, rows, user_data: dirFiles(world.dir, (name) => name.startsWith('publish-history.json')) };
    });
    out.push({ id: run.id, kind: 'history', ...(run.seed ? { seeded: run.seed } : {}), ...(run.userData ? { user_data_before: run.userData } : {}), ...record });
  }
  return out;
}

module.exports = { buildTrees, buildBodies, buildFeeds, buildGsoc, buildStamps, buildErrors, buildStores, errorRecord };
