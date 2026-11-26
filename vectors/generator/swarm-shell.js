'use strict';

// vectors/swarm.json's `shell` section (design 0015, SWM-4's D12): main's
// own Swarm methods, each case recorded from the swarm reference's own code
// over the fake node and the stores the other sections use:
//
// - swarm.publish: publish-service.js's publishData, publishFile,
//   publishCollection and publishDirectory, and the freedom://publish IPC
//   handlers that keep a history row (swarm:publish-data, -file, -directory);
// - swarm.feed: feed-service.js's createFeed, updateFeed and readFeedState
//   under the Bee wallet's signer (main's own feeds);
// - swarm.stamps: bee-js's stamp.getAll and stamp.get, as main reads them;
// - swarm.upload_status: publish-service.js's getUploadStatus;
// - swarm.identities: feed-store.js's IPC handlers, the functions
//   page-swarm.js's feed prompt calls, and getEthereumWalletIdentityReferences;
// - swarm.history: publish-history.js's getEntries, clearEntries and
//   removeEntry, and its two IPC handlers;
// - swarm.manifest: permission-manifests.js's page path (checkPageManifest,
//   decidePageManifest, releasePageManifest) and its three IPC handlers.
//
// Each step names the reference's call and records its own outcome, then
// the request and answer in the wire forms design 0015 gives main's own
// methods (SWM-4's D5 and D7): node methods' params as main's JSON, ops'
// params as `op` and typed members, every answer typed. Where the core's
// answer differs by a design deviation, the case is marked with its id and
// `core` holds the core's answer. Nothing the vectors pin is computed here:
// every outcome is the reference's, and a deviation's core answer is the
// reference's own over the input the core takes (or its own stated text).

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { withReference, requestRecord } = require('./swarm-run');
const { sha256 } = require('./swarm-node');
const { encode, answer } = require('./swarm-typed');
const { formOf } = require('./swarm-grammar');
const { errorRecord } = require('./swarm-sections');
const C = require('./swarm-cases');

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const json = (value) => JSON.stringify(value, null, 2);
const T0 = C.T0;
const STAMPS = C.STAMPS.usable;
const AGENT_TOPIC = 'freedom-agent/publications';
const BODY_INLINE = 8192;
// D6: main hands the core at most 8 KiB + 1 bytes of a manifest's body.
const MANIFEST_BODY_MOST = 8 * 1024 + 1;
// The text bee-js's error carries when storer peers don't know a batch yet
// (ant-storage-api.js's isBatchNotYetKnownError).
const NOT_YET_KNOWN = 'pushsync: chunk rejected by 3 peer(s) as not found on-chain';

// ---------------------------------------------------------------------------
// Records.

/** A node reply as the core reads it: status, reason phrase, headers in order, body. */
function replyRecord(r) {
  if (!r.reply) return null;
  const body = r.replyBody ?? Buffer.alloc(0);
  return {
    status: r.reply.status,
    status_text: http.STATUS_CODES[r.reply.status] ?? '',
    headers: Object.entries(r.replyHeaders || {}).map(([name, value]) => [name.toLowerCase(), String(value)]),
    body: body.length <= BODY_INLINE ? { bytes: body.length, base64: b64(body) } : { bytes: body.length, sha256: sha256(body) },
  };
}

/** The error a service threw, as main's own callers read it: `{ message, code?, status?, capacity? }`. */
function shellError(err) {
  const out = { message: String(err?.message) };
  if (typeof err?.code === 'string') out.code = err.code;
  if (typeof err?.status === 'number') out.status = err.status;
  if (err?.capacity && typeof err.capacity === 'object') {
    out.capacity = { uploadBytes: err.capacity.uploadBytes, requiredBytes: err.capacity.requiredBytes,
      largestRemainingBytes: err.capacity.largestRemainingBytes };
  }
  return out;
}

/** What a store op threw, as its caller reads it: `{ name, message, code? }`. */
function thrown(err) {
  return { name: err?.name ?? 'Error', message: String(err?.message), ...(typeof err?.code === 'string' ? { code: err.code } : {}) };
}

const typedResult = (value) => ({ result_typed: encode(value) });
const typedError = (value) => ({ error_typed: encode(value) });

/** An op's params: `op`, a string, and each member typed (D7). */
function opParams(op, members = {}) {
  const out = { op };
  for (const [name, value] of Object.entries(members)) out[name] = encode(value);
  return out;
}

/**
 * Each request of a node method's step, classified against its row
 * (design 0015, The operation grammar): `form <name>`, or one of a named
 * deviation's requests (stamps-one-read's second /stamps, index-probe's
 * whole GET /feeds). Fails on a request its row doesn't take.
 */
function classify(env, caseId, row, params, raws) {
  const out = [];
  let i = 0;
  const fail = (r, why) => {
    throw new Error(`shell ${caseId} (${row}): ${r ? `${r.method} ${r.path}: ` : ''}${why}`);
  };
  const header = (r, name) => r.headers.find(([n]) => n === name)?.[1];
  const next = () => raws[i];
  const take = (classification) => {
    out.push(classification);
    i += 1;
  };
  const stamps = () => {
    if (params.batch !== undefined || !next() || formOf(next()) !== 'stamps') return;
    take({ form: 'stamps' });
    if (next() && formOf(next()) === 'stamps') take({ deviation: 'stamps-one-read' });
  };
  const batchHeader = (r) => {
    if (params.batch !== undefined && header(r, 'swarm-postage-batch-id') !== params.batch) fail(r, 'another batch than the params give');
  };
  switch (row) {
    case 'swarm.publish:data,file':
    case 'swarm.publish:collection': {
      stamps();
      const r = next();
      if (!r) break;
      const form = row === 'swarm.publish:collection' ? 'bzz_tar' : 'bzz_file';
      if (formOf(r) !== form) fail(r, `not ${form}`);
      batchHeader(r);
      if ((header(r, 'swarm-encrypt') === 'true') !== (params.encrypt === true)) fail(r, 'swarm-encrypt where the params don\'t ask, or none where they do');
      if (header(r, 'swarm-deferred-upload') !== String(params.deferred)) fail(r, 'swarm-deferred-upload is not deferred');
      take({ form });
      break;
    }
    case 'swarm.feed:create': {
      stamps();
      const r = next();
      if (!r) break;
      if (formOf(r) !== 'feed_manifest') fail(r, 'not feed_manifest');
      if (!r.path.endsWith(`/${params.topic}`)) fail(r, 'another topic than the params give');
      batchHeader(r);
      take({ form: 'feed_manifest' });
      break;
    }
    case 'swarm.feed:update': {
      stamps();
      const look = next();
      if (!look) break;
      if (formOf(look) !== 'feed_latest' || !look.path.endsWith(`/${params.topic}`)) fail(look, 'the index lookup is not the topic\'s GET /feeds');
      const owner = look.path.split('/')[2];
      take({ deviation: 'index-probe' });
      while (next() && formOf(next()) === 'chunk') take({ form: 'chunk' });
      const s = next();
      if (!s) break;
      if (formOf(s) !== 'soc_up' || s.path.split('/')[2] !== owner) fail(s, 'not the feed owner\'s soc_up');
      batchHeader(s);
      take({ form: 'soc_up' });
      break;
    }
    case 'swarm.feed:read': {
      // readFeedState's lookup: the reference downloads the latest payload
      // whole (index-probe), where the core asks feed_head for the same
      // index; then the head probe, only after its 404.
      const look = next();
      if (!look) break;
      if (formOf(look) !== 'feed_latest' || !look.path.endsWith(`/${params.topic}`)) fail(look, 'the index lookup is not the topic\'s GET /feeds');
      take({ deviation: 'index-probe' });
      if (look.reply?.status !== 404) break;
      while (next() && formOf(next()) === 'chunk') take({ form: 'chunk' });
      break;
    }
    case 'swarm.stamps': {
      const r = next();
      if (!r) break;
      const form = params.id === undefined ? 'stamps' : 'stamp';
      if (formOf(r) !== form || (form === 'stamp' && r.path !== `/stamps/${params.id}`)) fail(r, `not ${form}`);
      take({ form });
      break;
    }
    case 'swarm.upload_status': {
      const r = next();
      if (!r) break;
      if (formOf(r) !== 'tag' || r.path !== `/tags/${params.tag_uid}`) fail(r, 'not the tag\'s GET /tags');
      take({ form: 'tag' });
      break;
    }
    default:
      fail(raws[0], 'no row');
  }
  if (i < raws.length) fail(raws[i], 'a call past the row');
  return out;
}

/** A step's node requests, each with its row's verdict and the node's reply. */
function stepRequests(env, caseId, row, params, node, before) {
  const raws = node.requests.slice(before);
  const verdicts = classify(env, caseId, row, params, raws);
  return raws.map((r, j) => ({ ...requestRecord(r, node), ...verdicts[j], reply: replyRecord(r) }));
}

/** The Freedom data directory's store files after a run. */
function storeFiles(dir) {
  const read = (name) => (fs.existsSync(path.join(dir, name)) ? fs.readFileSync(path.join(dir, name), 'utf8') : null);
  return { feeds: read('swarm-feeds.json'), manifests: read('swarm-manifest-grants.json') };
}

// ---------------------------------------------------------------------------
// Node methods: swarm.publish, swarm.feed, swarm.stamps, swarm.upload_status.

/** normalizeUploadResult's fields as swarm.publish answers them. */
const publishAnswer = (result) => ({ reference: result.reference, tag_uid: result.tagUid, batch: result.batchIdUsed, bytes: result.bytesSize });

/**
 * mapPostageBatch's fields Freedom reads (as `stamps.mapped` writes them),
 * then the raw batch's `exists` and `propagating` where booleans and the
 * node's own `batchTTL` where a finite number: swarm.stamps' answer.
 */
function mappedFields(batch) {
  return {
    batchID: batch.batchID.toHex(), utilization: batch.utilization, usable: batch.usable, label: batch.label, depth: batch.depth,
    amount: batch.amount, bucketDepth: batch.bucketDepth, blockNumber: batch.blockNumber, immutableFlag: batch.immutableFlag,
    usage: batch.usage, usageText: batch.usageText, size: batch.size.toBytes(), remainingSize: batch.remainingSize.toBytes(),
    theoreticalSize: batch.theoreticalSize.toBytes(), duration: batch.duration.toSeconds(),
  };
}

function stampAnswer(batch, raw) {
  const out = mappedFields(batch);
  if (typeof raw.exists === 'boolean') out.exists = raw.exists;
  if (typeof raw.propagating === 'boolean') out.propagating = raw.propagating;
  if (typeof raw.batchTTL === 'number' && Number.isFinite(raw.batchTTL)) out.batchTTL = raw.batchTTL;
  return out;
}

/**
 * One node-method case: `run(ref, world)` makes the reference's call and
 * returns `{ call, args, value | error, answer, handler? }`; the requests
 * and the history are recorded around it.
 */
async function nodeCase(env, spec) {
  return withReference(env, { node: spec.node, clock: spec.clock ?? T0, ipc: spec.ipc }, async (ref, node, world) => {
    if (spec.ipc) {
      ref.publishService.registerPublishIpc();
      ref.history.registerPublishHistoryIpc();
    }
    const before = node.requests.length;
    const out = await spec.run(ref, world, node);
    const step = { caller: spec.caller ?? 'shell', params: spec.params };
    if (spec.parts) step.parts = spec.parts.map((bytes) => ({ bytes: bytes.length, base64: b64(bytes) }));
    if (spec.part_abort) step.part_abort = spec.part_abort;
    step.reference = { call: out.call, args: encode(out.args) };
    if ('error' in out) step.reference.error = errorRecord(out.error, node);
    else Object.assign(step.reference, answer('result', out.value));
    if (out.handler) step.handler = { channel: out.handler.channel, ...answer('answer', out.handler.answer) };
    step.answer = 'error' in out ? typedError(shellError(out.error)) : typedResult(out.answer);
    step.requests = stepRequests(env, spec.id, spec.row, spec.params, node, before);
    return {
      id: spec.id,
      method: spec.method,
      row: spec.row,
      ...(spec.deviation ? { deviation: spec.deviation.id } : {}),
      world: { node: spec.node ?? {}, clock: spec.clock ?? T0, vault: 'unlocked' },
      steps: [step],
      ...(spec.deviation ? { core: spec.deviation.core } : {}),
      after: { history: ref.history.getEntries() },
    };
  });
}

/**
 * The service's own call: its value or throw, and the core's answer from the
 * value. `view` is how the vectors write a value of bee-js's classes (a
 * batch's fields Freedom reads, as `stamps.mapped` writes them).
 */
async function service(call, args, fn, toAnswer, view = (value) => value) {
  try {
    const value = await fn();
    return { call, args, value: view(value), answer: toAnswer(value) };
  } catch (error) {
    return { call, args, error };
  }
}

/** An IPC handler of the shell's, called as the shell calls it (a sender of its own). */
function handler(world, channel) {
  const fn = world.ipc.get(channel);
  assert.ok(fn, `no IPC handler ${channel}`);
  const sender = { id: 1, once() {}, isDestroyed: () => false };
  return (...args) => fn({ sender }, ...args);
}

/**
 * A freedom://publish IPC handler's run beside the service's: the handler
 * keeps the history row and answers the shell; the service's own value or
 * throw is what the core answers (main wraps it as the handler does). Both
 * runs must make the same requests.
 */
async function withHistory(env, spec) {
  const viaService = await nodeCase(env, spec);
  const viaHandler = await nodeCase(env, { ...spec, ipc: true, run: spec.handlerRun });
  assert.deepEqual(viaHandler.steps[0].requests, viaService.steps[0].requests, `${spec.id}: the handler's requests are the service's`);
  const { requests, answer: core, ...head } = viaService.steps[0];
  const step = { ...head, handler: viaHandler.steps[0].handler, answer: core, requests };
  const record = { ...viaService, steps: [step], after: viaHandler.after };
  if (spec.deviation?.coreOf) {
    const { after, ...rest } = record;
    return { ...rest, core: spec.deviation.coreOf(record), after };
  }
  return record;
}

/**
 * picked-read-text's core answer: describePickedPathError's coded form,
 * `Could not read "<name>" (<code>)`, from main's part abort, as the answer
 * (the error the service throws) and as the history row's text (the
 * reference's row otherwise). The core makes its upload call, whose body
 * main ends with the abort.
 */
function pickedReadCore(record, name, code) {
  const message = `Could not read "${name}" (${code})`;
  assert.match(record.steps[0].reference.error.message, /^fetch failed: /, 'the reference\'s text is fetch\'s');
  return {
    answers: [typedError({ message })],
    history: record.after.history.map((row) => ({ ...row, errorMessage: message })),
  };
}

function publishCases(env) {
  const out = [];
  const node = (rules) => ({ stamps: STAMPS, ...(rules ? { rules } : {}) });
  const bzz500 = (message) => [{ match: { method: 'POST', path: '/bzz' }, reply: { status: 500, json: { code: 500, message } } }];
  const data = (id, value, options, over = {}) => {
    const bytes = Buffer.from(value);
    const params = { kind: 'data', parts: [{ bytes: bytes.length, base64: b64(bytes) }] };
    if (options?.name !== undefined) params.name = options.name;
    if (options?.contentType !== undefined) params.content_type = options.contentType;
    if (options?.encrypt !== undefined) params.encrypt = options.encrypt;
    if (options?.batchId !== undefined) params.batch = options.batchId;
    Object.assign(params, { pin: true, deferred: false });
    const args = options === undefined ? [value] : [value, options];
    return {
      id: `publish-${id}`, method: 'swarm.publish', row: 'swarm.publish:data,file', params, node: node(), ...over,
      run: (ref) => service('publishData', args, () => ref.publishService.publishData(...args), publishAnswer),
    };
  };
  const plain = [
    data('data-default', Buffer.from('hello')),
    data('data-string', 'héllo ✓'),
    data('data-empty', Buffer.alloc(0)),
    data('data-options', Buffer.from('hello'), { batchId: C.BATCH_B, encrypt: true, name: 'draft.md', contentType: 'text/markdown' }),
    data('data-no-stamps', Buffer.from('hello'), undefined, { node: { stamps: C.STAMPS.none } }),
    data('data-batch-full', Buffer.from('hello'), undefined, { node: { stamps: { stamps: [C.batch({ utilization: 64 })] } } }),
    data('data-node-500', Buffer.from('hello'), undefined, { node: node(bzz500('upload failed')) }),
  ];
  for (const spec of plain) out.push(spec);
  // A collection: publishCollection over in-memory files.
  const collection = (id, files, options) => {
    const params = { kind: 'collection', parts: files.map((f, k) => ({ path: f.path, bytes: f.bytes.length, part: k })) };
    if (options?.indexDocument !== undefined) params.index_document = options.indexDocument;
    if (options?.encrypt !== undefined) params.encrypt = options.encrypt;
    if (options?.batchId !== undefined) params.batch = options.batchId;
    Object.assign(params, { pin: true, deferred: true });
    const args = options === undefined ? [files] : [files, options];
    return {
      id: `publish-${id}`, method: 'swarm.publish', row: 'swarm.publish:collection', params, node: node(), parts: files.map((f) => f.bytes),
      clock: T0,
      run: (ref) => service('publishCollection', args, () => ref.publishService.publishCollection(...args), publishAnswer),
    };
  };
  out.push(collection('collection-index-default', [{ path: 'index.html', bytes: Buffer.from('<h1>home</h1>') }, { path: 'a/b.txt', bytes: Buffer.from('b') }]));
  out.push(collection('collection-nested-no-index', [{ path: 'docs/a.txt', bytes: Buffer.from('a') }, { path: 'c.txt', bytes: Buffer.from('cc') }]));
  out.push(collection('collection-options', [{ path: 'x.txt', bytes: Buffer.from('x') }], { batchId: C.BATCH_B, encrypt: true, indexDocument: 'x.txt' }));
  return out;
}

/** The freedom://publish handlers' cases: the history row beside the service's own outcome. */
function historyPublishCases(env) {
  const out = [];
  const node = (rules) => ({ stamps: STAMPS, ...(rules ? { rules } : {}) });
  const bzz500 = (message) => [{ match: { method: 'POST', path: '/bzz' }, reply: { status: 500, json: { code: 500, message } } }];
  // swarm:publish-data: `publishData(data)`, the row `{ type: 'data', name: 'Text' }`.
  const data = (id, nodeSpec) => {
    const bytes = Buffer.from('hello');
    return {
      id: `publish-${id}`, method: 'swarm.publish', row: 'swarm.publish:data,file', node: nodeSpec,
      params: { kind: 'data', parts: [{ bytes: bytes.length, base64: b64(bytes) }], pin: true, deferred: false, history: { type: 'data', name: 'Text' } },
      run: (ref) => service('publishData', [bytes], () => ref.publishService.publishData(bytes), publishAnswer),
      handlerRun: async (ref, world) => ({ handler: { channel: 'swarm:publish-data', answer: await handler(world, 'swarm:publish-data')(bytes) } }),
    };
  };
  out.push(data('data-history', node()));
  out.push(data('data-history-node-500', node(bzz500('upload failed'))));
  out.push(data('data-history-not-yet-known', node(bzz500(NOT_YET_KNOWN))));
  out.push(data('data-history-no-stamps', { stamps: C.STAMPS.none }));
  // swarm:publish-file: a picked file, `publishFile(path)`, the row `{ type: 'file', name: basename }`.
  const file = (id, nodeSpec) => {
    const bytes = Buffer.from('the notes');
    const pickAndPublish = async (ref, world) => {
      const at = path.join(world.dir, 'picked', 'notes.txt');
      fs.mkdirSync(path.dirname(at), { recursive: true });
      fs.writeFileSync(at, bytes);
      world.pick = at;
      const picked = await handler(world, 'swarm:pick-file')();
      assert.equal(picked.success, true);
      return handler(world, 'swarm:publish-file')(picked.token);
    };
    return {
      id: `publish-${id}`, method: 'swarm.publish', row: 'swarm.publish:data,file', node: nodeSpec, parts: [bytes],
      params: { kind: 'file', parts: [{ bytes: bytes.length, part: 0 }], name: 'notes.txt', pin: true, deferred: true, history: { type: 'file', name: 'notes.txt' } },
      run: async (ref, world) => {
        const at = path.join(world.dir, 'picked', 'notes.txt');
        fs.mkdirSync(path.dirname(at), { recursive: true });
        fs.writeFileSync(at, bytes);
        return service('publishFile', ['<the picked file notes.txt>'], () => ref.publishService.publishFile(at), publishAnswer);
      },
      handlerRun: async (ref, world) => ({ handler: { channel: 'swarm:publish-file', answer: await pickAndPublish(ref, world) } }),
    };
  };
  out.push(file('file-history', node()));
  // picked-read-text: a picked file that can't be read once the upload
  // starts (here a folder at its path: EISDIR on the read stream). bee-js's
  // fetch wraps the read error, so describePickedPathError's coded form
  // (which only a stat error before the upload reaches) isn't the text: the
  // handler and the row give `fetch failed: EISDIR: …`. Main ends the part
  // with the errno's name (`part_abort`), and the core answers that form,
  // in the answer and the row.
  out.push({
    id: 'publish-file-history-unreadable', method: 'swarm.publish', row: 'swarm.publish:data,file', node: node(),
    params: { kind: 'file', parts: [{ bytes: 0, part: 0 }], name: 'notes', pin: true, deferred: true, history: { type: 'file', name: 'notes' } },
    part_abort: { part: 0, error_code: 'EISDIR' },
    deviation: { id: 'picked-read-text', coreOf: (record) => pickedReadCore(record, 'notes', 'EISDIR') },
    run: async (ref, world) => {
      const at = path.join(world.dir, 'picked', 'notes');
      fs.mkdirSync(at, { recursive: true });
      return service('publishFile', ['<the picked file notes, a folder>'], () => ref.publishService.publishFile(at), publishAnswer);
    },
    handlerRun: async (ref, world) => {
      world.pick = path.join(world.dir, 'picked', 'notes');
      fs.mkdirSync(world.pick, { recursive: true });
      const picked = await handler(world, 'swarm:pick-file')();
      return { handler: { channel: 'swarm:publish-file', answer: await handler(world, 'swarm:publish-file')(picked.token) } };
    },
  });
  out.push(file('file-history-not-yet-known', node(bzz500(NOT_YET_KNOWN))));
  out.push(file('file-history-node-500', node(bzz500('upload failed'))));
  // swarm:publish-directory: a picked folder of one file, `publishDirectory(path)`.
  const dir = (id, nodeSpec) => {
    const bytes = Buffer.from('<h1>site</h1>');
    const make = (world) => {
      const at = path.join(world.dir, 'picked', 'site');
      fs.mkdirSync(at, { recursive: true });
      fs.writeFileSync(path.join(at, 'index.html'), bytes);
      return at;
    };
    return {
      id: `publish-${id}`, method: 'swarm.publish', row: 'swarm.publish:collection', node: nodeSpec, parts: [bytes], clock: T0,
      params: { kind: 'collection', parts: [{ path: 'index.html', bytes: bytes.length, part: 0 }], pin: true, deferred: true,
        history: { type: 'directory', name: 'site' } },
      run: async (ref, world) => {
        const at = make(world);
        return service('publishDirectory', ['<the picked folder site>'], () => ref.publishService.publishDirectory(at), publishAnswer);
      },
      handlerRun: async (ref, world) => {
        world.pick = make(world);
        const picked = await handler(world, 'swarm:pick-directory')();
        assert.equal(picked.success, true);
        return { handler: { channel: 'swarm:publish-directory', answer: await handler(world, 'swarm:publish-directory')(picked.token) } };
      },
    };
  };
  out.push(dir('directory-history', node()));
  out.push(dir('directory-history-not-yet-known', node(bzz500(NOT_YET_KNOWN))));
  return out;
}

function feedCases(env) {
  const out = [];
  const topic = env.beeJs.Topic.fromString(AGENT_TOPIC).toHex();
  const signer = (ref) => ref.load('./swarm-signer.js').resolveSwarmSigner({ mode: 'bee-wallet' });
  const key = { kind: 'bee_wallet' };
  const latest = (reply) => [{ key: 'bee', topic: AGENT_TOPIC, reply }];
  const at = (index, next = index + 1) => ({ status: 200,
    headers: { 'swarm-feed-index': index.toString(16).padStart(16, '0'), 'swarm-feed-index-next': next.toString(16).padStart(16, '0') }, body_utf8: 'x' });
  const missing = { status: 404, json: { code: 404, message: 'Not Found' } };
  const create = (id, batch, nodeSpec) => ({
    id: `feed-${id}`, method: 'swarm.feed', row: 'swarm.feed:create', node: nodeSpec,
    params: { op: 'create', key, topic, ...(batch ? { batch } : {}) },
    run: async (ref) => {
      const s = await signer(ref);
      const args = batch ? ['<the Bee wallet signer>', AGENT_TOPIC, batch] : ['<the Bee wallet signer>', AGENT_TOPIC];
      return service('createFeed', args, () => ref.feedService.createFeed(s, AGENT_TOPIC, batch), (v) => v);
    },
  });
  out.push(create('create-batch', C.BATCH_B, { stamps: STAMPS }));
  out.push(create('create-auto', undefined, { stamps: STAMPS }));
  out.push(create('create-no-stamps', undefined, { stamps: C.STAMPS.none }));
  out.push(create('create-node-500', undefined, { stamps: STAMPS, rules: [
    { match: { method: 'POST', prefix: '/feeds/' }, reply: { status: 500, json: { code: 500, message: 'manifest failed' } } }] }));
  // The core asks feed_head for the index where the reference downloads the
  // latest payload whole (index-probe), as the methods' updateFeed cases mark.
  const indexProbe = { id: 'index-probe', core: 'feed_head with swarm-only-root-chunk instead of the whole latest payload; the same index' };
  const update = (id, { reference = C.REF, minIndex, batch, nodeSpec }) => ({
    id: `feed-${id}`, method: 'swarm.feed', row: 'swarm.feed:update', node: nodeSpec, deviation: indexProbe,
    params: { op: 'update', key, topic, reference, ...(minIndex !== undefined ? { min_index: minIndex } : {}), ...(batch ? { batch } : {}) },
    run: async (ref) => {
      const s = await signer(ref);
      const options = minIndex !== undefined ? { minIndex } : undefined;
      const args = ['<the Bee wallet signer>', AGENT_TOPIC, reference, batch, ...(options ? [options] : [])];
      return service('updateFeed', args, () => ref.feedService.updateFeed(s, AGENT_TOPIC, reference, batch, options), (v) => v);
    },
  });
  const probes = (head, targets = []) => [{ key: 'bee', topic: AGENT_TOPIC, ...(head !== undefined ? { head } : {}), targets }];
  out.push(update('update-first', { nodeSpec: { stamps: STAMPS, latest: latest(missing), probes: probes(undefined) } }));
  out.push(update('update-next', { nodeSpec: { stamps: STAMPS, latest: latest(at(2)) } }));
  out.push(update('update-min-index', { minIndex: 9, nodeSpec: { stamps: STAMPS, latest: latest(at(2)) } }));
  out.push(update('update-min-index-behind', { minIndex: 2, nodeSpec: { stamps: STAMPS, latest: latest(at(6)) } }));
  out.push(update('update-probe', { nodeSpec: { stamps: STAMPS, latest: latest(missing), probes: probes(4, [5]) } }));
  out.push(update('update-batch', { batch: C.BATCH_B, nodeSpec: { stamps: STAMPS, latest: latest(at(0)) } }));
  out.push(update('update-encrypted-reference', { reference: 'ab'.repeat(64), nodeSpec: { stamps: STAMPS, latest: latest(at(0)) } }));
  out.push(update('update-node-500', { nodeSpec: { stamps: STAMPS, latest: latest(at(0)), rules: [
    { match: { method: 'POST', prefix: '/soc/' }, reply: { status: 500, json: { code: 500, message: 'soc failed' } } }] } }));
  // readFeedState (op: read, which the agent's publication controller calls
  // after updateFeed; SWM-8's): the latest index, or the probe's head. Its
  // lookup is index-probe's, as the update's is.
  const read = (id, nodeSpec) => ({
    id: `feed-${id}`, method: 'swarm.feed', row: 'swarm.feed:read', node: nodeSpec, deviation: indexProbe,
    params: { op: 'read', key, topic },
    run: async (ref) => {
      const owner = env.keyOf('bee').address;
      return service('readFeedState', ['<the Bee wallet address>', AGENT_TOPIC], () => ref.feedService.readFeedState(owner, AGENT_TOPIC), (v) => v);
    },
  });
  out.push(read('read-latest', { latest: latest(at(2)) }));
  out.push(read('read-empty', { latest: latest(missing), probes: probes(undefined) }));
  out.push(read('read-probe', { latest: latest(missing), probes: probes(4, [5]) }));
  out.push(read('read-node-500', { latest: latest({ status: 500, json: { code: 500, message: 'feed lookup failed' } }) }));
  return out;
}

function stampCases(env) {
  const out = [];
  const listed = [C.batch({ batchTTL: 2000 }), C.batch({ batchID: C.BATCH_C, usable: false, propagating: true, batchTTL: 10 }),
    C.batch({ batchID: C.BATCH_B, immutableFlag: false, utilization: 16, depth: 20, exists: false })];
  const list = (id, nodeSpec, raws) => ({
    id: `stamps-${id}`, method: 'swarm.stamps', row: 'swarm.stamps', caller: 'chrome', node: nodeSpec, params: {},
    run: (ref) => service('stamp.getAll', [], async () => ref.swarmService.getBee().stamp.getAll(),
      (batches) => batches.map((b, k) => stampAnswer(b, raws[k])), (batches) => batches.map(mappedFields)),
  });
  out.push(list('list', { stamps: { stamps: listed } }, listed));
  out.push(list('list-empty', { stamps: C.STAMPS.none }, []));
  out.push(list('list-node-500', { stamps: STAMPS, rules: [{ match: { method: 'GET', path: '/stamps' }, reply: { status: 500, json: { code: 500, message: 'stamps failed' } } }] }, []));
  const one = C.batch({ batchTTL: 4000 });
  out.push({
    id: 'stamps-one', method: 'swarm.stamps', row: 'swarm.stamps', node: { rules: [{ match: { method: 'GET', path: `/stamps/${C.BATCH_A}` }, reply: { status: 200, json: one } }] },
    params: { id: C.BATCH_A },
    run: (ref) => service('stamp.get', [C.BATCH_A], async () => ref.swarmService.getBee().stamp.get(C.BATCH_A), (b) => stampAnswer(b, one), mappedFields),
  });
  out.push({
    id: 'stamps-one-not-found', method: 'swarm.stamps', row: 'swarm.stamps', node: { rules: [{ match: { method: 'GET', path: `/stamps/${C.BATCH_B}` },
      reply: { status: 404, json: { code: 404, message: 'issuer does not exist' } } }] },
    params: { id: C.BATCH_B },
    run: (ref) => service('stamp.get', [C.BATCH_B], async () => ref.swarmService.getBee().stamp.get(C.BATCH_B), (b) => stampAnswer(b, {}), mappedFields),
  });
  return out;
}

function uploadStatusCases() {
  const out = [];
  const tag = (over) => ({ uid: 101, split: 10, seen: 0, stored: 10, sent: 5, synced: 10, address: '', startedAt: '2026-01-01T00:00:00Z', ...over });
  const status = (id, uid, tags) => ({
    id: `upload-status-${id}`, method: 'swarm.upload_status', row: 'swarm.upload_status', caller: 'chrome', node: { tags },
    params: { tag_uid: uid },
    run: (ref) => service('getUploadStatus', [uid], () => ref.publishService.getUploadStatus(uid), (v) => v),
  });
  out.push(status('synced', 101, { 101: tag() }));
  out.push(status('encrypted-reference', 102, { 102: tag({ uid: 102, address: 'AB'.repeat(64), split: 4, sent: 4, synced: 1, seen: 3 }) }));
  out.push(status('nothing-split', 103, { 103: tag({ uid: 103, split: 0, stored: 0, sent: 0, synced: 0, address: 'cd'.repeat(32) }) }));
  out.push(status('not-found', 104, {}));
  return out;
}

// ---------------------------------------------------------------------------
// Store ops: swarm.identities, swarm.history, swarm.manifest.

/**
 * One store-op case over a world (`feeds`, `manifests`, `grants`, `vault`,
 * `accounts`, `clock`): each step `{ caller, op, members, call, run }`,
 * `run(ref, world)` the reference's call, recorded with the files after.
 */
async function opsCase(env, spec) {
  const world = {
    feeds: spec.feeds ?? null, manifests: spec.manifests ?? null, grants: spec.grants ?? {}, vault: spec.vault ?? 'unlocked',
    ...(spec.accounts ? { accounts: spec.accounts } : {}), clock: spec.clock ?? T0,
  };
  return withReference(env, { feeds: world.feeds, manifests: world.manifests, grants: world.grants, vault: world.vault, accounts: spec.accounts,
    clock: world.clock, ipc: true, tokens: true, manifestFetch: spec.fetch ? (url) => spec.fetch.next(url) : undefined, manifest: undefined },
  async (ref, node, w) => {
    ref.feedStore.registerFeedStoreIpc();
    ref.history.registerPublishHistoryIpc();
    ref.manifests.registerPermissionManifestIpc();
    if (spec.seed) {
      await spec.seed(ref, w);
      world.history = historyRows(ref);
    }
    const steps = [];
    for (const s of spec.steps) {
      if (s.clock !== undefined) w.clock.now = s.clock;
      if (s.vault !== undefined) w.unlocked = s.vault !== 'locked';
      const eventsBefore = w.events.length;
      const members = typeof s.members === 'function' ? s.members() : (s.members ?? {});
      const step = { caller: s.caller ?? 'shell', params: opParams(s.op, members) };
      if (s.clock !== undefined) step.clock = s.clock;
      if (s.vault !== undefined) step.vault = s.vault;
      step.reference = { call: s.call };
      let value;
      let error;
      try {
        value = await s.run(ref, w);
      } catch (err) {
        error = err;
      }
      // A world the case didn't script (a key keys.json lacks) fails the run.
      if (w.fatal) throw w.fatal;
      if (s.keep) value = s.keep(value);
      if (error) step.reference.error = errorRecord(error);
      else Object.assign(step.reference, answer('result', value));
      if (s.handler) {
        const handled = await s.handler(ref, w);
        step.handler = { channel: handled.channel, ...answer('answer', handled.answer) };
      }
      step.answer = error ? typedError(thrown(error)) : typedResult(value);
      // D6: main's fetch for a check, and its answer.
      const fetches = w.events.slice(eventsBefore).filter((e) => e.manifest_fetch);
      if (fetches.length) {
        assert.equal(fetches.length, 1, `${spec.id}: one fetch per check`);
        step.fetch = { url: fetches[0].manifest_fetch, answer: spec.fetch.answered.shift() };
      }
      if (s.after) step.files = storeFiles(w.dir);
      steps.push(step);
    }
    if (spec.settle) await spec.settle(ref);
    const after = { ...storeFiles(w.dir), grants: w.grants };
    if (spec.method === 'swarm.history') after.history = historyRows(ref);
    return { id: spec.id, method: spec.method, world, steps, after };
  });
}

/** publish-history.sqlite's rows in id order, each cell as stored (a BLOB as { blob: hex }). */
function historyRows(ref) {
  return ref.history.getDb().prepare('SELECT * FROM publishes ORDER BY id').all()
    .map((row) => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, Buffer.isBuffer(v) ? { blob: v.toString('hex') } : v])));
}

/** Main's manifest fetches, scripted: each answer as main hands it to the core (D6). */
function fetches(list) {
  const answered = [];
  let at = 0;
  return {
    answered,
    next(url) {
      const spec = list[Math.min(at, list.length - 1)];
      at += 1;
      if (spec.throws) {
        answered.push({ failed: true });
        return { throws: spec.throws };
      }
      const body = Buffer.from(spec.text, 'utf8');
      answered.push({ status: spec.status ?? 200, body_base64: b64(body.subarray(0, MANIFEST_BODY_MOST)) });
      return { status: spec.status ?? 200, body };
    },
  };
}

function identityCases(env) {
  const { identity, feedStore, originEntry, ORIGIN, OTHER, ENS } = C;
  const bee = identity('bee-wallet');
  const app0 = identity('app-scoped', 0);
  const app1 = identity('app-scoped', 1);
  const eth0 = identity('ethereum-wallet', 0);
  const fs1 = feedStore({ [ORIGIN]: originEntry(app0, { identities: [bee, app0] }), [OTHER]: originEntry(bee) }, 1);
  const out = [];
  const ipc = (channel, ...args) => (ref, w) => handler(w, channel)(...args);
  const chrome = (op, members, channel, args) => ({ caller: 'chrome', op, members, call: channel, run: ipc(channel, ...args) });
  // The chrome's ops, one per handler.
  out.push({ id: 'identities-chrome-reads', method: 'swarm.identities', feeds: json(fs1), steps: [
    chrome('get-all-origins', {}, 'swarm:get-all-origins', []),
    chrome('has-feed-identity', { origin: ORIGIN }, 'swarm:has-feed-identity', [ORIGIN]),
    chrome('has-feed-identity', { origin: ENS }, 'swarm:has-feed-identity', [ENS]),
    chrome('get-identity-mode', { origin: ORIGIN }, 'swarm:get-identity-mode', [ORIGIN]),
    chrome('get-identity-mode', { origin: ENS }, 'swarm:get-identity-mode', [ENS]),
    chrome('get-origin-identities', { origin: ORIGIN }, 'swarm:get-origin-identities', [ORIGIN]),
    chrome('get-origin-identities', { origin: ENS }, 'swarm:get-origin-identities', [ENS]),
  ] });
  out.push({ id: 'identities-chrome-changes', method: 'swarm.identities', feeds: json(fs1), steps: [
    chrome('create-app-scoped-identity', { origin: OTHER, options: { activate: false, label: '  Mine ' } }, 'swarm:create-app-scoped-identity',
      [OTHER, { activate: false, label: '  Mine ' }]),
    chrome('create-app-scoped-identity', { origin: ENS }, 'swarm:create-app-scoped-identity', [ENS]),
    chrome('ensure-ant-wallet-identity', { origin: ORIGIN, options: { activate: true } }, 'swarm:ensure-ant-wallet-identity', [ORIGIN, { activate: true }]),
    chrome('activate-feed-identity', { origin: ORIGIN, identity_id: 'app-scoped:0' }, 'swarm:activate-feed-identity', [ORIGIN, 'app-scoped:0']),
    chrome('activate-feed-identity', { origin: ORIGIN, identity_id: 'app-scoped:7' }, 'swarm:activate-feed-identity', [ORIGIN, 'app-scoped:7']),
    chrome('activate-feed-identity', { origin: ORIGIN, identity_id: 5 }, 'swarm:activate-feed-identity', [ORIGIN, 5]),
    chrome('set-feed-identity', {}, 'swarm:set-feed-identity', []),
    chrome('revoke-feed-access', { origin: ORIGIN }, 'swarm:revoke-feed-access', [ORIGIN]),
    chrome('revoke-feed-access', { origin: 'https://nobody.example' }, 'swarm:revoke-feed-access', ['https://nobody.example']),
  ] });
  // A locked vault: each mode's text.
  out.push({ id: 'identities-locked-bee-wallet', method: 'swarm.identities', vault: 'locked',
    feeds: json(feedStore({ [OTHER]: originEntry(bee) })), steps: [
      chrome('get-origin-identities', { origin: OTHER }, 'swarm:get-origin-identities', [OTHER]),
      chrome('get-origin-identities', { origin: ENS }, 'swarm:get-origin-identities', [ENS]),
    ] });
  out.push({ id: 'identities-locked-app-scoped', method: 'swarm.identities', vault: 'locked', feeds: json(fs1), steps: [
    chrome('get-origin-identities', { origin: ORIGIN }, 'swarm:get-origin-identities', [ORIGIN]),
    { op: 'previewAppScopedIdentity', members: { key: ORIGIN }, call: 'previewAppScopedIdentity', run: (ref) => ref.feedStore.previewAppScopedIdentity(ORIGIN) },
  ] });
  // An ethereum-wallet identity's label and owner, from the user's accounts.
  const wallet = env.keyOf('publisher:1000').address;
  out.push({ id: 'identities-ethereum-wallet-label', method: 'swarm.identities',
    accounts: [{ index: 0, name: 'Main account', address: wallet, type: 'mnemonic' }, { index: 3, name: 'Other', address: env.keyOf('publisher:2').address }],
    feeds: json(feedStore({ [ORIGIN]: originEntry(eth0, { identities: [eth0, identity('ethereum-wallet', 9)] }) })), steps: [
      chrome('get-origin-identities', { origin: ORIGIN }, 'swarm:get-origin-identities', [ORIGIN]),
    ] });
  // Main's own ops, as page-swarm.js's feed prompt calls them.
  const main = (op, members, call, run) => ({ op, members, call, run });
  out.push({ id: 'identities-main-prompt-ops', method: 'swarm.identities', feeds: json(feedStore({ [ORIGIN]: originEntry(bee, { feedGranted: false }),
    [OTHER]: originEntry(eth0) }, 2)), steps: [
    main('getOriginIdentityStateWithOwners', { key: ORIGIN }, 'getOriginIdentityStateWithOwners', (ref) => ref.feedStore.getOriginIdentityStateWithOwners(ORIGIN)),
    main('previewAppScopedIdentity', { key: ORIGIN }, 'previewAppScopedIdentity', (ref) => ref.feedStore.previewAppScopedIdentity(ORIGIN)),
    main('hasFeedGrant', { key: ORIGIN }, 'hasFeedGrant', (ref) => ref.feedStore.hasFeedGrant(ORIGIN)),
    main('assertFeedGrantable', { key: ORIGIN }, 'assertFeedGrantable', (ref) => ref.feedStore.assertFeedGrantable(ORIGIN)),
    main('assertFeedGrantable', { key: OTHER }, 'assertFeedGrantable', (ref) => ref.feedStore.assertFeedGrantable(OTHER)),
    main('createAppScopedIdentityAt', { key: ORIGIN, index: 2, options: { activate: true } }, 'createAppScopedIdentityAt',
      (ref) => ref.feedStore.createAppScopedIdentityAt(ORIGIN, 2, { activate: true, source: 'user' })),
    main('ensureAntWalletIdentity', { key: ORIGIN, options: { activate: true } }, 'ensureAntWalletIdentity',
      (ref) => ref.feedStore.ensureAntWalletIdentity(ORIGIN, { activate: true, source: 'user' })),
    main('activateIdentity', { key: ORIGIN, identity_id: 'app-scoped:2' }, 'activateIdentity',
      (ref) => ref.feedStore.activateIdentity(ORIGIN, 'app-scoped:2', { source: 'user' })),
    main('grantFeedAccess', { key: ORIGIN }, 'grantFeedAccess', (ref) => ref.feedStore.grantFeedAccess(ORIGIN, { source: 'user' })),
    main('hasFeedGrant', { key: ORIGIN }, 'hasFeedGrant', (ref) => ref.feedStore.hasFeedGrant(ORIGIN)),
    main('grantFeedAccess', { key: OTHER }, 'grantFeedAccess', (ref) => ref.feedStore.grantFeedAccess(OTHER, { source: 'user' })),
    main('createAppScopedIdentityAt', { key: ENS, index: 1000, options: { activate: true } }, 'createAppScopedIdentityAt',
      (ref) => ref.feedStore.createAppScopedIdentityAt(ENS, 1000, { activate: true, source: 'user' })),
    main('getOriginIdentityStateWithOwners', { key: ENS }, 'getOriginIdentityStateWithOwners', (ref) => ref.feedStore.getOriginIdentityStateWithOwners(ENS)),
  ] });
  out.push(...referenceCases(env));
  out.push(...ownerOrderCases(env));
  out.push(...detachCases(env));
  return out;
}

/**
 * getEthereumWalletIdentityReferences (accounts.remove's references): the
 * active ones first, then by site in localeCompare's order (ICU: punctuation
 * and symbols, digits, letters case-blind, then small before capital), feed
 * names by code unit; and its wallet-index refusals. A site outside
 * printable ASCII is deviation `collation`: the core sorts it by code unit.
 */
function referenceCases(env) {
  const { feedStore, originEntry, identity } = C;
  const eth = (index) => identity('ethereum-wallet', index);
  const app0 = identity('app-scoped', 0);
  const feedOf = (identityId) => ({ topic: 'ab'.repeat(32), owner: env.keyOf('bee').address, manifestReference: C.MANIFEST, identityId,
    createdAt: T0, lastUpdated: null, lastReference: null });
  // Sites holding ethereum-wallet identities of index 0: active, or with feeds.
  const site = (active, feeds = {}) => originEntry(active ? eth(0) : app0, { identities: active ? [eth(0)] : [app0, eth(0)], feeds });
  const sites = {
    'https://b.example': site(false, { b: feedOf(eth(0).id), B: feedOf(eth(0).id), a: feedOf(eth(0).id), z: feedOf(app0.id) }),
    'https://A.example': site(true),
    'https://a.example': site(false, { only: feedOf(eth(0).id) }),
    'https://B.example': site(false, { w: feedOf(eth(0).id) }),
    'https://a-b.example': site(false, { x: feedOf(eth(0).id) }),
    'https://a_b.example': site(true),
    'https://a.b.example': site(false, { y: feedOf(eth(0).id) }),
    'https://a1.example': site(false, { n: feedOf(eth(0).id) }),
    'ens:z.eth': site(true),
    'ens:Z.eth': site(false, { q: feedOf(eth(0).id) }),
    'https://unused.example': site(false),
    'https://other-wallet.example': originEntry(eth(1), { feeds: { f: feedOf(eth(1).id) } }),
  };
  const references = (id, store, index, over = {}) => ({ id, method: 'swarm.identities', feeds: json(store), ...over, steps: [
    { op: 'getEthereumWalletIdentityReferences', members: index === undefined ? {} : { wallet_index: index }, call: 'getEthereumWalletIdentityReferences',
      run: (ref) => ref.feedStore.getEthereumWalletIdentityReferences(index) },
  ] });
  const out = [];
  out.push(references('identities-references-order', feedStore(sites, 1), 0));
  out.push(references('identities-references-other-index', feedStore(sites, 1), 1));
  out.push(references('identities-references-none', feedStore({}, 0), 0));
  // The root order the reference's localeCompare gives these sites must be
  // ICU root's on this machine (a locale that orders ASCII otherwise is the
  // `collation` deviation, which these cases don't record).
  const keys = Object.keys(sites);
  const root = new Intl.Collator('und');
  for (const a of keys) for (const b of keys) assert.equal(Math.sign(a.localeCompare(b)), Math.sign(root.compare(a, b)), `the default locale orders ${a} and ${b} as root`);
  // collation: sites outside printable ASCII. ICU orders é with e; the core
  // by code unit, after z.
  const accented = {
    'ens:é.eth': site(false, { e: feedOf(eth(0).id) }),
    'ens:z.eth': site(false, { z: feedOf(eth(0).id) }),
    'ens:e.eth': site(false, { d: feedOf(eth(0).id) }),
    'ens:ä.eth': site(false, { c: feedOf(eth(0).id) }),
  };
  const collation = references('identities-references-collation', feedStore(accented, 1), 0);
  out.push(collation);
  for (const [id, index] of [['negative', -1], ['fraction', 1.5], ['string', '0'], ['missing', undefined], ['nan', NaN], ['null', null], ['infinity', Infinity]]) {
    out.push(references(`identities-references-wallet-index-${id}`, feedStore(sites, 1), index));
  }
  return out;
}

/**
 * owner-read-order: an identities answer that reads owners. The reference's
 * handler holds the site's withOriginLock across its change and the owners'
 * reads, so a revoke on the same site waits for it; the core reads the
 * answer when its last owner arrives, so the revoke made meanwhile shows.
 * The two handlers run at once: the create's owners are still being read
 * when the revoke arrives.
 */
function ownerOrderCases() {
  const { identity, feedStore, originEntry, OTHER } = C;
  const bee = identity('bee-wallet');
  return [{
    id: 'identities-owner-read-order', method: 'swarm.identities', concurrent: true,
    feeds: json(feedStore({ [OTHER]: originEntry(bee) }, 0)),
    deviation: 'owner-read-order',
    steps: [
      { caller: 'chrome', op: 'create-app-scoped-identity', members: { origin: OTHER, options: { activate: true } }, call: 'swarm:create-app-scoped-identity' },
      { caller: 'chrome', op: 'revoke-feed-access', members: { origin: OTHER }, call: 'swarm:revoke-feed-access' },
    ],
  }];
}

/**
 * A user's identity switch, or a feed revoke, lets go of what a manifest
 * managed (notifyManifestMutation, detachManagedLater); re-activating the
 * active identity doesn't. The reference detaches later, the core right
 * after the change (detach-timing). Each step's files are recorded as the
 * handler answers; where the detach hadn't run by then (a revoke's), the
 * case is marked, and its core files are the reference's once it ran.
 */
function detachCases() {
  const { identity, feedStore, originEntry } = C;
  const site = `bzz://${'5a'.repeat(32)}`;
  const bee = identity('bee-wallet');
  const app0 = identity('app-scoped', 0);
  const managed = json({ version: 1, records: { [site]: {
    managed: { connection: ['feeds'], identity: ['feeds'], feedGrant: ['feeds'] },
    acknowledged: { feeds: { decision: 'managed', source: 'sheet', whyShown: 'To keep your notes', decidedAt: T0 - 1000 } },
    revision: 1,
  } } });
  const feeds = json(feedStore({ [site]: originEntry(app0, { identities: [bee, app0] }) }, 1));
  const step = (op, members, channel, args) => ({ caller: 'chrome', op, members, call: channel, after: true,
    run: (ref, w) => handler(w, channel)(...args) });
  return [
    { id: 'identities-detach-on-switch', method: 'swarm.identities', feeds, manifests: managed,
      grants: C.connected(site), detach: true, steps: [step('activate-feed-identity', { origin: site, identity_id: 'bee-wallet' }, 'swarm:activate-feed-identity', [site, 'bee-wallet'])] },
    { id: 'identities-detach-on-revoke', method: 'swarm.identities', feeds, manifests: managed,
      grants: C.connected(site), detach: true, steps: [step('revoke-feed-access', { origin: site }, 'swarm:revoke-feed-access', [site])] },
    // Re-activating the active identity changes nothing: nothing to detach.
    { id: 'identities-no-detach-on-same-identity', method: 'swarm.identities', feeds, manifests: managed, grants: C.connected(site), steps: [
      step('activate-feed-identity', { origin: site, identity_id: 'app-scoped:0' }, 'swarm:activate-feed-identity', [site, 'app-scoped:0'])] },
  ];
}

function historyCases() {
  const out = [];
  const seed = async (ref) => {
    ref.history.addEntry({ type: 'data', name: 'Text', status: 'uploading', origin: 'freedom://publish' });
    ref.history.updateEntry(1, { status: 'completed', reference: 'ab'.repeat(32), bzzUrl: `bzz://${'ab'.repeat(32)}`, tagUid: 101, batchIdUsed: C.BATCH_A, bytesSize: 5 });
    ref.history.addEntry({ type: 'file', name: 'notes.txt', status: 'uploading', origin: 'freedom://publish' });
    ref.history.updateEntry(2, { status: 'failed', errorMessage: 'upload failed' });
    ref.history.addEntry({ type: 'chunk', status: 'completed', origin: C.ORIGIN, bytesSize: 9 });
  };
  const list = { caller: 'chrome', op: 'list', call: 'getEntries', run: (ref) => ref.history.getEntries(),
    handler: async (ref, w) => ({ channel: 'swarm:get-publish-history', answer: await handler(w, 'swarm:get-publish-history')() }) };
  const remove = (id, members = { id }) => ({ caller: 'chrome', op: 'remove', members, call: 'removeEntry', run: (ref) => ref.history.removeEntry(id) });
  out.push({ id: 'history-ops', method: 'swarm.history', seed, steps: [
    list,
    remove(2), remove(2), remove('1'), remove(3.5), remove(null), remove(99),
    remove(true), remove({ id: 3 }), remove([]), remove([3, 4]), remove(undefined, {}), remove([3]),
    list,
    { caller: 'chrome', op: 'clear', call: 'clearEntries', run: (ref) => ref.history.clearEntries(),
      handler: async (ref, w) => ({ channel: 'swarm:clear-publish-history', answer: await handler(w, 'swarm:clear-publish-history')() }) },
    list,
  ] });
  // history-blobs: a BLOB cell no writer makes; the reference's getEntries
  // throws on a started_at it can't read (the handler answers `{ success:
  // false }`), the core refuses the read for the BLOB.
  out.push({ id: 'history-list-blob', method: 'swarm.history', deviation: 'history-blobs', seed: async (ref) => {
    ref.history.addEntry({ type: 'data', name: 'a', status: 'completed', origin: C.ORIGIN });
    ref.history.getDb().prepare('UPDATE publishes SET started_at = ? WHERE id = 1').run(Buffer.from('61', 'hex'));
  }, steps: [list] });
  return out;
}

function manifestCases() {
  const { identity, feedStore, originEntry } = C;
  const site = `bzz://${'5a'.repeat(32)}`;
  const url = `${site}/index.html`;
  const other = `bzz://${'6b'.repeat(32)}`;
  const text = (capabilities, extra = {}) => JSON.stringify({ schema: 'freedom-manifest/1', name: 'Freedom Notes', description: 'Notes on Swarm',
    capabilities: { swarm: Object.fromEntries(capabilities.map((c) => [c, { why: `To ${c} your notes` }])) }, ...extra });
  const guest = { isDestroyed: () => false };
  // Each case's steps over its own tokens: a check keeps the token it got,
  // and a later step names it by its place.
  const make = (id, build, over = {}) => () => {
    const tokens = [];
    const check = (key, at, eager) => ({ op: 'check', members: { key, url: at, ...(eager !== undefined ? { eager } : {}) }, call: 'checkPageManifest',
      run: (ref) => ref.manifests.checkPageManifest({ key, url: at, guest, ...(eager !== undefined ? { eager } : {}) }),
      keep: (value) => {
        if (value?.token) tokens.push(value.token);
        return value;
      } });
    const decide = (key, k, outcome, live) => ({ op: 'decide', members: () => ({ key, token: tokens[k], outcome, live }), call: 'decidePageManifest',
      run: (ref) => ref.manifests.decidePageManifest(key, tokens[k], outcome, { recheck: async () => live, holds: () => live }) });
    const release = (k) => ({ op: 'release', members: () => ({ token: tokens[k] }), call: 'releasePageManifest',
      run: (ref) => ref.manifests.releasePageManifest(tokens[k]) });
    const chrome = (op, channel, arg, members) => ({ op, members, call: channel, run: (ref, w) => handler(w, channel)(arg) });
    return { id, method: 'swarm.manifest', grants: {}, ...over, steps: build({ check, decide, release, chrome }) };
  };
  const get = ({ chrome }) => chrome('get', 'swarm:manifest-get', site, { origin: site });
  return [
    make('manifest-page-allow', (m) => [m.check(site, url, true), m.decide(site, 0, 'allow', true), get(m)],
      { feeds: json(feedStore({}, 0)), fetch: fetches([{ text: text(['publish', 'feeds']) }]) }),
    make('manifest-page-individual-deny', (m) => [m.check(site, url, true), m.decide(site, 0, 'individual', true), m.check(site, url, true),
      m.decide(site, 1, 'deny', true), get(m)], { fetch: fetches([{ text: text(['publish', 'messaging']) }, { text: text(['publish', 'messaging', 'signing']) }]) }),
    make('manifest-page-deny-first-contact', (m) => [m.check(site, url, true), m.decide(site, 0, 'deny', true), get(m)],
      { fetch: fetches([{ text: text(['publish']) }]) }),
    make('manifest-page-refused', (m) => [m.check(site, url, true), m.decide(site, 0, 'allow', false), m.decide(site, 0, 'allow', true)],
      { fetch: fetches([{ text: text(['publish']) }]) }),
    make('manifest-page-other-key', (m) => [m.check(site, url, true), m.decide(other, 0, 'allow', true), m.decide(site, 0, 'maybe', true)],
      { fetch: fetches([{ text: text(['publish']) }]) }),
    make('manifest-page-release', (m) => [m.check(site, url, true), m.release(0), m.decide(site, 0, 'allow', true)],
      { fetch: fetches([{ text: text(['publish']) }]) }),
    make('manifest-page-expired', (m) => [m.check(site, url, true), { ...m.decide(site, 0, 'allow', true), clock: T0 + 5 * 60 * 1000 + 1 }],
      { fetch: fetches([{ text: text(['publish']) }]) }),
    make('manifest-page-legacy', (m) => [m.check(site, url, false), m.check('https://app.example', 'https://app.example/', true), m.check(site, url)]),
    make('manifest-page-unresolved', (m) => [m.check(site, url, true), m.check(site, url, true), { ...m.check(site, url, true), clock: T0 + 2001 },
      { ...m.check(site, url, true), clock: T0 + 2002 }, { ...m.check(site, url, true), clock: T0 + 12002 }],
    { fetch: fetches([{ throws: 'fetch failed' }, { status: 502, text: 'bad gateway' }, { text: text(['publish']) }]) }),
    make('manifest-page-ready', (m) => [m.check(site, url, true)], { grants: C.connected(site, { autoApprove: { publish: true, feeds: false, signing: false, messaging: false } }),
      fetch: fetches([{ text: text(['publish']) }]) }),
    make('manifest-page-absent-prunes', (m) => [m.check(site, url, true), m.decide(site, 0, 'allow', true), m.check(site, url, false), get(m)],
      { fetch: fetches([{ text: text(['publish']) }, { status: 404, text: 'Not Found' }]) }),
    make('manifest-page-too-large', (m) => [m.check(site, url, true)], { fetch: fetches([{ text: text(['publish'], { description: 'd'.repeat(9000) }) }]) }),
    make('manifest-page-ethereum-wallet', (m) => [m.check(site, url, true), m.decide(site, 0, 'allow', true)],
      { feeds: json(feedStore({ [site]: originEntry(identity('ethereum-wallet', 0)) })), fetch: fetches([{ text: text(['feeds']) }]) }),
    make('manifest-chrome-handlers', (m) => [m.check(site, url, true), m.decide(site, 0, 'allow', true),
      m.chrome('use-individual', 'swarm:manifest-use-individual', { origin: site, capability: 'feeds' }, { origin: site, capability: 'feeds' }),
      m.chrome('use-individual', 'swarm:manifest-use-individual', { origin: site, capability: 'messaging' }, { origin: site, capability: 'messaging' }),
      m.chrome('use-individual', 'swarm:manifest-use-individual', { origin: site, capability: 'teleport' }, { origin: site, capability: 'teleport' }),
      get(m),
      m.chrome('disconnect', 'swarm:manifest-disconnect', site, { origin: site }),
      get(m)],
    { feeds: json(feedStore({}, 0)), fetch: fetches([{ text: text(['publish', 'feeds']) }]) }),
    // The page consents' bound: 64 wait at once; a 65th check drops the
    // oldest, whose decision is then expired.
    make('manifest-page-consent-bound', (m) => [...Array.from({ length: 65 }, () => m.check(site, url, true)),
      m.decide(site, 0, 'allow', true), m.decide(site, 64, 'allow', true)], { fetch: fetches([{ text: text(['publish']) }]) }),
  ];
}

// ---------------------------------------------------------------------------
// The section.

async function buildShell(env) {
  const out = [];
  for (const spec of [...publishCases(env), ...feedCases(env), ...stampCases(env), ...uploadStatusCases()]) out.push(await nodeCase(env, spec));
  for (const spec of historyPublishCases(env)) out.push(await withHistory(env, spec));
  for (const spec of identityCases(env)) out.push(await identitiesCase(env, spec));
  for (const spec of historyCases()) out.push(await historyCase(env, spec));
  for (const make of manifestCases()) out.push(orderKeys(await opsCase(env, make())));
  return out;
}

async function identitiesCase(env, spec) {
  if (spec.concurrent) return concurrentCase(env, spec);
  const record = await opsCase(env, { ...spec, settle: spec.detach ? (ref) => ref.manifests.getRecord('https://settle.example') : undefined });
  if (spec.detach) {
    // The core detaches right after the change: its files at the answer are
    // the reference's once its detach ran. Where the reference's detach ran
    // before its answer was read (a switch's: the handler's lock awaits it),
    // the two agree and nothing is marked.
    assert.notEqual(record.after.manifests, spec.manifests, `${spec.id}: the record is detached`);
    if (record.steps[0].files.manifests !== record.after.manifests) {
      record.deviation = 'detach-timing';
      record.core = { files: [{ feeds: record.after.feeds, manifests: record.after.manifests }] };
    }
  }
  if (spec.id === 'identities-references-collation') {
    // collation: the core's order, by code unit after the active ones.
    const value = record.steps[0].reference.result;
    const sorted = [...value].sort((a, b) => (a.active !== b.active ? (a.active ? -1 : 1) : (a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : 0)));
    assert.notDeepEqual(sorted, value, `${spec.id}: the code-unit order differs`);
    record.deviation = 'collation';
    record.core = { answers: [typedResult(sorted)] };
  }
  if (spec.deviation && !record.deviation) record.deviation = spec.deviation;
  return orderKeys(record);
}

/** owner-read-order's two handlers at once, and the core's answers. */
async function concurrentCase(env, spec) {
  const world = { feeds: spec.feeds, manifests: null, grants: {}, vault: 'unlocked', clock: T0 };
  return withReference(env, { feeds: spec.feeds, grants: {}, clock: T0, ipc: true }, async (ref, node, w) => {
    ref.feedStore.registerFeedStoreIpc();
    const [create, revoke] = spec.steps;
    const createArgs = [create.members.origin, create.members.options];
    const first = handler(w, create.call)(...createArgs);
    const second = handler(w, revoke.call)(revoke.members.origin);
    const answers = await Promise.allSettled([first, second]);
    const steps = [create, revoke].map((s, k) => {
      const settled = answers[k];
      const step = { caller: s.caller, params: opParams(s.op, s.members), reference: { call: s.call } };
      if (settled.status === 'rejected') step.reference.error = errorRecord(settled.reason);
      else Object.assign(step.reference, answer('result', settled.value));
      step.answer = settled.status === 'rejected' ? typedError(thrown(settled.reason)) : typedResult(settled.value);
      return step;
    });
    // The core reads the create's answer once its owners arrive, after the
    // revoke: the reference's state of the site after both.
    const after = await ref.feedStore.getOriginIdentityStateWithOwners(create.members.origin);
    assert.equal(answers[0].value.feedGranted, true);
    assert.equal(after.feedGranted, false);
    return orderKeys({
      id: spec.id, method: spec.method, world, concurrent: 'step 1 runs while step 0\'s owners are being read; step 0 answers after it',
      steps, after: { ...storeFiles(w.dir), grants: w.grants },
      deviation: 'owner-read-order', core: { answers: [typedResult(after), steps[1].answer] },
    });
  });
}

async function historyCase(env, spec) {
  const record = await opsCase(env, spec);
  if (spec.deviation === 'history-blobs') {
    record.deviation = 'history-blobs';
    record.core = { answers: [typedError({ name: 'Error', message: 'publish-history.sqlite holds a BLOB in column started_at', code: 'history_blob' })] };
  }
  return orderKeys(record);
}

/** A case's members in one order: id, method, deviation, world, steps, core, after. */
function orderKeys(record) {
  const { id, method, deviation, world, concurrent, steps, core, after, ...rest } = record;
  return { id, method, ...(deviation ? { deviation } : {}), world, ...(concurrent ? { concurrent } : {}), steps, ...(core ? { core } : {}), after, ...rest };
}

/**
 * own-keys' core answer for `methods/create-feed-own-key-to-string`: the
 * reference's own new-feed path for the name (handleCreateFeed's history
 * row, createFeed, setFeed, the row's update and its answer), which its
 * inherited-property check skips. In the core every name is an own key, so
 * `toString` is an ordinary new feed.
 */
async function ownKeyCreateFeedCore(env, spec) {
  return withReference(env, spec, async (ref, node, world) => {
    const origin = spec.origin ?? C.ORIGIN;
    const name = 'toString';
    const entry = ref.feedStore.getOriginEntry(origin);
    const identity = entry.identities[entry.activeIdentityId];
    const signer = await ref.load('./swarm-signer.js').resolveSwarmSigner(identity);
    const row = ref.history.addEntry({ type: 'feed-create', name, status: 'uploading', origin });
    const result = await ref.feedService.createFeed(signer, ref.feedService.buildTopicString(origin, name));
    ref.feedStore.setFeed(origin, name, { topic: result.topic, owner: result.owner, manifestReference: result.manifestReference, identityId: identity.id });
    ref.history.updateEntry(row.id, { status: 'completed', ...result });
    const forms = ['stamps', 'feed_manifest'];
    const requests = node.requests.map((r, j) => {
      assert.equal(formOf(r), forms[j], 'createFeed reads /stamps, then posts the manifest');
      return { ...requestRecord(r, node), form: forms[j] };
    });
    assert.equal(requests.length, 2);
    return {
      result: { feedId: name, owner: result.owner, topic: result.topic, manifestReference: result.manifestReference, bzzUrl: result.bzzUrl,
        identityMode: identity.mode },
      requests,
      after: { feeds: fs.readFileSync(path.join(world.dir, 'swarm-feeds.json'), 'utf8'), history: ref.history.getEntries() },
    };
  });
}

module.exports = { buildShell, ownKeyCreateFeedCore, replyRecord, shellError, thrown, stampAnswer };
