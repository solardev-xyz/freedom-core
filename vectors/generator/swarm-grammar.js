'use strict';

// Design 0015's operation grammar (Node access), as data: the forms of
// `shell.swarm_api`, each parent's row, and the requests of the reference
// that the core drops (the named deviations). vectors/swarm-grammar.json is
// written from it, and every request a `methods` case records is checked
// against its row here: its form, the row's order and counts, and the
// values the row binds, the ones main derives from its own replies
// included. Every rule is the design's; the reference is only checked.

const assert = require('node:assert/strict');
const { NODE_URL } = require('./swarm-node');

const HEX64 = '[0-9a-f]{64}';
const HEX40 = '[0-9a-f]{40}';
// What main adds to every call (the transport's own aside).
const MAIN_HEADERS = { accept: 'application/json, text/plain, */*', 'accept-encoding': 'identity' };
const OCTET = 'application/octet-stream';

/**
 * The forms (design 0015, `shell.swarm_api`). `path` names its values;
 * `headers` are `[name, value or pattern, when]`: `when` is `row` (the row
 * says whether), `publish` (under `swarm.publish` only), `soc-raw`
 * (writeSingleOwnerChunk only) or absent (always).
 */
const FORMS = {
  chunk: { method: 'GET', path: '/chunks/<a>', query: [], headers: [], body: null, reply: { whole: 4201 }, annotations: ['feed', 'tree'] },
  bytes: { method: 'GET', path: '/bytes/<a>', query: [], headers: [['range', 'bytes=<s>-<e>', 'row']], body: null, reply: { stream: 'max_bytes' } },
  feed_head: { method: 'GET', path: '/feeds/<o>/<t>', query: [], headers: [['swarm-only-root-chunk', 'true']], body: null,
    reply: { whole: 4201, read: 'headers' } },
  feed_latest: { method: 'GET', path: '/feeds/<o>/<t>', query: [], headers: [], body: null, reply: { stream: 'max_bytes' } },
  tag: { method: 'GET', path: '/tags/<uid>', query: [], headers: [], body: null, reply: { whole: 65536, json: true } },
  addresses: { method: 'GET', path: '/addresses', query: [], headers: [], body: null, reply: { whole: 65536, json: true } },
  stamps: { method: 'GET', path: '/stamps', query: [], headers: [], body: null, reply: { whole: 1048576, json: true } },
  stamp: { method: 'GET', path: '/stamps/<b>', query: [], headers: [], body: null, reply: { whole: 65536, json: true } },
  bzz_file: { method: 'POST', path: '/bzz', query: ['name'], headers: [['content-type', '<content-type>'], ['swarm-postage-batch-id', '<b>'],
    ['swarm-pin', 'true'], ['swarm-deferred-upload', 'true|false'], ['swarm-encrypt', 'true', 'publish']], body: ['base64', 'stream'],
  reply: { whole: 65536, json: true } },
  bzz_tar: { method: 'POST', path: '/bzz', query: [], headers: [['content-type', 'application/x-tar'], ['swarm-collection', 'true'],
    ['swarm-postage-batch-id', '<b>'], ['swarm-pin', 'true'], ['swarm-deferred-upload', 'true'], ['swarm-index-document', '<p>', 'row'],
    ['swarm-encrypt', 'true', 'publish']], body: ['stream'], reply: { whole: 65536, json: true } },
  bytes_up: { method: 'POST', path: '/bytes', query: [], headers: [['content-type', OCTET], ['swarm-postage-batch-id', '<b>']], body: ['stream'],
    reply: { whole: 65536, json: true } },
  chunk_up: { method: 'POST', path: '/chunks', query: [], headers: [['content-type', OCTET], ['swarm-postage-batch-id', '<b>'], ['swarm-pin', 'true'],
    ['swarm-deferred-upload', 'false']], body: ['base64'], body_bytes: [9, 4104], reply: { whole: 65536, json: true } },
  soc_up: { method: 'POST', path: '/soc/<o>/<id>', query: ['sig'], headers: [['content-type', OCTET], ['swarm-postage-batch-id', '<b>'],
    ['swarm-pin', 'true', 'soc-raw'], ['swarm-deferred-upload', 'false', 'soc-raw']], body: ['base64'], body_bytes: [9, 4104],
  reply: { whole: 65536, json: true } },
  feed_manifest: { method: 'POST', path: '/feeds/<o>/<t>', query: [], headers: [['swarm-postage-batch-id', '<b>']], body: null,
    reply: { whole: 65536, json: true } },
  pss_send: { method: 'POST', path: '/pss/send/<t>/<x>', query: ['recipient'], headers: [['content-type', OCTET], ['swarm-postage-batch-id', '<b>']],
    body: ['base64'], body_bytes: [0, 4000], reply: { whole: 65536, json: true } },
};

const VALUES = {
  '<a>': '64 lowercase hex', '<t>': '64 lowercase hex', '<id>': '64 lowercase hex', '<b>': '64 lowercase hex', '<o>': '40 lowercase hex',
  '<uid>': 'a decimal integer from 1 to 2^53 − 1 with no leading zero', '<x>': '4 or 6 lowercase hex',
  sig: '130 lowercase hex', recipient: '66 lowercase hex, a compressed key (^0[23])', name: 'the operation\'s file name, as URLSearchParams encodes it',
  '<s>-<e>': 'decimal byte offsets, s ≤ e',
};

const PATHS = {
  chunk: new RegExp(`^/chunks/(${HEX64})$`),
  bytes: new RegExp(`^/bytes/(${HEX64})$`),
  feed: new RegExp(`^/feeds/(${HEX40})/(${HEX64})$`),
  tag: /^\/tags\/([1-9][0-9]{0,15})$/,
  addresses: /^\/addresses$/,
  stamps: /^\/stamps$/,
  stamp: new RegExp(`^/stamps/(${HEX64})$`),
  bzz: /^\/bzz$/,
  bytes_up: /^\/bytes$/,
  chunk_up: /^\/chunks$/,
  soc: new RegExp(`^/soc/(${HEX40})/(${HEX64})$`),
  pss: new RegExp(`^/pss/send/(${HEX64})/([0-9a-f]{4}|[0-9a-f]{6})$`),
};

/**
 * The rows (design 0015, The operation grammar), as the vectors' readers
 * take them: `ready`, and `calls`, each `{ forms, count: [min, max], when?,
 * binds }` in order. `binds` is the design's text; the checker below holds
 * the reference to it.
 */
const ROWS = {
  readChunk: { ready: 'reachable', calls: [{ forms: ['chunk'], count: [1, 1], binds: '<a> = params.reference' }] },
  readSingleOwnerChunk: { ready: 'reachable', calls: [{ forms: ['chunk'], count: [1, 1],
    binds: '<a> = params.address, or keccak256(params.identifier ‖ params.owner)' }] },
  readData: { ready: 'reachable', calls: [
    { forms: ['chunk'], count: [1, 1], binds: 'the root: <a> = params.reference' },
    // After the root: chunk at most 2 + 2⌈B / 4,096⌉ = 2,562 times (one per
    // slot of the walk's set), and bytes once.
    { forms: ['chunk', 'bytes'], count: [0, 2 + 2 * 1280 + 1], when: 'the root\'s size n is over 4,096 bytes (at most n ≤ B)',
      binds: 'bytes at most once: <a> = params.reference, range: bytes=0-<n − 1>, max_bytes = n; every later chunk with tree { length, depth }, '
        + 'an unfetched occurrence of a data child of an intermediate main returned (0009\'s geometry); chunk at most 2 + 2⌈B / 4,096⌉ = 2,562 after the root, 8 open at once' },
  ] },
  readFeedEntry_index: { ready: 'reachable', calls: [
    { forms: ['chunk'], count: [1, 1], binds: 'with feed { owner, index }: <a> = keccak256(keccak256(<t> ‖ index as 8 bytes BE) ‖ <o>)' },
    { forms: ['bytes'], count: [0, 1], when: 'the size in the SOC\'s wrapped span is over 4,096 bytes',
      binds: '<a> = the address of the chunk the SOC wraps (bytes 97 on of the reply), no range, max_bytes = that size (at most B)' },
  ] },
  readFeedEntry_latest: { ready: 'reachable', calls: [{ forms: ['feed_latest'], count: [1, 1],
    binds: '<t> = params.topic or keccak256(utf8(key + "/" + params.name)); <o> = params.owner when given; max_bytes at most B' }] },
  getUploadStatus: { ready: null, calls: [{ forms: ['tag'], count: [1, 1], binds: '<uid> = params.tagUid' }] },
  getMessagingIdentity: { ready: 'reachable', calls: [{ forms: ['addresses'], count: [1, 1], binds: '' }] },
  publishData: { ready: 'publish', calls: [{ forms: ['stamps'], count: [1, 1], binds: '' }, { forms: ['bzz_file'], count: [1, 1],
    binds: '<n> = params.name, else data; content-type = params.contentType; swarm-deferred-upload: false; the body exactly the data\'s length' }] },
  publishFiles: { ready: 'publish', calls: [{ forms: ['stamps'], count: [1, 1], binds: '' }, { forms: ['bzz_tar'], count: [1, 1],
    binds: 'swarm-index-document = params.indexDocument, else index.html when a top-level file has that name, else none; the body at most T(files)' }] },
  publishChunk: { ready: 'publish', calls: [{ forms: ['stamps'], count: [1, 1], binds: '' }, { forms: ['chunk_up'], count: [1, 1],
    binds: 'the body = span ‖ the data' }] },
  writeSingleOwnerChunk: { ready: 'publish', calls: [{ forms: ['stamps'], count: [1, 1], binds: '' }, { forms: ['soc_up'], count: [1, 1],
    binds: '<id> = params.identifier; the body = span ‖ the data' }] },
  createFeed: { ready: 'publish', calls: [{ forms: ['stamps'], count: [1, 1], binds: '' }, { forms: ['feed_manifest'], count: [1, 1],
    binds: '<t> = keccak256(utf8(key + "/" + params.name))' }] },
  updateFeed: { ready: 'publish', calls: [
    { forms: ['stamps'], count: [1, 1], binds: '' },
    { forms: ['feed_head'], count: [1, 1], binds: '<t> as for createFeed; one <o> throughout, fixed by feed_head' },
    { forms: ['chunk'], count: [0, 81], when: 'after feed_head\'s 404 or 500', binds: 'with feed: each at the SOC address of the index the head probe asks next' },
    { forms: ['soc_up'], count: [1, 1], binds: '<id> = keccak256(<t> ‖ the next index as 8 bytes BE); the body = span ‖ an 8-byte timestamp ‖ params.reference (48 or 80 bytes)' },
  ] },
  writeFeedEntry: { ready: 'publish', calls: [
    { forms: ['stamps'], count: [1, 1], binds: '' },
    { forms: ['chunk'], count: [1, 1], when: 'with index', binds: 'with feed: the SOC address of params.index' },
    { forms: ['feed_head'], count: [1, 1], when: 'without index', binds: 'one <o> throughout, fixed by the first call that names it' },
    { forms: ['chunk'], count: [0, 81], when: 'without index, after feed_head\'s 404 or 500', binds: 'with feed: the probe\'s next index' },
    { forms: ['bytes_up'], count: [0, 1], when: 'data over 4,096 bytes', binds: 'the body exactly the data\'s length' },
    { forms: ['soc_up'], count: [1, 1], binds: '<id> = keccak256(<t> ‖ the write\'s index as 8 bytes BE); the body = span ‖ the data (4,096 bytes or less), '
      + 'else a root chunk whose address is bytes_up\'s reference' },
  ] },
  sendPss: { ready: 'publish', calls: [{ forms: ['stamps'], count: [1, 1], binds: '' }, { forms: ['pss_send'], count: [1, 1],
    binds: '<t> = keccak256(utf8(params.topic)); <x> = params.targets, lowercased; recipient = params.recipient, lowercased; the body = the message' }] },
  sendGsoc: { ready: 'publish', calls: [{ forms: ['stamps'], count: [1, 1], binds: '' }, { forms: ['soc_up'], count: [1, 1],
    binds: '<id> = keccak256(utf8(params.topic)); the body = span ‖ the message' }] },
  subscribe: { ready: 'subscribe', calls: [] },
  getCapabilities: { ready: 'publish', calls: [] },
  requestAccess: { ready: null, calls: [] },
  getSigningIdentity: { ready: null, calls: [] },
  listFeeds: { ready: null, calls: [] },
  'swarm.publish:data,file': { ready: null, calls: [{ forms: ['stamps'], count: [0, 1], when: 'no batch given', binds: '' }, { forms: ['bzz_file'], count: [1, 1],
    binds: '<n> = name, else data for data; content-type = content_type, else text/plain (data) or application/octet-stream (file); '
      + 'swarm-deferred-upload = deferred; swarm-encrypt only when encrypt; the body exactly the part\'s length; with batch, swarm-postage-batch-id = batch' }] },
  'swarm.publish:collection': { ready: null, calls: [{ forms: ['stamps'], count: [0, 1], when: 'no batch given', binds: '' }, { forms: ['bzz_tar'], count: [1, 1],
    binds: 'swarm-index-document = index_document, else index.html when a top-level part has that name; swarm-encrypt only when encrypt; the body at most T(parts)' }] },
  'swarm.feed:create': { ready: null, calls: [{ forms: ['stamps'], count: [0, 1], when: 'no batch given', binds: '' }, { forms: ['feed_manifest'], count: [1, 1], binds: '<t> = topic' }] },
  'swarm.feed:update': { ready: null, calls: [{ forms: ['stamps'], count: [0, 1], when: 'no batch given', binds: '' }, { forms: ['feed_head'], count: [1, 1], binds: '<t> = topic' },
    { forms: ['chunk'], count: [0, 81], when: 'after feed_head\'s 404 or 500', binds: 'the probe\'s next index' },
    { forms: ['soc_up'], count: [1, 1], binds: 'the next index at least min_index; the body ending in reference' }] },
  'swarm.feed:read': { ready: null, calls: [{ forms: ['feed_head'], count: [1, 1], binds: '<t> = topic' },
    { forms: ['chunk'], count: [0, 81], when: 'after feed_head\'s 404', binds: 'the probe\'s next index' }] },
  'swarm.stamps': { ready: null, calls: [{ forms: ['stamps', 'stamp'], count: [1, 1], binds: '<b> = id' }] },
  'swarm.upload_status': { ready: null, calls: [{ forms: ['tag'], count: [1, 1], binds: '<uid> = tag_uid' }] },
};

// The reference's requests the core drops: each named deviation's.
const DEVIATION_REQUESTS = {
  'stamps-one-read': 'the second GET /stamps of a write (selectBestBatch\'s look for a propagating batch)',
  'index-probe': 'the whole GET /feeds/<o>/<t> download of an index lookup (the core asks feed_head, swarm-only-root-chunk: true)',
  'feed-wrap-root': 'GET /chunks/<root> after a feed entry\'s POST /bytes (the core wraps its own root)',
  'read-data-verified': 'readData\'s whole, unranged GET /bytes/<reference> (the core walks the tree and streams the leaves ranged)',
};

// ---------------------------------------------------------------------------
// The checker.

class GrammarError extends Error {
  constructor(message) {
    super(message);
    this.name = 'GrammarError';
  }
}

function fail(ctx, req, message) {
  throw new GrammarError(`${ctx.caseId} step ${ctx.step} (${ctx.row}): ${req ? `${req.method} ${req.path}: ` : ''}${message}`);
}

const pairs = (list) => new Map(list);

/** Whether `req`'s headers are `allowed` ([name, value] list) and main's own, each once. */
function checkHeaders(ctx, req, allowed) {
  const seen = new Set();
  for (const [name, value] of req.headers) {
    if (seen.has(name)) fail(ctx, req, `header ${name} twice`);
    seen.add(name);
    if (MAIN_HEADERS[name] === value) continue;
    const rule = allowed.find(([n]) => n === name);
    if (!rule) fail(ctx, req, `header ${name}: ${value} is outside the form`);
    if (rule[1] instanceof RegExp ? !rule[1].test(value) : rule[1] !== value) fail(ctx, req, `header ${name}: ${value}, the row binds ${rule[1]}`);
  }
  for (const [name, , required] of allowed) {
    if (required === 'required' && !seen.has(name)) fail(ctx, req, `header ${name} missing`);
  }
}

function checkQuery(ctx, req, names) {
  const got = req.query.map(([k]) => k);
  if (got.length !== names.length || got.some((k, i) => k !== names[i])) fail(ctx, req, `query ${JSON.stringify(got)}, the form takes ${JSON.stringify(names)}`);
}

/** The form a request is, by its method and path (null if none). */
function formOf(req) {
  const { method, path: p } = req;
  if (method === 'GET') {
    if (PATHS.chunk.test(p)) return 'chunk';
    if (PATHS.bytes.test(p)) return 'bytes';
    if (PATHS.feed.test(p)) return req.headers.some(([n]) => n === 'swarm-only-root-chunk') ? 'feed_head' : 'feed_latest';
    if (PATHS.tag.test(p)) return 'tag';
    if (PATHS.addresses.test(p)) return 'addresses';
    if (PATHS.stamps.test(p)) return 'stamps';
    if (PATHS.stamp.test(p)) return 'stamp';
  } else if (method === 'POST') {
    if (PATHS.bzz.test(p)) return req.headers.some(([n, v]) => n === 'swarm-collection' && v === 'true') ? 'bzz_tar' : 'bzz_file';
    if (PATHS.bytes_up.test(p)) return 'bytes_up';
    if (PATHS.chunk_up.test(p)) return 'chunk_up';
    if (PATHS.soc.test(p)) return 'soc_up';
    if (PATHS.feed.test(p)) return 'feed_manifest';
    if (PATHS.pss.test(p)) return 'pss_send';
  }
  return null;
}

const lower = (s) => String(s).toLowerCase();
const stripHex = (s) => String(s).replace(/^0x/, '').toLowerCase();

/**
 * Checks one step's requests against its row. `ctx`: { env, caseId, step,
 * method, params, origin, feedOwner (the store's feed owner, if any),
 * events }. Returns each request's classification, in order.
 */
function checkStep(ctx, requests) {
  const { env, params } = ctx;
  const out = [];
  let i = 0;
  const peek = () => requests[i];
  const take = (classification) => {
    out.push(classification);
    return requests[i++];
  };
  const name = typeof ctx.method === 'string' ? ctx.method.replace(/^swarm_/, '') : null;
  const indexGiven = params && typeof params === 'object' && params.index !== undefined && params.index !== null;
  ctx.row = name === 'readFeedEntry' ? (indexGiven ? 'readFeedEntry_index' : 'readFeedEntry_latest') : name;
  const row = ROWS[ctx.row];
  if (requests.length === 0) return out;
  if (!row) fail(ctx, requests[0], 'a parent with no row made a node call');
  // The ready check: the reachability probe (GET /node) is shell.swarm_ready,
  // never a form; the publish check is the readiness stub's event.
  if (row.ready === 'reachable' || row.ready === 'subscribe') {
    const first = peek();
    if (!(first.method === 'GET' && first.path === '/node')) fail(ctx, first, `the ${row.ready} check comes first`);
    take({ ready: row.ready });
  } else if (row.ready === 'publish') {
    const ready = ctx.events.find((e) => e.readiness === 'publish');
    if (!ready || ready.after_requests !== ctx.requestsBefore) fail(ctx, requests[0], 'a call before the publish check');
  }
  for (const r of requests) {
    if (r.method === 'GET' && r.path === '/node' && r !== requests[0]) fail(ctx, r, 'a second ready probe');
  }
  const stamps = () => {
    const r = peek();
    if (!r) return false;
    assertForm(ctx, r, 'stamps');
    checkHeaders(ctx, r, []);
    take({ form: 'stamps' });
    // The second read, when no usable batch has room (selectBestBatch's
    // propagating batches), is the reference's alone.
    if (peek() && formOf(peek()) === 'stamps') take({ deviation: 'stamps-one-read' });
    return true;
  };
  if (!peek()) return out;
  switch (ctx.row) {
    case 'readChunk': {
      const r = peek();
      chunkAt(ctx, r, lower(params.reference));
      take({ form: 'chunk' });
      break;
    }
    case 'readSingleOwnerChunk': {
      const r = peek();
      const address = params.address !== undefined && params.address !== null ? lower(params.address)
        : env.core.makeSOCAddress(new env.core.Identifier(params.identifier), new env.core.EthAddress(stripHex(params.owner))).toHex();
      chunkAt(ctx, r, address);
      take({ form: 'chunk' });
      break;
    }
    case 'readData': {
      const root = peek();
      chunkAt(ctx, root, lower(params.reference));
      take({ form: 'chunk' });
      if (peek()) {
        const r = peek();
        assertForm(ctx, r, 'bytes');
        if (r.path !== `/bytes/${lower(params.reference)}`) fail(ctx, r, 'bytes at another address than params.reference');
        const size = spanSize(root.replyBody);
        if (!(size > 4096n)) fail(ctx, r, 'bytes for data of 4,096 bytes or less');
        checkHeaders(ctx, r, []);
        // Unranged: the node's whole join, which the core never asks for.
        take({ deviation: 'read-data-verified' });
      }
      break;
    }
    case 'readFeedEntry_index': {
      const r = peek();
      const { topic, owner } = feedOf(ctx);
      const address = feedAddress(env, topic, owner, params.index);
      chunkAt(ctx, r, address);
      take({ form: 'chunk', feed: { owner, index: params.index } });
      if (peek()) {
        const b = peek();
        assertForm(ctx, b, 'bytes');
        const soc = r.replyBody;
        const span = soc.subarray(97, 105);
        const wrapped = env.core.makeContentAddressedChunk(soc.subarray(105), span.readBigUInt64LE(0)).address.toHex();
        if (b.path !== `/bytes/${wrapped}`) fail(ctx, b, 'bytes at another address than the wrapped chunk\'s');
        if (!(spanSize(soc.subarray(97)) > 4096n)) fail(ctx, b, 'bytes for an entry of 4,096 bytes or less');
        checkHeaders(ctx, b, []);
        take({ form: 'bytes', max_bytes: Number(spanSize(soc.subarray(97))) });
      }
      break;
    }
    case 'readFeedEntry_latest': {
      const r = peek();
      assertForm(ctx, r, 'feed_latest');
      const { topic, owner } = feedOf(ctx);
      if (r.path !== `/feeds/${owner}/${topic}`) fail(ctx, r, 'another feed than the row binds');
      checkHeaders(ctx, r, []);
      take({ form: 'feed_latest' });
      break;
    }
    case 'getUploadStatus': {
      const r = peek();
      assertForm(ctx, r, 'tag');
      if (r.path !== `/tags/${params.tagUid}`) fail(ctx, r, 'another tag than params.tagUid');
      checkHeaders(ctx, r, []);
      take({ form: 'tag' });
      break;
    }
    case 'getMessagingIdentity': {
      const r = peek();
      assertForm(ctx, r, 'addresses');
      checkHeaders(ctx, r, []);
      take({ form: 'addresses' });
      break;
    }
    case 'publishData': {
      if (!stamps() || !peek()) break;
      const r = peek();
      assertForm(ctx, r, 'bzz_file');
      checkQuery(ctx, r, ['name']);
      const expectName = params.name || 'data';
      if (pairs(r.query).get('name') !== String(expectName)) fail(ctx, r, `name ${pairs(r.query).get('name')}, the row binds ${expectName}`);
      checkHeaders(ctx, r, [['content-type', params.contentType], ['swarm-postage-batch-id', new RegExp(`^${HEX64}$`)], ['swarm-pin', 'true'],
        ['swarm-deferred-upload', 'false']]);
      const data = dataBytes(params.data);
      if (Buffer.compare(r.body, data) !== 0) fail(ctx, r, 'the body is not the data');
      take({ form: 'bzz_file' });
      break;
    }
    case 'publishFiles': {
      if (!stamps() || !peek()) break;
      const r = peek();
      assertForm(ctx, r, 'bzz_tar');
      checkQuery(ctx, r, []);
      const files = params.files;
      const index = params.indexDocument || (files.some((f) => f.path === 'index.html') ? 'index.html' : null);
      const allowed = [['content-type', 'application/x-tar'], ['swarm-collection', 'true'], ['swarm-postage-batch-id', new RegExp(`^${HEX64}$`)],
        ['swarm-pin', 'true'], ['swarm-deferred-upload', 'true']];
      if (index) allowed.push(['swarm-index-document', index]);
      checkHeaders(ctx, r, allowed);
      if (index && !r.headers.some(([n]) => n === 'swarm-index-document')) fail(ctx, r, 'the index document is missing');
      const bound = 1024 + files.reduce((t, f) => t + 1024 + Math.ceil(Buffer.byteLength(f.path) / 512) * 512
        + Math.ceil(dataBytes(f.bytes).length / 512) * 512, 0);
      if (r.body.length > bound) fail(ctx, r, `the tar is past T(files) = ${bound}`);
      take({ form: 'bzz_tar' });
      break;
    }
    case 'publishChunk': {
      if (!stamps() || !peek()) break;
      const r = peek();
      assertForm(ctx, r, 'chunk_up');
      checkHeaders(ctx, r, [['content-type', OCTET], ['swarm-postage-batch-id', new RegExp(`^${HEX64}$`)], ['swarm-pin', 'true'],
        ['swarm-deferred-upload', 'false']]);
      const data = dataBytes(params.data);
      const span = Buffer.alloc(8);
      span.writeBigUInt64LE(params.span ? BigInt(params.span) : BigInt(data.length)); // a span of 0, or none, is the data's length (core-sdk)
      if (Buffer.compare(r.body, Buffer.concat([span, data])) !== 0) fail(ctx, r, 'the body is not span ‖ the data');
      take({ form: 'chunk_up' });
      break;
    }
    case 'writeSingleOwnerChunk':
    case 'sendGsoc': {
      if (!stamps() || !peek()) break;
      const r = peek();
      assertForm(ctx, r, 'soc_up');
      const [, , ownerHex, id] = r.path.split('/');
      const expectId = ctx.row === 'sendGsoc' ? keccakUtf8(env, params.topic) : lower(params.identifier);
      if (id !== expectId) fail(ctx, r, 'another <id> than the row binds');
      checkQuery(ctx, r, ['sig']);
      if (!/^[0-9a-f]{130}$/.test(pairs(r.query).get('sig'))) fail(ctx, r, 'sig is not 130 hex');
      const allowed = [['content-type', OCTET], ['swarm-postage-batch-id', new RegExp(`^${HEX64}$`)]];
      if (ctx.row === 'writeSingleOwnerChunk') allowed.push(['swarm-pin', 'true'], ['swarm-deferred-upload', 'false']);
      checkHeaders(ctx, r, allowed);
      const data = dataBytes(params.data);
      const span = Buffer.alloc(8);
      span.writeBigUInt64LE(params.span ? BigInt(params.span) : BigInt(data.length)); // a span of 0, or none, is the data's length (core-sdk)
      if (Buffer.compare(r.body, Buffer.concat([span, data])) !== 0) fail(ctx, r, 'the body is not span ‖ the data');
      take({ form: 'soc_up', owner: ownerHex });
      break;
    }
    case 'createFeed': {
      if (!stamps() || !peek()) break;
      const r = peek();
      assertForm(ctx, r, 'feed_manifest');
      const topic = env.beeJs.Topic.fromString(`${ctx.origin}/${params.name}`).toHex();
      if (!r.path.endsWith(`/${topic}`)) fail(ctx, r, 'another topic than keccak256(key/name)');
      checkHeaders(ctx, r, [['swarm-postage-batch-id', new RegExp(`^${HEX64}$`)]]);
      take({ form: 'feed_manifest' });
      break;
    }
    case 'updateFeed':
    case 'writeFeedEntry': {
      if (!stamps() || !peek()) break;
      const name = ctx.row === 'updateFeed' ? params.feedId : params.name;
      const topic = env.beeJs.Topic.fromString(`${ctx.origin}/${name}`).toHex();
      let owner = null;
      let writeIndex = null;
      if (ctx.row === 'writeFeedEntry' && indexGiven) {
        const r = peek();
        owner = stripHex(ctx.feedOwner || '');
        chunkAt(ctx, r, feedAddress(env, topic, owner, params.index));
        take({ form: 'chunk', feed: { owner, index: params.index } });
        if (r.status !== 404 || !peek()) break;
        writeIndex = params.index;
      } else {
        // The index lookup: the reference downloads the latest payload whole
        // (index-probe); the core asks feed_head for the same index.
        const r = peek();
        if (formOf(r) !== 'feed_latest') fail(ctx, r, 'the index lookup is not GET /feeds');
        const [, , o, t] = r.path.split('/');
        if (t !== topic) fail(ctx, r, 'another topic than keccak256(key/name)');
        if (o !== stripHex(ctx.feedOwner || '')) fail(ctx, r, 'another owner than the feed\'s identity');
        owner = o;
        checkHeaders(ctx, r, []);
        take({ deviation: 'index-probe' });
        if (!peek()) break;
        if (r.status >= 200 && r.status < 300) {
          const index = r.replyHeaders?.['swarm-feed-index'];
          writeIndex = index && r.replyHeaders['swarm-feed-index-next'] ? Number(BigInt(`0x${index}`)) + 1 : null;
        } else if (r.status === 404 || r.status === 500) {
          writeIndex = probeRun(ctx, requests, () => i, (c) => take(c), env, topic, owner);
        } else {
          break;
        }
        if (writeIndex === undefined) break;
      }
      if (!peek()) break;
      const data = ctx.row === 'writeFeedEntry' ? dataBytes(params.data) : null;
      let root = null;
      if (data && data.length > 4096) {
        const up = peek();
        assertForm(ctx, up, 'bytes_up');
        checkHeaders(ctx, up, [['content-type', OCTET], ['swarm-postage-batch-id', new RegExp(`^${HEX64}$`)]]);
        if (Buffer.compare(up.body, data) !== 0) fail(ctx, up, 'the body is not the data');
        take({ form: 'bytes_up' });
        if (!peek()) break;
        root = JSON.parse(up.replyBody.toString()).reference;
        const back = peek();
        if (!(back.method === 'GET' && back.path === `/chunks/${root}`)) fail(ctx, back, 'after bytes_up, the reference reads its root back');
        take({ deviation: 'feed-wrap-root' });
        if (!peek()) break;
      }
      const s = peek();
      assertForm(ctx, s, 'soc_up');
      const [, , o, id] = s.path.split('/');
      if (owner !== null && o !== owner) fail(ctx, s, 'a second <o> within one request');
      if (writeIndex === null || id !== feedIdentifierHex(env, topic, writeIndex)) fail(ctx, s, `<id> is not keccak256(<t> ‖ ${writeIndex})`);
      checkQuery(ctx, s, ['sig']);
      checkHeaders(ctx, s, [['content-type', OCTET], ['swarm-postage-batch-id', new RegExp(`^${HEX64}$`)]]);
      if (ctx.row === 'updateFeed') {
        if (s.body.length !== 8 + 8 + 32 || !s.body.subarray(16).equals(Buffer.from(lower(params.reference), 'hex'))) {
          fail(ctx, s, 'the body is not span ‖ timestamp ‖ params.reference');
        }
      } else if (root) {
        const span = s.body.readBigUInt64LE(0);
        const address = env.core.makeContentAddressedChunk(s.body.subarray(8), span).address.toHex();
        if (address !== root) fail(ctx, s, 'the SOC wraps another root than bytes_up\'s reference');
      } else {
        const span = Buffer.alloc(8);
        span.writeBigUInt64LE(BigInt(data.length));
        if (Buffer.compare(s.body, Buffer.concat([span, data])) !== 0) fail(ctx, s, 'the body is not span ‖ the data');
      }
      take({ form: 'soc_up', index: writeIndex });
      break;
    }
    case 'sendPss': {
      if (!stamps() || !peek()) break;
      const r = peek();
      assertForm(ctx, r, 'pss_send');
      const [, , , t, x] = r.path.split('/');
      if (t !== keccakUtf8(env, params.topic)) fail(ctx, r, '<t> is not keccak256(utf8(topic))');
      if (x !== lower(params.targets)) fail(ctx, r, '<x> is not params.targets, lowercased');
      checkQuery(ctx, r, ['recipient']);
      const recipient = pairs(r.query).get('recipient');
      if (recipient !== stripHex(params.recipient) || !/^0[23][0-9a-f]{64}$/.test(recipient)) fail(ctx, r, 'recipient is not the compressed key, lowercased');
      checkHeaders(ctx, r, [['content-type', OCTET], ['swarm-postage-batch-id', new RegExp(`^${HEX64}$`)]]);
      if (Buffer.compare(r.body, dataBytes(params.data)) !== 0) fail(ctx, r, 'the body is not the message');
      take({ form: 'pss_send' });
      break;
    }
    default:
      break;
  }
  if (i < requests.length) fail(ctx, requests[i], 'a call past the row');
  return out;
}

// The head probe's cap (design 0015, Values main derives).
const MAX_PROBE_READS = 81;

/** The head probe, as main replays it over its own answers (probeFeedHead). */
function probeRun(ctx, requests, at, take, env, topic, owner) {
  const MAX = 2 ** 40;
  const ask = (index) => {
    const r = requests[at()];
    if (!r) return null;
    chunkAt(ctx, r, feedAddress(env, topic, owner, index));
    take({ form: 'chunk', feed: { owner, index } });
    if (r.status === 404) return false;
    if (r.status >= 200 && r.status < 300) return true;
    return null;
  };
  // The reference's longest run is 81 reads (42 to grow to 2^40, then 39
  // halvings); an 82nd is past the row.
  let reads = 0;
  const exists = (index) => {
    reads += 1;
    if (reads > MAX_PROBE_READS) fail(ctx, requests[at()], 'an 82nd probe');
    return ask(index);
  };
  const first = exists(0);
  if (first === null) return undefined;
  if (!first) return 0;
  let lo = 0;
  let hi = 1;
  for (;;) {
    if (hi > MAX) return undefined;
    const e = exists(hi);
    if (e === null) return undefined;
    if (!e) break;
    lo = hi;
    hi *= 2;
  }
  while (hi - lo > 1) {
    const mid = lo + Math.floor((hi - lo) / 2);
    const e = exists(mid);
    if (e === null) return undefined;
    if (e) lo = mid;
    else hi = mid;
  }
  return lo + 1;
}

function assertForm(ctx, req, form) {
  const got = formOf(req);
  if (got !== form) fail(ctx, req, `form ${got}, the row expects ${form}`);
}

function chunkAt(ctx, req, address) {
  if (!req) fail(ctx, null, 'a call is missing');
  assertForm(ctx, req, 'chunk');
  if (req.path !== `/chunks/${address}`) fail(ctx, req, `another address than the row binds (${address})`);
  checkHeaders(ctx, req, []);
}

function spanSize(bytes) {
  if (!bytes || bytes.length < 8) return -1n;
  const span = Buffer.from(bytes.subarray(0, 8));
  if (span[7] > 128) span[7] = 0;
  return span.readBigUInt64LE(0);
}

function feedOf(ctx) {
  const { params, env } = ctx;
  const topic = params.topic !== undefined && params.topic !== null ? lower(params.topic)
    : env.beeJs.Topic.fromString(`${ctx.origin}/${params.name}`).toHex();
  const owner = params.owner ? stripHex(params.owner) : stripHex(ctx.feedOwner || '');
  return { topic, owner };
}

function feedIdentifierHex(env, topicHex, index) {
  const feedIndex = env.beeJs.FeedIndex.fromBigInt(BigInt(index));
  return Buffer.from(env.core.keccak256(Buffer.concat([Buffer.from(topicHex, 'hex'), Buffer.from(feedIndex.toUint8Array())]))).toString('hex');
}

function feedAddress(env, topicHex, ownerHex, index) {
  return env.core.makeSOCAddress(new env.core.Identifier(feedIdentifierHex(env, topicHex, index)), new env.core.EthAddress(ownerHex)).toHex();
}

function keccakUtf8(env, text) {
  return Buffer.from(env.core.keccak256(Buffer.from(text, 'utf8'))).toString('hex');
}

/** A param's data as the reference sends it (normalizeBytes, or a string's UTF-8). */
function dataBytes(value) {
  if (typeof value === 'string') return Buffer.from(value, 'utf-8');
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  if (value && value.type === 'Buffer' && Array.isArray(value.data)) return Buffer.from(value.data);
  return Buffer.alloc(0);
}

module.exports = { FORMS, ROWS, VALUES, DEVIATION_REQUESTS, MAIN_HEADERS, MAX_PROBE_READS, checkStep, formOf, feedAddress, feedIdentifierHex, keccakUtf8, GrammarError, NODE_URL };
