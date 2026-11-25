'use strict';

// The `methods` cases of vectors/swarm.json (design 0015, SWM-1): each
// method's honest paths, its tables of bad params (one failing check per
// row, every later check failing too where it can, so the first failure
// pins the order), the state checks after them (grants, identities, SW-1,
// readiness, the vault), the node's answers, the dispatcher's approval path
// (prompts, rules, Agent custody, the rechecks before an effect), and the
// design's deviations. The worlds are scripted here; every outcome is the
// reference's.

const MiB = 1024 * 1024;
const T0 = 1767225600123; // 2026-01-01T00:00:00.123Z
const ORIGIN = 'https://app.example';
const OTHER = 'https://other.example';
const ENS = 'myapp.eth';
const BATCH_A = 'a1'.repeat(32);
const BATCH_B = 'b2'.repeat(32);
const BATCH_C = 'c3'.repeat(32);
const MANIFEST = 'cd'.repeat(32);
const REF = 'ef'.repeat(32);

/** A raw `/stamps` batch, as a node answers it. */
function batch(over = {}) {
  return {
    batchID: BATCH_A, utilization: 0, usable: true, label: 'freedom', depth: 22, amount: '100000000000',
    bucketDepth: 16, blockNumber: 1000, immutableFlag: true, exists: true, batchTTL: 864000, ...over,
  };
}

const STAMPS = {
  usable: { stamps: [batch()] },
  none: { stamps: [] },
  // Usable, room for a few MiB only (depth 18 holds 6.09 MB).
  small: { stamps: [batch({ batchID: BATCH_B, depth: 18 })] },
  // Two usable batches: the longer TTL wins.
  two: { stamps: [batch({ batchID: BATCH_B, batchTTL: 1000 }), batch({ batchTTL: 2000 })] },
  // Not usable, no flag: bee's "exists, awaiting confirmations" shape.
  pending: { stamps: [batch({ usable: false })] },
  // Not usable, but propagating (Ant v0.5.52+): uploads may use it.
  propagating: { stamps: [batch({ batchID: BATCH_C, usable: false, propagating: true })] },
  // A usable mutable batch with every bucket full: messaging may still use it.
  fullMutable: { stamps: [batch({ batchID: BATCH_B, immutableFlag: false, depth: 20, bucketDepth: 16, utilization: 16 })] },
  // A field bee-js's schema requires is missing.
  missingLabel: { stamps: [(({ label, ...rest }) => rest)(batch())] },
};

const NOT_READY = ['node-stopped', 'node-not-ready', 'ultra-light-mode', 'no-usable-stamps'];

function grant(origin, over = {}) {
  return {
    origin, connectedAt: T0 - 60000, lastUsed: T0 - 60000,
    autoApprove: { publish: false, feeds: false, signing: false, messaging: false }, ...over,
  };
}
const connected = (origin, over) => ({ [origin]: grant(origin, over) });
const messagingGrant = (origin = ORIGIN) => connected(origin, { messaging: true });

function identity(mode, index = null) {
  return {
    id: mode === 'bee-wallet' ? 'bee-wallet' : (mode === 'app-scoped' ? `app-scoped:${index}` : `ethereum-wallet:${index}`),
    mode,
    publisherKeyIndex: mode === 'app-scoped' ? index : null,
    walletIndex: mode === 'ethereum-wallet' ? index : null,
    label: mode === 'bee-wallet' ? 'Bee wallet identity' : (mode === 'app-scoped' ? `App-scoped identity ${index + 1}` : 'Ethereum wallet'),
    createdAt: T0 - 50000,
    lastUsedAt: null,
  };
}

/** The feed store's file, as feed-store.js writes it. */
function feedStore(origins, next = 0) {
  return { version: 2, nextPublisherKeyIndex: next, origins };
}

function originEntry(active, { identities, feedGranted = true, feeds = {} } = {}) {
  const list = identities || [active];
  return {
    activeIdentityId: active.id,
    identities: Object.fromEntries(list.map((i) => [i.id, i])),
    feedGranted,
    grantedAt: T0 - 50000,
    feeds,
  };
}

/** A whole case list, given the environment (env.topicHex, env.keyOf). */
function methodCases(env) {
  const { keyOf } = env;
  const topicHex = (origin, name) => env.beeJs.Topic.fromString(`${origin}/${name}`).toHex();
  const owner = (key) => keyOf(key).address;
  const ownerHex = (key) => keyOf(key).address.slice(2).toLowerCase();
  const feedRecord = (origin, name, idOf, key, over = {}) => ({
    topic: topicHex(origin, name), owner: owner(key), manifestReference: MANIFEST, identityId: idOf,
    createdAt: T0 - 40000, lastUpdated: null, lastReference: null, ...over,
  });
  const bytes = (seed, n) => env.seeded(seed, n);
  const u8 = (text) => new Uint8Array(Buffer.from(text, 'utf8'));
  const cases = [];
  const add = (c) => cases.push(c);
  // The vault's auto-lock fires after the dispatcher's checks, as main hands
  // the request to the service: the service meets a locked vault, which no
  // page reaches otherwise (the dispatcher unlocks first).
  const LOCKS = { at_execute: { vault: 'locked' } };
  // A connected site with standing rules (its "always allow").
  const rule = (flags, origin = ORIGIN, over = {}) => connected(origin, {
    autoApprove: { publish: false, feeds: false, signing: false, messaging: false, ...flags }, ...over });

  // Stores the feed cases share.
  const bee = identity('bee-wallet');
  const app0 = identity('app-scoped', 0);
  const app1 = identity('app-scoped', 1);
  const app2 = identity('app-scoped', 2);
  const eth = identity('ethereum-wallet', 0);
  const storeBee = (feeds = {}, granted = true) => feedStore({ [ORIGIN]: originEntry(bee, { feedGranted: granted, feeds }) });
  const storeApp = (feeds = {}, next = 1) => feedStore({ [ORIGIN]: originEntry(app0, { feeds }) }, next);
  const blogBee = { blog: feedRecord(ORIGIN, 'blog', 'bee-wallet', 'bee') };
  const blogApp = { blog: feedRecord(ORIGIN, 'blog', 'app-scoped:0', 'publisher:0') };

  // -------------------------------------------------------------------------
  // executeSwarmMethod's own checks of the method: no page reaches them
  // (page-requests.js answers a method it has no row for), so they run with
  // no meta (page: false).
  add({ id: 'method-missing', method: undefined, params: () => ({}) });
  add({ id: 'method-not-a-string', method: 42, params: () => ({}) });
  add({ id: 'method-unknown', method: 'swarm_mint', params: () => ({}) });
  add({ id: 'method-unknown-prototype', method: 'toString', params: () => ({}) });
  add({ id: 'method-unknown-case', method: 'swarm_ReadChunk', params: () => ({}) });

  // -------------------------------------------------------------------------
  // requestAccess, getCapabilities.
  add({ id: 'request-access-connected', method: 'swarm_requestAccess', params: () => undefined });
  add({ id: 'request-access-not-connected', method: 'swarm_requestAccess', params: () => undefined, grants: {} });
  add({ id: 'request-access-ens-key', method: 'swarm_requestAccess', origin: ENS, grants: connected(ENS), params: () => ({}) });
  add({ id: 'request-access-other-site', method: 'swarm_requestAccess', params: () => ({}), grants: connected(OTHER) });
  add({ id: 'request-access-rejected', method: 'swarm_requestAccess', params: () => undefined, grants: {},
    prompts: [{ kind: 'swarm.connect', approve: false }] });
  // A bzz: site's permission manifest (main's own check, eager for
  // requestAccess): its consent is main's prompt (swarm.manifest), decided
  // on the user's answer: managed by the manifest, one by one, or denied.
  const BZZ = `bzz://${'5a'.repeat(32)}`;
  const manifest = { schema: 'freedom-manifest/1', name: 'Notes', description: 'A notes app',
    capabilities: { swarm: { publish: { why: 'Saves your notes' }, messaging: { why: 'Syncs between devices' } } } };
  const ma = (id, over) => add({ id: `request-access-manifest-${id}`, method: 'swarm_requestAccess', params: () => undefined, origin: BZZ, grants: {},
    manifest, ...over });
  ma('allow', {});
  ma('individual', { prompts: [{ kind: 'swarm.manifest', approve: true, choices: { outcome: 'individual' } }] });
  ma('denied', { prompts: [{ kind: 'swarm.manifest', approve: false }] });
  ma('absent', { manifest: undefined });
  add({ id: 'request-access-keyless', method: 'swarm_requestAccess', params: () => undefined, keyless: true });
  add({ id: 'request-access-identity-wallet-off', method: 'swarm_requestAccess', params: () => undefined, identity_wallet: false });
  add({ id: 'capabilities-keyless', method: 'swarm_getCapabilities', params: () => undefined, keyless: true });
  add({ id: 'capabilities-grants-unavailable', method: 'swarm_getCapabilities', params: () => undefined, grants_unavailable: true });
  add({ id: 'capabilities-connected-ready', method: 'swarm_getCapabilities', params: () => undefined });
  add({ id: 'capabilities-not-connected', method: 'swarm_getCapabilities', params: () => undefined, grants: {} });
  for (const reason of NOT_READY) {
    add({ id: `capabilities-${reason}`, method: 'swarm_getCapabilities', params: () => undefined, readiness: { ok: false, reason } });
  }
  add({ id: 'capabilities-readiness-throws', method: 'swarm_getCapabilities', params: () => undefined, readiness: 'throws' });
  add({ id: 'capabilities-not-connected-not-ready', method: 'swarm_getCapabilities', params: () => undefined, grants: {},
    readiness: { ok: false, reason: 'node-stopped' } });

  // The grant comes before every gated method's params.
  for (const method of ['swarm_publishData', 'swarm_publishFiles', 'swarm_publishChunk', 'swarm_getUploadStatus',
    'swarm_createFeed', 'swarm_updateFeed', 'swarm_writeFeedEntry', 'swarm_writeSingleOwnerChunk',
    'swarm_getSigningIdentity', 'swarm_getMessagingIdentity', 'swarm_sendPss', 'swarm_sendGsoc', 'swarm_subscribe']) {
    add({ id: `not-connected-${method.slice(6)}`, method, params: () => null, grants: {} });
  }
  add({ id: 'not-connected-unsubscribe-without-page', method: 'swarm_unsubscribe', params: () => null, grants: {}, steps: [
    { method: 'swarm_unsubscribe', params: () => null, page: false },
  ] });

  // -------------------------------------------------------------------------
  // publishData.
  const pd = (id, params, over = {}) => add({ id: `publish-data-${id}`, method: 'swarm_publishData', params, node: { stamps: STAMPS.usable }, ...over });
  pd('params-null', () => null);
  pd('params-string', () => 'hello');
  pd('params-array', () => []);
  pd('data-missing', () => ({ contentType: 7 }));
  pd('data-null', () => ({ data: null }));
  pd('content-type-missing', () => ({ data: 42 }));
  pd('content-type-empty', () => ({ data: 42, contentType: '' }));
  pd('content-type-number', () => ({ data: 42, contentType: 5 }));
  pd('data-number', () => ({ data: 42, contentType: 'text/plain' }), { readiness: { ok: false, reason: 'node-stopped' } });
  pd('data-object', () => ({ data: { length: 3 }, contentType: 'text/plain' }), { readiness: { ok: false, reason: 'node-stopped' } });
  pd('data-array', () => ({ data: [1, 2, 3], contentType: 'text/plain' }), { readiness: { ok: false, reason: 'node-stopped' } });
  pd('data-int16array', () => ({ data: new Int16Array([1, 2]), contentType: 'text/plain' }));
  pd('too-large', () => ({ data: bytes('publish-data/10mib', 10 * MiB + 1), contentType: 'application/octet-stream' }),
    { readiness: { ok: false, reason: 'node-stopped' } });
  pd('too-large-string', () => ({ data: 'é'.repeat(5 * MiB + 1), contentType: 'text/plain' }),
    { readiness: { ok: false, reason: 'node-stopped' } });
  for (const reason of NOT_READY) pd(`not-ready-${reason}`, () => ({ data: 'x', contentType: 'text/plain' }), { readiness: { ok: false, reason } });
  pd('readiness-throws', () => ({ data: 'x', contentType: 'text/plain' }), { readiness: 'throws' });
  pd('string', () => ({ data: '<h1>Freedom</h1>', contentType: 'text/html' }));
  pd('string-named', () => ({ data: 'notes', contentType: 'text/plain', name: 'notes.txt' }));
  pd('name-unicode', () => ({ data: 'x', contentType: 'text/plain', name: 'ñandú & co/?#.txt' }));
  pd('name-empty', () => ({ data: 'x', contentType: 'text/plain', name: '' }));
  pd('name-number', () => ({ data: 'x', contentType: 'text/plain', name: 7 }));
  pd('string-empty', () => ({ data: '', contentType: 'text/plain' }));
  pd('string-lone-surrogate', () => ({ data: 'a\ud800b', contentType: 'text/plain' }));
  pd('uint8array', () => ({ data: u8('bytes'), contentType: 'application/octet-stream' }));
  pd('arraybuffer', () => ({ data: u8('an array buffer').buffer, contentType: 'application/octet-stream' }));
  pd('buffer-json', () => ({ data: { type: 'Buffer', data: [104, 105, 256, -1, 'x', 1.7] }, contentType: 'application/octet-stream' }));
  pd('uint8array-view', () => {
    const whole = u8('0123456789');
    return { data: whole.subarray(2, 6), contentType: 'application/octet-stream' };
  });
  pd('content-type-odd', () => ({ data: 'x', contentType: 'TEXT/Plain; charset=latin1' }));
  pd('10mib', () => ({ data: bytes('publish-data/10mib', 10 * MiB), contentType: 'application/octet-stream', name: 'big.bin' }),
    { node: { stamps: STAMPS.usable } });
  pd('extra-params', () => ({ data: 'x', contentType: 'text/plain', encrypt: true, batch: BATCH_B, pin: false }));
  pd('no-stamps', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.none } });
  pd('stamps-pending', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.pending },
    deviation: { id: 'stamps-one-read', core: 'one GET /stamps; the same error' } });
  pd('stamps-propagating', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.propagating },
    deviation: { id: 'stamps-one-read', core: 'one GET /stamps; the same batch and result' } });
  pd('stamps-capacity', () => ({ data: bytes('publish-data/capacity', 5 * MiB), contentType: 'application/octet-stream' }),
    { node: { stamps: STAMPS.small } });
  pd('stamps-longest-ttl', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.two } });
  pd('stamps-full-mutable', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.fullMutable } });
  pd('stamps-malformed', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.missingLabel } });
  pd('stamps-500', () => ({ data: 'x', contentType: 'text/plain' }), { node: { rules: [
    { match: { method: 'GET', path: '/stamps' }, reply: { status: 500, json: { code: 500, message: 'storage incentives unavailable' } } },
  ] } });
  pd('node-500', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 500, json: { code: 500, message: 'chunk store failed' } } },
  ] } });
  pd('node-batch-not-yet-known', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 500, json: { code: 500,
      message: `pushsync: postage batch 0x${BATCH_A} rejected by 3 peer(s) as not found on-chain` } } },
  ] } });
  pd('node-text-error', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 402, statusText: 'Payment Required', body_utf8: 'batch is overissued' } },
  ] } });
  pd('node-json-string-error', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 400, json: 'a JSON string' } },
  ] } });
  pd('node-empty-error', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 503, statusText: 'Service Unavailable' } },
  ] } });
  pd('node-redirect', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 307, headers: { location: 'http://127.0.0.1:9/bzz' } } },
  ] } });
  pd('node-no-reference', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 201, json: { ref: 'nope' } } },
  ] } });
  pd('node-upper-case-reference', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 201, headers: { 'swarm-tag': '7' }, json: { reference: 'AB'.repeat(32) } } },
  ] } });
  pd('node-encrypted-reference', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 201, json: { reference: 'ab'.repeat(64) } } },
  ] } });
  pd('node-not-json', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 201, body_utf8: '<html>' } },
  ] } });
  pd('node-stopped-after-ready', () => ({ data: 'x', contentType: 'text/plain' }), { nodeStopped: true });
  // A /stamps answer past its form's 1 MiB cap: bee-js reads it whole.
  pd('stamps-reply-past-cap', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps_label_bytes: 1048576 },
    deviation: { id: 'reply-bounds', core: { error: { code: -32603, message: 'Swarm node reply too large' } } } });
  // A /stamps answer that isn't JSON: the page reads V8's SyntaxError text,
  // the core one fixed text (reply-syntax).
  pd('stamps-not-json', () => ({ data: 'x', contentType: 'text/plain' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'GET', path: '/stamps' }, reply: { status: 200, body_utf8: '<html>busy</html>' } },
  ] }, deviation: { id: 'reply-syntax', core: { error: { code: -32603, message: 'Swarm node reply is not valid JSON' } } } });
  // The dispatcher's approval path (page/page-swarm.js): the publish prompt,
  // or the site's publish rule, which never answers for a tab in Agent
  // custody, read when the rule is chosen and again just before the upload
  // (after its last wait: the /stamps read), with the name and the key.
  const x = () => ({ data: 'x', contentType: 'text/plain' });
  const atStamps = (world) => ({ stamps: STAMPS.usable, rules: [
    { match: { method: 'GET', path: '/stamps' }, world, reply: { status: 200, json: STAMPS.usable } }] });
  pd('prompt-rejected', x, { prompts: [{ kind: 'swarm.publish', approve: false }] });
  pd('prompt-closed', x, { prompts: [{ kind: 'swarm.publish', closed: 'navigated' }] });
  pd('rule', x, { grants: rule({ publish: true }) });
  pd('rule-in-custody', x, { grants: rule({ publish: true }), custody: true });
  pd('rule-custody-before-upload', x, { grants: rule({ publish: true }), node: atStamps({ custody: true }) });
  pd('rule-off-before-upload', x, { grants: rule({ publish: true }), node: atStamps({ rule_off: 'publish' }) });
  pd('prompt-custody-before-upload', x, { node: atStamps({ custody: true }) });
  pd('name-moved-before-upload', x, { origin: ENS, grants: connected(ENS), node: atStamps({ name: 'moved' }) });
  add({ id: 'publish-data-always-allow', node: { stamps: STAMPS.usable },
    prompts: [{ kind: 'swarm.publish', approve: true, choices: { alwaysAllow: true } }], steps: [
      { method: 'swarm_publishData', params: x }, { method: 'swarm_publishData', params: () => ({ data: 'y', contentType: 'text/plain' }) },
    ] });
  pd('disconnected-at-service', x, { at_execute: { connection: 'revoked' } });
  pd('keyless', x, { keyless: true });
  pd('identity-wallet-off', x, { identity_wallet: false });
  pd('grants-unavailable', x, { grants_unavailable: true });

  // -------------------------------------------------------------------------
  // publishFiles.
  const file = (p, data, over = {}) => ({ path: p, bytes: data, ...over });
  const pf = (id, params, over = {}) => add({ id: `publish-files-${id}`, method: 'swarm_publishFiles', params, node: { stamps: STAMPS.usable }, ...over });
  pf('params-null', () => null);
  pf('files-missing', () => ({}));
  pf('files-empty', () => ({ files: [] }));
  pf('files-not-array', () => ({ files: { 0: file('a', u8('a')), length: 1 } }));
  pf('files-101', () => ({ files: Array.from({ length: 101 }, () => null) }));
  pf('file-null', () => ({ files: [file('a', u8('a')), null, file('', 'x')] }));
  pf('file-number', () => ({ files: [7] }));
  const badPaths = [
    ['path-missing', undefined], ['path-empty', ''], ['path-number', 5], ['path-101-bytes', `${'é'.repeat(50)}x`],
    ['path-backslash', 'a\\b'], ['path-leading-slash', '/a'], ['path-colon', 'a:b'], ['path-control', 'a\u0001b'],
    ['path-nul', 'a\u0000'], ['path-empty-segment', 'a//b'], ['path-trailing-slash', 'a/'], ['path-dot', './a'],
    ['path-dot-dot', 'a/../b'], ['path-trailing-dot', 'a./b'], ['path-trailing-space', 'a /b'], ['path-reserved-con', 'CON'],
    ['path-reserved-ext', 'docs/nul.txt'], ['path-reserved-superscript', 'COM¹.log'], ['path-reserved-conin', 'conin$'],
    ['path-reserved-trailing', 'lpt9 .x'],
  ];
  for (const [id, p] of badPaths) pf(id, () => ({ files: [file('ok.txt', u8('ok')), file(p, 'not bytes')], indexDocument: 9 }));
  pf('path-duplicate', () => ({ files: [file('a.txt', u8('1')), file('a.txt', 'not bytes')], indexDocument: 9 }));
  pf('path-same-but-case', () => ({ files: [file('a.txt', u8('1')), file('A.txt', u8('2'))] }));
  pf('bytes-string', () => ({ files: [file('a.txt', 'text')], indexDocument: 9 }));
  pf('bytes-missing', () => ({ files: [file('a.txt', undefined)] }));
  pf('total-too-large', () => ({
    files: Array.from({ length: 100 }, (_, i) => file(`files/${String(i).padStart(3, '0')}.bin`,
      bytes(`publish-files/50mib/${i}`, i === 99 ? 50 * MiB - 99 * 524288 + 1 : 524288))),
    indexDocument: 9,
  }), { readiness: { ok: false, reason: 'node-stopped' } });
  pf('index-document-number', () => ({ files: [file('a.txt', u8('a'))], indexDocument: 9 }), { readiness: { ok: false, reason: 'node-stopped' } });
  pf('index-document-unknown', () => ({ files: [file('a.txt', u8('a'))], indexDocument: 'index.html' }));
  pf('index-document-empty', () => ({ files: [file('a.txt', u8('a'))], indexDocument: '' }));
  for (const reason of NOT_READY) pf(`not-ready-${reason}`, () => ({ files: [file('a.txt', u8('a'))] }), { readiness: { ok: false, reason } });
  pf('one-file', () => ({ files: [file('index.html', u8('<h1>Freedom</h1>\n'))] }));
  pf('nested', () => ({ files: [
    file('index.html', bytes('publish-files/index', 700)),
    file('assets/app.js', bytes('publish-files/app', 5000), { contentType: 'text/javascript' }),
    file('assets/css/site.css', bytes('publish-files/css', 33)),
    file('a/b/c/d/e/deep.txt', u8('deep')),
  ] }));
  pf('index-document-nested', () => ({ files: [file('docs/start.html', u8('start')), file('index.html', u8('top'))], indexDocument: 'docs/start.html' }));
  pf('index-document-null', () => ({ files: [file('page.html', u8('p'))], indexDocument: null }));
  pf('no-index', () => ({ files: [file('readme.md', u8('# hi')), file('sub/index.html', u8('not top level'))] }));
  pf('empty-file', () => ({ files: [file('empty.txt', new Uint8Array(0)), file('after.txt', u8('after the empty one'))] }));
  pf('block-sizes', () => ({ files: [511, 512, 513, 1024].map((n) => file(`f${n}.bin`, bytes(`publish-files/block/${n}`, n))) }));
  pf('path-100-bytes', () => ({ files: [file(`${'é'.repeat(48)}abcd`, u8('100 bytes'))] }));
  pf('path-100-ascii', () => ({ files: [file(`${'d'.repeat(40)}/${'n'.repeat(59)}`, u8('100 bytes'))] }));
  pf('path-unicode', () => ({ files: [file('ドキュメント/説明.txt', u8('within 100 bytes'))] }));
  pf('kinds', () => ({ files: [
    file('buffer.bin', Buffer.from('buffer')), file('ab.bin', u8('arraybuffer').buffer),
    file('json.bin', { type: 'Buffer', data: [1, 2, 3] }), file('view.bin', u8('0123456789').subarray(3, 5)),
  ] }));
  pf('content-types-ignored', () => ({ files: [file('a', u8('no extension'), { contentType: 'text/html' }), file('b.json', u8('{}'), { contentType: 7 })] }));
  pf('100-files-50mib', () => ({
    files: Array.from({ length: 100 }, (_, i) => file(`files/${String(i).padStart(3, '0')}.bin`,
      bytes(`publish-files/50mib/${i}`, i === 99 ? 50 * MiB - 99 * 524288 : 524288))),
  }), { node: { stamps: STAMPS.usable } });
  pf('no-stamps', () => ({ files: [file('a.txt', u8('a'))] }), { node: { stamps: STAMPS.none } });
  pf('stamps-capacity', () => ({ files: [file('a.bin', bytes('publish-files/capacity', 5 * MiB))] }), { node: { stamps: STAMPS.small } });
  pf('node-500', () => ({ files: [file('a.txt', u8('a'))] }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 500, json: { code: 500, message: 'manifest build failed' } } },
  ] } });
  pf('node-no-tag', () => ({ files: [file('a.txt', u8('a'))] }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 201, json: { reference: 'ab'.repeat(32) } } },
  ] } });
  pf('node-bad-tag', () => ({ files: [file('a.txt', u8('a'))] }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/bzz' }, reply: { status: 201, headers: { 'swarm-tag': '-3' }, json: { reference: 'ab'.repeat(32) } } },
  ] } });
  pf('rule', () => ({ files: [file('a.txt', u8('a'))] }), { grants: rule({ publish: true }) });
  pf('prompt-rejected', () => ({ files: [file('a.txt', u8('a'))] }), { prompts: [{ kind: 'swarm.publish', approve: false }] });

  // -------------------------------------------------------------------------
  // getUploadStatus: a tag is the site's only after its own publishFiles.
  const tagJson = (uid, over = {}) => ({ uid, split: 10, seen: 2, stored: 10, sent: 5, synced: 3, address: 'AB'.repeat(32), startedAt: '2026-01-01T00:00:00Z', ...over });
  const gu = (id, steps, over = {}) => add({ id: `upload-status-${id}`, steps, node: { stamps: STAMPS.usable, tags: { 101: tagJson(101) } }, ...over });
  const publishOne = { method: 'swarm_publishFiles', params: () => ({ files: [file('a.txt', u8('a'))] }) };
  gu('params-null', [{ method: 'swarm_getUploadStatus', params: () => null }]);
  for (const [id, uid] of [['tag-missing', undefined], ['tag-string', '101'], ['tag-zero', 0], ['tag-negative', -1],
    ['tag-fraction', 1.5], ['tag-nan', NaN], ['tag-bigint', 101n]]) {
    gu(id, [{ method: 'swarm_getUploadStatus', params: () => ({ tagUid: uid }) }]);
  }
  gu('not-owned', [{ method: 'swarm_getUploadStatus', params: () => ({ tagUid: 101 }) }]);
  gu('in-progress', [publishOne, { method: 'swarm_getUploadStatus', params: () => ({ tagUid: 101 }) }]);
  gu('other-site', [publishOne, { method: 'swarm_getUploadStatus', params: () => ({ tagUid: 101 }), origin: OTHER }],
    { grants: { ...connected(ORIGIN), ...connected(OTHER) } });
  gu('done-then-forgotten', [publishOne, { method: 'swarm_getUploadStatus', params: () => ({ tagUid: 101 }) },
    { method: 'swarm_getUploadStatus', params: () => ({ tagUid: 101 }) }],
  { node: { stamps: STAMPS.usable, tags: { 101: tagJson(101, { split: 4, seen: 1, synced: 3, sent: 4 }) } } });
  gu('split-zero', [publishOne, { method: 'swarm_getUploadStatus', params: () => ({ tagUid: 101 }) }],
    { node: { stamps: STAMPS.usable, tags: { 101: tagJson(101, { split: 0, seen: 0, stored: 0, sent: 0, synced: 0, address: '' }) } } });
  gu('fields-missing', [publishOne, { method: 'swarm_getUploadStatus', params: () => ({ tagUid: 101 }) }],
    { node: { stamps: STAMPS.usable, tags: { 101: { uid: 101 } } } });
  gu('encrypted-address', [publishOne, { method: 'swarm_getUploadStatus', params: () => ({ tagUid: 101 }) }],
    { node: { stamps: STAMPS.usable, tags: { 101: tagJson(101, { address: 'Cd'.repeat(64) }) } } });
  gu('node-404', [publishOne, { method: 'swarm_getUploadStatus', params: () => ({ tagUid: 101 }) }],
    { node: { stamps: STAMPS.usable, tags: {} } });

  // -------------------------------------------------------------------------
  // publishChunk.
  const pc = (id, params, over = {}) => add({ id: `publish-chunk-${id}`, method: 'swarm_publishChunk', params, node: { stamps: STAMPS.usable }, ...over });
  pc('params-null', () => null);
  pc('options-string', () => ({ options: 'x', data: null, span: -1 }));
  pc('options-array', () => ({ options: [], data: null, span: -1 }));
  pc('options-key', () => ({ options: { pin: false, deferred: true }, data: null, span: -1 }));
  pc('options-null', () => ({ options: null, data: 'x' }));
  pc('data-missing', () => ({ span: -1 }));
  pc('data-number', () => ({ data: 7, span: -1 }));
  pc('data-empty', () => ({ data: '', span: -1 }));
  pc('data-empty-bytes', () => ({ data: new Uint8Array(0), span: -1 }));
  pc('data-4097', () => ({ data: bytes('publish-chunk/4097', 4097), span: -1 }));
  pc('data-4097-string', () => ({ data: 'é'.repeat(2049), span: -1 }));
  for (const [id, span] of [['span-negative', -1], ['span-fraction', 1.5], ['span-unsafe', 2 ** 53], ['span-string', '5'],
    ['span-bigint-negative', -1n], ['span-bigint-past-u64', 1n << 64n], ['span-nan', NaN]]) {
    pc(id, () => ({ data: 'x', span }), { readiness: { ok: false, reason: 'node-stopped' } });
  }
  for (const reason of NOT_READY) pc(`not-ready-${reason}`, () => ({ data: 'x' }), { readiness: { ok: false, reason } });
  pc('one-byte', () => ({ data: 'x' }));
  pc('4096', () => ({ data: bytes('publish-chunk/4096', 4096) }));
  pc('span-number', () => ({ data: u8('root of something larger'), span: 1048576 }));
  pc('span-bigint-max', () => ({ data: u8('max span'), span: (1n << 64n) - 1n }));
  pc('span-zero', () => ({ data: u8('zero span'), span: 0 }));
  pc('span-null', () => ({ data: u8('null span'), span: null }));
  pc('no-stamps', () => ({ data: 'x' }), { node: { stamps: STAMPS.none } });
  pc('node-500', () => ({ data: 'x' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/chunks' }, reply: { status: 500, json: { code: 500, message: 'chunk write failed' } } },
  ] } });
  pc('rule', () => ({ data: 'x' }), { grants: rule({ publish: true }) });
  pc('node-other-reference', () => ({ data: 'x' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', path: '/chunks' }, reply: { status: 201, json: { reference: 'ab'.repeat(32) } } },
  ] }, deviation: { id: 'reference-check', core: { error: { code: -32603, message: 'The Swarm node returned another reference' } } } });

  // -------------------------------------------------------------------------
  // readChunk.
  const stored = [{ utf8: 'hello swarm' }, { seed: 'read-chunk/4096', length: 4096 }];
  const helloAddress = env.cacAddress(Buffer.from('hello swarm'));
  const rc = (id, params, over = {}) => add({ id: `read-chunk-${id}`, method: 'swarm_readChunk', params, node: { data: stored }, ...over });
  rc('params-null', () => null);
  rc('options-key', () => ({ options: { timeout: 1 }, reference: 5 }));
  rc('reference-missing', () => ({}));
  rc('reference-number', () => ({ reference: 5 }));
  rc('reference-0x', () => ({ reference: `0x${helloAddress}` }));
  rc('reference-63', () => ({ reference: helloAddress.slice(1) }));
  rc('reference-65', () => ({ reference: `${helloAddress}0` }));
  rc('reference-not-hex', () => ({ reference: `${helloAddress.slice(1)}g` }));
  rc('reference-128', () => ({ reference: helloAddress.repeat(2) }));
  rc('found', () => ({ reference: helloAddress }));
  rc('found-anonymous', () => ({ reference: helloAddress }), { grants: {} });
  // A keyless document reads on the anonymous budget's one bucket; the
  // switch off refuses even a read.
  rc('found-keyless', () => ({ reference: helloAddress }), { keyless: true });
  rc('identity-wallet-off', () => ({ reference: helloAddress }), { identity_wallet: false });
  rc('grants-unavailable', () => ({ reference: helloAddress }), { grants_unavailable: true });
  rc('upper-case', () => ({ reference: helloAddress.toUpperCase() }));
  rc('4096', () => ({ reference: env.cacAddress(env.seeded('read-chunk/4096', 4096)) }));
  rc('not-found', () => ({ reference: 'ab'.repeat(32) }));
  rc('500-read-chunk-failed', () => ({ reference: 'ab'.repeat(32) }), { node: { rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 500, json: { code: 500, message: ' Read Chunk Failed ' } } },
  ] } });
  rc('500-other', () => ({ reference: 'ab'.repeat(32) }), { node: { rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 500, json: { code: 500, message: 'storage error' } } },
  ] } });
  rc('500-text', () => ({ reference: 'ab'.repeat(32) }), { node: { rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 500, body_utf8: 'read chunk failed' } },
  ] } });
  rc('wrong-bytes', () => ({ reference: 'ab'.repeat(32) }), { node: { chunks: [{ address: 'ab'.repeat(32), utf8: '\u0005\0\0\0\0\0\0\0hello' }] } });
  rc('short-bytes', () => ({ reference: 'ab'.repeat(32) }), { node: { chunks: [{ address: 'ab'.repeat(32), hex: '0102' }] } });
  rc('node-unreachable', () => ({ reference: helloAddress }), { node: { rules: [
    { match: { path: '/node' }, reply: { status: 503 } },
  ] } });
  rc('node-hangs-up', () => ({ reference: helloAddress }), { node: { rules: [
    { match: { prefix: '/chunks/' }, reply: { hangUp: true } },
  ] }, deviation: { id: 'transport-error-text', core: 'one text for the failure class (error)' } });
  rc('node-stopped', () => ({ reference: helloAddress }), { nodeStopped: true });
  // The page gives up 50 ms in; the node answers at 300 ms. A read takes no
  // signal at the reference, so it answers anyway.
  rc('page-gives-up', () => ({ reference: helloAddress }), { node: { data: stored, rules: [
    { match: { prefix: '/chunks/' }, reply: { abortPage: true, delayMs: 300, status: 200,
      body_hex: Buffer.concat([Buffer.from('0b00000000000000', 'hex'), Buffer.from('hello swarm')]).toString('hex') } },
  ] },
  deviation: { id: 'deadlines', core: 'cancelled at the page\'s timer: the core answers cancelled and nothing more is sent' } });
  // The request budget: 120 a minute for a site with no grant.
  add({ id: 'read-chunk-request-budget', grants: {}, node: { data: stored }, steps: [
    ...Array.from({ length: 120 }, () => ({ method: 'swarm_listFeeds', params: () => undefined })),
    { method: 'swarm_readChunk', params: () => ({ reference: helloAddress }) },
  ] });
  add({ id: 'read-chunk-request-budget-window', grants: {}, node: { data: stored }, steps: [
    ...Array.from({ length: 120 }, () => ({ method: 'swarm_listFeeds', params: () => undefined })),
    { method: 'swarm_readChunk', params: () => ({ reference: helloAddress }), clock: T0 + 60000 },
  ] });

  // -------------------------------------------------------------------------
  // readData.
  const sizes = [1, 4095, 4096, 4097, 524288, 524289];
  const blobs = sizes.map((n) => ({ seed: `read-data/${n}`, length: n }));
  const rootOf = (n) => env.rootAddress(env.seeded(`read-data/${n}`, n));
  const rd = (id, params, over = {}) => add({ id: `read-data-${id}`, method: 'swarm_readData', params, node: { data: blobs }, ...over });
  rd('params-null', () => null);
  rd('options-key', () => ({ options: { range: [0, 1] }, reference: 'x' }));
  rd('reference-number', () => ({ reference: 5 }));
  rd('reference-128', () => ({ reference: 'ab'.repeat(64) }));
  for (const n of sizes) {
    const big = n > 4096;
    rd(`${n}`, () => ({ reference: rootOf(n) }), big ? { deviation: { id: 'read-data-verified', core: 'the same result, read through the verified walk' } } : {});
  }
  rd('524289-anonymous', () => ({ reference: rootOf(524289) }), { grants: {} });
  rd('524288-anonymous', () => ({ reference: rootOf(524288) }), { grants: {},
    deviation: { id: 'read-data-verified', core: 'the same result, read through the verified walk' } });
  rd('5mib-connected', () => ({ reference: env.rootAddress(env.seeded('read-data/5mib', 5 * MiB)) }), {
    node: { data: [{ seed: 'read-data/5mib', length: 5 * MiB }] },
    deviation: { id: 'read-data-verified', core: 'the same result, read through the verified walk' },
  });
  rd('5mib+1-connected', () => ({ reference: env.rootAddress(env.seeded('read-data/5mib+1', 5 * MiB + 1)) }), {
    node: { data: [{ seed: 'read-data/5mib+1', length: 5 * MiB + 1 }] },
  });
  rd('upper-case', () => ({ reference: rootOf(4097).toUpperCase() }),
    { deviation: { id: 'read-data-verified', core: 'the same result, read through the verified walk' } });
  rd('not-found', () => ({ reference: 'ab'.repeat(32) }));
  rd('root-wrong-bytes', () => ({ reference: 'ab'.repeat(32) }), { node: { chunks: [{ address: 'ab'.repeat(32), utf8: '\u0005\0\0\0\0\0\0\0hello' }] } });
  rd('bytes-not-found', () => ({ reference: rootOf(4097) }), { node: { data: blobs, rules: [
    { match: { prefix: '/bytes/' }, reply: { status: 404, json: { code: 404, message: 'Not Found' } } },
  ] }, deviation: { id: 'read-data-verified', core: 'chunk_not_found when a leaf is missing; the walk reads chunks and a ranged /bytes' } });
  rd('bytes-500', () => ({ reference: rootOf(4097) }), { node: { data: blobs, rules: [
    { match: { prefix: '/bytes/' }, reply: { status: 500, json: { code: 500, message: 'join failed' } } },
  ] }, deviation: { id: 'read-data-verified', core: 'the walk reads a ranged /bytes; its 500 is -32603' } });
  rd('join-short', () => ({ reference: rootOf(4097) }), { node: { data: blobs, rules: [
    { match: { prefix: '/bytes/' }, reply: { status: 200, body_data: { seed: 'read-data/4097', length: 4096 } } },
  ] }, deviation: { id: 'read-data-verified', core: 'the walk refuses the short stream' } });
  rd('join-wrong-bytes', () => ({ reference: rootOf(4097) }), { node: { data: blobs, rules: [
    { match: { prefix: '/bytes/' }, reply: { status: 200, body_data: { seed: 'read-data/other', length: 4097 } } },
  ] }, deviation: { id: 'read-data-verified',
    core: { error: { code: -32602, message: 'Downloaded bytes do not validate as the requested content-addressed chunk', data: { reason: 'chunk_type_mismatch' } } } } });
  rd('redundancy-level-span', () => ({ reference: env.levelRoot.address }), { node: { chunks: env.levelRoot.chunks, blobs: [] , rules: [
    { match: { path: `/bytes/${env.levelRoot.address}` }, reply: { status: 200, body_data: env.levelRoot.data } },
  ] }, deviation: { id: 'read-data-verified', core: 'the same result, read through the verified walk' } });
  rd('span-top-byte-128', () => ({ reference: env.hugeRoot.address }), { node: { chunks: env.hugeRoot.chunks } });
  // The byte budget: the root is charged, then the rest reserved.
  add({ id: 'read-data-byte-budget', grants: {}, node: { data: blobs }, steps: [
    { method: 'swarm_readData', params: () => ({ reference: rootOf(524288) }) },
    { method: 'swarm_readData', params: () => ({ reference: rootOf(1) }) },
  ], deviation: { id: 'read-data-verified', core: 'the same results, read through the verified walk' } });
  add({ id: 'read-data-reserve-refused', grants: {}, node: { data: blobs }, steps: [
    { method: 'swarm_readData', params: () => ({ reference: rootOf(4097) }) },
    { method: 'swarm_readData', params: () => ({ reference: rootOf(524288) }) },
  ], deviation: { id: 'read-data-verified', core: 'the same results, read through the verified walk' } });

  // -------------------------------------------------------------------------
  // writeSingleOwnerChunk.
  const sid = '42'.repeat(32);
  const shared = feedStore({
    [ORIGIN]: originEntry(app0),
    [OTHER]: originEntry(app1, { identities: [app1, identity('app-scoped', 0)] }),
  }, 2);
  const ws = (id, params, over = {}) => add({ id: `write-soc-${id}`, method: 'swarm_writeSingleOwnerChunk', params,
    feeds: storeApp(), node: { stamps: STAMPS.usable }, ...over });
  ws('params-null', () => null);
  ws('options-key', () => ({ options: { pin: true }, identifier: 5, data: '', span: -1 }));
  ws('identifier-missing', () => ({ data: '', span: -1 }));
  ws('identifier-0x', () => ({ identifier: `0x${sid}`, data: '', span: -1 }));
  ws('identifier-short', () => ({ identifier: sid.slice(2), data: '', span: -1 }));
  ws('data-missing', () => ({ identifier: sid, span: -1 }));
  ws('data-empty', () => ({ identifier: sid, data: '', span: -1 }));
  ws('data-4097', () => ({ identifier: sid, data: bytes('write-soc/4097', 4097), span: -1 }));
  ws('span-negative', () => ({ identifier: sid, data: 'x', span: -1 }), { feeds: storeBee({}, false) });
  ws('no-feed-grant', () => ({ identifier: sid, data: 'x' }), { feeds: feedStore({ [ORIGIN]: originEntry(eth, { feedGranted: false }) }) });
  ws('no-store', () => ({ identifier: sid, data: 'x' }), { feeds: null });
  // SW-1: the site's signing rule answers (no prompt picks an identity), so
  // the service's own checks meet the stored identity, before the vault
  // (locked at the service) and readiness.
  const sw1 = rule({ signing: true });
  ws('ethereum-wallet-first', () => ({ identifier: sid, data: 'x' }), { feeds: feedStore({ [ORIGIN]: originEntry(eth) }), grants: sw1, ...LOCKS,
    readiness: { ok: false, reason: 'node-stopped' } });
  ws('bee-wallet-shared', () => ({ identifier: sid, data: 'x' }), { feeds: storeBee(), grants: sw1, ...LOCKS, readiness: { ok: false, reason: 'node-stopped' } });
  ws('app-scoped-shared-index', () => ({ identifier: sid, data: 'x' }), { feeds: shared, grants: sw1, ...LOCKS, readiness: { ok: false, reason: 'node-stopped' } });
  ws('app-scoped-index-missing', () => ({ identifier: sid, data: 'x' }), {
    feeds: feedStore({ [ORIGIN]: originEntry({ ...app0, publisherKeyIndex: null }) }, 1), grants: sw1, ...LOCKS,
  });
  ws('app-scoped-index-string', () => ({ identifier: sid, data: 'x' }), {
    feeds: feedStore({ [ORIGIN]: originEntry({ ...app0, publisherKeyIndex: '0' }) }, 1), grants: sw1, ...LOCKS,
  });
  ws('app-scoped-other-site-other-index', () => ({ identifier: sid, data: 'x' }), {
    feeds: feedStore({ [ORIGIN]: originEntry(app0), [OTHER]: originEntry(app1) }, 2), grants: sw1,
  });
  ws('app-scoped-held-inactive-elsewhere', () => ({ identifier: sid, data: 'x' }), {
    feeds: feedStore({ [ORIGIN]: originEntry(app0), [OTHER]: originEntry(bee, { identities: [bee, identity('app-scoped', 0)] }) }, 1),
    grants: sw1, ...LOCKS,
  });
  ws('app-scoped-counter-behind', () => ({ identifier: sid, data: 'x' }), { feeds: storeApp({}, 0), grants: sw1 });
  // On the prompt path a shared identity is no choice for a raw chunk: the
  // user's pick (here the default, the new app-scoped identity) is made and
  // signs.
  ws('bee-wallet-shared-prompt', () => ({ identifier: sid, data: 'x' }), { feeds: storeBee() });
  ws('locked', () => ({ identifier: sid, data: 'x' }), { ...LOCKS, readiness: { ok: false, reason: 'node-stopped' } });
  // A locked vault through the dispatcher: main's unlock prompt first.
  ws('unlock-prompt', () => ({ identifier: sid, data: 'x' }), { vault: 'locked' });
  ws('unlock-cancelled', () => ({ identifier: sid, data: 'x' }), { vault: 'locked', prompts: [{ kind: 'vault.unlock', approve: false }] });
  ws('feed-prompt-rejected', () => ({ identifier: sid, data: 'x' }), { prompts: [{ kind: 'swarm.feed', approve: false }] });
  // The signing rule and Agent custody: a tab in custody gets the prompt,
  // and custody taken (or the rule turned off) before the write refuses it.
  ws('rule', () => ({ identifier: sid, data: 'x' }), { grants: sw1 });
  ws('rule-in-custody', () => ({ identifier: sid, data: 'x' }), { grants: sw1, custody: true });
  ws('rule-custody-before-write', () => ({ identifier: sid, data: 'x' }), { grants: sw1, node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'GET', path: '/stamps' }, world: { custody: true }, reply: { status: 200, json: STAMPS.usable } }] } });
  ws('rule-off-before-write', () => ({ identifier: sid, data: 'x' }), { grants: sw1, node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'GET', path: '/stamps' }, world: { rule_off: 'signing' }, reply: { status: 200, json: STAMPS.usable } }] } });
  // A grant gone between the dispatcher's checks and the service: the
  // service's own refusals.
  ws('feed-access-revoked-at-service', () => ({ identifier: sid, data: 'x' }), { at_execute: { feed_access: 'revoked' } });
  ws('disconnected-at-service', () => ({ identifier: sid, data: 'x' }), { at_execute: { connection: 'revoked' } });
  ws('always-allow', () => null, { prompts: [{ kind: 'swarm.feed', approve: true, choices: { identity: 'app-scoped:0', alwaysAllow: true } }], steps: [
    { method: 'swarm_writeSingleOwnerChunk', params: () => ({ identifier: sid, data: 'one' }) },
    { method: 'swarm_writeSingleOwnerChunk', params: () => ({ identifier: '43'.repeat(32), data: 'two' }) },
  ] });
  for (const reason of NOT_READY) ws(`not-ready-${reason}`, () => ({ identifier: sid, data: 'x' }), { readiness: { ok: false, reason } });
  ws('one-byte', () => ({ identifier: sid, data: 'x' }));
  ws('upper-case-identifier', () => ({ identifier: sid.toUpperCase().replace(/4/g, 'A'), data: u8('upper') }));
  ws('4096', () => ({ identifier: '00'.repeat(32), data: bytes('write-soc/4096', 4096) }));
  ws('span', () => ({ identifier: 'ff'.repeat(32), data: bytes('write-soc/root', 64), span: 4097 }));
  ws('span-bigint', () => ({ identifier: 'ff'.repeat(32), data: bytes('write-soc/root', 64), span: 1n << 40n }));
  ws('auto-approval', () => ({ identifier: sid, data: 'x' }), { grants: sw1 });
  ws('publisher-2', () => ({ identifier: sid, data: 'x' }), { feeds: feedStore({ [ORIGIN]: originEntry(app2) }, 3), grants: sw1 });
  ws('no-stamps', () => ({ identifier: sid, data: 'x' }), { node: { stamps: STAMPS.none } });
  ws('node-500', () => ({ identifier: sid, data: 'x' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/soc/' }, reply: { status: 500, json: { code: 500, message: 'invalid soc' } } },
  ] } });
  ws('node-error-empty', () => ({ identifier: sid, data: 'x' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/soc/' }, reply: { status: 400, statusText: '' } },
  ] } });
  ws('node-error-text', () => ({ identifier: sid, data: 'x' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/soc/' }, reply: { status: 402, statusText: 'Payment Required' } },
  ] } });
  ws('node-other-reference', () => ({ identifier: sid, data: 'x' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/soc/' }, reply: { status: 201, json: { reference: 'ab'.repeat(32) } } },
  ] } });
  ws('node-no-reference', () => ({ identifier: sid, data: 'x' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/soc/' }, reply: { status: 201, json: {} } },
  ] } });
  ws('node-batch-not-yet-known', () => ({ identifier: sid, data: 'x' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/soc/' }, reply: { status: 500, json: { code: 500,
      message: `pushsync: postage batch 0x${BATCH_A} rejected by 1 peer(s) as not found on-chain` } } },
  ] } });
  ws('no-page', () => ({ identifier: sid, data: 'x' }), { steps: [
    { method: 'swarm_writeSingleOwnerChunk', params: () => ({ identifier: sid, data: 'x' }), page: false },
  ] });

  // -------------------------------------------------------------------------
  // readSingleOwnerChunk.
  const socEntry = env.socOf('bee', sid, Buffer.from('a single owner chunk'));
  const socBig = env.socOf('publisher:1', 'ff'.repeat(32), env.seeded('read-soc/4096', 4096));
  const socSpan = env.socOf('publisher:0', '11'.repeat(32), Buffer.from('wrapped root'), (1n << 53n) + 1n);
  const socNode = { chunks: [socEntry.chunk, socBig.chunk, socSpan.chunk] };
  const rs = (id, params, over = {}) => add({ id: `read-soc-${id}`, method: 'swarm_readSingleOwnerChunk', params, node: socNode, ...over });
  rs('params-null', () => null);
  rs('options-array', () => ({ options: [1], address: 7 }));
  rs('address-and-owner', () => ({ address: socEntry.address, owner: 'x' }));
  rs('address-and-identifier', () => ({ address: socEntry.address, identifier: 'x' }));
  rs('none', () => ({}));
  rs('owner-only', () => ({ owner: owner('bee') }));
  rs('identifier-only', () => ({ identifier: sid }));
  rs('address-number', () => ({ address: 5 }));
  rs('address-0x', () => ({ address: `0x${socEntry.address}` }));
  rs('owner-short', () => ({ owner: '0x1234', identifier: 'x' }));
  rs('owner-number', () => ({ owner: 1234, identifier: 'x' }));
  rs('identifier-bad', () => ({ owner: owner('bee'), identifier: 'x' }));
  rs('by-address', () => ({ address: socEntry.address }));
  rs('by-address-upper-case', () => ({ address: socEntry.address.toUpperCase() }));
  rs('by-owner-identifier', () => ({ owner: owner('bee'), identifier: sid }));
  rs('by-owner-no-0x-upper', () => ({ owner: ownerHex('bee').toUpperCase(), identifier: sid.toUpperCase() }));
  rs('4096', () => ({ address: socBig.address }));
  rs('span-past-safe', () => ({ address: socSpan.address }));
  rs('null-address-with-owner', () => ({ address: null, owner: owner('bee'), identifier: sid }));
  rs('not-found', () => ({ address: 'ab'.repeat(32) }));
  rs('500-read-chunk-failed', () => ({ address: 'ab'.repeat(32) }), { node: { rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 500, json: { code: 500, message: 'read chunk failed' } } },
  ] } });
  rs('wrong-address', () => ({ address: 'ab'.repeat(32) }), { node: { chunks: [{ ...socEntry.chunk, address: 'ab'.repeat(32) }] } });
  rs('cac-not-soc', () => ({ address: 'ab'.repeat(32) }), { node: { chunks: [{ address: 'ab'.repeat(32), utf8: '\u0005\0\0\0\0\0\0\0hello' }] } });
  rs('anonymous', () => ({ address: socEntry.address }), { grants: {} });

  // -------------------------------------------------------------------------
  // getSigningIdentity.
  const gs = (id, over = {}) => add({ id: `signing-identity-${id}`, method: 'swarm_getSigningIdentity', params: () => undefined, feeds: storeBee(), ...over });
  gs('bee-wallet');
  gs('app-scoped', { feeds: storeApp() });
  gs('no-feed-grant', { feeds: storeBee({}, false) });
  gs('no-store', { feeds: null });
  gs('locked', { ...LOCKS });
  gs('locked-app-scoped', { ...LOCKS, feeds: storeApp() });
  gs('rule', { grants: rule({ signing: true }) });
  gs('feed-access-revoked-at-service', { at_execute: { feed_access: 'revoked' } });
  gs('prompt-rejected', { prompts: [{ kind: 'swarm.feed', approve: false }] });
  gs('ethereum-wallet', { feeds: feedStore({ [ORIGIN]: originEntry(eth) }), grants: rule({ signing: true }) });
  gs('no-active-identity', { feeds: feedStore({ [ORIGIN]: { ...originEntry(bee), activeIdentityId: 'app-scoped:9' } }) });

  // -------------------------------------------------------------------------
  // createFeed.
  const cf = (id, params, over = {}) => add({ id: `create-feed-${id}`, method: 'swarm_createFeed', params, feeds: storeBee(),
    node: { stamps: STAMPS.usable }, ...over });
  cf('params-null', () => null);
  for (const [id, name] of [['name-missing', undefined], ['name-empty', ''], ['name-number', 5], ['name-65', 'n'.repeat(65)],
    ['name-slash', 'a/b'], ['name-control', 'a\u001fb'], ['name-newline', 'a\nb']]) {
    cf(id, () => ({ name }), { feeds: storeBee({}, false) });
  }
  cf('name-64', () => ({ name: 'n'.repeat(64) }));
  cf('name-64-units-astral', () => ({ name: '🎉'.repeat(32) }));
  cf('name-del', () => ({ name: 'a\u007fb' }));
  cf('no-feed-grant', () => ({ name: 'blog' }), { feeds: storeBee({}, false), readiness: { ok: false, reason: 'node-stopped' } });
  cf('no-store', () => ({ name: 'blog' }), { feeds: null });
  cf('bee-wallet', () => ({ name: 'blog' }));
  cf('app-scoped', () => ({ name: 'blog' }), { feeds: storeApp() });
  cf('ens-key', () => ({ name: 'blog' }), { origin: ENS, grants: connected(ENS), feeds: feedStore({ [ENS]: originEntry(bee) }) });
  cf('existing', () => ({ name: 'blog' }), { feeds: storeBee(blogBee), readiness: { ok: false, reason: 'node-stopped' }, ...LOCKS });
  cf('existing-other-identity', () => ({ name: 'blog' }), {
    feeds: feedStore({ [ORIGIN]: originEntry(app0, { identities: [bee, app0], feeds: blogBee }) }, 1),
  });
  cf('ethereum-wallet', () => ({ name: 'blog' }), { feeds: feedStore({ [ORIGIN]: originEntry(eth) }), grants: rule({ feeds: true }),
    readiness: { ok: false, reason: 'node-stopped' } });
  for (const reason of NOT_READY) cf(`not-ready-${reason}`, () => ({ name: 'blog' }), { readiness: { ok: false, reason }, ...LOCKS });
  cf('locked', () => ({ name: 'blog' }), { ...LOCKS });
  cf('unlock-prompt', () => ({ name: 'blog' }), { vault: 'locked' });
  cf('prompt-rejected', () => ({ name: 'blog' }), { prompts: [{ kind: 'swarm.feed', approve: false }] });
  cf('prompt-closed', () => ({ name: 'blog' }), { prompts: [{ kind: 'swarm.feed', closed: 'navigated' }] });
  // The user picks the prompt's new app-scoped identity: main makes it the
  // site's, on the key the prompt showed, and grants feed access.
  cf('prompt-new-identity', () => ({ name: 'blog' }), { feeds: storeBee({}, false),
    prompts: [{ kind: 'swarm.feed', approve: true, choices: { identity: 'app-scoped:0' } }] });
  cf('prompt-ant-wallet', () => ({ name: 'blog' }), { feeds: storeApp(),
    prompts: [{ kind: 'swarm.feed', approve: true, choices: { identity: 'bee-wallet' } }] });
  cf('rule', () => ({ name: 'blog' }), { grants: rule({ feeds: true }) });
  cf('feed-access-revoked-at-service', () => ({ name: 'blog' }), { at_execute: { feed_access: 'revoked' } });
  cf('rule-without-feed-grant', () => ({ name: 'blog' }), { grants: rule({ feeds: true }), feeds: storeBee({}, false) });
  cf('no-stamps', () => ({ name: 'blog' }), { node: { stamps: STAMPS.none } });
  cf('stamps-pending', () => ({ name: 'blog' }), { node: { stamps: STAMPS.pending },
    deviation: { id: 'stamps-one-read', core: 'one GET /stamps; the same error' } });
  cf('node-500', () => ({ name: 'blog' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', prefix: '/feeds/' }, reply: { status: 500, json: { code: 500, message: 'manifest failed' } } },
  ] } });
  cf('node-no-reference', () => ({ name: 'blog' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { method: 'POST', prefix: '/feeds/' }, reply: { status: 201, json: { reference: 'xyz' } } },
  ] } });

  // -------------------------------------------------------------------------
  // updateFeed: the index from the node's answers.
  const blogTopicStr = `${ORIGIN}/blog`;
  const uf = (id, params, over = {}) => add({ id: `update-feed-${id}`, method: 'swarm_updateFeed', params, feeds: storeBee(blogBee),
    node: { stamps: STAMPS.usable, latest: [{ key: 'bee', topic: blogTopicStr, reply: { status: 404, json: { code: 404, message: 'Not Found' } } }],
      probes: [{ key: 'bee', topic: blogTopicStr, targets: [] }] }, ...over });
  uf('params-null', () => null);
  uf('feed-id-missing', () => ({ reference: 5 }));
  uf('feed-id-number', () => ({ feedId: 5, reference: 5 }));
  uf('reference-missing', () => ({ feedId: 'blog' }));
  uf('reference-0x', () => ({ feedId: 'blog', reference: `0x${REF}` }), { feeds: storeBee(blogBee, false) });
  uf('reference-128', () => ({ feedId: 'blog', reference: REF.repeat(2) }), { feeds: storeBee(blogBee, false) });
  uf('no-feed-grant', () => ({ feedId: 'blog', reference: REF }), { feeds: storeBee(blogBee, false) });
  uf('feed-not-found', () => ({ feedId: 'news', reference: REF }), { readiness: { ok: false, reason: 'node-stopped' } });
  uf('feed-id-invalid-name', () => ({ feedId: 'a/b', reference: REF }));
  uf('ethereum-wallet-feed', () => ({ feedId: 'blog', reference: REF }), {
    feeds: feedStore({ [ORIGIN]: originEntry(bee, { identities: [bee, eth], feeds: { blog: feedRecord(ORIGIN, 'blog', eth.id, 'bee') } }) }),
    readiness: { ok: false, reason: 'node-stopped' },
  });
  for (const reason of NOT_READY) uf(`not-ready-${reason}`, () => ({ feedId: 'blog', reference: REF }), { readiness: { ok: false, reason }, ...LOCKS });
  uf('locked', () => ({ feedId: 'blog', reference: REF }), { ...LOCKS });
  const head = (h, extra = {}) => ({ stamps: STAMPS.usable,
    latest: [{ key: 'bee', topic: blogTopicStr, reply: { status: 404, json: { code: 404, message: 'Not Found' } } }],
    probes: [{ key: 'bee', topic: blogTopicStr, targets: h === null ? [] : [h], head: h }], ...extra });
  const indexDeviation = { id: 'index-probe', core: 'feed_head with swarm-only-root-chunk instead of the whole latest payload; the same index' };
  for (const h of [null, 0, 1, 2, 3, 7, 8, 1023, 1024]) {
    uf(`head-${h === null ? 'none' : h}`, () => ({ feedId: 'blog', reference: REF }), { node: head(h), deviation: indexDeviation });
  }
  uf('head-81-reads', () => ({ feedId: 'blog', reference: REF }), { node: head(2 ** 40 - 1), deviation: indexDeviation });
  uf('head-past-probe', () => ({ feedId: 'blog', reference: REF }), { node: head(2 ** 40), deviation: indexDeviation });
  uf('latest-500-then-probe', () => ({ feedId: 'blog', reference: REF }), { node: { ...head(5),
    latest: [{ key: 'bee', topic: blogTopicStr, reply: { status: 500, json: { code: 500, message: 'wrapped chunk cannot be retrieved' } } }] },
  deviation: indexDeviation });
  uf('latest-503', () => ({ feedId: 'blog', reference: REF }), { node: { ...head(5),
    latest: [{ key: 'bee', topic: blogTopicStr, reply: { status: 503, json: { code: 503, message: 'unavailable' } } }] },
  deviation: indexDeviation });
  uf('probe-500', () => ({ feedId: 'blog', reference: REF }), { node: { ...head(3), probeFail: { index: 2, status: 500 } },
    deviation: indexDeviation });
  uf('latest-found', () => ({ feedId: 'blog', reference: REF }), { node: { stamps: STAMPS.usable,
    latest: [{ key: 'bee', topic: blogTopicStr, reply: { status: 200, headers: { 'swarm-feed-index': '0000000000000004', 'swarm-feed-index-next': '0000000000000005' }, body_utf8: 'the latest payload' } }] },
  deviation: indexDeviation });
  uf('latest-no-next', () => ({ feedId: 'blog', reference: REF }), { node: { stamps: STAMPS.usable,
    latest: [{ key: 'bee', topic: blogTopicStr, reply: { status: 200, headers: { 'swarm-feed-index': '0000000000000004' }, body_utf8: 'x' } }] },
  deviation: indexDeviation });
  uf('app-scoped', () => ({ feedId: 'blog', reference: REF }), { feeds: storeApp(blogApp), node: { stamps: STAMPS.usable,
    latest: [{ key: 'publisher:0', topic: blogTopicStr, reply: { status: 404, json: { code: 404, message: 'Not Found' } } }],
    probes: [{ key: 'publisher:0', topic: blogTopicStr, targets: [0], head: 0 }] }, deviation: indexDeviation });
  uf('upper-case-reference', () => ({ feedId: 'blog', reference: REF.toUpperCase() }), { node: head(null), deviation: indexDeviation });
  uf('auto-approval', () => ({ feedId: 'blog', reference: REF }), { grants: rule({ feeds: true }), node: head(null), deviation: indexDeviation });
  uf('no-stamps', () => ({ feedId: 'blog', reference: REF }), { node: { ...head(null), stamps: STAMPS.none } });
  uf('node-500', () => ({ feedId: 'blog', reference: REF }), { node: head(null, { rules: [
    { match: { prefix: '/soc/' }, reply: { status: 500, json: { code: 500, message: 'invalid soc' } } },
  ] }), deviation: indexDeviation });

  // -------------------------------------------------------------------------
  // writeFeedEntry.
  const wf = (id, params, over = {}) => add({ id: `write-feed-${id}`, method: 'swarm_writeFeedEntry', params, feeds: storeBee(blogBee),
    node: head(null), deviation: indexDeviation, ...over });
  wf('params-null', () => null, { deviation: undefined });
  wf('name-missing', () => ({ data: null, index: -1 }), { deviation: undefined });
  wf('name-slash', () => ({ name: 'a/b', data: null, index: -1 }), { deviation: undefined });
  wf('data-missing', () => ({ name: 'blog', index: -1 }), { deviation: undefined });
  wf('data-number', () => ({ name: 'blog', data: 5, index: -1 }), { deviation: undefined });
  for (const [id, index] of [['index-negative', -1], ['index-fraction', 0.5], ['index-string', '1'], ['index-bigint', 1n], ['index-nan', NaN]]) {
    wf(id, () => ({ name: 'blog', data: 'x', index }), { feeds: storeBee(blogBee, false), deviation: undefined });
  }
  wf('no-feed-grant', () => ({ name: 'blog', data: 'x' }), { feeds: storeBee(blogBee, false), deviation: undefined });
  wf('feed-not-found', () => ({ name: 'news', data: 'x' }), { readiness: { ok: false, reason: 'node-stopped' }, deviation: undefined });
  wf('ethereum-wallet-feed', () => ({ name: 'blog', data: 'x' }), {
    feeds: feedStore({ [ORIGIN]: originEntry(bee, { identities: [bee, eth], feeds: { blog: feedRecord(ORIGIN, 'blog', eth.id, 'bee') } }) }),
    readiness: { ok: false, reason: 'node-stopped' }, deviation: undefined,
  });
  for (const reason of NOT_READY) wf(`not-ready-${reason}`, () => ({ name: 'blog', data: 'x' }), { readiness: { ok: false, reason }, ...LOCKS, deviation: undefined });
  wf('locked', () => ({ name: 'blog', data: 'x' }), { ...LOCKS, deviation: undefined });
  // The feeds rule and Agent custody, read when the rule is chosen and again
  // just before the write.
  wf('rule', () => ({ name: 'blog', data: 'x' }), { grants: rule({ feeds: true }) });
  wf('rule-in-custody', () => ({ name: 'blog', data: 'x' }), { grants: rule({ feeds: true }), custody: true });
  wf('rule-custody-before-write', () => ({ name: 'blog', data: 'x' }), { grants: rule({ feeds: true }), node: head(null, { rules: [
    { match: { method: 'GET', path: '/stamps' }, world: { custody: true }, reply: { status: 200, json: STAMPS.usable } }] }) });
  wf('rule-off-before-write', () => ({ name: 'blog', data: 'x' }), { grants: rule({ feeds: true }), node: head(null, { rules: [
    { match: { method: 'GET', path: '/stamps' }, world: { rule_off: 'feeds' }, reply: { status: 200, json: STAMPS.usable } }] }) });
  wf('prompt-rejected', () => ({ name: 'blog', data: 'x' }), { prompts: [{ kind: 'swarm.feed', approve: false }], deviation: undefined });
  wf('feed-access-revoked-at-service', () => ({ name: 'blog', data: 'x' }), { at_execute: { feed_access: 'revoked' }, deviation: undefined });
  wf('always-allow', () => null, { prompts: [{ kind: 'swarm.feed', approve: true, choices: { identity: 'bee-wallet', alwaysAllow: true } }],
    steps: [
      { method: 'swarm_writeFeedEntry', params: () => ({ name: 'blog', data: 'one', index: 0 }) },
      { method: 'swarm_writeFeedEntry', params: () => ({ name: 'blog', data: 'two', index: 1 }) },
    ], node: { stamps: STAMPS.usable }, deviation: undefined });
  wf('string', () => ({ name: 'blog', data: 'hello feed' }));
  wf('bytes', () => ({ name: 'blog', data: u8('bytes entry') }));
  wf('4096', () => ({ name: 'blog', data: bytes('write-feed/4096', 4096) }));
  wf('4097', () => ({ name: 'blog', data: bytes('write-feed/4097', 4097) }),
    { deviation: { id: 'feed-wrap-root', also: ['index-probe'], core: 'the same index; the SOC wraps the core\'s own root, with no GET /chunks' } });
  wf('4097-string', () => ({ name: 'blog', data: 'é'.repeat(2048) + 'x' }),
    { deviation: { id: 'feed-wrap-root', also: ['index-probe'], core: 'the same index; the SOC wraps the core\'s own root, with no GET /chunks' } });
  wf('10mib', () => ({ name: 'blog', data: bytes('write-feed/10mib', 10 * MiB) }),
    { deviation: { id: 'feed-wrap-root', also: ['index-probe'], core: 'the same index; the SOC wraps the core\'s own root, with no GET /chunks' } });
  wf('10mib+1', () => ({ name: 'blog', data: bytes('write-feed/10mib', 10 * MiB + 1) }), {
    deviation: { id: 'feed-entry-bound',
      core: { error: { code: -32602, message: 'Payload exceeds maximum size of 10485760 bytes',
        data: { reason: 'payload_too_large', limit: 10485760, actual: 10485761 } } },
      before: 'any node call' },
  });
  wf('empty-string', () => ({ name: 'blog', data: '' }));
  wf('empty-bytes', () => ({ name: 'blog', data: new Uint8Array(0) }));
  for (const h of [0, 2, 7]) wf(`head-${h}`, () => ({ name: 'blog', data: 'x' }), { node: head(h) });
  wf('explicit-index-free', () => ({ name: 'blog', data: 'x', index: 3 }), { node: { stamps: STAMPS.usable }, deviation: undefined });
  wf('explicit-index-zero', () => ({ name: 'blog', data: 'x', index: 0 }), { node: { stamps: STAMPS.usable }, deviation: undefined });
  wf('explicit-index-taken', () => ({ name: 'blog', data: 'x', index: 3 }), { node: { stamps: STAMPS.usable,
    entries: [{ key: 'bee', topic: blogTopicStr, index: 3, data: { utf8: 'already there' } }] }, deviation: undefined });
  wf('explicit-index-500', () => ({ name: 'blog', data: 'x', index: 3 }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 500, json: { code: 500, message: 'read chunk failed' } } },
  ] }, deviation: undefined });
  wf('explicit-index-503', () => ({ name: 'blog', data: 'x', index: 3 }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 503, json: { code: 503, message: 'unavailable' } } },
  ] }, deviation: undefined });
  wf('explicit-index-not-the-soc', () => ({ name: 'blog', data: 'x', index: 3 }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 200, body_utf8: '\u0005\0\0\0\0\0\0\0hello' } },
  ] }, deviation: undefined });
  wf('explicit-index-hangs-up', () => ({ name: 'blog', data: 'x', index: 3 }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/chunks/' }, reply: { hangUp: true } },
  ] }, deviation: { id: 'transport-error-text', core: 'one text for the failure class (error)' } });
  wf('explicit-index-empty', () => ({ name: 'blog', data: '', index: 3 }), { node: { stamps: STAMPS.usable }, deviation: undefined });
  // The page gives up while the node holds the existence check: the write's
  // signal aborts it.
  wf('explicit-index-timeout', () => ({ name: 'blog', data: 'x', index: 3 }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/chunks/' }, reply: { abortPage: true, delayMs: 300, status: 404, json: { code: 404, message: 'Not Found' } } },
  ] }, deviation: undefined });
  wf('explicit-index-4097', () => ({ name: 'blog', data: bytes('write-feed/4097', 4097), index: 9 }), { node: { stamps: STAMPS.usable },
    deviation: { id: 'feed-wrap-root', core: 'the SOC wraps the core\'s own root, with no GET /chunks' } });
  wf('app-scoped', () => ({ name: 'blog', data: 'x' }), { feeds: storeApp(blogApp), node: { stamps: STAMPS.usable,
    latest: [{ key: 'publisher:0', topic: blogTopicStr, reply: { status: 404, json: { code: 404, message: 'Not Found' } } }],
    probes: [{ key: 'publisher:0', topic: blogTopicStr, targets: [], head: null }] } });
  wf('wrap-node-other-reference', () => ({ name: 'blog', data: bytes('write-feed/4097', 4097) }), { node: head(null, { rules: [
    { match: { method: 'POST', path: '/bytes' }, reply: { status: 201, json: { reference: env.cacAddress(Buffer.from('hello swarm')) } } },
  ], data: [{ utf8: 'hello swarm' }] }), deviation: { id: 'feed-wrap-root', also: ['index-probe', 'reference-check'],
    core: { error: { code: -32603, message: 'The Swarm node returned another reference' } } } });
  wf('wrap-root-missing', () => ({ name: 'blog', data: bytes('write-feed/4097', 4097) }), { node: head(null, { rules: [
    { match: { method: 'POST', path: '/bytes' }, reply: { status: 201, json: { reference: 'ab'.repeat(32) } } },
  ] }), deviation: { id: 'feed-wrap-root', also: ['index-probe', 'reference-check'],
    core: { error: { code: -32603, message: 'The Swarm node returned another reference' } } } });
  wf('bytes-upload-500', () => ({ name: 'blog', data: bytes('write-feed/4097', 4097) }), { node: head(null, { rules: [
    { match: { method: 'POST', path: '/bytes' }, reply: { status: 500, json: { code: 500, message: 'upload failed' } } },
  ] }) });
  wf('soc-500', () => ({ name: 'blog', data: 'x' }), { node: head(null, { rules: [
    { match: { prefix: '/soc/' }, reply: { status: 500, json: { code: 500, message: 'payload size 5000 exceeds limits' } } },
  ] }) });
  wf('no-stamps', () => ({ name: 'blog', data: 'x' }), { node: { ...head(null), stamps: STAMPS.none }, deviation: undefined });

  // -------------------------------------------------------------------------
  // readFeedEntry (#1057's metered reads).
  const rfTopicStr = `${ORIGIN}/blog`;
  const rfTopic = topicHex(ORIGIN, 'blog');
  const readNode = (extra = {}) => ({ entries: [
    { key: 'bee', topic: rfTopicStr, index: 0, data: { utf8: 'entry zero' } },
    { key: 'bee', topic: rfTopicStr, index: 1, data: { seed: 'read-feed/4096', length: 4096 } },
    { key: 'bee', topic: rfTopicStr, index: 2, wrap: true, data: { seed: 'read-feed/4097', length: 4097 } },
    { key: 'bee', topic: rfTopicStr, index: 3, wrap: true, data: { seed: 'read-feed/524289', length: 524289 } },
    { key: 'bee', topic: rfTopicStr, index: 4, wrap: true, data: { seed: 'read-feed/524288', length: 524288 } },
  ], probes: [{ key: 'bee', topic: rfTopicStr, targets: [] }], ...extra });
  const rf = (id, params, over = {}) => add({ id: `read-feed-${id}`, method: 'swarm_readFeedEntry', params, feeds: storeBee(blogBee),
    node: readNode(), ...over });
  rf('params-null', () => null);
  rf('topic-and-name', () => ({ topic: rfTopic, name: 'blog' }));
  rf('neither', () => ({ owner: owner('bee') }));
  rf('index-negative', () => ({ name: 'blog', index: -1, topic: undefined }));
  rf('index-string', () => ({ topic: 7, index: '1' }));
  rf('index-null', () => ({ name: 'blog', index: null }), { node: readNode({ latest: [{ key: 'bee', topic: rfTopicStr,
    reply: { status: 200, headers: { 'swarm-feed-index': '0000000000000000', 'swarm-feed-index-next': '0000000000000001' }, body_utf8: 'entry zero' } }] }) });
  rf('topic-number', () => ({ topic: 7 }));
  rf('topic-0x', () => ({ topic: `0x${rfTopic}`, owner: owner('bee') }));
  rf('topic-owner-missing', () => ({ topic: rfTopic }));
  rf('topic-owner-number', () => ({ topic: rfTopic, owner: 5 }));
  rf('topic-owner-short', () => ({ topic: rfTopic, owner: '0xabcd' }));
  rf('name-invalid', () => ({ name: 'a/b', owner: 'bad' }));
  rf('name-owner-bad', () => ({ name: 'blog', owner: 'bad' }));
  rf('name-owner-number', () => ({ name: 'blog', owner: 5 }));
  rf('name-owner-empty', () => ({ name: 'blog', owner: '', index: 0 }));
  rf('name-feed-not-found', () => ({ name: 'news' }));
  rf('name-no-store', () => ({ name: 'blog' }), { feeds: null });
  rf('index-inline', () => ({ name: 'blog', index: 0 }));
  rf('index-inline-anonymous', () => ({ topic: rfTopic, owner: owner('bee'), index: 0 }), { grants: {}, feeds: null });
  rf('index-4096', () => ({ topic: rfTopic.toUpperCase(), owner: ownerHex('bee').toUpperCase(), index: 1 }));
  rf('index-4097', () => ({ name: 'blog', index: 2 }));
  rf('index-524289-anonymous', () => ({ topic: rfTopic, owner: owner('bee'), index: 3 }), { grants: {} });
  rf('index-524288-anonymous', () => ({ topic: rfTopic, owner: owner('bee'), index: 4 }), { grants: {} });
  rf('index-524289-connected', () => ({ name: 'blog', index: 3 }));
  rf('index-name-with-owner', () => ({ name: 'blog', owner: owner('publisher:0'), index: 0 }), { node: readNode({ entries: [
    { key: 'publisher:0', topic: rfTopicStr, index: 0, data: { utf8: 'by another owner' } }] }) });
  rf('index-not-found', () => ({ name: 'blog', index: 9 }));
  rf('index-500', () => ({ name: 'blog', index: 0 }), { node: readNode({ rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 500, json: { code: 500, message: 'read chunk failed' } } }] }) });
  rf('index-503', () => ({ name: 'blog', index: 0 }), { node: readNode({ rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 503, json: { code: 503, message: 'unavailable' } } }] }) });
  rf('index-not-the-soc', () => ({ name: 'blog', index: 0 }), { node: readNode({ rules: [
    { match: { prefix: '/chunks/' }, reply: { status: 200, body_utf8: '\u0005\0\0\0\0\0\0\0hello' } }] }) });
  rf('index-join-longer', () => ({ name: 'blog', index: 2 }), { node: readNode({ rules: [
    { match: { prefix: '/bytes/' }, reply: { status: 200, body_data: { seed: 'read-feed/4097', length: 4200 } } }] }) });
  rf('index-join-shorter', () => ({ name: 'blog', index: 2 }), { node: readNode({ rules: [
    { match: { prefix: '/bytes/' }, reply: { status: 200, body_data: { seed: 'read-feed/4097', length: 4000 } } }] }) });
  rf('index-join-404', () => ({ name: 'blog', index: 2 }), { node: readNode({ rules: [
    { match: { prefix: '/bytes/' }, reply: { status: 404, json: { code: 404, message: 'Not Found' } } }] }) });
  rf('index-span-past-payload', () => ({ name: 'blog', index: 5 }), { node: readNode({ chunks: [env.feedSoc('bee', rfTopicStr, 5, Buffer.from('ten bytes!'), 20n)] }) });
  rf('index-payload-past-span', () => ({ name: 'blog', index: 6 }), { node: readNode({ chunks: [env.feedSoc('bee', rfTopicStr, 6, Buffer.from('thirty bytes of payload, held!'), 10n)] }) });
  rf('index-soc-charge-refused', () => null, { grants: {}, feeds: null, steps: [
    { method: 'swarm_readData', params: () => ({ reference: env.rootAddress(env.seeded('read-feed/budget', 520000)) }) },
    { method: 'swarm_readFeedEntry', params: () => ({ topic: rfTopic, owner: owner('bee'), index: 1 }) },
  ], node: readNode({ data: [{ seed: 'read-feed/budget', length: 520000 }] }),
  deviation: { id: 'read-data-verified', core: 'the first read through the verified walk; the same results' } });
  rf('index-reserve-refused', () => null, { grants: {}, feeds: null, steps: [
    { method: 'swarm_readFeedEntry', params: () => ({ topic: rfTopic, owner: owner('bee'), index: 2 }) },
    { method: 'swarm_readFeedEntry', params: () => ({ topic: rfTopic, owner: owner('bee'), index: 4 }) },
  ] });
  const latestReply = (body, extra = {}) => ({ status: 200, headers: { 'swarm-feed-index': '0000000000000007',
    'swarm-feed-index-next': '0000000000000008', 'content-type': 'application/octet-stream', ...(extra.headers || {}) }, ...body, ...extra.reply });
  const latestNode = (reply) => readNode({ latest: [{ key: 'bee', topic: rfTopicStr, reply }] });
  rf('latest', () => ({ name: 'blog' }), { node: latestNode(latestReply({ body_utf8: 'the latest' })) });
  rf('latest-topic', () => ({ topic: rfTopic, owner: owner('bee') }), { node: latestNode(latestReply({ body_utf8: 'the latest' })) });
  rf('latest-empty-body', () => ({ name: 'blog' }), { node: latestNode(latestReply({ body_utf8: '' })) });
  rf('latest-declared-past-max', () => ({ topic: rfTopic, owner: owner('bee') }), { grants: {},
    node: latestNode(latestReply({ body_data: { seed: 'read-feed/latest', length: 524289 } })) });
  rf('latest-declared-at-max', () => ({ topic: rfTopic, owner: owner('bee') }), { grants: {},
    node: latestNode(latestReply({ body_data: { seed: 'read-feed/latest', length: 524288 } })) });
  rf('latest-declared-past-left', () => null, { grants: {}, feeds: null,
    node: latestNode(latestReply({ body_data: { seed: 'read-feed/latest', length: 300000 } })), steps: [
      { method: 'swarm_readFeedEntry', params: () => ({ topic: rfTopic, owner: owner('bee') }) },
      { method: 'swarm_readFeedEntry', params: () => ({ topic: rfTopic, owner: owner('bee') }) },
    ] });
  rf('latest-chunked', () => ({ name: 'blog' }), { node: latestNode(latestReply({ chunked: true,
    pieces_data: [{ seed: 'read-feed/piece-1', length: 70000 }, { seed: 'read-feed/piece-2', length: 5 }] })),
  deviation: { id: 'read-pieces', core: 'reserved per data frame from main; the same result' } });
  rf('latest-chunked-past-max', () => ({ topic: rfTopic, owner: owner('bee') }), { grants: {},
    node: latestNode(latestReply({ chunked: true, pieces_data: [{ seed: 'read-feed/piece-1', length: 400000 }, { seed: 'read-feed/piece-2', length: 200000 }] })),
    deviation: { id: 'read-pieces', core: 'reserved per data frame from main; data_too_large once past maxBytes' } });
  rf('latest-chunked-past-left', () => null, { grants: {}, feeds: null,
    node: latestNode(latestReply({ chunked: true, pieces_data: [{ seed: 'read-feed/piece-1', length: 300000 }] })), steps: [
      { method: 'swarm_readFeedEntry', params: () => ({ topic: rfTopic, owner: owner('bee') }) },
      { method: 'swarm_readFeedEntry', params: () => ({ topic: rfTopic, owner: owner('bee') }) },
    ], deviation: { id: 'read-pieces', core: 'reserved per data frame from main; what stays charged differs by less than one piece' } });
  rf('latest-chunked-cut', () => ({ name: 'blog' }), { node: latestNode(latestReply({ chunked: true,
    pieces_data: [{ seed: 'read-feed/piece-1', length: 1000 }], cutAfterPieces: true })),
  deviation: { id: 'transport-error-text', core: 'one text for the failure class (error)' } });
  rf('latest-declared-short', () => ({ name: 'blog' }), { node: latestNode(latestReply({ body_utf8: 'short', declare: 50 })),
    deviation: { id: 'transport-error-text', core: 'one text for the failure class (error)' } });
  rf('latest-no-index', () => ({ name: 'blog' }), { node: latestNode({ status: 200, headers: { 'swarm-feed-index-next': '0000000000000001' }, body_utf8: 'x' }) });
  rf('latest-no-next', () => ({ name: 'blog' }), { node: latestNode({ status: 200, headers: { 'swarm-feed-index': '0000000000000000' }, body_utf8: 'x' }) });
  rf('latest-bad-index', () => ({ name: 'blog' }), { node: latestNode({ status: 200, headers: { 'swarm-feed-index': 'zz', 'swarm-feed-index-next': '01' }, body_utf8: 'x' }) });
  rf('latest-404', () => ({ name: 'blog' }), { node: latestNode({ status: 404, json: { code: 404, message: 'Not Found' } }) });
  rf('latest-500', () => ({ name: 'blog' }), { node: latestNode({ status: 500, json: { code: 500, message: 'lookup failed' } }) });
  rf('latest-503-text', () => ({ name: 'blog' }), { node: latestNode({ status: 503, statusText: 'Service Unavailable', body_utf8: 'overloaded' }) });
  rf('latest-error-4097-bytes', () => ({ name: 'blog' }), { node: latestNode({ status: 503, body_data: { seed: 'read-feed/error', length: 4097 } }) });
  rf('latest-error-bom', () => ({ name: 'blog' }), { node: latestNode({ status: 400, body_hex: 'efbbbf227175697465643f22' }) });
  rf('latest-encoded-despite-identity', () => ({ name: 'blog' }), { node: latestNode(latestReply({ body_utf8: 'not really brotli' }, { headers: { 'content-encoding': 'br' } })),
    deviation: { id: 'transport-error-text', core: 'one text for the failure class (error)' } });
  rf('anonymous-request-budget', () => null, { grants: {}, feeds: null, steps: [
    ...Array.from({ length: 120 }, () => ({ method: 'swarm_listFeeds', params: () => undefined })),
    { method: 'swarm_readFeedEntry', params: () => ({ topic: rfTopic, owner: owner('bee'), index: 0 }) },
  ] });

  // -------------------------------------------------------------------------
  // listFeeds.
  add({ id: 'list-feeds-none', method: 'swarm_listFeeds', params: () => ({ ignored: true }), grants: {} });
  add({ id: 'list-feeds-two', method: 'swarm_listFeeds', params: () => undefined, feeds: storeBee({
    blog: feedRecord(ORIGIN, 'blog', 'bee-wallet', 'bee', { lastUpdated: T0 - 1000, lastReference: REF }),
    news: feedRecord(ORIGIN, 'news', 'bee-wallet', 'bee'),
  }) });
  add({ id: 'list-feeds-other-site', method: 'swarm_listFeeds', params: () => undefined, origin: OTHER, grants: {}, feeds: storeBee(blogBee) });
  add({ id: 'list-feeds-byte-budget', grants: {}, feeds: storeBee(Object.fromEntries(Array.from({ length: 40 }, (_, i) =>
    [`feed-${String(i).padStart(2, '0')}-${'x'.repeat(50)}`, feedRecord(ORIGIN, `feed-${i}`, 'bee-wallet', 'bee')]))),
  steps: Array.from({ length: 30 }, () => ({ method: 'swarm_listFeeds', params: () => undefined })) });

  // -------------------------------------------------------------------------
  // Messaging: getMessagingIdentity, sendPss, sendGsoc, subscribe, unsubscribe.
  const addresses = {
    overlay: '36b7efd913ca4cf880b8eeac5093fa27b0825906c600685b6abdd6566e6cfe8f',
    underlay: ['/ip4/127.0.0.1/tcp/1634/p2p/16Uiu2HAm8k3iE4M7kxzxx4K2sKGSgC5Yp4wDS6xLdqyAn6B2Gk5q'],
    ethereum: '0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0',
    publicKey: keyOf('bee').publicKey.slice(2),
    pssPublicKey: keyOf('publisher:1').publicKey.slice(2),
  };
  const gm = (id, over = {}) => add({ id: `messaging-identity-${id}`, method: 'swarm_getMessagingIdentity', params: () => undefined,
    grants: messagingGrant(), node: { addresses }, ...over });
  gm('granted');
  gm('no-messaging-grant', { grants: connected(ORIGIN) });
  gm('unreachable', { node: { addresses, rules: [{ match: { path: '/node' }, reply: { status: 500 } }] } });
  gm('uncompressed-key', { node: { addresses: { ...addresses, pssPublicKey: `04${'ab'.repeat(64)}` } } });
  gm('node-500', { node: { rules: [{ match: { path: '/addresses' }, reply: { status: 500, json: { code: 500, message: 'no' } } }] } });
  gm('malformed', { node: { addresses: { overlay: 5 } } });
  gm('grant-prompt-rejected', { grants: connected(ORIGIN), prompts: [{ kind: 'swarm.messaging', approve: false }] });
  gm('messaging-revoked-at-service', { at_execute: { messaging: 'revoked' } });

  const recipient = keyOf('publisher:2').publicKey.slice(2);
  const sp = (id, params, over = {}) => add({ id: `send-pss-${id}`, method: 'swarm_sendPss', params, grants: messagingGrant(),
    node: { stamps: STAMPS.usable }, ...over });
  sp('params-null', () => null);
  sp('options-key', () => ({ options: { x: 1 }, topic: '' }));
  sp('topic-missing', () => ({ recipient: 'x' }));
  sp('topic-empty', () => ({ topic: '', recipient: 'x' }));
  sp('topic-257-bytes', () => ({ topic: `${'é'.repeat(128)}x`, recipient: 'x' }));
  sp('topic-control', () => ({ topic: 'a\u0000', recipient: 'x' }));
  sp('recipient-missing', () => ({ topic: 'chat', targets: 'zz' }));
  sp('recipient-uncompressed', () => ({ topic: 'chat', recipient: `04${'ab'.repeat(64)}`, targets: 'zz' }));
  sp('recipient-short', () => ({ topic: 'chat', recipient: recipient.slice(2), targets: 'zz' }));
  sp('recipient-0x', () => ({ topic: 'chat', recipient: `0x${recipient}`, targets: 'zz', data: 7 }));
  for (const [id, targets] of [['targets-missing', undefined], ['targets-number', 1234], ['targets-1-byte', 'ab'],
    ['targets-4-bytes', 'abcdef01'], ['targets-odd', 'abc'], ['targets-not-hex', 'abzz'], ['targets-megabyte', 'a'.repeat(1 << 20)]]) {
    sp(id, () => ({ topic: 'chat', recipient, targets, data: 7 }));
  }
  sp('data-missing', () => ({ topic: 'chat', recipient, targets: 'abcd' }), { grants: connected(ORIGIN) });
  sp('data-4001', () => ({ topic: 'chat', recipient, targets: 'abcd', data: bytes('send-pss/4001', 4001) }), { grants: connected(ORIGIN) });
  sp('no-messaging-grant', () => ({ topic: 'chat', recipient, targets: 'abcd', data: 'hi' }), { grants: connected(ORIGIN),
    readiness: { ok: false, reason: 'node-stopped' } });
  for (const reason of NOT_READY) sp(`not-ready-${reason}`, () => ({ topic: 'chat', recipient, targets: 'abcd', data: 'hi' }), { readiness: { ok: false, reason } });
  sp('sent', () => ({ topic: 'chat', recipient, targets: 'abcd', data: 'hi' }));
  sp('sent-empty', () => ({ topic: 'chat', recipient, targets: 'abcd', data: '' }));
  sp('sent-4000', () => ({ topic: 'chat', recipient, targets: 'ABCDEF', data: bytes('send-pss/4000', 4000) }));
  sp('sent-upper-case', () => ({ topic: 'Chat 💬', recipient: recipient.toUpperCase().replace(/^0/, '0'), targets: 'ABCD', data: u8('hi') }));
  sp('sent-0x-recipient', () => ({ topic: 'chat', recipient: `0x${recipient}`, targets: 'abcd', data: 'hi' }));
  sp('bad-point', () => ({ topic: 'chat', recipient: `02${'ff'.repeat(32)}`, targets: 'abcd', data: 'hi' }));
  sp('full-mutable-batch', () => ({ topic: 'chat', recipient, targets: 'abcd', data: 'hi' }), { node: { stamps: STAMPS.fullMutable } });
  sp('no-stamps', () => ({ topic: 'chat', recipient, targets: 'abcd', data: 'hi' }), { node: { stamps: STAMPS.none } });
  sp('node-400', () => ({ topic: 'chat', recipient, targets: 'abcd', data: 'hi' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/pss/send/' }, reply: { status: 400, json: { code: 400, message: 'invalid recipient public key' } } }] } });
  sp('node-hangs-up', () => ({ topic: 'chat', recipient, targets: 'abcd', data: 'hi' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/pss/send/' }, reply: { hangUp: true } }] },
  deviation: { id: 'transport-error-text', core: 'one text for the failure class (error)' } });
  // The send prompt, the messaging rule and Agent custody, read when the
  // rule is chosen and again just before the send: the send's effect covers
  // its /stamps read, so the world changes as the request reaches the
  // service.
  const hi = () => ({ topic: 'chat', recipient, targets: 'abcd', data: 'hi' });
  const messagingRule = rule({ messaging: true }, ORIGIN, { messaging: true });
  sp('prompt-rejected', hi, { prompts: [{ kind: 'swarm.messaging', approve: false }] });
  sp('grant-prompt-rejected', hi, { grants: connected(ORIGIN), prompts: [{ kind: 'swarm.messaging', approve: false }] });
  sp('rule', hi, { grants: messagingRule });
  sp('rule-in-custody', hi, { grants: messagingRule, custody: true });
  sp('rule-off-before-send', hi, { grants: messagingRule, at_execute: { rule_off: 'messaging' } });
  sp('rule-custody-before-send', hi, { grants: messagingRule, at_execute: { custody: true } });
  sp('messaging-revoked-at-service', hi, { at_execute: { messaging: 'revoked' } });
  add({ id: 'send-pss-always-allow', grants: messagingGrant(), node: { stamps: STAMPS.usable },
    prompts: [{ kind: 'swarm.messaging', approve: true, choices: { alwaysAllow: true } }], steps: [
      { method: 'swarm_sendPss', params: hi }, { method: 'swarm_sendPss', params: () => ({ topic: 'chat', recipient, targets: 'abcd', data: 'again' }) },
    ] });

  const sg = (id, params, over = {}) => add({ id: `send-gsoc-${id}`, method: 'swarm_sendGsoc', params, grants: messagingGrant(),
    node: { stamps: STAMPS.usable }, ...over });
  sg('params-null', () => null);
  sg('options-key', () => ({ options: { x: 1 }, address: 'x' }));
  sg('address', () => ({ address: 'ab'.repeat(32), topic: '' }));
  sg('topic-empty', () => ({ topic: '' }));
  sg('data-empty', () => ({ topic: 'room', data: '' }), { grants: connected(ORIGIN) });
  sg('data-4001', () => ({ topic: 'room', data: bytes('send-gsoc/4001', 4001) }), { grants: connected(ORIGIN) });
  sg('no-messaging-grant', () => ({ topic: 'room', data: 'hi' }), { grants: connected(ORIGIN), readiness: { ok: false, reason: 'node-stopped' } });
  sg('not-ready', () => ({ topic: 'room', data: 'hi' }), { readiness: { ok: false, reason: 'no-usable-stamps' } });
  sg('sent', () => ({ topic: 'chat', data: 'hello room' }));
  sg('sent-4000', () => ({ topic: 'чат/聊天/🎉', data: bytes('send-gsoc/4000', 4000) }));
  sg('sent-256-byte-topic', () => ({ topic: 'r'.repeat(256), data: u8('hi') }));
  sg('sent-twice-cached', () => null, { steps: [
    { method: 'swarm_sendGsoc', params: () => ({ topic: 'chat', data: 'one' }) },
    { method: 'swarm_sendGsoc', params: () => ({ topic: 'chat', data: 'two' }) },
  ] });
  // Topics bee-js mines within 400 candidates, so the budget's sixteen run quickly.
  const quick = [4, 6, 8, 11, 13, 14, 26, 27, 30, 46, 60, 62, 69, 81, 104, 111, 112].map((i) => `room ${i}`);
  sg('topic-budget', () => null, { steps: quick.map((topic) => ({ method: 'swarm_sendGsoc', params: () => ({ topic, data: 'hi' }) })) });
  sg('no-stamps', () => ({ topic: 'chat', data: 'hi' }), { node: { stamps: STAMPS.none } });
  sg('full-mutable-batch', () => ({ topic: 'chat', data: 'hi' }), { node: { stamps: STAMPS.fullMutable } });
  sg('node-500', () => ({ topic: 'chat', data: 'hi' }), { node: { stamps: STAMPS.usable, rules: [
    { match: { prefix: '/soc/' }, reply: { status: 500, json: { code: 500, message: 'gsoc refused' } } }] } });
  sg('rule', () => ({ topic: 'chat', data: 'hi' }), { grants: rule({ messaging: true }, ORIGIN, { messaging: true }) });
  sg('rule-custody-before-send', () => ({ topic: 'chat', data: 'hi' }), { grants: rule({ messaging: true }, ORIGIN, { messaging: true }),
    at_execute: { custody: true } });
  sg('messaging-revoked-at-service', () => ({ topic: 'chat', data: 'hi' }), { at_execute: { messaging: 'revoked' } });
  sg('name-moved-before-send', () => ({ topic: 'chat', data: 'hi' }), { origin: ENS, grants: messagingGrant(ENS), at_execute: { name: 'moved' } });

  const su = (id, params, over = {}) => add({ id: `subscribe-${id}`, method: 'swarm_subscribe', params, grants: messagingGrant(), ...over });
  su('params-null', () => null);
  su('options-key', () => ({ options: { x: 1 }, kind: 'nope' }));
  su('kind-missing', () => ({ topic: 'room' }));
  su('kind-other', () => ({ kind: 'feed', topic: 'room' }));
  su('gsoc-both', () => ({ kind: 'gsoc', topic: 'room', address: 'ab'.repeat(32) }));
  su('gsoc-neither', () => ({ kind: 'gsoc' }));
  su('gsoc-address-bad', () => ({ kind: 'gsoc', address: 'xyz' }));
  su('gsoc-topic-bad', () => ({ kind: 'gsoc', topic: '' }));
  su('pss-address', () => ({ kind: 'pss', address: 'ab'.repeat(32) }));
  su('pss-no-topic', () => ({ kind: 'pss' }));
  su('pss-topic-bad', () => ({ kind: 'pss', topic: 'a\u0007' }));
  su('no-page', () => null, { steps: [{ method: 'swarm_subscribe', params: () => ({ kind: 'pss', topic: 'chat' }), page: false }] });
  su('no-messaging-grant', () => ({ kind: 'pss', topic: 'chat' }), { grants: connected(ORIGIN) });
  su('unreachable', () => ({ kind: 'pss', topic: 'chat' }), { node: { rules: [{ match: { path: '/node' }, reply: { status: 502 } }] } });
  su('pss-topic', () => ({ kind: 'pss', topic: 'chat' }));
  su('gsoc-address', () => ({ kind: 'gsoc', address: 'AB'.repeat(32) }));
  su('gsoc-topic', () => ({ kind: 'gsoc', topic: 'chat' }));
  su('grant-prompt-rejected', () => ({ kind: 'pss', topic: 'chat' }), { grants: connected(ORIGIN),
    prompts: [{ kind: 'swarm.messaging', approve: false }] });
  su('messaging-revoked-at-service', () => ({ kind: 'pss', topic: 'chat' }), { at_execute: { messaging: 'revoked' } });
  // subscribe-proxy (question 4, decided 2026-11-24). The world's session:
  // a proxy or Tor on or off, and the node, its URL classified by main's own
  // test (ipfs/gateway-transport.js's isLoopbackGatewayUrl, which bzz:'s
  // transport uses for the Ant node). The reference ignores the session and
  // opens the socket; the core's subscribe check gets main's answer
  // (session.subscribe_check, the core's input): refused while a proxy or
  // Tor is on and the node isn't on loopback. Ending open subscriptions
  // when a proxy or Tor comes on, and telling the user, are main's (SWM-7).
  const REMOTE_NODE = 'http://192.0.2.7:1633';
  const proxyOrTor = { id: 'subscribe-proxy', core: {
    error: { code: 4900, message: 'Node not available: proxy-or-tor', data: { reason: 'proxy-or-tor' } }, websockets: [] } };
  su('pss-topic-remote-node-proxy', () => ({ kind: 'pss', topic: 'chat' }), {
    session: { proxy: true, tor: false, node_kind: 'external', node_url: REMOTE_NODE }, deviation: proxyOrTor });
  su('gsoc-topic-remote-node-tor', () => ({ kind: 'gsoc', topic: 'chat' }), {
    session: { proxy: false, tor: true, node_kind: 'external', node_url: REMOTE_NODE }, deviation: proxyOrTor });
  // Parity: an external node on loopback subscribes with a proxy on, and a
  // remote one with neither on.
  su('pss-topic-loopback-node-proxy', () => ({ kind: 'pss', topic: 'chat' }), { session: { proxy: true, tor: false, node_kind: 'external' } });
  su('gsoc-topic-loopback-node-tor', () => ({ kind: 'gsoc', topic: 'chat' }), { session: { proxy: false, tor: true, node_kind: 'external' } });
  su('pss-topic-remote-node-direct', () => ({ kind: 'pss', topic: 'chat' }), {
    session: { proxy: false, tor: false, node_kind: 'external', node_url: REMOTE_NODE } });
  su('then-unsubscribe', () => null, { steps: [
    { method: 'swarm_subscribe', params: () => ({ kind: 'pss', topic: 'chat' }) },
    { method: 'swarm_unsubscribe', params: () => ({ subscriptionId: env.firstSubscriptionId }) },
    { method: 'swarm_unsubscribe', params: () => ({ subscriptionId: env.firstSubscriptionId }) },
  ] });
  for (const [id, params] of [['unsubscribe-params-null', null], ['unsubscribe-id-missing', {}], ['unsubscribe-id-empty', { subscriptionId: '' }],
    ['unsubscribe-id-number', { subscriptionId: 5 }], ['unsubscribe-unknown', { subscriptionId: 'nope' }]]) {
    add({ id, method: 'swarm_unsubscribe', params: () => params, grants: {} });
  }
  add({ id: 'unsubscribe-without-page-connected', grants: connected(ORIGIN), steps: [
    { method: 'swarm_unsubscribe', params: () => ({ subscriptionId: 'nope' }), page: false },
  ] });

  return cases;
}

module.exports = {
  methodCases, STAMPS, batch, grant, connected, identity, feedStore, originEntry,
  T0, ORIGIN, OTHER, ENS, BATCH_A, BATCH_B, BATCH_C, MANIFEST, REF, MiB,
};
