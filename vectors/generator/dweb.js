'use strict';

// Dweb transport vectors (design 0006, step 2): the reference's own protocol
// handlers produce every expected output. bzz-protocol.js, ipfs-protocol.js,
// ipfs-manager.js, content-name-resolver.js, lib/gateway-location.js,
// lib/gateway-response-headers.js, shared/cid-utils.js, shared/origin-utils.js,
// onchain-html.js and onchain-app-protocol.js are loaded through naming.js's
// harness, which appends test-only exports to the original source and stubs
// the Electron environment, so no reference code is copied here.
//
// Name resolution is stubbed: each case says what the resolver returns or
// throws, and records which resolver the handler asked, for which name.
// Upstream answers are scripted Responses whose bodies count their reads.
//
// What isn't the reference's is marked:
// - `plan` composes the reference's outcome (`js`) with the tables in
//   `constants`; its `response` operations, its `trust` labels and
//   `body_idle_ms` are the design's.
// - `validation` has no reference at all (design 0006, "Validation before any
//   dial"): its cases and outcomes are the design's, marked `source: design`.
// - `deviation` marks where the core differs from today by design.

const assert = require('node:assert/strict');
const { loadWithInternals } = require('./naming');

const SILENT_LOG = { verbose() {}, info() {}, warn() {}, error() {}, debug() {}, log() {} };
const ELECTRON = {
  ipcMain: { handle() {}, on() {}, removeHandler() {} },
  net: {},
  session: { defaultSession: { resolveProxy: async () => 'DIRECT' } },
  app: { getPath: () => '/nonexistent' },
  BrowserWindow: { getAllWindows: () => [] },
};
// Where the stubs put the nodes. The core never learns these (design 0006).
const ANT_API_URL = 'http://127.0.0.1:1633';
const GATEWAY_URL = 'http://127.0.0.1:8080';
// Design 0006: a body idle bound for every backend (deviation body-idle).
const BODY_IDLE_MS = 60_000;
// Design 0006, "Validation before any dial": the bound on an error plan's
// message, in UTF-16 code units.
const MAX_MESSAGE_UNITS = 131_072;

class TaskWorkerUnavailable extends Error {}

const ch = (...codes) => String.fromCodePoint(...codes);
const hexOf = (bytes) => Buffer.from(bytes).toString('hex');
const bytesOf = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

// ---------------------------------------------------------------------------
// The reference, loaded with its I/O stubbed

function loadReference(checkout) {
  const world = {
    antApiUrl: ANT_API_URL,
    resolution: null,
    calls: [],
    fetches: [],
    upstream: null,
  };
  const resolver = (fn) => async (name) => {
    world.calls.push({ fn, name });
    const resolution = world.resolution;
    // The handler catches what the resolver throws: flag it, so the run fails.
    if (!resolution) {
      world.unscripted = name;
      throw new Error(`unscripted resolution of ${name}`);
    }
    if (Object.hasOwn(resolution, 'threw')) throw new Error(resolution.threw);
    return resolution.value;
  };
  const names = loadWithInternals(checkout, 'src/main/content-name-resolver.js', [], {
    './ens-resolver': { resolveEnsContent: resolver('resolveEnsContent') },
    './tezos-domains-resolver': { resolveTezosDomain: resolver('resolveTezosDomain') },
  });
  const bzz = loadWithInternals(checkout, 'src/main/swarm/bzz-protocol.js', [
    'withoutPageStateHeaders', 'shouldRetry', 'FORWARDED_REQUEST_HEADERS', 'REDIRECT_STATUSES', 'NULL_BODY_STATUSES',
  ], {
    '../logger': SILENT_LOG,
    '../service-registry': { getAntApiUrl: () => world.antApiUrl },
    '../content-name-resolver': names,
  });
  const registry = loadWithInternals(checkout, 'src/main/service-registry.js', [], { electron: ELECTRON });
  const manager = loadWithInternals(checkout, 'src/main/ipfs-manager.js', [
    'proxiedResponseHeaders', 'proxiedRedirectHeaders', 'DROPPED_UPSTREAM_RESPONSE_HEADERS',
  ], {
    electron: ELECTRON,
    './logger': SILENT_LOG,
    './profile-paths': { getIpfsDataDir: () => '/nonexistent' },
    './profile-resolver': { getActiveProfile: () => null },
    './service-registry': {
      MODE: registry.MODE, updateService() {}, setStatusMessage() {}, setErrorState() {}, clearErrorState() {}, clearService() {},
    },
    './ipfs/freedom-ipfs-native-node': { FreedomIpfsNativeNode: class {} },
    './ipfs/ipfs-gateway-probe': { IPFS_GATEWAY_PROBE_PATH: '/', isIpfsGatewayProbeResponse: () => false },
    './ipfs/gateway-transport': {
      gatewayFetch: (...args) => world.gatewayFetch(...args),
      isLoopbackHostname: () => true,
      isOnionHostname: () => false,
    },
  }, `module.exports.__setState = (mode, state, url) => { currentMode = mode; currentState = state; externalGatewayUrl = url; };`);
  const ipfs = loadWithInternals(checkout, 'src/main/ipfs/ipfs-protocol.js', [
    'renderSmallTextResponse', 'isDocumentRequest', 'STRIPPED_REQUEST_HEADERS', 'KNOWN_GATEWAY_HOSTS',
  ], {
    '../logger': SILENT_LOG,
    '../content-name-resolver': names,
    '../ipfs-manager': manager,
  });
  const native = loadWithInternals(checkout, 'src/main/ipfs/freedom-ipfs-native-node.js', [
    'BUFFER_SIZE', 'ATTEMPT_TIMEOUT_MS', 'REQUEST_QUEUE_TIMEOUT_MS',
  ], {
    '../logger': SILENT_LOG,
    './freedom-ipfs-native-binding': {
      loadNativeBinding() { throw new Error('no native binding in the vectors'); },
      isNativeBindingAvailable: () => false,
    },
  });
  const cids = loadWithInternals(checkout, 'src/shared/cid-utils.js', [], {});
  const origins = loadWithInternals(checkout, 'src/shared/origin-utils.js', [], {});
  const location = loadWithInternals(checkout, 'src/main/lib/gateway-location.js', ['decodeSegment', 'sameSegment'], {});
  const pageState = loadWithInternals(checkout, 'src/main/lib/gateway-response-headers.js', [], {});
  const html = loadWithInternals(checkout, 'src/main/onchain/onchain-html.js', [], {});
  const onchain = loadWithInternals(checkout, 'src/main/onchain/onchain-app-protocol.js', ['hasTrustConflict'], {
    '../logger': SILENT_LOG,
    '../networks/chain-data-router': { request: async () => { throw new Error('unscripted chain read'); } },
    '../networks/network-registry': { getNetwork: () => ({ name: 'Ethereum' }) },
    '../webrequest-dispatcher': { registerWebRequestHandler() {} },
    '../task-worker-host': {
      createTaskWorkerHost: () => ({ run: async () => { throw new TaskWorkerUnavailable('decoded in the vectors\' thread'); } }),
      TaskWorkerUnavailable,
    },
    './onchain-html': html,
  });
  return { world, names, bzz, manager, mode: registry.MODE, ipfs, native, cids, origins, location, pageState, html, onchain };
}

// ---------------------------------------------------------------------------
// Responses and bodies

/** A chunk: hex, or `{ fill, length }` for a long run of one byte. */
function chunkBytes(spec) {
  if (typeof spec === 'string') return bytesOf(spec);
  return new Uint8Array(spec.length).fill(parseInt(spec.fill, 16));
}

/** A body that counts the reads it answers; `highWaterMark: 0`, so a read is a pull. */
function countedBody(chunks, counter) {
  let next = 0;
  return new ReadableStream({
    pull(controller) {
      counter.reads += 1;
      if (next < chunks.length) controller.enqueue(chunkBytes(chunks[next++]));
      else controller.close();
    },
    cancel() {
      counter.cancelled = true;
    },
  }, { highWaterMark: 0 });
}

function scriptedResponse(upstream, counter) {
  const body = upstream.chunks == null ? null : countedBody(upstream.chunks, counter);
  return new Response(body, { status: upstream.status, headers: upstream.headers });
}

async function describeResponse(response) {
  const body = response.body ? hexOf(new Uint8Array(await response.arrayBuffer())) : null;
  return { status: response.status, headers: [...response.headers], body };
}

const concatChunks = (chunks) => hexOf(Buffer.concat((chunks || []).map((c) => Buffer.from(chunkBytes(c)))));

// ---------------------------------------------------------------------------
// Multibase, for building inputs only (the reference decides what they mean)

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_FLICKR = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

function radix(bytes, alphabet) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  const base = BigInt(alphabet.length);
  let out = '';
  while (n > 0n) {
    out = alphabet[Number(n % base)] + out;
    n /= base;
  }
  for (const b of bytes) {
    if (b) break;
    out = alphabet[0] + out;
  }
  return out;
}

function packed(bytes, alphabet, bits, pad) {
  let buffer = 0;
  let held = 0;
  let out = '';
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    held += 8;
    while (held >= bits) {
      out += alphabet[(buffer >> (held - bits)) & ((1 << bits) - 1)];
      held -= bits;
    }
    buffer &= (1 << held) - 1;
  }
  if (held > 0) out += alphabet[(buffer << (bits - held)) & ((1 << bits) - 1)];
  if (pad) while ((out.length * bits) % 8 !== 0) out += '=';
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const MULTIBASES = [
  ['base2', '0', (b) => packed(b, '01', 1)],
  ['base8', '7', (b) => packed(b, '01234567', 3)],
  ['base10', '9', (b) => radix(b, '0123456789')],
  ['base16', 'f', (b) => packed(b, '0123456789abcdef', 4)],
  ['base16upper', 'F', (b) => packed(b, '0123456789ABCDEF', 4)],
  ['base32', 'b', (b) => packed(b, B32, 5)],
  ['base32upper', 'B', (b) => packed(b, B32.toUpperCase(), 5)],
  ['base32pad', 'c', (b) => packed(b, B32, 5, true)],
  ['base32hex', 'v', (b) => packed(b, '0123456789abcdefghijklmnopqrstuv', 5)],
  ['base36', 'k', (b) => radix(b, '0123456789abcdefghijklmnopqrstuvwxyz')],
  ['base36upper', 'K', (b) => radix(b, '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')],
  ['base58btc', 'z', (b) => radix(b, B58)],
  ['base58flickr', 'Z', (b) => radix(b, B58_FLICKR)],
  ['base64', 'm', (b) => packed(b, B64, 6)],
  ['base64pad', 'M', (b) => packed(b, B64, 6, true)],
  ['base64url', 'u', (b) => packed(b, B64URL, 6)],
  ['base64urlpad', 'U', (b) => packed(b, B64URL, 6, true)],
];

const DIGEST = '6e6ff7950a36187a801613426e858dce686cd7d7e3c0fc42ee0330072d245c95';
const ED25519_KEY = '8a1f8b0c2d4e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8';
const CID_BYTES = {
  dagPb: '01701220' + DIGEST,
  raw: '01551220' + DIGEST,
  dagJson: '01a9021220' + DIGEST,
  blake2b: '0171a0e40220' + DIGEST,
  libp2pKey: '017200240801122' + '0' + ED25519_KEY,
};
const b58 = (hex) => radix(bytesOf(hex), B58);
const b32cid = (hex) => 'b' + packed(bytesOf(hex), B32, 5);
const zcid = (hex) => 'z' + b58(hex);
const CIDV0 = b58('1220' + DIGEST);
const PEER_ED25519 = b58('00240801122' + '0' + ED25519_KEY);
const PEER_SHA256 = b58('1220' + 'ab'.repeat(32));
const PEER_SECP256K1 = b58('002508021221' + '03' + 'cd'.repeat(32));
const SWARM_REF = 'c0ffee'.repeat(10) + 'beef';
const SWARM_REF_ENCRYPTED = SWARM_REF + 'a1b2'.repeat(16);

// ---------------------------------------------------------------------------
// CIDs and IPNS keys

function cidInputs() {
  const v0 = [
    ['cidv0', CIDV0],
    ['cidv0-lowercased', CIDV0.toLowerCase()],
    ['cidv0-uppercased', CIDV0.toUpperCase()],
    ['cidv0-other-digest', b58('1220' + 'ff'.repeat(32))],
    ['cidv0-short', CIDV0.slice(0, -1)],
    ['cidv0-long', CIDV0 + 'x'],
    ['cidv0-zero-in-body', CIDV0.slice(0, -1) + '0'],
  ];
  // Other 34-byte multihashes whose base58 still reads `Qm` + 44.
  for (const prefix of ['1221', '121f', '1320', '1120']) {
    const text = b58(prefix + DIGEST);
    if (/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(text)) v0.push([`cidv0-header-${prefix}`, text]);
  }
  const z = [
    ['z-dag-pb', zcid(CID_BYTES.dagPb)],
    ['z-raw', zcid(CID_BYTES.raw)],
    ['z-dag-json', zcid(CID_BYTES.dagJson)],
    ['z-blake2b', zcid(CID_BYTES.blake2b)],
    ['z-libp2p-key', zcid(CID_BYTES.libp2pKey)],
    ['z-lowercased', zcid(CID_BYTES.dagPb).toLowerCase()],
    ['z-uppercased', 'z' + zcid(CID_BYTES.dagPb).slice(1).toUpperCase()],
    ['z-version-0', zcid('00701220' + DIGEST)],
    ['z-version-2', zcid('02701220' + DIGEST)],
    ['z-truncated', zcid(CID_BYTES.dagPb.slice(0, -2))],
    ['z-extended', zcid(CID_BYTES.dagPb + '00')],
    ['z-overlong-codec', zcid('01f0001220' + DIGEST)],
    ['z-five-byte-codec', zcid('01ffffffff0f1220' + DIGEST)],
    ['z-five-byte-codec-high-bits', zcid('0180808080101220' + DIGEST)],
    ['z-six-byte-codec', zcid('0180808080801020' + DIGEST)],
    ['z-five-byte-length-vanishing', zcid('017012' + 'a080808010' + DIGEST)],
    ['z-digest-length-zero', zcid('0170120' + '0')],
    ['z-codec-unterminated', zcid('01ff')],
    ['z-identity-hash', zcid('015500' + '05' + '68656c6c6f')],
    ['z-short-body', 'z' + 'A'.repeat(39)],
    ['z-min-body', 'z' + 'A'.repeat(40)],
    ['z-only-lowercase-letters', 'z' + '1'.repeat(10) + 'abc'.repeat(10)],
    ['z-zero-in-body', zcid(CID_BYTES.dagPb).slice(0, -1) + '0'],
    ['z-leading-ones', 'z11' + zcid(CID_BYTES.dagPb).slice(1)],
    ['z-long', zcid('0170' + 'a0e402' + 'fe03' + 'ab'.repeat(510))],
  ];
  const ipns = [
    ['peer-ed25519', PEER_ED25519],
    ['peer-ed25519-lowercased', PEER_ED25519.toLowerCase()],
    ['peer-sha256', PEER_SHA256],
    ['peer-sha256-lowercased', PEER_SHA256.toLowerCase()],
    ['peer-secp256k1', PEER_SECP256K1],
    ['cidv0-as-peer', CIDV0],
    ['dnslink-name', 'docs.ipfs.tech'],
    ['ens-name', 'vitalik.eth'],
    ['empty', ''],
    ['one', '1'],
    ['ones', '111'],
    ['two-byte-mh', b58('0000')],
    ['three-byte-mh', b58('000100')],
    ['code-0x80', b58('8001' + '00')],
    ['length-0x80', b58('0080' + '00'.repeat(128))],
    ['length-mismatch', b58('0005' + '00'.repeat(4))],
    ['identity-127', b58('007f' + '11'.repeat(127))],
    ['base32-cid', b32cid(CID_BYTES.libp2pKey)],
  ];
  return { v0, z, ipns };
}

function buildCids(ref) {
  const { cids } = ref;
  const { v0, z, ipns } = cidInputs();
  const all = [...v0, ...z, ...ipns];
  const out = [];
  for (const [id, input] of all) {
    out.push({
      id,
      input,
      cid_v0_to_v1_base32: cids.cidV0ToV1Base32(input),
      cid_v1_b58btc_to_base32: cids.cidV1B58btcToBase32(input),
      ipns_mh_to_cid_v1_base36: cids.ipnsMhToCidV1Base36(input),
    });
  }
  // Sanity: the inputs mean what their names say.
  assert.equal(out.find((e) => e.id === 'cidv0').cid_v0_to_v1_base32, b32cid(CID_BYTES.dagPb));
  assert.equal(out.find((e) => e.id === 'z-dag-json').cid_v1_b58btc_to_base32, b32cid(CID_BYTES.dagJson));
  assert.match(PEER_ED25519, /^12D3KooW/);
  assert.match(PEER_SECP256K1, /^16Uiu2H/);
  return out;
}

// ---------------------------------------------------------------------------
// Hosts and published paths

function hostInputs() {
  return [
    'site.eth', 'Site.ETH', 'a.b.c.eth', 'x.box', 'x.wei', 'x.gwei', 'x.GWEI', 'x.tez', 'X.TEZ', 'a..tez', '.tez', 'tez', 'x.tez.',
    'eth', '.eth', 'a..eth', 'a.eth.', 'example.com', 'localhost', '127.0.0.1', '[::1]', 'a', '', '.', 'a.', '..',
    'a b.eth', 'a%20b.eth', 'a' + ch(0xa0) + 'b.c', 'a' + ch(0x3000) + 'b.c', 'a' + ch(0x2028) + 'b.c', 'a' + ch(0xfeff) + 'b.c',
    'a' + ch(0x85) + 'b.c', 'a' + ch(0x0b) + 'b.c', 'a' + ch(0) + 'b.c', 'a' + ch(0x1f) + 'b.c', 'a' + ch(0x7f) + 'b.c',
    'a/b.eth', 'a:b.eth', 'a@b.eth', 'a?b.eth', 'a#b.eth', 'a\\b.eth', 'a%b.eth', ch(0xe4) + '.eth', '%C3%A4.eth', 'xn--4ca.eth',
    ch(0x1f600) + '.eth', 'x.' + ch(0x212a) + 'eth', 'x.et' + ch(0x0130), 'a_b.example', 'docs.ipfs.tech', 'x.ETH.',
  ];
}

function buildHosts(ref) {
  const { origins, names } = ref;
  return hostInputs().map((host) => ({
    host,
    is_ens_host: origins.isEnsHost(host),
    is_tezos_domain_host: origins.isTezosDomainHost(host),
    is_dweb_name_host: origins.isDwebNameHost(host),
    is_potential_ens_name: origins.isPotentialEnsName(host),
    label: names.nameSystemLabelForHost(host),
  }));
}

function buildPublishedPaths(ref) {
  const bases = [null, '', '/', '/docs', '/docs/', 'docs', 'docs/', '//', '/a//', '/a/b/', '0', '/%2F', '/' + ch(0xe9)];
  const requests = ['', '/', '/x', 'x', '//x', '/x/', '/x?y', '/%2e'];
  const out = [];
  for (const base of bases) {
    for (const request of requests) out.push({ base_path: base, request_path: request, joined: ref.names.joinPublishedPath(base, request) });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Requests: one handler call each, with the resolver and the node stubbed

const NAV = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
const okBzz = (extra = {}) => ({ value: { type: 'ok', protocol: 'bzz', decoded: SWARM_REF, ...extra } });
const okIpfs = (extra = {}) => ({ value: { type: 'ok', protocol: 'ipfs', decoded: b32cid(CID_BYTES.dagPb), ...extra } });
const okIpns = (extra = {}) => ({ value: { type: 'ok', protocol: 'ipns', decoded: 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8', ...extra } });

function bzzCases() {
  const h = SWARM_REF;
  const cases = [
    // Hash hosts.
    ['hash', `bzz://${h}/`],
    ['hash-no-path', `bzz://${h}`],
    ['hash-path-query', `bzz://${h}/a/b.html?x=1&y=%2F#frag`],
    ['hash-empty-query', `bzz://${h}/a?`],
    ['hash-uppercase', `bzz://${h.toUpperCase()}/x`],
    ['hash-mixed-case', `bzz://${h.slice(0, 32).toUpperCase()}${h.slice(32)}/x`],
    ['hash-encrypted', `bzz://${SWARM_REF_ENCRYPTED}/x`],
    ['hash-63', `bzz://${h.slice(1)}/`],
    ['hash-65', `bzz://${h}a/`],
    ['hash-127', `bzz://${SWARM_REF_ENCRYPTED.slice(1)}/`],
    ['hash-129', `bzz://${SWARM_REF_ENCRYPTED}a/`],
    ['hash-non-hex', `bzz://${h.slice(1)}g/`],
    ['hash-port', `bzz://${h}:8080/x`],
    ['hash-userinfo', `bzz://user:pass@${h}/x`],
    ['hash-dot-segments', `bzz://${h}/a/./b/../c`],
    ['hash-encoded-dot-segments', `bzz://${h}/a/%2e%2E/c`],
    ['hash-encoded-slash', `bzz://${h}/a%2Fb`],
    ['hash-encoded-slash-lower', `bzz://${h}/a%2fb`],
    ['hash-encoded-backslash', `bzz://${h}/a%5Cb`],
    ['hash-encoded-backslash-lower', `bzz://${h}/a%5cb`],
    ['hash-encoded-separator-in-query', `bzz://${h}/a?b=%2F%5C`],
    ['hash-double-encoded-slash', `bzz://${h}/a%252Fb`],
    ['hash-backslash', `bzz://${h}/a\\b`],
    ['hash-backslash-escape', `bzz://${h}/a/..\\..\\..\\stamps`, 'path'],
    ['hash-unicode-path', `bzz://${h}/caf${ch(0xe9)}/${ch(0x65e5, 0x672c)}?q=${ch(0xe9)}`],
    ['hash-odd-escapes', `bzz://${h}/%zz/%/%G0/%e9`],
    ['hash-special-characters', `bzz://${h}/^|\`{}<>"'!()*[]$&+,;=@:~?^|\`{}'"`],
    ['hash-space-and-tab', `bzz://${h}/a b\tc`],
    ['hash-controls', `bzz://${h}/a${ch(1)}b${ch(0x7f)}c`],
    ['hash-nbsp-and-bom', `bzz://${h}/${ch(0xa0)}${ch(0xfeff)}`],
    ['hash-doubled-slashes', `bzz://${h}//a//b`],
    ['scheme-uppercase', `BZZ://${h}/x`],
    // Not a reference or a name.
    ['host-plain', 'bzz://example/x'],
    ['host-empty', 'bzz:///x'],
    ['host-opaque', 'bzz:abc'],
    ['host-opaque-encoded-slash', 'bzz:a%2Fb'],
    ['host-empty-label', 'bzz://a..eth/'],
    ['host-leading-dot', 'bzz://.eth/'],
    ['host-trailing-dot', 'bzz://site.eth./'],
    ['host-ipv6', 'bzz://[::1]/'],
    ['url-invalid', 'bzz://a b.eth/'],
    ['url-invalid-port', `bzz://${h}:99999/`],
    ['url-backslash-port', 'bzz://site.eth:\\/'],
    ['url-invalid-host-character', 'bzz://a<b.eth/'],
  ].map(([id, url, validation]) => ({ id, url, validation }));
  // Methods.
  for (const [id, method] of [['get-lowercase', 'get'], ['method-empty', ''], ['head', 'HEAD'], ['head-mixed', 'hEaD'],
    ['post', 'POST'], ['put', 'PUT'], ['options', 'OPTIONS'], ['delete', 'DELETE'], ['method-unicode', 'g' + ch(0x0435) + 't']]) {
    cases.push({ id: `method-${id}`, url: `bzz://${h}/x`, method });
  }
  cases.push({ id: 'method-post-encoded-slash', url: `bzz://${h}/a%2Fb`, method: 'POST' });
  // Headers: an allowlist plus Swarm's own.
  cases.push({
    id: 'headers-allowlist',
    url: `bzz://${h}/video.mp4`,
    headers: [
      ['Accept', '*/*'], ['Accept-Encoding', 'gzip, br'], ['Accept-Language', 'en'], ['If-Match', '"a"'],
      ['If-Modified-Since', 'Thu, 01 Jan 2026 00:00:00 GMT'], ['If-None-Match', '"b"'], ['If-Range', '"c"'],
      ['If-Unmodified-Since', 'Thu, 01 Jan 2026 00:00:00 GMT'], ['Range', 'bytes=0-1023'], ['User-Agent', 'Freedom'],
      ['Cookie', 'a=1'], ['Origin', 'bzz://x'], ['Referer', 'bzz://x/'], ['Authorization', 'Bearer x'],
      ['Swarm-Act', 'true'], ['Swarm-Pin', 'true'], ['Swarm-Chunk-Retrieval-Timeout', '1s'], ['Swarm-Redundancy-Strategy', '0'],
      ['Swarm-Redundancy-Fallback-Mode', 'false'], ['X-Custom', 'y'], ['Accept-Charset', 'utf-8'], ['Content-Type', 'text/plain'],
      ['Connection', 'close'], ['Host', 'evil'],
    ],
  });
  cases.push({ id: 'headers-duplicates', url: `bzz://${h}/x`, headers: [['accept', 'a'], ['Accept', 'b'], ['range', 'bytes=1-'], ['RANGE', 'bytes=2-']] });
  cases.push({ id: 'headers-whitespace', url: `bzz://${h}/x`, headers: [['accept', '  text/html\t'], ['user-agent', ''], ['if-none-match', ch(0xa0) + 'x' + ch(0xa0)]] });
  cases.push({ id: 'headers-none', url: `bzz://${h}/x`, headers: [] });
  // Backends.
  cases.push({ id: 'external', url: `bzz://${h}/x`, backend: 'external' });
  // Ant down: the method, path and host checks first, then 503 before any name.
  for (const [id, url, method, backend] of [['down-hash', `bzz://${h}/x`], ['down-name', 'bzz://site.eth/x'],
    ['down-post', `bzz://${h}/x`, 'POST'], ['down-encoded-slash', `bzz://${h}/a%2Fb`], ['down-invalid', 'bzz://example/'],
    ['down-empty-label', 'bzz://a..eth/'], ['down-external-hash', `bzz://${h}/x`, 'GET', 'external'],
    ['down-external-name', 'bzz://site.eth/x', 'GET', 'external']]) {
    cases.push({ id, url, method, backend, up: false });
  }
  // Name hosts, with the resolver's answers.
  const named = (id, url, resolution, extra = {}) => cases.push({ id, url, resolution, ...extra });
  named('name-ok', 'bzz://site.eth/a/b?q=1', okBzz());
  named('name-ok-root', 'bzz://site.eth/', okBzz());
  named('name-ok-no-path', 'bzz://site.eth', okBzz());
  named('name-ok-uppercase', 'bzz://Site.ETH/x', okBzz());
  named('name-ok-encrypted', 'bzz://site.eth/x', okBzz({ decoded: SWARM_REF_ENCRYPTED }));
  named('name-ok-trust', 'bzz://site.eth/x', okBzz({ trust: { level: 'verified' } }));
  named('name-ok-trust-not-string', 'bzz://site.eth/x', okBzz({ trust: { level: 7 } }));
  named('name-ok-encoded-separator', 'bzz://site.eth/a%2Fb', okBzz());
  named('name-box', 'bzz://site.box/x', okBzz());
  named('name-wei', 'bzz://site.wei/x', okBzz({ system: 'wns' }));
  named('name-gwei', 'bzz://site.gwei/x', okBzz({ system: 'gns' }));
  named('name-tez', 'bzz://site.tez/x', okBzz({ system: 'tezos' }));
  named('name-potential', 'bzz://example.com/x', okBzz());
  named('name-unicode-host', `bzz://${ch(0xe4)}.eth/x`, okBzz());
  named('name-punycode-host', 'bzz://xn--4ca.eth/x', okBzz());
  named('name-subdomain', 'bzz://a.b.c.eth/x', okBzz());
  // A relative base path glues onto the reference, dots climb out of it, and
  // an encoded separator in one reaches the node: the design refuses all three.
  for (const [id, basePath, validation] of [['null', null], ['empty', ''], ['slash', '/'], ['dir', '/docs'], ['dir-slash', '/docs/'],
    ['relative', 'docs', 'path'], ['double-slash', '//'], ['nested', '/a/b/'], ['dots', '/a/../..', 'path'], ['encoded', '/a%2Fb', 'path']]) {
    named(`name-base-path-${id}`, 'bzz://site.eth/page?q', okBzz({ basePath }), { validation });
    named(`name-base-path-${id}-root`, 'bzz://site.eth/', okBzz({ basePath }), { validation });
  }
  named('name-base-path-escape', 'bzz://site.eth/x', okBzz({ basePath: '/../../..' }), { validation: 'path' });
  named('name-decoded-escape', 'bzz://site.eth/x', okBzz({ decoded: '../../stamps' }), { validation: 'path' });
  named('name-decoded-not-hex', 'bzz://site.eth/x', okBzz({ decoded: 'not-a-reference' }), { validation: 'path' });
  named('name-decoded-number', 'bzz://site.eth/x', okBzz({ decoded: 12 }), { validation: 'path' });
  named('name-mismatch-ipfs', 'bzz://site.eth/x', okIpfs());
  named('name-mismatch-ipns', 'bzz://site.wei/x', okIpns({ system: 'wns' }));
  named('name-mismatch-case', 'bzz://site.eth/x', okBzz({ protocol: 'BZZ' }));
  named('name-mismatch-missing', 'bzz://site.eth/x', { value: { type: 'ok', decoded: SWARM_REF } });
  named('name-mismatch-number', 'bzz://site.eth/x', { value: { type: 'ok', protocol: 5, decoded: SWARM_REF } });
  named('name-not-found', 'bzz://site.eth/x', { value: { type: 'not_found', reason: 'no_contenthash' } });
  named('name-not-found-no-reason', 'bzz://site.tez/x', { value: { type: 'not_found' } });
  named('name-not-found-empty-reason', 'bzz://site.eth/x', { value: { type: 'not_found', reason: '' } });
  named('name-not-found-gns', 'bzz://site.gwei/x', { value: { type: 'not_found', reason: 'no_resolver', system: 'gns' } });
  named('name-unsupported', 'bzz://site.eth/x', { value: { type: 'unsupported', reason: 'codec' } });
  named('name-unsupported-tezos', 'bzz://site.tez/x', { value: { type: 'unsupported', system: 'tezos' } });
  named('name-conflict', 'bzz://site.eth/x', { value: { type: 'conflict' } });
  named('name-conflict-wns', 'bzz://site.wei/x', { value: { type: 'conflict', system: 'wns' } });
  named('name-error', 'bzz://site.eth/x', { value: { type: 'error', error: 'all providers failed' } });
  named('name-error-reason', 'bzz://site.eth/x', { value: { type: 'error', reason: 'timeout' } });
  named('name-error-empty', 'bzz://site.eth/x', { value: { type: 'error', error: '', reason: '' } });
  named('name-error-number', 'bzz://site.eth/x', { value: { type: 'error', error: 0, reason: 42 } });
  named('name-error-object', 'bzz://site.eth/x', { value: { type: 'error', error: { code: 1 } } });
  named('name-unknown-type', 'bzz://site.eth/x', { value: { type: 'weird', reason: 'why' } });
  named('name-no-type', 'bzz://site.eth/x', { value: {} });
  named('name-null', 'bzz://site.eth/x', { value: null });
  named('name-string', 'bzz://site.tez/x', { value: 'ok' });
  named('name-array', 'bzz://site.eth/x', { value: ['ok'] });
  named('name-threw', 'bzz://site.eth/x', { threw: 'resolver exploded for site.eth' });
  named('name-threw-tezos', 'bzz://site.tez/x', { threw: '' });
  named('name-long-host', `bzz://${'a'.repeat(300)}.eth/x`, { value: { type: 'not_found', reason: 'x' } });
  return cases.map((c) => ({ scheme: 'bzz', ...c }));
}

function ipfsCases() {
  const v1 = b32cid(CID_BYTES.dagPb);
  const z = zcid(CID_BYTES.dagPb);
  const key36 = 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8';
  const cases = [];
  const add = (scheme, id, url, extra = {}) => cases.push({ scheme, id, url, ...extra });
  // ipfs: CID hosts in every base.
  add('ipfs', 'cid-base32', `ipfs://${v1}/a/b?q=1`);
  add('ipfs', 'cid-base32-uppercase', `ipfs://${v1.toUpperCase()}/`);
  add('ipfs', 'cid-v0', `ipfs://${CIDV0}/index.html`);
  add('ipfs', 'cid-v0-lowercased', `ipfs://${CIDV0.toLowerCase()}/`);
  add('ipfs', 'cid-v0-uppercased', `ipfs://${CIDV0.toUpperCase()}/`);
  add('ipfs', 'cid-v0-bad-header', `ipfs://${b58('1221' + DIGEST)}/`);
  add('ipfs', 'cid-base58', `ipfs://${z}/x`);
  add('ipfs', 'cid-base58-lowercased', `ipfs://${z.toLowerCase()}/x`);
  add('ipfs', 'cid-base58-dag-json', `ipfs://${zcid(CID_BYTES.dagJson)}/`);
  add('ipfs', 'cid-base58-blake2b', `ipfs://${zcid(CID_BYTES.blake2b)}/`);
  add('ipfs', 'cid-base58-bad-structure', `ipfs://${zcid('02701220' + DIGEST)}/`);
  add('ipfs', 'cid-base32-raw', `ipfs://${b32cid(CID_BYTES.raw)}/`);
  add('ipfs', 'cid-base32-dag-json', `ipfs://${b32cid(CID_BYTES.dagJson)}/`);
  add('ipfs', 'cid-base32-short', `ipfs://${v1.slice(0, 50)}/`);
  add('ipfs', 'cid-base32-min', `ipfs://${v1.slice(0, 51)}/`);
  for (const [name, prefix, encode] of MULTIBASES) {
    if (prefix === 'b' || prefix === 'z') continue;
    add('ipfs', `cid-${name}`, `ipfs://${prefix}${encode(bytesOf(CID_BYTES.dagPb))}/`);
  }
  add('ipfs', 'cid-path-escapes', `ipfs://${v1}/a%2Fb/%5C/%2e%2e/%zz?x=%2F`);
  add('ipfs', 'cid-path-unicode', `ipfs://${v1}/caf${ch(0xe9)}/${ch(0x1f600)}?${ch(0xe9)}=${ch(0x3000)}`);
  add('ipfs', 'cid-path-special', `ipfs://${v1}/^|\`{}<>"'?^'"`);
  add('ipfs', 'cid-path-backslash-escape', `ipfs://${v1}/a/..\\..\\..\\ipns\\evil.example`, { validation: 'path' });
  add('ipfs', 'cid-path-dot-segments', `ipfs://${v1}/a/../../b/./c`);
  add('ipfs', 'cid-port-userinfo', `ipfs://u:p@${v1}:5001/x`);
  add('ipfs', 'cid-empty-query', `ipfs://${v1}/x?`);
  add('ipfs', 'cid-fragment', `ipfs://${v1}/x#y`);
  add('ipfs', 'not-cid-short-name', 'ipfs://abc/');
  add('ipfs', 'not-cid-empty', 'ipfs:///x');
  add('ipfs', 'not-cid-opaque', 'ipfs:abc');
  add('ipfs', 'key-under-ipfs', `ipfs://${key36}/`);
  // ipns: keys, DNSLink and names.
  add('ipns', 'key-base36', `ipns://${key36}/x?y`);
  add('ipns', 'key-base36-uppercase', `ipns://${key36.toUpperCase()}/`);
  add('ipns', 'key-peer-ed25519', `ipns://${PEER_ED25519}/`);
  add('ipns', 'key-peer-ed25519-lowercased', `ipns://${PEER_ED25519.toLowerCase()}/`);
  add('ipns', 'key-peer-sha256', `ipns://${PEER_SHA256}/`);
  add('ipns', 'key-peer-secp256k1', `ipns://${PEER_SECP256K1}/`);
  add('ipns', 'key-cidv0-as-peer-lowercased', `ipns://${CIDV0.toLowerCase()}/`);
  add('ipns', 'key-base58-cid', `ipns://${zcid(CID_BYTES.libp2pKey)}/`);
  add('ipns', 'key-base58-cid-lowercased', `ipns://${zcid(CID_BYTES.libp2pKey).toLowerCase()}/`);
  add('ipns', 'key-base32-cid', `ipns://${b32cid(CID_BYTES.libp2pKey)}/`);
  add('ipns', 'dnslink', 'ipns://docs.ipfs.tech/install/');
  add('ipns', 'dnslink-underscore', 'ipns://a_b.example/');
  add('ipns', 'dnslink-hyphen-start', 'ipns://-a.example/');
  add('ipns', 'dnslink-long', `ipns://${'a'.repeat(250)}.com/`);
  add('ipns', 'dnslink-percent', 'ipns://a%41.example/');
  add('ipns', 'dnslink-no-dot', 'ipns://plain/');
  add('ipns', 'ipns-empty', 'ipns:///');
  // Gateway forms.
  for (const [id, url, resolution] of [
    ['localhost', `ipfs://localhost/ipfs/${v1}/a/b?q=1#f`],
    ['localhost-port', `ipfs://localhost:8080/ipfs/${CIDV0}/`],
    ['localhost-no-rest', `ipfs://localhost/ipfs/${v1}`],
    ['localhost-uppercase', `ipfs://LOCALHOST/ipfs/${v1}/`],
    ['loopback-v4', `ipfs://127.0.0.1/ipfs/${v1}/`],
    ['any-v4', `ipfs://0.0.0.0/ipfs/${v1}/`],
    ['loopback-v6', `ipfs://[::1]/ipfs/${v1}/`],
    ['subdomain-localhost', `ipfs://${v1}.ipfs.localhost/ipfs/${v1}/x`],
    ['dweb-link-ipns', 'ipfs://dweb.link/ipns/docs.ipfs.tech/install'],
    ['ipfs-io-z', `ipfs://ipfs.io/ipfs/${z}/x`],
    ['pinata-encoded-separators', `ipfs://gateway.pinata.cloud/ipfs/${v1}/a%2Fb%5C`],
    ['cloudflare', `ipfs://cloudflare-ipfs.com/ipfs/${v1.toUpperCase()}/`],
    ['ipns-key', `ipfs://localhost/ipns/${key36}/x`],
    ['ipns-peer', `ipfs://localhost/ipns/${PEER_ED25519}/x`],
    ['ipns-peer-lowercased', `ipfs://localhost/ipns/${PEER_ED25519.toLowerCase()}/x`],
    ['ipns-base32', `ipfs://localhost/ipns/${b32cid(CID_BYTES.libp2pKey)}/`],
    ['ipns-uppercase-dnslink', 'ipfs://localhost/ipns/Docs.IPFS.tech/'],
    ['ipfs-lowercased-v0', `ipfs://localhost/ipfs/${CIDV0.toLowerCase()}/`],
    ['ipfs-key', `ipfs://localhost/ipfs/${key36}/`],
    ['ipfs-dnslink', 'ipfs://localhost/ipfs/docs.ipfs.tech/'],
    ['no-ref', 'ipfs://localhost/ipfs/'],
    ['uppercase-namespace', `ipfs://localhost/IPFS/${v1}/`],
    ['other-path', 'ipfs://localhost/'],
    // Not gateway-form: a name host, resolved.
    ['unknown-gateway', `ipfs://example.com/ipfs/${v1}/`, okIpfs()],
    ['public-not-cid', 'ipfs://ipfs.io/ipfs/not-a-cid/', { value: { type: 'not_found', reason: 'no_resolver' } }],
    ['from-ipns-scheme', `ipns://localhost/ipfs/${v1}/x`],
  ]) add(id.startsWith('from-ipns') ? 'ipns' : 'ipfs', `gateway-${id}`, url, resolution ? { resolution } : {});
  add('ipfs', 'gateway-post', `ipfs://localhost/ipfs/${v1}/`, { method: 'POST' });
  add('ipfs', 'gateway-form-node-down', `ipfs://localhost/ipfs/${v1}/`, { up: false });
  add('ipfs', 'gateway-form-external-down', `ipfs://localhost/ipfs/${v1}/`, { backend: 'gateway', up: false });
  add('ipfs', 'gateway-form-refused-node-down', `ipfs://localhost/ipfs/${CIDV0.toLowerCase()}/`, { up: false });
  // Methods.
  for (const [id, method] of [['head', 'HEAD'], ['get-lowercase', 'get'], ['empty', ''], ['post', 'POST'], ['patch', 'PATCH']]) {
    add('ipfs', `method-${id}`, `ipfs://${v1}/`, { method });
  }
  // Headers: a strip-list.
  add('ipfs', 'headers-strip-list', `ipfs://${v1}/video.mp4`, {
    headers: [
      ['Host', 'x'], ['Origin', 'ipfs://y'], ['Referer', 'ipfs://y/'], ['Cookie', 'a=1'], ['Authorization', 'Bearer z'],
      ['Connection', 'keep-alive'], ['Keep-Alive', 'timeout=5'], ['Proxy-Authenticate', 'Basic'], ['Proxy-Authorization', 'Basic eA=='],
      ['TE', 'trailers'], ['Trailer', 'X'], ['Transfer-Encoding', 'chunked'], ['Upgrade', 'websocket'],
      ['Range', 'bytes=100-'], ['If-Range', '"etag"'], ['Accept', '*/*'], ['X-Custom', '1'], ['Swarm-Act', 'true'],
      ['Set-Cookie', 'a=1'], ['set-cookie', 'b=2'], ['Content-Type', 'text/plain'],
    ],
  });
  add('ipfs', 'headers-duplicates', `ipfs://${v1}/`, { headers: [['x-a', '1'], ['X-A', '2'], ['accept', 'text/html'], ['Accept', 'image/png']] });
  // Navigations: the small-text rule.
  for (const [id, values, method] of [
    ['nav', [NAV]], ['nav-exact', ['text/html']], ['nav-uppercase', ['TEXT/HTML,*/*']], ['nav-spaces', ['  text/html  ,x']],
    ['nav-nbsp', [ch(0xa0) + 'text/html']], ['nav-vertical-tab', [ch(0x0b) + 'text/html']], ['nav-parameter', ['text/html;q=0.9']],
    ['nav-space-parameter', ['text/html ;q=0.9']], ['nav-second', ['*/*,text/html']], ['nav-two-headers', ['text/html', 'image/png']],
    ['nav-two-headers-second', ['image/png', 'text/html']], ['nav-none', []], ['nav-empty', ['']], ['nav-star', ['*/*']],
    ['nav-xhtml', ['application/xhtml+xml']], ['nav-head', [NAV], 'HEAD'], ['nav-lowercase-get', [NAV], 'get'],
  ]) add('ipfs', `small-text-${id}`, `ipfs://${v1}/file`, { headers: values.map((v) => ['Accept', v]), method });
  add('ipfs', 'small-text-gateway', `ipfs://${v1}/file`, { headers: [['Accept', NAV]], backend: 'gateway' });
  // Backends.
  add('ipfs', 'gateway', `ipfs://${v1}/x`, { backend: 'gateway' });
  add('ipns', 'gateway-ipns', `ipns://${key36}/x`, { backend: 'gateway' });
  // Down: canonicalization and the name's result first; only a plan bound
  // for the node becomes the 503, with its mode's text.
  add('ipfs', 'node-down', `ipfs://${v1}/x`, { up: false });
  add('ipns', 'node-down-ipns', `ipns://${key36}/x`, { up: false });
  add('ipfs', 'node-down-invalid', 'ipfs://abc/', { up: false });
  add('ipfs', 'node-down-lowercased', `ipfs://${CIDV0.toLowerCase()}/`, { up: false });
  add('ipfs', 'node-down-post', `ipfs://${v1}/`, { up: false, method: 'POST' });
  add('ipfs', 'external-down', `ipfs://${v1}/x`, { backend: 'gateway', up: false });
  add('ipns', 'external-down-ipns', `ipns://docs.ipfs.tech/x`, { backend: 'gateway', up: false });
  add('ipfs', 'external-down-invalid', 'ipfs://abc/', { backend: 'gateway', up: false });
  add('ipfs', 'external-down-post', `ipfs://${v1}/`, { backend: 'gateway', up: false, method: 'POST' });
  // Name hosts.
  add('ipfs', 'name-ok', 'ipfs://site.eth/a?b', { resolution: okIpfs() });
  add('ipfs', 'name-ok-trust', 'ipfs://site.eth/a', { resolution: okIpfs({ trust: { level: 'unverified' } }) });
  add('ipfs', 'name-ok-base-path', 'ipfs://site.eth/a', { resolution: okIpfs({ basePath: '/site/' }) });
  add('ipfs', 'name-ok-base-path-root', 'ipfs://site.eth/', { resolution: okIpfs({ basePath: '/site' }) });
  add('ipfs', 'name-ok-decoded-v0', 'ipfs://site.eth/', { resolution: okIpfs({ decoded: CIDV0 }) });
  add('ipfs', 'name-ok-decoded-escape', 'ipfs://site.eth/', { resolution: okIpfs({ decoded: '../ipns/evil.example' }), validation: 'path' });
  add('ipfs', 'name-potential', 'ipfs://example.com/', { resolution: okIpfs() });
  add('ipfs', 'name-tez', 'ipfs://site.tez/', { resolution: okIpfs({ system: 'tezos' }) });
  add('ipfs', 'name-wei', 'ipfs://site.wei/', { resolution: okIpfs({ system: 'wns' }) });
  add('ipfs', 'name-mismatch-bzz', 'ipfs://site.eth/', { resolution: okBzz() });
  add('ipfs', 'name-mismatch-ipns', 'ipfs://site.eth/', { resolution: okIpns() });
  add('ipns', 'name-ok-ipns', 'ipns://site.eth/x', { resolution: okIpns() });
  add('ipns', 'name-mismatch-ipfs', 'ipns://site.eth/x', { resolution: okIpfs() });
  add('ipns', 'name-potential-ipns', 'ipns://example.com/x');
  add('ipns', 'name-tez-ipns', 'ipns://site.tez/', { resolution: okIpns({ system: 'tezos' }) });
  add('ipns', 'name-long-eth-ipns', `ipns://${'a'.repeat(260)}.eth/`, { resolution: okIpns() });
  add('ipfs', 'name-not-found', 'ipfs://site.eth/', { resolution: { value: { type: 'not_found', reason: 'empty' } } });
  add('ipfs', 'name-unsupported', 'ipfs://site.eth/', { resolution: { value: { type: 'unsupported' } } });
  add('ipfs', 'name-conflict', 'ipfs://site.gwei/', { resolution: { value: { type: 'conflict', system: 'gns' } } });
  add('ipfs', 'name-error', 'ipfs://site.eth/', { resolution: { value: { type: 'error', error: 'quorum failed' } } });
  add('ipfs', 'name-null', 'ipfs://site.eth/', { resolution: { value: null } });
  add('ipfs', 'name-threw', 'ipfs://site.eth/', { resolution: { threw: 'boom' } });
  add('ipfs', 'name-empty-label', 'ipfs://a..eth/');
  add('ipns', 'name-empty-label-ipns', 'ipns://a..eth/');
  for (const [id, resolution] of [['ok', okIpfs()], ['not-found', { value: { type: 'not_found' } }], ['unsupported', { value: { type: 'unsupported' } }],
    ['mismatch', okBzz()], ['threw', { threw: 'x' }]]) {
    add('ipfs', `name-node-down-${id}`, 'ipfs://site.eth/', { resolution, up: false });
    add('ipfs', `name-external-down-${id}`, 'ipfs://site.eth/', { resolution, backend: 'gateway', up: false });
  }
  add('ipfs', 'name-gateway', 'ipfs://site.eth/', { resolution: okIpfs(), backend: 'gateway' });
  return cases;
}

const BACKENDS = { bzz: 'bundled', ipfs: 'native', ipns: 'native' };

/** The backend's mode: `{ ant: mode, up }` or `{ ipfs: mode, up }`. */
const modeOf = (request) => request.backend.ant ?? request.backend.ipfs;

function requestOf(c) {
  const node = c.scheme === 'bzz' ? 'ant' : 'ipfs';
  return {
    url: c.url,
    method: c.method ?? 'GET',
    headers: c.headers ?? [['Accept', '*/*'], ['User-Agent', 'Freedom']],
    backend: { [node]: c.backend ?? BACKENDS[c.scheme], up: c.up ?? true },
  };
}

/** Runs one request through the reference handler; `upstream` scripts the node. */
async function runRequest(ref, c, upstream = { status: 200, headers: [], chunks: [] }) {
  const { world, bzz, ipfs, manager, mode } = ref;
  const request = requestOf(c);
  const backend = modeOf(request);
  const { up } = request.backend;
  world.calls = [];
  world.fetches = [];
  world.unscripted = null;
  world.resolution = c.resolution ?? null;
  const counter = { reads: 0, cancelled: false };
  const reply = () => scriptedResponse(upstream, counter);
  const jsRequest = { url: request.url, method: request.method, headers: new Headers(request.headers), signal: new AbortController().signal };
  let response;
  if (c.scheme === 'bzz') {
    // Either mode: main has no Ant API URL while Ant isn't up.
    world.antApiUrl = up ? ANT_API_URL : null;
    response = await bzz.handleBzzRequest(jsRequest, {
      fetchImpl: async (url, init) => {
        world.fetches.push({ url, method: init.method, headers: [...init.headers], redirect: init.redirect });
        return reply();
      },
    });
  } else {
    let requestImpl;
    if (backend === 'native' && up) {
      requestImpl = async ({ path, method, headers }) => {
        world.fetches.push({ path, method, headers: [...headers] });
        return reply();
      };
    } else {
      // The external gateway, and either mode when it isn't up, go through
      // the real manager.
      manager.__setState(backend === 'gateway' ? mode.EXTERNAL : mode.BUNDLED, up ? 'running' : 'stopped', GATEWAY_URL);
      world.gatewayFetch = async (url, init) => {
        world.fetches.push({ url, method: init.method, headers: [...init.headers], redirect: init.redirect });
        return reply();
      };
      requestImpl = manager.serveNativeGatewayRequest;
    }
    response = await ipfs.handleRequest(c.scheme, jsRequest, { requestImpl });
  }
  const readsAtResponse = counter.reads;
  assert.equal(world.unscripted, null, `${c.scheme}-${c.id}: the handler resolved ${world.unscripted}, unscripted`);
  return { request, jsRequest, response, readsAtResponse, counter };
}

function outcomeOf(c, run, ref) {
  const { world } = ref;
  const { response } = run;
  const resolve = world.calls.map(({ fn, name }) => ({ fn, name }));
  assert.ok(world.fetches.length <= 1, `${c.id}: one dial at most`);
  if (world.fetches.length === 1) {
    const dial = world.fetches[0];
    let fetch;
    if (c.scheme === 'bzz') {
      assert.ok(dial.url.startsWith(ANT_API_URL + '/'), c.id);
      assert.equal(dial.redirect, 'manual');
      // What undici sends: the gateway URL as the WHATWG parser reads it.
      const parsed = new URL(dial.url);
      fetch = { gateway_url: dial.url.slice(ANT_API_URL.length), path: parsed.pathname + parsed.search, method: dial.method, headers: dial.headers };
    } else if (dial.url) {
      assert.ok(dial.url.startsWith(GATEWAY_URL + '/'), c.id);
      assert.equal(dial.redirect, 'manual');
      fetch = { path: dial.url.slice(GATEWAY_URL.length), method: dial.method, headers: dial.headers };
    } else {
      fetch = { path: dial.path, method: dial.method, headers: dial.headers };
    }
    return { resolve, fetch };
  }
  return { resolve, response: null };
}

const RESPONSE_OPS = {
  ant: ['canonicalize_redirect', 'strip_page_state'],
  // The external gateway's length is gone before small_text could read it,
  // so the rule never fires there (ipfs-manager.js drops content-length).
  gateway: ['strip_decoded_encoding', 'strip_page_state', 'canonicalize_redirect'],
  native: ['strip_page_state'],
};

function tables(ref) {
  const { bzz, native } = ref;
  return {
    bzz: {
      retry: {
        statuses: [...bzz.RETRYABLE_STATUSES],
        on_error: bzz.__internals.shouldRetry({ error: new Error('any') }),
        attempts: bzz.RETRY_DELAYS_MS.length + 1,
        delays_ms: [...bzz.RETRY_DELAYS_MS],
      },
      timers: { queue_ms: null, headers_ms: bzz.ATTEMPT_TIMEOUT_MS, body_idle_ms: BODY_IDLE_MS },
    },
    native: {
      retry: { statuses: [], on_error: false, attempts: 1, delays_ms: [] },
      timers: {
        queue_ms: native.__internals.REQUEST_QUEUE_TIMEOUT_MS,
        headers_ms: native.__internals.ATTEMPT_TIMEOUT_MS,
        body_idle_ms: BODY_IDLE_MS,
      },
    },
    // No timeout until the headers: only the page's abort (ipfs-manager.js).
    gateway: {
      retry: { statuses: [], on_error: false, attempts: 1, delays_ms: [] },
      timers: { queue_ms: null, headers_ms: null, body_idle_ms: BODY_IDLE_MS },
    },
  };
}

function planOf(c, request, js, run, ref, table) {
  const backend = modeOf(request);
  if (js.fetch) {
    const node = c.scheme === 'bzz' ? 'ant' : 'ipfs';
    const kind = node === 'ant' ? 'bzz' : backend;
    const response = [...RESPONSE_OPS[node === 'ant' ? 'ant' : backend]];
    const method = js.fetch.method;
    if (backend === 'native' && method === 'GET' && ref.ipfs.__internals.isDocumentRequest(run.jsRequest)) response.push('small_text');
    const level = c.resolution?.value?.trust?.level;
    return {
      fetch: {
        node,
        path: js.fetch.path,
        headers: js.fetch.headers,
        retry: table[kind].retry,
        timers: table[kind].timers,
        response,
        trust: {
          name: typeof level === 'string' ? level : null,
          content: backend === 'bundled' || backend === 'native' ? 'node_asserted' : 'unverified',
        },
      },
    };
  }
  if (js.redirect) {
    const { headers } = js.redirect;
    const location = headers.find(([name]) => name === 'location')[1];
    return { redirect: { status: js.redirect.status, location, headers: headers.filter(([name]) => name !== 'location') } };
  }
  const { code, message } = JSON.parse(js.error.body);
  return { error: { status: js.error.status, code, message } };
}

async function buildRequests(ref, table) {
  const out = [];
  for (const c of [...bzzCases(), ...ipfsCases()]) {
    const run = await runRequest(ref, c);
    const js = outcomeOf(c, run, ref);
    const { response } = run;
    if (!js.fetch) {
      delete js.response;
      if (response.status === 307) {
        assert.equal(response.body, null, c.id);
        js.redirect = { status: 307, headers: [...response.headers] };
      } else {
        const body = await response.text();
        assert.deepEqual(Object.keys(JSON.parse(body)), ['code', 'message'], c.id);
        js.error = { status: response.status, headers: [...response.headers], body };
      }
    }
    const plan = planOf(c, run.request, js, run, ref, table);
    const entry = { id: `${c.scheme}-${c.id}`, request: run.request };
    if (c.resolution) entry.resolution = c.resolution;
    // Today's handler dials these; design 0006 refuses them (plan-paths).
    if (c.validation) entry.deviation = 'plan-paths';
    entry.js = js;
    entry.plan = plan;
    entry.validation = c.validation ?? 'valid';
    out.push(entry);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Responses: whole exchanges, the node's answer through the handler

function exchangeCases() {
  const h = SWARM_REF;
  const v1 = b32cid(CID_BYTES.dagPb);
  const req = (scheme, id, url, upstream, extra = {}) => ({ scheme, id, url, upstream, ...extra });
  const text = (s) => Buffer.from(s, 'utf8').toString('hex');
  const cases = [
    // bzz: Ant's directory redirect, rewritten relative and bodiless.
    req('bzz', 'redirect-directory', `bzz://${h}/blog`, { status: 308, headers: [['Location', `/bzz/${h}/blog/`], ['Content-Length', '9'], ['Content-Type', 'text/html'], ['Content-Encoding', 'gzip'], ['Transfer-Encoding', 'chunked']], chunks: [text('redirect!')] }),
    req('bzz', 'redirect-named', 'bzz://site.eth/blog', { status: 308, headers: [['Location', `/bzz/${h}/blog/`]], chunks: [] }, { resolution: okBzz() }),
    req('bzz', 'redirect-named-base-path', 'bzz://site.eth/blog', { status: 301, headers: [['Location', `/bzz/${h}/site/blog/`]], chunks: [] }, { resolution: okBzz({ basePath: '/site' }) }),
    req('bzz', 'redirect-go-escapes', `bzz://${h}/photos(2024)/blog`, { status: 308, headers: [['Location', `/bzz/${h}/photos%282024%29/blog/`]], chunks: [] }),
    req('bzz', 'redirect-up', `bzz://${h}/a/b`, { status: 302, headers: [['Location', `/bzz/${h}/c`]], chunks: [text('x')] }),
    req('bzz', 'redirect-cross-origin', `bzz://${h}/a`, { status: 302, headers: [['Location', 'http://127.0.0.1:9999/bzz/x/']], chunks: [text('x')] }),
    req('bzz', 'redirect-absolute-same-origin', `bzz://${h}/a`, { status: 307, headers: [['Location', `${ANT_API_URL}/bzz/${h}/a/?q#f`]], chunks: [] }),
    req('bzz', 'redirect-300', `bzz://${h}/a`, { status: 300, headers: [['Location', `/bzz/${h}/a/`]], chunks: [text('x')] }),
    req('bzz', 'redirect-303', `bzz://${h}/a`, { status: 303, headers: [['Location', `/bzz/${h}/a/`]], chunks: [] }),
    req('bzz', 'redirect-304', `bzz://${h}/a`, { status: 304, headers: [['Location', `/bzz/${h}/a/`], ['Set-Cookie', 'a=1']], chunks: null }),
    req('bzz', 'redirect-no-location', `bzz://${h}/a`, { status: 301, headers: [], chunks: [text('x')] }),
    req('bzz', 'redirect-empty-location', `bzz://${h}/a`, { status: 301, headers: [['Location', '']], chunks: [text('x')] }),
    req('bzz', 'redirect-two-locations', `bzz://${h}/a`, { status: 302, headers: [['Location', `/bzz/${h}/a/`], ['Location', '/y']], chunks: [] }),
    req('bzz', 'redirect-head', `bzz://${h}/blog`, { status: 308, headers: [['Location', `/bzz/${h}/blog/`]], chunks: null }, { method: 'HEAD' }),
    req('bzz', 'redirect-with-cookie', `bzz://${h}/blog`, { status: 308, headers: [['Location', `/bzz/${h}/blog/`], ['Set-Cookie', 'a=1'], ['Service-Worker-Allowed', '/']], chunks: [] }),
    req('bzz', 'ok-with-page-state', `bzz://${h}/a`, { status: 200, headers: [['Set-Cookie', 'a=1'], ['set-cookie', 'b=2'], ['Set-Cookie2', 'c'], ['Service-Worker-Allowed', '/'], ['Content-Type', 'text/html'], ['Content-Length', '2']], chunks: [text('hi')] }),
    req('bzz', 'no-content-with-page-state', `bzz://${h}/a`, { status: 204, headers: [['Set-Cookie', 'a=1']], chunks: null }),
    req('bzz', 'partial-content', `bzz://${h}/v.mp4`, { status: 206, headers: [['Content-Range', 'bytes 0-1/10'], ['Content-Length', '2']], chunks: ['0001'] }, { headers: [['Range', 'bytes=0-1']] }),
    req('bzz', 'range-not-satisfiable', `bzz://${h}/v.mp4`, { status: 416, headers: [['Content-Range', 'bytes */10']], chunks: [] }),
    req('bzz', 'not-found', `bzz://${h}/missing`, { status: 404, headers: [['Content-Type', 'application/json']], chunks: [text('{"code":404}')] }),
    // ipfs, native node: no redirect rewrite or header strip today.
    req('ipfs', 'native-redirect', `ipfs://${v1}/docs`, { status: 301, headers: [['Location', `/ipfs/${v1}/docs/`]], chunks: [] }),
    req('ipfs', 'native-page-state', `ipfs://${v1}/a`, { status: 200, headers: [['Set-Cookie', 'a=1'], ['Content-Type', 'text/html']], chunks: [text('x')] }, { deviation: 'native-page-state' }),
    req('ipfs', 'native-partial', `ipfs://${v1}/v`, { status: 206, headers: [['Content-Range', 'bytes 0-0/9'], ['Content-Length', '1'], ['Content-Encoding', 'identity']], chunks: ['00'] }),
    // ipfs, external gateway: decoded-encoding and page-state strip, then the redirect.
    req('ipfs', 'gateway-redirect', `ipfs://${v1}/docs`, { status: 301, headers: [['Location', `/ipfs/${v1}/docs/`], ['Content-Length', '5'], ['Set-Cookie', 'x']], chunks: [text('moved')] }, { backend: 'gateway' }),
    req('ipfs', 'gateway-redirect-300', `ipfs://${v1}/docs`, { status: 300, headers: [['Location', `/ipfs/${v1}/docs/`]], chunks: [] }, { backend: 'gateway' }),
    req('ipfs', 'gateway-redirect-399', `ipfs://${v1}/docs`, { status: 399, headers: [['Location', `/ipfs/${v1}/docs/`]], chunks: [] }, { backend: 'gateway' }),
    req('ipfs', 'gateway-redirect-subdomain', `ipfs://${v1}/docs`, { status: 301, headers: [['Location', `http://${v1}.ipfs.localhost:8080/docs/`]], chunks: [] }, { backend: 'gateway' }),
    req('ipfs', 'gateway-redirect-up', `ipfs://${v1}/a/b`, { status: 302, headers: [['Location', `/ipfs/${v1}/`]], chunks: [] }, { backend: 'gateway' }),
    req('ipfs', 'gateway-redirect-colon', `ipfs://${v1}/re:port`, { status: 301, headers: [['Location', `/ipfs/${v1}/re:port/`]], chunks: [] }, { backend: 'gateway' }),
    req('ipfs', 'gateway-ok', `ipfs://${v1}/a`, { status: 200, headers: [['Content-Encoding', 'gzip'], ['Content-Length', '3'], ['Transfer-Encoding', 'chunked'], ['Connection', 'keep-alive'], ['Keep-Alive', 'timeout=5'], ['Set-Cookie', 'a'], ['Set-Cookie2', 'b'], ['Service-Worker-Allowed', '/'], ['Content-Type', 'text/plain'], ['Cache-Control', 'immutable']], chunks: [text('abc')] }, { backend: 'gateway' }),
    req('ipfs', 'gateway-head', `ipfs://${v1}/a`, { status: 200, headers: [['Content-Length', '3']], chunks: null }, { backend: 'gateway', method: 'HEAD' }),
    req('ipfs', 'gateway-small-text', `ipfs://${v1}/a`, { status: 200, headers: [['Content-Type', 'application/octet-stream'], ['Content-Length', '5']], chunks: [text('hello')] }, { backend: 'gateway', headers: [['Accept', NAV]] }),
  ];
  // Small text through the native node: a navigation, then each condition broken.
  const small = (id, upstream, extra = {}) => cases.push(req('ipfs', `small-text-${id}`, `ipfs://${v1}/file`, upstream, { headers: [['Accept', NAV]], ...extra }));
  const octet = (length, chunks, more = []) => ({ status: 200, headers: [['Content-Type', 'application/octet-stream'], ['Content-Length', String(length)], ...more], chunks });
  small('relabel', octet(12, [text('hello world\n')]));
  small('relabel-chunks', octet(12, [text('hello '), text('world\n')]));
  small('relabel-empty-chunks', octet(5, ['', text('hello'), '']));
  small('relabel-tabs-crlf-ff', octet(5, [text('a\t\r\n\f')]));
  small('relabel-unicode', octet(9, [text(ch(0xe9) + ch(0x1f600) + 'abc')]));
  small('relabel-bom', octet(4, ['efbbbf41']));
  small('relabel-max', octet(4096, [{ fill: '61', length: 4096 }]));
  small('relabel-max-split', octet(4096, [{ fill: '61', length: 4095 }, '62']));
  small('relabel-type-parameters', { ...octet(2, [text('ok')]), headers: [['Content-Type', ' Application/Octet-Stream ; charset=x'], ['Content-Length', '2']] });
  small('relabel-length-forms', { ...octet(0, [text('ok')]), headers: [['Content-Type', 'application/octet-stream'], ['Content-Length', '0x2']] });
  for (const [id, value] of [['spaces', ' 2 '], ['plus', '+2'], ['decimal', '2.0'], ['exponent', '2e0'], ['fraction-exponent', '.2e1'],
    ['octal', '0o2'], ['binary', '0b10'], ['hex-upper', '0X2'], ['octal-upper', '0O2'], ['binary-upper', '0B10'], ['nbsp', ch(0xa0) + '2'], ['leading-zeros', '002'], ['trailing-dot', '2.'],
    ['precision', '2.0000000000000001'], ['precision-max', '4096.0000000000001']]) {
    small(`length-${id}`, { ...octet(0, [text('ok')]), headers: [['Content-Type', 'application/octet-stream'], ['Content-Length', value]] });
  }
  small('length-precision-max-body', { status: 200, headers: [['Content-Type', 'application/octet-stream'], ['Content-Length', '4096.0000000000001']], chunks: [{ fill: '61', length: 4096 }] });
  for (const [id, value] of [['zero', '0'], ['negative', '-2'], ['negative-zero', '-0'], ['over', '4097'], ['nan', 'two'], ['empty', ''],
    ['fraction', '1.5'], ['two-values', '2, 2'], ['separator', '1_0'], ['hex-empty', '0x'], ['signed-hex', '-0x2'], ['infinity', 'Infinity'],
    ['huge', '1e400'], ['tiny', '1e-400'], ['big-hex', '0x' + '0'.repeat(30) + '2'], ['superscript-digit', ch(0xb2)]]) {
    small(`length-${id}`, { ...octet(0, [text('ok')]), headers: [['Content-Type', 'application/octet-stream'], ['Content-Length', value]] });
  }
  small('lying-length-short', octet(10, [text('hello')]));
  small('lying-length-long', octet(5, [text('hello world')]));
  small('lying-length-oversized-chunk', octet(10, [{ fill: '61', length: 65536 }, text('tail')]));
  small('lying-length-many-chunks', octet(100, Array.from({ length: 4100 }, () => '61')));
  small('lying-length-exact-overflow', octet(4096, [{ fill: '61', length: 4096 }, '62', '63']));
  small('binary', octet(4, ['00010203']));
  small('control-del', octet(2, ['417f']));
  small('control-bell', octet(2, ['4107']));
  small('control-vertical-tab', octet(2, ['410b']));
  small('control-nul', octet(2, ['4100']));
  small('control-c1', octet(3, ['41c285']));
  small('invalid-utf8', octet(2, ['c328']));
  small('invalid-surrogate', octet(3, ['eda080']));
  small('invalid-overlong', octet(2, ['c0af']));
  small('truncated-utf8', octet(2, ['41e2']));
  small('not-octet-stream', { ...octet(2, [text('ok')]), headers: [['Content-Type', 'text/plain'], ['Content-Length', '2']] });
  small('no-type', { status: 200, headers: [['Content-Length', '2']], chunks: [text('ok')] });
  small('two-types', { ...octet(2, [text('ok')]), headers: [['Content-Type', 'application/octet-stream'], ['Content-Type', 'text/html'], ['Content-Length', '2']] });
  small('no-length', { status: 200, headers: [['Content-Type', 'application/octet-stream']], chunks: [text('ok')] });
  small('nosniff-present', octet(2, [text('ok')], [['X-Content-Type-Options', 'whatever']]));
  small('disposition-present', octet(2, [text('ok')], [['Content-Disposition', 'inline']]));
  small('range-present', octet(2, [text('ok')], [['Content-Range', 'bytes 0-1/2']]));
  small('status-206', { ...octet(2, [text('ok')]), status: 206 });
  small('status-404', { ...octet(2, [text('ok')]), status: 404 });
  small('no-body', octet(2, null));
  small('head', octet(2, null), { method: 'HEAD' });
  small('subresource', octet(2, [text('ok')]), { headers: [['Accept', '*/*']] });
  small('with-page-state', octet(2, [text('ok')], [['Set-Cookie', 'a=1']]), { deviation: 'native-page-state' });
  return cases;
}

async function buildExchanges(ref) {
  const out = [];
  for (const c of exchangeCases()) {
    const run = await runRequest(ref, c, c.upstream);
    const js = outcomeOf(c, run, ref);
    assert.ok(js.fetch, `${c.id}: the exchange reaches the node`);
    // The external gateway's counting stream reads one chunk ahead (a
    // ReadableStream's default high-water mark), so reads before the
    // response say something only where the body passes straight through.
    const gateway = modeOf(run.request) === 'gateway';
    if (gateway) assert.ok(run.readsAtResponse <= 1, c.id);
    const reads = gateway ? null : run.readsAtResponse;
    const response = await describeResponse(run.response);
    // Every byte the node sent reaches the page, unless the handler dropped the body.
    if (response.body !== null) {
      assert.ok(c.upstream.chunks, c.id);
      assert.equal(response.body, concatChunks(c.upstream.chunks), c.id);
      response.body = 'intact';
    }
    const entry = { id: `${c.scheme}-${c.id}`, request: run.request };
    if (c.resolution) entry.resolution = c.resolution;
    if (c.deviation) entry.deviation = c.deviation;
    entry.upstream = c.upstream;
    entry.js = {
      resolve: js.resolve,
      request_url: c.scheme === 'bzz' ? ANT_API_URL + js.fetch.gateway_url : GATEWAY_URL + js.fetch.path,
      reads_before_response: reads,
      body_cancelled: run.counter.cancelled,
      response,
    };
    out.push(entry);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Redirect locations, directly

function locationCases() {
  const h = SWARM_REF;
  const v1 = b32cid(CID_BYTES.dagPb);
  const ant = (p) => `${ANT_API_URL}/bzz/${h}${p}`;
  const gw = (p) => `${GATEWAY_URL}/ipfs/${v1}${p}`;
  const cases = [];
  const add = (request, locations) => { for (const location of locations) cases.push({ request_url: request, location }); };
  add(ant('/blog'), [
    `/bzz/${h}/blog/`, `/bzz/${h}/blog`, `/bzz/${h}/`, `/bzz/${h}`, `/bzz/${h}/blog/x/y/`, `/bzz/${h}/other/`, `/bzz/${h.toUpperCase()}/blog/`,
    `${ANT_API_URL}/bzz/${h}/blog/`, `HTTP://127.0.0.1:1633/bzz/${h}/blog/`, 'http://127.0.0.1:80/bzz/x/', `http://localhost:1633/bzz/${h}/blog/`,
    `https://127.0.0.1:1633/bzz/${h}/blog/`, `//127.0.0.1:1633/bzz/${h}/blog/`, '//evil.example/x', 'blog/', './blog/', '../blog/', '../../../x',
    '?q=1', '#frag', '', ' ', `\t/bzz/${h}/blog/\n`, `/bzz/${h}/blog/?a=b#c`, `/bzz/${h}/blog/#`, `/bzz/${h}/blog/?`, `/bzz/${h}/re:port/`,
    `/bzz/${h}//x`, `/bzz/${h}/blog/../blog/`, `/bzz/${h}/%2e%2e/x`, `/bzz/${h}/x/%2E/`, `\\bzz\\${h}\\blog\\`, `/bzz/${h}/a%2Fb/`,
    `/bzz/${h}/caf${ch(0xe9)}/`, `/bzz/${h}/${ch(0x1f600)}`, `/bzz/${h}/^|\`{}/`, 'javascript:alert(1)', 'data:text/html,x',
    `blob:${ANT_API_URL}/bzz/${h}/blog/`, 'bzz://other/x', `http://[::1]:1633/bzz/${h}/blog/`, `http://user@127.0.0.1:1633/bzz/${h}/blog/`,
    `http://127.0.0.1:01633/bzz/${h}/blog/`, `http://0x7f.0.0.1:1633/bzz/${h}/blog/`, 'http://%zz/', 'http://[::1', `/bzz/${h}/blog/, /x`,
  ]);
  add(ant('/photos(2024)/blog'), [`/bzz/${h}/photos%282024%29/blog/`, `/bzz/${h}/photos%282024%29/`, `/bzz/${h}/photos(2024)/blog/`, `/bzz/${h}/photos%282024%2/blog/`]);
  add(ant('/caf%C3%A9/x'), [`/bzz/${h}/caf%c3%a9/x/`, `/bzz/${h}/caf${ch(0xe9)}/x/`, `/bzz/${h}/CAF%C3%A9/x/`, `/bzz/${h}/caf%C3/x/`]);
  add(ant('/%zz/x'), [`/bzz/${h}/%zz/x/`, `/bzz/${h}/%ZZ/x/`, `/bzz/${h}/%7azz/x/`]);
  add(ant('/a%2Fb/c'), [`/bzz/${h}/a%2Fb/c/`, `/bzz/${h}/a%2fb/c/`, `/bzz/${h}/a/b/c/`]);
  add(ant('/undefined/x'), [`/bzz/${h}`]);
  add(ant(''), [`/bzz/${h}/`, '/bzz/', '/']);
  add(ant('/'), [`/bzz/${h}/x`, `/bzz/${h}/`]);
  add(ant('/a?q=1'), [`/bzz/${h}/a/?q=1`, '?q=2']);
  add(ant('/a/'), ['b', '', '.', '..']);
  add(`${ANT_API_URL}`, ['/x']);
  add('not a url', ['/x']);
  add(gw('/docs'), [`/ipfs/${v1}/docs/`, `http://${v1}.ipfs.localhost:8080/docs/`, `/ipfs/${v1}/`, `/ipns/x/docs/`]);
  return cases;
}

function buildLocations(ref) {
  const { rewriteGatewayLocation, __internals: { decodeSegment, sameSegment } } = ref.location;
  const locations = locationCases().map((c) => ({ ...c, rewritten: rewriteGatewayLocation(c.location, c.request_url) }));
  const segments = ['', 'a', '%41', '%4', '%', '%zz', '%C3%A9', '%c3%a9', '%C3', '%C3%28', '%E2%82', '%E2%82%AC', '%ED%A0%80', '%F4%90%80%80',
    '%F0%9F%98%80', '%C0%AF', '%80', '%2F', '%25', 'caf' + ch(0xe9), 'a%2', '%FF', '%F8%88%80%80%80', '%e2%82%ac%', 'x%20y']
    .map((segment) => ({ segment, decoded: decodeSegment(segment) }));
  const pairs = [['a', 'a'], ['a', '%61'], ['%61', '%61'], ['%zz', '%zz'], ['%zz', '%ZZ'], ['%C3%A9', '%c3%a9'], ['%2F', '/'],
    ['%C3', '%C3'], ['%C3', '%c3'], ['(', '%28'], ['%28', '('], ['a', 'b']].map(([a, b]) => ({ a, b, same: sameSegment(a, b) }));
  return { locations, segments, same_segment: pairs };
}

// ---------------------------------------------------------------------------
// Response operations, directly

function opHeaders() {
  return [
    [['Location', '/x'], ['Set-Cookie', 'a=1'], ['Set-Cookie', 'b=2'], ['Content-Length', '5']],
    [['SET-COOKIE2', 'x'], ['service-worker-allowed', '/'], ['X-Keep', 'yes']],
    [['Content-Encoding', 'gzip'], ['Content-Length', '10'], ['Transfer-Encoding', 'chunked'], ['Connection', 'close'], ['Keep-Alive', '5'], ['TE', 'x'], ['Trailer', 'y'], ['Upgrade', 'z']],
    [['Content-Type', 'text/html'], ['x-a', '1'], ['X-A', '2'], ['Set-Cookie', 'z']],
    [],
  ];
}

async function buildOperations(ref) {
  const { pageState, manager, bzz } = ref;
  const { stripPageStateHeaders } = pageState;
  const { proxiedResponseHeaders } = manager.__internals;
  const { withoutPageStateHeaders } = bzz.__internals;
  const strip_page_state = [];
  const strip_decoded_encoding = [];
  for (const headers of opHeaders()) {
    for (const status of [200, 204, 301, 304]) {
      const upstream = new Response(status === 204 || status === 304 ? null : new Uint8Array([1]), { status, headers });
      const wrapped = withoutPageStateHeaders(upstream);
      strip_page_state.push({
        status, headers,
        js: { headers: [...stripPageStateHeaders(new Headers(headers))], rewrapped: wrapped !== upstream, body: wrapped.body ? 'kept' : null },
      });
    }
    strip_decoded_encoding.push({ headers, js: { headers: [...proxiedResponseHeaders(new Headers(headers))] } });
  }
  // The bzz rewrite: statuses and headers.
  const canonicalize_redirect = [];
  const h = SWARM_REF;
  const gatewayUrl = `${ANT_API_URL}/bzz/${h}/blog`;
  for (const status of [200, 300, 301, 302, 303, 304, 305, 307, 308, 399, 400]) {
    for (const headers of [[['Location', `/bzz/${h}/blog/`], ['Content-Length', '3'], ['Content-Encoding', 'br'], ['Transfer-Encoding', 'chunked'], ['ETag', '"e"']],
      [['Location', 'http://elsewhere.example/']], [['location', `/bzz/${h}/blog/`], ['Location', `/bzz/${h}/blog/`]], []]) {
      const nullBody = status === 304;
      const upstream = new Response(nullBody ? null : new Uint8Array([1, 2, 3]), { status, headers });
      const result = bzz.canonicalizeRedirect(upstream, gatewayUrl);
      // ipfs-manager rewrites only a 3xx, after its own strip.
      const isRedirect = status >= 300 && status < 400;
      const gateway = isRedirect ? [...manager.__internals.proxiedRedirectHeaders(new Headers(headers), gatewayUrl)] : null;
      canonicalize_redirect.push({
        status, headers, request_url: gatewayUrl,
        js: {
          ant: { headers: [...result.headers], body: result === upstream ? (result.body ? 'kept' : null) : (result.body ? 'replaced' : 'dropped') },
          gateway_redirect_headers: gateway,
        },
      });
    }
  }
  return { strip_page_state, strip_decoded_encoding, canonicalize_redirect };
}

// ---------------------------------------------------------------------------
// Failures after the dial

async function buildFailures(ref) {
  const { bzz, ipfs, manager, mode, world } = ref;
  const out = [];
  const errorOf = ({ name, message, code, cause_code: causeCode }) => {
    const error = new Error(message);
    if (name) error.name = name;
    if (code !== undefined) error.code = code;
    if (causeCode !== undefined) error.cause = { code: causeCode };
    return error;
  };
  const errors = [
    { message: 'fetch failed', cause_code: 'ECONNREFUSED' },
    { message: 'fetch failed', cause_code: 'ECONNRESET' },
    { message: 'fetch failed', cause_code: 'ENOTFOUND' },
    { message: 'fetch failed', cause_code: 'ETIMEDOUT' },
    { message: 'socket', code: 'ECONNREFUSED' },
    { message: 'socket', code: 'ECONNREFUSED', cause_code: 'EPIPE' },
    { message: 'socket', code: 'EPIPE', cause_code: '' },
    { message: 'socket', code: 'ENOTFOUND', cause_code: '' },
    { message: 'bee fetch timed out after 30000ms', code: 'ATTEMPT_TIMEOUT' },
    { message: '' },
    { message: 'aborted', name: 'AbortError' },
  ];
  for (const failure of errors) {
    // bzz: one attempt (the page already went away), then the mapping.
    const controller = new AbortController();
    controller.abort();
    world.antApiUrl = ANT_API_URL;
    const request = { url: `bzz://${SWARM_REF}/x`, method: 'GET', headers: new Headers(), signal: controller.signal };
    const response = await bzz.handleBzzRequest(request, { fetchImpl: async () => { throw errorOf(failure); } });
    const nativeResponse = await ipfs.handleRequest('ipfs', { url: `ipfs://${b32cid(CID_BYTES.dagPb)}/`, method: 'GET', headers: new Headers() }, {
      requestImpl: async () => { throw errorOf(failure); },
    });
    manager.__setState(mode.EXTERNAL, 'running', GATEWAY_URL);
    world.gatewayFetch = async () => { throw errorOf(failure); };
    const gatewayResponse = await ipfs.handleRequest('ipfs', { url: `ipfs://${b32cid(CID_BYTES.dagPb)}/`, method: 'GET', headers: new Headers() }, {
      requestImpl: manager.serveNativeGatewayRequest,
    });
    out.push({
      failure,
      js: {
        ant: { status: response.status, body: await response.text() },
        native: { status: nativeResponse.status, body: await nativeResponse.text() },
        gateway: { status: gatewayResponse.status, body: await gatewayResponse.text() },
      },
    });
  }
  // The node isn't running: what the manager answers at dispatch, by mode.
  const notRunning = {};
  for (const [id, m] of [['native', mode.BUNDLED], ['gateway', mode.EXTERNAL]]) {
    manager.__setState(m, 'stopped', GATEWAY_URL);
    const response = await manager.serveNativeGatewayRequest({ path: '/ipfs/x', method: 'GET', headers: new Headers() });
    notRunning[id] = { status: response.status, body: await response.text() };
  }
  return { failures: out, notRunning };
}

// ---------------------------------------------------------------------------
// html(): the decode, the caps, the hash, and the class

const ABI_WORD = (n) => BigInt(n).toString(16).padStart(64, '0');

function htmlCases() {
  const text = (s) => Buffer.from(s, 'utf8').toString('hex');
  const pad = (hex) => hex + '0'.repeat((64 - (hex.length % 64)) % 64);
  const abi = (hex, { offset = 32, length = hex.length / 2, tail = '' } = {}) => '0x' + ABI_WORD(offset) + ABI_WORD(length) + pad(hex) + tail;
  const MAX = 8 * 1024 * 1024;
  const cases = [
    ['hello', abi(text('<h1>hello</h1>'))],
    ['empty-string', abi('')],
    ['one-word', abi(text('a'.repeat(32)))],
    ['unicode', abi(text(ch(0xe9) + ch(0x65e5) + ch(0x1f600) + '<p>')) ],
    ['uppercase-hex', abi(text('<b>X</b>')).toUpperCase().replace(/^0X/, '0x')],
    ['uppercase-prefix', '0X' + abi(text('x')).slice(2)],
    ['offset-zero-overlap', '0x' + ABI_WORD(0)],
    ['offset-zero-two-words', '0x' + ABI_WORD(0) + ABI_WORD(0)],
    ['offset-64', '0x' + ABI_WORD(64) + ABI_WORD(0) + ABI_WORD(3) + pad(text('abc'))],
    ['offset-unaligned', '0x' + ABI_WORD(33) + '00' + ABI_WORD(3) + pad(text('abc')).slice(0, -2)],
    ['offset-unaligned-fits', '0x' + ABI_WORD(1) + ABI_WORD(1).slice(2) + '41' + '00'.repeat(31)],
    ['offset-past-end', '0x' + ABI_WORD(1024) + ABI_WORD(0)],
    ['offset-at-end', '0x' + ABI_WORD(64) + ABI_WORD(0)],
    ['offset-max-safe', '0x' + ABI_WORD(2 ** 53 - 1) + ABI_WORD(0)],
    ['offset-over-safe', '0x' + ABI_WORD(2 ** 53) + ABI_WORD(0)],
    ['offset-uint256-max', '0x' + 'f'.repeat(64) + ABI_WORD(0)],
    ['length-over-data', abi(text('abc'), { length: 64 })],
    ['length-max-safe', abi(text('abc'), { length: 2 ** 53 - 1 })],
    ['length-over-safe', abi(text('abc'), { length: 2 ** 53 })],
    ['length-uint256-max', '0x' + ABI_WORD(32) + 'f'.repeat(64) + pad(text('abc'))],
    ['length-no-padding', '0x' + ABI_WORD(32) + ABI_WORD(3) + text('abc')],
    ['length-short-padding', '0x' + ABI_WORD(32) + ABI_WORD(33) + pad(text('a'.repeat(33))).slice(0, -64) + text('a').padEnd(62, '0')],
    ['padding-not-zero', abi(text('abc')).slice(0, -2) + 'ff'],
    ['tail-garbage', abi(text('abc'), { tail: 'ab'.repeat(32) })],
    ['tail-odd-word', abi(text('abc'), { tail: 'ab' })],
    ['only-offset', '0x' + ABI_WORD(32)],
    ['empty', '0x'],
    ['no-prefix', abi(text('x')).slice(2)],
    ['odd-length', abi(text('x')) + '0'],
    ['not-hex', abi(text('x')).slice(0, -1) + 'g'],
    ['whitespace', ' ' + abi(text('x'))],
    ['trailing-newline', abi(text('x')) + '\n'],
    ['short-word', '0x' + '00'.repeat(31)],
    ['invalid-utf8', abi('c328')],
    ['invalid-surrogate', abi('eda080')],
    ['invalid-overlong', abi('c0af')],
    ['invalid-five-byte', abi('f888808080')],
    ['invalid-continuation', abi('80')],
    ['invalid-truncated', abi('e282')],
    ['invalid-above-max', abi('f4908080')],
    ['nul-and-controls', abi('0001027f')],
    ['bom', abi('efbbbf3c703e')],
    ['replacement-char', abi('efbfbd')],
    ['noncharacter', abi('efbfbf')],
  ].map(([id, result]) => ({ id, result }));
  cases.push({ id: 'result-null', result_json: null });
  cases.push({ id: 'result-number', result_json: 5 });
  cases.push({ id: 'result-object', result_json: { data: '0x' } });
  // Sizes around the caps, as recipes: `0x` + parts, each hex or a repeat.
  const word = (n) => ({ hex: ABI_WORD(n) });
  const fill = (byte, count) => ({ repeat: byte, count });
  cases.push({ id: 'size-max', recipe: [word(32), word(MAX), fill('61', MAX)] });
  cases.push({ id: 'size-max-plus-one', recipe: [word(32), word(MAX + 1), fill('61', MAX + 1), fill('00', 31)] });
  cases.push({ id: 'size-encoded-limit', recipe: [word(32), word(MAX), fill('61', MAX), fill('00', 31)] });
  cases.push({ id: 'size-encoded-over', recipe: [word(32), word(MAX), fill('61', MAX), fill('00', 32)] });
  cases.push({ id: 'size-encoded-limit-odd', recipe: [word(32), word(MAX), fill('61', MAX), fill('00', 31), { hex: '0' }] });
  cases.push({ id: 'size-encoded-over-not-hex', recipe: [fill('7a7a', MAX / 2 + 64)] });
  cases.push({ id: 'size-encoded-limit-not-hex', recipe: [word(32), word(MAX), fill('61', MAX), fill('00', 30), { hex: 'zz' }] });
  cases.push({ id: 'size-short-claims-max', recipe: [word(32), word(MAX), fill('61', 32)] });
  return cases;
}

function expandRecipe(recipe) {
  return '0x' + recipe.map((part) => part.hex ?? part.repeat.repeat(part.count)).join('');
}

function htmlInput(c) {
  if (c.recipe) return expandRecipe(c.recipe);
  if (Object.hasOwn(c, 'result_json')) return c.result_json;
  return c.result;
}

function htmlKind(error) {
  if (error.code === 'ONCHAIN_APP_TOO_LARGE') return 'too_large';
  if (error.message === 'html() returned malformed ABI data') return 'malformed';
  if (error.code === 'INVALID_ARGUMENT' && /invalid BytesLike value/.test(error.message)) return 'odd_length';
  if (error.code === 'BAD_DATA' && error.shortMessage === 'invalid length for result data') return 'bad_length';
  if (error.code === 'BAD_DATA' && error.shortMessage === 'could not decode result data') return 'undecodable';
  if (/^deferred error during ABI decoding triggered accessing index 0$/.test(error.message)) return 'bad_string';
  throw new Error(`unclassified html() error: ${error.code} ${error.message}`);
}

async function buildHtml(ref, ethers) {
  const { html, onchain } = ref;
  const out = [];
  const trusted = { trust: { level: 'verified', method: 'quorum', agreed: ['a'], dissented: [], queried: ['a'] }, source: 'quorum', verified: true };
  for (const c of htmlCases()) {
    const input = htmlInput(c);
    // Through the handler, as the page sees it: the O(1) size check, the
    // decode, the cap and the hash.
    const response = await onchain.handleOnchainAppRequest(
      { url: 'web3://0x1111111111111111111111111111111111111111.eip155-1/', method: 'GET', headers: new Headers() },
      { chainRequest: async () => ({ result: input, ...trusted }), trustState: onchain.createOnchainAppTrustState({ now: () => 0, createToken: () => 'T'.repeat(43) }) },
    );
    const js = { status: response.status };
    if (response.status === 200) {
      const body = Buffer.from(await response.arrayBuffer());
      const provenance = JSON.parse(Buffer.from(response.headers.get('x-freedom-onchain-app-provenance'), 'base64url').toString('utf8'));
      js.ok = { hash: provenance.htmlHash, length: body.length, ...(body.length <= 256 ? { html: body.toString('utf8') } : {}) };
      if (!c.recipe) {
        assert.equal(ethers.keccak256(body), js.ok.hash, c.id);
        assert.equal(html.decodeHtmlDocument(input).htmlHash, js.ok.hash, c.id);
      }
    } else {
      // Which stage refused it, in decodeHtmlInWorker's order.
      try {
        html.assertHtmlResultSize(input);
        html.decodeHtmlDocument(input);
        assert.fail(`${c.id}: the handler refused what decodes`);
      } catch (error) {
        js.error = htmlKind(error);
      }
    }
    const entry = { id: c.id };
    for (const key of ['result', 'result_json', 'recipe']) if (Object.hasOwn(c, key)) entry[key] = c[key];
    entry.js = js;
    out.push(entry);
  }
  return out;
}

function classCases() {
  const trust = (fields) => ({ trust: fields });
  return [
    ['verified', trust({ level: 'verified', dissented: [] })],
    ['verified-dissented', trust({ level: 'verified', dissented: ['b'] })],
    ['user-configured', trust({ level: 'user-configured' })],
    ['user-configured-dissented', trust({ level: 'user-configured', dissented: ['b'] })],
    ['unverified', trust({ level: 'unverified', dissented: [] })],
    ['unverified-dissented', trust({ level: 'unverified', dissented: ['b', 'c'] })],
    ['unverified-dissented-empty-string', trust({ level: 'unverified', dissented: [''] })],
    ['unverified-dissented-not-array', trust({ level: 'unverified', dissented: 'b' })],
    ['unverified-dissented-object', trust({ level: 'unverified', dissented: { length: 1 } })],
    ['level-uppercase', trust({ level: 'VERIFIED' })],
    ['level-missing', trust({})],
    ['level-number', trust({ level: 1 })],
    ['level-array', trust({ level: ['verified'] })],
    ['trust-null-verified', { trust: null, verified: true }],
    ['trust-null-unverified', { trust: null, verified: false }],
    ['trust-missing-verified', { verified: true }],
    ['trust-missing-verified-truthy', { verified: 1 }],
    ['trust-missing', {}],
    ['trust-false', { trust: false, verified: true }],
    ['trust-zero', { trust: 0, verified: true }],
    ['trust-empty-string', { trust: '', verified: true }],
    ['trust-string', { trust: 'verified', verified: true }],
    ['trust-array', { trust: ['verified'], verified: true }],
    ['trust-empty-object', { trust: {}, verified: true }],
  ].map(([id, chain_result]) => ({ id, chain_result }));
}

async function buildClasses(ref) {
  const { onchain } = ref;
  const { hasTrustConflict } = onchain.__internals;
  const doc = '0x' + ABI_WORD(32) + ABI_WORD(2) + Buffer.from('hi').toString('hex').padEnd(64, '0');
  const out = [];
  for (const c of classCases()) {
    const response = await onchain.handleOnchainAppRequest(
      { url: 'web3://0x1111111111111111111111111111111111111111.eip155-1/', method: 'GET', headers: new Headers() },
      { chainRequest: async () => ({ result: doc, ...c.chain_result }), trustState: onchain.createOnchainAppTrustState({ now: () => 0, createToken: () => 'T'.repeat(43) }) },
    );
    let klass;
    if (response.status === 200) klass = 'trusted';
    else {
      assert.equal(response.status, 451, c.id);
      const gate = new URL(Buffer.from(response.headers.get('x-freedom-onchain-app-gate'), 'base64url').toString('utf8'));
      klass = gate.searchParams.get('conflict') === '1' ? 'conflict' : 'untrusted';
      assert.equal(gate.searchParams.has('token'), klass === 'untrusted', c.id);
    }
    const provenance = onchain.buildOnchainProvenance('0x' + '00'.repeat(32), { chainId: 1, address: '0x1111111111111111111111111111111111111111' }, c.chain_result);
    out.push({ ...c, js: { class: klass, has_trust_conflict: hasTrustConflict(provenance.trust) } });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Plan validation: the design's, with no reference

function validationCases(requests) {
  const out = [];
  // Every plan above, for its own request: valid unless the case says why not.
  for (const entry of requests) {
    out.push({ id: `plan-${entry.id}`, source: 'design', request_id: entry.id, expect: entry.validation });
  }
  const base = requests.find((e) => e.id === 'bzz-hash-path-query');
  const ipfsBase = requests.find((e) => e.id === 'ipfs-small-text-nav');
  const gatewayBase = requests.find((e) => e.id === 'ipfs-gateway');
  const redirect = requests.find((e) => e.id === 'ipfs-gateway-localhost');
  const error = requests.find((e) => e.id === 'bzz-name-not-found');
  const mutate = (id, from, change, expect, request = from.request) => {
    const plan = structuredClone(from.plan);
    change(plan);
    out.push({ id, source: 'design', request, plan, expect });
  };
  const withRequest = (from, change) => { const request = structuredClone(from.request); change(request); return request; };
  const f = (plan) => plan.fetch;
  // Shape.
  out.push({ id: 'shape-null', source: 'design', request: base.request, plan: null, expect: 'shape' });
  out.push({ id: 'shape-array', source: 'design', request: base.request, plan: [base.plan], expect: 'shape' });
  out.push({ id: 'shape-empty', source: 'design', request: base.request, plan: {}, expect: 'shape' });
  mutate('shape-two-variants', base, (p) => { p.error = error.plan.error; }, 'shape');
  mutate('shape-unknown-variant', base, (p) => { p.stream = p.fetch; delete p.fetch; }, 'shape');
  mutate('shape-unknown-field', base, (p) => { f(p).url = 'http://127.0.0.1:1633/'; }, 'shape');
  mutate('shape-missing-field', base, (p) => { delete f(p).timers; }, 'shape');
  mutate('shape-fetch-not-object', base, (p) => { p.fetch = 'x'; }, 'shape');
  // Method and node.
  mutate('method-post', base, () => {}, 'method', withRequest(base, (r) => { r.method = 'POST'; }));
  mutate('method-lowercase-get', base, () => {}, 'valid', withRequest(base, (r) => { r.method = 'get'; }));
  mutate('method-empty', base, () => {}, 'valid', withRequest(base, (r) => { r.method = ''; }));
  mutate('node-ipfs-for-ant', base, (p) => { f(p).node = 'ipfs'; }, 'node');
  mutate('node-unknown', base, (p) => { f(p).node = 'http://127.0.0.1:1633'; }, 'node');
  mutate('node-down', base, () => {}, 'node', withRequest(base, (r) => { r.backend.up = false; }));
  mutate('node-external', base, (p) => { f(p).trust.content = 'unverified'; }, 'valid', withRequest(base, (r) => { r.backend.ant = 'external'; }));
  mutate('node-external-down', base, () => {}, 'node', withRequest(base, (r) => { r.backend = { ant: 'external', up: false }; }));
  mutate('node-gateway-down', gatewayBase, () => {}, 'node', withRequest(gatewayBase, (r) => { r.backend.up = false; }));
  mutate('node-scheme-mismatch', base, () => {}, 'node', withRequest(base, (r) => { r.backend = { ipfs: 'native', up: true }; }));
  mutate('node-ant-for-ipfs', ipfsBase, (p) => { f(p).node = 'ant'; }, 'node');
  // Paths.
  const h = SWARM_REF;
  for (const [id, path, expect] of [
    ['bzz-ok', `/bzz/${h}/a/b?c=%2F`, 'valid'],
    ['bzz-ok-root', `/bzz/${h}`, 'valid'],
    ['bzz-ok-query-only', `/bzz/${h}?x`, 'valid'],
    ['bzz-ok-uppercase', `/bzz/${h.toUpperCase()}/`, 'valid'],
    ['bzz-ok-encrypted', `/bzz/${SWARM_REF_ENCRYPTED}/x`, 'valid'],
    ['bzz-short-ref', `/bzz/${h.slice(1)}/x`, 'path'],
    ['bzz-long-ref', `/bzz/${h}a/x`, 'path'],
    ['bzz-ref-not-hex', `/bzz/${h.slice(1)}g/x`, 'path'],
    ['bzz-other-namespace', `/bytes/${h}`, 'path'],
    ['bzz-root', '/', 'path'],
    ['bzz-empty', '', 'path'],
    ['bzz-no-slash', `bzz/${h}`, 'path'],
    ['bzz-dot-dot', `/bzz/${h}/../stamps`, 'path'],
    ['bzz-encoded-dot-dot', `/bzz/${h}/%2e%2e/%2E%2E/stamps`, 'path'],
    ['bzz-backslash', `/bzz/${h}/a\\b`, 'path'],
    ['bzz-encoded-slash', `/bzz/${h}/a%2Fb`, 'path'],
    ['bzz-encoded-backslash', `/bzz/${h}/a%5cb`, 'path'],
    ['bzz-scheme', `http://evil.example/bzz/${h}/`, 'path'],
    ['bzz-authority', `//evil.example/bzz/${h}/`, 'path'],
    ['bzz-fragment', `/bzz/${h}/a#b`, 'path'],
    ['bzz-unencoded-space', `/bzz/${h}/a b`, 'path'],
    ['bzz-unencoded-caret', `/bzz/${h}/a^b`, 'path'],
    ['bzz-unencoded-unicode', `/bzz/${h}/caf${ch(0xe9)}`, 'path'],
    ['bzz-not-string', 12, 'shape'],
  ]) mutate(`path-${id}`, base, (p) => { f(p).path = path; }, expect);
  const v1 = b32cid(CID_BYTES.dagPb);
  for (const [id, path, expect] of [
    ['ipfs-ok', `/ipfs/${v1}/a%2Fb/%5C?x`, 'valid'],
    ['ipns-for-ipfs', '/ipns/docs.ipfs.tech/install', 'path'],
    ['ipfs-root', `/ipfs/${v1}`, 'valid'],
    ['ipfs-no-ref', '/ipfs/', 'path'],
    ['ipfs-no-ref-slash', '/ipfs//x', 'path'],
    ['ipfs-bad-ref', '/ipfs/a%20b/', 'path'],
    ['ipfs-other-namespace', `/api/v0/cat?arg=${v1}`, 'path'],
    ['ipfs-dot-dot', `/ipfs/${v1}/../../api/v0/shutdown`, 'path'],
    ['ipfs-escape-to-ipns', `/ipfs/${v1}/%2e%2e/%2e%2e/ipns/x`, 'path'],
    ['ipfs-backslash', `/ipfs/${v1}/a\\b`, 'path'],
    ['ipfs-ref-dot-dot', '/ipfs/../x', 'path'],
    ['ipfs-uppercase-namespace', `/IPFS/${v1}`, 'path'],
  ]) mutate(`path-${id}`, ipfsBase, (p) => { f(p).path = path; }, expect);
  const ipnsBase = requests.find((e) => e.id === 'ipns-dnslink');
  for (const [id, path, expect] of [
    ['ipns-ok', '/ipns/docs.ipfs.tech/install', 'valid'],
    ['ipns-key', '/ipns/k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8/', 'valid'],
    ['ipfs-for-ipns', `/ipfs/${v1}/`, 'path'],
  ]) mutate(`path-${id}`, ipnsBase, (p) => { f(p).path = path; }, expect);
  // Headers.
  mutate('headers-bzz-not-allowed', base, (p) => { f(p).headers.push(['cookie', 'a=1']); }, 'header');
  mutate('headers-bzz-act', base, (p) => { f(p).headers.push(['swarm-act', 'true']); }, 'header');
  mutate('headers-bzz-uppercase-name', base, (p) => { f(p).headers[0][0] = 'Accept'; }, 'header');
  mutate('headers-bzz-swarm-value', base, (p) => { f(p).headers.find(([n]) => n === 'swarm-redundancy-strategy')[1] = '0'; }, 'header');
  mutate('headers-bzz-swarm-missing', base, (p) => { f(p).headers = f(p).headers.filter(([n]) => n !== 'swarm-chunk-retrieval-timeout'); }, 'header');
  mutate('headers-bzz-swarm-twice', base, (p) => { f(p).headers.push(['swarm-redundancy-fallback-mode', 'true']); }, 'header');
  mutate('headers-bzz-value-newline', base, (p) => { f(p).headers[0][1] = 'a\r\nx-evil: 1'; }, 'header');
  mutate('headers-bzz-value-nul', base, (p) => { f(p).headers[0][1] = 'a' + ch(0) + 'b'; }, 'header');
  mutate('headers-bzz-value-not-latin1', base, (p) => { f(p).headers[0][1] = ch(0x3042); }, 'header');
  mutate('headers-bzz-value-padded', base, (p) => { f(p).headers[0][1] = ' a'; }, 'header');
  mutate('headers-bzz-name-empty', base, (p) => { f(p).headers.push(['', 'x']); }, 'header');
  mutate('headers-bzz-not-pair', base, (p) => { f(p).headers.push(['accept']); }, 'shape');
  mutate('headers-bzz-not-list', base, (p) => { f(p).headers = {}; }, 'shape');
  mutate('headers-ipfs-custom', ipfsBase, (p) => { f(p).headers.push(['x-custom', '1'], ['range', 'bytes=0-']); }, 'valid');
  for (const name of ['host', 'origin', 'referer', 'cookie', 'authorization', 'connection', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
    mutate(`headers-ipfs-${name}`, ipfsBase, (p) => { f(p).headers.push([name, 'x']); }, 'header');
  }
  mutate('headers-ipfs-bad-name', ipfsBase, (p) => { f(p).headers.push(['x y', '1']); }, 'header');
  mutate('headers-ipfs-uppercase-name', ipfsBase, (p) => { f(p).headers.push(['X-Custom', '1']); }, 'header');
  // Retry and timers.
  mutate('retry-attempts-11', base, (p) => { f(p).retry.attempts = 11; f(p).retry.delays_ms.push(15000); }, 'retry');
  mutate('retry-attempts-0', base, (p) => { f(p).retry.attempts = 0; f(p).retry.delays_ms = []; }, 'retry');
  mutate('retry-delay-over', base, (p) => { f(p).retry.delays_ms[8] = 15001; }, 'retry');
  mutate('retry-delay-negative', base, (p) => { f(p).retry.delays_ms[0] = -1; }, 'retry');
  mutate('retry-delay-fraction', base, (p) => { f(p).retry.delays_ms[0] = 0.5; }, 'retry');
  mutate('retry-delays-count', base, (p) => { f(p).retry.delays_ms.pop(); }, 'retry');
  mutate('retry-fewer', base, (p) => { f(p).retry.attempts = 3; f(p).retry.delays_ms = [500, 1000]; }, 'valid');
  mutate('retry-status-404', base, (p) => { f(p).retry.statuses.push(404); }, 'retry');
  mutate('retry-status-duplicate', base, (p) => { f(p).retry.statuses.push(500); }, 'retry');
  mutate('retry-on-error-string', base, (p) => { f(p).retry.on_error = 'yes'; }, 'retry');
  mutate('retry-ipfs', ipfsBase, (p) => { f(p).retry = structuredClone(base.plan.fetch.retry); }, 'retry');
  mutate('timers-headers-over', base, (p) => { f(p).timers.headers_ms = 30001; }, 'timers');
  mutate('timers-headers-null-ant', base, (p) => { f(p).timers.headers_ms = null; }, 'timers');
  mutate('timers-headers-null-gateway', gatewayBase, () => {}, 'valid');
  mutate('timers-headers-gateway-bounded', gatewayBase, (p) => { f(p).timers.headers_ms = 30000; }, 'valid');
  mutate('timers-queue-over', ipfsBase, (p) => { f(p).timers.queue_ms = 15001; }, 'timers');
  mutate('timers-queue-null-native', ipfsBase, (p) => { f(p).timers.queue_ms = null; }, 'valid');
  mutate('timers-queue-ant', base, (p) => { f(p).timers.queue_ms = 1000; }, 'valid');
  mutate('timers-body-idle-over', base, (p) => { f(p).timers.body_idle_ms = 60001; }, 'timers');
  mutate('timers-body-idle-null', base, (p) => { f(p).timers.body_idle_ms = null; }, 'timers');
  mutate('timers-zero', base, (p) => { f(p).timers.headers_ms = 0; }, 'timers');
  mutate('timers-string', base, (p) => { f(p).timers.headers_ms = '30000'; }, 'timers');
  mutate('timers-shorter', base, (p) => { f(p).timers.headers_ms = 1; f(p).timers.body_idle_ms = 1; }, 'valid');
  // Response operations.
  mutate('response-unknown', base, (p) => { f(p).response.push('follow_redirects'); }, 'response');
  mutate('response-duplicate', base, (p) => { f(p).response.push('strip_page_state'); }, 'response');
  mutate('response-small-text-ant', base, (p) => { f(p).response.push('small_text'); }, 'response');
  mutate('response-decoded-encoding-native', ipfsBase, (p) => { f(p).response.unshift('strip_decoded_encoding'); }, 'response');
  mutate('response-redirect-native', ipfsBase, (p) => { f(p).response.push('canonicalize_redirect'); }, 'response');
  mutate('response-small-text-gateway', gatewayBase, (p) => { f(p).response.push('small_text'); }, 'valid');
  mutate('response-empty', base, (p) => { f(p).response = []; }, 'valid');
  mutate('response-not-string', base, (p) => { f(p).response.push(1); }, 'response');
  // Trust labels.
  mutate('trust-content-wrong', base, (p) => { f(p).trust.content = 'unverified'; }, 'trust');
  mutate('trust-content-unknown', base, (p) => { f(p).trust.content = 'verified'; }, 'trust');
  mutate('trust-name-number', base, (p) => { f(p).trust.name = 1; }, 'trust');
  mutate('trust-name-string', base, (p) => { f(p).trust.name = 'verified'; }, 'valid');
  // Redirects.
  mutate('redirect-302', redirect, (p) => { p.redirect.status = 302; }, 'redirect');
  mutate('redirect-elsewhere', redirect, (p) => { p.redirect.location = 'https://evil.example/'; }, 'redirect');
  mutate('redirect-other-cid', redirect, (p) => { p.redirect.location = p.redirect.location.replace('/a/b', '/a/c'); }, 'redirect');
  mutate('redirect-extra-header', redirect, (p) => { p.redirect.headers.push(['set-cookie', 'a=1']); }, 'redirect');
  mutate('redirect-no-header', redirect, (p) => { p.redirect.headers = []; }, 'redirect');
  mutate('redirect-header-value', redirect, (p) => { p.redirect.headers[0][1] = 'https://evil.example'; }, 'redirect');
  mutate('redirect-not-gateway-form', redirect, () => {}, 'redirect', withRequest(redirect, (r) => { r.url = `ipfs://${v1}/a/b?q=1`; }));
  mutate('redirect-for-bzz', redirect, () => {}, 'redirect', withRequest(base, () => {}));
  mutate('redirect-node-down', redirect, () => {}, 'valid', withRequest(redirect, (r) => { r.backend.up = false; }));
  mutate('redirect-external-down', redirect, () => {}, 'valid', withRequest(redirect, (r) => { r.backend = { ipfs: 'gateway', up: false }; }));
  // Errors.
  mutate('error-500', error, (p) => { p.error.status = 500; p.error.code = 500; }, 'error');
  mutate('error-code-mismatch', error, (p) => { p.error.code = 502; }, 'error');
  mutate('error-message-number', error, (p) => { p.error.message = 404; }, 'error');
  // Long strings as `{ $repeat: [text, count] }`.
  mutate('error-message-bound', error, (p) => { p.error.message = { $repeat: ['m', MAX_MESSAGE_UNITS] }; }, 'valid');
  mutate('error-message-over', error, (p) => { p.error.message = { $repeat: ['m', MAX_MESSAGE_UNITS + 1] }; }, 'error');
  mutate('error-message-astral-bound', error, (p) => { p.error.message = { $repeat: [ch(0x1f600), MAX_MESSAGE_UNITS / 2] }; }, 'valid');
  mutate('error-message-astral-over', error, (p) => { p.error.message = { $repeat: [ch(0x1f600) + 'x', Math.floor(MAX_MESSAGE_UNITS / 3) + 1] }; }, 'error');
  mutate('error-message-empty', error, (p) => { p.error.message = ''; }, 'valid');
  mutate('error-503', error, (p) => { p.error.status = 503; p.error.code = 503; }, 'valid');
  mutate('error-503-down', error, (p) => { p.error.status = 503; p.error.code = 503; }, 'valid', withRequest(error, (r) => { r.backend.up = false; }));
  mutate('error-405-any-method', error, (p) => { p.error.status = 405; p.error.code = 405; }, 'valid', withRequest(error, (r) => { r.method = 'POST'; }));
  mutate('error-status-string', error, (p) => { p.error.status = '404'; }, 'error');
  return out;
}

// ---------------------------------------------------------------------------

async function buildDweb(checkout, ethers, meta) {
  const ref = loadReference(checkout);
  const table = tables(ref);
  const { bzz, ipfs, manager, pageState, html } = ref;
  const requests = await buildRequests(ref, table);
  const failures = await buildFailures(ref);
  return {
    meta,
    constants: {
      ant_api_url: ANT_API_URL,
      gateway_url: GATEWAY_URL,
      bzz: {
        ...table.bzz,
        forwarded_request_headers: [...bzz.__internals.FORWARDED_REQUEST_HEADERS],
        swarm_headers: [...bzz.sanitizeRequestHeaders(new Headers())],
        redirect_statuses: [...bzz.__internals.REDIRECT_STATUSES],
        null_body_statuses: [...bzz.__internals.NULL_BODY_STATUSES],
      },
      ipfs: {
        native: table.native,
        gateway: table.gateway,
        stripped_request_headers: [...ipfs.__internals.STRIPPED_REQUEST_HEADERS],
        known_gateway_hosts: [...ipfs.__internals.KNOWN_GATEWAY_HOSTS],
        dropped_upstream_response_headers: [...manager.__internals.DROPPED_UPSTREAM_RESPONSE_HEADERS],
        native_buffer_size: ref.native.__internals.BUFFER_SIZE,
        not_running: failures.notRunning,
      },
      page_state_response_headers: [...pageState.PAGE_STATE_RESPONSE_HEADERS],
      html: { max_html_bytes: html.MAX_HTML_BYTES, selector: ref.onchain.HTML_SELECTOR },
      design: { body_idle_ms: BODY_IDLE_MS, max_message_units: MAX_MESSAGE_UNITS, response_operations: RESPONSE_OPS },
    },
    cids: buildCids(ref),
    hosts: buildHosts(ref),
    published_paths: buildPublishedPaths(ref),
    requests,
    exchanges: await buildExchanges(ref),
    locations: buildLocations(ref),
    operations: await buildOperations(ref),
    failures: failures.failures,
    html: await buildHtml(ref, ethers),
    html_class: await buildClasses(ref),
    validation: validationCases(requests),
  };
}

module.exports = { buildDweb, expandRecipe };
