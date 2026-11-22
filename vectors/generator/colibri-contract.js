'use strict';

// Design 0014's fetch contract ("The fetch contract"), as the grammar COL-1's
// recording is checked against. The table is the design's, derived from the
// sources of Colibri 3.0.3; nothing here comes from the reference's code, and
// the generator only checks the reference's requests against it, from both
// sides: every request a case in a served form makes must match a variant its
// operation allows, and every variant must be reached by some case.

const CLIENT_VERSION = 196611;
// Gnosis chains get a 2 s tx-cache age, others 6 s (`verify_pap_tx.c:49-51`).
const GNOSIS_CHAINS = new Set([100, 10200]);
const SECONDS_PER_SLOT = { 1: 12, 100: 5 };
const SLOTS_PER_EPOCH = { 1: 32, 100: 16 };
const U32 = 2n ** 32n - 1n;
const U64 = 2n ** 64n - 1n;

// Every variant of the table, in its order. `sync` ones are admitted for
// every operation; `checkpoint_proof` is main's own fetch, not the C core's.
const VARIANTS = [
  'lc_updates', 'lc_bootstrap', 'finality', 'block_root',
  'pap_account', 'pap_storage', 'code', 'block',
  'tx_cache', 'tx_cache_incremental', 'tx_fallback', 'tx_receipts', 'tx_block',
  'checkpoint_proof', 'checkpoint_root',
];

const ACCOUNT_READS = ['eth_getBalance', 'eth_getTransactionCount', 'eth_getCode'];
const TX_LOOKUPS = ['eth_getTransactionByHash', 'eth_getTransactionReceipt'];

const isHash = (value) => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
const isBlockNumber = (value) => typeof value === 'string' && /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,15})$/.test(value);
const decimal = (text, max) => /^(?:0|[1-9][0-9]*)$/.test(text) && BigInt(text) <= max;

/**
 * Whether the service serves `method` with `params` (the design's "What the
 * service serves", freedom-core #279's rule), and so which operation's
 * variants apply. `params` is the value main passes (`null` included).
 */
function served(method, params) {
  if (['eth_blockNumber', 'eth_maxPriorityFeePerGas'].includes(method)) return true;
  if (TX_LOOKUPS.includes(method)) return Array.isArray(params) && params.length === 1 && isHash(params[0]);
  if (ACCOUNT_READS.includes(method)) return Array.isArray(params) && params.length === 2 && params[1] === 'latest';
  if (method === 'eth_getStorageAt') return Array.isArray(params) && params.length === 3 && params[2] === 'latest';
  if (method === 'eth_getBlockByNumber') {
    if (params === null) return true;
    if (!Array.isArray(params)) return false;
    if (params.length === 0) return true;
    return params[0] === 'latest' || isBlockNumber(params[0]) || isHash(params[0]);
  }
  if (method === 'eth_getBlockByHash') return Array.isArray(params) && params.length > 0 && isHash(params[0]);
  return false;
}

// Parsed JSON compared with hex strings (addresses, slots, hashes) taken
// without regard to case.
function sameJson(a, b) {
  if (typeof a === 'string' && typeof b === 'string') {
    return /^0x[0-9a-fA-F]*$/.test(a) && /^0x[0-9a-fA-F]*$/.test(b) ? a.toLowerCase() === b.toLowerCase() : a === b;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((item, i) => sameJson(item, b[i]));
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && sameJson(a[key], b[key]));
  }
  return a === b;
}

/** Why the props of a prover POST break the contract, or null. */
function propsFault(payload, zk) {
  const allowed = new Set(['method', 'params', 'version', 'c4', 'zk_proof', 'last_block_hash']);
  for (const key of Object.keys(payload)) if (!allowed.has(key)) return `payload key ${key}`;
  if (payload.version !== CLIENT_VERSION) return 'version';
  if ('c4' in payload && !(typeof payload.c4 === 'string' && /^0x(?:[0-9a-fA-F]{2}){0,41}$/.test(payload.c4))) return 'c4';
  // Only on a ZK client; it may drop it (F-4's fallback).
  if ('zk_proof' in payload && !(zk && payload.zk_proof === true)) return 'zk_proof';
  if ('last_block_hash' in payload && !isHash(payload.last_block_hash)) return 'last_block_hash';
  return null;
}

function proverPost(request, zk, method, params) {
  if (request.type !== 'prover' || request.method !== 'post' || request.url !== '' || request.encoding !== 'ssz') return false;
  if ('ttl' in request && Number(request.ttl) !== 0) return false;
  const payload = request.payload;
  if (!payload || typeof payload !== 'object' || propsFault(payload, zk)) return false;
  return payload.method === method && sameJson(payload.params, params);
}

// The cached GET: `proof/<m>/<B>/196611/<std|zk>/0x<client state>`, its
// max_age derived from B (`c4_eth_block_ttl_s`).
function cachedGet(request, chain, zk, method, block) {
  if (request.type !== 'prover' || request.method !== 'get' || request.encoding !== 'ssz' || 'payload' in request) return false;
  const match = /^proof\/([A-Za-z_]+)\/([^/]+)\/([0-9]+)\/(std|zk)\/0x((?:[0-9a-fA-F]{2}){0,41})$/.exec(request.url);
  if (!match || match[1] !== method || match[3] !== String(CLIENT_VERSION) || (match[4] === 'zk' && !zk)) return false;
  if (block !== undefined && !sameJson(match[2], block)) return false;
  const B = match[2];
  if (!/^(?:latest|safe|justified|finalized|0x[0-9a-fA-F]{1,64})$/.test(B)) return false;
  const slot = SECONDS_PER_SLOT[chain];
  const epoch = slot * SLOTS_PER_EPOCH[chain];
  const ttl = B === 'latest' ? Math.floor(slot / 2) : (B === 'safe' || B === 'justified') ? Math.floor(epoch / 2) : B === 'finalized' ? epoch : 0;
  return Number(request.ttl ?? 0) === ttl;
}

function syncVariant(request) {
  if ('payload' in request || Number(request.ttl ?? 0) !== 0 || request.method !== 'get') return null;
  if (request.type === 'beacon_api' && request.encoding === 'ssz') {
    const updates = /^eth\/v1\/beacon\/light_client\/updates\?start_period=([0-9]+)&count=([0-9]+)$/.exec(request.url);
    if (updates && decimal(updates[1], U32) && decimal(updates[2], U32)) return 'lc_updates';
    if (/^eth\/v1\/beacon\/light_client\/bootstrap\/0x[0-9a-fA-F]{64}$/.test(request.url)) return 'lc_bootstrap';
  }
  if (request.type === 'checkpointz' && request.encoding === 'json') {
    if (request.url === 'eth/v1/beacon/states/head/finality_checkpoints') return 'finality';
    const root = /^eth\/v1\/beacon\/blocks\/([0-9]+)\/root$/.exec(request.url);
    if (root && decimal(root[1], U64)) return 'block_root';
  }
  return null;
}

/**
 * The variant `request` (a data request from a step's status, parsed) matches
 * for `operation` ({ method, params } as Colibri sees them, the chain, the
 * client's ZK setting, or { checkpoint: true }), or null.
 */
function classify(request, operation, servers) {
  const length = servers[request.type]?.length ?? 0;
  const mask = BigInt(request.exclude_mask ?? 0);
  if (length === 0 || mask >> BigInt(length) !== 0n) return null;
  if (operation.checkpoint) {
    const variant = syncVariant(request);
    return variant === 'block_root' ? 'checkpoint_root' : variant;
  }
  const sync = syncVariant(request);
  if (sync) return sync;
  const { method: M, params: P, chain, zk } = operation;
  if (!served(M, P)) return null;
  const args = Array.isArray(P) ? P : P ? [P] : [];
  if (['eth_getBalance', 'eth_getTransactionCount'].includes(M)) {
    return proverPost(request, zk, 'eth_getProof', [args[0], [], 'latest']) ? 'pap_account' : null;
  }
  if (M === 'eth_getStorageAt') {
    return proverPost(request, zk, 'eth_getProof', [args[0], [args[1]], 'latest']) ? 'pap_storage' : null;
  }
  if (M === 'eth_getCode') return proverPost(request, zk, M, args) ? 'code' : null;
  if (TX_LOOKUPS.includes(M)) {
    if (request.type === 'prover' && request.method === 'get' && request.encoding === 'ssz' && !('payload' in request)
      && Number(request.ttl) === (GNOSIS_CHAINS.has(chain) ? 2 : 6)) {
      if (request.url === 'tx_cache?max_blocks=256') return 'tx_cache';
      const from = /^tx_cache\?from_block=([0-9]+)&max_blocks=256$/.exec(request.url);
      if (from && decimal(from[1], U64)) return 'tx_cache_incremental';
    }
    if (proverPost(request, zk, M, args)) return 'tx_fallback';
    if (M === 'eth_getTransactionReceipt' && cachedGet(request, chain, zk, 'eth_getBlockReceipts')) {
      return /\/0x[0-9a-fA-F]{1,64}\//.test(request.url) ? 'tx_receipts' : null;
    }
    if (M === 'eth_getTransactionByHash' && cachedGet(request, chain, zk, 'eth_getBlockByNumber')) {
      return /\/0x[0-9a-fA-F]{1,64}\//.test(request.url) ? 'tx_block' : null;
    }
    return null;
  }
  return proverPost(request, zk, M, args) ? 'block' : null;
}

module.exports = { VARIANTS, CLIENT_VERSION, served, classify, sameJson };
