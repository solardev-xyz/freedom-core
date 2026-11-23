'use strict';

// Design 0014's fetch contract ("The fetch contract"), as the grammar COL-1's
// recording is checked against. The table is the design's, derived from the
// sources of Colibri 3.0.3; nothing here comes from the reference's code, and
// the generator only checks the reference's requests against it, from both
// sides: every request a case in a served form makes must match a variant its
// operation allows, and every variant must be reached by some case.
// colibri-contract.test.js holds its direct cases, refusals at every bound.

const CLIENT_VERSION = 196611;
// "A payload is at most 64 KiB": JSON.stringify of its parse, as main sends it.
const MAX_PAYLOAD = 64 * 1024;
// Gnosis chains get a 2 s tx-cache age, others 6 s (`verify_pap_tx.c:49-51`).
const GNOSIS_CHAINS = new Set([100, 10200]);
const U32 = 2n ** 32n - 1n;
const U64 = 2n ** 64n - 1n;
// The fields a data request carries (`colibri_common.c:230-247`).
const REQUEST_KEYS = new Set(['req_ptr', 'chain_id', 'encoding', 'exclude_mask', 'ttl', 'delay', 'method', 'url', 'payload', 'type']);
const PAYLOAD_KEYS = new Set(['method', 'params', 'version', 'c4', 'zk_proof', 'last_block_hash']);

// Every variant of the table, in its order. The four sync ones are admitted
// for every served operation; a checkpoint operation admits only main's own
// `checkpoint_proof` and the C core's `checkpoint_root`.
const VARIANTS = [
  'lc_updates', 'lc_bootstrap', 'finality', 'block_root',
  'pap_account', 'pap_storage', 'code', 'block',
  'tx_cache', 'tx_cache_incremental', 'tx_fallback', 'tx_receipts', 'tx_block',
  'checkpoint_proof', 'checkpoint_root',
];

const ACCOUNT_READS = ['eth_getBalance', 'eth_getTransactionCount', 'eth_getCode'];
const TX_LOOKUPS = ['eth_getTransactionByHash', 'eth_getTransactionReceipt'];

const isHash = (value) => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
// A block number: `0x` and 1 to 16 hex digits, no leading zero (64 bits).
const isBlockNumber = (value) => typeof value === 'string' && /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,15})$/.test(value);
// A decimal within `max`, with no sign and no leading zero.
const decimal = (text, max) => typeof text === 'string' && /^(?:0|[1-9][0-9]*)$/.test(text) && BigInt(text) <= max;
const has = (object, key) => Object.hasOwn(object, key);

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
    return keys.length === Object.keys(b).length && keys.every((key) => has(b, key) && sameJson(a[key], b[key]));
  }
  return a === b;
}

// No `ttl`, or the one given (0 for none).
const ttlIs = (request, ttl) => (has(request, 'ttl') ? request.ttl === ttl : ttl === 0);

/**
 * The fields every variant binds: no field a data request doesn't carry,
 * the operation's chain, an `exclude_mask` (a decimal) whose bits are within
 * the type's list of `length` servers, no `delay` but a non-negative integer.
 */
function envelope(request, chain, length) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) return false;
  if (!Object.keys(request).every((key) => REQUEST_KEYS.has(key))) return false;
  if (request.chain_id !== chain) return false;
  if (has(request, 'delay') && !(Number.isSafeInteger(request.delay) && request.delay >= 0)) return false;
  const mask = request.exclude_mask ?? '0';
  return decimal(mask, U64) && length > 0 && BigInt(mask) >> BigInt(length) === 0n;
}

/** Why the props of a prover POST break the contract, or null. */
function propsFault(payload, zk) {
  for (const key of Object.keys(payload)) if (!PAYLOAD_KEYS.has(key)) return `payload key ${key}`;
  if (payload.version !== CLIENT_VERSION) return 'version';
  // `0x` and the client state, at most 41 bytes (`sync_committee.h:39`).
  if (has(payload, 'c4') && !(typeof payload.c4 === 'string' && /^0x(?:[0-9a-fA-F]{2}){0,41}$/.test(payload.c4))) return 'c4';
  // Only on a ZK client; it may drop it (F-4's fallback).
  if (has(payload, 'zk_proof') && !(zk && payload.zk_proof === true)) return 'zk_proof';
  if (has(payload, 'last_block_hash') && !isHash(payload.last_block_hash)) return 'last_block_hash';
  return null;
}

/** A prover POST of `{ method, params }` and the props, the payload within 64 KiB. */
function proverPost(request, zk, method, params) {
  if (request.type !== 'prover' || request.method !== 'post' || request.url !== '' || request.encoding !== 'ssz') return false;
  if (!ttlIs(request, 0)) return false;
  const payload = request.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
  if (Buffer.byteLength(JSON.stringify(payload)) > MAX_PAYLOAD) return false;
  if (propsFault(payload, zk)) return false;
  return payload.method === method && sameJson(payload.params, params);
}

/** A prover GET with no payload. */
const proverGet = (request) => request.type === 'prover' && request.method === 'get' && request.encoding === 'ssz' && !has(request, 'payload');

// The cached GET of a transaction lookup's block:
// `proof/<m>/0x<n>/196611/<std|zk>/0x<client state>`. Its block is a number,
// whose max_age is none (`c4_eth_block_ttl_s`); `zk` only on a ZK client.
function cachedGet(request, zk, method) {
  if (!proverGet(request) || !ttlIs(request, 0)) return false;
  const match = /^proof\/([A-Za-z_]+)\/([^/]+)\/([0-9]+)\/(std|zk)\/0x((?:[0-9a-fA-F]{2}){0,41})$/.exec(request.url);
  if (!match || match[1] !== method || match[3] !== String(CLIENT_VERSION) || (match[4] === 'zk' && !zk)) return false;
  return isBlockNumber(match[2]);
}

function syncVariant(request) {
  if (has(request, 'payload') || !ttlIs(request, 0) || request.method !== 'get') return null;
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
 * A checkpoint operation's data request: only `checkpoint_root`, the one path
 * today's interception admits (GET `eth/v1/beacon/blocks/<slot>/root`, JSON),
 * to its one checkpoint server. `checkpoint_proof` is main's own fetch.
 */
function classifyCheckpoint(request, chain) {
  if (!envelope(request, chain, 1)) return null;
  if (request.type !== 'checkpointz' || request.method !== 'get' || request.encoding !== 'json') return null;
  if (has(request, 'payload') || !ttlIs(request, 0)) return null;
  const root = /^eth\/v1\/beacon\/blocks\/([0-9]+)\/root$/.exec(request.url);
  return root && decimal(root[1], U64) ? 'checkpoint_root' : null;
}

/**
 * The variant `request` (a data request from a step's status, parsed) matches
 * for `operation` ({ method, params } as main passes them, the chain and the
 * client's ZK setting, or { checkpoint: true, chain }), given main's server
 * table `servers`, or null. A form the service doesn't serve admits nothing,
 * the sync variants included.
 */
function classify(request, operation, servers) {
  const { chain } = operation;
  if (operation.checkpoint) return classifyCheckpoint(request, chain);
  const { method: M, params: P, zk } = operation;
  if (!served(M, P)) return null;
  if (!envelope(request, chain, servers[request?.type]?.length ?? 0)) return null;
  const sync = syncVariant(request);
  if (sync) return sync;
  // Colibri reads `null` params as `[]` and other non-arrays as `[params]`.
  const args = Array.isArray(P) ? P : P ? [P] : [];
  if (['eth_getBalance', 'eth_getTransactionCount'].includes(M)) {
    return proverPost(request, zk, 'eth_getProof', [args[0], [], 'latest']) ? 'pap_account' : null;
  }
  if (M === 'eth_getStorageAt') {
    return proverPost(request, zk, 'eth_getProof', [args[0], [args[1]], 'latest']) ? 'pap_storage' : null;
  }
  if (M === 'eth_getCode') return proverPost(request, zk, M, args) ? 'code' : null;
  if (TX_LOOKUPS.includes(M)) {
    if (proverGet(request) && ttlIs(request, GNOSIS_CHAINS.has(chain) ? 2 : 6)) {
      if (request.url === 'tx_cache?max_blocks=256') return 'tx_cache';
      const from = /^tx_cache\?from_block=([0-9]+)&max_blocks=256$/.exec(request.url);
      if (from && decimal(from[1], U64)) return 'tx_cache_incremental';
      return null;
    }
    if (proverPost(request, zk, M, args)) return 'tx_fallback';
    if (M === 'eth_getTransactionReceipt' && cachedGet(request, zk, 'eth_getBlockReceipts')) return 'tx_receipts';
    if (M === 'eth_getTransactionByHash' && cachedGet(request, zk, 'eth_getBlockByNumber')) return 'tx_block';
    return null;
  }
  return proverPost(request, zk, M, args) ? 'block' : null;
}

module.exports = { VARIANTS, CLIENT_VERSION, MAX_PAYLOAD, served, classify, sameJson };
