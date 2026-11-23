'use strict';

// Direct cases for design 0014's fetch contract (colibri-contract.js): each
// variant admitted in its exact form, and refused one step past every bound
// the table names. colibri.json's recording checks the grammar against the
// reference; these check the grammar itself.

const assert = require('node:assert/strict');
const test = require('node:test');
const { classify, served, MAX_PAYLOAD } = require('./colibri-contract');

const PROVER = ['https://prover.example'];
const SERVERS = {
  prover: PROVER,
  beacon_api: ['https://b0.example', 'https://b1.example', 'https://b2.example', ...PROVER],
  checkpointz: Array.from({ length: 7 }, (_, i) => `https://c${i}.example`).concat(['https://b0.example', 'https://b1.example', 'https://b2.example', ...PROVER]),
  eth_rpc: ['https://rpc.example'],
};
const A = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const H = `0x${'ab'.repeat(32)}`;
const SLOT = `0x${'00'.repeat(32)}`;
const op = (method, params, { chain = 1, zk = false } = {}) => ({ method, params, chain, zk });
const CHECKPOINT = { checkpoint: true, chain: 1 };
const base = (fields) => ({ req_ptr: 0, chain_id: 1, exclude_mask: '0', ...fields });
const post = (payload, fields = {}) => base({ encoding: 'ssz', method: 'post', url: '', payload: { version: 196611, ...payload }, type: 'prover', ...fields });
const get = (url, fields = {}) => base({ encoding: 'ssz', method: 'get', url, type: 'prover', ...fields });
const sync = {
  lc_updates: base({ encoding: 'ssz', method: 'get', url: 'eth/v1/beacon/light_client/updates?start_period=1917&count=2', type: 'beacon_api' }),
  lc_bootstrap: base({ encoding: 'ssz', method: 'get', url: `eth/v1/beacon/light_client/bootstrap/${H}`, type: 'beacon_api' }),
  finality: base({ encoding: 'json', method: 'get', url: 'eth/v1/beacon/states/head/finality_checkpoints', type: 'checkpointz' }),
  block_root: base({ encoding: 'json', method: 'get', url: 'eth/v1/beacon/blocks/15713344/root', type: 'checkpointz' }),
};
const BALANCE = op('eth_getBalance', [A, 'latest']);
const RECEIPT = op('eth_getTransactionReceipt', [H]);
const TX = op('eth_getTransactionByHash', [H]);
const balanceProof = (extra = {}) => post({ method: 'eth_getProof', params: [A, [], 'latest'], ...extra });

// Each variant in its exact form.
const ADMITTED = [
  ['lc_updates', sync.lc_updates, BALANCE],
  ['lc_bootstrap', sync.lc_bootstrap, BALANCE],
  ['finality', sync.finality, BALANCE],
  ['block_root', sync.block_root, BALANCE],
  ['pap_account', balanceProof({ c4: '0x017e070000' }), BALANCE],
  ['pap_account', post({ method: 'eth_getProof', params: [A, [], 'latest'] }), op('eth_getTransactionCount', [A, 'latest'])],
  ['pap_storage', post({ method: 'eth_getProof', params: [A, [SLOT], 'latest'] }), op('eth_getStorageAt', [A, SLOT, 'latest'])],
  ['code', post({ method: 'eth_getCode', params: [A, 'latest'] }), op('eth_getCode', [A, 'latest'])],
  ['block', post({ method: 'eth_blockNumber', params: [] }), op('eth_blockNumber', [])],
  ['block', post({ method: 'eth_getBlockByNumber', params: [] }), op('eth_getBlockByNumber', null)],
  ['block', post({ method: 'eth_getBlockByHash', params: [H, false] }), op('eth_getBlockByHash', [H, false])],
  ['tx_cache', get('tx_cache?max_blocks=256', { ttl: 6 }), RECEIPT],
  ['tx_cache', get('tx_cache?max_blocks=256', { ttl: 2, chain_id: 100 }), op('eth_getTransactionReceipt', [H], { chain: 100 })],
  ['tx_cache_incremental', get('tx_cache?from_block=26472643&max_blocks=256', { ttl: 6 }), TX],
  ['tx_fallback', post({ method: 'eth_getTransactionByHash', params: [H] }), TX],
  ['tx_receipts', get('proof/eth_getBlockReceipts/0x193f4c3/196611/std/0x'), RECEIPT],
  ['tx_block', get('proof/eth_getBlockByNumber/0x193f4c3/196611/zk/0x017e070000'), op('eth_getTransactionByHash', [H], { zk: true })],
  ['checkpoint_root', sync.block_root, CHECKPOINT],
];

test('the fetch contract admits each variant in its exact form', () => {
  for (const [variant, request, operation] of ADMITTED) {
    assert.equal(classify(request, operation, SERVERS), variant, JSON.stringify(request));
  }
});

test('a checkpoint operation admits only checkpoint_root', () => {
  for (const request of [sync.finality, sync.lc_bootstrap, sync.lc_updates, balanceProof(), get('tx_cache?max_blocks=256', { ttl: 6 }),
    { ...sync.block_root, encoding: 'ssz' }, { ...sync.block_root, type: 'beacon_api' }, { ...sync.block_root, method: 'post' },
    { ...sync.block_root, ttl: 6 }, { ...sync.block_root, payload: {} }, { ...sync.block_root, exclude_mask: '2' },
    { ...sync.block_root, url: 'eth/v1/beacon/blocks/head/root' }, { ...sync.block_root, chain_id: 100 }]) {
    assert.equal(classify(request, CHECKPOINT, SERVERS), null, JSON.stringify(request));
  }
});

test('a payload is at most 64 KiB', () => {
  // eth_blockNumber's params are passed as sent, so its payload can be padded to any length.
  const sized = (bytes) => {
    const empty = Buffer.byteLength(JSON.stringify({ method: 'eth_blockNumber', params: [''], version: 196611 }));
    const params = ['x'.repeat(bytes - empty)];
    const request = post({ method: 'eth_blockNumber', params });
    assert.equal(Buffer.byteLength(JSON.stringify(request.payload)), bytes);
    return classify(request, op('eth_blockNumber', params), SERVERS);
  };
  assert.equal(MAX_PAYLOAD, 65536);
  assert.equal(sized(65536), 'block');
  assert.equal(sized(65537), null);
});

// Each row: the variant's exact form is admitted, and every refusal is one
// step past a bound.
const EDGES = [
  ['lc_updates: the period and count are 32-bit decimals, no sign or leading zero', BALANCE, (period, count) =>
    ({ ...sync.lc_updates, url: `eth/v1/beacon/light_client/updates?start_period=${period}&count=${count}` }),
  [['4294967295', '1'], ['0', '4294967295']], [['4294967296', '1'], ['1', '4294967296'], ['01', '1'], ['1', '02'], ['-1', '1'], ['+1', '1'], ['1', ''], ['0x1', '1']]],
  ['lc_updates: the query in its order, nothing after it', BALANCE, (url) => ({ ...sync.lc_updates, url }),
    [['eth/v1/beacon/light_client/updates?start_period=1&count=1']],
    [['eth/v1/beacon/light_client/updates?count=1&start_period=1'], ['eth/v1/beacon/light_client/updates?start_period=1&count=1&x=1'],
      ['/eth/v1/beacon/light_client/updates?start_period=1&count=1']]],
  ['lc_bootstrap: the root is 0x and 64 hex digits', BALANCE, (root) => ({ ...sync.lc_bootstrap, url: `eth/v1/beacon/light_client/bootstrap/${root}` }),
    [[H], [H.toUpperCase().replace('0X', '0x')]], [[H.slice(0, -1)], [`${H}a`], [`0X${H.slice(2)}`], [`0x${'g'.repeat(64)}`], [H.slice(2)]]],
  ['block_root: the slot is a 64-bit decimal', BALANCE, (slot) => ({ ...sync.block_root, url: `eth/v1/beacon/blocks/${slot}/root` }),
    [['0'], ['18446744073709551615']], [['18446744073709551616'], ['00'], ['01'], ['-1'], ['head'], ['0x10']]],
  ['tx_cache_incremental: from_block is a 64-bit decimal', TX, (from) => get(`tx_cache?from_block=${from}&max_blocks=256`, { ttl: 6 }),
    [['0'], ['18446744073709551615']], [['18446744073709551616'], ['01'], ['-1'], ['']]],
  ['tx_cache: max_blocks 256 and its age', RECEIPT, (url, ttl) => get(url, ttl === undefined ? {} : { ttl }),
    [['tx_cache?max_blocks=256', 6]], [['tx_cache?max_blocks=255', 6], ['tx_cache?max_blocks=256', 2], ['tx_cache?max_blocks=256', 7], ['tx_cache?max_blocks=256', undefined]]],
  ['the props: version, c4 of at most 41 bytes, last_block_hash of 32, no other key', BALANCE, (extra) => balanceProof(extra),
    [[{ c4: `0x${'ab'.repeat(41)}` }], [{ c4: '0x' }], [{ last_block_hash: H }]],
    [[{ c4: `0x${'ab'.repeat(42)}` }], [{ c4: '0xabc' }], [{ c4: 'ab' }], [{ c4: 7 }], [{ last_block_hash: H.slice(0, -2) }],
      [{ version: 196610 }], [{ version: '196611' }], [{ include_code: true }], [{ logs_completeness: true }], [{ signers: [] }],
      [{ rpc: 'x' }], [{ beacon: 'x' }]]],
  ['zk_proof only on a ZK client, and only true', null, (zk, value) => ({ request: balanceProof(value === undefined ? {} : { zk_proof: value }), operation: op('eth_getBalance', [A, 'latest'], { zk }) }),
    [[true, true], [true, undefined], [false, undefined]], [[false, true], [true, false], [true, 'true']]],
  ['a cached GET: its block a number, version, std or zk, a client state of at most 41 bytes, no query, no age', null, (url, zk, ttl) =>
    ({ request: get(url, ttl === undefined ? {} : { ttl }), operation: op('eth_getTransactionReceipt', [H], { zk }) }),
    [[`proof/eth_getBlockReceipts/0x0/196611/std/0x${'ab'.repeat(41)}`, false], ['proof/eth_getBlockReceipts/0xffffffffffffffff/196611/zk/0x', true]],
    [[`proof/eth_getBlockReceipts/0x0/196611/std/0x${'ab'.repeat(42)}`, false], ['proof/eth_getBlockReceipts/0x1/196611/zk/0x', false],
      ['proof/eth_getBlockReceipts/0x1/196610/std/0x', false], ['proof/eth_getBlockReceipts/0x01/196611/std/0x', false],
      ['proof/eth_getBlockReceipts/0x10000000000000000/196611/std/0x', false], ['proof/eth_getBlockReceipts/latest/196611/std/0x', false],
      ['proof/eth_getBlockReceipts/0x1/196611/std/0x?signers=1', false], ['proof/eth_getBlockReceipts/0x1/196611/std/0x', false, 6],
      ['proof/eth_getBlockByNumber/0x1/196611/std/0x', false]]],
  ['exclude_mask: a decimal whose bits are within the type\'s list', null, (type, mask) =>
    ({ request: type === 'prover' ? { ...balanceProof(), exclude_mask: mask } : { ...sync.lc_bootstrap, exclude_mask: mask }, operation: BALANCE }),
    [['prover', '0'], ['prover', '1'], ['beacon_api', '8'], ['beacon_api', '15']], [['prover', '2'], ['beacon_api', '16'], ['beacon_api', '0x1'], ['beacon_api', '-1'], ['beacon_api', 1]]],
  ['the verb exactly, and the request\'s own fields only', BALANCE, (fields) => ({ ...sync.lc_updates, ...fields }),
    [[{}], [{ delay: 0 }]], [[{ method: 'GET' }], [{ method: 'get ' }], [{ method: 'post' }], [{ method: '' }], [{ chain_id: 100 }],
      [{ encoding: 'json' }], [{ type: 'checkpointz' }], [{ type: 'eth_rpc' }], [{ ttl: 6 }], [{ payload: {} }], [{ delay: -1 }], [{ extra: 1 }]]],
  ['each operation\'s own payload', null, (request, operation) => ({ request, operation }),
    [[post({ method: 'eth_getProof', params: [A.toLowerCase(), [], 'latest'] }), BALANCE]],
    [[post({ method: 'eth_getBalance', params: [A, 'latest'] }), BALANCE], [post({ method: 'eth_getProof', params: [A, [], 'safe'] }), BALANCE],
      [post({ method: 'eth_getProof', params: [`0x${'11'.repeat(20)}`, [], 'latest'] }), BALANCE],
      [post({ method: 'eth_getProof', params: [A, [SLOT], 'latest'] }), BALANCE],
      [post({ method: 'eth_getTransactionByHash', params: [`0x${'cd'.repeat(32)}`] }), TX],
      [post({ method: 'eth_getTransactionReceipt', params: [H] }), TX],
      [{ ...balanceProof(), type: 'eth_rpc' }, BALANCE], [{ ...balanceProof(), url: 'x' }, BALANCE], [{ ...balanceProof(), encoding: 'json' }, BALANCE],
      [post({ jsonrpc: '2.0', id: 1, method: 'eth_getCode', params: [A, 'latest'] }), op('eth_getCode', [A, 'latest'])]]],
];

test('the fetch contract refuses one step past every bound field', () => {
  for (const [name, operation, make, admitted, refused] of EDGES) {
    const run = (args) => {
      const made = make(...args);
      return made.request ? classify(made.request, made.operation, SERVERS) : classify(made, operation, SERVERS);
    };
    for (const args of admitted) assert.notEqual(run(args), null, `${name}: admits ${JSON.stringify(args)}`);
    for (const args of refused) assert.equal(run(args), null, `${name}: refuses ${JSON.stringify(args)}`);
  }
});

test('a form the service doesn\'t serve admits nothing, the sync variants included', () => {
  for (const operation of [op('eth_getBalance', [A, 'safe']), op('eth_getBalance', [A]), op('eth_getBalance', [A, { blockHash: H }]),
    op('eth_getBlockByNumber', ['0X10', false]), op('eth_getBlockByNumber', ['justified', false]), op('eth_call', [{ to: A }, 'latest']),
    op('eth_gasPrice', []), op('eth_getTransactionReceipt', ['0x12'])]) {
    assert.equal(served(operation.method, operation.params), false);
    for (const request of Object.values(sync)) assert.equal(classify(request, operation, SERVERS), null, JSON.stringify(operation));
  }
});
