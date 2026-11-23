'use strict';

// Design 0014's vector cases (COL-1, "Vectors"), run by colibri.js. Each case
// names the capture session whose recorded server answers it reads, the
// store it starts from (empty, or another case's final store), its requests,
// and the rules that script its world before the session's captures are
// consulted: a failing server, a flipped byte, a prover answering from
// another block. Cases marked `deviation` also carry the design's outcome:
// the refusal the service gives before any context.

const fs = require('node:fs');
const path = require('node:path');

// Accounts and contracts read on each chain: an account with a balance and
// nonce, a token contract for code and storage (WETH, and Gnosis' WXDAI).
const CHAINS = {
  1: {
    account: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    token: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
    // Mined about four days before the capture (block 26443674): still in
    // the prover's transaction index.
    oldTx: '0x1a81d62142d40021d6d043b5f80d731b1389e23bffc8d97215903baf29325994',
    // Mined in June 2024 (block 20000000): not in the index, so the lookup
    // falls back to the prover, which has no proof for it.
    unindexedTx: '0xbb4b3fc2b746877dce70862850602f1d19bd890ab4db47e6b7ee1da1fe578a0d',
    // A finalized epoch-boundary block of the sync period before the
    // capture's (slot 15711968, epoch 490999): the lagging checkpoint
    // server's answer.
    lagging: { epoch: '490999', root: '0xa404598b23ba05e6b384e252841f5a0bca578db3a6d821d8107d1b5ac4cccfb0' },
    wait: 14000,
  },
  100: {
    account: '0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d',
    token: '0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d',
    // About six days before the capture (block 49317830).
    oldTx: '0x223088df7e4184d46c7420e632c5118943ceffc06985c0efd142c6b1c44ba6ae',
    // Block 35000000, 2024.
    unindexedTx: '0xcedbf7f06f9ea9d0f5bfa326c075f95385d16726e173784ae699c8f1c00fbe1d',
    // Slot 31276800, epoch 1954800.
    lagging: { epoch: '1954800', root: '0x4e18a33128b2907cac682f15c995cff97201721f19204b73dfb090a94863c277' },
    wait: 13000,
  },
};
// Storage slot 0, as the 32 bytes the prover takes.
const SLOT0 = '0x' + '00'.repeat(32);
const UNKNOWN_TX = '0x' + 'c0'.repeat(31) + '01';
// Code that returns 42 and reads no storage or block context:
// PUSH1 0x2a PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN.
const SCRIPTED_CODE = '0x602a60005260206000f3';
// ENS's Universal Resolver call for vitalik.eth's address, as the reference's
// ens-resolver.js made it through ethers' BrowserProvider before #1083
// (`universalResolverCall`: `resolve(dnsEncode(name), addr(namehash(name)))`
// on 0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe); colibri.js builds the
// calldata with the reference's ethers and checks it here.
const UR_CALL = {
  to: '0xeeeeeeee14d718c2b47d9923deab1335e144eeee',
  data: '0x9061b92300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000d07766974616c696b03657468000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000243b3b57deee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a5347583500000000000000000000000000000000000000000000000000000000',
};
const HTTP_BODY = '{"error":"prover unavailable"}';
const ZK_NOT_READY = 'No zk sync proof has been generated for this period yet';

const isProver = (request) => request.server?.type === 'prover';
const payloadMethod = (request) => request.payload?.method;
const findExchange = (pool, predicate) => {
  for (const exchange of pool.values()) if (predicate(exchange)) return exchange;
  throw new Error('No captured exchange matches the rule');
};
const proverPost = (method, test = () => true) => (exchange) => {
  if (exchange.method !== 'POST' || exchange.body === null) return false;
  const payload = JSON.parse(exchange.body);
  return payload.method === method && test(payload);
};

// #279's refusal text, as the service gives it (design 0014, What the service serves).
function refused(method, why) {
  return `Colibri cannot prove ${method} ${why}`;
}

function chainCases(chain) {
  const c = CHAINS[chain];
  const zk = `${chain}-zk`;
  const std = `${chain}-std`;
  const warm = `${zk}-cold`;
  const cases = [];
  const add = (kase) => cases.push({ chain, kind: 'request', ...kase });

  // Store: a cold start's bootstrap (ZK: the proof's sync data and a
  // checkpoint root), then warm starts from its store.
  add({ id: warm, session: zk, zk: true, store: null, requests: [{ method: 'eth_blockNumber', params: [] }] });
  const served = [
    ['balance', 'eth_getBalance', [c.account, 'latest']],
    ['nonce', 'eth_getTransactionCount', [c.account, 'latest']],
    ['storage', 'eth_getStorageAt', [c.token, SLOT0, 'latest']],
    // The short form of the same slot, which the prover refuses.
    ['storage-short-slot', 'eth_getStorageAt', [c.token, '0x0', 'latest']],
    ['code', 'eth_getCode', [c.token, 'latest']],
    ['block-latest', 'eth_getBlockByNumber', ['latest', false]],
    ['block-latest-full', 'eth_getBlockByNumber', ['latest', true]],
    ['block-number', 'eth_getBlockByNumber', (p) => [p.number, false]],
    ['block-hash', 'eth_getBlockByNumber', (p) => [p.hash, false]],
    ['block-empty', 'eth_getBlockByNumber', []],
    ['block-null', 'eth_getBlockByNumber', null],
    ['block-by-hash', 'eth_getBlockByHash', (p) => [p.hash, false]],
    ['block-number-warm', 'eth_blockNumber', []],
    ['priority-fee', 'eth_maxPriorityFeePerGas', []],
    ['tx', 'eth_getTransactionByHash', (p) => [p.tx]],
    ['receipt', 'eth_getTransactionReceipt', (p) => [p.tx]],
  ];
  for (const [name, method, params] of served) {
    add({
      id: `${chain}-${name}`, session: zk, zk: true, store: warm, requests: [{ method, params }],
      // The receipt reads the transaction index the transaction's lookup fetched.
      ...(name === 'receipt' ? { clockOf: `${chain}-tx` } : {}),
      ...(name === 'block-latest-full' ? {
        // The block's number, hash and a transaction of it, for the cases after.
        discover: (_, { result }) => {
          const txs = result.transactions;
          if (!txs.length) throw new Error('The latest block has no transaction: capture again');
          return { number: result.number, hash: result.hash, tx: txs[Math.min(1, txs.length - 1)].hash };
        },
      } : {}),
    });
  }
  // The transaction index, stale after 12 s, refreshed from the block after
  // its last when a lookup misses: a transaction mined after the first
  // lookup's index (the capture took it from the package's RPC host, one
  // block behind its head, before the second lookup).
  add({ id: `${chain}-tx-incremental`, session: zk, zk: true, store: warm, clockOf: `${chain}-tx`, requests: [
    { method: 'eth_getTransactionByHash', params: (p) => [p.tx] },
    { method: 'eth_getTransactionByHash', params: (p) => [p.newTx], wait: c.wait, before: newTx },
  ] });
  // Days old, and still in the index.
  add({ id: `${chain}-tx-old`, session: zk, zk: true, store: warm, clockOf: `${chain}-tx`, requests: [{ method: 'eth_getTransactionByHash', params: [c.oldTx] }] });
  // Outside the index: the fallback to the prover's own proof.
  add({ id: `${chain}-tx-unindexed`, session: zk, zk: true, store: warm, clockOf: `${chain}-tx`, requests: [{ method: 'eth_getTransactionByHash', params: [c.unindexedTx] }] });
  // #750: a hash the prover hasn't seen traps in WASM.
  add({ id: `${chain}-receipt-unknown`, session: zk, zk: true, store: warm, clockOf: `${chain}-tx`, requests: [{ method: 'eth_getTransactionReceipt', params: [UNKNOWN_TX] }] });

  // Failures: a flipped byte in each proof.
  const flip = (id, of, method, params, clockOf, store = warm, session = zk, isZk = true) => add({
    id: `${chain}-flip-${id}`, session, zk: isZk, store, clockOf, requests: [{ method, params }],
    rules: [{ name: `flip:${of.name}`, match: (request) => request.server && of.test(request), answer: (request, { lookup }) => ({ base: lookup(request), flip: 'middle' }) }],
  });
  const proverAsked = (method) => ({ name: method, test: (request) => isProver(request) && payloadMethod(request) === method });
  const urlHas = (text) => ({ name: text, test: (request) => request.url.includes(text) });
  flip('cold-proof', proverAsked('eth_blockNumber'), 'eth_blockNumber', [], warm, null);
  flip('account', proverAsked('eth_getProof'), 'eth_getBalance', [c.account, 'latest'], `${chain}-balance`);
  flip('storage', proverAsked('eth_getProof'), 'eth_getStorageAt', [c.token, SLOT0, 'latest'], `${chain}-storage`);
  flip('code', proverAsked('eth_getCode'), 'eth_getCode', [c.token, 'latest'], `${chain}-code`);
  flip('block', proverAsked('eth_getBlockByNumber'), 'eth_getBlockByNumber', ['latest', false], `${chain}-block-latest`);
  flip('tx-cache', urlHas('tx_cache'), 'eth_getTransactionReceipt', (p) => [p.tx], `${chain}-tx`);
  flip('receipts', urlHas('proof/eth_getBlockReceipts/'), 'eth_getTransactionReceipt', (p) => [p.tx], `${chain}-tx`);
  flip('tx-block', urlHas('proof/eth_getBlockByNumber/'), 'eth_getTransactionByHash', (p) => [p.tx], `${chain}-tx`);
  // A stale proof: the clock two minutes on.
  add({ id: `${chain}-stale-account`, session: zk, zk: true, store: warm, clockOf: `${chain}-balance`, requests: [{ method: 'eth_getBalance', params: [c.account, 'latest'], clockOffset: 120000 }] });
  add({ id: `${chain}-stale-block`, session: zk, zk: true, store: warm, clockOf: `${chain}-block-number-warm`, requests: [{ method: 'eth_blockNumber', params: [], clockOffset: 120000 }] });

  // F-9: the prover fails each proofable method the service serves, by an
  // HTTP error and by a transport error; the reference (with #1081) ends it.
  const proofable = [
    ['balance', 'eth_getBalance', [c.account, 'latest']],
    ['nonce', 'eth_getTransactionCount', [c.account, 'latest']],
    ['storage', 'eth_getStorageAt', [c.token, SLOT0, 'latest']],
    ['code', 'eth_getCode', [c.token, 'latest']],
    ['block-number', 'eth_getBlockByNumber', ['latest', false]],
    ['block-hash', 'eth_getBlockByHash', (p) => [p.hash, false]],
    ['block-number-now', 'eth_blockNumber', []],
    ['priority-fee', 'eth_maxPriorityFeePerGas', []],
  ];
  for (const [name, method, params] of proofable) {
    add({ id: `${chain}-f9-http-${name}`, session: zk, zk: true, store: warm, requests: [{ method, params }],
      rules: [{ name: 'prover:http-503', match: isProver, answer: { status: 503, body: HTTP_BODY } }] });
    add({ id: `${chain}-f9-transport-${name}`, session: zk, zk: true, store: warm, requests: [{ method, params }],
      deviation: 'fetch-error-text', designFetchError: true,
      rules: [{ name: 'prover:transport', match: isProver, answer: { transport: 'fetch failed' } }] });
  }

  // F-4: the ZK fallback. The prover has no ZK sync proof for the period yet;
  // the client drops ZK for good and asks again.
  add({ id: `${chain}-zk-fallback`, session: zk, zk: true, store: warm, requests: [{ method: 'eth_blockNumber', params: [] }, { method: 'eth_blockNumber', params: [] }],
    rules: [{ name: 'prover:zk-not-ready', match: (request) => isProver(request) && request.payload?.zk_proof === true, answer: { status: 500, body: ZK_NOT_READY } }] });

  // F-1: unproofable reads, answered by the package's public RPC hosts.
  for (const [name, method, params, why] of [
    ['gas-price', 'eth_gasPrice', [], null],
    ['fee-history', 'eth_feeHistory', ['0x4', 'latest', [25, 75]], null],
    ['balance-pending', 'eth_getBalance', [c.account, 'pending'], 'at block "pending"'],
    ['balance-earliest', 'eth_getBalance', [c.account, 'earliest'], 'at block "earliest"'],
  ]) {
    add({ id: `${chain}-${name}`, session: zk, zk: true, store: warm, requests: [{ method, params }],
      deviation: 'colibri-unproofable', design: why === null ? `Method ${method} is not supported` : refused(method, why) });
  }
  // F-11: calls run on code from a public RPC host, never compared with the
  // account's proven code hash; one that reads nothing has no proof at all.
  const scripted = { name: 'eth_rpc:eth_getCode:scripted', match: (request) => request.server?.type === 'eth_rpc' && payloadMethod(request) === 'eth_getCode',
    answer: { body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: SCRIPTED_CODE }), headers: { 'content-type': 'application/json' } } };
  add({ id: `${chain}-call-scripted-code`, session: zk, zk: true, store: warm, requests: [{ method: 'eth_call', params: [{ to: c.token, data: '0x313ce567' }, 'latest'] }],
    rules: [scripted], deviation: 'colibri-no-calls', design: 'Method eth_call is not supported' });
  add({ id: `${chain}-estimate-scripted-code`, session: zk, zk: true, store: warm, requests: [{ method: 'eth_estimateGas', params: [{ to: c.token, data: '0x313ce567' }, 'latest'] }],
    rules: [scripted], deviation: 'colibri-no-calls', design: 'Method eth_estimateGas is not supported' });
  if (chain === 1) {
    add({ id: '1-ur-resolve', session: zk, zk: true, store: warm, requests: [{ method: 'eth_call', params: [UR_CALL, 'latest'] }],
      deviation: 'colibri-no-calls', design: 'Method eth_call is not supported' });
  }
  // F-12: reads Colibri doesn't bind to the requested block, with a prover
  // that answers from another block (the latest one, captured above).
  const fromLatestAccount = { name: 'prover:latest-account-proof', match: isProver,
    answer: (_, { pool }) => ({ from: findExchange(pool, proverPost('eth_getProof', (payload) => payload.params[2] === 'latest' && payload.params[0].toLowerCase() === c.account.toLowerCase() && payload.params[1].length === 0)) }) };
  const fromLatestBlock = { name: 'prover:latest-block-proof', match: isProver,
    answer: (_, { pool }) => ({ from: findExchange(pool, proverPost('eth_getBlockByNumber', (payload) => payload.params[0] === 'latest' && payload.params[1] === false)) }) };
  const unbound = [
    ['balance-number', 'eth_getBalance', (p) => [c.account, p.number], fromLatestAccount, (p) => `at block "${p.number}"`],
    ['balance-hash', 'eth_getBalance', (p) => [c.account, p.hash], fromLatestAccount, (p) => `at block "${p.hash}"`],
    ['balance-safe', 'eth_getBalance', [c.account, 'safe'], fromLatestAccount, 'at block "safe"'],
    ['balance-finalized', 'eth_getBalance', [c.account, 'finalized'], fromLatestAccount, 'at block "finalized"'],
    ['balance-justified', 'eth_getBalance', [c.account, 'justified'], fromLatestAccount, 'at block "justified"'],
    ['balance-no-block', 'eth_getBalance', [c.account], fromLatestAccount, 'with params of length 1'],
    ['balance-1898-hash', 'eth_getBalance', (p) => [c.account, { blockHash: p.hash }], fromLatestAccount, 'at a block that isn\'t a string'],
    ['balance-1898-canonical', 'eth_getBalance', (p) => [c.account, { blockHash: p.hash, requireCanonical: true }], fromLatestAccount, 'at a block that isn\'t a string'],
    ['balance-1898-number', 'eth_getBalance', (p) => [c.account, { blockNumber: p.number }], fromLatestAccount, 'at a block that isn\'t a string'],
    ['block-safe', 'eth_getBlockByNumber', ['safe', false], fromLatestBlock, 'at block "safe"'],
    ['block-finalized', 'eth_getBlockByNumber', ['finalized', false], fromLatestBlock, 'at block "finalized"'],
    ['block-justified', 'eth_getBlockByNumber', ['justified', false], fromLatestBlock, 'at block "justified"'],
    ['block-0X10', 'eth_getBlockByNumber', ['0X10', false], fromLatestBlock, 'at block "0X10"'],
    ['block-1x10', 'eth_getBlockByNumber', ['1x10', false], fromLatestBlock, 'at block "1x10"'],
  ];
  for (const [name, method, params, rule, why] of unbound) {
    add({ id: `${chain}-unbound-${name}`, session: zk, zk: true, store: warm, requests: [{ method, params }],
      clockOf: method === 'eth_getBalance' ? `${chain}-balance` : `${chain}-block-latest`,
      rules: [rule], deviation: 'colibri-unbound', design: (p) => refused(method, typeof why === 'function' ? why(p) : why) });
  }

  // The ZK-off client: a cold start bootstraps from the checkpoint servers'
  // finalized root, then warm reads.
  const stdCold = `${std}-cold`;
  add({ id: stdCold, session: std, zk: false, store: null, requests: [{ method: 'eth_blockNumber', params: [] }] });
  add({ id: `${chain}-std-balance`, session: std, zk: false, store: stdCold, requests: [{ method: 'eth_getBalance', params: [c.account, 'latest'] }] });
  add({ id: `${chain}-std-storage`, session: std, zk: false, store: stdCold, requests: [{ method: 'eth_getStorageAt', params: [c.token, SLOT0, 'latest'] }] });
  if (chain === 100) {
    add({ id: '100-std-receipt', session: std, zk: false, store: stdCold, requests: [{ method: 'eth_getTransactionReceipt', params: [c.oldTx] }] });
  }
  // A checkpoint server a sync period behind: the bootstrap is the earlier
  // period's, and light-client updates bring it forward.
  add({ id: `${chain}-std-lagging-checkpoint`, session: std, zk: false, store: null, clockOf: stdCold, requests: [{ method: 'eth_blockNumber', params: [] }], rules: [laggingRule(c)] });
  // A server failing before another answers, and every server failing.
  add({ id: `${chain}-std-failover`, session: std, zk: false, store: null, clockOf: stdCold, requests: [{ method: 'eth_blockNumber', params: [] }],
    rules: [{ name: 'beacon_api[0]:http-503', match: (request) => request.server?.type === 'beacon_api' && request.server.index === 0, answer: { status: 503, body: HTTP_BODY } }] });
  add({ id: `${chain}-std-sync-all-fail`, session: std, zk: false, store: null, clockOf: stdCold, requests: [{ method: 'eth_blockNumber', params: [] }],
    rules: [{ name: 'beacon_api:http-503', match: (request) => request.url.includes('/light_client/'), answer: { status: 503, body: HTTP_BODY } }] });
  flip('bootstrap', urlHas('light_client/bootstrap/'), 'eth_blockNumber', [], stdCold, null, std, false);
  flip('updates', urlHas('light_client/updates'), 'eth_blockNumber', [], `${chain}-std-lagging-checkpoint`, null, std, false);
  cases.at(-1).rules.unshift(laggingRule(c));
  return cases;
}

// Capture only: a transaction one block behind the RPC host's head.
// Waits until the head is four blocks past the first lookup's block, so the
// transaction is newer than that lookup's index.
async function newTx(live, chain) {
  let head = BigInt(await live.rpc(chain, 'eth_blockNumber', []));
  for (let tries = 0; head < BigInt(live.params.number) + 4n; tries += 1) {
    if (tries > 30) throw new Error('The chain did not advance');
    await new Promise((resolve) => setTimeout(resolve, 3000));
    head = BigInt(await live.rpc(chain, 'eth_blockNumber', []));
  }
  const block = await live.rpc(chain, 'eth_getBlockByNumber', [`0x${(head - 1n).toString(16)}`, false]);
  if (!block.transactions.length) throw new Error('The block has no transaction: capture again');
  live.params.newTx = block.transactions[0];
}

function laggingRule(c) {
  return { name: 'checkpointz:finality:previous-period', match: (request) => request.url.endsWith('/eth/v1/beacon/states/head/finality_checkpoints'),
    answer: { body: JSON.stringify({ data: { finalized: c.lagging, current_justified: c.lagging, previous_justified: c.lagging } }), headers: { 'content-type': 'application/json' } } };
}

// The 2,000-unit cut, on chain 1's balance read and block number.
function cutCases() {
  const c = CHAINS[1];
  const base = { chain: 1, kind: 'request', session: '1-zk', zk: true, store: '1-zk-cold' };
  return [
    // The fetch text is under 2,000 units; the completed adapter message crosses it.
    { ...base, id: '1-f9-cut-message', requests: [{ method: 'eth_getBalance', params: [c.account, 'latest'] }],
      rules: [{ name: 'prover:http-503:long', match: isProver, answer: { status: 503, body: 'x'.repeat(1900) } }] },
    // The body alone runs past 2,000.
    { ...base, id: '1-f9-cut-body', requests: [{ method: 'eth_getBalance', params: [c.account, 'latest'] }],
      rules: [{ name: 'prover:http-503:longer', match: isProver, answer: { status: 503, body: 'y'.repeat(2500) } }] },
    // A transport error whose params carry the completed message across it.
    { ...base, id: '1-f9-cut-params', requests: [{ method: 'eth_blockNumber', params: ['0x' + 'ab'.repeat(500)] }],
      deviation: 'fetch-error-text', designFetchError: true,
      rules: [{ name: 'prover:transport', match: isProver, answer: { transport: 'fetch failed' } }] },
  ];
}

// The Myotis checkpoint check over freedom-browser's own captures
// (docs/audits/evidence/colibri-v3-2026-09/captures), its v2 proofs from
// myotis-recovery-spike-2026-09 as the legacy control.
function checkpointCases() {
  const evidence = (reference, network) => {
    const dir = path.join(reference.checkout, 'docs/audits/evidence/colibri-v3-2026-09/captures', network);
    const original = JSON.parse(fs.readFileSync(path.join(dir, 'verified-checkpoint.json'), 'utf8'));
    const responses = JSON.parse(fs.readFileSync(path.join(dir, 'responses.json'), 'utf8'));
    const proof = fs.readFileSync(path.join(dir, 'proof.ssz'));
    const legacy = fs.readFileSync(path.join(reference.checkout, 'docs/audits/evidence/myotis-recovery-spike-2026-09/captures', `${network}-finalized`, 'proof.ssz'));
    return { original, responses, proof, legacy };
  };
  const make = (id, network, chain, { transform = (proof) => proof, legacy = false, clockOffset = 0 } = {}) => ({
    id, kind: 'checkpoint', chain,
    // The legacy proof isn't a valid object of its type: the service's
    // decode (c4_decode_proof) refuses it, where the reference walks the
    // unchecked bytes into a partial object (#443) and refuses that.
    ...(legacy ? { deviation: 'checked-decode' } : {}),
    files: [`docs/audits/evidence/colibri-v3-2026-09/captures/${network}/{proof.ssz,responses.json,verified-checkpoint.json}`,
      ...(legacy ? [`docs/audits/evidence/myotis-recovery-spike-2026-09/captures/${network}-finalized/proof.ssz`] : [])],
    capture: (reference) => {
      const { original, responses, proof, legacy: v2 } = evidence(reference, network);
      const bytes = legacy ? v2 : transform(Buffer.from(proof));
      return {
        now: original.verifiedAt + clockOffset,
        proofs: legacy ? [v2] : [proof],
        fetch: (url, options) => {
          if ((options.method ?? 'GET') === 'POST') return { proof: bytes };
          const response = responses[url];
          return response ? { status: response.status, body: response.body } : { missing: 'Provider offline in capture' };
        },
      };
    },
  });
  const flipLast = (proof) => { proof[proof.length - 1] ^= 1; return proof; };
  return [
    make('checkpoint-mainnet', 'mainnet', 1),
    make('checkpoint-gnosis', 'gnosis', 100),
    make('checkpoint-mainnet-flipped', 'mainnet', 1, { transform: flipLast }),
    make('checkpoint-gnosis-flipped', 'gnosis', 100, { transform: flipLast }),
    make('checkpoint-mainnet-v2', 'mainnet', 1, { legacy: true }),
    make('checkpoint-gnosis-v2', 'gnosis', 100, { legacy: true }),
    make('checkpoint-mainnet-stale', 'mainnet', 1, { clockOffset: 120000 }),
  ];
}

// A private session's process: memory store, the same cold start.
function privateCases() {
  return [{ id: '1-private-cold', chain: 1, kind: 'request', session: '1-zk', zk: true, store: null, private: true, clockOf: '1-zk-cold',
    requests: [{ method: 'eth_blockNumber', params: [] }] }];
}

const CASES = [...chainCases(1), ...cutCases(), ...privateCases(), ...chainCases(100), ...checkpointCases()];

module.exports = { CASES, CHAINS, UR_CALL, SCRIPTED_CODE, UNKNOWN_TX };
