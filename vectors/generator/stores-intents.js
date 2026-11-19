'use strict';

// stores.json's `intents` (design 0013, PRF-5e-2): the stores reference's
// src/main/wallet/intent-store.js, loaded whole and unpatched, over its own
// lib/durable-journal.js in a temporary directory. `crypto.randomUUID` (the
// store's intent and handoff ids, and RUN_ID at each load of the module) and
// the clock are stubbed, so every id and time is fixed. Each run drives one
// live store (a `restart` loads the module again: a new run of main); after
// each step its file's records are loaded by a fresh store, whose verdict,
// views and usage the core's replay must give.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadWithInternals } = require('./naming');

const MODULE = 'src/main/wallet/intent-store.js';
const FILE = 'wallet-intents.jsonl';
const T = 1_763_000_000_000;
const LOCK = Object.freeze({ lock: 'held' });
const KEYS = ['0x' + '11'.repeat(32), '0x' + '22'.repeat(32)];
const PAYEE = '0x' + 'ab'.repeat(20);
const PROBE_UUIDS = 900_000;

const plain = (value) => (value === undefined ? null : JSON.parse(JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))));
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const SILENT = { info() {}, warn() {}, error() {}, debug() {} };

function loadModule(checkout, ethers, counter) {
  return loadWithInternals(checkout, MODULE, [], {
    crypto: { randomUUID: () => uuid((counter.n += 1)) },
    '../freedom-root': { getFreedomDataPath: (name) => path.join(os.tmpdir(), 'unused', name) },
    ethers,
    '../logger': SILENT,
    './nonce-reservations': { holdsAccountLock: (lock) => lock === LOCK },
  });
}

function readRecords(file) {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line).record);
}

// A signed transaction from ethers: type 2 by default, at `chainId`.
function signer(ethers) {
  const wallets = KEYS.map((key) => new ethers.Wallet(key));
  const sign = ({ key = 0, type = 2, chainId = 1, nonce, fee = 1, value = 1000n, data = '0x', to = PAYEE }) => {
    const fields = { type, chainId, nonce, to, value, data, gasLimit: 21000n + BigInt(data.length) };
    if (type === 2) Object.assign(fields, { maxFeePerGas: 1_000_000_000n * BigInt(fee), maxPriorityFeePerGas: 1_000_000n });
    else fields.gasPrice = 1_000_000_000n * BigInt(fee);
    const tx = ethers.Transaction.from(fields);
    tx.signature = wallets[key].signingKey.sign(tx.unsignedHash);
    return { raw: tx.serialized, hash: ethers.keccak256(tx.serialized), sender: wallets[key].address.toLowerCase(), chainId };
  };
  return { sign, decode: (raw) => ethers.Transaction.from(raw), senders: wallets.map((w) => w.address.toLowerCase()) };
}

async function probe(checkout, ethers, records, file, limits, encodeLine) {
  fs.writeFileSync(file, records.map((r) => encodeLine(r)).join(''));
  const { createIntentStore } = loadModule(checkout, ethers, { n: PROBE_UUIDS });
  const store = createIntentStore({ filePath: file, now: () => T - 1, ...(limits ? { limits } : {}) });
  await store.load();
  const quarantined = store.quarantined;
  for (const name of fs.readdirSync(path.dirname(file))) {
    if (name !== path.basename(file)) fs.rmSync(path.join(path.dirname(file), name));
  }
  if (quarantined) return { reason: quarantined.reason };
  const after = readRecords(file);
  const list = plain(store.list());
  const keys = [...new Set(list.map((v) => v.context?.key).filter((k) => k !== undefined))];
  const accounts = [];
  for (const v of list) {
    if (!accounts.some((a) => a.chain_id === v.chainId && a.sender === v.sender)) accounts.push({ chain_id: v.chainId, sender: v.sender });
  }
  return {
    reason: null,
    compacted: JSON.stringify(after) !== JSON.stringify(records) ? after : null,
    list,
    held: store.held().map((v) => v.intentId),
    by_key: keys.map((key) => ({ key, id: store.byKey(key)?.intentId ?? null })),
    held_nonces: accounts.map((a) => ({ ...a, nonces: store.heldNonces(a.chain_id, a.sender) })),
    void_refusal: list.map((v) => store.voidRefusal(v.intentId)),
    usage: plain(store.usage()),
  };
}

// Each run: its steps, each `[op, args]`. Intents are named (`A`, `B`…) in the
// steps; their ids are the store's. A tx is `{ key, type, chainId, nonce, fee, value }`.
function runsOf() {
  const ctx = (extra = {}) => ({ kind: 'payment', origin: 'https://shop.example', key: null, walletIndex: 0, ...extra });
  return [
    { name: 'lifecycle', steps: [
      ['commit', { name: 'A', tx: { nonce: 0 }, context: ctx({ key: 'order-1' }) }],
      ['commit', { name: 'A', via: 'replacement', tx: { nonce: 0, fee: 2 } }],
      ['handoff', { name: 'A', handoff: 'h1' }],
      ['outcome', { name: 'A', handoff: 'h1', outcome: 'sent', source: 'rpc', reasonClass: null }],
      ['handoff', { name: 'A', handoff: 'h2', hashOf: 0 }],
      ['outcome', { name: 'A', handoff: 'h2', outcome: 'not_sent', source: 'broadcast (x402)', reasonClass: 'nonce too low: 1/2' }],
      ['track', { name: 'A', bracket: { number: 100, hash: '0x' + 'CD'.repeat(32) }, unreadSince: null }],
      ['commit', { name: 'B', tx: { nonce: 1, value: 5n, data: '0x1234' }, context: ctx({ kind: 'safe-exec', origin: null, walletIndex: 3 }) }],
      ['settle', { name: 'A', label: 'paid', hashOf: 1, block: 120 }],
      ['restart', {}],
      ['handoff', { name: 'B', handoff: 'h3' }],
      ['outcome', { name: 'B', handoff: 'h3', outcome: 'uncertain', source: 'naïve', reasonClass: 'x'.repeat(129) }],
      ['commit', { name: 'C', tx: { nonce: 2 }, context: ctx({ key: 'order-2', origin: 'https://other.example' }) }],
      ['settle', { name: 'B', label: 'taken', hash: null, block: 130 }],
      ['retire', { name: 'C', block: 140, hashes: 'all' }],
      ['compact', {}],
      ['restart', {}],
    ] },
    { name: 'void and recovery', steps: [
      ['commit', { name: 'A', tx: { nonce: 5 }, context: ctx({ key: 'k' }) }],
      ['handoff', { name: 'A', handoff: 'h1' }],
      ['outcome', { name: 'A', handoff: 'h1', outcome: 'not_sent', source: null, reasonClass: null }],
      ['void', { name: 'A' }],
      ['commit', { name: 'B', tx: { nonce: 5, fee: 3 }, context: ctx({ key: 'k' }) }],
      ['handoff', { name: 'B', handoff: 'h2' }],
      ['commit', { name: 'C', tx: { nonce: 6 }, context: ctx() }],
      ['withdrawOrigin', { name: 'C' }],
      ['restart', {}],
      ['void', { name: 'C' }],
      ['handoff', { name: 'B', handoff: 'h3' }],
      ['outcome', { name: 'B', handoff: 'h3', outcome: 'rejected', source: 'rpc', reasonClass: 'underpriced' }],
      ['outcome', { name: 'B', handoff: 'h2', outcome: 'sent', source: null, reasonClass: null }],
    ] },
    { name: 'tombstones past the limit, other chains and accounts', limits: { tombstones: 2 }, steps: [
      ['commit', { name: 'A', tx: { nonce: 0 }, context: ctx() }],
      ['commit', { name: 'B', tx: { key: 1, type: 0, chainId: 100, nonce: 7 }, context: ctx({ walletIndex: 1 }) }],
      ['commit', { name: 'C', tx: { key: 1, nonce: 3 }, context: ctx({ key: 'c', walletIndex: undefined }) }],
      ['commit', { name: 'D', tx: { nonce: 1 }, context: ctx() }],
      ['settle', { name: 'A', label: 'failed', hashOf: 0, block: 9 }],
      ['settle', { name: 'B', label: 'paid', hashOf: 0, block: 10 }],
      ['settle', { name: 'D', label: 'taken', hash: null, block: 11 }],
      ['restart', {}],
      ['commit', { name: 'E', tx: { key: 1, type: 0, chainId: 100, nonce: 8, fee: 2 }, context: ctx() }],
      ['commit', { name: 'E', via: 'replacement', tx: { key: 1, type: 0, chainId: 100, nonce: 8, fee: 4 } }],
      ['retire', { name: 'E', block: 12, hashes: 'all' }],
      ['compact', {}],
    ] },
    { name: 'open handoffs across compaction', steps: [
      ['commit', { name: 'A', tx: { nonce: 0 }, context: ctx({ key: 'a' }) }],
      ['handoff', { name: 'A', handoff: 'h1' }],
      ['handoff', { name: 'A', handoff: 'h2' }],
      ['outcome', { name: 'A', handoff: 'h1', outcome: 'not_sent', source: null, reasonClass: null }],
      ['track', { name: 'A', bracket: null, unreadSince: T + 5 }],
      ['compact', {}],
      ['outcome', { name: 'A', handoff: 'h2', outcome: 'not_sent', source: null, reasonClass: null }],
      ['outcome', { name: 'A', handoff: 'h1', outcome: 'sent', source: null, reasonClass: null }],
      ['commit', { name: 'A', via: 'replacement', tx: { nonce: 0, fee: 5 } }],
      ['track', { name: 'A', bracket: null, unreadSince: null }],
      ['restart', {}],
      ['handoff', { name: 'A', handoff: 'h3' }],
    ] },
    { name: 'refusals', limits: { heldPerAccount: 1 }, steps: [
      ['commit', { name: 'A', tx: { nonce: 0 }, context: ctx({ key: 'x' }) }],
      ['commit', { name: 'B', tx: { nonce: 1 }, context: ctx() }],
      ['commit', { name: 'A', via: 'replacement', tx: { nonce: 0, value: 1n } }],
      ['commit', { name: 'A', via: 'replacement', tx: { nonce: 1 } }],
      ['commit', { name: 'Z', tx: { key: 1, nonce: 0 }, context: ctx({ key: 'x' }) }],
      ['void', { name: 'A', lock: null }],
      ['retire', { name: 'A', block: 1, hashes: ['0x' + '00'.repeat(32)] }],
      ['settle', { name: 'A', label: 'paid', hash: '0x' + '00'.repeat(32), block: 1 }],
      ['void', { name: 'A' }],
      ['handoff', { name: 'A', handoff: 'h1' }],
      ['void', { name: 'A' }],
      ['settle', { name: 'A', label: 'failed', hashOf: 0, block: 3 }],
      ['handoff', { name: 'A', handoff: 'h2' }],
      ['commit', { name: 'A', via: 'replacement', tx: { nonce: 0, fee: 9 } }],
    ] },
  ];
}

async function runOf(checkout, ethers, dir, encodeLine, s, run) {
  const file = path.join(dir, FILE);
  const probeFile = path.join(dir, 'probe', FILE);
  fs.mkdirSync(path.dirname(probeFile), { recursive: true });
  const counter = { n: 0 };
  let time = T;
  let mod = loadModule(checkout, ethers, counter);
  let store = mod.createIntentStore({ filePath: file, now: () => time, ...(run.limits ? { limits: run.limits } : {}) });
  await store.load();
  const ids = {};
  const handoffs = {};
  const hashes = {};
  const steps = [];
  for (const [op, args] of run.steps) {
    time += 1000;
    let refusal = null;
    try {
      if (op === 'restart') {
        mod = loadModule(checkout, ethers, counter);
        store = mod.createIntentStore({ filePath: file, now: () => time, ...(run.limits ? { limits: run.limits } : {}) });
        await store.load();
      } else if (op === 'commit') {
        const tx = s.sign(args.tx);
        const via = args.via ?? 'original';
        const view = await store.commit({
          ...(via === 'replacement' ? { intentId: ids[args.name] } : {}),
          chainId: tx.chainId, sender: tx.sender.toUpperCase().replace('0X', '0x'), nonce: args.tx.nonce,
          hash: tx.hash, raw: tx.raw, via, context: args.context,
        });
        ids[args.name] = view.intentId;
        (hashes[args.name] ??= []).push(tx.hash);
      } else if (op === 'handoff') {
        const hash = args.hashOf === undefined ? undefined : hashes[args.name][args.hashOf];
        handoffs[args.handoff] = (await store.handoff(ids[args.name], hash)).handoffId;
      } else if (op === 'outcome') {
        await store.outcome({ intentId: ids[args.name], handoffId: handoffs[args.handoff], outcome: args.outcome, source: args.source, reasonClass: args.reasonClass });
      } else if (op === 'settle') {
        const hash = args.hashOf === undefined ? args.hash : hashes[args.name][args.hashOf];
        await store.settle({ intentId: ids[args.name], label: args.label, hash, block: args.block });
      } else if (op === 'void') {
        await store.void(ids[args.name], args.lock === null ? null : LOCK);
      } else if (op === 'retire') {
        await store.retire({ intentId: ids[args.name], block: args.block, hashes: args.hashes === 'all' ? hashes[args.name] : args.hashes }, LOCK);
      } else if (op === 'track') {
        await store.track({ intentId: ids[args.name], bracket: args.bracket, unreadSince: args.unreadSince });
      } else if (op === 'withdrawOrigin') {
        await store.withdrawOrigin(ids[args.name]);
      } else if (op === 'compact') {
        await store.compact();
      } else {
        throw new Error(`unknown op ${op}`);
      }
    } catch (error) {
      if (!error.code) throw error;
      refusal = { code: error.code, message: error.message };
    }
    const records = readRecords(file);
    steps.push({ op, args: plain(args), at: time, refusal, records, load: await probe(checkout, ethers, records, probeFile, run.limits, encodeLine) });
  }
  return { name: run.name, limits: run.limits ?? null, steps };
}

// A damaged file: the records of a run's step with one changed, and the
// reason the reference moves the file aside for (null: not damaged).
function damagedCases(base, s) {
  const A = base[0];
  const B = base.find((r) => r.type === 'commit' && r.via === 'original' && r.intent_id !== A.intent_id);
  const set = (record, fields) => ({ ...record, ...fields });
  const drop = (record, key) => Object.fromEntries(Object.entries(record).filter(([k]) => k !== key));
  // Signed again, with the fields its bytes have (as the store's fieldsOf).
  const resign = (record, tx) => {
    const t = s.sign(tx);
    const d = s.decode(t.raw);
    const fee = (name) => (d.type === 2 ? d[name].toString() : null);
    const fields = {
      type: d.type, to: d.to.toLowerCase(), value: d.value.toString(), data: d.data, gas_limit: d.gasLimit.toString(),
      max_fee_per_gas: fee('maxFeePerGas'), max_priority_fee_per_gas: fee('maxPriorityFeePerGas'), gas_price: d.type === 0 ? d.gasPrice.toString() : null,
    };
    return set(record, { raw: t.raw, hash: t.hash, fields });
  };
  const replacement = base.find((r) => r.type === 'commit' && r.via === 'replacement');
  const handoff = base.find((r) => r.type === 'handoff' && r.hash === A.hash);
  const outcome = base.find((r) => r.type === 'outcome' && r.handoff_id === handoff.handoff_id);
  const cases = [
    ['unknown type', [set(A, { type: 'nope' })]],
    ['type as an array', [set(A, { type: ['commit'] })]],
    ['negative time', [set(A, { at: -1 })]],
    ['fractional time', [set(A, { at: 1.5 })]],
    ['short intent id', [set(A, { intent_id: 'short' })]],
    ['intent id of seven', [set(A, { intent_id: 'abcdefg' })]],
    ['bad run', [set(A, { run: 'a b c d e f g h' })]],
    ['chain id zero', [set(A, { chain_id: 0 })]],
    ['sender not hex', [set(A, { sender: '0x' + 'zz'.repeat(20) })]],
    ['uppercase sender and hash accepted', [set(A, { sender: A.sender.toUpperCase().replace('0X', '0x'), hash: A.hash.toUpperCase().replace('0X', '0x') })]],
    ['negative nonce', [set(A, { nonce: -1 })]],
    ['odd raw', [set(A, { raw: A.raw + '0' })]],
    ['raw not a transaction', [set(A, { raw: '0x00' })]],
    ['raw unsigned', [set(A, { raw: '0x02c90180808080808080c0' })]],
    ['raw of type 1', [resign(A, { type: 1, nonce: A.nonce })]],
    ['raw of type 0', [set(resign(A, { type: 0, nonce: A.nonce }), { chain_id: 1 })]],
    ['nonce not the signed one', [set(A, { nonce: A.nonce + 1 })]],
    ['chain not the signed one', [set(A, { chain_id: 5 })]],
    ['hash not the bytes', [set(A, { hash: '0x' + '00'.repeat(32) })]],
    ['fields reordered', [set(A, { fields: { to: A.fields.to, ...A.fields } })]],
    ['fields missing', [drop(A, 'fields')]],
    ['signed by another key', [resign(A, { key: 1, nonce: A.nonce })]],
    ['pre-155 legacy', [resign(A, { type: 0, chainId: 0, nonce: A.nonce })]],
    ['original twice', [A, A]],
    ['bad via', [set(A, { via: 'other' })]],
    ['no context', [drop(A, 'context')]],
    ['bad kind', [set(A, { context: { ...A.context, kind: 'Payment' } })]],
    ['camel wallet index', [set(A, { context: { kind: 'payment', walletIndex: 4 } })]],
    ['empty origin', [set(A, { context: { ...A.context, origin: '' } })]],
    ['nonce below a held one', [A, set(resign(B, { nonce: 0 }), { nonce: 0 })]],
    ['the same key held twice', [A, set(B, { context: { ...B.context, key: A.context.key } })]],
    ['replacement paying other data', [A, resign(replacement, { nonce: A.nonce, fee: 2, data: '0x12' })]],
    ['replacement paying another value', [A, resign(replacement, { nonce: A.nonce, fee: 2, value: 1n })]],
    ['replacement after its settle', [A, { type: 'settle', run: A.run, at: 5, intent_id: A.intent_id, label: 'failed', hash: A.hash, block: 1 }, replacement]],
    ['settle of an uncommitted hash', [A, { type: 'settle', run: A.run, at: 5, intent_id: A.intent_id, label: 'paid', hash: B.hash, block: 1 }]],
    ['settle without a block', [A, { type: 'settle', run: A.run, at: 5, intent_id: A.intent_id, label: 'paid', hash: A.hash }]],
    ['void below a held nonce', [A, B, { type: 'void', run: A.run, at: 5, intent_id: A.intent_id }]],
    ['void of a sent handoff', [A, handoff, set(outcome, { outcome: 'sent' }), { type: 'void', run: A.run, at: 5, intent_id: A.intent_id }]],
    ['void then a handoff', [A, { type: 'void', run: A.run, at: 5, intent_id: A.intent_id }, handoff]],
    ['outcome of another hash', [A, replacement, handoff, set(outcome, { hash: replacement.hash })]],
    ['outcome after a settle', [A, handoff, { type: 'settle', run: A.run, at: 5, intent_id: A.intent_id, label: 'taken', hash: null, block: 1 }, outcome]],
    ['outcome reason too long', [A, handoff, set(outcome, { reason_class: 'x'.repeat(129) })]],
    ['replacement of an unknown intent', [replacement]],
    ['replacement at another nonce', [A, set(resign(replacement, { nonce: 9, fee: 2 }), { nonce: 9 })]],
    ['replacement of the same hash', [A, set(replacement, { hash: A.hash, raw: A.raw, fields: A.fields })]],
    ['handoff of an unknown intent', [handoff]],
    ['handoff of an uncommitted hash', [A, set(handoff, { hash: '0x' + '00'.repeat(32) })]],
    ['handoff twice', [A, handoff, handoff]],
    ['outcome without its handoff', [A, outcome]],
    ['outcome of another run', [A, handoff, set(outcome, { run: 'another-run-id' })]],
    ['outcome twice', [A, handoff, outcome, outcome]],
    ['bad outcome', [A, handoff, set(outcome, { outcome: 'lost' })]],
    ['outcome source missing', [A, handoff, drop(outcome, 'source')]],
    ['outcome for an unknown intent with a bad handoff id', [set(outcome, { handoff_id: 'x' })]],
    ['settle with a bad label', [A, { type: 'settle', run: A.run, at: 5, intent_id: A.intent_id, label: 'lost', hash: null, block: 1 }]],
    ['taken with a hash', [A, { type: 'settle', run: A.run, at: 5, intent_id: A.intent_id, label: 'taken', hash: A.hash, block: 1 }]],
    ['settle twice', [A, ...[0, 1].map(() => ({ type: 'settle', run: A.run, at: 5, intent_id: A.intent_id, label: 'paid', hash: A.hash, block: 1 }))]],
    ['void after a handoff without its outcome', [A, handoff, { type: 'void', run: A.run, at: 5, intent_id: A.intent_id }]],
    ['void of another run', [A, { type: 'void', run: 'another-run-id', at: 5, intent_id: A.intent_id }]],
    ['retire with a bad block', [A, { type: 'retire', run: A.run, at: 5, intent_id: A.intent_id, block: -2 }]],
    ['track with a bad bracket', [A, { type: 'track', run: A.run, at: 5, intent_id: A.intent_id, bracket: { number: 1 } }]],
    ['held snapshot written live', [set(A, { type: 'held' })]],
    ['tombstone with hashes', [{ type: 'tombstone', at: 1, intent_id: A.intent_id, chain_id: 1, sender: A.sender, nonce: 0, closed: 'voided', hashes: [A.hash] }]],
    ['voided tombstone with a label', [{ type: 'tombstone', at: 1, intent_id: A.intent_id, chain_id: 1, sender: A.sender, nonce: 0, closed: 'voided', label: 'paid' }]],
    ['tombstone with a bad state', [{ type: 'tombstone', at: 1, intent_id: A.intent_id, chain_id: 1, sender: A.sender, nonce: 0, closed: 'held' }]],
    ['retired tombstone without hashes', [{ type: 'tombstone', at: 1, intent_id: A.intent_id, chain_id: 1, sender: A.sender, nonce: 0, closed: 'retired', hashes: [] }]],
    ['settled tombstone without a label', [{ type: 'tombstone', at: 1, intent_id: A.intent_id, chain_id: 1, sender: A.sender, nonce: 0, closed: 'settled' }]],
    ['tombstone then a commit', [{ type: 'tombstone', at: 1, intent_id: A.intent_id, chain_id: 1, sender: A.sender, nonce: 0, closed: 'voided' }, A]],
  ];
  return cases.map(([name, records]) => ({ name, records: plain(records) }));
}

function snapshotCases(held) {
  const set = (fields) => ({ ...held, ...fields });
  return [
    ['no hashes', [set({ hashes: [] })]],
    ['a hash listed twice', [set({ hashes: [held.hashes[0], { ...held.hashes[0], via: 'replacement' }] })]],
    ['latest not its bytes', [set({ hashes: [...held.hashes].reverse() })]],
    ['bad hash entry', [set({ hashes: [{ ...held.hashes[0], via: 'replacement' }, ...held.hashes.slice(1)] })]],
    ['bad summary', [set({ handoffs: { count: 1 } })]],
    ['bad count', [set({ handoffs: { count: -1, possibly_sent: false } })]],
    ['bad unread time', [set({ unread_since: 'soon' })]],
    ['snapshot then its replacement', [held, held]],
    ['void after a possibly sent handoff', [set({ handoffs: { count: 1, possibly_sent: true } }), { type: 'void', run: held.run, at: held.at + 1, intent_id: held.intent_id }]],
  ].map(([name, records]) => ({ name, records: plain(records) }));
}

const INTENTS_FORMAT =
  'wallet-intents.jsonl, from the stores reference\'s src/main/wallet/intent-store.js over its lib/durable-journal.js, `crypto.randomUUID` numbered (RUN_ID at each load of the module, then the intent and handoff ids) and the clock fixed. `runs`: one live store per run, with its `limits` overrides, each step an operation (`op`, `args`, at `at`; `restart` loads the module again, a new run of main; `void` without a `lock` is refused) with its `refusal` (`code`, `message`) or null, the file\'s `records` after it, and `load`: a fresh store loading those records, its `reason` for moving the file aside (null: loaded), the records it rewrote the file to (`compacted`, null when unchanged), `list()`, the ids of `held()`, `byKey` of each key, `heldNonces` of each account, `voidRefusal` of each listed intent, and `usage()`. `damaged`: records the reference loads, with its `reason` (null when it loads them).';

async function buildIntents(checkout, ethers) {
  const { encodeLine } = require(path.join(checkout, 'src/main/lib/durable-journal.js'));
  const s = signer(ethers);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-intents-'));
  try {
    const runs = [];
    for (const [i, run] of runsOf().entries()) {
      const runDir = path.join(dir, `run-${i}`);
      fs.mkdirSync(runDir);
      runs.push(await runOf(checkout, ethers, runDir, encodeLine, s, run));
    }
    const lifecycle = runs[0].steps;
    const base = lifecycle[7].records;
    const held = runs[3].steps[10].records.find((r) => r.type === 'held');
    const damaged = [];
    const probeFile = path.join(dir, 'damaged', FILE);
    fs.mkdirSync(path.dirname(probeFile));
    for (const c of [...damagedCases(base, s), ...snapshotCases(held)]) {
      const { reason } = await probe(checkout, ethers, c.records, probeFile, null, encodeLine);
      damaged.push({ ...c, reason });
    }
    const mod = loadModule(checkout, ethers, { n: PROBE_UUIDS });
    return { file: FILE, limits: { ...mod.LIMITS }, line_max: { ...mod.LINE_MAX }, runs, damaged };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

module.exports = { buildIntents, INTENTS_FORMAT };
