'use strict';

// The cases of vectors/ledger.json (design 0016, "Vectors"): their requests,
// records and scripted devices, and the deviation each is marked with. A
// deviation is the design's (its Deviations table). A case marks here only
// what its stream can't show (the reference's answer to a signature or an
// address, the app's name, a chain ID's width); the marks its APDU stream
// shows are found by the grammar's check (ledger-grammar-file.js), which
// requires the recorded stream to differ from the honest one only as those
// deviations describe the reference. Inputs that must have a property (a
// parity, a piece-size branch) are found by search over the input alone.

const assert = require('node:assert/strict');
const { TYPED_DATA } = require('./signing');
const grammar = require('./ledger-grammar');

const ADDRESS = '0x8ba1f109551bD432803012645Ac136ddd64DBA72';
const LIVE0 = "44'/60'/0'/0/0";
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const PAY_TO = '0x209693bc6afc0c5328ba36faf03c514ef312287c';
// x402's clock (ms) and nonce, as approvals.json's x402 section fixes them.
const X402_NOW_MS = 1_762_000_000_000;
const X402_NONCE = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff)).toString('hex');

const CHAINS = [['1', '1'], ['100', '100'], ['137', '137'], ['2-32-minus-1', (2n ** 32n - 1n).toString()],
  ['2-32', (2n ** 32n).toString()], ['2-53', (2n ** 53n).toString()], ['2-64', (2n ** 64n).toString()]];
// errors.js's status table (STATUS_TO_CODE), and one status outside it.
const STATUSES = [0x5515, 0x6982, 0x6985, 0x5501, 0x6a80, 0x6511, 0x6d00, 0x6e00, 0x6e01, 0x6f00];
const SIGNATURE_FAULTS = ['other-key', 'other-digest', 'high-s', 'flip-v', 'long', 'short'];

const bytesOf = (n, seed = 3) => Buffer.from(Array.from({ length: n }, (_, i) => (i * 7 + seed) & 0xff));
const hex = (b) => '0x' + Buffer.from(b).toString('hex');

function baseTx(type, chainId, extra = {}) {
  const tx = { type, chain_id: chainId, nonce: '0', gas_limit: '21000', to: ADDRESS, value: '1000000000000000', data: '0x' };
  if (type === 0) tx.gas_price = '1000000000';
  else Object.assign(tx, { max_fee_per_gas: '2000000000', max_priority_fee_per_gas: '1000000000' });
  return { ...tx, ...extra };
}

/** The unsigned serialization of a wire-form transaction, by the reference's ethers. */
function unsignedOf(ethers, toEthersTx, tx) {
  return ethers.Transaction.from(toEthersTx(tx)).unsignedSerialized;
}

/** The first nonce whose signature by `key` has `parity`. */
function nonceForParity(ethers, toEthersTx, key, tx, parity) {
  for (let nonce = 0; nonce < 64; nonce++) {
    const t = { ...tx, nonce: String(nonce) };
    if (key.sign(ethers.keccak256(unsignedOf(ethers, toEthersTx, t))).yParity === parity) return t;
  }
  throw new Error('no nonce for that parity');
}

/** The first data length whose legacy `P ‖ T` meets `want(length, vrs)`. */
function legacyWithPayload(ethers, toEthersTx, chainId, want) {
  for (let n = 200; n < 1200; n++) {
    const tx = baseTx(0, chainId, { data: hex(Buffer.alloc(n, 0xab)), gas_limit: '100000' });
    const t = Buffer.from(unsignedOf(ethers, toEthersTx, tx).slice(2), 'hex');
    const vrs = Buffer.from(ethers.getBytes(ethers.encodeRlp(ethers.decodeRlp(t).slice(-3)))).length - 1;
    const length = 21 + t.length;
    if (want(length, vrs)) return tx;
  }
  throw new Error('no data length meets the branch');
}

const inVrs = (r, vrs) => r >= 1 && r <= vrs;

const mail = () => TYPED_DATA.find((c) => c.id === 'mail').typed_data;

// A typed-data case whose stream holds every kind of APDU: names, fields,
// roots, an array, a value in two pieces.
const STEPS_TYPED = {
  domain: { name: 'Steps', chainId: 1 },
  types: { M: [{ name: 'items', type: 'uint8[]' }, { name: 'text', type: 'string' }] },
  message: { items: [1, 2], text: 's'.repeat(300) },
};

/**
 * Whether 0002's case fits a Ledger: ethers signs it, 0002 marks no
 * deviation, the design's encoder carries it, and the device, which
 * rebuilds each type from its descriptor, hashes the same encodeType.
 */
function fit(ethers, c) {
  if (c.deviation || c.proto || c.id.startsWith('error-')) return { fits: false, why: 'ethers or the core refuses it (signing.json)' };
  try {
    grammar.typedDataStream(ethers, LIVE0, c.typed_data);
  } catch (err) {
    return { fits: false, why: err instanceof grammar.Refused ? `refused (${err.deviation}): ${err.message}` : err.message };
  }
  const { payload } = grammar.typedPayload(ethers, c.typed_data);
  const rebuilt = {};
  for (const [name, fields] of Object.entries(payload.types)) {
    if (name === 'EIP712Domain') continue;
    rebuilt[name] = fields.map(({ name: n, type }) => {
      const t = grammar.parseType(type, payload.types);
      const base = { int: `int${8 * t.size}`, uint: `uint${8 * t.size}`, bytesN: `bytes${t.size}` }[t.kind] ?? t.base;
      return { name: n, type: base + t.dims.map((d) => `[${d ?? ''}]`).join('') };
    });
  }
  const types = { ...payload.types };
  delete types.EIP712Domain;
  const ours = ethers.TypedDataEncoder.from(rebuilt).encodeType(payload.primaryType);
  const theirs = ethers.TypedDataEncoder.from(types).encodeType(payload.primaryType);
  if (ours !== theirs) return { fits: false, why: `the device rebuilds ${ours}, the hash has ${theirs}` };
  return { fits: true };
}

function typedCase(ethers, id, family, typedData, record, extra = {}) {
  const { hash } = grammar.typedPayload(ethers, typedData);
  return { id, family, operation: 'sign.typed_data', record, request: { typed_data: typedData, expected_hash: hash }, digest: hash, ...extra };
}

/** The cases that need no earlier run. */
function baseCases(env, toEthersTx) {
  const { ethers } = env;
  const key0 = new ethers.SigningKey(env.account(0).privateKey);
  const record = { path: LIVE0, address: env.account(0).address };
  const legacyAddress = (i) => ethers.HDNodeWallet.fromPhrase(env.mnemonic, '', `m/44'/60'/0'/${i}`).address;
  const legacyRecord = { path: "44'/60'/0'/3", address: legacyAddress(3) };
  const cases = [];
  const add = (c) => cases.push(c);

  // Discovery, both schemes (ipc.js's ledger:get-accounts).
  for (const [scheme, start, count, extra] of [['live', 0, 5], ['legacy', 0, 5], ['live', 0, 1], ['live', 0, 2], ['live', 0, 20],
    ['legacy', 0, 20], ['live', 2147483643, 5], ['legacy', 2147483647, 1], ['live', 2147483647, 2]]) {
    add({ id: `discovery-${scheme}-${start}-${count}`, family: 'discovery', operation: 'ledger.accounts', request: { scheme, start, count } });
  }

  // Adding an account (identity-manager.js's addLedgerWallet, #1065).
  add({ id: 'add-live-0', family: 'add', operation: 'ledger.add', request: { name: 'Ledger 1', address: env.account(0).address, path: LIVE0 } });
  add({ id: 'add-legacy-3', family: 'add', operation: 'ledger.add', request: { name: '', address: legacyRecord.address, path: legacyRecord.path } });
  add({ id: 'add-other-address', family: 'add', operation: 'ledger.add', request: { name: 'Planted', address: env.account(1).address, path: LIVE0 } });
  add({ id: 'add-path-outside-schemes', family: 'add', operation: 'ledger.add',
    request: { name: 'Off', address: ethers.HDNodeWallet.fromPhrase(env.mnemonic, '', "m/44'/60'/0'/0/1").address, path: "44'/60'/0'/0/1" } });

  // Transactions: both types at each chain ID, both parities; at 2^53 and
  // above, chain-id-width (hw-app-eth's ethers v5 parse overflows).
  for (const type of [0, 2]) {
    for (const [label, chainId] of CHAINS) {
      for (const parity of [0, 1]) {
        const tx = nonceForParity(ethers, toEthersTx, key0, baseTx(type, chainId), parity);
        const wide = BigInt(chainId) >= 2n ** 53n;
        add({ id: `tx-type${type}-chain-${label}-parity-${parity}`, family: 'transaction', operation: 'sign.transaction', record, request: { tx },
          ...(wide ? { deviation: 'chain-id-width' } : {}) });
      }
    }
  }
  // safeChunkTransaction's branches: one piece; a type 2 in pieces of 255;
  // a legacy one whose last piece would be 0, above the v, r, s list, or in
  // it (a smaller size, found at 254 or below).
  const pieces = [
    ['type2-three', baseTx(2, '1', { data: hex(Buffer.alloc(600, 0xcd)), gas_limit: '100000' })],
    ['legacy-exact', legacyWithPayload(ethers, toEthersTx, '1', (n) => n > 255 && n % 255 === 0)],
    ['legacy-above-vrs', legacyWithPayload(ethers, toEthersTx, '1', (n, vrs) => n > 255 && n % 255 > vrs)],
    ['legacy-shrink-254', legacyWithPayload(ethers, toEthersTx, '1', (n, vrs) => n > 255 && inVrs(n % 255, vrs) && !inVrs(n % 254, vrs))],
    ['legacy-shrink-below-254', legacyWithPayload(ethers, toEthersTx, '1', (n, vrs) => n > 255 && inVrs(n % 255, vrs) && inVrs(n % 254, vrs))],
    ['legacy-wide-vrs', legacyWithPayload(ethers, toEthersTx, (2n ** 32n - 1n).toString(), (n, vrs) => n > 255 && n % 255 > 3 && inVrs(n % 255, vrs))],
  ];
  for (const [label, tx] of pieces) add({ id: `tx-pieces-${label}`, family: 'transaction-pieces', operation: 'sign.transaction', record, request: { tx } });
  add({ id: 'tx-steps', family: 'transaction-pieces', operation: 'sign.transaction', record, request: { tx: baseTx(2, '1', { data: hex(bytesOf(300)), gas_limit: '90000' }) } });
  add({ id: 'tx-legacy-path', family: 'transaction', operation: 'sign.transaction', record: legacyRecord, request: { tx: baseTx(2, '100') } });

  // Messages: 1 byte; the first APDU's edge for both path lengths (145 − 4n)
  // and one past it; 150 more and one past that; F-5's empty one.
  for (const [scheme, rec, edge] of [['live', record, 125], ['legacy', legacyRecord, 129]]) {
    for (const n of [1, edge, edge + 1, edge + 150, edge + 151]) {
      add({ id: `msg-${scheme}-${n}`, family: 'message', operation: 'sign.message', record: rec, request: { message: hex(bytesOf(n)) } });
    }
  }
  add({ id: 'msg-steps', family: 'message', operation: 'sign.message', record, request: { message: hex(bytesOf(200, 5)) } });
  add({ id: 'msg-empty', family: 'message', operation: 'sign.message', record, request: { message: '0x' } });

  // 0002's EIP-712 cases that fit a Ledger; the others are listed with why.
  const excluded = [];
  for (const c of TYPED_DATA) {
    const verdict = fit(ethers, c);
    if (!verdict.fits) {
      if (!c.deviation && !c.proto && !c.id.startsWith('error-')) excluded.push({ id: c.id, why: verdict.why });
      continue;
    }
    add(typedCase(ethers, `typed-${c.id}`, 'typed-data', c.typed_data, record));
  }
  add(typedCase(ethers, 'typed-steps', 'typed-data', STEPS_TYPED, record));
  add(typedCase(ethers, 'typed-legacy-path', 'typed-data', mail(), legacyRecord));
  // Q23's fallback: a Nano S answers 6D00 to the first E0 1A.
  add(typedCase(ethers, 'typed-hash-only-mail', 'hash-only', mail(), record, { device: { fields: false } }));
  add(typedCase(ethers, 'typed-hash-only-safe-tx', 'hash-only', TYPED_DATA.find((c) => c.id === 'safe-tx').typed_data, record, { device: { fields: false } }));

  // F-2's value lengths: encodings (2-byte length ‖ value) of 255 to 513 bytes.
  for (const n of [255, 256, 257, 510, 511, 512, 513]) {
    add(typedCase(ethers, `value-string-encoding-${n}`, 'value-length',
      { domain: { name: 'L' }, types: { M: [{ name: 'v', type: 'string' }] }, message: { v: 'v'.repeat(n - 2) } }, record));
  }
  add(typedCase(ethers, 'value-bytes-encoding-256', 'value-length',
    { domain: { name: 'L' }, types: { M: [{ name: 'v', type: 'bytes' }] }, message: { v: hex(bytesOf(254)) } }, record));
  // F-2's array counts.
  for (const [label, type, n] of [['dynamic-255', 'uint8[]', 255], ['dynamic-256', 'uint8[]', 256], ['dynamic-300', 'uint8[]', 300],
    ['fixed-255', 'uint8[255]', 255], ['fixed-256', 'uint8[256]', 256]]) {
    add(typedCase(ethers, `array-${label}`, 'array-length',
      { domain: { name: 'A' }, types: { M: [{ name: 'v', type }] }, message: { v: Array.from({ length: n }, (_, i) => i & 0xff) } }, record));
  }

  // Names. A definition APDU carries at most 255 bytes: a field's
  // descriptor is its type byte, a size or a custom type's name, and its
  // name with their length bytes. ASCII names at each edge; names holding
  // é (2 bytes in UTF-8, 1 UTF-16 unit) and 😀 (4 bytes, 2 units), whose
  // length byte the reference writes in UTF-16 units (name-ascii).
  const one = (fieldName, type = 'string') => ({ domain: { name: 'N' }, types: { M: [{ name: fieldName, type }] }, message: { [fieldName]: type === 'string' ? 'x' : 1 } });
  const primary = (typeName) => ({ domain: { name: 'N' }, types: { [typeName]: [{ name: 'v', type: 'uint8' }] }, message: { v: 1 } });
  const referenced = (typeName) => ({ domain: { name: 'N' }, types: { M: [{ name: 'v', type: typeName }], [typeName]: [{ name: 'w', type: 'uint8' }] }, message: { v: { w: 1 } } });
  const named = (id, td) => add(typedCase(ethers, id, 'name-length', td, record));
  for (const n of [253, 254, 255, 256]) named(`name-field-ascii-${n}`, one('f'.repeat(n)));
  for (const n of [252, 253]) named(`name-field-ascii-uint8-${n}`, one('f'.repeat(n), 'uint8'));
  for (const n of [254, 255, 256]) named(`name-primary-type-ascii-${n}`, primary('P'.repeat(n)));
  for (const n of [251, 252, 254, 255, 256]) named(`name-type-ascii-${n}`, referenced('T'.repeat(n)));
  const withChar = (char, bytes, lead) => lead + 'a'.repeat(bytes - Buffer.byteLength(lead + char)) + char;
  for (const [label, char] of [['e-acute', 'é'], ['emoji', '\u{1f600}']]) {
    named(`name-field-${label}-short`, one(char));
    for (const n of [252, 253, 254, 255, 256]) named(`name-field-${label}-${n}`, one(withChar(char, n, 'f')));
    named(`name-type-${label}-short`, referenced('T' + char));
    for (const n of [251, 252, 254, 255, 256]) named(`name-type-${label}-${n}`, referenced(withChar(char, n, 'T')));
  }

  // x402, the three forms @x402/evm 2.29.0 builds, under a fixed clock and nonce.
  const v2 = { scheme: 'exact', network: 'eip155:8453', amount: '10000', asset: USDC, payTo: PAY_TO, maxTimeoutSeconds: 60, extra: { name: 'USD Coin', version: '2' } };
  for (const [label, version, requirements] of [
    ['eip3009-v2', 2, v2],
    ['eip3009-v1', 1, { scheme: 'exact', network: 'base', maxAmountRequired: '10000', resource: 'https://paid.example/a', description: '', mimeType: '', payTo: PAY_TO, maxTimeoutSeconds: 60, asset: USDC, extra: { name: 'USD Coin', version: '2' } }],
    ['permit2-v2', 2, { ...v2, extra: { ...v2.extra, assetTransferMethod: 'permit2' } }],
  ]) {
    add({ id: `x402-${label}`, family: 'x402', operation: 'sign.typed_data', record, x402: { version, requirements, now_ms: X402_NOW_MS, nonce: X402_NONCE } });
  }

  // The answers: a signature the core refuses, or one it reads otherwise.
  const answerBases = [
    ['tx-type0', 'sign.transaction', { tx: nonceForParity(ethers, toEthersTx, key0, baseTx(0, '1'), 0) }],
    ['tx-type2', 'sign.transaction', { tx: nonceForParity(ethers, toEthersTx, key0, baseTx(2, '1'), 0) }],
    ['msg', 'sign.message', { message: hex(Buffer.from('Freedom')) }],
  ];
  // Whether each is signature-check is the reference's answer's to say (ledger.js, markSignatureFault).
  for (const [label, operation, request] of answerBases) {
    for (const kind of [...SIGNATURE_FAULTS, ...(label === 'tx-type0' ? ['v-27'] : [])]) {
      add({ id: `answer-${label}-${kind}`, family: 'answer', operation, record, request, device: { answerFault: { at: 'signature', kind } } });
    }
  }
  for (const kind of SIGNATURE_FAULTS) {
    add(typedCase(ethers, `answer-typed-${kind}`, 'answer', mail(), record, { device: { answerFault: { at: 'signature', kind } } }));
    add(typedCase(ethers, `answer-hash-only-${kind}`, 'answer', mail(), record, { device: { fields: false, answerFault: { at: 'signature', kind } } }));
  }
  // The address check's answer: another seed at the path, or the path's
  // address text beside another key.
  add({ id: 'answer-msg-other-address', family: 'answer', operation: 'sign.message', record, request: { message: hex(Buffer.from('Freedom')) }, device: { answerFault: { at: 0, kind: 'other-address' } } });
  add({ id: 'answer-msg-key-not-address', family: 'answer', operation: 'sign.message', record, request: { message: hex(Buffer.from('Freedom')) }, device: { answerFault: { at: 0, kind: 'key-not-address' } }, deviation: 'key-check' });
  add(typedCase(ethers, 'answer-typed-key-not-address', 'answer', mail(), record, { device: { answerFault: { at: 0, kind: 'key-not-address' } }, deviation: 'key-check' }));
  add({ id: 'answer-discovery-key-not-address', family: 'answer', operation: 'ledger.accounts', request: { scheme: 'live', start: 0, count: 1 }, device: { answerFault: { at: 0, kind: 'key-not-address' } }, deviation: 'key-check' });
  add({ id: 'answer-add-key-not-address', family: 'answer', operation: 'ledger.add', request: { name: 'Ledger 1', address: env.account(0).address, path: LIVE0 }, device: { answerFault: { at: 0, kind: 'key-not-address' } }, deviation: 'key-check' });
  add({ id: 'answer-add-other-address', family: 'answer', operation: 'ledger.add', request: { name: 'Ledger 1', address: env.account(0).address, path: LIVE0 }, device: { answerFault: { at: 0, kind: 'other-address' } } });

  // The app: another app that answers as the Ethereum app does; an older version.
  const polygon = { app: { name: 'Polygon', version: '1.13.0' } };
  add({ id: 'app-other-name-tx', family: 'app', operation: 'sign.transaction', record, request: { tx: baseTx(2, '137') }, device: polygon, deviation: 'app-check' });
  add({ id: 'app-other-name-msg', family: 'app', operation: 'sign.message', record, request: { message: hex(Buffer.from('Freedom')) }, device: polygon, deviation: 'app-check' });
  add(typedCase(ethers, 'app-other-name-typed', 'app', mail(), record, { device: polygon, deviation: 'app-check' }));
  add(typedCase(ethers, 'app-version-1.9.0-typed', 'app', mail(), record, { device: { app: { name: 'Ethereum', version: '1.9.0' } } }));

  // Opening the device: no Ledger attached (the transport's own NoDevice
  // error), and one node-hid can't open.
  for (const open of ['no-device', 'cannot-open']) {
    add({ id: `open-${open}-discovery`, family: 'open', operation: 'ledger.accounts', request: { scheme: 'live', start: 0, count: 1 }, device: { open } });
    add({ id: `open-${open}-msg`, family: 'open', operation: 'sign.message', record, request: { message: hex(Buffer.from('Freedom')) }, device: { open } });
  }
  return { cases, excluded };
}

// The steps a status or a disconnect is scripted at: each kind of APDU of
// these cases, at its first place in the recorded stream.
const STEP_BASES = {
  'discovery-live-0-2': [['address-0', (h, i) => i === 0], ['address-1', (h, i) => i === 1]],
  'add-live-0': [['address', (h) => h === 'e0020000']],
  'tx-steps': [['address', (h) => h === 'e0020000'], ['piece-first', (h) => h === 'e0040000'], ['piece-last', (h) => h === 'e0048000']],
  'msg-steps': [['address', (h) => h === 'e0020000'], ['piece-first', (h) => h === 'e0080000'], ['piece-last', (h) => h === 'e0088000']],
  'typed-steps': [['address', (h) => h === 'e0020000'], ['app', (h) => h === 'b0010000'], ['type-name', (h) => h === 'e01a0000'],
    ['type-field', (h) => h === 'e01a00ff'], ['root', (h) => h === 'e01c0000'], ['array', (h) => h === 'e01c000f'],
    ['value', (h) => h === 'e01c00ff'], ['value-piece', (h) => h === 'e01c01ff'], ['sign', (h) => h === 'e00c0001']],
  'typed-hash-only-mail': [['hash-only', (h) => h === 'e00c0000']],
};

/** Statuses and disconnects at each step of the step bases, from their recorded streams. */
function stepCases(bases) {
  const out = [];
  for (const [baseId, steps] of Object.entries(STEP_BASES)) {
    const base = bases.get(baseId);
    assert.ok(base, `no base case ${baseId}`);
    const headers = base.exchanges.map((e) => e.apdu.slice(0, 8));
    for (const [step, match] of steps) {
      const at = headers.findIndex((h, i) => match(h, i));
      assert.ok(at >= 0, `${baseId} has no ${step}`);
      const inherit = (fault) => {
        const device = { ...(base.device || {}), fault };
        const c = { ...base, device };
        delete c.exchanges; delete c.transport; delete c.result; delete c.events;
        return c;
      };
      for (const status of STATUSES) {
        const c = inherit({ at, status });
        c.id = `status-${baseId}-${step}-${status.toString(16).padStart(4, '0')}`;
        c.family = 'status';
        c.fault_step = step;
        out.push(c);
      }
      const c = inherit({ at, disconnect: true });
      c.id = `disconnect-${baseId}-${step}`;
      c.family = 'disconnect';
      c.fault_step = step;
      out.push(c);
    }
  }
  return out;
}

module.exports = { baseCases, stepCases, STATUSES, LIVE0, X402_NOW_MS, X402_NONCE, STEP_BASES };
