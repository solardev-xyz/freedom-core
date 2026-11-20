'use strict';

// Design 0013's payment history (PRF-5g-2): the stores reference's own
// src/main/payment-history.js, loaded whole and unpatched over the main
// reference's better-sqlite3, run through a list of operations on one fresh
// database, and through each legacy x402-receipts.json import on its own.
// After each step the table is read back as SQLite holds it: every column's
// `typeof()` and value (an INTEGER as its exact decimal text, a REAL as the
// double better-sqlite3 reads, TEXT as is), so the vectors show how the
// reference's driver binds each JS value (a number binds as a double: a
// whole one lands as INTEGER in an INTEGER column and as `21000.0` text in a
// TEXT one; a non-integer `chainId` stays REAL). `Date.now` is the step's
// `now`. A step's result is the function's answer, or the error it threw
// (its class and message); its `rows` are there only when the step changed
// the table.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadWithInternals } = require('./naming');

const SILENT_LOG = { info() {}, warn() {}, error() {}, debug() {} };
const COLUMNS = ['id', 'kind', 'chain_id', 'tx_hash', 'from_address', 'to_address', 'asset', 'amount', 'origin', 'url',
  'status', 'created_at', 'confirmed_at', 'gas_used', 'gas_price', 'metadata'];
const LEGACY = 'x402-receipts.json';

function load(checkout, Database, directory) {
  const inert = () => {};
  return loadWithInternals(checkout, 'src/main/payment-history.js', ['setDroppedSeenAt', 'getStatements'], {
    electron: {
      app: { getPath: (name) => { assert.equal(name, 'userData'); return directory; } },
      ipcMain: { handle: inert, on: inert, removeHandler: inert },
    },
    'better-sqlite3': Database,
    './logger': SILENT_LOG,
    './freedom-root': { getFreedomDataPath: (name) => path.join(directory, name) },
    './lib/broadcast-to-all-webcontents': { broadcastToAllWebContents: inert },
  });
}

/** Every row, in id order, each column `[typeof, value]`. */
function rowsOf(db) {
  const select = COLUMNS.map((c) => `typeof(${c}) AS "t_${c}", CASE typeof(${c}) WHEN 'integer' THEN CAST(${c} AS TEXT) ELSE ${c} END AS "v_${c}"`);
  return db.prepare(`SELECT ${select.join(', ')} FROM payments ORDER BY id`).all()
    .map((row) => Object.fromEntries(COLUMNS.map((c) => [c, [row[`t_${c}`], row[`v_${c}`]]])));
}

function withClock(now, fn) {
  const real = Date.now;
  Date.now = () => now;
  try {
    return { ok: fn() ?? null };
  } catch (err) {
    return { error: { name: err.constructor.name, message: err.message } };
  } finally {
    Date.now = real;
  }
}

function inDirectory(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-payments-'));
  try {
    return fn(directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

const T = 1_700_000_000_000;
const WALLET = '0x00000000000000000000000000000000000000aa';
const PAYEE = '0x00000000000000000000000000000000000000bb';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const HASH = (n) => `0x${String(n).padStart(64, '0')}`;

// [op, args, now]: `append(entry)`, `update(id, patch)`, `markConfirmed(id,
// receipt)`, `markFailed(id, info)`, `markDropped(id)`, `setDroppedSeen(id,
// seenAt)` (the repoll's write, on the row of that id), `pending()` (the
// repoll's read: raw rows), `getRecent(filters)`, `getCount(filters)`,
// `getById(id)` and `clear()`. An argument absent from `args` is undefined.
const OPERATIONS = [
  ['append', [{ kind: 'x402', chainId: 8453, amount: '1000', asset: USDC, origin: 'https://a.example', url: 'https://a.example/p' }], T],
  ['append', [{ kind: 'wallet-send', chainId: 1, amount: '25', txHash: HASH(1), fromAddress: WALLET, toAddress: PAYEE, createdAt: T + 5,
    metadata: { txFrom: WALLET, txNonce: 7, b: 1, 2: true, 10: null, nested: { z: 1, a: [1.5, 'é', 1e21] } } }], T + 10],
  ['append', [{ kind: 'dapp-send', chainId: 1.5, amount: '0', createdAt: 1.25, gasUsed: 21000, gasPrice: 1.5, origin: 'https://d.example' }], T + 20],
  ['append', [{ kind: 'safe-send', chainId: 100, amount: '9', status: 'confirmed', metadata: 'text' }], T + 30],
  ['append', [{ kind: 'safe-deploy', chainId: 100, amount: '0', status: 0, metadata: 0, txHash: [HASH(5)] }], T + 40],
  ['append', [{ kind: 'wallet-send', chainId: 10, amount: '3', status: 7, metadata: true, url: 12 }], T + 50],
  ['append', [{ kind: 'x402', chainId: -0, amount: '00', status: 'pending', createdAt: 1e300, metadata: [7, 'x'] }], T + 60],
  ['append', [{ kind: 'dapp-send', chainId: 2 ** 60, amount: '1', createdAt: 2 ** 53 + 1, metadata: { a: ' ' } }], T + 70],
  ['append', [{ kind: 'nope', chainId: 1, amount: '1' }], T],
  ['append', [{ kind: { a: 1 }, chainId: 1, amount: '1' }], T],
  ['append', [{ kind: ['x402'], chainId: 1, amount: '1' }], T],
  ['append', [{ kind: { toString: 1 }, chainId: 1, amount: '1' }], T],
  ['append', [{ chainId: 1, amount: '1' }], T],
  ['append', [{ kind: 'x402', chainId: '1', amount: '1' }], T],
  ['append', [{ kind: 'x402', amount: '1' }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1.0' }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: 5 }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '' }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1\n' }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '١' }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', txHash: true }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', txHash: {} }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', txHash: { k: 'v' } }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', txHash: ['a', 'b'] }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', txHash: [[1]] }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', txHash: [] }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', txHash: {}, origin: {} }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', status: [] }], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', status: true, txHash: [] }], T],
  ['append', [], T],
  ['append', [null], T],
  ['update', [2, { status: 'confirmed', gasUsed: '21000', gasPrice: '1000000000' }], T + 100],
  ['update', [2, {}], T + 110],
  ['update', [999, { status: 'failed' }], T + 120],
  ['update', ['3', { txHash: HASH(3), confirmedAt: 5, metadata: { k: 1 } }], T + 130],
  ['update', [3.5, { status: 'failed' }], T + 140],
  ['update', [3, { status: 'unverified', confirmedAt: '77', gasUsed: 0 }], T + 150],
  ['update', [3, { status: 'settled', confirmedAt: null, metadata: [] }], T + 160],
  ['update', [3, { status: 'pending', txHash: '' }], T + 170],
  ['update', [3], T + 175],
  ['update', [3, null], T + 176],
  ['update', [{}, {}], T + 177],
  ['update', [[5], { gasPrice: 'x' }], T + 180],
  ['update', [5, { gasPrice: true }], T + 190],
  ['markConfirmed', [3, { gasUsed: '1', effectiveGasPrice: '2', confirmedAt: 123 }], T + 200],
  ['markConfirmed', [6], T + 210],
  ['markConfirmed', [6, null], T + 211],
  ['markFailed', [6, { reason: 'reverted', gasUsed: '3' }], T + 220],
  ['markFailed', [4], T + 230],
  ['markFailed', [4, null], T + 231],
  ['markFailed', [4, 'reason'], T + 232],
  ['markFailed', [999, { reason: 'x' }], T + 240],
  ['append', [{ kind: 'wallet-send', chainId: 1, amount: '1', txHash: HASH(9), metadata: { txFrom: WALLET, failureReason: 'old', z: 2 } }], T + 300],
  ['append', [{ kind: 'wallet-send', chainId: 1, amount: '2', metadata: 'ab😀' }], T + 310],
  ['append', [{ kind: 'wallet-send', chainId: 1, amount: '3', metadata: [7, { q: 1 }] }], T + 320],
  ['append', [{ kind: 'wallet-send', chainId: 1, amount: '4', metadata: 42 }], T + 330],
  ['append', [{ kind: 'wallet-send', chainId: 1, amount: '5' }], T + 340],
  ['setDroppedSeen', [9, T + 400], T + 400],
  ['setDroppedSeen', [13, T + 410], T + 410],
  ['setDroppedSeen', [9, null], T + 420],
  ['setDroppedSeen', [1, T + 430], T + 430],
  ['setDroppedSeen', [999, T + 440], T + 440],
  ['setDroppedSeen', [12, null], T + 450],
  ['pending', [], T + 500],
  ['markDropped', [9], T + 510],
  ['markDropped', [10], T + 520],
  ['markDropped', [11], T + 530],
  ['markDropped', [12], T + 540],
  ['markDropped', [13], T + 550],
  ['markDropped', [1], T + 560],
  ['markDropped', [999], T + 570],
  ['markDropped', ['13'], T + 580],
  ['getRecent', [], T],
  ['getRecent', [{ kind: 'x402' }], T],
  ['getRecent', [{ chainId: 1.5 }], T],
  ['getRecent', [{ chainId: null }], T],
  ['getRecent', [{ chainId: '1', status: 'dropped' }], T],
  ['getRecent', [{ limit: '2', offset: 1 }], T],
  ['getRecent', [{ limit: 1e10 }], T],
  ['getRecent', [{ limit: -5 }], T],
  ['getRecent', [{ limit: ' 0x3 ' }], T],
  ['getRecent', [{ limit: [2], offset: '1e0' }], T],
  ['getRecent', [{ limit: {} }], T],
  ['getRecent', [{ limit: 3.9, offset: 2 ** 32 + 1 }], T],
  ['getRecent', [{ limit: null, offset: true }], T],
  ['getRecent', [{ limit: 'Infinity', offset: -1e10 }], T],
  ['getRecent', [{ limit: { toString: 'x' } }], T],
  ['getRecent', [{ kind: '', origin: 0, status: false }], T],
  ['getRecent', [{ origin: 'https://d.example', extra: 1 }], T],
  ['getRecent', [null], T],
  ['getRecent', ['kind'], T],
  ['getRecent', [{ kind: true }], T],
  ['getRecent', [{ status: ['pending'] }], T],
  ['getRecent', [{ status: { a: 1 } }], T],
  ['getCount', [], T],
  ['getCount', [{ kind: 'wallet-send', chainId: 1 }], T],
  ['getCount', [{ limit: 1 }], T],
  ['getCount', [null], T],
  ['getById', [1], T],
  ['getById', ['2'], T],
  ['getById', [999], T],
  ['getById', [null], T],
  ['clear', [], T + 600],
  ['clear', [], T + 610],
  ['getCount', [], T],
  ['append', [{ kind: 'x402', chainId: 1, amount: '1', createdAt: 'soon', status: 'settled' }], T + 700],
  ['getRecent', [{ limit: 1 }], T + 710],
];

function runOperation(reference, [op, args, now]) {
  const call = () => {
    switch (op) {
      case 'setDroppedSeen': return reference.__internals.setDroppedSeenAt({ id: args[0] }, args[1]);
      case 'pending': return reference.__internals.getStatements().getPending.all().map((row) => ({ ...row }));
      default: return reference[op](...args);
    }
  };
  return withClock(now, call);
}

function operations(checkout, Database) {
  return inDirectory((directory) => {
    const reference = load(checkout, Database, directory);
    try {
      const db = reference.getDb();
      let before = JSON.stringify(rowsOf(db));
      return OPERATIONS.map((step) => {
        const [op, args, now] = step;
        const result = runOperation(reference, step);
        const rows = rowsOf(db);
        const after = JSON.stringify(rows);
        const changed = after !== before;
        before = after;
        return changed ? { op, args, now, result, rows } : { op, args, now, result };
      });
    } finally {
      reference.closeDb();
    }
  });
}

// x402-receipts.json at the profile's userData root, imported by the
// reference's first getDb(). `before` appends rows first (on a database
// opened and closed before the file is written); `migrated` puts a
// `.migrated` file beside it. Each case records the rows and the files after.
const RECEIPT = { id: 'r1', settledAt: 1_699_000_000, status: 'settled', chainId: 8453, txHash: HASH(21), asset: USDC,
  amount: '500', origin: 'https://x.example', url: 'https://x.example/a' };
const IMPORTS = [
  { name: 'entries', now: T, text: JSON.stringify([
    RECEIPT,
    { ...RECEIPT },
    { ...RECEIPT, id: 'r2' },
    { settledAt: 1_699_000_001.5, chainId: 1, amount: '7' },
    { status: 'pending', chainId: '1', amount: 7, txHash: 5, url: 'https://x.example/b' },
    { status: 'pending', chainId: '1', amount: 7, txHash: 5, url: 'https://x.example/b' },
    { id: '', settledAt: 1, status: 'failed', chainId: 1.5, txHash: HASH(22), amount: '1' },
    { id: 7, settledAt: 2, chainId: [1, 2], url: { a: 1 }, amount: '2' },
    'string entry',
    42,
    { id: 'e\ud800', amount: '3', settledAt: 3 },
  ]) },
  { name: 'not an array', now: T, text: JSON.stringify({ entries: [RECEIPT] }) },
  { name: 'empty', now: T, text: '[]' },
  { name: 'unparseable', now: T, text: '[{"id": "r1",' },
  { name: 'byte order mark', now: T, text: `﻿${JSON.stringify([RECEIPT])}` },
  { name: 'a null entry', now: T, text: JSON.stringify([RECEIPT, null]) },
  { name: 'an unprintable chainId', now: T, text: JSON.stringify([RECEIPT, { chainId: { toString: 1 }, amount: '1' }]) },
  { name: 'already migrated', now: T, text: JSON.stringify([RECEIPT]), migrated: true },
  { name: 'rows before', now: T, text: JSON.stringify([RECEIPT, { ...RECEIPT, id: 'r3', settledAt: 1_699_000_100 }, { ...RECEIPT, id: 'r4', amount: '501' }]),
    before: [{ kind: 'x402', chainId: 8453, amount: '500', txHash: HASH(21), asset: USDC, origin: 'https://x.example', url: 'https://x.example/a',
      status: 'settled', createdAt: 1_699_000_100_000 }, { kind: 'wallet-send', chainId: 1, amount: '501', metadata: { legacyId: 'r4' } }] },
];

function runImport(checkout, Database, { name, now, text, migrated, before }) {
  return inDirectory((directory) => {
    if (before) {
      const first = load(checkout, Database, directory);
      try {
        for (const entry of before) withClock(now, () => first.append(entry));
      } finally {
        first.closeDb();
      }
    }
    fs.writeFileSync(path.join(directory, LEGACY), text);
    if (migrated) fs.writeFileSync(path.join(directory, LEGACY + '.migrated'), '[]');
    const reference = load(checkout, Database, directory);
    try {
      const result = withClock(now, () => { reference.getDb(); });
      return {
        name, now, text, migrated: Boolean(migrated), before: before ?? [], result,
        rows: rowsOf(reference.getDb()),
        files: fs.readdirSync(directory).filter((file) => !file.startsWith('payment-history.sqlite')).sort(),
      };
    } finally {
      reference.closeDb();
    }
  });
}

function buildPayments(checkout, Database) {
  return {
    columns: COLUMNS,
    operations: operations(checkout, Database),
    imports: IMPORTS.map((item) => runImport(checkout, Database, item)),
  };
}

module.exports = { buildPayments, load };
