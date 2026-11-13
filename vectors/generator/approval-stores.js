'use strict';

// Design 0012's grant files (step APR-2), from the approvals reference's own
// stores: src/main/wallet/dapp-permissions.js, swarm/swarm-permissions.js,
// radicle/radicle-permissions.js and x402/permissions.js. Each is loaded
// fresh for each run through naming.js's harness, with an in-memory `fs`
// (so every write is seen, a Swarm temp file and its rename included),
// `app.getPath('userData')` stubbed and `Date.now` fixed for each step. The
// stores' other requires are their IPC wiring, stubbed; nothing else of the
// reference is read.
//
// What the reference decides, and the generator records:
// - `runs`: each store's operations in order, from a file's text (`start`,
//   or none), with each step's `at` (the wall clock, in milliseconds), its
//   `result`, whether it wrote the file (`wrote`) and the file's text after
//   it (`text`, null while there is no file). A `reload` step drops the
//   store's cache, as a new process would, before it reads.
// - `malformed`: a file's text, and what each store loads from it: `loaded`
//   (`getAllPermissions()`, or its error) and the text after a connect of
//   another site (`afterGrant`, or its error).
//
// What the design adds: `core` on a step, where the core doesn't do the
// operation itself: `load`, an older build's write (the legacy signing flag
// and transaction rule, which the core never writes: Q9), or x402's cap
// operations, which are X402-1's (the core reads each text and writes it
// back byte for byte, and APR-2 takes only the cap file's codec); `legacy`, a
// lookup of today's rule, which the new build answers none of (Q9,
// `rule-legacy`); and on a
// malformed file, `core: unreadable` (renamed aside, the store empty:
// `file-unreadable`) or `parsed`.
//
// Every key is a permission key already (0011's `key`, which main
// normalizes): the generator asserts normalizeOrigin leaves each unchanged,
// so the core, which takes the key as main attests it, keys alike.

const assert = require('node:assert/strict');
const { loadWithInternals } = require('./naming');

const BACKSLASH = String.fromCharCode(92);
const USER_DATA = '/user-data';
const FILES = Object.freeze({
  dapp: 'dapp-permissions.json',
  swarm: 'swarm-permissions.json',
  radicle: 'radicle-permissions.json',
  x402: 'x402-permissions.json',
});
const MODULES = Object.freeze({
  dapp: 'src/main/wallet/dapp-permissions.js',
  swarm: 'src/main/swarm/swarm-permissions.js',
  radicle: 'src/main/radicle/radicle-permissions.js',
  x402: 'src/main/x402/permissions.js',
});

// Wall-clock milliseconds (2025-11-01T12:26:40Z), as `Date.now()` gives them.
const T = 1_762_000_000_000;
const SITE = 'https://app.example';
const OTHER = 'https://other.example';
const NAME = 'myapp.eth';
const DWEB = 'bzz://' + 'ab'.repeat(32);
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const ROUTER = '0x' + 'Ab'.repeat(20);
const APPROVE = '0x095ea7b3';
const TRANSFER = '0xA9059CBB';

/** An in-memory `fs`, with the calls the four stores make. */
function memoryFs() {
  const files = new Map();
  const state = { writes: 0 };
  const enoent = (file) => Object.assign(new Error(`ENOENT: no such file, open '${file}'`), { code: 'ENOENT' });
  return {
    files,
    state,
    existsSync: (file) => files.has(file),
    readFileSync: (file) => {
      if (!files.has(file)) throw enoent(file);
      return files.get(file);
    },
    writeFileSync: (file, text) => {
      state.writes += 1;
      files.set(file, String(text));
    },
    renameSync: (from, to) => {
      if (!files.has(from)) throw enoent(from);
      files.set(to, files.get(from));
      files.delete(from);
    },
  };
}

/** A fresh copy of one store's module, over `fs`. */
function loadStore(checkout, store, fs) {
  const stubs = {
    electron: { app: { getPath: () => USER_DATA }, ipcMain: { handle() {}, on() {} } },
    fs,
  };
  if (store === 'dapp') stubs['./auto-approve-pause'] = { transactionAutoApprovePaused: async () => false };
  if (store === 'radicle') stubs['../private/private-sender'] = { isPrivateSender: () => false };
  return loadWithInternals(checkout, MODULES[store], [], stubs);
}

/** `fn` with `Date.now` fixed at `at`, and the stores' logging silenced. */
function at(time, fn) {
  const realNow = Date.now;
  const { log, error } = console;
  Date.now = () => time;
  console.log = () => {};
  console.error = () => {};
  try {
    return fn();
  } finally {
    Date.now = realNow;
    console.log = log;
    console.error = error;
  }
}

const plain = (value) => (value === undefined ? null : JSON.parse(JSON.stringify(value)));

function attempt(fn) {
  try {
    return { value: plain(fn()) };
  } catch (error) {
    return { error: String(error?.message ?? error) };
  }
}

// ---------------------------------------------------------------------------
// The runs. Each step is `{ op, args, at }`, with `core: 'load'` where the
// core doesn't make the change itself.

const STEP = (op, args, time, extra = {}) => ({ op, args, at: time, ...extra });

const dappRuns = [
  {
    id: 'connect-use-revoke',
    start: null,
    steps: [
      STEP('grantPermission', [SITE, 0, 1], T),
      STEP('grantPermission', [NAME, 2, 100], T + 1),
      STEP('updateLastUsed', [SITE], T + 5),
      STEP('updateLastUsed', [SITE, 137], T + 6),
      STEP('updateWalletIndex', [NAME, 3], T + 7),
      // The same account again: written all the same, with its lastUsed.
      STEP('updateWalletIndex', [NAME, 3], T + 8),
      STEP('updateLastUsed', [OTHER], T + 9),
      STEP('updateWalletIndex', [OTHER, 1], T + 9),
      STEP('getAllPermissions', [], T + 10),
      STEP('revokePermission', [NAME], T + 11),
      STEP('revokePermission', [NAME], T + 12),
      STEP('getPermission', [NAME], T + 12),
      STEP('grantPermission', [DWEB, 4, 10], T + 13),
      // Connected again: the entry is replaced where it stands.
      STEP('grantPermission', [SITE, 5, 8453], T + 14),
      STEP('getAllPermissions', [], T + 15),
      STEP('getPermission', [SITE], T + 15),
    ],
  },
  {
    id: 'legacy-rules-and-narrowing',
    start: null,
    steps: [
      STEP('grantPermission', [SITE, 0, 1], T),
      // An older build's "Always allow": the core never writes these (Q9).
      STEP('setSigningAutoApprove', [SITE, true], T + 1, { core: 'load' }),
      STEP('addTransactionAutoApprove', [SITE, ROUTER, APPROVE + '00'.repeat(4), 1, '1000'], T + 2, { core: 'load' }),
      STEP('addTransactionAutoApprove', [SITE, USDC, TRANSFER, 8453, undefined], T + 3, { core: 'load' }),
      STEP('addTransactionAutoApprove', [SITE, ROUTER, APPROVE, 1, '0x10000'], T + 4, { core: 'load' }),
      STEP('getSigningAutoApprove', [SITE], T + 5),
      STEP('isTransactionAutoApproved', [SITE, ROUTER.toUpperCase().replace('0X', '0x'), APPROVE, 1, '65536'], T + 5),
      STEP('isTransactionAutoApproved', [SITE, ROUTER, APPROVE, 1, '65537'], T + 5),
      STEP('isTransactionAutoApproved', [SITE, USDC, TRANSFER.toLowerCase(), 8453, '0'], T + 5),
      STEP('isTransactionAutoApproved', [SITE, USDC, TRANSFER, 8453, '1'], T + 5),
      // A touch keeps the rules as they are.
      STEP('updateLastUsed', [SITE, 10], T + 6),
      // Narrowing: a rule off, matched in any case, then the signing flag.
      STEP('removeTransactionAutoApprove', [SITE, ROUTER.toLowerCase(), APPROVE.toUpperCase().replace('0X', '0x'), 1], T + 7),
      STEP('removeTransactionAutoApprove', [SITE, ROUTER, APPROVE, 1], T + 8),
      STEP('removeTransactionAutoApprove', [SITE, USDC, TRANSFER, 1], T + 9),
      STEP('setSigningAutoApprove', [SITE, false], T + 10),
      STEP('setSigningAutoApprove', [SITE, false], T + 11),
      STEP('setSigningAutoApprove', [OTHER, false], T + 12),
      STEP('removeTransactionAutoApprove', [OTHER, USDC, TRANSFER, 8453], T + 12),
      STEP('removeTransactionAutoApprove', [SITE, USDC, TRANSFER, 8453], T + 13),
      STEP('getPermission', [SITE], T + 14),
    ],
  },
  {
    id: 'forget-account',
    start: null,
    steps: [
      STEP('grantPermission', [SITE, 0, 1], T),
      STEP('grantPermission', [OTHER, 1, 1], T + 1),
      STEP('grantPermission', [NAME, 0, 100], T + 2),
      STEP('grantPermission', [DWEB, 2, 1], T + 3),
      STEP('revokePermissionsForWalletIndex', [0], T + 4),
      STEP('revokePermissionsForWalletIndex', [0], T + 5),
      STEP('revokePermissionsForWalletIndex', [2], T + 6),
      STEP('getAllPermissions', [], T + 7),
    ],
  },
  {
    // An older build's entry without `autoApprove`, a newer build's fields
    // the store doesn't know, and values a rewrite must keep as JS writes
    // them: numbers, escapes, and integer-like keys, which JS lists first.
    id: 'foreign-fields',
    start: () => foreignFile(),
    steps: [
      STEP('getAllPermissions', [], T),
      STEP('updateLastUsed', [SITE], T + 1),
      STEP('setSigningAutoApprove', [OTHER, false], T + 2),
      STEP('removeTransactionAutoApprove', [SITE, ROUTER, APPROVE, 1], T + 3),
      STEP('revokePermission', [NAME], T + 4),
      STEP('getPermission', [SITE], T + 5),
    ],
  },
  {
    // Duplicate keys: the last value wins, where the first stood.
    id: 'duplicate-keys',
    start: () => '{"' + SITE + '":{"origin":"' + SITE + '","walletIndex":0},"' + OTHER + '":{"origin":"' + OTHER + '"},"' + SITE + '":{"origin":"' + SITE + '","walletIndex":7,"lastUsed":1}}',
    steps: [
      STEP('getPermission', [SITE], T),
      STEP('updateLastUsed', [OTHER], T + 1),
    ],
  },
];

/** A dApp file with what a rewrite must keep, built here so its escapes are
 * the file's own. */
function foreignFile() {
  const u = (hex) => BACKSLASH + 'u' + hex;
  return [
    '{',
    `  "${SITE}": {"origin": "${SITE}", "connectedAt": ${T - 9}, "lastUsed": ${T - 9}, "walletIndex": 0, "chainId": 1,`,
    `    "autoApprove": {"signing": true, "transactions": [{"to": "${ROUTER}", "selector": "${APPROVE}", "chainId": 1}], "future": {"b": 1, "10": 2, "2": 3, "a": 4}},`,
    `    "numbers": [1.5, 1e21, 1E-7, 0.000001, -0, 12345678901234567890, 2.50, 100e-2, -1.25e-10, 9007199254740993],`,
    `    "text": "q${BACKSLASH}"b${BACKSLASH}${BACKSLASH}s${BACKSLASH}/${u('0001')}${u('001F')}${BACKSLASH}t${u('2028')}é${u('D83D')}${u('DE00')}${u('007f')}"},`,
    `  "${OTHER}": {"origin": "${OTHER}", "connectedAt": ${T - 8}, "lastUsed": ${T - 8}, "walletIndex": 1, "chainId": 100},`,
    `  "${NAME}": {"origin": "${NAME}", "lastUsed": ${T - 7}}`,
    '}',
  ].join('\n');
}

const swarmRuns = [
  {
    id: 'tiers',
    start: null,
    steps: [
      STEP('grantPermission', [SITE], T),
      STEP('grantPermission', [NAME], T + 1),
      STEP('setAutoApprove', [SITE, 'publish', true], T + 2),
      STEP('setAutoApprove', [SITE, 'feeds', true], T + 3),
      STEP('setAutoApprove', [SITE, 'bogus', true], T + 4),
      STEP('setAutoApprove', [OTHER, 'publish', true], T + 4),
      STEP('grantMessaging', [SITE], T + 5),
      STEP('grantMessaging', [OTHER], T + 5),
      STEP('setAutoApprove', [SITE, 'messaging', true], T + 6),
      STEP('setAutoApprove', [SITE, 'signing', true], T + 7),
      STEP('getAutoApprove', [SITE, 'feeds'], T + 8),
      STEP('getAutoApprove', [SITE, 'bogus'], T + 8),
      STEP('hasMessagingGrant', [SITE], T + 8),
      STEP('updateLastUsed', [NAME], T + 9),
      STEP('updateLastUsed', [OTHER], T + 9),
      STEP('getAllPermissions', [], T + 10),
      // Messaging revoked: the grant and its rule.
      STEP('revokeMessaging', [SITE], T + 11),
      STEP('revokeMessaging', [SITE], T + 12),
      STEP('setAutoApprove', [SITE, 'feeds', false], T + 13),
      STEP('revokePermission', [NAME], T + 14),
      STEP('revokePermission', [NAME], T + 15),
      STEP('grantPermission', [SITE], T + 16),
    ],
  },
  {
    id: 'foreign-fields',
    start: () => [
      '{',
      `  "${SITE}": {"origin": "${SITE}", "connectedAt": ${T - 9}, "lastUsed": ${T - 9}, "messaging": {"grantedAt": ${T - 9}, "scope": "x"}},`,
      `  "${NAME}": {"origin": "${NAME}", "lastUsed": ${T - 8}, "autoApprove": {"publish": true, "extra": 1}}`,
      '}',
    ].join('\n'),
    steps: [
      STEP('setAutoApprove', [SITE, 'publish', true], T),
      STEP('revokeMessaging', [SITE], T + 1),
      STEP('setAutoApprove', [NAME, 'signing', true], T + 2),
    ],
  },
];

const radicleRuns = [
  {
    id: 'tiers',
    start: null,
    steps: [
      STEP('grantPermission', [SITE], T),
      STEP('grantPermission', [DWEB], T + 1),
      // lastUsed is written at most once a minute.
      STEP('updateLastUsed', [SITE], T + 59_999),
      STEP('updateLastUsed', [SITE], T + 60_000),
      STEP('updateLastUsed', [OTHER], T + 60_000),
      STEP('grantSigning', [SITE], T + 60_001),
      STEP('grantSigning', [OTHER], T + 60_001),
      STEP('hasSigningGrant', [SITE], T + 60_002),
      STEP('setAutoApprove', [SITE, 'signing', true], T + 60_003),
      STEP('setAutoApprove', [SITE, 'node', true], T + 60_004),
      STEP('setAutoApprove', [SITE, 'bogus', true], T + 60_005),
      STEP('getAutoApprove', [SITE, 'node'], T + 60_006),
      STEP('setAutoApprove', [SITE, 'node', false], T + 60_007),
      STEP('getAllPermissions', [], T + 60_008),
      STEP('revokePermission', [SITE], T + 60_009),
      STEP('revokePermission', [SITE], T + 60_010),
    ],
  },
  {
    // An entry with no lastUsed is written at the first use; one with a
    // lastUsed in the future (a clock set back since) isn't.
    id: 'last-used',
    start: () => `{"${SITE}": {"origin": "${SITE}", "signing": true}, "${NAME}": {"origin": "${NAME}", "lastUsed": ${T + 3_600_000}}}`,
    steps: [
      STEP('updateLastUsed', [SITE], T),
      STEP('updateLastUsed', [NAME], T + 1),
      STEP('setAutoApprove', [SITE, 'signing', true], T + 2),
    ],
  },
];

// x402's caps: X402-1's operations; the core reads and writes each text.
const LOAD = { core: 'load' };
const S = Math.floor(T / 1000);
const x402Runs = [
  {
    id: 'caps',
    start: null,
    steps: [
      STEP('grant', [SITE, 8453, USDC, '10000000', 3600], T, LOAD),
      STEP('grant', [SITE, 1, USDC.toLowerCase(), '5', 60], T + 1, LOAD),
      STEP('charge', [SITE, 8453, USDC, '2500000'], T + 2, LOAD),
      STEP('charge', [SITE, 8453, USDC, '7500001'], T + 3, LOAD),
      STEP('updatePermission', [SITE, 8453, USDC, { capAmount: '20000000' }], T + 4, LOAD),
      STEP('grant', [NAME, 100, USDC, '1', 10], T + 5, LOAD),
      STEP('revoke', [SITE, 1, USDC.toLowerCase()], T + 6, LOAD),
      STEP('revokeAllForOrigin', [NAME], T + 7, LOAD),
    ],
  },
  {
    // Expired caps are dropped as the file is read, and the file loses them
    // at the next write. Expired at exactly `expiresAt`.
    id: 'compaction',
    start: () => JSON.stringify({
      [SITE]: {
        [`8453:${USDC}`]: { capAmount: '10', spentAmount: '0', createdAt: S - 100, expiresAt: S },
        [`1:${USDC}`]: { capAmount: '10', spentAmount: '3', createdAt: S - 100, expiresAt: S + 1 },
        '10:0xabc': 'not a record',
      },
      [NAME]: { [`8453:${USDC}`]: { capAmount: '1', spentAmount: '0', createdAt: S - 50, expiresAt: S - 1 } },
      [OTHER]: 'not an object',
    }, null, 2),
    steps: [
      STEP('getAllPermissions', [], T),
      STEP('grant', [OTHER, 8453, USDC, '1', 60], T + 1, LOAD),
      STEP('getAllPermissions', [], T + 1000),
      STEP('reload', [], T + 1000),
      STEP('getAllPermissions', [], T + 1000),
    ],
  },
];

// The reference's lookups of today's rules (`rule-legacy`).
const LEGACY_LOOKUPS = new Set(['getSigningAutoApprove', 'isTransactionAutoApproved']);

const RUNS = { dapp: dappRuns, swarm: swarmRuns, radicle: radicleRuns, x402: x402Runs };

/** The keys a run names, each a permission key already. */
function assertKeys(origins, runs) {
  for (const run of runs) {
    for (const step of run.steps) {
      const key = step.args[0];
      if (typeof key === 'string') assert.equal(origins.normalizeOrigin(key), key, `${run.id}: ${key}`);
    }
  }
}

function runStore(checkout, store, run) {
  const fs = memoryFs();
  const file = `${USER_DATA}/${FILES[store]}`;
  const start = typeof run.start === 'function' ? run.start() : run.start;
  if (start !== null) fs.files.set(file, start);
  let mod = loadStore(checkout, store, fs);
  const steps = run.steps.map((step) => {
    const before = fs.state.writes;
    let outcome;
    if (step.op === 'reload') {
      mod._resetCache();
      outcome = { value: null };
    } else {
      assert.equal(typeof mod[step.op], 'function', `${store}: ${step.op}`);
      outcome = at(step.at, () => attempt(() => mod[step.op](...step.args)));
    }
    const out = {
      op: step.op,
      args: plain(step.args),
      at: step.at,
      ...(outcome.error !== undefined ? { error: outcome.error } : { result: outcome.value }),
      wrote: fs.state.writes > before,
      text: fs.files.has(file) ? fs.files.get(file) : null,
    };
    if (step.core) out.core = step.core;
    // Today's rules, which the new build answers none of (Q9, `rule-legacy`).
    else if (store === 'dapp' && LEGACY_LOOKUPS.has(step.op)) out.core = 'legacy';
    return out;
  });
  // No temp file is left behind (Swarm's rename).
  assert.deepEqual([...fs.files.keys()].filter((name) => name !== file), [], `${store}/${run.id}`);
  return { id: run.id, start, steps };
}

// ---------------------------------------------------------------------------
// Malformed files: what each store loads, and what its next write leaves.

const MALFORMED = [
  { id: 'truncated', text: () => `{\n  "${SITE}": {\n    "origin": "${SITE}",\n    "connectedAt": ${T}`, core: 'unreadable' },
  { id: 'not-json', text: () => 'not json', core: 'unreadable' },
  { id: 'empty', text: () => '', core: 'unreadable' },
  { id: 'byte-order-mark', text: () => String.fromCharCode(0xfeff) + '{}', core: 'unreadable' },
  { id: 'trailing-comma', text: () => `{"${SITE}": {"origin": "${SITE}"},}`, core: 'unreadable' },
  { id: 'array', text: () => '[]', core: 'unreadable' },
  { id: 'array-of-entries', text: () => `[{"origin": "${SITE}", "walletIndex": 0}]`, core: 'unreadable' },
  { id: 'number', text: () => '42', core: 'unreadable' },
  { id: 'string', text: () => '"text"', core: 'unreadable' },
  { id: 'null', text: () => 'null', core: 'unreadable' },
  { id: 'entry-not-object', text: () => `{"${SITE}": 5}`, core: 'unreadable' },
  { id: 'entry-null', text: () => `{"${SITE}": null}`, core: 'unreadable' },
  { id: 'whitespace-around', text: () => `\n \t{"${SITE}": {"origin": "${SITE}", "lastUsed": 1}}\r\n `, core: 'parsed' },
  { id: 'empty-object', text: () => '{}', core: 'parsed' },
];

// x402 drops what isn't a live record as it reads: its entries' shapes are
// the cap codec's, read alike in the core.
const X402_PARSED = new Set(['entry-not-object', 'entry-null']);

function malformedFor(checkout, store) {
  return MALFORMED.map((c) => {
    const text = c.text();
    const load = () => {
      const fs = memoryFs();
      fs.files.set(`${USER_DATA}/${FILES[store]}`, text);
      return { fs, mod: loadStore(checkout, store, fs) };
    };
    const first = load();
    const loaded = at(T, () => attempt(() => first.mod.getAllPermissions()));
    const second = load();
    const grant = store === 'x402'
      ? () => second.mod.grant(OTHER, 8453, USDC, '1', 60)
      : store === 'dapp' ? () => second.mod.grantPermission(OTHER, 0, 1) : () => second.mod.grantPermission(OTHER);
    const granted = at(T, () => attempt(grant));
    const file = `${USER_DATA}/${FILES[store]}`;
    const afterGrant = granted.error !== undefined
      ? { error: granted.error }
      : { text: second.fs.files.has(file) ? second.fs.files.get(file) : null };
    const core = store === 'x402' && X402_PARSED.has(c.id) ? 'parsed' : c.core;
    return { id: c.id, text, loaded, afterGrant, core };
  });
}

function buildStores(checkout) {
  const origins = require(`${checkout}/src/shared/origin-utils.js`);
  const out = {};
  for (const store of Object.keys(FILES)) {
    assertKeys(origins, RUNS[store]);
    out[store] = {
      file: FILES[store],
      runs: RUNS[store].map((run) => runStore(checkout, store, run)),
      malformed: malformedFor(checkout, store),
    };
  }
  return out;
}

const STORES_FORMAT = 'Each grant store\'s file (`file`): `runs`, from a `start` text (or none), each step an operation of the reference\'s store (`op`, its `args`) at `at` (the wall clock, in milliseconds, as `Date.now()` gives it), its `result` (or `error`), whether it wrote the file (`wrote`) and the file\'s text after it (`text`, null while there is none); a `reload` drops the store\'s cache, as a new process would. `core: load` where the core makes no such change itself (an older build\'s rule, or x402\'s cap operations, which are X402-1\'s): the core reads the text the reference wrote and writes it back byte for byte. `core: legacy`: the reference\'s lookup of today\'s rule, which the new build answers none of (`rule-legacy`). `malformed`: a file\'s `text`, what the reference\'s store loads from it (`loaded`, `getAllPermissions()` or its error), the text a connect of another site then leaves (`afterGrant`, or its error), and the core\'s reading (`core`: `unreadable`, renamed aside with the store empty, or `parsed`).';

module.exports = { buildStores, STORES_FORMAT, T, SITE, OTHER, NAME, DWEB, USDC, ROUTER, APPROVE, TRANSFER, memoryFs, loadStore, at, attempt, plain };
