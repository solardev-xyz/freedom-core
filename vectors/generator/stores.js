'use strict';

// Design 0013's set-A stores (PRF-5a): `vault-meta.json`, from the stores
// reference's own src/main/identity-manager.js. The module is loaded fresh
// for each run through naming.js's harness, over approval-stores.js's
// in-memory `fs` (every write seen), with its requires stubbed: the identity
// core (`./core/vault-backend`, scripted), the Ledger, the phone, the Swarm
// feed store and the Safe modules (scripted, every call recorded), and its
// Electron, profile and node wiring (inert). `ethers` (its `isAddress`) is
// the main reference's install, and `Date` is faked with the main
// reference's @sinonjs/fake-timers at each step's `at` (`createdAt`).
// Nothing of the reference is patched.
//
// What the reference decides, and the generator records:
// - `runs`: identity-manager's operations in order, from a file's text
//   (`start`, or none), each with its `at`, `result` or `error` (`message`,
//   `code`), the calls it made (`calls`: the identity core's, the device's,
//   the phone's, the feed store's and the Safe modules', each with its
//   answer), whether it wrote the file (`wrote`) and the text after it.
// - `malformed`: a file's text (or bytes), and what the reference loads
//   from it: `getVaultMeta()`, a locked `getDerivedWallets()` and
//   `getActiveWalletIndex()`.
//
// What the design adds:
// - `core` on a step: the codec's operation and its arguments, as the core
//   is asked once main has done its part (the device's or the phone's check,
//   the Swarm feed references), or null where main refuses before the core
//   is asked (a device or phone that doesn't answer for the address).
// - on a malformed file, `core`: `unreadable` (renamed aside and reported,
//   `vault-meta-unreadable`) or `parsed`, and the rule (`reason`). The bound
//   (`MAX_FILE_BYTES`, 1 MiB) is the design's (`source: design`).

const assert = require('node:assert/strict');
const path = require('node:path');
const { createRequire } = require('node:module');
const { loadWithInternals } = require('./naming');
const { memoryFs } = require('./approval-stores');
const { buildIntents, INTENTS_FORMAT } = require('./stores-intents');
const { buildSafePending, SAFE_PENDING_FORMAT } = require('./stores-safe-pending');

const IDENTITY = '/identity';
const FILE = `${IDENTITY}/vault-meta.json`;
const MODULE = 'src/main/identity-manager.js';
const INTERNALS = ['getVaultMeta', 'getWalletList', 'nextHardwareWalletIndex', 'saveNewVaultMeta', 'afterUnlock',
  'removeWalletRecord', 'addDeviceWallet'];
const MAX_FILE_BYTES = 1024 * 1024;

// Wall-clock milliseconds (2025-11-01T12:26:40Z), as `Date.now()` gives them.
const T = 1_762_000_000_000;
const PATH0 = "44'/60'/0'/0/0";
const PATH1 = "44'/60'/1'/0/0";

const plain = (value) => (value === undefined ? null : JSON.parse(JSON.stringify(value)));
const clone = (value) => (value === undefined ? undefined : structuredClone(value));

/** The addresses the runs use, from ethers itself. */
function addressesOf(ethers) {
  const of = (byte) => ethers.getAddress('0x' + byte.repeat(20));
  const derived = (index) => ethers.getAddress('0x' + (0x1000 + index).toString(16).padStart(40, '0'));
  const a = {
    derived,
    bee: of('be'),
    ledger1: of('a1'),
    ledger2: of('a2'),
    phone1: of('b1'),
    phone2: of('b2'),
    safe1: of('c1'),
    safe2: of('c2'),
    other: of('d4'),
  };
  // A mixed-case address whose checksum is wrong: its first letter's case
  // flipped.
  const flip = a.ledger2.replace(/[a-fA-F]/, (c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()));
  a.badChecksum = flip;
  a.icap = ethers.getIcapAddress(of('e5'));
  assert.ok(!ethers.isAddress(a.badChecksum) && ethers.isAddress(a.icap), 'STOP: ethers address sanity check failed');
  return a;
}

// ---------------------------------------------------------------------------
// The module, over a scripted world.

function newWorld(over = {}) {
  return { exists: true, unlocked: true, ledger: {}, phone: true, references: {}, calls: [], ...over };
}

function loadIdentityManager(checkout, ethers, fs, world, a) {
  const record = (fn, args, outcome) => world.calls.push({ fn, args: plain(args), ...outcome });
  const answer = (fn, args, value) => {
    record(fn, args, { answer: plain(value) });
    return value;
  };
  const refuse = (fn, args, message) => {
    record(fn, args, { error: message });
    throw new Error(message);
  };
  const vaultAddresses = { user_wallet: a.derived(0), bee_wallet: a.bee };
  const vaultBackend = {
    status: async () => answer('vault.status', [], { exists: world.exists, unlocked: world.unlocked }),
    addresses: async (request) => {
      if (!world.unlocked) refuse('vault.addresses', [request], 'Vault is locked');
      return answer('vault.addresses', [request], {
        user_wallets: request.accounts.map((account) => ({ account, address: a.derived(account) })),
        publishers: [],
        bee_wallet: a.bee,
      });
    },
    createVault: async (_password, strength, options) =>
      answer('vault.create', [strength, { userKnowsPassword: options.userKnowsPassword }], { mnemonic: '(the mnemonic)', addresses: vaultAddresses }),
    importVault: async (_password, _mnemonic, options) =>
      answer('vault.import', [{ overwrite: options.overwrite, quickUnlock: options.quickUnlock }], { addresses: vaultAddresses }),
    unlock: async () => answer('vault.unlock', [], { addresses: vaultAddresses }),
  };
  const inert = () => {};
  const stubs = {
    electron: { ipcMain: { handle: inert, on: inert } },
    fs: {
      ...fs,
      mkdirSync: (dir, options) => record('fs.mkdirSync', [dir, options], {}),
    },
    './fs-offload': {},
    './profile-paths': {
      getIdentityDataDir: () => IDENTITY,
      getAntDataDir: () => '/ant',
      getIpfsDataDir: () => '/ipfs',
      getRadicleDataDir: () => '/radicle',
      prepareRadicleDataDir: async () => {},
    },
    './profile-resolver': { getActiveProfile: () => ({ id: 'default' }) },
    './windows/request-window': { forSenderWindow: (fn) => fn },
    './core/vault-backend': { vaultBackend },
    './core/node-identity-guard': { blockNode: inert, unblockNode: inert, nodeWriteStatus: () => null, restoreNodeWrite: inert },
    './radicle/radicled-gate': { withRadicleGate: (fn) => fn() },
    './radicle/radicle-backend-kind': { radicleBackendKind: () => 'service' },
    './private-files': { withPrivateDir: inert },
    './swarm/ant-keystore-password': {},
    ethers,
    './wallet/ledger/transport': {
      readAddresses: async (paths) => answer('ledger.readAddresses', [paths], paths.map((p) => world.ledger[p] ?? null)),
    },
    './wallet/remote/account-proof': {
      proveRemoteAccount: async (address, index) => {
        if (world.phone === 'throw') refuse('phone.proveRemoteAccount', [address, index], 'Request rejected on your phone.');
        return answer('phone.proveRemoteAccount', [address, index], world.phone);
      },
    },
    './swarm/feed-store': {
      getEthereumWalletIdentityReferences: (index) => answer('feeds.references', [index], world.references[index] ?? []),
    },
    './wallet/safe/safe-approvals': {
      beginDeletion: (index) => {
        record('safe.beginDeletion', [index], {});
        return { release: () => record('safe.release', [index], {}) };
      },
      endSafe: async (index) => record('safe.endSafe', [index], {}),
    },
    './wallet/safe/message-sessions': { discardSession: (index) => record('safe.discardSession', [index], {}) },
    './wallet/safe/pending-store': { clearPending: (index) => record('safe.clearPending', [index], {}) },
    './wallet/dapp-permissions': { revokePermissionsForWalletIndex: async (index) => record('dapp.revoke', [index], {}) },
  };
  return loadWithInternals(checkout, MODULE, INTERNALS, stubs);
}

/** `fn` at `at` (fake `Date`), with the module's logging silenced. */
async function at(FakeTimers, time, fn) {
  const { log, error, warn } = console;
  const clock = FakeTimers.install({ toFake: ['Date'], now: time });
  console.log = () => {};
  console.error = () => {};
  console.warn = () => {};
  try {
    return await fn();
  } finally {
    clock.uninstall();
    console.log = log;
    console.error = error;
    console.warn = warn;
  }
}

async function attempt(fn) {
  try {
    return { result: plain(await fn()) };
  } catch (error) {
    return { error: { message: String(error?.message ?? error), code: error?.code ?? null } };
  }
}

// ---------------------------------------------------------------------------
// What the core is asked for each step.

const MAIN_REFUSALS = new Set(['LEDGER_ADDRESS_MISMATCH', 'REMOTE_ADDRESS_MISMATCH', 'REMOTE_ADDRESS_UNPROVEN']);

function coreOf(step, outcome, calls) {
  const [x, y, z, w] = step.args;
  const called = (fn) => calls.find((c) => c.fn === fn);
  // A device or phone that doesn't answer for the address: main refuses,
  // and the core isn't asked.
  if (outcome.error && MAIN_REFUSALS.has(outcome.error.code)) return null;
  switch (step.op) {
    case 'createNewVault':
      return { op: 'new_vault', args: [z, step.at, called('vault.create').answer.addresses] };
    case 'importExistingMnemonic':
      return { op: 'new_vault', args: [z, step.at, called('vault.import').answer.addresses] };
    case 'saveNewVaultMeta':
      return { op: 'new_vault', args: [y, step.at, x] };
    case 'unlockVault':
      return { op: 'migrate_addresses', args: [called('vault.unlock').answer.addresses] };
    case 'getDerivedWallets':
      return { op: 'list', args: [] };
    case 'getWalletRecord':
      return { op: 'record', args: [x] };
    case 'findWalletRecordByAddress':
      return { op: 'find_by_address', args: [x] };
    case '$nextHardwareWalletIndex':
      return { op: 'next_hardware_index', args: [] };
    case 'createDerivedWallet':
      return { op: 'add_mnemonic', args: [called('vault.status').answer.unlocked, x] };
    case 'addDeviceWallet':
      return { op: 'add_device', args: [x, y, z, w ?? {}] };
    case 'addLedgerWallet':
      return { op: 'add_ledger', args: [x, y, z] };
    case 'addRemoteWallet':
      return { op: 'add_remote', args: [x, y] };
    case 'recordLedgerAddressCheck':
      return { op: 'record_address_check', args: ['ledger', x, y] };
    case 'recordRemoteAddressCheck':
      return { op: 'record_address_check', args: ['remote', x, y] };
    case 'addSafeWallet':
      return { op: 'add_safe', args: [x, y] };
    case 'markSafeDeployed':
      return { op: 'mark_safe_deployed', args: [x, y] };
    case 'getActiveWalletIndex':
      return { op: 'active_index', args: [] };
    case 'setActiveWalletIndex':
      return { op: 'set_active', args: [x] };
    case 'renameDerivedWallet':
      return { op: 'rename', args: [x, y] };
    case 'deleteDerivedWallet': {
      // The Swarm feed references are main's (feeds stay main's until
      // 0015): main passes their origins.
      const references = called('feeds.references')?.answer ?? [];
      return { op: 'remove', args: [x, references.map((reference) => reference.origin)] };
    }
    default:
      throw new Error(`STOP: no core operation for ${step.op}`);
  }
}

// ---------------------------------------------------------------------------
// The runs. Each step is `{ op, args, at }`, with `world` changing the
// scripted world (the vault's lock, the device's and the phone's answers,
// the feed references) before it.

const STEP = (op, args, time, world) => ({ op, args, at: time, ...(world ? { world } : {}) });

const metaText = (meta) => JSON.stringify(meta, null, 2);

function runsOf(a) {
  const created = { userKnowsPassword: true, createdAt: '2025-10-01T08:00:00.000Z', addresses: { userWallet: a.derived(0), beeWallet: a.bee } };
  const main = { index: 0, name: 'Main Wallet', address: a.derived(0) };
  const listed = (wallets, extra = {}) => metaText({ ...created, derivedWallets: wallets, activeWalletIndex: 0, ...extra });
  const ledger = (index, address, extra = {}) => ({ index, name: `Ledger ${index}`, address, type: 'ledger', path: PATH0, ...extra });
  const phone = (index, address, extra = {}) => ({ index, name: `Phone ${index}`, address, type: 'remote', ...extra });
  const safe = (index, address, owners, extra = {}) => ({ index, name: `Safe ${index}`, address, type: 'safe', owners, threshold: 1, saltNonce: '7', deployed: {}, ...extra });
  return [
    {
      id: 'create-then-list',
      start: null,
      steps: [
        STEP('createNewVault', ['(password)', 256, true], T),
        STEP('getDerivedWallets', [], T + 1),
        STEP('getDerivedWallets', [], T + 2),
        STEP('getDerivedWallets', [], T + 3, { unlocked: false }),
        STEP('getActiveWalletIndex', [], T + 4),
      ],
    },
    {
      id: 'import-quick-setup',
      start: null,
      steps: [
        STEP('importExistingMnemonic', ['(password)', '(mnemonic)', false], T),
        STEP('getDerivedWallets', [], T + 1, { unlocked: false }),
      ],
    },
    {
      // Over an existing file: everything but the new vault's fields goes.
      id: 'new-vault-over-existing',
      start: listed([main, ledger(1000000, a.ledger1)], { nextHardwareWalletIndex: 1000001 }),
      steps: [STEP('saveNewVaultMeta', [{ user_wallet: a.derived(0), bee_wallet: a.bee }, true], T)],
    },
    {
      id: 'unlock-migration',
      start: metaText({ userKnowsPassword: false, createdAt: '2025-01-01T00:00:00.000Z' }),
      steps: [
        STEP('unlockVault', ['(password)'], T),
        STEP('unlockVault', ['(password)'], T + 1),
      ],
    },
    {
      // A falsy `addresses` keeps its place.
      id: 'unlock-migration-null-addresses',
      start: metaText({ userKnowsPassword: true, addresses: null, createdAt: '2025-01-01T00:00:00.000Z', derivedWallets: [{ index: 0, name: 'Main Wallet', address: null }] }),
      steps: [STEP('unlockVault', ['(password)'], T), STEP('getDerivedWallets', [], T + 1, { unlocked: false })],
    },
    {
      // List's lazy init: written while listing, `activeWalletIndex` reset.
      id: 'list-lazy-init',
      start: metaText({ ...created, activeWalletIndex: 3 }),
      steps: [
        STEP('getActiveWalletIndex', [], T),
        STEP('getDerivedWallets', [], T + 1, { unlocked: false }),
        STEP('getDerivedWallets', [], T + 2),
        STEP('getActiveWalletIndex', [], T + 3),
      ],
    },
    {
      id: 'list-lazy-init-no-addresses',
      start: metaText({ userKnowsPassword: true }),
      steps: [STEP('getDerivedWallets', [], T), STEP('getWalletRecord', [0], T + 1)],
    },
    {
      id: 'mnemonic-add',
      start: listed([main]),
      steps: [
        STEP('createDerivedWallet', ['Savings'], T),
        STEP('createDerivedWallet', [''], T + 1),
        STEP('createDerivedWallet', [7], T + 2),
        STEP('createDerivedWallet', ['Locked'], T + 3, { unlocked: false }),
        STEP('getDerivedWallets', [], T + 4),
        STEP('getDerivedWallets', [], T + 5, { unlocked: true }),
      ],
    },
    {
      // A Ledger on a low index (before HARDWARE_INDEX_BASE): it counts
      // toward the next mnemonic index.
      id: 'mnemonic-add-legacy-low-ledger',
      start: listed([main, { index: 3, name: 'Old Ledger', address: a.ledger1, type: 'ledger', path: PATH0 }]),
      steps: [STEP('createDerivedWallet', ['After'], T), STEP('getDerivedWallets', [], T + 1)],
    },
    {
      // The taken-index skip: the next mnemonic index lands on a hardware
      // account's.
      id: 'mnemonic-add-taken-skip',
      start: listed([main, { index: 999999, name: 'Far', address: a.derived(999999) }, ledger(1000000, a.ledger1), phone(1000001, a.phone1, { addressCheck: 'matched' })]),
      steps: [STEP('createDerivedWallet', ['Skipped'], T), STEP('$nextHardwareWalletIndex', [], T + 1)],
    },
    {
      id: 'ledger-add',
      start: listed([main]),
      steps: [
        STEP('addLedgerWallet', ['', a.ledger1, PATH0], T, { ledger: { [PATH0]: a.ledger1, [PATH1]: a.ledger1 } }),
        // The device holds another address there: main refuses.
        STEP('addLedgerWallet', ['Mine', a.ledger2, PATH1], T + 1),
        STEP('addLedgerWallet', ['Again', a.ledger1.toLowerCase(), PATH1], T + 2),
        STEP('addLedgerWallet', ['No path', a.ledger2, ''], T + 3),
        STEP('addLedgerWallet', ['Bad', 'not an address', PATH0], T + 4),
        STEP('addLedgerWallet', ['  Padded name  ﻿', a.ledger2, PATH1], T + 5, { ledger: { [PATH1]: a.ledger2 } }),
        STEP('getDerivedWallets', [], T + 6),
      ],
    },
    {
      id: 'phone-add',
      start: listed([main]),
      steps: [
        STEP('addRemoteWallet', ['', a.phone1], T),
        STEP('addRemoteWallet', ['Other account', a.phone2], T + 1, { phone: false }),
        STEP('addRemoteWallet', ['No answer', a.phone2], T + 2, { phone: 'throw' }),
        // Refused before the phone is asked.
        STEP('addRemoteWallet', ['Duplicate', a.phone1.toLowerCase()], T + 3, { phone: true }),
        STEP('addRemoteWallet', ['  ', a.phone2], T + 4),
        STEP('addRemoteWallet', [5, a.other], T + 5),
        STEP('getDerivedWallets', [], T + 6, { unlocked: false }),
      ],
    },
    {
      id: 'device-address-forms',
      start: listed([main]),
      steps: [
        STEP('addDeviceWallet', ['remote', 'Checksummed', a.phone1, { addressCheck: 'matched' }], T),
        STEP('addDeviceWallet', ['remote', 'Lowercase', a.phone2.toLowerCase(), { addressCheck: 'matched' }], T + 1),
        STEP('addDeviceWallet', ['remote', 'No prefix', a.ledger1.slice(2), { addressCheck: 'matched' }], T + 2),
        // The same account with its prefix: a different string in lowercase.
        STEP('addDeviceWallet', ['remote', 'Prefixed', a.ledger1, { addressCheck: 'matched' }], T + 3),
        STEP('addDeviceWallet', ['remote', 'ICAP', a.icap, { addressCheck: 'matched' }], T + 4),
        STEP('addDeviceWallet', ['remote', 'Uppercase', '0x' + a.safe1.slice(2).toUpperCase(), { addressCheck: 'matched' }], T + 5),
        STEP('addDeviceWallet', ['remote', 'Bad checksum', a.badChecksum, { addressCheck: 'matched' }], T + 6),
        STEP('addDeviceWallet', ['remote', 'Capital prefix', '0X' + a.safe2.slice(2).toLowerCase(), { addressCheck: 'matched' }], T + 7),
        STEP('addDeviceWallet', ['remote', 'Short', a.safe2.slice(0, 41), { addressCheck: 'matched' }], T + 8),
        STEP('addDeviceWallet', ['remote', 'Number', 42, { addressCheck: 'matched' }], T + 9),
        STEP('addDeviceWallet', ['ledger', 'Ledger form', a.other.toLowerCase().slice(2), { path: PATH0, addressCheck: 'matched' }], T + 10),
        STEP('findWalletRecordByAddress', [a.ledger1.slice(2).toUpperCase()], T + 11),
        STEP('findWalletRecordByAddress', [a.icap.toLowerCase()], T + 12),
      ],
    },
    {
      id: 'address-checks',
      start: listed([main, ledger(1000000, a.ledger1), phone(1000001, a.phone1, { addressCheck: 'unchecked' }), phone(1000002, a.phone2, { addressCheck: 'bogus' })], { nextHardwareWalletIndex: 1000003 }),
      steps: [
        STEP('recordLedgerAddressCheck', [1000000, false], T),
        STEP('recordLedgerAddressCheck', [1000000, false], T + 1),
        STEP('recordLedgerAddressCheck', [1000000, true], T + 2),
        // Matched stays matched.
        STEP('recordLedgerAddressCheck', [1000000, false], T + 3),
        STEP('recordRemoteAddressCheck', [1000001, true], T + 4),
        STEP('recordRemoteAddressCheck', [1000002, false], T + 5),
        STEP('recordRemoteAddressCheck', [1000000, true], T + 6),
        STEP('recordLedgerAddressCheck', [5, true], T + 7),
        STEP('getDerivedWallets', [], T + 8, { unlocked: false }),
      ],
    },
    {
      id: 'safe-add',
      start: listed([
        main,
        { index: 1, name: 'Second', address: a.derived(1) },
        ledger(1000000, a.ledger1, { addressCheck: 'matched' }),
        phone(1000001, a.phone1),
        ledger(1000002, a.ledger2, { addressCheck: 'mismatched' }),
        phone(1000003, a.phone2, { addressCheck: 'mismatched' }),
        ledger(1000004, a.other),
      ], { nextHardwareWalletIndex: 1000005 }),
      steps: [
        STEP('addSafeWallet', ['', { address: a.safe1, owners: [0, 1], threshold: 1, saltNonce: '0' }], T),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1], threshold: 2, saltNonce: '1' }], T + 1),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1, 1000000], threshold: 1, saltNonce: '1' }], T + 2),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: '0,1', threshold: 1, saltNonce: '1' }], T + 3),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 0], threshold: 1, saltNonce: '1' }], T + 4),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 42], threshold: 1, saltNonce: '1' }], T + 5),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1000005], threshold: 1, saltNonce: '1' }], T + 6),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1000001], threshold: 1, saltNonce: '1' }], T + 7),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1000002], threshold: 1, saltNonce: '1' }], T + 8),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1000003], threshold: 1, saltNonce: '1' }], T + 9),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1000004], threshold: 1, saltNonce: '1' }], T + 10),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1], threshold: 1, saltNonce: '0x1' }], T + 11),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1], threshold: 1, saltNonce: 5 }], T + 12),
        STEP('addSafeWallet', ['x', { address: a.safe2, owners: [0, 1], threshold: 1, saltNonce: '' }], T + 13),
        STEP('addSafeWallet', ['Dup', { address: a.safe1.toLowerCase(), owners: [0, 1], threshold: 1, saltNonce: '2' }], T + 14),
        STEP('addSafeWallet', ['Bad', { address: 'nope', owners: [0, 1], threshold: 1, saltNonce: '2' }], T + 15),
        STEP('addSafeWallet', ['Team', { address: a.safe2, owners: [1000000, 0, 1], threshold: 2, saltNonce: '115792089237316195423570985008687907853269984665640564039457584007913129639935' }], T + 16),
        STEP('getWalletRecord', [1000006], T + 17),
        STEP('getDerivedWallets', [], T + 18, { unlocked: false }),
      ],
    },
    {
      id: 'safe-deployed',
      start: listed([
        main,
        safe(1000000, a.safe1, [0, 1000002], { deployed: { 1: true, 10: { verified: true }, 137: { verified: false } } }),
        safe(1000001, a.safe2, [0, 1000002], { deployed: undefined }),
        ledger(1000002, a.ledger1, { addressCheck: 'matched' }),
      ], { nextHardwareWalletIndex: 1000003 }),
      steps: [
        STEP('getWalletRecord', [1000000], T),
        STEP('markSafeDeployed', [1000000, 1], T + 1),
        STEP('markSafeDeployed', [1000000, 100], T + 2),
        STEP('markSafeDeployed', [1000000, 100], T + 3),
        STEP('markSafeDeployed', [1000000, 11155111], T + 4),
        STEP('markSafeDeployed', [1000001, 8453], T + 5),
        STEP('markSafeDeployed', [0, 1], T + 6),
        STEP('markSafeDeployed', [999, 1], T + 7),
        STEP('getWalletRecord', [1000000], T + 8),
        STEP('getDerivedWallets', [], T + 9, { unlocked: false }),
      ],
    },
    {
      id: 'set-active',
      start: listed([main, { index: 1, name: 'Second', address: a.derived(1) }]),
      steps: [
        STEP('setActiveWalletIndex', [1], T),
        STEP('getActiveWalletIndex', [], T + 1),
        STEP('setActiveWalletIndex', [7], T + 2),
        STEP('setActiveWalletIndex', [1], T + 3),
      ],
    },
    {
      // No wallet list yet: the default one answers, and only the index is
      // written.
      id: 'set-active-default-list',
      start: metaText(created),
      steps: [STEP('setActiveWalletIndex', [1], T), STEP('setActiveWalletIndex', [0], T + 1)],
    },
    {
      id: 'rename',
      start: listed([main, { index: 1, name: 'Second', address: a.derived(1) }, { index: 2, address: a.derived(2) }]),
      steps: [
        STEP('renameDerivedWallet', [1, 'Renamed'], T),
        STEP('renameDerivedWallet', [1, ''], T + 1),
        STEP('renameDerivedWallet', [1, 42], T + 2),
        STEP('renameDerivedWallet', [1, { label: 'object' }], T + 3),
        STEP('renameDerivedWallet', [2, 'Named now'], T + 4),
        STEP('renameDerivedWallet', [9, 'Missing'], T + 5),
        STEP('getDerivedWallets', [], T + 6, { unlocked: false }),
      ],
    },
    {
      id: 'rename-default-list',
      start: metaText(created),
      steps: [STEP('renameDerivedWallet', [0, 'Primary'], T)],
    },
    {
      id: 'remove',
      start: listed([
        main,
        { index: 1, name: 'One', address: a.derived(1) },
        { index: 2, name: 'Active', address: a.derived(2) },
        { index: 3, name: 'Publisher', address: a.derived(3) },
        ledger(1000000, a.ledger1, { addressCheck: 'matched' }),
        safe(1000001, a.safe1, [0, 1000000], { name: 'Vault Safe' }),
      ], { activeWalletIndex: 2, nextHardwareWalletIndex: 1000002 }),
      steps: [
        STEP('deleteDerivedWallet', [0], T, {
          references: {
            3: ['https://a.example', 'https://b.example', 'https://c.example', 'https://d.example'].map((origin) => ({ origin, identityId: 'id-3', active: true, feedNames: [], feedCount: 0 })),
            1: [{ origin: 'https://one.example', identityId: 'id-1', active: false, feedNames: ['blog'], feedCount: 1 }],
          },
        }),
        STEP('deleteDerivedWallet', [77], T + 1),
        STEP('deleteDerivedWallet', [3], T + 2),
        STEP('deleteDerivedWallet', [1], T + 3),
        STEP('deleteDerivedWallet', [1000000], T + 4),
        STEP('deleteDerivedWallet', [2], T + 5),
        STEP('getActiveWalletIndex', [], T + 6),
        STEP('deleteDerivedWallet', [1000001], T + 7),
        STEP('deleteDerivedWallet', [1000000], T + 8),
        STEP('setActiveWalletIndex', [3], T + 9),
        STEP('deleteDerivedWallet', [3], T + 10, { references: {} }),
        STEP('getActiveWalletIndex', [], T + 11),
        STEP('$nextHardwareWalletIndex', [], T + 12),
      ],
    },
    {
      // A record that is no wallet list's yet (the default list): removing
      // another index finds none.
      id: 'remove-default-list',
      start: metaText(created),
      steps: [STEP('deleteDerivedWallet', [1], T)],
    },
    {
      // The counter behind the list's high-water mark.
      id: 'hardware-counter-stale',
      start: listed([main, ledger(1000005, a.ledger1, { addressCheck: 'matched' })], { nextHardwareWalletIndex: 1000000 }),
      steps: [
        STEP('$nextHardwareWalletIndex', [], T),
        STEP('addRemoteWallet', ['', a.phone1], T + 1),
        STEP('$nextHardwareWalletIndex', [], T + 2),
      ],
    },
    {
      // The counter past the high-water mark (a deleted device's index is
      // never given again).
      id: 'hardware-counter-ahead',
      start: listed([main, ledger(1000002, a.ledger1, { addressCheck: 'matched' })], { nextHardwareWalletIndex: 1000010 }),
      steps: [
        STEP('$nextHardwareWalletIndex', [], T),
        STEP('addRemoteWallet', ['', a.phone1], T + 1),
      ],
    },
    {
      id: 'hardware-counter-not-integer',
      start: listed([main], { nextHardwareWalletIndex: 1000003.5 }),
      steps: [STEP('$nextHardwareWalletIndex', [], T), STEP('addRemoteWallet', ['', a.phone1], T + 1)],
    },
    {
      id: 'hardware-counter-string',
      start: listed([main], { nextHardwareWalletIndex: '1000009' }),
      steps: [STEP('$nextHardwareWalletIndex', [], T), STEP('addRemoteWallet', ['', a.phone1], T + 1)],
    },
    {
      id: 'records',
      start: metaText({
        ...created,
        derivedWallets: [
          { index: 0, name: 'Main Wallet', address: null },
          { index: 1, name: 'Stored', address: a.derived(1), type: '' },
          ledger(1000000, a.ledger1, { addressCheck: 'matched' }),
          phone(1000001, a.phone1, { addressCheck: 'mismatched', path: '' }),
          safe(1000002, a.safe1, [0, 1000000], { deployed: { 5: true, 1: { verified: true } } }),
          { index: 1000003, name: 'Odd type', address: a.safe2, type: 'watch', path: 'm/0' },
        ],
        activeWalletIndex: 1,
      }),
      steps: [
        STEP('getWalletRecord', [0], T),
        STEP('getWalletRecord', [1], T + 1),
        STEP('getWalletRecord', [1000000], T + 2),
        STEP('getWalletRecord', [1000001], T + 3),
        STEP('getWalletRecord', [1000002], T + 4),
        STEP('getWalletRecord', [1000003], T + 5),
        STEP('getWalletRecord', [5], T + 6),
        STEP('findWalletRecordByAddress', [a.ledger1.toLowerCase()], T + 7),
        STEP('findWalletRecordByAddress', [a.derived(1).toUpperCase()], T + 8),
        STEP('findWalletRecordByAddress', [a.derived(0)], T + 9),
        STEP('findWalletRecordByAddress', [''], T + 10),
        STEP('findWalletRecordByAddress', [42], T + 11),
        STEP('getDerivedWallets', [], T + 12),
        STEP('getDerivedWallets', [], T + 13, { unlocked: false }),
        STEP('getActiveWalletIndex', [], T + 14),
      ],
    },
    {
      id: 'no-vault',
      start: null,
      steps: [
        STEP('getDerivedWallets', [], T),
        STEP('getActiveWalletIndex', [], T + 1),
        STEP('getWalletRecord', [0], T + 2),
        STEP('findWalletRecordByAddress', [a.ledger1], T + 3),
        STEP('setActiveWalletIndex', [0], T + 4),
        STEP('renameDerivedWallet', [0, 'x'], T + 5),
        STEP('markSafeDeployed', [1000000, 1], T + 6),
        STEP('recordLedgerAddressCheck', [1000000, true], T + 7),
        STEP('addRemoteWallet', ['', a.phone1], T + 8),
        STEP('addRemoteWallet', ['', 'bad'], T + 9),
        STEP('addLedgerWallet', ['', a.ledger1, PATH0], T + 10, { ledger: { [PATH0]: a.ledger1 } }),
        STEP('addSafeWallet', ['', { address: a.safe1, owners: [0, 1], threshold: 1, saltNonce: '0' }], T + 11),
        STEP('createDerivedWallet', ['x'], T + 12),
        STEP('createDerivedWallet', ['x'], T + 13, { unlocked: false }),
        STEP('deleteDerivedWallet', [0], T + 14),
        STEP('deleteDerivedWallet', [1], T + 15),
        STEP('unlockVault', ['(password)'], T + 16, { unlocked: true }),
      ],
    },
  ];
}

async function runOf(checkout, ethers, FakeTimers, a, run) {
  const fs = memoryFs();
  if (run.start !== null) fs.files.set(FILE, run.start);
  const world = newWorld();
  const mod = loadIdentityManager(checkout, ethers, fs, world, a);
  const internals = mod.__internals;
  const steps = [];
  for (const step of run.steps) {
    if (step.world) Object.assign(world, clone(step.world));
    world.calls = [];
    const before = fs.state.writes;
    const args = clone(step.args);
    const outcome = await at(FakeTimers, step.at, () => attempt(() => {
      if (step.op === '$nextHardwareWalletIndex') {
        const meta = internals.getVaultMeta();
        return internals.nextHardwareWalletIndex(meta, internals.getWalletList(meta));
      }
      const fn = Object.hasOwn(mod, step.op) ? mod[step.op] : internals[step.op];
      assert.equal(typeof fn, 'function', `${run.id}: ${step.op}`);
      return fn(...args);
    }));
    const calls = world.calls;
    steps.push({
      op: step.op,
      args: plain(step.args),
      at: step.at,
      ...(step.world ? { world: plain(step.world) } : {}),
      calls,
      ...outcome,
      wrote: fs.state.writes > before,
      text: fs.files.has(FILE) ? fs.files.get(FILE) : null,
      core: coreOf(step, outcome, calls),
    });
  }
  // Nothing but vault-meta.json is written.
  assert.deepEqual([...fs.files.keys()].filter((name) => name !== FILE), [], run.id);
  return { id: run.id, start: run.start, steps };
}

// ---------------------------------------------------------------------------
// Malformed files: what the reference loads from each, and the core's
// reading of it (the design's).

const BACKSLASH = String.fromCharCode(92);
const fill = (open, close, bytes) => ({ open, char: 'x', close, bytes });
const filled = (spec) => spec.open + spec.char.repeat(spec.bytes - spec.open.length - spec.close.length) + spec.close;

function malformedCases(a) {
  const wallets = `"derivedWallets": [{"index": 0, "name": "Main Wallet", "address": "${a.derived(0)}"}]`;
  return [
    { id: 'not-json', text: 'not json', core: 'unreadable', reason: 'not_json' },
    { id: 'empty', text: '', core: 'unreadable', reason: 'not_json' },
    { id: 'truncated', text: `{\n  "userKnowsPassword": true,\n  "derivedWallets": [`, core: 'unreadable', reason: 'not_json' },
    { id: 'byte-order-mark', text: String.fromCharCode(0xfeff) + '{}', core: 'unreadable', reason: 'not_json' },
    { id: 'null', text: 'null', core: 'unreadable', reason: 'not_object' },
    { id: 'array', text: '[]', core: 'unreadable', reason: 'not_object' },
    { id: 'string', text: '"x"', core: 'unreadable', reason: 'not_object' },
    { id: 'number', text: '42', core: 'unreadable', reason: 'not_object' },
    { id: 'empty-object', text: '{}', core: 'parsed' },
    { id: 'whitespace-around', text: `\n\t {${wallets}}\r\n `, core: 'parsed' },
    {
      id: 'invalid-utf8',
      bytes: Buffer.concat([
        Buffer.from('{"userKnowsPassword": true, "derivedWallets": [{"index": 0, "name": "'),
        Buffer.from([0xff, 0x61, 0xed, 0xa0, 0x80, 0xc3, 0x28, 0xf0, 0x9f, 0x98]),
        Buffer.from('", "address": null}]}'),
      ]),
      core: 'parsed',
    },
    { id: 'lone-surrogate', text: `{"derivedWallets": [{"index": 0, "name": "a${BACKSLASH}ud800b", "address": null}]}`, core: 'parsed' },
    // Nested past the core's parser (fc-json's MAX_DEPTH, 512); V8 reads it.
    { id: 'deep-nesting', text: '{"deep": ' + '['.repeat(600) + ']'.repeat(600) + '}', core: 'unreadable', reason: 'not_json' },
    { id: 'at-the-bound', fill: fill('{"pad": "', '"}', MAX_FILE_BYTES), core: 'parsed' },
    { id: 'over-the-bound', fill: fill('{"pad": "', '"}', MAX_FILE_BYTES + 1), core: 'unreadable', reason: 'too_large' },
    // The first key's place, the last key's value.
    { id: 'duplicate-keys', text: `{"activeWalletIndex": 1, ${wallets}, "userKnowsPassword": true, "activeWalletIndex": 0, "derivedWallets": [{"index": 0, "name": "Second"}, {"index": 4, "name": "Four"}]}`, core: 'parsed' },
    { id: 'proto-key', text: `{"__proto__": {"derivedWallets": [{"index": 9}]}, "userKnowsPassword": true, ${wallets}}`, core: 'parsed' },
    { id: 'proto-key-only', text: '{"__proto__": {"derivedWallets": [{"index": 9}], "activeWalletIndex": 9}}', core: 'parsed' },
    { id: 'number-overflow', text: `{"createdAt": 1e400, "nextHardwareWalletIndex": -1e400, ${wallets}}`, core: 'parsed' },
    { id: 'integer-keys', text: `{"b": 1, "10": 2, "2": 3, ${wallets}, "-1": 4, "01": 5}`, core: 'parsed' },
    // A falsy wallet list is no list: list's lazy init writes the default.
    { id: 'wallets-null', text: '{"derivedWallets": null, "activeWalletIndex": 0}', core: 'parsed' },
    { id: 'wallets-false', text: '{"derivedWallets": false}', core: 'parsed' },
    { id: 'wallets-empty', text: '{"derivedWallets": []}', core: 'parsed' },
    { id: 'wallets-object', text: '{"derivedWallets": {"0": {"index": 0, "name": "Main Wallet"}}}', core: 'unreadable', reason: 'wallets_not_array' },
    { id: 'wallets-string', text: '{"derivedWallets": "Main Wallet"}', core: 'unreadable', reason: 'wallets_not_array' },
    { id: 'wallets-true', text: '{"derivedWallets": true}', core: 'unreadable', reason: 'wallets_not_array' },
    { id: 'record-null', text: '{"derivedWallets": [null]}', core: 'unreadable', reason: 'record_not_object' },
    { id: 'record-number', text: '{"derivedWallets": [{"index": 0, "name": "Main Wallet"}, 3]}', core: 'unreadable', reason: 'record_not_object' },
    { id: 'record-array', text: '{"derivedWallets": [[0, "Main Wallet"]]}', core: 'unreadable', reason: 'record_not_object' },
    { id: 'string-index', text: '{"derivedWallets": [{"index": "0", "name": "Main Wallet"}]}', core: 'unreadable', reason: 'index_not_integer' },
    { id: 'missing-index', text: '{"derivedWallets": [{"name": "Main Wallet"}]}', core: 'unreadable', reason: 'index_not_integer' },
    { id: 'fractional-index', text: '{"derivedWallets": [{"index": 0.5, "name": "Half"}]}', core: 'unreadable', reason: 'index_not_integer' },
    { id: 'infinite-index', text: '{"derivedWallets": [{"index": 1e400, "name": "Far"}]}', core: 'unreadable', reason: 'index_not_integer' },
    { id: 'negative-index', text: '{"derivedWallets": [{"index": 0, "name": "Main Wallet"}, {"index": -3, "name": "Below"}]}', core: 'parsed' },
    { id: 'active-string', text: `{${wallets}, "activeWalletIndex": "0"}`, core: 'unreadable', reason: 'active_not_integer' },
    { id: 'active-fraction', text: `{${wallets}, "activeWalletIndex": 0.5}`, core: 'unreadable', reason: 'active_not_integer' },
    { id: 'active-null', text: `{${wallets}, "activeWalletIndex": null}`, core: 'parsed' },
    { id: 'safe-owners-string', text: '{"derivedWallets": [{"index": 0, "name": "Main Wallet"}, {"index": 1000000, "name": "S", "type": "safe", "owners": "0"}]}', core: 'unreadable', reason: 'owners_not_array' },
    { id: 'safe-owners-missing', text: '{"derivedWallets": [{"index": 0, "name": "Main Wallet"}, {"index": 1000000, "name": "S", "type": "safe"}]}', core: 'parsed' },
    { id: 'addresses-string', text: '{"addresses": "0xabc", "userKnowsPassword": true}', core: 'parsed' },
  ];
}

async function malformedOf(checkout, ethers, FakeTimers, a, c) {
  const contents = c.bytes ?? (c.fill ? filled(c.fill) : c.text);
  const fresh = () => {
    const fs = memoryFs();
    fs.files.set(FILE, contents);
    const world = newWorld({ unlocked: false });
    return { fs, mod: loadIdentityManager(checkout, ethers, fs, world, a) };
  };
  const first = fresh();
  const meta = await at(FakeTimers, T, () => attempt(() => first.mod.__internals.getVaultMeta()));
  assert.equal(meta.error, undefined, c.id);
  const second = fresh();
  const listed = await at(FakeTimers, T, () => attempt(() => second.mod.getDerivedWallets()));
  const listWrote = second.fs.state.writes > 0;
  const third = fresh();
  const active = await at(FakeTimers, T, () => attempt(() => third.mod.getActiveWalletIndex()));
  assert.equal(active.error, undefined, c.id);
  // What the core reads as a meta, the reference lists and writes as it.
  if (c.core === 'parsed') assert.equal(listed.error, undefined, `STOP: the reference fails on ${c.id}, which the core parses`);
  // Large texts by their recipe, and what was loaded by its keys.
  const value = await at(FakeTimers, T, () => third.mod.__internals.getVaultMeta());
  const source = c.bytes ? { hex: contents.toString('hex') } : c.fill ? { fill: c.fill } : { text: contents };
  const loaded = c.fill
    ? { keys: Object.keys(value), padLength: value.pad.length }
    : { json: JSON.stringify(value) };
  return {
    id: c.id,
    ...source,
    loaded,
    listed: { ...listed, wrote: listWrote },
    active: active.result,
    core: c.core,
    ...(c.reason ? { reason: c.reason } : {}),
  };
}

const VAULT_META_FORMAT = 'identity/vault-meta.json, from the stores reference\'s identity-manager.js. `runs`: from a `start` text (or none), each step one of its functions (`op`, its `args`; `$nextHardwareWalletIndex` is `nextHardwareWalletIndex(meta, getWalletList(meta))` over the file) at `at` (the wall clock in milliseconds; `createdAt` is `new Date().toISOString()` at it), after `world` changed the scripted world (`unlocked`: the vault\'s lock; `ledger`: the address the device answers at each path; `phone`: the phone\'s proof, `throw` for no answer; `references`: the Swarm feed references of each wallet index), with its `result` (or `error`: `message` and `code`), the `calls` it made (`vault.*` the identity core\'s, `ledger.*`, `phone.*`, `feeds.*`, `safe.*` and `dapp.*` main\'s modules\', each with its `answer` or `error`), whether it wrote the file (`wrote`) and the file\'s text after it (`text`, null while there is none). `core`: what the core is asked for the step once main has done its part (`op`, `args`: `new_vault` [userKnowsPassword, at, addresses], `migrate_addresses` [addresses], `add_mnemonic` [unlocked, name] with the address from the step\'s `vault.addresses` call, `list` with the addresses from its `vault.addresses` call, `remove` [index, the feed references\' origins], and the others the function\'s own arguments), or null where main refuses before asking it (the device or the phone doesn\'t answer for the address). `malformed`: a file\'s `text` (or its bytes in `hex`, which Node decodes as UTF-8 with U+FFFD for each invalid sequence, or a `fill`: `open`, `char` repeated, `close`, `bytes` long), what the reference loads from it (`loaded`: `getVaultMeta()` as its `JSON.stringify` text in `json`, or a filled file\'s keys and `pad` length), a locked `getDerivedWallets()` (`listed`: its `result` or `error`, and whether it wrote), `getActiveWalletIndex()` (`active`), and the core\'s reading (`core`: `unreadable`, renamed aside and reported, with its `reason`, or `parsed`; the design\'s, `source: design`, with the 1 MiB bound).';

async function buildStores(checkout, mainCheckout, meta) {
  const mainRequire = createRequire(path.join(mainCheckout, 'package.json'));
  const ethers = mainRequire('ethers');
  assert.equal(ethers.version, '6.17.0', 'STOP: the main reference installs another ethers');
  const FakeTimers = mainRequire('@sinonjs/fake-timers');
  const a = addressesOf(ethers);
  const runs = [];
  for (const run of runsOf(a)) runs.push(await runOf(checkout, ethers, FakeTimers, a, run));
  const malformed = [];
  for (const c of malformedCases(a)) malformed.push(await malformedOf(checkout, ethers, FakeTimers, a, c));
  const intents = await buildIntents(checkout, ethers);
  const safePending = buildSafePending(checkout);
  return {
    meta,
    description: 'Design 0013 (PRF-5a): the set-A stores the core takes over, each from the stores reference\'s own module, run whole over an in-memory file system, with the core\'s operation for each step and its reading of each malformed file.',
    formats: { vault_meta: VAULT_META_FORMAT, intents: INTENTS_FORMAT, safe_pending: SAFE_PENDING_FORMAT },
    source: { max_file_bytes: 'design' },
    max_file_bytes: MAX_FILE_BYTES,
    vault_meta: { file: 'identity/vault-meta.json', runs, malformed },
    intents,
    safe_pending: safePending,
  };
}

module.exports = { buildStores };
