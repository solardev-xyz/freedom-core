'use strict';

// Design 0013's downgrade runs (PRF-5c-2b): the stores reference's own
// src/main/identity-manager.js over a real freedom-cored, the previous core
// release in the runs, on files a newer core left. freedom-cored's
// tests/quick_unlock.rs (`the_downgrade_after_the_commit`) runs it.
//
// The reference's core-client.js starts the core (`serve` on the profile's
// identity and lock directories, the hello main sends), its vault-backend.js
// talks to it, and identity-manager.js runs over that, with only the wiring
// identity-manager.js needs from Electron, the profile and the nodes stubbed
// inert, as stores.js stubs it, and its logging silenced. The real `fs`:
// every read and write is the reference's on the profile's files. Nothing of
// the reference is patched.
//
// Usage: node downgrade-actor.js '<json>', the JSON being
//   { stores, cored, data, locks, grantRoot, steps: [{ op, ...args }] }
// with `stores` the stores reference's checkout. Each step is one of the
// reference's functions:
//   hasVault, unlocked (isVaultUnlocked), meta (getVaultMeta), wallets
//   (getDerivedWallets), active (getActiveWalletIndex), addresses
//   (deriveAddresses, `accounts`), unlock (unlockVault, `password`), lock
//   (lockVault), createAccount (createDerivedWallet, `name`), rename
//   (renameDerivedWallet, `index`, `name`), createVault (createNewVault,
//   `password`, 12 words, the user knowing it).
// Prints one JSON line: { core_version, steps: [{ op, result } | { op,
// error: { message, code } }] }.

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { loadWithInternals } = require('./naming');

const SILENT = { info() {}, warn() {}, error() {}, debug() {}, log() {} };

function loadReference(stores, data, core) {
  const { vaultBackend } = loadWithInternals(stores, 'src/main/core/vault-backend.js', [], {
    '../logger': SILENT,
    './core-process': { getCoreClient: () => core },
  });
  const inert = () => {};
  return loadWithInternals(stores, 'src/main/identity-manager.js', ['getVaultMeta'], {
    electron: { ipcMain: { handle: inert, on: inert } },
    './fs-offload': {},
    './profile-paths': {
      getIdentityDataDir: () => data,
      getAntDataDir: () => path.join(data, 'ant-unused'),
      getIpfsDataDir: () => path.join(data, 'ipfs-unused'),
      getRadicleDataDir: () => path.join(data, 'radicle-unused'),
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
  });
}

async function step(identity, { op, ...args }) {
  switch (op) {
    case 'hasVault': return identity.hasVault();
    case 'unlocked': return identity.isVaultUnlocked();
    case 'meta': return identity.__internals.getVaultMeta();
    case 'wallets': return identity.getDerivedWallets();
    case 'active': return identity.getActiveWalletIndex();
    case 'addresses': return identity.deriveAddresses({ accounts: args.accounts });
    case 'unlock': return identity.unlockVault(args.password);
    case 'lock': return identity.lockVault();
    case 'createAccount': return identity.createDerivedWallet(args.name);
    case 'rename': return identity.renameDerivedWallet(args.index, args.name);
    case 'createVault': return identity.createNewVault(args.password, 128, true);
    default: throw new Error(`unknown step ${op}`);
  }
}

async function main() {
  const { stores, cored, data, locks, grantRoot, steps } = JSON.parse(process.argv[2]);
  const { CoreClient } = require(path.join(stores, 'src/main/core/core-client.js'));
  fs.mkdirSync(grantRoot, { recursive: true });
  const core = new CoreClient({
    spawn,
    command: cored,
    args: ['serve', '--data-dir', data, '--lock-dir', locks],
    log: SILENT,
    shellVersion: 'downgrade-actor',
    grantRoot,
  });
  const quiet = { log: console.log, error: console.error, warn: console.warn };
  console.log = () => {};
  console.error = () => {};
  console.warn = () => {};
  const out = { core_version: null, steps: [] };
  try {
    const hello = await core.start();
    out.core_version = hello?.core_version ?? core.hello?.core_version ?? null;
    const identity = loadReference(stores, data, core);
    for (const s of steps) {
      try {
        const result = await step(identity, s);
        out.steps.push({ op: s.op, result: result === undefined ? null : result });
      } catch (err) {
        out.steps.push({ op: s.op, error: { message: err.message, code: err.code ?? null } });
      }
    }
  } finally {
    await core.stop();
    Object.assign(console, quiet);
  }
  process.stdout.write(`${JSON.stringify(out)}\n`);
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err}\n`);
  process.exit(1);
});
