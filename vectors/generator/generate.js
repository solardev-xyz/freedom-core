'use strict';

// The oracle is the installed desktop JS, never a parallel crypto implementation.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createRequire } = require('node:module');
const { buildSigning } = require('./signing');
const { buildNaming } = require('./naming');
const { buildNamingReplay } = require('./naming-replay');
const { buildChain } = require('./chain');
const { buildChainReplay } = require('./chain-replay');
const { buildDweb, buildVerifyPlans } = require('./dweb');
const { buildStreams } = require('./streams');
const { buildSecrets } = require('./secrets');
const { buildKeystore } = require('./keystore');
const { buildLayout } = require('./layout');
const { buildRadicleReads } = require('./radicle-reads');
const { buildRadicleBlob } = require('./radicle-blob');
const { buildRadicleNetwork } = require('./radicle-network');
const { buildRadicleStats } = require('./radicle-stats');
const { buildRadicleImport } = require('./radicle-import');
const { buildApprovals } = require('./approvals');
const { buildProfiles } = require('./profiles');
const { buildEip1193 } = require('./eip1193');
const { buildSafe } = require('./safe');
const { buildJournal } = require('./journal');
const { buildStores } = require('./stores');
const { buildSqlite } = require('./sqlite');
const { buildColibri } = require('./colibri');
const { buildLedger } = require('./ledger');

const REFERENCE_COMMIT = 'fb540328162839e68150fe2c5e517edb86734d1c';
// The Radicle vectors' own reference: freedom-browser's integration/rust-core,
// whose main the service replaces (design 0008) and whose parity harness
// (src/main/radicle/radicle-vectors.test.js) replays them against its main.
// It moves on its own, when that main changes what the vectors record; the
// shared reference above stays, since moving it would re-derive every other
// file from another browser and break the random fixtures' meta.
const RADICLE_REFERENCE_COMMIT = '1ea598373fcc406bed8a3df1e54b734dcc4e5ac5';
// The approvals vectors' own reference (design 0012): freedom-browser's
// integration/rust-core, with SEC-1's eleventh token kind (#1016) and 0011's
// page tokens (PRQ-5a). Like the Radicle reference, it moves on its own.
const APPROVALS_REFERENCE_COMMIT = '7f85551d82bddb1337df73b331785e969d62d1b9';
// The profile vectors' reference (design 0013, PRF-3): the approvals
// reference's checkout, whose profile modules (profile-catalog.js,
// profile-resolver.js, profile-lock.js, profile-switch-scheme.js) are byte
// for byte integration/rust-core's at 2f0c571f. Their one package,
// proper-lockfile, comes from the main reference's install, the same version
// (profiles.js).
const PROFILES_REFERENCE_COMMIT = APPROVALS_REFERENCE_COMMIT;
// The Ethereum dispatcher's vectors' reference (design 0012, APR-5a): the
// approvals reference's checkout, whose src/main/page/ is 0011's dispatcher
// whole (PRQ-3 to PRQ-6) before APB-1 to APB-3 moved its tokens, rules and
// grants into the core. Its one package, ethers, comes from the main
// reference's install, the same version (eip1193.js).
const EIP1193_REFERENCE_COMMIT = APPROVALS_REFERENCE_COMMIT;
// The JSON Lines journal's vectors' reference (design 0013, PRF-5d): the
// approvals reference's checkout, whose src/main/lib/durable-journal.js is
// byte for byte integration/rust-core's at 5e62992a (it last changed in
// db09e7f7). The shared reference predates the module. It reads no package.
const JOURNAL_REFERENCE_COMMIT = APPROVALS_REFERENCE_COMMIT;

// The set-A stores' reference (design 0013, PRF-5a): freedom-browser's
// integration/rust-core, whose identity-manager.js has the Safe owners'
// address checks (#1065, #1078), the verified deployed mark (#1066) and the
// core's vault backend. Its generator (stores.js) loads that file whole and
// reads no package of the checkout's: ethers and @sinonjs/fake-timers come
// from the main reference's install. Like the Radicle reference, it moves on
// its own.
const STORES_REFERENCE_COMMIT = '9d4ea62516034731dea082c6d81765e355f1182f';
// The Colibri vectors' reference (design 0014, COL-1): freedom-browser's
// integration/rust-core, with #1081 (no local proving), #1071 (the private
// store) and #1083 (no ENS through Colibri). Its generator (colibri.js) loads
// colibri-runtime.js, colibri-worker.js and checkpoint-verifier-worker.js
// whole, over the checkout's installed @corpus-core/colibri-stateless 3.0.3
// (c4w.wasm checked by digest) and its ethers. Like the Radicle reference, it
// moves on its own.
const COLIBRI_REFERENCE_COMMIT = '7cf6a0c299b50b64944d5d246a911bdb25dc5c82';
// The window.swarm vectors' reference (design 0015, SWM-1): freedom-browser's
// integration/rust-core, with #1057 (the metered feed reads, feedEntryExists,
// publishFiles through publishCollection) and #1062 (the PSS recipient as the
// compressed key). Its generator (swarm.js) loads src/main/swarm/ whole over
// the checkout's installed @ethersphere/bee-js 13.2.0 and core-sdk 0.2.2,
// refusing any other version, with every package file the run loads checked by
// digest. Like the Radicle reference, it moves on its own.
const SWARM_REFERENCE_COMMIT = 'dea09d2f58c18c5ffe5baef464fdf70af1ef40ef';
// The Ledger vectors' reference (design 0016, LDG-1): the swarm reference's
// checkout, whose src/main/wallet/ledger/ has #1063 (every signature
// recovered) and #1065 (the address read from the device), over its
// installed @ledgerhq/hw-app-eth 7.11.1, hw-transport-node-hid 6.33.5 and
// @x402/evm 2.29.0, the versions design 0016 pins (ledger.js refuses any
// other). It moves with the swarm reference until the Ledger vectors need
// another commit.
const LEDGER_REFERENCE_COMMIT = SWARM_REFERENCE_COMMIT;
const OUTPUT = path.resolve(__dirname, '..');
const INDICES = [0, 1, 2, 1000, 2147483647];
const MNEMONICS = [
  { id: 'abandon-12', mnemonic: [...Array(11).fill('abandon'), 'about'].join(' ') },
  { id: 'abandon-24', mnemonic: [...Array(23).fill('abandon'), 'art'].join(' ') },
  { id: 'legal-12', mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow' },
  { id: 'zoo-12', mnemonic: [...Array(11).fill('zoo'), 'wrong'].join(' ') },
  // Generated once by the reference createMnemonic(128/256), then frozen here.
  { id: 'fresh-128', mnemonic: 'move slight police dish goddess wonder slender skate siege rookie faith laundry' },
  { id: 'fresh-256', mnemonic: 'debate leisure left spoon alley double transfer segment region actual nest timber home garage easily tone thing bread anger boring belt trend eager vivid' },
];
const COMMENTS = ['FreedomBrowser', 'vector-alias'];
// Aliases whose private section is 4, 5 (aligned), 6 and 13 (aligned) bytes
// past 131, for radiclePrivateFiles.
const RADICLE_ALIGNMENT_ALIASES = ['alic', 'alice', 'alices', 'Freedom-Node1'];
const RADICLE_FIXED_CHECK = '0a0b0c0d';
const UNICODE_PASSWORD = 'Caf\u00e9-\ud83d\udd10-password';
const VAULT_CASES = [
  { id: 'ascii-min-12', mnemonicId: 'abandon-12', password: 'testpass' },
  { id: 'ascii-min-24', mnemonicId: 'abandon-24', password: 'testpass' },
  { id: 'long-24', mnemonicId: 'fresh-256', password: 'Freedom public test password: ' + 'long-password-'.repeat(12) },
  { id: 'unicode-nfc-12', mnemonicId: 'legal-12', password: UNICODE_PASSWORD },
  { id: 'utf16-min-12', mnemonicId: 'zoo-12', password: '\ud83d\udd10'.repeat(4) },
];
const BEE_CASES = [
  { id: 'ascii', mnemonicId: 'abandon-12', password: 'testpass' },
  { id: 'unicode-nfc', mnemonicId: 'abandon-24', password: UNICODE_PASSWORD },
];

const json = (value) => JSON.stringify(value, null, 2) + '\n';

// A failed check names the first line that differs, with its neighbours, so a
// mismatch seen only on another machine (CI) can be read from its log.
function byteMismatch(filename, committed, generated) {
  const a = committed.split('\n');
  const b = generated.split('\n');
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  const clip = (line) => (line === undefined ? '(end of file)' : line.length > 400 ? `${line.slice(0, 400)}…` : line);
  const lines = [`Byte mismatch: ${filename}`, `first difference at line ${i + 1} (committed ${a.length} lines, generated ${b.length})`];
  for (let j = Math.max(0, i - 3); j < i; j++) lines.push(`  ${j + 1}  ${clip(a[j])}`);
  for (let j = i; j < i + 4; j++) lines.push(`- ${j + 1}  ${clip(a[j])}`);
  for (let j = i; j < i + 4; j++) lines.push(`+ ${j + 1}  ${clip(b[j])}`);
  return lines.join('\n');
}
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const mnemonicFor = (id) => MNEMONICS.find((entry) => entry.id === id).mnemonic;

function errorResult(error) {
  const result = { status: 'error', name: error.name, message: error.message };
  if (error.cause) result.cause = { name: error.cause.name, message: error.cause.message };
  return result;
}

function capture(fn) {
  try {
    return { status: 'success', value: fn() };
  } catch (error) {
    return errorResult(error);
  }
}

function packageVersion(referenceRequire, name) {
  // Package exports can hide package.json; ethers also has a nested package.json.
  let directory = path.dirname(referenceRequire.resolve(name));
  while (true) {
    const filename = path.join(directory, 'package.json');
    if (fs.existsSync(filename)) {
      const pkg = JSON.parse(fs.readFileSync(filename, 'utf8'));
      if (pkg.name === name && pkg.version) return pkg.version;
    }
    const parent = path.dirname(directory);
    assert.notEqual(parent, directory, `Cannot locate installed package.json for ${name}`);
    directory = parent;
  }
}

/** The checkout's commit, after checking it is `expected` and clean. */
function checkedCommit(checkout, expected, what) {
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: checkout, encoding: 'utf8' }).trim();
  assert.equal(commit, expected, `Use the pinned ${what} commit`);
  // Include staged, unstaged, and untracked source/config changes in this guard.
  const status = execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: checkout, encoding: 'utf8' });
  assert.equal(status, '', `The ${what} checkout must be clean (node_modules is ignored)`);
  return commit;
}

/** The Radicle vectors' reference: their generators load its main-process
 * modules, and no package of its own is read, so its meta names none. */
function loadRadicleReference(checkout) {
  const commit = checkedCommit(checkout, RADICLE_REFERENCE_COMMIT, 'Radicle reference');
  return { checkout, meta: { freedomBrowserCommit: commit, nodeVersion: process.version, generator: 'vectors/generator/generate.js' } };
}

/** The approvals vectors' reference: their generator loads its
 * signing-confirmation.js, its four grant stores and its x402 code. The x402
 * code's SDK is the main reference's install, which buildApprovals' meta
 * names (`packages`). */
function loadApprovalsReference(checkout) {
  const commit = checkedCommit(checkout, APPROVALS_REFERENCE_COMMIT, 'approvals reference');
  return { checkout, meta: { freedomBrowserCommit: commit, nodeVersion: process.version, generator: 'vectors/generator/generate.js' } };
}

/** The set-A stores' reference: stores.js loads its identity-manager.js.
 * Its packages are the main reference's, which the file's meta names. */
function loadStoresReference(checkout) {
  const commit = checkedCommit(checkout, STORES_REFERENCE_COMMIT, 'stores reference');
  return { checkout, meta: { freedomBrowserCommit: commit, nodeVersion: process.version, generator: 'vectors/generator/generate.js' } };
}

/** The Colibri vectors' reference: colibri.js loads its main-process
 * modules over the package it installs, which meta names with ethers. */
function loadColibriCheckout(checkout) {
  const commit = checkedCommit(checkout, COLIBRI_REFERENCE_COMMIT, 'colibri reference');
  const referenceRequire = createRequire(path.join(checkout, 'package.json'));
  const packages = Object.fromEntries(['@corpus-core/colibri-stateless', 'ethers']
    .map((name) => [name, packageVersion(referenceRequire, name)]));
  return { checkout, meta: { freedomBrowserCommit: commit, packages, nodeVersion: process.version, generator: 'vectors/generator/generate.js' } };
}

/** The window.swarm vectors' reference: swarm.js loads its src/main/swarm/
 * modules over its installed bee-js and core-sdk, which meta names. */
function loadSwarmReference(checkout) {
  const commit = checkedCommit(checkout, SWARM_REFERENCE_COMMIT, 'swarm reference');
  return { checkout, meta: { freedomBrowserCommit: commit, nodeVersion: process.version, generator: 'vectors/generator/generate.js' } };
}

let swarmWorker = null;

/** swarm.json and swarm-grammar.json, built in a worker thread beside the other files. */
function startSwarm(swarm) {
  const { Worker } = require('node:worker_threads');
  return new Promise((resolve, reject) => {
    const worker = swarmWorker = new Worker(path.join(__dirname, 'swarm-worker.js'), {
      workerData: { checkout: swarm.checkout, meta: swarm.meta, keysPath: path.join(OUTPUT, 'keys.json'),
        dwebVerifyPath: path.join(OUTPUT, 'dweb-verify.json') },
    });
    worker.once('message', (message) => {
      worker.terminate();
      if (message.error) reject(new Error(message.error));
      else resolve(message);
    });
    worker.once('error', reject);
    worker.once('exit', (code) => reject(new Error(`the swarm vectors' worker exited (${code}) without an answer`)));
  });
}

// The Safe vectors' reference (design 0016, SAFE-1): the swarm reference's
// checkout, whose src/main/wallet/safe/ has the pinned deployment (#1066)
// and the core's pending SafeTx store (PRF-6(d)). Its generator (safe.js)
// loads those modules whole over the checkout's installed protocol-kit
// 8.0.11, safe-deployments 1.37.66 and ethers 6.17.0, refusing any other
// version, which meta names.
const SAFE_REFERENCE_COMMIT = SWARM_REFERENCE_COMMIT;

function loadReference(checkout) {
  const commit = checkedCommit(checkout, REFERENCE_COMMIT, 'reference');
  const referenceRequire = createRequire(path.join(checkout, 'package.json'));
  const packages = Object.fromEntries([
    'ethers', '@scure/bip39', '@scure/base', 'micro-key-producer', '@metamask/browser-passworder',
  ].map((name) => [name, packageVersion(referenceRequire, name)]));
  return {
    checkout,
    meta: { freedomBrowserCommit: commit, packages, nodeVersion: process.version, generator: 'vectors/generator/generate.js' },
    derivation: referenceRequire('./src/main/identity/derivation.js'),
    formats: referenceRequire('./src/main/identity/formats.js'),
    vault: referenceRequire('./src/main/identity/vault.js'),
    passworder: referenceRequire('@metamask/browser-passworder'),
    ethers: referenceRequire('ethers'),
    beeJs: referenceRequire('@ethersphere/bee-js'),
    signingPackages: Object.fromEntries(['@ethersphere/bee-js', '@ethersphere/core-sdk']
      .map((name) => [name, packageVersion(referenceRequire, name)])),
    bip39: referenceRequire('@scure/bip39'),
    wordlist: referenceRequire('@scure/bip39/wordlists/english.js').wordlist,
  };
}

function buildKeys({ meta, derivation: d }) {
  assert.equal(d.deriveUserWallet(MNEMONICS[0].mnemonic, 0).address,
    '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', 'STOP: wallet sanity check failed');
  const vectors = MNEMONICS.map(({ id, mnemonic }) => {
    const all = d.deriveAllKeys(mnemonic);
    const edKey = (key) => ({ path: key.path, privateKey: hex(key.privateKey), publicKey: hex(key.publicKey) });
    return {
      id, mnemonic, seed: hex(d.getSeed(mnemonic)),
      userWallets: INDICES.map((index) => d.deriveUserWallet(mnemonic, index)),
      beeWallet: all.beeWallet,
      publisherKeys: INDICES.map((index) => d.derivePublisherKey(mnemonic, index)),
      radicleKey: edKey(all.radicleKey), ipfsKey: edKey(all.ipfsKey),
    };
  });
  // Special JS values are tagged rather than silently serialized as null/zero.
  const cases = [
    ['max-plus-one', 2147483648], ['negative', -1], ['negative-fraction', -0.5],
    ['fraction', 1.5], ['numeric-string', '1'], ['null', null],
    ['undefined', undefined], ['nan', NaN], ['infinity', Infinity], ['negative-zero', -0],
  ];
  const edgeCases = MNEMONICS.map(({ id, mnemonic }) => ({
    mnemonicId: id,
    cases: cases.map(([label, index]) => ({
      id: label,
      input: { type: typeof index, value: typeof index === 'number' && (!Number.isFinite(index) || Object.is(index, -0)) ? String(Object.is(index, -0) ? '-0' : index) : (index === undefined ? 'undefined' : index) },
      userWallet: capture(() => d.deriveUserWallet(mnemonic, index)),
      publisherKey: capture(() => d.derivePublisherKey(mnemonic, index)),
    })),
  }));
  return {
    meta,
    encodings: {
      seed: '64-byte lowercase hex, no 0x',
      secp256k1PrivateKey: '32-byte lowercase hex with 0x',
      secp256k1PublicKey: '33-byte compressed SEC1 lowercase hex with 0x',
      address: 'EIP-55 checksummed hex with 0x',
      ed25519PrivateKey: '32-byte Uint8Array returned by JS, serialized as lowercase hex without 0x',
      ed25519PublicKey: '32-byte raw Uint8Array returned by JS, serialized as lowercase hex without 0x',
    },
    vectors, edgeCases,
  };
}

function buildValidation({ meta, derivation: d, bip39, wordlist }) {
  const mnemonic = MNEMONICS[0].mnemonic;
  const nfc = mnemonic.replace('abandon', '\u00e1bandon');
  const fullwidth = mnemonic.replace(/[a-z]/g, (letter) => String.fromCharCode(letter.charCodeAt(0) + 0xfee0));
  const inputs = [
    ...[16, 20, 24, 28, 32].map((length) => [`valid-${length * 3 / 4}-words`, bip39.entropyToMnemonic(new Uint8Array(length), wordlist)]),
    ['legal-12', MNEMONICS[2].mnemonic], ['zoo-12', MNEMONICS[3].mnemonic],
    ['bad-checksum', Array(12).fill('abandon').join(' ')],
    ['11-words', Array(11).fill('abandon').join(' ')],
    ['13-words', 'abandon ' + mnemonic], ['unknown-word', mnemonic.replace('abandon', 'notaword')],
    ['other-language-word', mnemonic.replace('abandon', 'abaisser')],
    ['uppercase', mnemonic.toUpperCase()], ['mixed-case', mnemonic.replace('abandon', 'Abandon')],
    ['leading-space', ' ' + mnemonic], ['trailing-space', mnemonic + ' '],
    ['double-space', mnemonic.replace(' ', '  ')], ['tab', mnemonic.replace(' ', '\t')],
    ['newline', mnemonic.replace(' ', '\n')], ['empty', ''],
    ['non-string-null', null], ['non-string-number', 123], ['non-string-array', mnemonic.split(' ')],
    ['non-string-object', { mnemonic }], ['accent-nfc', nfc.normalize('NFC')],
    ['accent-nfkd', nfc.normalize('NFKD')], ['fullwidth-nfc', fullwidth.normalize('NFC')],
    ['fullwidth-nfkd', fullwidth.normalize('NFKD')],
    ['ideographic-spaces', mnemonic.replaceAll(' ', '\u3000')],
    ['nonbreaking-spaces', mnemonic.replaceAll(' ', '\u00a0')],
    ['unpaired-surrogate', mnemonic.replace('abandon', '\ud800bandon')],
  ];
  return {
    meta,
    vectors: inputs.map(([id, input]) => {
      const valid = d.isValidMnemonic(input);
      const result = { id, input, valid, getSeed: capture(() => hex(d.getSeed(input))) };
      if (valid) result.userWallet0 = capture(() => d.deriveUserWallet(input, 0));
      return result;
    }),
  };
}

function buildIdentities({ meta, derivation: d, formats: f }) {
  return {
    meta,
    vectors: MNEMONICS.map(({ id, mnemonic }) => {
      const { radicleKey, ipfsKey } = d.deriveAllKeys(mnemonic);
      return {
        mnemonicId: id,
        ipfs: f.createIpfsIdentity(ipfsKey.privateKey, ipfsKey.publicKey),
        radicle: COMMENTS.map((comment, index) => {
          const result = index === 0 ? f.createRadicleIdentity(radicleKey.privateKey, radicleKey.publicKey)
            : f.createRadicleIdentity(radicleKey.privateKey, radicleKey.publicKey, comment);
          return { comment, did: result.did, nodeId: result.nodeId, publicKeyFile: result.publicKeyFile };
        }),
        didFromPublicKey: f.didFromPublicKey(radicleKey.publicKey),
      };
    }),
    // Whole private key files with a fixed check integer, for aliases around
    // an aligned private section (131 bytes plus the alias). The reference
    // pads an aligned section with a full 8 bytes, which OpenSSH reads but
    // ssh-key (Radicle's reader) refuses; the core pads it with none, as
    // OpenSSH writes it (deviation openssh-padding, freedom-core #77).
    radiclePrivateFiles: RADICLE_ALIGNMENT_ALIASES.map((comment) => {
      const key = d.deriveAllKeys(mnemonicFor('abandon-12')).radicleKey;
      const result = replayRadicle(f, key, comment, RADICLE_FIXED_CHECK);
      const parsed = parseOpenSSH(result.privateKeyFile, key, comment);
      const aligned = (131 + Buffer.byteLength(comment)) % 8 === 0;
      return {
        mnemonicId: 'abandon-12', comment, checkIntegerHex: RADICLE_FIXED_CHECK, paddingHex: parsed.paddingHex,
        ...(aligned ? { deviation: 'openssh-padding' } : {}),
        privateKeyFile: result.privateKeyFile,
      };
    }),
  };
}

function scratchDirectory() {
  // Existing repo-local scratch directories are deliberately left untouched.
  return fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-vectors-'));
}

async function unlockOutcome(vault, directory, fileContents, password) {
  fs.writeFileSync(path.join(directory, 'identity-vault.json'), fileContents, { mode: 0o600 });
  vault.lockVault();
  try {
    await vault.unlockVault(directory, password, 0);
    return { status: 'success', mnemonic: vault.getMnemonic() };
  } catch (error) {
    return errorResult(error);
  } finally {
    vault.lockVault();
  }
}

function mutateVault(fileContents, mutation) {
  const outer = JSON.parse(fileContents);
  const payload = JSON.parse(outer.encrypted);
  if (['data', 'iv', 'salt'].includes(mutation.field)) {
    const bytes = Buffer.from(payload[mutation.field], 'base64');
    bytes[0] ^= 1;
    payload[mutation.field] = bytes.toString('base64');
  } else if (mutation.field === 'iterations') {
    payload.keyMetadata.params.iterations += 1;
  } else if (mutation.field === 'keyMetadata') {
    delete payload.keyMetadata;
  } else {
    throw new Error('Unknown mutation');
  }
  outer.encrypted = JSON.stringify(payload);
  return JSON.stringify(outer, null, 2); // The vault itself has no trailing newline.
}

async function buildLegacyVaults(reference, existing, mode, directory) {
  const { vault, passworder } = reference;
  const config = { id: 'synthetic-legacy-10000-12', mnemonicId: 'abandon-12', password: 'testpass' };
  const mnemonic = mnemonicFor(config.mnemonicId);
  const parameters = { algorithm: 'PBKDF2', params: { iterations: 10000 } };
  assert.ok(!existing || existing.legacyFixtures || mode === 'generate', 'Missing positive legacy vault fixture');
  let fileContents;
  if (existing?.legacyFixtures) {
    assert.equal(existing.legacyFixtures.length, 1);
    fileContents = existing.legacyFixtures[0].fileContents;
  } else {
    // Use the app to create the real envelope, then replace only its encrypted
    // payload with passworder's legacy format. Freedom never wrote this format.
    const caseDirectory = path.join(directory, config.id);
    await vault.importVault(caseDirectory, config.password, mnemonic);
    const envelope = JSON.parse(fs.readFileSync(vault.getVaultPath(caseDirectory), 'utf8'));
    const encrypted = await passworder.encrypt(config.password, { mnemonic }, undefined, undefined, parameters);
    const payload = JSON.parse(encrypted);
    assert.deepEqual(payload.keyMetadata, parameters);
    delete payload.keyMetadata;
    envelope.encrypted = JSON.stringify(payload);
    fileContents = JSON.stringify(envelope, null, 2);
  }
  const envelope = JSON.parse(fileContents);
  assert.equal(fileContents, JSON.stringify(envelope, null, 2));
  assert.deepEqual(Object.keys(envelope), ['version', 'encrypted', 'createdAt']);
  assert.equal(envelope.version, 1);
  assert.equal(new Date(envelope.createdAt).toISOString(), envelope.createdAt);
  const payload = JSON.parse(envelope.encrypted);
  assert.deepEqual(Object.keys(payload), ['data', 'iv', 'salt']);
  for (const field of ['data', 'iv', 'salt']) {
    assert.equal(Buffer.from(payload[field], 'base64').toString('base64'), payload[field]);
  }
  assert.equal(Buffer.from(payload.iv, 'base64').length, 16);
  assert.equal(Buffer.from(payload.salt, 'base64').length, 32);
  assert.equal(Buffer.from(payload.data, 'base64').length, Buffer.byteLength(JSON.stringify({ mnemonic })) + 16);
  assert.deepEqual(await passworder.decrypt(config.password, envelope.encrypted), { mnemonic });
  const outcome = await unlockOutcome(vault, directory, fileContents, config.password);
  assert.deepEqual(outcome, { status: 'success', mnemonic });
  const wrongPasswordOutcome = await unlockOutcome(vault, directory, fileContents, config.password + '-wrong');
  assert.equal(wrongPasswordOutcome.status, 'error');
  return [{ ...config, synthetic: true,
    provenance: 'Freedom never wrote these vaults. Real passworder.encrypt at 10000 PBKDF2 iterations, with keyMetadata removed, inside a real importVault envelope; the reader must accept the legacy fallback.',
    mnemonic, encryptionParameters: parameters, fileContents, payload, outcome, wrongPasswordOutcome }];
}

async function buildVaults(reference, existing, mode) {
  // Each run writes its vaults to a fresh directory, removed after.
  const directory = scratchDirectory();
  try {
    return await buildVaultsIn(directory, reference, existing, mode);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

async function buildVaultsIn(directory, reference, existing, mode) {
  const { meta, vault, passworder } = reference;
  const fixtures = [];
  for (const [index, config] of VAULT_CASES.entries()) {
    const mnemonic = mnemonicFor(config.mnemonicId);
    let fileContents;
    if (existing) {
      fileContents = existing.fixtures[index].fileContents;
    } else {
      const caseDirectory = path.join(directory, config.id);
      await vault.importVault(caseDirectory, config.password, mnemonic);
      fileContents = fs.readFileSync(vault.getVaultPath(caseDirectory), 'utf8');
    }
    const outer = JSON.parse(fileContents);
    assert.equal(fileContents, JSON.stringify(outer, null, 2), 'Vault file bytes/format');
    assert.deepEqual(Object.keys(outer), ['version', 'encrypted', 'createdAt']);
    assert.equal(outer.version, 1);
    assert.equal(new Date(outer.createdAt).toISOString(), outer.createdAt);
    const payload = JSON.parse(outer.encrypted);
    assert.deepEqual(Object.keys(payload), ['data', 'iv', 'keyMetadata', 'salt']);
    assert.deepEqual(payload.keyMetadata, { algorithm: 'PBKDF2', params: { iterations: 900000 } });
    for (const field of ['data', 'iv', 'salt']) {
      assert.equal(Buffer.from(payload[field], 'base64').toString('base64'), payload[field]);
    }
    assert.equal(Buffer.from(payload.iv, 'base64').length, 16);
    assert.equal(Buffer.from(payload.salt, 'base64').length, 32);
    assert.equal(Buffer.from(payload.data, 'base64').length, Buffer.byteLength(JSON.stringify({ mnemonic })) + 16);
    assert.deepEqual(await passworder.decrypt(config.password, outer.encrypted), { mnemonic });
    const outcome = await unlockOutcome(vault, directory, fileContents, config.password);
    assert.deepEqual(outcome, { status: 'success', mnemonic });
    const negativeInputs = [{ id: 'wrong-password', password: config.password + '-wrong', mutation: null }];
    if (config.id === 'unicode-nfc-12') {
      negativeInputs.push({ id: 'password-nfd', password: config.password.normalize('NFD'), mutation: null });
    }
    negativeInputs.push(...['data', 'iv', 'salt', 'iterations', 'keyMetadata'].map((field) => ({
      id: field === 'keyMetadata' ? 'metadata-removed' : (field === 'iterations' ? 'iterations-changed' : `${field}-first-byte-flipped`),
      password: config.password,
      mutation: { field, operation: field === 'keyMetadata' ? 'remove' : (field === 'iterations' ? 'add-1' : 'xor-first-byte-with-1') },
    })));
    const negativeCases = [];
    for (const input of negativeInputs) {
      const mutatedFile = input.mutation ? mutateVault(fileContents, input.mutation) : fileContents;
      const negativeOutcome = await unlockOutcome(vault, directory, mutatedFile, input.password);
      assert.equal(negativeOutcome.status, 'error', `${config.id}/${input.id} unexpectedly decrypted`);
      negativeCases.push({ ...input, fileContents: mutatedFile, outcome: negativeOutcome });
    }
    fixtures.push({ ...config, mnemonic, passwordUtf16Length: config.password.length,
      fileContents, payload, outcome, negativeCases });
  }
  // Probe the real password-length guard without changing the imported mnemonic.
  const passwordValidation = [];
  for (const password of ['', '1234567']) {
    let outcome;
    try {
      await vault.importVault(path.join(directory, 'short-password'), password, MNEMONICS[0].mnemonic);
      outcome = { status: 'success' };
    } catch (error) {
      outcome = errorResult(error);
    }
    assert.equal(outcome.status, 'error');
    passwordValidation.push({ password, outcome });
  }
  return {
    meta,
    structure: {
      file: 'identity-vault.json: 2-space JSON without a trailing newline; version=1, encrypted=JSON string, createdAt=ISO UTC timestamp',
      plaintext: 'UTF-8 bytes of JSON.stringify({ mnemonic })',
      encryptedFieldsInOrder: ['data', 'iv', 'keyMetadata', 'salt'],
      encoding: 'data, iv and salt are standard padded base64',
      kdf: { algorithm: 'PBKDF2', hash: 'SHA-256', iterations: 900000, saltBytes: 32, derivedKeyBits: 256, passwordEncoding: 'UTF-8, no Unicode normalization', iterationsWhenMetadataMissing: 10000 },
      cipher: { algorithm: 'AES-GCM', keyBits: 256, ivBytes: 16, tagBits: 128, dataLayout: 'ciphertext || 16-byte authentication tag', additionalAuthenticatedData: null },
      passwordMinimum: '8 JavaScript UTF-16 code units; four supplementary-plane characters suffice',
    },
    fixtures, passwordValidation,
    legacyFixtures: await buildLegacyVaults(reference, existing, mode, directory),
  };
}

async function buildBee(reference, existing) {
  const { meta, derivation: d, formats: f, ethers } = reference;
  const fixtures = [];
  for (const [index, config] of BEE_CASES.entries()) {
    const key = d.deriveAllKeys(mnemonicFor(config.mnemonicId)).beeWallet;
    const keystore = existing ? existing.fixtures[index].keystore : await f.createBeeKeystore(key.privateKey, config.password);
    const parsed = JSON.parse(keystore);
    assert.equal(parsed.version, 3);
    assert.equal(parsed.address, key.address.slice(2).toLowerCase());
    assert.equal(parsed.Crypto.cipher, 'aes-128-ctr');
    assert.equal(parsed.Crypto.kdf, 'scrypt');
    assert.deepEqual({ ...parsed.Crypto.kdfparams, salt: null }, { salt: null, n: 131072, dklen: 32, p: 1, r: 8 });
    assert.equal(Buffer.from(parsed.Crypto.kdfparams.salt, 'hex').length, 32);
    assert.equal(Buffer.from(parsed.Crypto.cipherparams.iv, 'hex').length, 16);
    const wallet = await ethers.Wallet.fromEncryptedJson(keystore, config.password);
    assert.equal(wallet.privateKey, key.privateKey);
    assert.equal(wallet.address, key.address);
    let nfdPasswordOutcome = null;
    if (config.id === 'unicode-nfc') {
      const nfdWallet = await ethers.Wallet.fromEncryptedJson(keystore, config.password.normalize('NFD'));
      assert.equal(nfdWallet.privateKey, key.privateKey);
      nfdPasswordOutcome = { password: config.password.normalize('NFD'), status: 'success', privateKey: nfdWallet.privateKey, address: nfdWallet.address };
    }
    fixtures.push({ ...config, privateKey: key.privateKey, address: key.address,
      keystore, parsed, kdfParameters: parsed.Crypto.kdfparams, nfdPasswordOutcome });
  }
  return {
    meta,
    structure: { version: 3, cipher: 'AES-128-CTR', kdf: 'scrypt', passwordNormalization: 'NFKC in ethers', mac: 'Keccak-256(derivedKey[16..32] || ciphertext)', encodings: 'lowercase hex, without 0x; keystore address is lowercase, expected address is EIP-55' },
    fixtures,
  };
}

function parseOpenSSH(privateKeyFile, expectedKey, comment) {
  assert.match(privateKeyFile, /^-----BEGIN OPENSSH PRIVATE KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END OPENSSH PRIVATE KEY-----\n$/);
  const lines = privateKeyFile.trimEnd().split('\n').slice(1, -1);
  for (const line of lines.slice(0, -1)) assert.equal(line.length, 70);
  assert.ok(lines.at(-1).length <= 70);
  const b64 = lines.join('');
  const bytes = Buffer.from(b64, 'base64');
  assert.equal(bytes.toString('base64'), b64);
  assert.equal(bytes.subarray(0, 15).toString(), 'openssh-key-v1\0');
  let offset = 15;
  const uint32 = () => { assert.ok(offset + 4 <= bytes.length); const result = bytes.readUInt32BE(offset); offset += 4; return result; };
  const string = () => { const length = uint32(); assert.ok(offset + length <= bytes.length); const result = bytes.subarray(offset, offset + length); offset += length; return result; };
  assert.equal(string().toString(), 'none');
  assert.equal(string().toString(), 'none');
  assert.equal(string().length, 0);
  assert.equal(uint32(), 1);
  const publicBlob = string();
  const privateSection = string();
  assert.equal(offset, bytes.length);
  const expectedPublic = Buffer.concat([Buffer.from('0000000b7373682d6564323535313900000020', 'hex'), Buffer.from(expectedKey.publicKey)]);
  assert.deepEqual(publicBlob, expectedPublic);
  let innerOffset = 8;
  const innerString = () => {
    assert.ok(innerOffset + 4 <= privateSection.length);
    const length = privateSection.readUInt32BE(innerOffset);
    innerOffset += 4;
    assert.ok(innerOffset + length <= privateSection.length);
    const result = privateSection.subarray(innerOffset, innerOffset + length);
    innerOffset += length;
    return result;
  };
  assert.equal(privateSection.readUInt32BE(0), privateSection.readUInt32BE(4));
  assert.equal(innerString().toString(), 'ssh-ed25519');
  assert.deepEqual(innerString(), Buffer.from(expectedKey.publicKey));
  assert.deepEqual(innerString(), Buffer.concat([Buffer.from(expectedKey.privateKey), Buffer.from(expectedKey.publicKey)]));
  assert.equal(innerString().toString('utf8'), comment);
  const padding = privateSection.subarray(innerOffset);
  assert.equal(padding.length, 8 - (innerOffset % 8));
  assert.deepEqual(padding, Buffer.from(Array.from({ length: padding.length }, (_, index) => index + 1)));
  assert.equal(privateSection.length % 8, 0);
  return { checkIntegerHex: privateSection.subarray(0, 4).toString('hex'), paddingHex: padding.toString('hex') };
}

function replayRadicle(formats, key, comment, checkIntegerHex) {
  const original = crypto.randomBytes;
  let calls = 0;
  try {
    crypto.randomBytes = (size) => {
      assert.equal(size, 4, 'Only the OpenSSH check integer may be injected');
      calls += 1;
      return Buffer.from(checkIntegerHex, 'hex');
    };
    const result = formats.createRadicleIdentity(key.privateKey, key.publicKey, comment);
    assert.equal(calls, 1);
    return result;
  } finally {
    crypto.randomBytes = original;
  }
}

function buildRadicle({ meta, derivation: d, formats: f }, existing) {
  const fixtures = [];
  for (const { id, mnemonic } of MNEMONICS) {
    const key = d.deriveAllKeys(mnemonic).radicleKey;
    for (const comment of COMMENTS) {
      const index = fixtures.length;
      const result = existing ? existing.fixtures[index].identity : f.createRadicleIdentity(key.privateKey, key.publicKey, comment);
      const parsed = parseOpenSSH(result.privateKeyFile, key, comment);
      assert.deepEqual(replayRadicle(f, key, comment, parsed.checkIntegerHex), result);
      fixtures.push({ mnemonicId: id, comment, ...parsed, identity: result });
    }
  }
  return {
    meta,
    structure: { cipher: 'none', kdf: 'none', checkInteger: 'random 4-byte unsigned big-endian integer, repeated twice', privateKeyLayout: '32-byte private seed || 32-byte public key', padding: 'bytes 01, 02, ... up to an 8-byte boundary; a full 8 bytes when already aligned', pemLineWidth: 70, trailingNewline: true },
    fixtures,
  };
}

async function main() {
  // Local time is UTC for every reference, set before any thread starts (the
  // swarm vectors' thread reads it too): the swarm vectors' legacy-dates and
  // history-blobs cases read a time without an offset as local time.
  process.env.TZ = 'UTC';
  const args = process.argv.slice(2);
  assert.ok(args.length === 13 && ['generate', 'check'].includes(args[0]) && args[1] === '--freedom-browser'
    && args[3] === '--radicle-browser' && args[5] === '--approvals-browser' && args[7] === '--stores-browser'
    && args[9] === '--colibri-browser' && args[11] === '--swarm-browser',
    'Usage: node vectors/generator/generate.js <generate|check> --freedom-browser <checkout> --radicle-browser <checkout> --approvals-browser <checkout> --stores-browser <checkout> --colibri-browser <checkout> --swarm-browser <checkout>');
  const [mode, , checkout, , radicleCheckout, , approvalsCheckout, , storesCheckout, , colibriCheckout, , swarmCheckout] = args;
  const reference = loadReference(path.resolve(checkout));
  const radicle = loadRadicleReference(path.resolve(radicleCheckout));
  const approvals = loadApprovalsReference(path.resolve(approvalsCheckout));
  const stores = loadStoresReference(path.resolve(storesCheckout));
  const colibri = loadColibriCheckout(path.resolve(colibriCheckout));
  const swarmReference = loadSwarmReference(path.resolve(swarmCheckout));
  // The swarm vectors run in their own thread from the start; their files
  // join the others at the end.
  const swarmJob = startSwarm(swarmReference);
  swarmJob.catch(() => {});
  // Built in this order; a check compares each file as soon as it is built,
  // so a mismatch stops the run there.
  // Design 0016's Ledger exchanges (LDG-1): one run builds both files.
  let ledgerFiles = null;
  const builders = [
    ['keys.json', () => buildKeys(reference)],
    // The ledger reference's src/main/wallet/ledger/ over a recording
    // transport and a scripted device holding keys.json's test mnemonic, and
    // the APDU grammar every exchange is checked against. Early in the list,
    // so a mismatch there stops the run quickly.
    ['ledger.json', async () => {
      ledgerFiles = await buildLedger(swarmReference.checkout, {
        freedomBrowserCommit: checkedCommit(swarmReference.checkout, LEDGER_REFERENCE_COMMIT, 'ledger reference'),
        nodeVersion: process.version,
        generator: 'vectors/generator/generate.js',
      }, JSON.parse(fs.readFileSync(path.join(OUTPUT, 'keys.json'), 'utf8')));
      return ledgerFiles.ledger;
    }],
    ['ledger-grammar.json', () => ledgerFiles.grammar],
    ['mnemonic-validation.json', () => buildValidation(reference)],
    ['identity-formats.json', () => buildIdentities(reference)],
    // Its own meta: the shared one is frozen into the existing fixtures.
    ['signing.json', () => buildSigning(reference, mnemonicFor, {
      ...reference.meta,
      packages: { ...reference.meta.packages, ...reference.signingPackages },
    })],
    ['naming-replay.json', () => buildNamingReplay(reference.checkout, reference.ethers, {
      ...reference.meta,
      packages: { ...reference.meta.packages, '@sinonjs/fake-timers': packageVersion(createRequire(path.join(reference.checkout, 'package.json')), '@sinonjs/fake-timers') },
    })],
    ['naming.json', () => buildNaming(reference.checkout, reference.ethers, {
      ...reference.meta,
      packages: { ...reference.meta.packages, '@adraffy/ens-normalize': packageVersion(createRequire(path.join(reference.checkout, 'package.json')), '@adraffy/ens-normalize') },
    })],
    // Signed with the first test wallet; ethers only hashes them.
    ['chain.json', () => buildChain(reference.checkout, reference.ethers,
      reference.derivation.deriveUserWallet(mnemonicFor('abandon-12'), 0).privateKey, reference.meta)],
    // Its broadcasts are signed with the same wallet.
    ['chain-replay.json', () => buildChainReplay(reference.checkout, reference.ethers,
      reference.derivation.deriveUserWallet(mnemonicFor('abandon-12'), 0).privateKey, {
        ...reference.meta,
        packages: { ...reference.meta.packages, '@sinonjs/fake-timers': packageVersion(createRequire(path.join(reference.checkout, 'package.json')), '@sinonjs/fake-timers') },
      })],
    ['dweb.json', () => buildDweb(reference.checkout, reference.ethers, reference.meta)],
    // Design 0009's verify plans, from the same cases on external backends.
    ['dweb-verify-plans.json', () => buildVerifyPlans(reference.checkout, reference.meta)],
    // The design's, with no reference: its meta is the shared one.
    ['streams.json', () => buildStreams(reference.meta)],
    // Design 0013's secrets file (PRF-1a): the design's, with no reference;
    // its meta is the shared one.
    ['secrets.json', () => buildSecrets(reference.meta)],
    // Design 0013's key-store helper's answers (PRF-1b): the design's, with
    // no reference; its meta is the shared one.
    ['keystore.json', () => buildKeystore(reference.meta)],
    // Design 0013's Freedom directory move (PRF-9a): the list, the journal
    // and its recovery, and the start's preconditions; the design's, with
    // no reference; its meta is the shared one.
    ['layout.json', () => buildLayout(reference.meta)],
    // Design 0008's composed reads, from main's radapi handlers over a
    // scripted add-on.
    ['radicle-reads.json', () => buildRadicleReads(radicle.checkout, radicle.meta)],
    // Design 0008's rad.blob: its ranges are the design's; main's /blob/
    // route over the same files.
    ['radicle-blob.json', () => buildRadicleBlob(radicle.checkout, radicle.meta)],
    // Design 0008's network operations, from main's manager and seed
    // status over a scripted add-on, and the design's progress queue.
    ['radicle-network.json', () => buildRadicleNetwork(radicle.checkout, radicle.meta)],
    // Design 0008's `rad.stats`: the design's result, with main's peer
    // count today.
    ['radicle-stats.json', () => buildRadicleStats(radicle.checkout, radicle.meta)],
    // Design 0008's import, from main's GitHub bridge over a scripted
    // add-on, and the service's answers.
    ['radicle-import.json', () => buildRadicleImport(radicle.checkout, radicle.meta)],
    // Design 0012's tokens, from main's signing-confirmation.js, and its
    // grant files, from main's four stores.
    // x402's payloads come from its code over the main reference's
    // installed SDK (@x402/core and @x402/evm 2.28.0), which meta names.
    ['approvals.json', () => buildApprovals(approvals.checkout, {
      ...approvals.meta,
      packages: require('./approval-x402').x402Packages(reference.checkout, packageVersion),
    }, reference.checkout)],
    // Design 0013's profile catalog, from main's profile-catalog.js and
    // profile-resolver.js.
    ['profiles.json', () => buildProfiles(approvals.checkout, reference.checkout, {
      freedomBrowserCommit: checkedCommit(approvals.checkout, PROFILES_REFERENCE_COMMIT, 'profiles reference'),
      packages: { 'proper-lockfile': packageVersion(createRequire(path.join(reference.checkout, 'package.json')), 'proper-lockfile') },
      nodeVersion: process.version,
      generator: 'vectors/generator/generate.js',
    })],
    // Design 0012's Ethereum dispatcher (APR-5a), from main's
    // page-ethereum.js, page-signing.js and page-sends.js.
    ['eip1193.json', () => buildEip1193(approvals.checkout, reference.checkout, {
      freedomBrowserCommit: checkedCommit(approvals.checkout, EIP1193_REFERENCE_COMMIT, 'eip1193 reference'),
      packages: { ethers: packageVersion(createRequire(path.join(reference.checkout, 'package.json')), 'ethers') },
      nodeVersion: process.version,
      generator: 'vectors/generator/generate.js',
    })],
    // Design 0013's JSON Lines journal (PRF-5d), from main's
    // durable-journal.js.
    ['journal.json', () => buildJournal(approvals.checkout, {
      freedomBrowserCommit: checkedCommit(approvals.checkout, JOURNAL_REFERENCE_COMMIT, 'journal reference'),
      nodeVersion: process.version,
      generator: 'vectors/generator/generate.js',
    })],
    // Design 0013's set-A stores (PRF-5a): vault-meta.json, from main's
    // identity-manager.js, over the main reference's ethers and fake timers.
    ['stores.json', () => buildStores(stores.checkout, reference.checkout, {
      ...stores.meta,
      packages: Object.fromEntries(['ethers', '@sinonjs/fake-timers']
        .map((name) => [name, packageVersion(createRequire(path.join(reference.checkout, 'package.json')), name)])),
    })],
    // Design 0013's SQLite stores (PRF-5g-1): each database's schema, from
    // the stores reference's own modules over the main reference's
    // better-sqlite3, which meta names with the SQLite it bundles.
    ['sqlite.json', () => buildSqlite(stores.checkout, reference.checkout, {
      ...stores.meta,
      packages: { 'better-sqlite3': packageVersion(createRequire(path.join(reference.checkout, 'package.json')), 'better-sqlite3') },
    })],
    // Design 0016's Safe (SAFE-1): the Safe reference's src/main/wallet/safe/
    // over its own protocol-kit and safe-deployments and the browser's test
    // chain, keys.json's accounts as the owners.
    ['safe.json', () => buildSafe(swarmReference.checkout, deterministic['keys.json'], {
      freedomBrowserCommit: checkedCommit(swarmReference.checkout, SAFE_REFERENCE_COMMIT, 'safe reference'),
      nodeVersion: process.version,
      generator: 'vectors/generator/generate.js',
    })],
    // Design 0014's Colibri adapter (COL-1): the colibri reference's worker
    // service and checkpoint check over the real c4w.wasm, every call into
    // it recorded, in worlds scripted from vectors/fixtures/colibri/.
    ['colibri.json', () => buildColibri(colibri.checkout, colibri.meta)],
  ];
  const deterministic = {};
  const checkFile = (filename) => {
    const committed = fs.readFileSync(path.join(OUTPUT, filename), 'utf8');
    const generated = json(deterministic[filename]);
    if (committed !== generated) throw new assert.AssertionError({ message: byteMismatch(filename, committed, generated) });
    console.log(`check: ${filename}`);
  };
  for (const [filename, build] of builders) {
    deterministic[filename] = await build();
    if (mode === 'check') checkFile(filename);
  }
  // Design 0015's window.swarm backend (SWM-1): the swarm reference's
  // src/main/swarm/ over a recording fake node, at bee-js 13.2.0 and
  // core-sdk 0.2.2, and the operation grammar its requests are checked against.
  const swarmFiles = await swarmJob;
  deterministic['swarm.json'] = swarmFiles.swarm;
  deterministic['swarm-grammar.json'] = swarmFiles.grammar;
  if (mode === 'check') {
    checkFile('swarm.json');
    checkFile('swarm-grammar.json');
  } else {
    // Nothing is written until every file is built.
    for (const [filename, contents] of Object.entries(deterministic)) {
      fs.writeFileSync(path.join(OUTPUT, filename), json(contents));
      console.log(`generate: ${filename}`);
    }
  }
  // Every deterministic file is checked before the more expensive fixture checks.
  for (const [filename, builder] of [
    ['fixtures/vaults.json', buildVaults],
    ['fixtures/bee-keystores.json', buildBee],
    ['fixtures/radicle-openssh.json', buildRadicle],
  ]) {
    const destination = path.join(OUTPUT, filename);
    const exists = fs.existsSync(destination);
    assert.ok(mode === 'generate' || exists, `Missing fixture: ${filename}`);
    const previous = exists ? fs.readFileSync(destination, 'utf8') : null;
    const existing = exists ? JSON.parse(previous) : null;
    if (existing) assert.deepEqual(existing.meta, reference.meta, `Reference metadata mismatch: ${filename}`);
    const contents = await builder(reference, existing, mode);
    // The requested legacy coverage extends this file once, without changing
    // any existing random fixture bytes. Later generation preserves all of it.
    const addLegacy = exists && mode === 'generate' && filename === 'fixtures/vaults.json' && !existing.legacyFixtures;
    if (addLegacy) {
      const originalContents = { ...contents };
      delete originalContents.legacyFixtures;
      assert.equal(previous, json(originalContents), `Existing fixture changed: ${filename}`);
      fs.writeFileSync(destination, json(contents));
    } else if (exists) assert.equal(previous, json(contents), `Fixture validation mismatch: ${filename}`);
    else {
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.writeFileSync(destination, json(contents));
    }
    console.log(`${exists ? 'verified' : 'created'}: ${filename}`);
  }
  reference.vault.lockVault();
  console.log('All vectors match the pinned JS reference.');
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
  // A failed check doesn't wait for the swarm vectors' thread.
  swarmWorker?.terminate();
});
