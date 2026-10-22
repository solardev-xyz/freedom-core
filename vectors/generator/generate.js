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
const { buildDweb } = require('./dweb');
const { buildStreams } = require('./streams');

const REFERENCE_COMMIT = 'fb540328162839e68150fe2c5e517edb86734d1c';
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

function loadReference(checkout) {
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: checkout, encoding: 'utf8' }).trim();
  assert.equal(commit, REFERENCE_COMMIT, 'Use the pinned reference commit');
  // Include staged, unstaged, and untracked source/config changes in this guard.
  const status = execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: checkout, encoding: 'utf8' });
  assert.equal(status, '', 'The reference checkout must be clean (node_modules is ignored)');
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
  const args = process.argv.slice(2);
  assert.ok(args.length === 3 && ['generate', 'check'].includes(args[0]) && args[1] === '--freedom-browser',
    'Usage: node vectors/generator/generate.js <generate|check> --freedom-browser <checkout>');
  const [mode, , checkout] = args;
  const reference = loadReference(path.resolve(checkout));
  const deterministic = {
    'keys.json': buildKeys(reference),
    'mnemonic-validation.json': buildValidation(reference),
    'identity-formats.json': buildIdentities(reference),
    // Its own meta: the shared one is frozen into the existing fixtures.
    'signing.json': await buildSigning(reference, mnemonicFor, {
      ...reference.meta,
      packages: { ...reference.meta.packages, ...reference.signingPackages },
    }),
    'naming-replay.json': await buildNamingReplay(reference.checkout, reference.ethers, {
      ...reference.meta,
      packages: { ...reference.meta.packages, '@sinonjs/fake-timers': packageVersion(createRequire(path.join(reference.checkout, 'package.json')), '@sinonjs/fake-timers') },
    }),
    'naming.json': await buildNaming(reference.checkout, reference.ethers, {
      ...reference.meta,
      packages: { ...reference.meta.packages, '@adraffy/ens-normalize': packageVersion(createRequire(path.join(reference.checkout, 'package.json')), '@adraffy/ens-normalize') },
    }),
    // Signed with the first test wallet; ethers only hashes them.
    'chain.json': await buildChain(reference.checkout, reference.ethers,
      reference.derivation.deriveUserWallet(mnemonicFor('abandon-12'), 0).privateKey, reference.meta),
    // Its broadcasts are signed with the same wallet.
    'chain-replay.json': await buildChainReplay(reference.checkout, reference.ethers,
      reference.derivation.deriveUserWallet(mnemonicFor('abandon-12'), 0).privateKey, {
        ...reference.meta,
        packages: { ...reference.meta.packages, '@sinonjs/fake-timers': packageVersion(createRequire(path.join(reference.checkout, 'package.json')), '@sinonjs/fake-timers') },
      }),
    'dweb.json': await buildDweb(reference.checkout, reference.ethers, reference.meta),
    // The design's, with no reference: its meta is the shared one.
    'streams.json': buildStreams(reference.meta),
  };
  // Check every deterministic file before doing the more expensive fixture checks.
  for (const [filename, contents] of Object.entries(deterministic)) {
    const destination = path.join(OUTPUT, filename);
    if (mode === 'generate') fs.writeFileSync(destination, json(contents));
    else assert.equal(fs.readFileSync(destination, 'utf8'), json(contents), `Byte mismatch: ${filename}`);
    console.log(`${mode}: ${filename}`);
  }
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
});
