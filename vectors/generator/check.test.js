'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const SOURCE = path.resolve(__dirname, '..');
const REFERENCE = process.env.FREEDOM_BROWSER_CHECKOUT || '/root/herdr/freedom-browser';
const FILES = ['keys.json', 'mnemonic-validation.json', 'identity-formats.json',
  'fixtures/vaults.json', 'fixtures/bee-keystores.json', 'fixtures/radicle-openssh.json',
  'generator/generate.js'];

function corruptedCheck(filename, corrupt) {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-vectors-'));
  for (const file of FILES) {
    const destination = path.join(copy, file);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(SOURCE, file), destination);
  }
  const destination = path.join(copy, filename);
  const contents = JSON.parse(fs.readFileSync(destination, 'utf8'));
  corrupt(contents);
  fs.writeFileSync(destination, JSON.stringify(contents, null, 2) + '\n');
  const result = spawnSync(process.execPath, [path.join(copy, 'generator/generate.js'),
    'check', '--freedom-browser', REFERENCE], { encoding: 'utf8', timeout: 60000 });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  return result.stderr;
}

test('check rejects a changed deterministic private key', () => {
  const stderr = corruptedCheck('keys.json', (contents) => {
    contents.vectors[0].userWallets[0].privateKey = '0x' + '00'.repeat(32);
  });
  assert.match(stderr, /Byte mismatch: keys.json/);
});

test('check decrypts vault fixtures and rejects a damaged authentication tag', () => {
  const stderr = corruptedCheck('fixtures/vaults.json', (contents) => {
    const vault = JSON.parse(contents.fixtures[0].fileContents);
    const encrypted = JSON.parse(vault.encrypted);
    const data = Buffer.from(encrypted.data, 'base64');
    data[data.length - 1] ^= 1;
    encrypted.data = data.toString('base64');
    vault.encrypted = JSON.stringify(encrypted);
    contents.fixtures[0].fileContents = JSON.stringify(vault, null, 2);
  });
  assert.match(stderr, /Incorrect password/);
});

test('check decrypts Bee fixtures and rejects a damaged ciphertext', () => {
  const stderr = corruptedCheck('fixtures/bee-keystores.json', (contents) => {
    const keystore = JSON.parse(contents.fixtures[0].keystore);
    const data = Buffer.from(keystore.Crypto.ciphertext, 'hex');
    data[0] ^= 1;
    keystore.Crypto.ciphertext = data.toString('hex');
    contents.fixtures[0].keystore = JSON.stringify(keystore);
  });
  assert.match(stderr, /incorrect password/i);
});

test('check requires the positive legacy fallback fixture', () => {
  const stderr = corruptedCheck('fixtures/vaults.json', (contents) => {
    delete contents.legacyFixtures;
  });
  assert.match(stderr, /Missing positive legacy vault fixture/);
});

test('check decrypts the positive legacy fallback fixture', () => {
  const stderr = corruptedCheck('fixtures/vaults.json', (contents) => {
    const vault = JSON.parse(contents.legacyFixtures[0].fileContents);
    const payload = JSON.parse(vault.encrypted);
    const data = Buffer.from(payload.data, 'base64');
    data[data.length - 1] ^= 1;
    payload.data = data.toString('base64');
    vault.encrypted = JSON.stringify(payload);
    contents.legacyFixtures[0].fileContents = JSON.stringify(vault, null, 2);
  });
  assert.match(stderr, /Incorrect password/);
});

test('check parses OpenSSH and rejects unequal check integers', () => {
  const stderr = corruptedCheck('fixtures/radicle-openssh.json', (contents) => {
    const identity = contents.fixtures[0].identity;
    const lines = identity.privateKeyFile.trimEnd().split('\n');
    const data = Buffer.from(lines.slice(1, -1).join(''), 'base64');
    let offset = 15;
    // cipher, KDF name, KDF options
    for (let field = 0; field < 3; field += 1) offset += 4 + data.readUInt32BE(offset);
    offset += 4; // key count
    offset += 4 + data.readUInt32BE(offset); // public key blob
    offset += 4; // private section length
    data[offset] ^= 1;
    const base64 = data.toString('base64');
    identity.privateKeyFile = lines[0] + '\n' + base64.match(/.{1,70}/g).join('\n') + '\n' + lines.at(-1) + '\n';
  });
  assert.match(stderr, /AssertionError/);
  assert.match(stderr, /parseOpenSSH/);
});
