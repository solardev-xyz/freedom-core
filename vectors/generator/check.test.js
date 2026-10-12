'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const SOURCE = path.resolve(__dirname, '..');
const REFERENCE = process.env.FREEDOM_BROWSER_CHECKOUT || '/root/herdr/freedom-browser';
const FILES = ['keys.json', 'mnemonic-validation.json', 'identity-formats.json', 'signing.json', 'naming.json', 'naming-replay.json',
  'fixtures/vaults.json', 'fixtures/bee-keystores.json', 'fixtures/radicle-openssh.json',
  'generator/generate.js', 'generator/signing.js', 'generator/naming.js', 'generator/naming-replay.js'];

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

test('check rejects a changed signature', () => {
  const stderr = corruptedCheck('signing.json', (contents) => {
    const entry = contents.typedData.find((item) => item.result.status === 'success');
    entry.result.signature = entry.result.signature.slice(0, -2) + '1b';
  });
  assert.match(stderr, /Byte mismatch: signing.json/);
});

test('check rejects a changed naming result', () => {
  const stderr = corruptedCheck('naming.json', (contents) => {
    contents.contenthash[0].js.decoded = 'Qm' + 'x'.repeat(44);
  });
  assert.match(stderr, /Byte mismatch: naming.json/);
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

test('check rejects a changed replay request', () => {
  const stderr = corruptedCheck('naming-replay.json', (contents) => {
    contents.scenarios[0].io[0].params = ['0x1'];
  });
  assert.match(stderr, /Byte mismatch: naming-replay.json/);
});

// The replay runs in this process: it must not see or leave global state.
const replay = require('./naming-replay');

function referenceEthers() {
  return require('node:module').createRequire(path.join(REFERENCE, 'package.json'))('ethers').ethers;
}

function globalsSnapshot(ethers) {
  return {
    random: Math.random,
    date: Date,
    setTimeout,
    load: require('node:module')._load,
    getUrl: new ethers.FetchRequest('https://snapshot.invalid').getUrlFunc,
    env: { ETH_RPC: process.env.ETH_RPC, TEZOS_RPC: process.env.TEZOS_RPC },
  };
}

function definition(ethers, id) {
  return replay.scenarioDefinitions(ethers).find((scenario) => scenario.id === id);
}

test('replay ignores the ambient resolver environment', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const clean = await replay.runScenario(REFERENCE, ethers, FakeTimers, definition(ethers, 'quorum-agree'));
  process.env.ETH_RPC = 'https://ambient.rpc.example';
  process.env.TEZOS_RPC = 'https://ambient.tez.example';
  try {
    assert.deepEqual(await replay.runScenario(REFERENCE, ethers, FakeTimers, definition(ethers, 'quorum-agree')), clean);
    assert.equal(process.env.ETH_RPC, 'https://ambient.rpc.example');
    assert.equal(process.env.TEZOS_RPC, 'https://ambient.tez.example');
  } finally {
    delete process.env.ETH_RPC;
    delete process.env.TEZOS_RPC;
  }
});

test('replay leaves its input unchanged and repeats exactly', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const scenario = definition(ethers, 'ccip-slow-gateway-then-another-name');
  const before = structuredClone(scenario);
  const first = await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario);
  assert.deepEqual(scenario, before);
  assert.deepEqual(await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario), first);
});

test('replay restores every global, also when setup fails', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const before = globalsSnapshot(ethers);
  await replay.runScenario(REFERENCE, ethers, FakeTimers, definition(ethers, 'quorum-agree'));
  assert.deepEqual(globalsSnapshot(ethers), before);
  await assert.rejects(replay.runScenario(path.join(os.tmpdir(), 'no-such-checkout'), ethers, FakeTimers, definition(ethers, 'quorum-agree')), /ENOENT/);
  assert.deepEqual(globalsSnapshot(ethers), before);
});

test('replay fails loudly on unscripted I/O', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const unscriptedCall = structuredClone(definition(ethers, 'quorum-agree'));
  delete unscriptedCall.world.calls.resolve;
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, unscriptedCall), /unscripted I\/O: resolve:contenthash call to/);
  const undeclaredGateway = structuredClone(definition(ethers, 'ccip-fast-gateway'));
  delete undeclaredGateway.world.gateways;
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, undeclaredGateway), /undeclared gateway gw\.example/);
});
