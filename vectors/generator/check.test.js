'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const SOURCE = path.resolve(__dirname, '..');
const REFERENCE = process.env.FREEDOM_BROWSER_CHECKOUT || '/root/herdr/freedom-browser';
// The Radicle vectors' reference (generate.js, RADICLE_REFERENCE_COMMIT).
const RADICLE_REFERENCE = process.env.FREEDOM_BROWSER_RADICLE_CHECKOUT || '/root/herdr/freedom-browser-wt/radicle-reference';
// The approvals vectors' reference (generate.js, APPROVALS_REFERENCE_COMMIT).
const APPROVALS_REFERENCE = process.env.FREEDOM_BROWSER_APPROVALS_CHECKOUT || '/root/herdr/freedom-browser-wt/approvals-reference';
const FILES = ['keys.json', 'mnemonic-validation.json', 'identity-formats.json', 'signing.json', 'naming.json', 'naming-replay.json',
  'chain.json', 'chain-replay.json', 'fixtures/vaults.json', 'fixtures/bee-keystores.json', 'fixtures/radicle-openssh.json',
  'generator/generate.js', 'generator/signing.js', 'generator/naming.js', 'generator/naming-replay.js', 'generator/chain.js',
  'generator/chain-replay.js'];

FILES.push('dweb.json', 'dweb-verify-plans.json', 'generator/dweb.js');
FILES.push('streams.json', 'generator/streams.js');
FILES.push('radicle-reads.json', 'generator/radicle-reads.js');
FILES.push('radicle-blob.json', 'generator/radicle-blob.js');
FILES.push('radicle-network.json', 'generator/radicle-network.js');
FILES.push('radicle-stats.json', 'generator/radicle-stats.js');
FILES.push('radicle-import.json', 'generator/radicle-import.js');
FILES.push('approvals.json', 'generator/approvals.js', 'generator/approval-stores.js');
FILES.push('profiles.json', 'generator/profiles.js');
FILES.push('secrets.json', 'generator/secrets.js');
FILES.push('keystore.json', 'generator/keystore.js', 'generator/hpke.js');
FILES.push('generator/approval-rules.js', 'generator/approval-decisions.js');

function corruptedCheck(filename, corrupt) {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-vectors-'));
  let result;
  // Everything after the directory exists, setup included, is undone.
  try {
    for (const file of FILES) {
      const destination = path.join(copy, file);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.copyFileSync(path.join(SOURCE, file), destination);
    }
    const destination = path.join(copy, filename);
    const contents = JSON.parse(fs.readFileSync(destination, 'utf8'));
    corrupt(contents);
    fs.writeFileSync(destination, JSON.stringify(contents, null, 2) + '\n');
    result = spawnSync(process.execPath, [path.join(copy, 'generator/generate.js'),
      'check', '--freedom-browser', REFERENCE, '--radicle-browser', RADICLE_REFERENCE,
      '--approvals-browser', APPROVALS_REFERENCE], { encoding: 'utf8', timeout: 60000 });
  } finally {
    fs.rmSync(copy, { recursive: true, force: true });
  }
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

test('check rejects a changed chain-data codec result', () => {
  const stderr = corruptedCheck('chain.json', (contents) => {
    const entry = contents.normalization.find((item) => item.id === 'decimal-negative');
    entry.js.params = entry.js.params.replace('0x-1', '0x1');
  });
  assert.match(stderr, /Byte mismatch: chain.json/);
});

test('check rejects a changed chain-data aggregate text', () => {
  const stderr = corruptedCheck('chain.json', (contents) => {
    contents.failure_texts.request[0].failures[0].message_json = '"other"';
  });
  assert.match(stderr, /Byte mismatch: chain.json/);
});

test('check rejects a changed Myotis classification', () => {
  const stderr = corruptedCheck('chain.json', (contents) => {
    contents.myotis.reads.find((item) => item.id === 'invalid-params').js.error.final = false;
  });
  assert.match(stderr, /Byte mismatch: chain.json/);
});

test('check rejects a changed log-scan rank and a changed broadcast refusal', () => {
  for (const corrupt of [
    (contents) => { contents.ant_profile.errors[0].js.rank = 3; },
    (contents) => { contents.broadcast_refusals.errors[0].design = { class: 'ambiguous' }; },
  ]) {
    assert.match(corruptedCheck('chain.json', corrupt), /Byte mismatch: chain.json/);
  }
});

test('check rejects a changed chain replay exchange', () => {
  const stderr = corruptedCheck('chain-replay.json', (contents) => {
    const exchange = contents.scenarios.find((scenario) => scenario.id === 'router-quorum-settles-at-m').io[2];
    exchange.outcome = 'answered';
  });
  assert.match(stderr, /Byte mismatch: chain-replay.json/);
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

test('replay patches the reference per scenario, and loudly', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const scenario = definition(ethers, 'deviation-ccip-urls');
  const patched = await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario);
  assert.deepEqual(patched.patches.map((patch) => patch.id), ['ccip-urls']);
  // A patched module never outlives its scenario.
  const plain = await replay.runScenario(REFERENCE, ethers, FakeTimers, { ...scenario, deviation: undefined, patches: [] });
  assert.notDeepEqual(plain.steps, patched.steps);
  assert.deepEqual(await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario), patched);
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, { ...scenario, patches: ['no-such-patch'] }), /unknown patch no-such-patch/);
  // An edit whose text isn't there exactly once fails the run.
  replay.PATCHES.stale = () => ({ text: 'stale', source: { 'ens-resolver.js': { edits: [['no such text', '']], append: [] } } });
  try {
    await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, { ...scenario, patches: ['stale'] }), /patch for ens-resolver\.js: 0 matches/);
  } finally {
    delete replay.PATCHES.stale;
  }
  // So does one for a module the resolver loads lazily, before any global
  // changes.
  const before = globalsSnapshot(ethers);
  replay.PATCHES.staleLazy = () => ({ text: 'stale', source: { 'ens/myotis-resolver.js': { edits: [['no such text', '']], append: [] } } });
  try {
    await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, { ...definition(ethers, 'myotis-ccip'), patches: ['staleLazy'] }), /patch for ens\/myotis-resolver\.js: 0 matches/);
  } finally {
    delete replay.PATCHES.staleLazy;
  }
  assert.deepEqual(globalsSnapshot(ethers), before);
});

test('replay\'s request-size patch leaves verifier adapters\' CCIP alone', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  // Myotis' own CCIP with a 3,000-byte callData over an 8 KiB frame: the
  // adapter's networking is main's, so the patch changes nothing.
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const scenario = structuredClone(definition(ethers, 'myotis-ccip'));
  scenario.world.bounds = { messageBytes: 8192 };
  const UR = '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe';
  scenario.world.myotis.calls.resolve = { revert: '0x556f1830' + coder.encode(
    ['address', 'string[]', 'bytes', 'bytes4', 'bytes'],
    [UR, ['https://gw.example/{sender}/{data}.json'], '0x' + 'ab'.repeat(3000), '0xdeadbeef', '0x09']).slice(2) };
  const plain = await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario);
  const patched = await replay.runScenario(REFERENCE, ethers, FakeTimers, { ...scenario, deviation: 'request-size', patches: ['request-size'] });
  assert.ok(plain.io.some((item) => item.kind === 'gateway'), 'the adapter fetched its gateway');
  assert.deepEqual(patched.steps, plain.steps);
  assert.deepEqual(patched.io, plain.io);
});

test('core sizes substitute endpoint references only where results name endpoints', () => {
  const refOf = (text) => ({ 'a.rpc.example': 'https://a.rpc.example/x', 'https://t1.tez.example': 'https://t1.tez.example' })[text];
  const value = {
    type: 'ok',
    record: { ttl: { urls: ['https://t1.tez.example'] }, agreed: ['a.rpc.example'] },
    urls: ['a.rpc.example'],
    trust: { agreed: ['a.rpc.example', 'myotis-p2p'], dissented: [], queried: ['a.rpc.example'], prover: 'a.rpc.example', block: { hash: 'a.rpc.example' } },
    groups: [{ value: 'a.rpc.example', urls: ['https://t1.tez.example'] }],
  };
  const ref = { ref: 'https://a.rpc.example/x' };
  assert.deepEqual(replay.__toCore(value, refOf), {
    ...value,
    trust: { agreed: [ref, 'myotis-p2p'], dissented: [], queried: [ref], prover: ref, block: { hash: 'a.rpc.example' } },
    groups: [{ value: 'a.rpc.example', urls: [{ ref: 'https://t1.tez.example' }] }],
  });
  assert.equal(replay.__toCore('text', refOf), 'text');
});

test('replay\'s size patches refuse a host that two endpoint URLs share', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  // Three URLs on a.rpc.example: a wave queries more than one, so the
  // host in its trust lists could name any of them.
  const scenario = structuredClone(definition(ethers, 'deviation-reply-size'));
  scenario.world.endpoints = ['x', 'y', 'z'].map((path) => `https://a.rpc.example/${path}`);
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, scenario), /one host from several endpoint URLs/);
});

test('a host named like an Object property is declared only when the world lists it', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  for (const host of ['constructor', '__proto__', 'unlisted.example']) {
    const scenario = structuredClone(definition(ethers, 'rpc-redirect-then-429'));
    scenario.world.hosts['a.rpc.example'].location = `https://${host}/`;
    await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, scenario), new RegExp(`undeclared RPC endpoint ${host}`));
  }
  // Listed, it is declared and answers.
  const scenario = structuredClone(definition(ethers, 'rpc-redirect-then-429'));
  scenario.world.hosts['a.rpc.example'].location = 'https://constructor/';
  scenario.world.hosts.constructor = {};
  const result = await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario);
  assert.ok(result.io.some((item) => item.host === 'constructor'));
});

test('replay\'s verified-failure-text patch refuses failures returned as a status', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  // A NameNFT call through Myotis that comes back { status: 'error' }.
  const scenario = structuredClone(definition(ethers, 'myotis-wns-call-unavailable'));
  scenario.world.network = { ...scenario.world.network, verification: { order: ['myotis'], preferVerified: false } };
  Object.assign(scenario, { deviation: 'verified-failure-text', patches: ['verified-failure-text'] });
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, scenario), /failure returned as a status/);
});

test('replay\'s memory-budgets patch refuses what it can\'t model', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const run = (sessionBytes) => {
    const scenario = structuredClone(definition(ethers, 'deviation-memory-budgets'));
    scenario.world.bounds = { sessionBytes };
    return replay.runScenario(REFERENCE, ethers, FakeTimers, scenario);
  };
  // The first probes' requests cross 100 bytes: the core charges a poll's
  // requests together, which the patch can't model.
  await assert.rejects(run(100), /a request crossed the budget/);
  // Nothing crosses a megabyte: no deviation to show.
  await assert.rejects(run(1 << 20), /finished under its budget/);
  // A redirect is a hop, not an exchange the core charges.
  const redirected = structuredClone(definition(ethers, 'deviation-memory-budgets'));
  redirected.world.hosts = { 'a.rpc.example': { statuses: [302], location: 'https://r.rpc.example/' }, 'r.rpc.example': {} };
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, redirected), /no redirects or 429s/);
  // An empty name ends at once, with no answer to cross the budget.
  const empty = structuredClone(definition(ethers, 'deviation-memory-budgets'));
  empty.steps[0].call = { fn: 'resolveEnsContent', args: [''] };
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, empty), /ended otherwise/);
  // A name is charged as the core keys it, normalized: a decomposed name
  // and its composed form record the same trace. At 3,000 bytes the first
  // block answer crosses; charged as written, the decomposed name's 800
  // bytes more would cross at the head answers instead.
  const named = (name) => {
    const scenario = structuredClone(definition(ethers, 'deviation-memory-budgets'));
    scenario.steps[0].call = { fn: 'resolveEnsContent', args: [name] };
    scenario.world.bounds = { sessionBytes: 3_000 };
    return replay.runScenario(REFERENCE, ethers, FakeTimers, scenario);
  };
  const decomposed = `${('e' + String.fromCharCode(0x301)).repeat(100)}.eth`;
  const trace = (vector) => [vector.steps.map((s) => s.results), vector.io.map((e) => [e.t, e.end, e.host, e.outcome])];
  assert.deepEqual(trace(await named(decomposed)), trace(await named(decomposed.normalize('NFC'))));
});

test('verified revert data is bytes, checked in constant stack', () => {
  const { revertData } = replay;
  assert.equal(revertData({ data: '0xABcd' }), '0xABcd');
  assert.equal(revertData({ info: { error: { data: '0x12' } } }), '0x12');
  for (const data of ['0x123', '0X12', '0xzz', ' 0x12', 12, undefined]) assert.equal(revertData({ data }), null);
  // V8's unoptimized regexp tier backtracks on the stack: a 2 MB revert
  // must still be recognized there.
  const { execFileSync } = require('node:child_process');
  const script = `const { revertData } = require(${JSON.stringify(require.resolve('./naming-replay.js'))});
    const data = '0x' + 'ab'.repeat(2_000_000);
    process.stdout.write(String(revertData({ data }) === data));`;
  assert.equal(execFileSync(process.execPath, ['--no-regexp-optimization', '-e', script], { encoding: 'utf8' }), 'true');
});

test('replay\'s overall-deadline patch refuses what it can\'t model', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const scenario = structuredClone(definition(ethers, 'deviation-overall-deadline'));
  scenario.steps.push({ after: 1000, call: scenario.steps[0].call });
  await assert.rejects(replay.runScenario(REFERENCE, ethers, FakeTimers, scenario), /one step with one call/);
});

test('replay\'s response-caps patch leaves verifier adapters\' CCIP alone', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  // Myotis' own CCIP with a gateway answer over the lowered cap: the
  // adapter keeps its 4 MiB cap, so the patch changes nothing.
  const scenario = structuredClone(definition(ethers, 'myotis-ccip'));
  scenario.world.bounds = { answerBytes: 4096 };
  scenario.world.gateways['gw.example'].body = JSON.stringify({ data: '0xcafe', pad: 'x'.repeat(5000) });
  const plain = await replay.runScenario(REFERENCE, ethers, FakeTimers, scenario);
  const patched = await replay.runScenario(REFERENCE, ethers, FakeTimers, { ...scenario, deviation: 'response-caps', patches: ['response-caps'] });
  assert.deepEqual(patched.steps, plain.steps);
  assert.deepEqual(patched.io, plain.io);
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

test('replay transport keeps ethers\' cancel and timeout semantics', async () => {
  const ethers = referenceEthers();
  const FakeTimers = replay.loadFakeTimers(REFERENCE);
  const probe = (options, hosts = {}) => replay.runScenario(REFERENCE, ethers, FakeTimers, {
    id: 'transport-probe',
    world: { endpoints: ['https://a.rpc.example'], hosts: { 'a.rpc.example': { delay: 10, ...hosts } } },
    steps: [{ call: { fn: '$fetch', args: ['https://a.rpc.example', options] } }],
  });
  const outcome = async (options, hosts) => {
    const run = await probe(options, hosts);
    const [result] = run.steps[0].results;
    return { thrown: result.thrown ?? null, settled: result.settled, io: run.io[0] };
  };
  // A cancel at the reply's own instant wins, as checkSignal() does natively.
  const sameInstant = await outcome({ cancelAt: 10 });
  assert.match(sameInstant.thrown, /cancelled/);
  assert.equal(sameInstant.io.outcome, 'answered');
  assert.equal(sameInstant.io.rejected.code, 'CANCELLED');
  // The inactivity timeout, either side of a 10 ms reply.
  assert.match((await outcome({ timeout: 9 })).thrown, /request timeout/);
  // Zero turns the timer off.
  assert.equal((await outcome({ timeout: 0 })).thrown, null);
  const inTime = await outcome({ timeout: 11 });
  assert.equal(inTime.thrown, null);
  assert.equal(inTime.io.rejected, undefined);
  // A hang rejects at ethers' default 300 s and the exchange stays open.
  const hang = await outcome({}, { hang: true });
  assert.match(hang.thrown, /request timeout/);
  assert.equal(hang.settled, 300_000);
  assert.equal(hang.io.outcome, 'open');
});

test('replay attributes every verifier raw call to its operation', async () => {
  const vectors = JSON.parse(fs.readFileSync(path.join(SOURCE, 'naming-replay.json'), 'utf8'));
  const attributed = (scenario) => {
    const ops = new Map(scenario.io.filter((e) => e.kind === 'verified-op').map((e) => [e.id, e]));
    for (const entry of scenario.io) {
      if (entry.kind !== 'verified' && entry.within === undefined) continue;
      const op = ops.get(entry.within);
      assert.ok(op, `${scenario.id}: exchange ${entry.id} has no operation`);
      assert.ok(entry.t >= op.t && (op.end === null || entry.t <= op.end), `${scenario.id}: exchange ${entry.id} outside operation ${op.id}`);
      if (entry.kind === 'verified') assert.equal(entry.host, op.host, `${scenario.id}: exchange ${entry.id} attributed to another verifier`);
    }
  };
  for (const scenario of vectors.scenarios) attributed(scenario);
  // Two operations at once, each owning its raw call: Colibri's, as the
  // pinned reference runs them. Main's #1076 keeps names off Colibri, so
  // the recorded scenario asks it nothing.
  const ethers = referenceEthers();
  const plain = { ...definition(ethers, 'colibri-concurrent'), patches: [] };
  const concurrent = await replay.runScenario(REFERENCE, ethers, replay.loadFakeTimers(REFERENCE), plain);
  attributed(concurrent);
  const owners = concurrent.io.filter((e) => e.kind === 'verified').map((e) => e.within);
  assert.equal(new Set(owners).size, 2, 'each concurrent operation owns its raw call');
});

// Main's #1076: no recorded scenario asks Colibri for a name, and each the
// reference patch changes records it, with the pinned reference's results.
test('naming replay asks Colibri nothing, and records main\'s #1076 where it applies', () => {
  const vectors = JSON.parse(fs.readFileSync(path.join(SOURCE, 'naming-replay.json'), 'utf8'));
  for (const scenario of vectors.scenarios) {
    assert.ok(!scenario.io.some((e) => e.host === 'colibri'), `${scenario.id} asks Colibri`);
    for (const result of scenario.steps.flatMap((step) => step.results)) {
      assert.notEqual(result.value?.trust?.method, 'colibri', `${scenario.id}: a Colibri label`);
    }
  }
  const patched = vectors.scenarios.filter((s) => (s.patches ?? []).some((p) => p.id === 'no-colibri-names'));
  assert.deepEqual(patched.map((s) => s.id).sort(), [...replay.NO_COLIBRI_NAMES_SCENARIOS].sort());
  for (const scenario of patched) {
    assert.ok(Array.isArray(scenario.unpatched), `${scenario.id}: no unpatched results`);
  }
  // The ports of main's tests: the pinned reference took Colibri's forgery.
  for (const scenario of patched.filter((s) => s.id.startsWith('no-colibri-names-'))) {
    assert.match(JSON.stringify(scenario.unpatched), /"method":"colibri"/, `${scenario.id}: the pinned reference didn't use Colibri`);
  }
});

// The chain replay runs in this process too.
const chainReplay = require('./chain-replay');
const TEST_KEY = '0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727';

function chainDefinition(id) {
  return chainReplay.scenarioDefinitions(referenceEthers(), TEST_KEY).find((scenario) => scenario.id === id);
}

function chainGlobals() {
  return { fetch: globalThis.fetch, date: Date, setTimeout, load: require('node:module')._load };
}

test('chain replay leaves its input unchanged and repeats exactly', async () => {
  const FakeTimers = chainReplay.loadFakeTimers(REFERENCE);
  for (const id of ['router-colibri-cooldown-escalation', 'ant-index-first-wallet-scan']) {
    const scenario = chainDefinition(id);
    const before = structuredClone(scenario);
    const first = await chainReplay.runScenario(REFERENCE, FakeTimers, scenario);
    assert.deepEqual(scenario, before);
    assert.deepEqual(await chainReplay.runScenario(REFERENCE, FakeTimers, scenario), first);
  }
});

test('chain replay restores every global, also when setup fails', async () => {
  const FakeTimers = chainReplay.loadFakeTimers(REFERENCE);
  const before = chainGlobals();
  await chainReplay.runScenario(REFERENCE, FakeTimers, chainDefinition('router-quorum-settles-at-m'));
  assert.deepEqual(chainGlobals(), before);
  await assert.rejects(chainReplay.runScenario(path.join(os.tmpdir(), 'no-such-checkout'), FakeTimers, chainDefinition('router-quorum-settles-at-m')), /ENOENT/);
  assert.deepEqual(chainGlobals(), before);
  // No router module survives its scenario.
  assert.ok(!Object.keys(require.cache).some((key) => key.includes(`${path.sep}src${path.sep}main${path.sep}networks${path.sep}`)));
});

test('chain replay fails loudly on unscripted I/O', async () => {
  const FakeTimers = chainReplay.loadFakeTimers(REFERENCE);
  const undeclared = structuredClone(chainDefinition('router-quorum-settles-at-m'));
  delete undeclared.world.rpc['https://c.example'];
  await assert.rejects(chainReplay.runScenario(REFERENCE, FakeTimers, undeclared), /undeclared RPC endpoint https:\/\/c\.example/);
  const myotis = structuredClone(chainDefinition('router-myotis-balance'));
  delete myotis.world.myotis[100].ops.account;
  await assert.rejects(chainReplay.runScenario(REFERENCE, FakeTimers, myotis), /unscripted Myotis account on chain 100/);
  const colibri = structuredClone(chainDefinition('router-colibri-deadline'));
  delete colibri.world.colibri;
  await assert.rejects(chainReplay.runScenario(REFERENCE, FakeTimers, colibri), /unscripted Colibri eth_getBalance/);
  const dns = structuredClone(chainDefinition('blockscout-redirect-dns-fails'));
  delete dns.world.dns;
  await assert.rejects(chainReplay.runScenario(REFERENCE, FakeTimers, dns), /undeclared DNS name nowhere\.example/);
});

test('chain replay attributes every request to its call and every hop to its page', () => {
  const vectors = JSON.parse(fs.readFileSync(path.join(SOURCE, 'chain-replay.json'), 'utf8'));
  const ids = new Set();
  for (const scenario of vectors.scenarios) {
    assert.ok(!ids.has(scenario.id), `${scenario.id} twice`);
    ids.add(scenario.id);
    const byId = new Map(scenario.io.map((entry) => [entry.id, entry]));
    for (const entry of scenario.io) {
      if (entry.kind === 'event') continue;
      assert.equal(typeof entry.call, 'number', `${scenario.id}: ${entry.kind} ${entry.id} has no call`);
      const calls = scenario.steps[entry.step].calls;
      assert.ok(entry.call < calls.length && entry.t >= calls[entry.call].started, `${scenario.id}: ${entry.id} before its call`);
      if (['blockscout', 'dns'].includes(entry.kind)) assert.equal(byId.get(entry.within)?.kind, 'blockscout-page', `${scenario.id}: ${entry.id}`);
      if (entry.kind === 'blockscout-page') assert.equal(byId.get(entry.within)?.kind, 'blockscout-read', `${scenario.id}: ${entry.id}`);
      if (entry.kind === 'rpc') assert.match(entry.body, /^\{"jsonrpc":"2\.0","id":0,"method":"/);
    }
  }
  // No key in the file is an encoding: values are text.
  const keys = (value) => (Array.isArray(value) ? value.flatMap(keys) : value && typeof value === 'object'
    ? Object.entries(value).flatMap(([key, item]) => [key, ...keys(item)]) : []);
  assert.deepEqual(keys(vectors).filter((key) => key.startsWith('$')), []);
});

test('chain replay records values as JSON text, apart from its encodings', () => {
  const { jsonText, jsonField, entriesOf, textField, recordError } = chainReplay;
  // A missing value and values that look like the old tags stay apart.
  assert.deepEqual(jsonField('result', undefined), { result_undefined: true });
  assert.deepEqual(jsonField('result', { $undefined: true }), { result_json: '{"$undefined":true}' });
  assert.deepEqual(jsonField('result', { $repeat: { head: '', unit: 'x', count: 2, tail: '' } }), { result_json: '{"$repeat":{"head":"","unit":"x","count":2,"tail":""}}' });
  assert.deepEqual(entriesOf({ result: undefined, source: 'quorum' }), [{ key: 'result', undefined: true }, { key: 'source', json: '"quorum"' }]);
  // Every value JSON.parse makes survives its text.
  for (const text of ['-0', '1e400', '-1e400', '{"__proto__":1,"b":[null,true,"x"]}']) assert.equal(jsonText(JSON.parse(text)), text);
  assert.ok(Object.is(JSON.parse(jsonText(-0)), -0));
  const lone = String.fromCharCode(0xd800);
  assert.equal(jsonText(lone), `"${String.fromCharCode(92)}ud800"`);
  assert.equal(JSON.parse(jsonText(lone)), lone);
  const deep = `${'['.repeat(600)}${']'.repeat(600)}`;
  assert.equal(jsonText(JSON.parse(deep)), deep);
  // What no record could keep fails the generation.
  assert.throws(() => jsonText({ a: undefined }), /nested undefined/);
  assert.throws(() => jsonText([undefined]), /nested undefined/);
  assert.throws(() => jsonText(Number.NaN), /NaN/);
  assert.throws(() => jsonText(() => 1), /function/);
  // A large text takes its field's repeat form, verified.
  const body = `{"result":"0x${'0'.repeat(128)}${'61'.repeat(40_000)}00"}`;
  const { body_repeat: repeat } = textField('body', body);
  assert.equal(repeat.head + repeat.unit.repeat(repeat.count) + repeat.tail, body);
  assert.equal(repeat.length, body.length);
  assert.deepEqual(textField('body', 'short'), { body: 'short' });
  assert.throws(() => textField('body', Array.from({ length: 70_000 }, (_, i) => String.fromCharCode(33 + ((i * 7919) % 90))).join('')), /no repeat form/);
  // A thrown error keeps its class, name, message and own properties in order.
  const error = Object.assign(new Error('execution reverted'), { code: 3, data: undefined });
  assert.deepEqual(recordError(error), {
    class: 'Error', name: 'Error', message_json: '"execution reverted"',
    props: [{ key: 'code', json: '3' }, { key: 'data', undefined: true }],
  });
});

test('chain replay keeps the router\'s values as data, literal tags included', async () => {
  const FakeTimers = chainReplay.loadFakeTimers(REFERENCE);
  const resultOf = (run, step) => run.steps[step].results[0].value.find((entry) => entry.key === 'result');
  const repeat = await chainReplay.runScenario(REFERENCE, FakeTimers, chainDefinition('boundary-result-literal-repeat-tag'));
  assert.deepEqual(resultOf(repeat, 0), { key: 'result', json: '{"$repeat":{"head":"","unit":"x","count":2,"tail":""}}' });
  const undef = await chainReplay.runScenario(REFERENCE, FakeTimers, chainDefinition('boundary-result-literal-undefined-tag'));
  assert.deepEqual(resultOf(undef, 0), { key: 'result', json: '{"$undefined":true}' });
  assert.deepEqual(undef.steps[1].results[0].thrown.props.find((entry) => entry.key === 'data'), { key: 'data', json: '{"$undefined":true}' });
  const empty = await chainReplay.runScenario(REFERENCE, FakeTimers, chainDefinition('boundary-result-empty-body'));
  assert.deepEqual(resultOf(empty, 0), { key: 'result', undefined: true });
  assert.deepEqual(resultOf(empty, 1), { key: 'result', json: 'null' });
});

test('chain replay fails when a fixture drifts from its source test\'s settle time', async () => {
  const FakeTimers = chainReplay.loadFakeTimers(REFERENCE);
  // chain-data-router.test.js:1842 answers the full range at once; a 10 ms
  // reply moves the settle time off the test's 5,000 ms.
  const drifted = structuredClone(chainDefinition('truncation-direct-check-one-attempt'));
  for (const plan of Object.values(drifted.world.rpc)) plan.rules[0].then.delay = 10;
  await assert.rejects(chainReplay.runScenario(REFERENCE, FakeTimers, drifted), /settled after 5010 ms, not 5000/);
  const bounded = structuredClone(chainDefinition('ant-index-blockscout-hung'));
  bounded.steps[1].calls[0].expect_settle_max_ms = 1000;
  await assert.rejects(chainReplay.runScenario(REFERENCE, FakeTimers, bounded), /settled after 25000 ms, over 1000/);
});

test('check rejects a changed dweb outcome', () => {
  const stderr = corruptedCheck('dweb.json', (contents) => {
    const entry = contents.requests.find((item) => item.id === 'bzz-headers-allowlist');
    entry.js.fetch.headers.push(['cookie', 'a=1']);
  });
  assert.match(stderr, /Byte mismatch: dweb.json/);
});

test('check rejects a changed dweb validation expectation', () => {
  const stderr = corruptedCheck('dweb.json', (contents) => {
    const entry = contents.validation.find((item) => item.id === 'path-bzz-dot-dot');
    entry.expect = 'valid';
  });
  assert.match(stderr, /Byte mismatch: dweb.json/);
});

test('check rejects a changed verify plan', () => {
  const stderr = corruptedCheck('dweb-verify-plans.json', (contents) => {
    const entry = contents.requests.find((item) => item.id === 'bzz-hash-verify');
    entry.plan.verify.trust.content = 'node_asserted';
  });
  assert.match(stderr, /Byte mismatch: dweb-verify-plans.json/);
});

test('check rejects a changed verify validation expectation', () => {
  const stderr = corruptedCheck('dweb-verify-plans.json', (contents) => {
    const entry = contents.validation.find((item) => item.id === 'root-swarm-63');
    entry.expect = 'valid';
  });
  assert.match(stderr, /Byte mismatch: dweb-verify-plans.json/);
});

test('check rejects a changed stream expectation', () => {
  const stderr = corruptedCheck('streams.json', (contents) => {
    const entry = contents.sender.find((item) => item.id === 'abort-purges-queued-data');
    entry.steps.find((step) => step.write)?.write.unshift(['data', 41, 1000, 50000]);
  });
  assert.match(stderr, /Byte mismatch: streams.json/);
});

test('check rejects a changed secrets-file transition', () => {
  const stderr = corruptedCheck('secrets.json', (contents) => {
    const entry = contents.transitions.find((item) => item.id === 'begin-fifth-refused');
    entry.refused = 'named';
  });
  assert.match(stderr, /Byte mismatch: secrets.json/);
});

test('check rejects a changed secrets-file ciphertext', () => {
  const stderr = corruptedCheck('secrets.json', (contents) => {
    const entry = contents.files.find((item) => item.id === 'enrolled');
    entry.text = entry.text.replace('"ciphertext": "', '"ciphertext": "A');
  });
  assert.match(stderr, /Byte mismatch: secrets.json/);
});

test('check rejects a changed key-store answer', () => {
  const stderr = corruptedCheck('keystore.json', (contents) => {
    const entry = contents.answers.find((item) => item.id === 'open-sealed-for-another-item');
    entry.outcome = { key: entry.sealed.wrap };
  });
  assert.match(stderr, /Byte mismatch: keystore.json/);
});

test('check rejects a changed key-store seal', () => {
  const stderr = corruptedCheck('keystore.json', (contents) => {
    const entry = contents.helper.find((item) => item.id === 'create');
    entry.line = entry.line.replace('"key":"', '"key":"A');
  });
  assert.match(stderr, /Byte mismatch: keystore.json/);
});

// RFC 9180's own test vectors, as data: hpke.js's composition of
// node:crypto's primitives must give every intermediate value and the
// ciphertext. Appendix A.1.1 is the printed base-mode vector of
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM; the second is the
// base-mode entry (mode 0, kem_id 32, kdf_id 1, aead_id 2) of the suite the
// key store uses, AES-256-GCM, from the JSON file Appendix A cites as
// [TestVectors] (cfrg/draft-irtf-cfrg-hpke at commit
// 5f503c564da00b0687b3de75f1dfbdfc4079ad31, test-vectors.json), which the
// RFC prints only for its other suites. Each with its first two
// encryptions (sequence numbers 0 and 1).
const RFC9180_VECTORS = [
  {
    source: 'RFC 9180, Appendix A.1.1 (Base Setup Information) and A.1.1.1 (Encryptions)',
    aead: 'aes-128-gcm', kem_id: 32, kdf_id: 1, aead_id: 1,
    info: '4f6465206f6e2061204772656369616e2055726e',
    ikmE: '7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234',
    pkEm: '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431',
    skEm: '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736',
    ikmR: '6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037',
    pkRm: '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d',
    skRm: '4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8',
    enc: '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431',
    shared_secret: 'fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc',
    key_schedule_context: '00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449',
    secret: '12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397',
    key: '4531685d41d65f03dc48f6b8302c05b0',
    base_nonce: '56d890e5accaaf011cff4b7d',
    exporter_secret: '45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8',
    encryptions: [
      { seq: 0, pt: '4265617574792069732074727574682c20747275746820626561757479', aad: '436f756e742d30', nonce: '56d890e5accaaf011cff4b7d',
        ct: 'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a' },
      { seq: 1, pt: '4265617574792069732074727574682c20747275746820626561757479', aad: '436f756e742d31', nonce: '56d890e5accaaf011cff4b7c',
        ct: 'af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84' },
    ],
  },
  {
    source: 'RFC 9180, Appendix A, [TestVectors]: test-vectors.json at 5f503c564da00b0687b3de75f1dfbdfc4079ad31, mode 0, kem_id 32, kdf_id 1, aead_id 2',
    aead: 'aes-256-gcm', kem_id: 32, kdf_id: 1, aead_id: 2,
    info: '4f6465206f6e2061204772656369616e2055726e',
    ikmE: '2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9',
    pkEm: '6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256',
    skEm: '179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11',
    ikmR: 'dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee',
    pkRm: '430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c',
    skRm: '497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d',
    enc: '6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256',
    shared_secret: '3101c54c3a4f87439eaac080699ed9bbcc726ffe44e860c0424ccb7e3e2ead7b',
    key_schedule_context: '004ce5472ecdd5093ba0aecb8f871ff13f1fbc90ee76f0e18ace1a1b7e565bafa306f6ef962c9ee7cea40407b5d60f0f26990472faae3ac44c78366f1cac1ecde1',
    secret: '2058ac9b02c1f52c1aaf08bedbec9198219751a94ef67b7d5f0c8b6e2b54ebfb',
    key: 'f50b0609186798729ed0564b36ef2ef8044f1f9d05636874d1f46c819c7a669f',
    base_nonce: '151d9929e2449747889bc923',
    exporter_secret: '86017151bbff6a1940e8abae2ac9e0e7032e33df1eaaecc02ca6259b130d62df',
    encryptions: [
      { seq: 0, pt: '4265617574792069732074727574682c20747275746820626561757479', aad: '436f756e742d30', nonce: '151d9929e2449747889bc923',
        ct: 'e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a' },
      { seq: 1, pt: '4265617574792069732074727574682c20747275746820626561757479', aad: '436f756e742d31', nonce: '151d9929e2449747889bc922',
        ct: '2c43aff25343fdbff864506f0818b9d87df84ea01b1a2144d23b4d40c26bf655fdf197fe40297a8aebeed5cc2d' },
    ],
  },
];

test('hpke.js gives RFC 9180\'s own test vectors', () => {
  const hpke = require('./hpke');
  const hex = (text) => Buffer.from(text, 'hex');
  for (const v of RFC9180_VECTORS) {
    assert.deepEqual([v.kem_id, v.kdf_id, v.aead_id], [hpke.KEM_ID, hpke.KDF_ID, hpke.AEADS[v.aead].id], v.source);
    for (const e of v.encryptions) {
      const t = hpke.trace({ aead: v.aead, ikmR: hex(v.ikmR), ikmE: hex(v.ikmE), info: hex(v.info), aad: hex(e.aad), pt: hex(e.pt), seq: e.seq });
      const got = {
        skRm: t.skR, pkRm: t.pkR, skEm: t.skE, pkEm: t.pkE, enc: t.enc, shared_secret: t.sharedSecret,
        key_schedule_context: t.keyScheduleContext, secret: t.secret, key: t.key, base_nonce: t.baseNonce,
        exporter_secret: t.exporterSecret,
      };
      for (const [name, value] of Object.entries(got)) assert.equal(value.toString('hex'), v[name], `${v.source}: ${name}`);
      assert.equal(t.nonce.toString('hex'), e.nonce, `${v.source}: nonce ${e.seq}`);
      assert.equal(t.ct.toString('hex'), e.ct, `${v.source}: ct ${e.seq}`);
    }
    // Single-shot, as the key store seals and opens: sequence number 0.
    const [first] = v.encryptions;
    const sealed = hpke.sealBase({ aead: v.aead, pkR: hex(v.pkRm), ikmE: hex(v.ikmE), info: hex(v.info), aad: hex(first.aad), pt: hex(first.pt) });
    assert.equal(sealed.enc.toString('hex'), v.enc, v.source);
    assert.equal(sealed.ct.toString('hex'), first.ct, v.source);
    const opened = hpke.openBase({ aead: v.aead, enc: hex(v.enc), skR: hex(v.skRm), info: hex(v.info), aad: hex(first.aad), ct: hex(first.ct) });
    assert.equal(opened.toString('hex'), first.pt, v.source);
    // One changed byte of the ciphertext, or another aad, doesn't open.
    const damaged = hex(first.ct);
    damaged[0] ^= 1;
    assert.throws(() => hpke.openBase({ aead: v.aead, enc: hex(v.enc), skR: hex(v.skRm), info: hex(v.info), aad: hex(first.aad), ct: damaged }), v.source);
    assert.throws(() => hpke.openBase({ aead: v.aead, enc: hex(v.enc), skR: hex(v.skRm), info: hex(v.info), aad: hex(v.encryptions[1].aad), ct: hex(first.ct) }), v.source);
  }
});

test('check rejects a changed composed read', () => {
  const stderr = corruptedCheck('radicle-reads.json', (contents) => {
    const entry = contents.cases.find((item) => item.id === 'remotes-index-branches');
    entry.main.body = entry.main.body.replace('"0":', '"00":');
  });
  assert.match(stderr, /Byte mismatch: radicle-reads.json/);
});

test('check rejects a changed blob range', () => {
  const stderr = corruptedCheck('radicle-blob.json', (contents) => {
    const entry = contents.cases.find((item) => item.id === 'README.md GET bytes=-10');
    entry.expect.head.range.start -= 1;
  });
  assert.match(stderr, /Byte mismatch: radicle-blob.json/);
});

test('check rejects a changed progress envelope', () => {
  const stderr = corruptedCheck('radicle-network.json', (contents) => {
    const entry = contents.queue.find((item) => item.id === 'eight-failures-then-a-summary');
    entry.written[8] = entry.written[8].replace('"count\\":12', '"count\\":13');
  });
  assert.match(stderr, /Byte mismatch: radicle-network.json/);
});

test('check rejects a changed stats result', () => {
  const stderr = corruptedCheck('radicle-stats.json', (contents) => {
    const entry = contents.cases.find((item) => item.id === 'nat64-past-its-bounds');
    entry.result_text = entry.result_text.replace('"over_limit"]', '"over_limit","over_limit"]');
  });
  assert.match(stderr, /Byte mismatch: radicle-stats.json/);
});

test('check rejects a changed import answer', () => {
  const stderr = corruptedCheck('radicle-import.json', (contents) => {
    const entry = contents.imports.find((item) => item.id === 'error-outcome-unknown');
    entry.expect.error.message = 'the import timed out';
  });
  assert.match(stderr, /Byte mismatch: radicle-import.json/);
});

test('check takes the Radicle vectors from their own reference, at its pinned commit', () => {
  // The shared reference is at another commit: refused before anything is built.
  const result = spawnSync(process.execPath, [path.join(SOURCE, 'generator/generate.js'),
    'check', '--freedom-browser', REFERENCE, '--radicle-browser', REFERENCE,
    '--approvals-browser', APPROVALS_REFERENCE], { encoding: 'utf8', timeout: 60000 });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /Use the pinned Radicle reference commit/);
  // And each Radicle file records it.
  const radicle = (name) => JSON.parse(fs.readFileSync(path.join(SOURCE, name), 'utf8')).meta.freedomBrowserCommit;
  const commit = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: RADICLE_REFERENCE, encoding: 'utf8' }).stdout.trim();
  for (const name of ['radicle-reads.json', 'radicle-blob.json', 'radicle-network.json', 'radicle-stats.json', 'radicle-import.json']) {
    assert.equal(radicle(name), commit, name);
  }
  const stderr = corruptedCheck('radicle-network.json', (contents) => {
    contents.meta.freedomBrowserCommit = 'fb540328162839e68150fe2c5e517edb86734d1c';
  });
  assert.match(stderr, /Byte mismatch: radicle-network.json/);
});

test('check rejects a changed approvals decision', () => {
  const stderr = corruptedCheck('approvals.json', (contents) => {
    const pair = contents.pairs.find((item) => item.a === 'sign-typed-data/text' && item.b === 'sign-typed-data/text-spacing');
    pair.core = 'apart';
  });
  assert.match(stderr, /Byte mismatch: approvals.json/);
});

test('check takes the approvals vectors from their own reference, at its pinned commit', () => {
  // The shared reference is at another commit: refused before anything is built.
  const result = spawnSync(process.execPath, [path.join(SOURCE, 'generator/generate.js'),
    'check', '--freedom-browser', REFERENCE, '--radicle-browser', RADICLE_REFERENCE,
    '--approvals-browser', REFERENCE], { encoding: 'utf8', timeout: 60000 });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /Use the pinned approvals reference commit/);
  // And the file records it.
  const commit = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: APPROVALS_REFERENCE, encoding: 'utf8' }).stdout.trim();
  assert.equal(JSON.parse(fs.readFileSync(path.join(SOURCE, 'approvals.json'), 'utf8')).meta.freedomBrowserCommit, commit);
});
