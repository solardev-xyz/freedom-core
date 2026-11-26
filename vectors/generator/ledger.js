'use strict';

// vectors/ledger.json and vectors/ledger-grammar.json (design 0016, LDG-1):
// the Ledger exchanges as the ledger reference makes them. Its own
// src/main/wallet/ledger/signer.js, transport.js, errors.js and ipc.js (with
// account-checks.js), and identity-manager.js's addLedgerWallet, run loaded
// fresh for every case with Electron stubbed, over the checkout's installed
// @ledgerhq/hw-app-eth 7.11.1; `TransportNodeHid.open` hands transport.js a
// recording transport over a scripted device (generator/ledger-device.js).
// hw-app-eth builds every APDU and the reference reads every answer: nothing
// the vectors pin is computed here. generator/ledger-grammar.js holds the
// design's grammar, which every recorded APDU is checked against.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const Module = require('node:module');
const { createRequire } = Module;
const { ScriptedDevice, recordingTransport } = require('./ledger-device');
const grammar = require('./ledger-grammar');
const ledgerCases = require('./ledger-cases');
const { buildGrammarFile, streamDeviations } = require('./ledger-grammar-file');

// The versions design 0016 pins, from the reference's lockfile; any other
// install is refused before anything is built. hw-transport 6.36.0 is
// hw-app-eth's (its types only); the transport's class is 6.35.5's, the copy
// hw-transport-node-hid and -noevents pin.
const PACKAGES = {
  '@ledgerhq/hw-app-eth': '7.11.1',
  '@ledgerhq/hw-transport': '6.36.0',
  '@ledgerhq/hw-transport-node-hid': '6.33.5',
  '@ledgerhq/hw-transport-node-hid-noevents': '6.36.0',
  'hw-transport-node-hid-noevents/@ledgerhq/hw-transport': '6.35.5',
  '@ledgerhq/errors': '6.37.0',
  '@ledgerhq/evm-tools': '2.0.0',
  ethers: '6.17.0',
  '@x402/evm': '2.29.0',
};

function packageDir(name, from) {
  let dir = path.dirname(require.resolve(name, { paths: [from] }));
  for (;;) {
    const manifest = path.join(dir, 'package.json');
    if (fs.existsSync(manifest) && JSON.parse(fs.readFileSync(manifest, 'utf8')).name === name) return dir;
    const up = path.dirname(dir);
    assert.notEqual(up, dir, `no package.json for ${name}`);
    dir = up;
  }
}
const versionAt = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;

/** The checkout's packages, refused unless exactly PACKAGES. */
function loadPackages(checkout) {
  const dirs = {};
  for (const name of Object.keys(PACKAGES)) {
    if (name.includes('/@')) continue;
    dirs[name] = packageDir(name, checkout);
  }
  // The Transport TransportNodeHid extends: -noevents' own hw-transport.
  const noevents = dirs['@ledgerhq/hw-transport-node-hid-noevents'];
  dirs['hw-transport-node-hid-noevents/@ledgerhq/hw-transport'] = packageDir('@ledgerhq/hw-transport', noevents);
  const versions = Object.fromEntries(Object.entries(dirs).map(([name, dir]) => [name, versionAt(dir)]));
  for (const [name, want] of Object.entries(PACKAGES)) {
    if (versions[name] !== want) {
      throw new Error(`The Ledger vectors are ${name} ${want}'s; ${checkout} has ${versions[name]}`);
    }
  }
  const ref = createRequire(path.join(checkout, 'package.json'));
  const fromNoevents = createRequire(path.join(noevents, 'package.json'));
  const Transport = fromNoevents('@ledgerhq/hw-transport').default;
  const noeventsClass = fromNoevents('./lib/TransportNodeHid.js').default;
  // The class TransportNodeHid extends is this Transport, so `send` is the one a device's exchanges go through.
  assert.equal(Object.getPrototypeOf(noeventsClass.prototype), Transport.prototype, 'the node-hid transport extends this Transport');
  return {
    versions,
    Transport,
    errors: fromNoevents('@ledgerhq/errors'),
    ethers: ref('ethers'),
    x402: { exact: ref('@x402/evm/exact/client'), v1: ref('@x402/evm/exact/v1/client') },
  };
}

/** Every require from the reference's src/ that a case's world answers. */
function withReference(checkout, world, fn) {
  const src = path.join(checkout, 'src') + path.sep;
  for (const key of Object.keys(require.cache)) if (key.startsWith(src)) delete require.cache[key];
  const originalLoad = Module._load;
  Module._load = function load(request, parent, isMain) {
    if (parent?.filename?.startsWith(src)) {
      if (request === 'electron') return world.electron;
      if (request === '@ledgerhq/hw-transport-node-hid') return world.nodeHid;
      if (request.startsWith('.')) {
        const resolved = Module._resolveFilename(request, parent, isMain);
        const rel = path.relative(checkout, resolved).split(path.sep).join('/');
        if (Object.hasOwn(world.stubs, rel)) return world.stubs[rel];
        if (world.unscripted && !world.real.has(rel)) return unscripted(rel);
      }
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  // No case reaches the network: hw-app-eth's hosted lookups are off
  // (transport.js's OFFLINE_LOAD_CONFIG), and a request would fail the run.
  const saved = { request: http.request, get: http.get, srequest: https.request, sget: https.get, fetch: globalThis.fetch };
  const refuse = () => { throw new Error('a Ledger case reached the network'); };
  http.request = http.get = https.request = https.get = refuse;
  globalThis.fetch = refuse;
  const restore = () => {
    Module._load = originalLoad;
    Object.assign(http, { request: saved.request, get: saved.get });
    Object.assign(https, { request: saved.srequest, get: saved.sget });
    globalThis.fetch = saved.fetch;
  };
  let result;
  try {
    result = fn(createRequire(path.join(checkout, 'src', 'main', 'wallet', 'ledger', 'signer.js')));
  } catch (err) {
    restore();
    throw err;
  }
  return Promise.resolve(result).finally(restore);
}

/** A module the world doesn't script: any use of it fails the run. */
function unscripted(rel) {
  return new Proxy({}, {
    get: (_, key) => (key === '__esModule' ? false : () => { throw new Error(`unscripted ${rel}.${String(key)}`); }),
  });
}

const errorOf = (err) => {
  const out = { status: 'error', code: err?.code ?? null, message: String(err?.message ?? err) };
  if (err?.cause) out.cause = { name: err.cause.name, message: err.cause.message };
  return out;
};

/**
 * Run one case: its world (the device, Electron, the stubs), the reference
 * loaded fresh, the operation, and what it recorded.
 */
async function runCase(env, c) {
  const log = { exchanges: [], opened: 0, closed: 0 };
  const device = new ScriptedDevice(env.deviceEnv, {
    app: c.device?.app ?? env.app,
    fields: c.device?.fields,
    typedDigest: c.digest,
    fault: c.device?.fault,
    answerFault: c.device?.answerFault,
  });
  const RecordingTransport = env.RecordingTransport;
  const open = async (descriptor) => {
    assert.equal(descriptor, '', 'transport.js opens the first Ledger');
    if (c.device?.open === 'no-device') throw new env.errors.TransportError('NoDevice', 'NoDevice');
    if (c.device?.open === 'cannot-open') throw new Error('cannot open device with path /dev/hidraw0');
    return new RecordingTransport(device, log);
  };
  const handlers = new Map();
  const events = [];
  const world = {
    electron: { ipcMain: { handle: (channel, fn) => handlers.set(channel, fn), on() {}, removeHandler() {} } },
    nodeHid: { default: { open } },
    stubs: {},
    real: new Set(),
    unscripted: false,
    device,
  };
  let result;
  // The reference's own logs, kept as the run's events.
  const saved = { warn: console.warn, error: console.error, log: console.log };
  for (const level of ['warn', 'error', 'log']) console[level] = (...args) => events.push({ console: level, text: args.map(String).join(' ') });
  try {
    await withReference(env.checkout, world, async (requireRef) => {
      try {
        result = await OPERATIONS[c.x402 ? 'x402' : c.operation](env, c, requireRef, world, handlers, events);
      } catch (err) {
        result = errorOf(err);
      }
    });
  } finally {
    Object.assign(console, saved);
  }
  const out = { exchanges: log.exchanges, transport: { opened: log.opened, closed: log.closed }, result };
  if (events.length) out.events = events;
  return out;
}

const OPERATIONS = {
  /** `ledger:get-accounts` through ipc.js, with account-checks.js's record check over the world's records. */
  'ledger.accounts': async (env, c, requireRef, world, handlers, events) => {
    world.stubs['src/main/identity-manager.js'] = {
      getLedgerRecordsToCheck: () => [],
      recordLedgerAddressCheck: async (index, matched) => { events.push({ address_check: { index, matched } }); return matched ? 'matched' : 'mismatched'; },
      ADDRESS_CHECK: { UNCHECKED: 'unchecked', MATCHED: 'matched', MISMATCHED: 'mismatched' },
    };
    requireRef('./ipc.js').registerLedgerIpc();
    const answer = await handlers.get('ledger:get-accounts')({}, c.request);
    return answer.success ? { status: 'success', ...answer } : { status: 'error', code: answer.code ?? null, message: answer.error };
  },
  /** identity-manager.js's addLedgerWallet: the device read, the compare, and the record it hands the core. */
  'ledger.add': async (env, c, requireRef, world, handlers, events) => {
    world.unscripted = true;
    for (const rel of ['src/main/identity-manager.js', 'src/main/wallet/ledger/errors.js', 'src/main/wallet/ledger/transport.js', 'src/main/wallet/remote/errors.js', 'src/shared/ipc-channels.js']) world.real.add(rel);
    world.stubs['src/main/core/vault-backend.js'] = {
      vaultBackend: {
        accounts: {
          addLedger: async (params) => {
            events.push({ core: { method: 'accounts.add_ledger', params } });
            return { index: 100, name: params.name, address: params.address, type: 'ledger', path: params.path, addressCheck: 'matched' };
          },
        },
      },
    };
    const identityManager = requireRef('../../identity-manager.js');
    const { name, address, path: p } = c.request;
    const wallet = await identityManager.addLedgerWallet(name, address, p);
    return { status: 'success', wallet };
  },
  'sign.transaction': async (env, c, requireRef, world, handlers, events) => {
    const backend = ledgerBackend(c, requireRef, events);
    const raw = await backend.signTransaction(toEthersTx(c.request.tx));
    return { status: 'success', raw };
  },
  'sign.message': async (env, c, requireRef, world, handlers, events) => {
    const backend = ledgerBackend(c, requireRef, events);
    const signature = await backend.signMessage(Buffer.from(c.request.message.replace(/^0x/, ''), 'hex'));
    return { status: 'success', signature };
  },
  'sign.typed_data': async (env, c, requireRef, world, handlers, events) => {
    const backend = ledgerBackend(c, requireRef, events);
    const typedData = c.typedDataInput ?? c.request.typed_data;
    const signature = await backend.signTypedData(typedData, { digest: c.request.expected_hash });
    return { status: 'success', signature };
  },
  /** @x402/evm's client builds the authorization, and its signer is the Ledger backend. */
  x402: async (env, c, requireRef, world, handlers, events) => {
    const backend = ledgerBackend(c, requireRef, events);
    const asked = [];
    const signer = {
      address: c.record.address,
      signTypedData: async (typedData) => {
        asked.push(typedData);
        const { TypedDataEncoder } = env.ethers;
        const types = { ...typedData.types };
        const digest = TypedDataEncoder.hash(typedData.domain, types, typedData.message);
        // The device signs E0 0C 00 01 over the typed data's hash, which only now exists.
        world.device.script.typedDigest = digest;
        return backend.signTypedData(typedData, { digest });
      },
    };
    const scheme = c.x402.version === 1 ? new env.x402.v1.ExactEvmSchemeV1(signer) : new env.x402.exact.ExactEvmScheme(signer);
    const payload = await withClock(c.x402.now_ms, c.x402.nonce, () => scheme.createPaymentPayload(c.x402.version, c.x402.requirements));
    assert.equal(asked.length, 1);
    events.push({ typed_data: jsonSafe(asked[0]) });
    return { status: 'success', payload: JSON.stringify(jsonSafe(payload)) };
  },
};

function ledgerBackend(c, requireRef, events) {
  const { createLedgerBackend } = requireRef('./signer.js');
  return createLedgerBackend(c.record, { onAddressCheck: (matched) => events.push({ address_check: matched }) });
}

/** The core's wire form of a transaction (0002's) as the ethers fields the reference's backend takes. */
function toEthersTx(tx) {
  const out = { type: tx.type, chainId: BigInt(tx.chain_id), nonce: Number(tx.nonce), gasLimit: BigInt(tx.gas_limit), to: tx.to, value: BigInt(tx.value), data: tx.data };
  if (tx.type === 0) out.gasPrice = BigInt(tx.gas_price);
  else Object.assign(out, { maxFeePerGas: BigInt(tx.max_fee_per_gas), maxPriorityFeePerGas: BigInt(tx.max_priority_fee_per_gas) });
  return out;
}

/** `Date.now` and `crypto.getRandomValues` fixed while `fn` runs: x402's clock and nonce. */
async function withClock(nowMs, nonceHex, fn) {
  const realNow = Date.now;
  const realRandom = globalThis.crypto.getRandomValues;
  const nonce = Buffer.from(nonceHex, 'hex');
  Date.now = () => nowMs;
  globalThis.crypto.getRandomValues = (array) => {
    assert.equal(array.length, nonce.length, 'x402 draws one 32-byte nonce');
    array.set(nonce);
    return array;
  };
  try {
    return await fn();
  } finally {
    Date.now = realNow;
    globalThis.crypto.getRandomValues = realRandom;
  }
}

/** BigInts as decimal strings and byte arrays as hex, as 0012's `typed_data` writes them. */
function jsonSafe(value) {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return '0x' + Buffer.from(value).toString('hex');
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, jsonSafe(v)]));
  return value;
}

/** The environment every case shares: the packages, the device's keys, the transport class. */
function environment(checkout, keysJson) {
  const packages = loadPackages(checkout);
  const vector = keysJson.vectors.find((v) => v.id === 'abandon-12');
  assert.ok(vector, 'keys.json lacks abandon-12');
  const { ethers } = packages;
  const account = (i) => vector.userWallets.find((w) => w.accountIndex === i);
  // keys.json's account 1 signs for a device that holds another seed.
  const otherKey = new ethers.SigningKey(account(1).privateKey);
  const check = ethers.HDNodeWallet.fromPhrase(vector.mnemonic, '', account(0).path);
  assert.equal(check.address, account(0).address, 'the scripted device derives keys.json\'s account 0');
  return {
    checkout, ...packages,
    mnemonic: vector.mnemonic,
    account,
    deviceEnv: { ethers, mnemonic: vector.mnemonic, otherKey, errors: packages.errors },
    RecordingTransport: recordingTransport(packages.Transport),
    app: { name: 'Ethereum', version: '1.13.0' },
  };
}

/** The typed data @x402/evm hands its signer for `requirements`, under the fixed clock and nonce. */
async function x402TypedData(env, address, version, requirements) {
  let asked = null;
  const signer = {
    address,
    signTypedData: async (typedData) => {
      asked = jsonSafe(typedData);
      return '0x' + '00'.repeat(65);
    },
  };
  const scheme = version === 1 ? new env.x402.v1.ExactEvmSchemeV1(signer) : new env.x402.exact.ExactEvmScheme(signer);
  await withClock(ledgerCases.X402_NOW_MS, ledgerCases.X402_NONCE, () => scheme.createPaymentPayload(version, requirements));
  return asked;
}

/** The other transfer method's typed data for each x402 case's accept entry. */
async function x402OtherForms(env, cases) {
  const out = {};
  for (const c of cases.filter((x) => x.x402)) {
    const form = c.id.replace(/^x402-/, '');
    const r = c.x402.requirements;
    const v2 = c.x402.version === 1
      ? { scheme: r.scheme, network: 'eip155:8453', amount: r.maxAmountRequired, asset: r.asset, payTo: r.payTo, maxTimeoutSeconds: r.maxTimeoutSeconds, extra: { ...r.extra } }
      : structuredClone(r);
    if (form === 'permit2-v2') delete v2.extra.assetTransferMethod;
    else v2.extra.assetTransferMethod = 'permit2';
    out[form] = await x402TypedData(env, c.record.address, 2, v2);
  }
  return out;
}

// Design 0016's Ledger deviations, each with the cases that record it, or why none can.
const DEVIATION_IDS = ['signature-check', 'field-pieces', 'device-bounds', 'blind-typed-data', 'app-check', 'key-check', 'empty-message',
  'path-strict', 'address-from-device', 'device-deadlines', 'cancel', 'discovery-busy', 'name-ascii', 'chain-id-width'];
const NO_CASE = {
  'device-deadlines': 'no case: the reference sets no deadline (hw-transport\'s 15 s only emits "unresponsive"); LDG-2 tests both deadlines under a fixed clock',
  cancel: 'no case: the reference has no way to cancel an exchange; LDG-2 cancels before the first APDU, between two and during the user\'s wait',
  'discovery-busy': 'no case: it needs discovery while a signature holds the device queue, which one case\'s run never does; LDG-2\'s lane tests make it',
};

function deviationsOf(vectors) {
  const where = Object.fromEntries(DEVIATION_IDS.map((id) => [id, []]));
  for (const c of vectors) {
    for (const id of [c.deviation, ...(c.also || [])]) {
      if (!id) continue;
      assert.ok(Object.hasOwn(where, id), `${c.id}: ${id} is no Ledger deviation of design 0016`);
      where[id].push(c.id);
    }
  }
  return Object.fromEntries(DEVIATION_IDS.map((id) => [id, where[id].length ? { cases: where[id] } : { note: NO_CASE[id] }]));
}

/**
 * A signature fault the core refuses with LEDGER_BAD_SIGNATURE: where the
 * reference answers otherwise (it accepts the signature, or fails with
 * another code), the case is signature-check.
 */
function markSignatureFault(c, run) {
  if (c.family !== 'answer' || c.device?.answerFault?.at !== 'signature') return;
  if (!(run.result.status === 'error' && run.result.code === 'LEDGER_BAD_SIGNATURE')) c.deviation = 'signature-check';
}

// Which of a case's deviations it names first: a refusal before any APDU,
// then what changes its answer, then what changes its stream.
const PRIORITY = ['path-strict', 'empty-message', 'name-ascii', 'device-bounds', 'chain-id-width', 'signature-check', 'key-check',
  'blind-typed-data', 'field-pieces', 'address-from-device', 'app-check'];

/** The case's marks: its own (what its stream can't show) and those its stream shows. */
function markCase(env, c, run) {
  markSignatureFault(c, run);
  const marks = new Set([c.deviation, ...(c.also || []), ...streamDeviations(env, c, run)].filter(Boolean));
  const ordered = PRIORITY.filter((id) => marks.has(id));
  assert.equal(ordered.length, marks.size, `${c.id}: a mark outside the priority list`);
  delete c.deviation;
  delete c.also;
  if (ordered.length) c.deviation = ordered[0];
  if (ordered.length > 1) c.also = ordered.slice(1);
}

/** A recorded case as ledger.json writes it. */
function vectorOf(env, c, run) {
  const out = { id: c.id, family: c.family, operation: c.operation };
  if (c.x402) {
    const asked = run.events.find((e) => e.typed_data).typed_data;
    out.request = { typed_data: asked, expected_hash: grammar.typedPayload(env.ethers, asked).hash };
    out.x402 = { version: c.x402.version, requirements: c.x402.requirements, now_s: Math.floor(c.x402.now_ms / 1000), nonce: c.x402.nonce };
  } else {
    out.request = c.request;
  }
  if (c.record) out.record = c.record;
  const device = { app: c.device?.app ?? env.app };
  if (c.device?.fields === false) device.fields = false;
  if (c.device?.fault) device.fault = c.device.fault.disconnect ? { at: c.device.fault.at, disconnect: true } : { at: c.device.fault.at, status: c.device.fault.status.toString(16).padStart(4, '0') };
  if (c.device?.answerFault) device.answer_fault = c.device.answerFault;
  if (c.device?.open) device.open = c.device.open;
  out.device = device;
  if (c.fault_step) out.fault_step = c.fault_step;
  out.exchanges = run.exchanges;
  out.transport = run.transport;
  const events = (run.events || []).filter((e) => !e.typed_data);
  if (events.length) out.events = events;
  out.result = run.result;
  if (c.deviation) out.deviation = c.deviation;
  if (c.also?.length) out.also = c.also;
  return out;
}

/** ledger.json and ledger-grammar.json from the ledger reference at `checkout`. */
async function buildLedger(checkout, meta, keysJson) {
  const env = environment(checkout, keysJson);
  env.toEthersTx = toEthersTx;
  const { cases: bases, excluded } = ledgerCases.baseCases(env, toEthersTx);
  const recorded = [];
  for (const c of bases) recorded.push({ c, run: await runCase(env, c) });
  const runs = new Map(recorded.map(({ c, run }) => [c.id, { ...c, ...run }]));
  for (const c of ledgerCases.stepCases(runs)) recorded.push({ c, run: await runCase(env, c) });
  const ids = new Set();
  for (const { c, run } of recorded) {
    assert.ok(!ids.has(c.id), `two cases named ${c.id}`);
    ids.add(c.id);
    markCase(env, c, run);
  }
  const fullMeta = { ...meta, packages: env.versions, design: '0016, LDG-1' };
  const vectors = recorded.map(({ c, run }) => vectorOf(env, c, run));
  const ledger = {
    meta: fullMeta,
    formats: LEDGER_FORMATS,
    device: { mnemonicId: 'abandon-12', app: env.app, b001: 'format 01, the name, the version, flags 01 00, then 9000' },
    deviations: deviationsOf(vectors),
    typed_data_excluded: excluded,
    cases: vectors,
  };
  const other = await x402OtherForms(env, bases);
  const grammarFile = buildGrammarFile(env, fullMeta, recorded, (form) => other[form]);
  return { ledger, grammar: grammarFile };
}

const LEDGER_FORMATS = {
  reference: 'freedom-browser at meta.freedomBrowserCommit (integration/rust-core, the swarm reference\'s checkout), its src/main/wallet/ledger/signer.js, transport.js, errors.js, ipc.js and account-checks.js and identity-manager.js\'s addLedgerWallet, loaded fresh for each case with Electron stubbed, over meta.packages exactly (hw-app-eth builds every APDU). TransportNodeHid.open hands transport.js a recording transport, a subclass of the Transport class hw-transport-node-hid\'s transport extends (hw-transport 6.35.5, -noevents\' copy), so send\'s framing, its 255-byte limit and its status check are the package\'s. No case reaches the network.',
  device: 'the scripted device (generator/ledger-device.js) holds keys.json\'s abandon-12 mnemonic. E0 02: 65 ‖ the uncompressed key at the path (65 bytes) ‖ 40 ‖ its EIP-55 address without 0x (40 ASCII) ‖ 9000. B0 01: `device.b001` with the case\'s app. A transaction: 9000 until the RLP it was sent is whole, then v ‖ r ‖ s ‖ 9000 over keccak256 of the bytes after the path, v the parity for a typed one and (chainId\' · 2 + 35 + parity) mod 256 for type 0, chainId\' the chain ID\'s first four bytes. A message: 9000 until it has the announced length, then 27 + parity ‖ r ‖ s over its EIP-191 hash. E0 1A and E0 1C: 9000 (6D00 for a device with `fields: false`, a Nano S). E0 0C 00 01: a signature over the case\'s `expected_hash` (the device can\'t hash fields; LDG-3\'s recordings check that a real one gets the same hash); E0 0C 00 00 over keccak256(19 01 ‖ the two hashes). Every signature is RFC 6979\'s, low s. `fault`: at APDU `at` (0-based, the case\'s) the device answers `status` alone, or throws DisconnectedDeviceDuringOperation (node-hid\'s read failure). `answer_fault` at APDU `at` (`signature`: the APDU the device signs at): other-address (another seed\'s key and address), key-not-address (the path\'s address text beside another key), other-key (keys.json\'s account 1 signs), other-digest (a signature over keccak256 of the digest), high-s (n − s, the parity flipped), flip-v (the parity flipped), long (one byte more), short (one byte less), v-27 (27 + parity for a type 0). `open`: no-device (the transport\'s own TransportError NoDevice), cannot-open (node-hid\'s "cannot open device with path").',
  case: '{ id, family, operation (the core\'s method), request (the core\'s wire form: ledger.accounts { scheme, start, count }; ledger.add { name, address, path }, the reference\'s wallet:add-ledger-wallet arguments; sign.transaction { tx } in 0002\'s form; sign.message { message } the bytes; sign.typed_data { typed_data, expected_hash }, the hash the user confirmed, over which the reference recovers), record { path, address } for a signature, x402 { version, requirements, now_s, nonce } where @x402/evm 2.29.0 built the typed data under that clock and nonce, device (above), fault_step (the step a fault is at), exchanges [{ apdu, answer } | { apdu, thrown: { name, message } }] in order (hex), transport { opened, closed }, events (the record\'s address check as onAddressCheck heard it, the core call addLedgerWallet made, the reference\'s console), result, deviation, also }. result: { status: success, accounts, mismatched } for discovery (ipc.js\'s answer), { status: success, wallet } for an add, { status: success, raw | signature | payload }, or { status: error, code, message, cause }.',
  deviation: 'a case the core answers differently names its deviation (design 0016\'s table) in `deviation`, and any other in `also`; the result is the reference\'s. `deviations` lists each Ledger deviation with its cases, or why none can show it. ledger-grammar.json gives the core\'s stream for each case (`honest`) or its refusal (`refused`).',
  typed_data_excluded: '0002\'s typed-data cases ethers and the core sign that no Ledger case carries, and why.',
};

module.exports = { loadPackages, environment, runCase, toEthersTx, jsonSafe, buildLedger, PACKAGES, grammar };
