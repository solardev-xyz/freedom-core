'use strict';

// stores.json's `rpc_api_keys` (design 0013, PRF-5h): the stores
// reference's own src/main/wallet/rpc-api-key-store.js, driven through its
// src/main/wallet/rpc-manager.js (`setApiKey`, `removeApiKey`,
// `hasApiKey`), both loaded fresh for each run and unpatched. The key
// store's requires are stubbed: `../freedom-root` names the file under a
// fixed root, and `../private-files` reads and writes an in-memory file of
// bytes, as `readPrivateFile` returns them (a Buffer, null when missing)
// and `writePrivateFileSync` writes them. rpc-manager's registry is a fixed
// catalog of keyed providers (`getKeyedSources`), and its provider manager
// is inert. `Date.now` is fixed at each step's `at` (`addedAt`).
//
// What the reference decides, and the generator records:
// - `runs`: rpc-manager's sets and removes from a start text (or none),
//   each with its result, whether it wrote, the file's text after it, and
//   the keys a fresh rpc-manager reads from that text.
// - `malformed`: a file's text (or bytes, or a filled file), what the key
//   store reads from it, the keys a fresh rpc-manager counts, and a set
//   over it.
//
// What the design adds: each step's `core` (how the core's file codec takes
// it where there is no key store) and each malformed file's `core` reading,
// with the Deviations row (`row`) where the core deliberately differs.

const assert = require('node:assert/strict');
const { loadWithInternals } = require('./naming');

const ROOT = '/freedom';
const FILE = `${ROOT}/rpc-api-keys.json`;
const STORE = 'src/main/wallet/rpc-api-key-store.js';
const MANAGER = 'src/main/wallet/rpc-manager.js';
const MAX_FILE_BYTES = 1024 * 1024;
// Wall-clock milliseconds (2025-11-24T16:00:00Z), as `Date.now()` gives them.
const T = 1_764_000_000_000;

const BACKSLASH = String.fromCharCode(92);
const ch = (...codes) => String.fromCharCode(...codes);
const SEVENTEEN = Array.from({ length: 17 }, (_, i) => `p${String(i + 1).padStart(2, '0')}`);
// main's registry of keyed providers, which a renderer can extend under any
// id (`networks:upsert-source`).
const CATALOG = ['alchemy', 'infura', 'drpc', '2', '10', 'Alchemy', ...SEVENTEEN];

function load(checkout, files) {
  const privateFiles = {
    readPrivateFile: (target) => (files.has(target) ? Buffer.from(files.get(target)) : null),
    writePrivateFileSync: (target, data) => {
      files.writes = (files.writes ?? 0) + 1;
      files.set(target, Buffer.from(String(data)));
    },
    repairPrivateFile: () => false,
  };
  const store = loadWithInternals(checkout, STORE, [], {
    '../freedom-root': { getFreedomDataPath: (name) => `${ROOT}/${name}` },
    '../private-files': privateFiles,
  });
  const sources = Object.fromEntries(CATALOG.map((id) => [id, { id, role: 'rpc', keyed: true, coverage: {} }]));
  const manager = loadWithInternals(checkout, MANAGER, [], {
    '../networks/network-registry': { getKeyedSources: () => sources, getEndpoints: () => [], getEndpointSources: () => [] },
    './rpc-api-key-store': store,
    './provider-manager': { onApiKeysChanged() {} },
  });
  return { store, manager };
}

/** `fn` with `Date.now` at `time` and the modules' logging silenced. */
function at(time, fn) {
  const realNow = Date.now;
  const { log, error, warn } = console;
  Date.now = () => time;
  console.log = () => {};
  console.error = () => {};
  console.warn = () => {};
  try {
    return fn();
  } finally {
    Date.now = realNow;
    console.log = log;
    console.error = error;
    console.warn = warn;
  }
}

function attempt(fn) {
  try {
    return { result: JSON.parse(JSON.stringify(fn())) };
  } catch (error) {
    return { error: String(error?.message ?? error) };
  }
}

const textOf = (files) => (files.has(FILE) ? files.get(FILE).toString('utf8') : null);

/** A string as the vector holds it: well-formed, and whether it was. */
const wellFormed = (s) => ({ text: s.toWellFormed(), well_formed: s.isWellFormed() });

/**
 * The keys a fresh rpc-manager reads from `files`: each own property of the
 * key store's object that `hasApiKey` counts, in its order, with
 * `String(apiKey)` (what a URL template takes), or what that threw.
 */
function keysOf(checkout, files) {
  const { store, manager } = load(checkout, new Map(files));
  return at(T, () => {
    let read;
    try {
      read = store.readRpcApiKeys();
    } catch {
      read = {}; // rpc-manager's loadApiKeys
    }
    if (read === null || typeof read !== 'object') return { error: `not an object: ${JSON.stringify(read)}` };
    return Object.keys(read).filter((id) => manager.hasApiKey(id)).map((id) => {
      try {
        const key = String(read[id].apiKey);
        return { id, key: key.toWellFormed(), well_formed: key.isWellFormed(), bytes: Buffer.byteLength(key.toWellFormed()), string: typeof read[id].apiKey === 'string' };
      } catch (error) {
        return { id, error: String(error.message) };
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Runs.

const set = (id, key, n = 0) => ({ op: 'set', id, key, at: T + n });
const remove = (id, n = 0) => ({ op: 'remove', id, at: T + n });

function runsOf() {
  const escapes = `a"b${BACKSLASH}c${ch(10, 13, 9, 8, 12, 1, 0x1f, 0x7f)}${ch(0xe9)}${ch(0xd83d, 0xde00)}z`;
  const hand = '{"alchemy":{"apiKey":"ka","enabled":true,"addedAt":1,"note":"x"},"Alchemy":{"apiKey":"kA","enabled":true,"addedAt":2},"infura":{"apiKey":"ki","enabled":false},"drpc":0}';
  return [
    {
      id: 'set-replace-remove',
      start: null,
      steps: [set('nope', 'k0'), set('alchemy', 'k1'), set('infura', 'k2', 1), set('alchemy', 'k3', 2),
        remove('infura', 3), remove('infura', 4), remove('alchemy', 5), remove('alchemy', 6)],
    },
    { id: 'remove-without-a-file', start: null, steps: [remove('alchemy')] },
    { id: 'array-index-ids', start: null, steps: [set('drpc', 'kd'), set('10', 'k10', 1), set('2', 'k2', 2), set('alchemy', 'ka', 3)] },
    { id: 'escapes', start: null, steps: [set('alchemy', escapes), set('infura', 'x'.repeat(1024), 1)] },
    // A hand-edited file: extra fields kept, an id outside the entry form
    // answered and removable, a record that isn't counted removed.
    { id: 'hand-edited', start: hand, steps: [set('drpc', 'kd', 1), remove('Alchemy', 2), remove('infura', 3), set('alchemy', 'kb', 4)] },
    { id: 'seventeen', start: null, steps: SEVENTEEN.map((id, i) => set(id, `key-${id}`, i)) },
    // An inherited name passes main's registry check (`loadProviders()[id]`).
    { id: 'constructor', start: null, steps: [set('constructor', 'kc'), remove('constructor', 1), remove('constructor', 2)] },
    // The reference reads `{}` from a file that isn't JSON and replaces it.
    { id: 'unreadable-start', start: '{"alchemy": {"apiKey": "ka", "enabled": true}', steps: [set('infura', 'ki'), remove('alchemy', 1)] },
    // Last steps, where the core deliberately differs.
    { id: 'out-of-form-set', start: null, steps: [set('alchemy', 'ka'), set('Alchemy', 'kA', 1)] },
    { id: 'proto-set', start: null, steps: [set('alchemy', 'ka'), set('__proto__', 'kp', 1)] },
  ];
}

/** The core's taking of a step, as its codec does it with no key store. */
function coreOf(step, outcome) {
  if (outcome.result?.error?.startsWith('Unknown provider')) return { core: 'main_refuses' };
  if (step.op === 'set' && !/^[a-z0-9._-]{1,52}$/.test(step.id)) return { core: 'refused', row: 'rpc-key-provider-id' };
  if (step.op === 'set' && step.id === '__proto__') return { core: 'own_property', row: 'rpc-key-provider-id' };
  return { core: step.op };
}

function runOf(checkout, run) {
  const files = new Map();
  if (run.start !== null) files.set(FILE, Buffer.from(run.start));
  const { manager } = load(checkout, files);
  const steps = [];
  for (const step of run.steps) {
    const before = files.writes ?? 0;
    const outcome = at(step.at, () => attempt(() =>
      (step.op === 'set' ? manager.setApiKey(step.id, step.key) : manager.removeApiKey(step.id))));
    assert.equal(outcome.error, undefined, `${run.id}: ${step.op} ${step.id}`);
    const core = coreOf(step, outcome);
    steps.push({
      op: step.op,
      id: step.id,
      ...(step.op === 'set' ? { key: step.key } : {}),
      at: step.at,
      ...outcome,
      wrote: (files.writes ?? 0) > before,
      text: textOf(files),
      has: at(step.at, () => manager.hasApiKey(step.id)),
      keys: keysOf(checkout, files),
      ...core,
    });
  }
  assert.deepEqual([...files.keys()].filter((name) => name !== FILE), [], run.id);
  const startCore = run.start === null ? {} : startReading(run.start);
  return { id: run.id, start: run.start, ...startCore, steps };
}

function startReading(text) {
  try {
    const value = JSON.parse(text);
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? { start_core: 'parsed' }
      : { start_core: 'unreadable', row: 'rpc-keys-unreadable' };
  } catch {
    return { start_core: 'unreadable', row: 'rpc-keys-unreadable' };
  }
}

// ---------------------------------------------------------------------------
// Malformed files.

const fill = (open, close, bytes) => ({ open, char: 'x', close, bytes });
const filled = (spec) => spec.open + spec.char.repeat(spec.bytes - spec.open.length - spec.close.length) + spec.close;
const rec = (key, more = '') => `{"apiKey": ${key}, "enabled": true${more}}`;

function malformedCases() {
  const unreadable = (id, text, reason) => ({ id, text, core: 'unreadable', reason, row: 'rpc-keys-unreadable' });
  const parsed = (id, text) => ({ id, text, core: 'parsed' });
  return [
    unreadable('empty', '', 'not_json'),
    unreadable('truncated', '{"alchemy": {"apiKey": "ka"', 'not_json'),
    unreadable('bom', `${ch(0xfeff)}{}`, 'not_json'),
    unreadable('trailing-comma', '{"alchemy": 1,}', 'not_json'),
    unreadable('null', 'null', 'not_object'),
    unreadable('array', '[{"apiKey": "ka", "enabled": true}]', 'not_object'),
    unreadable('string', '"ka"', 'not_object'),
    unreadable('number', '42', 'not_object'),
    unreadable('true', 'true', 'not_object'),
    // Nested past fc-json's MAX_DEPTH (512); V8 reads it.
    { ...unreadable('deep-nesting', `{"note": ${'['.repeat(600)}${']'.repeat(600)}, "alchemy": ${rec('"ka"')}}`, 'not_json'), large: true },
    parsed('empty-object', '{}'),
    parsed('whitespace-around', `${ch(10, 9, 32)}{"alchemy": ${rec('"ka"')}}${ch(13, 10, 32)}`),
    parsed('empty-key', `{"alchemy": ${rec('""')}}`),
    parsed('enabled-values', '{"a": {"apiKey": "k1", "enabled": 0}, "b": {"apiKey": "k2", "enabled": "yes"}, "c": {"apiKey": "k3"}, "d": {"apiKey": "k4", "enabled": false}, "e": {"apiKey": "k5", "enabled": []}, "f": {"apiKey": "k6", "enabled": null}}'),
    parsed('key-values', `{"a": ${rec('7')}, "b": ${rec('true')}, "c": ${rec('{}')}, "d": ${rec('["x", 1]')}, "e": ${rec('null')}, "f": ${rec('0')}, "g": ${rec('false')}, "h": ${rec('1e400')}, "i": ${rec('-0')}}`),
    parsed('key-to-string-throws', `{"a": ${rec('{"toString": 1}')}, "b": ${rec('"kb"')}}`),
    parsed('records-not-objects', `{"a": "ka", "b": 0, "c": [], "d": null, "e": true, "f": ${rec('"kf"')}}`),
    parsed('lone-surrogate-key', `{"alchemy": ${rec(`"a${BACKSLASH}ud800b"`)}, "infura": ${rec(`"${BACKSLASH}udc00"`)}}`),
    parsed('long-key', `{"alchemy": ${rec(`"${'k'.repeat(1025)}"`)}, "infura": ${rec(`"${'k'.repeat(1024)}"`)}}`),
    parsed('duplicate-ids', `{"alchemy": ${rec('"k1"')}, "infura": ${rec('"ki"')}, "alchemy": ${rec('"k2"', ', "addedAt": 3')}}`),
    parsed('duplicate-fields', '{"alchemy": {"apiKey": "k1", "enabled": false, "apiKey": "k2", "enabled": true}}'),
    parsed('integer-ids', `{"b": ${rec('"kb"')}, "10": ${rec('"k10"')}, "2": ${rec('"k2"')}, "-1": ${rec('"km"')}, "01": ${rec('"k01"')}, "4294967295": ${rec('"kmax"')}}`),
    parsed('integer-fields', `{"alchemy": {"enabled": true, "9": 1, "apiKey": "ka", "1": 2}}`),
    parsed('proto-id', `{"__proto__": ${rec('"kp"')}, "constructor": ${rec('"kc"')}, "alchemy": ${rec('"ka"')}}`),
    parsed('out-of-form-ids', `{"Alchemy": ${rec('"k1"')}, "a b": ${rec('"k2"')}, "${ch(0xe9)}": ${rec('"k3"')}, "": ${rec('"k4"')}, "${'p'.repeat(53)}": ${rec('"k5"')}}`),
    parsed('nested-values', `{"alchemy": {"apiKey": "ka", "enabled": true, "note": {"n": [1, {"m": "${BACKSLASH}n"}, []], "o": {}}}, "x": [1, [2, {}], {"a": []}]}`),
    parsed('number-forms', `{"alchemy": {"apiKey": "ka", "enabled": 1, "addedAt": 1.7640000000000E12, "f": 0.1, "big": 1e21, "small": 1e-7, "neg": -5e-324}}`),
    {
      id: 'invalid-utf8',
      bytes: Buffer.concat([
        Buffer.from('{"alchemy": {"apiKey": "k'),
        Buffer.from([0xff, 0x61, 0xed, 0xa0, 0x80, 0xc3, 0x28, 0xf0, 0x9f, 0x98]),
        Buffer.from('", "enabled": true}, "a'),
        Buffer.from([0xc3]),
        Buffer.from(`": ${rec('"kb"')}}`),
      ]),
      core: 'parsed',
    },
    { id: 'at-the-bound', fill: fill(`{"alchemy": ${rec('"ka"')}, "pad": "`, '"}', MAX_FILE_BYTES), core: 'parsed' },
    { id: 'over-the-bound', fill: fill(`{"alchemy": ${rec('"ka"')}, "pad": "`, '"}', MAX_FILE_BYTES + 1), core: 'unreadable', reason: 'too_large', row: 'rpc-keys-unreadable' },
  ];
}

function malformedOf(checkout, c) {
  const contents = c.bytes ?? Buffer.from(c.fill ? filled(c.fill) : c.text);
  const files = new Map([[FILE, contents]]);
  const { store } = load(checkout, new Map(files));
  const read = at(T, () => {
    try {
      const value = store.readRpcApiKeys();
      // The text its next save writes, or a filled file's length of it.
      const text = JSON.stringify(value, null, 2);
      return c.fill || c.large ? { text_length: Buffer.byteLength(text) } : { text };
    } catch (error) {
      return { error: String(error.message) };
    }
  });
  const keys = keysOf(checkout, files);
  // A set over it, as main makes one.
  const after = new Map(files);
  const { manager } = load(checkout, after);
  const setOutcome = at(T, () => attempt(() => manager.setApiKey('alchemy', 'k-new')));
  const setText = textOf(after);
  const source = c.bytes ? { hex: contents.toString('hex') } : c.fill ? { fill: c.fill } : { text: c.text };
  if (c.core === 'parsed') assert.ok(read.text !== undefined || read.text_length !== undefined, `STOP: the reference can't read ${c.id}, which the core parses`);
  return {
    id: c.id,
    ...source,
    read,
    keys,
    set: { at: T, ...setOutcome, ...(c.fill || c.large ? { text_length: Buffer.byteLength(setText) } : { text: setText }) },
    core: c.core,
    ...(c.reason ? { reason: c.reason } : {}),
    ...(c.row ? { row: c.row } : {}),
  };
}

const RPC_KEYS_FORMAT = 'rpc-api-keys.json, from the stores reference\'s rpc-api-key-store.js through its rpc-manager.js, main\'s registry a fixed catalog of keyed providers (`catalog`). `runs`: from a `start` text (or none; `start_core`, the core\'s reading of it, with its `row`), each step rpc-manager\'s `setApiKey(id, key)` or `removeApiKey(id)` (`op`, `id`, `key`) at `at` (`Date.now()`, the record\'s `addedAt`), with its `result` (`success`, `error`), whether it wrote the file (`wrote`), the file\'s text after it (`text`, null while there is none), `hasApiKey(id)` after it (`has`), and the keys a fresh rpc-manager reads from that text (`keys`: each own property `hasApiKey` counts, in order, with `String(apiKey)` well-formed in `key`, `well_formed`, its UTF-8 `bytes`, whether `apiKey` was a `string`, or the `error` it threw). `core`: how the core\'s file codec takes the step with no key store: `set` (`keys[id] = { apiKey, enabled: true, addedAt }`), `remove` (`delete keys[id]` where the record is truthy), `main_refuses` (main\'s registry refuses the id first), or, where it deliberately differs (`row`), `refused` (an id outside the entry form) or `own_property` (`__proto__`, which the reference\'s assignment makes the object\'s prototype). `malformed`: a file\'s `text` (or its bytes in `hex`, which Node decodes as UTF-8 with U+FFFD for each invalid sequence, or a `fill`: `open`, `char` repeated, `close`, `bytes` long), what the key store\'s `readRpcApiKeys()` reads (`read`: the `JSON.stringify(value, null, 2)` text its next save writes, a filled or deeply nested file\'s `text_length`, or the `error`, which rpc-manager reads as `{}`), the keys a fresh rpc-manager counts (`keys`, as above, or an `error` where the value isn\'t an object), a `setApiKey(\'alchemy\', \'k-new\')` over it (`set`: at `at`, its result or error and the text after, or its `text_length`), and the core\'s reading (`core`: `unreadable`, renamed aside and reported, with its `reason` and `row`, or `parsed`; the 1 MiB bound is the design\'s).';

function buildRpcKeys(checkout) {
  return {
    file: 'rpc-api-keys.json',
    catalog: CATALOG,
    runs: runsOf().map((run) => runOf(checkout, run)),
    malformed: malformedCases().map((c) => malformedOf(checkout, c)),
  };
}

module.exports = { buildRpcKeys, RPC_KEYS_FORMAT };
