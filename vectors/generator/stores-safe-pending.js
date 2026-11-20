'use strict';

// stores.json's `safe_pending` (design 0013, PRF-5f): the stores
// reference's src/main/wallet/safe/pending-store.js, loaded whole and
// unpatched over an in-memory file system. Each run is one load of the
// module (its cache starts empty) over the run's start text; after each
// step a fresh load over the file must answer as the live one does, so
// the core, which reads the file at each request, answers the same.

const assert = require('node:assert/strict');
const { loadWithInternals } = require('./naming');
const { memoryFs } = require('./approval-stores');

const MODULE = 'src/main/wallet/safe/pending-store.js';
const ROOT = '/freedom';
const FILE = `${ROOT}/safe-pending.json`;
const MAX_FILE_BYTES = 1024 * 1024;

const plain = (value) => (value === undefined ? null : JSON.parse(JSON.stringify(value)));

function load(checkout, fs) {
  return loadWithInternals(checkout, MODULE, ['load'], {
    '../../freedom-root': { getFreedomDataPath: (name) => `${ROOT}/${name}` },
    fs,
  });
}

/** `fn`'s answer, with the store's logging silenced. */
function quiet(fn) {
  const { error } = console;
  console.error = () => {};
  try {
    return { result: plain(fn()) };
  } catch (err) {
    return { error: String(err?.message ?? err) };
  } finally {
    console.error = error;
  }
}

function call(mod, op, args) {
  switch (op) {
    case 'get': return quiet(() => mod.getPending(args[0]));
    // The entry as main's JSON gives it to the core.
    case 'set': return quiet(() => mod.setPending(args[0], JSON.parse(JSON.stringify(args[1]))));
    case 'clear': return quiet(() => mod.clearPending(args[0]));
    case 'list': return quiet(() => mod.listPendingIndexes());
    default: throw new Error(`unknown op ${op}`);
  }
}

// Entries in the shape safe-transactions.js keeps.
const HASH = (byte) => '0x' + byte.repeat(32);
const SAFE = '0x' + 'c1'.repeat(20);
function pending(nonce, extra = {}) {
  return {
    chainId: 100,
    safeAddress: SAFE,
    safeTxData: {
      to: '0x' + 'ab'.repeat(20), value: '1000000000000000', data: '0x', operation: 0, safeTxGas: '0', baseGas: '0',
      gasPrice: '0', gasToken: '0x' + '00'.repeat(20), refundReceiver: '0x' + '00'.repeat(20), nonce: String(nonce),
    },
    safeTxHash: HASH(String(nonce).padStart(2, '0')),
    typedData: { domain: { chainId: 100, verifyingContract: SAFE }, primaryType: 'SafeTx', message: { nonce: String(nonce) } },
    threshold: 2,
    signatures: [],
    createdAt: 1_763_000_000_000 + nonce,
    ...extra,
  };
}
const signed = pending(5, {
  signatures: [{ signer: '0x' + 'a1'.repeat(20), data: '0x' + '11'.repeat(65) }],
  display: { site: 'https://app.example', title: 'Swap ✓ é 😀' },
});
const executed = pending(6, { executed: { hash: HASH('ee'), explorerUrl: 'https://gnosisscan.io/tx/' + HASH('ee') } });

const S = (start) => (start === null ? null : JSON.stringify(start, null, 2));
const step = (op, ...args) => ({ op, args });

function runsOf() {
  return [
    {
      id: 'from-none',
      start: null,
      steps: [
        step('list'), step('get', 0), step('clear', 0),
        step('set', 3, pending(1)), step('get', 3), step('list'),
        step('set', 1, pending(2)), step('list'),
        step('set', 1_000_000, signed), step('get', 1_000_000),
        step('set', 3, executed), step('get', 3), step('list'),
        step('clear', 1), step('clear', 1), step('get', 1), step('list'),
        step('clear', 3), step('clear', 1_000_000), step('list'), step('get', 3),
      ],
    },
    {
      id: 'existing',
      start: S({ 2: pending(3), 1_000_001: signed }),
      steps: [step('list'), step('get', 2), step('get', 1_000_001), step('get', 7), step('clear', 7), step('set', 0, executed), step('list')],
    },
    {
      // Main's text is pretty; a compact one with its keys out of order,
      // and a trailing newline, is read as JS reads it and rewritten at
      // the next write.
      id: 'compact-unordered',
      start: '{"5":{"b":1,"a":2},"2":{"z":[1,{"2":3,"1":4}]},"10":{}}\n',
      steps: [step('list'), step('get', 5), step('get', 2), step('get', 10), step('set', 4, { k: 'v' }), step('list')],
    },
    {
      id: 'falsy-entries',
      start: '{"1":null,"2":0,"3":"","4":false,"5":{},"6":[]}',
      steps: [
        step('get', 1), step('get', 2), step('get', 3), step('get', 4), step('get', 5), step('get', 6), step('list'),
        step('clear', 2), step('list'), step('set', 7, null), step('get', 7), step('set', 8, 0), step('list'), step('clear', 7),
      ],
    },
    {
      id: 'entry-values',
      start: null,
      steps: [
        step('set', 0, { n: [1e21, -0, 0.1, 5e-324, 1.7976931348623157e308, 123456789012345680000, 0.30000000000000004, -1e-7, 2 ** 53 + 2] }),
        step('get', 0),
        step('set', 1, { b: 1, 10: 2, 2: 3, a: { 1: 4, 0: 5, x: 6 }, '': 7, '01': 8 }),
        step('get', 1),
        step('set', 2, { s: ['é ✓ 😀', '\u0000\u001f\u007f', '"\\/', '  ', '\t\n\r\b\f', 'x'.repeat(100)] }),
        step('get', 2),
        step('set', 3, [[], {}, [[{}]], true, false, null, 'str', 42]),
        step('get', 3),
        step('set', 4, 'a string entry'),
        step('get', 4),
        step('set', 5, 0.5),
        step('list'),
      ],
    },
    {
      // Array indices first, ascending; the larger indices in the order
      // they were set; a cleared one set again goes last.
      id: 'large-indices',
      start: null,
      steps: [
        step('set', 4_294_967_295, { a: 1 }), step('set', 7, { b: 2 }), step('set', Number.MAX_SAFE_INTEGER, { c: 3 }),
        step('set', 0, { d: 4 }), step('set', 4_294_967_294, { e: 5 }), step('set', 4_294_967_296, { f: 6 }),
        step('list'), step('get', 4_294_967_295), step('get', Number.MAX_SAFE_INTEGER),
        step('set', 4_294_967_295, { a: 7 }), step('list'),
        step('clear', 4_294_967_295), step('set', 4_294_967_295, { a: 8 }), step('list'),
      ],
    },
  ];
}

function runOf(checkout, run) {
  const fs = memoryFs();
  if (run.start !== null) fs.files.set(FILE, run.start);
  const mod = load(checkout, fs);
  const steps = [];
  for (const s of run.steps) {
    const before = fs.state.writes;
    const answer = call(mod, s.op, s.args);
    assert.equal(answer.error, undefined, `${run.id}: ${s.op} threw ${answer.error}`);
    const text = fs.files.has(FILE) ? fs.files.get(FILE) : null;
    // A fresh load over the file answers as the live store.
    const reread = memoryFs();
    if (text !== null) reread.files.set(FILE, text);
    const again = load(checkout, reread);
    assert.deepEqual(call(again, 'list', []), call(mod, 'list', []), `STOP: ${run.id}: the file lists other indices than the store`);
    for (const index of call(mod, 'list', []).result) {
      assert.deepEqual(call(again, 'get', [index]), call(mod, 'get', [index]), `STOP: ${run.id}: the file holds another entry`);
    }
    steps.push({ op: s.op, args: plain(s.args), result: answer.result, wrote: fs.state.writes > before, text });
  }
  return { id: run.id, start: run.start, steps };
}

// Each a file the reference loads, as `text`, its bytes in `hex`, or a
// `fill` (`open`, `char` repeated, `close`, `bytes` long).
function malformedCases() {
  // Nested `levels` deep under "2"; "1" is the entry got.
  const deep = (levels) => '{"1":{"a":1},"2":' + '['.repeat(levels - 1) + ']'.repeat(levels - 1) + '}';
  return [
    { id: 'not-json', text: '{"1": {', core: 'unreadable', reason: 'not_json' },
    { id: 'empty-file', text: '', core: 'unreadable', reason: 'not_json' },
    { id: 'byte-order-mark', hex: Buffer.from('﻿{"1":{"a":1}}').toString('hex'), core: 'unreadable', reason: 'not_json' },
    { id: 'too-deep', text: deep(513), core: 'unreadable', reason: 'not_json' },
    { id: 'at-depth-limit', text: deep(512), core: 'parsed', index: 1 },
    { id: 'null', text: 'null', core: 'unreadable', reason: 'not_object' },
    { id: 'array', text: '[{"a":1},{"b":2}]', core: 'unreadable', reason: 'not_object' },
    { id: 'string', text: '"ab"', core: 'unreadable', reason: 'not_object' },
    { id: 'number', text: '5', core: 'unreadable', reason: 'not_object' },
    { id: 'boolean', text: 'true', core: 'unreadable', reason: 'not_object' },
    { id: 'key-leading-zero', text: '{"01":{"a":1}}', core: 'unreadable', reason: 'key_not_index', index: 1 },
    { id: 'key-negative', text: '{"-1":{"a":1}}', core: 'unreadable', reason: 'key_not_index', index: -1 },
    { id: 'key-word', text: '{"0":{"a":1},"abc":{"b":2}}', core: 'unreadable', reason: 'key_not_index' },
    { id: 'key-fraction', text: '{"1.5":{"a":1}}', core: 'unreadable', reason: 'key_not_index', index: 1.5 },
    { id: 'key-empty', text: '{"":{"a":1}}', core: 'unreadable', reason: 'key_not_index' },
    { id: 'key-past-safe', text: '{"9007199254740992":{"a":1}}', core: 'unreadable', reason: 'key_not_index', index: 2 ** 53 },
    { id: 'key-max-safe', text: '{"9007199254740991":{"a":1}}', core: 'parsed', index: Number.MAX_SAFE_INTEGER },
    { id: 'duplicate-key', text: '{"1":{"a":1},"2":{},"1":{"b":2}}', core: 'parsed', index: 1 },
    { id: 'invalid-utf8', hex: Buffer.concat([Buffer.from('{"1":{"s":"a'), Buffer.from([0xff, 0xc3]), Buffer.from('b"}}')]).toString('hex'), core: 'parsed', index: 1 },
    { id: 'whitespace', text: '\n\t {"2" : {"x":1}} \r\n', core: 'parsed', index: 2 },
    { id: 'too-large', fill: { open: '{"1":"', char: 'x', close: '"}', bytes: MAX_FILE_BYTES + 1 }, core: 'unreadable', reason: 'too_large', index: 1 },
    { id: 'at-bound', fill: { open: '{"1":"', char: 'x', close: '"}', bytes: MAX_FILE_BYTES }, core: 'parsed', index: 1 },
  ];
}

function contentsOf(c) {
  if (c.hex !== undefined) return Buffer.from(c.hex, 'hex');
  if (c.fill) return c.fill.open + c.fill.char.repeat(c.fill.bytes - c.fill.open.length - c.fill.close.length) + c.fill.close;
  return c.text;
}

function malformedOf(checkout, c) {
  const fresh = () => {
    const fs = memoryFs();
    fs.files.set(FILE, contentsOf(c));
    return { fs, mod: load(checkout, fs) };
  };
  if (c.fill) assert.equal(contentsOf(c).length, c.fill.bytes, c.id);
  const index = c.index ?? 0;
  const first = fresh();
  const value = quiet(() => first.mod.__internals.load());
  const loaded = c.fill
    ? { keys: Object.keys(value.result), padLength: value.result['1'].length }
    : { json: JSON.stringify(value.result) };
  const listed = call(fresh().mod, 'list', []);
  const got = call(fresh().mod, 'get', [index]);
  // A filled file's entry, a string, by its length.
  if (c.fill) got.result = { length: got.result.length };
  // What a set over it leaves (the core's, for a file it parses).
  const setter = fresh();
  const set = call(setter.mod, 'set', [7, { a: 1 }]);
  const written = setter.fs.files.get(FILE);
  // A long text (the filled files, the deep ones) by its length.
  const afterSet = written.length <= 4096 ? { text: written } : { bytes: Buffer.byteLength(written) };
  if (c.core === 'parsed') {
    assert.equal(listed.error, undefined, `STOP: the reference fails on ${c.id}, which the core parses`);
    assert.equal(set.error, undefined, c.id);
  }
  const source = c.hex !== undefined ? { hex: c.hex } : c.fill ? { fill: c.fill } : { text: c.text };
  return {
    id: c.id,
    ...source,
    loaded,
    index,
    listed,
    got,
    set: {
      ...(set.error ? { error: set.error } : {}),
      ...afterSet,
      // The core's set over a file it parses: refused past the bound.
      ...(c.core === 'parsed' ? { core: Buffer.byteLength(written) > MAX_FILE_BYTES ? 'refused' : 'written' } : {}),
    },
    core: c.core,
    ...(c.reason ? { reason: c.reason } : {}),
  };
}

// The 1 MiB bound at a set: the entry a string of `length` `x`s at index
// 0 over no file; the reference writes `bytes` either way.
function boundOf(checkout) {
  const cases = [];
  const overhead = JSON.stringify({ 0: '' }, null, 2).length;
  for (const [id, length, core] of [['at-bound', MAX_FILE_BYTES - overhead, 'written'], ['past-bound', MAX_FILE_BYTES - overhead + 1, 'refused']]) {
    const fs = memoryFs();
    const mod = load(checkout, fs);
    const answer = call(mod, 'set', [0, 'x'.repeat(length)]);
    assert.equal(answer.error, undefined, id);
    const bytes = Buffer.byteLength(fs.files.get(FILE));
    assert.equal(bytes > MAX_FILE_BYTES, core === 'refused', `STOP: ${id}`);
    cases.push({ id, index: 0, entry: { char: 'x', length }, bytes, core, ...(core === 'refused' ? { reason: 'too_large' } : {}) });
  }
  return cases;
}

const SAFE_PENDING_FORMAT = 'safe-pending.json at the Freedom root, from the stores reference\'s wallet/safe/pending-store.js. `runs`: from a `start` text (or none), each step one of its functions in one load of the module (`get` getPending, `set` setPending, `clear` clearPending, `list` listPendingIndexes, with its `args`: the wallet index, and for `set` the entry), its `result` (null for undefined), whether it wrote the file (`wrote`) and the file\'s text after it (`text`, null while there is none); the core is asked the same. `malformed`: a file\'s `text` (or its bytes in `hex`, which Node decodes as UTF-8 with U+FFFD for each invalid sequence, or a `fill`: `open`, `char` repeated, `close`, `bytes` long), what the reference loads from it (`loaded`: its `JSON.stringify` text in `json`, or a filled file\'s keys and the string\'s length), `listPendingIndexes()` (`listed`: its `result` or `error`), `getPending(index)` (`got`; a filled file\'s string entry by its `length`), the file after `setPending(7, { a: 1 })` (`set`: its `text`, or its length in `bytes` past 4,096, with the set\'s `error` if it threw, and for a file the core parses its own verdict, `core`: `written`, the same text, or `refused` past the bound), and the core\'s reading (`core`: `unreadable`, renamed aside and reported, with its `reason`, or `parsed`, where the core answers and sets as the reference does). `bound`: a set at `index` of a string entry (`char` repeated `length` times) over no file, the bytes the reference writes, and the core\'s verdict: `written`, or `refused` (the store unchanged) past the design\'s 1 MiB.';

function buildSafePending(checkout) {
  return {
    file: 'safe-pending.json',
    max_file_bytes: MAX_FILE_BYTES,
    source: { max_file_bytes: 'design' },
    runs: runsOf().map((run) => runOf(checkout, run)),
    malformed: malformedCases().map((c) => malformedOf(checkout, c)),
    bound: boundOf(checkout),
  };
}

module.exports = { buildSafePending, SAFE_PENDING_FORMAT };
