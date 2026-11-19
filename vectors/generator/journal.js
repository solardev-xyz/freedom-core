'use strict';

// Design 0013's JSON Lines journal (step PRF-5d), from the reference's own
// src/main/lib/durable-journal.js: freedom-browser's integration/rust-core at
// JOURNAL_REFERENCE_COMMIT (generate.js), the approvals reference's checkout,
// whose durable-journal.js is byte for byte integration's head when this file
// was written (5e62992a; the module last changed in db09e7f7, which keeps a
// whole last record whose newline was lost). It requires only Node's fs,
// path and crypto: nothing is stubbed, and no package is read.
//
// What the reference decides, and the generator records:
// - `encode`: `encodeLine` of records given as JSON text (`JSON.parse`d
//   first, so property order, numbers and strings are V8's), each line's
//   bytes in hex, or the refusal's code;
// - `parse`: `parseJournal` of bytes (hex): the records, each as its
//   `JSON.stringify` text, the damaged lines, where the complete records
//   end, the torn tail and whether the last record lacked its newline;
// - `read`: `readJournal` of a file on disk, at, under and over a bound
//   (the journal's 64 MiB default, the intent store's 16 MiB read bound,
//   and small ones), and of what isn't a regular file. A large file is
//   sparse zeros, given by its `size`;
// - `journal`: runs of `createJournal`'s `open`, `append`, `compact` and
//   `moveAside` on a temp directory, each step's result (or refusal), the
//   journal's `size`, and every file in the directory after it, in hex,
//   with the journal's mode.
//
// A case where the core answers otherwise has `deviation` and `core`, the
// core's answer: `json-depth`, a record nested deeper than 512 levels,
// which the core counts a damaged line (fc_json::MAX_DEPTH, design 0003).

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
// wallet/intent-store.js: the journal is read with LIMITS.readBytes, and
// LIMITS.fileBytes caps what the store lets it grow to.
const INTENT_READ_BYTES = 16 * 1024 * 1024;
const INTENT_FILE_BYTES = 8 * 1024 * 1024;
const NAME = 'wallet-intents.jsonl';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const sha = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

/** A line with this record body (bytes) and its true checksum. */
function lineOf(body, { digest, newline = true } = {}) {
  const b = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  return Buffer.concat([
    Buffer.from(`{"v":1,"sha256":"${digest ?? sha(b)}","record":`, 'latin1'),
    b,
    Buffer.from(newline ? '}\n' : '}', 'latin1'),
  ]);
}

const RECORDS = {
  plain: '{"kind":"commit","run":"0b6f1c2e-6a8a-4a8e-9a43-1f7f2e1f5a10","key":"0x1:5","at":1763577600000}',
  empty: '{}',
  order: '{"b":1,"2":"two","a":[3,{"z":null,"y":true}],"1":false,"__proto__":{"x":1}}',
  numbers: '{"n":[1e21,1e-7,-0,0.1,123456789012345678901,5e-324,1.7976931348623157e308,1E2,-1.50]}',
  strings: '{"s":"é€😀\\u0000\\u001f\\b\\f\\n\\r\\t\\"\\\\/\\u007f\\u2028\\u2029</script>"}',
  surrogates: '{"lone":"\\ud800","trail":"\\udc00x","pair":"\\ud83d\\ude00","rev":"\\udc00\\ud800"}',
  duplicate: '{"a":1,"b":2,"a":3}',
  nested: '{"a":{"b":{"c":{"d":[[[[]]],{}]}}}}',
  unicodeKeys: '{"ключ":"значение","🔑":"v","":"empty"}',
};

function encodeCases(journal) {
  const cases = Object.entries(RECORDS).map(([name, text]) => ({
    name,
    record: text,
    line: hex(journal.encodeLine(JSON.parse(text))),
  }));
  for (const [name, text] of [
    ['array', '[1,2]'],
    ['null', 'null'],
    ['number', '1'],
    ['string', '"x"'],
    ['boolean', 'true'],
  ]) {
    try {
      journal.encodeLine(JSON.parse(text));
      throw new Error(`encodeLine accepted ${name}`);
    } catch (error) {
      if (!error.code) throw error;
      cases.push({ name, record: text, error: error.code });
    }
  }
  return cases;
}

function parsedOf(result) {
  return {
    records: result.records.map((record) => JSON.stringify(record)),
    corrupt: result.corrupt,
    completeLength: result.completeLength,
    tornTail: result.tornTail,
    unterminated: result.unterminated,
  };
}

function parseInputs(journal) {
  const line = (text) => Buffer.from(journal.encodeLine(JSON.parse(text)), 'utf8');
  const a = line(RECORDS.plain);
  const b = line(RECORDS.strings);
  const c = line(RECORDS.surrogates);
  const cut = (buf, n) => buf.subarray(0, buf.length - n);
  const damaged = Buffer.from(b);
  damaged[damaged.length - 5] ^= 0x01; // a byte of the record: its checksum fails
  const upper = Buffer.from(a.toString('latin1').replace(/sha256":"([0-9a-f]+)/, (_, d) => `sha256":"${d.toUpperCase()}`), 'latin1');
  const deep = `{"d":${'['.repeat(600)}${']'.repeat(600)}}`;
  const bytes = (...parts) => Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p, 'latin1'))));
  return [
    ['empty', bytes()],
    ['one-line', a],
    ['three-lines', bytes(a, b, c)],
    ['whole-last-record-without-newline', bytes(a, cut(b, 1))],
    ['only-record-without-newline', cut(a, 1)],
    ['torn-tail', bytes(a, cut(b, 2))],
    ['torn-tail-header-only', bytes(a, b.subarray(0, 40))],
    ['torn-tail-one-byte', bytes(a, '{')],
    ['torn-tail-zeros', bytes(a, Buffer.alloc(32))],
    ['zeros-then-newline', bytes(a, Buffer.alloc(8), '\n', c)],
    ['blank-line', bytes(a, '\n', c)],
    ['damaged-line', bytes(a, damaged, c)],
    ['damaged-unterminated-tail', bytes(a, cut(damaged, 1))],
    ['damaged-then-torn', bytes(damaged, cut(c, 3))],
    ['upper-case-digest', bytes(upper, c)],
    ['non-hex-digest', bytes(lineOf('{"a":1}', { digest: 'g'.repeat(64) }), c)],
    ['short-digest', bytes(Buffer.from(a.toString('latin1').replace(/sha256":"[0-9a-f]/, 'sha256":"'), 'latin1'), c)],
    ['other-record-key', Buffer.from(lineOf('{"a":1}').toString('latin1').replace('","record":', '","recorX":'), 'latin1')],
    ['version-2', bytes(Buffer.from(a.toString('latin1').replace('{"v":1', '{"v":2'), 'latin1'), c)],
    ['crlf', bytes(cut(a, 1), '\r\n', c)],
    ['no-closing-brace', bytes(cut(a, 2), '\n', c)],
    ['header-only-and-brace', lineOf('')],
    ['header-only-wrong-digest', lineOf('', { digest: sha('x') })],
    ['record-array', lineOf('[1]')],
    ['record-null', lineOf('null')],
    ['record-string', lineOf('"x"')],
    ['record-not-json', lineOf('{"a":}')],
    ['record-trailing-comma', lineOf('{"a":1,}')],
    ['record-bom', lineOf(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"a":1}')]))],
    ['record-spaced', lineOf(' { "a" : 1 }\t')],
    ['record-duplicate-keys', lineOf('{"a":1,"a":{"b":2}}')],
    ['record-lone-surrogate-escape', lineOf('{"a":"\\ud800"}')],
    ['record-invalid-utf8-ff', lineOf(Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]))],
    ['record-invalid-utf8-overlong', lineOf(Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xc0, 0x80, 0x22, 0x7d]))],
    ['record-invalid-utf8-surrogate', lineOf(Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xed, 0xa0, 0x80, 0x22, 0x7d]))],
    ['record-invalid-utf8-truncated', lineOf(Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xe2, 0x82, 0x22, 0x7d]))],
    ['record-invalid-utf8-truncated-4', lineOf(Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xf0, 0x9f, 0x98, 0x41, 0x22, 0x7d]))],
    ['record-invalid-utf8-in-key', lineOf(Buffer.from([0x7b, 0x22, 0xfe, 0x22, 0x3a, 0x31, 0x7d]))],
    ['record-control-char', lineOf('{"a":"\t"}')],
    ['record-depth-600', lineOf(deep), { deviation: 'json-depth' }],
  ];
}

function parseCases(journal) {
  return parseInputs(journal).map(([name, buffer, extra]) => {
    const result = parsedOf(journal.parseJournal(buffer));
    const entry = { name, bytes: hex(buffer), ...result };
    if (extra?.deviation === 'json-depth') {
      // The reference keeps the record; the core counts the line damaged.
      if (result.records.length !== 1) throw new Error('json-depth: the reference refused the record');
      entry.deviation = 'json-depth';
      entry.core = {
        records: [],
        corrupt: [{ line: 1, offset: 0, reason: 'malformed' }],
        completeLength: buffer.length,
        tornTail: 0,
        unterminated: false,
      };
    }
    return entry;
  });
}

async function readCases(journal, dir) {
  const cases = [];
  const file = path.join(dir, NAME);
  const reset = () => fs.rmSync(file, { recursive: true, force: true });
  const record = async (entry, maxBytes) => {
    try {
      const options = maxBytes === null ? undefined : { maxBytes };
      const result = await journal.readJournal(file, options);
      cases.push({ ...entry, maxBytes, result: { missing: result.missing, size: result.size, ...parsedOf(result) } });
    } catch (error) {
      if (!error.code) throw error;
      cases.push({ ...entry, maxBytes, error: error.code });
    }
  };
  reset();
  await record({ name: 'missing', kind: 'missing' }, null);
  const two = Buffer.concat([RECORDS.plain, RECORDS.order].map((t) => Buffer.from(journal.encodeLine(JSON.parse(t)), 'utf8')));
  for (const [name, maxBytes] of [
    ['under-the-bound', two.length + 1],
    ['at-the-bound', two.length],
    ['over-the-bound', two.length - 1],
    ['default-bound', null],
    ['zero-bound', 0],
  ]) {
    reset();
    fs.writeFileSync(file, two);
    await record({ name, kind: 'file', bytes: hex(two) }, maxBytes);
  }
  reset();
  fs.writeFileSync(file, '');
  await record({ name: 'empty-at-zero-bound', kind: 'file', bytes: '' }, 0);
  for (const [name, size, maxBytes] of [
    ['default-bound-exactly', DEFAULT_MAX_BYTES, null],
    ['default-bound-plus-one', DEFAULT_MAX_BYTES + 1, null],
    ['intent-read-bound-exactly', INTENT_READ_BYTES, INTENT_READ_BYTES],
    ['intent-read-bound-plus-one', INTENT_READ_BYTES + 1, INTENT_READ_BYTES],
  ]) {
    reset();
    fs.writeFileSync(file, '');
    fs.truncateSync(file, size);
    await record({ name, kind: 'zeros', size }, maxBytes);
  }
  reset();
  fs.mkdirSync(file);
  await record({ name: 'directory', kind: 'directory' }, null);
  reset();
  fs.writeFileSync(path.join(dir, 'target'), two);
  fs.symlinkSync('target', file);
  await record({ name: 'symlink', kind: 'symlink', bytes: hex(two) }, null);
  fs.rmSync(path.join(dir, 'target'));
  reset();
  return cases;
}

/** Every file in `dir`, by name, in hex, and the journal's mode. */
function snapshot(dir) {
  const files = {};
  for (const name of fs.readdirSync(dir).sort()) {
    files[name] = hex(fs.readFileSync(path.join(dir, name)));
  }
  const journalFile = path.join(dir, NAME);
  const mode = fs.existsSync(journalFile) ? fs.statSync(journalFile).mode & 0o777 : null;
  return { files, mode };
}

const line = (journal, text) => Buffer.from(journal.encodeLine(JSON.parse(text)), 'utf8');

function runs(journal) {
  const L = (text) => line(journal, text);
  const damaged = Buffer.from(L(RECORDS.strings));
  damaged[damaged.length - 5] ^= 0x01;
  return [
    {
      name: 'fresh',
      steps: [
        { op: 'open' },
        { op: 'append', record: RECORDS.plain },
        { op: 'append', record: RECORDS.strings },
        { op: 'append', record: RECORDS.surrogates },
      ],
    },
    {
      name: 'whole-last-record-without-newline',
      files: { [NAME]: Buffer.concat([L(RECORDS.plain), L(RECORDS.order).subarray(0, -1)]) },
      steps: [{ op: 'open' }, { op: 'append', record: RECORDS.numbers }],
    },
    {
      name: 'torn-tail',
      files: { [NAME]: Buffer.concat([L(RECORDS.plain), L(RECORDS.order).subarray(0, 50)]) },
      steps: [{ op: 'open' }, { op: 'append', record: RECORDS.numbers }],
    },
    {
      name: 'damaged-line',
      files: { [NAME]: Buffer.concat([L(RECORDS.plain), damaged, L(RECORDS.order)]) },
      steps: [{ op: 'open' }, { op: 'append', record: RECORDS.duplicate }],
    },
    {
      name: 'compaction',
      steps: [
        { op: 'open' },
        { op: 'append', record: RECORDS.plain },
        { op: 'append', record: RECORDS.order },
        { op: 'append', record: RECORDS.numbers },
        { op: 'compact', records: [RECORDS.plain, RECORDS.numbers] },
        { op: 'append', record: RECORDS.unicodeKeys },
        { op: 'compact', records: [] },
        { op: 'append', record: RECORDS.empty },
        { op: 'open' },
      ],
    },
    {
      name: 'compaction-temps',
      files: {
        [NAME]: L(RECORDS.plain),
        [`${NAME}.compact-1b4e28ba-2fa1-41d2-883f-0016d3cca427.tmp`]: Buffer.from('partial'),
        [`${NAME}.compact-.tmp`]: Buffer.from(''),
        [`${NAME}.compact-1b4e28ba.tmp.keep`]: Buffer.from('kept'),
        [`other.jsonl.compact-1b4e28ba.tmp`]: Buffer.from('kept'),
        [`.${NAME}.123.0.tmp`]: Buffer.from('kept'),
      },
      steps: [{ op: 'open' }, { op: 'compact', records: [RECORDS.plain] }],
    },
    {
      name: 'move-aside',
      files: { [NAME]: L(RECORDS.plain), [`${NAME}.corrupt-1`]: Buffer.from('earlier') },
      steps: [
        { op: 'open' },
        { op: 'moveAside', tag: 'corrupt-1' },
        { op: 'moveAside', tag: 'corrupt-1' },
        { op: 'append', record: RECORDS.order },
        { op: 'moveAside', tag: 'corrupt-1' },
        { op: 'append', record: RECORDS.empty },
      ],
    },
    {
      name: 'too-large',
      maxBytes: 100,
      files: { [NAME]: Buffer.concat([L(RECORDS.plain), L(RECORDS.order)]) },
      steps: [
        { op: 'open' },
        { op: 'append', record: RECORDS.empty },
        { op: 'moveAside', tag: 'corrupt-2' },
        { op: 'append', record: RECORDS.empty },
        { op: 'open' },
      ],
    },
    {
      name: 'refusals',
      steps: [
        { op: 'append', record: '[1]' },
        { op: 'append', record: RECORDS.empty },
        { op: 'compact', records: [RECORDS.empty, '2'] },
        { op: 'compact', records: [RECORDS.empty] },
        { op: 'open' },
        { op: 'append', record: 'null' },
        { op: 'compact', records: [RECORDS.empty] },
      ],
    },
  ];
}

async function runCases(journal, root) {
  const out = [];
  for (const run of runs(journal)) {
    const dir = fs.mkdtempSync(path.join(root, 'run-'));
    for (const [name, bytes] of Object.entries(run.files ?? {})) {
      fs.writeFileSync(path.join(dir, name), bytes, { mode: 0o644 });
      fs.chmodSync(path.join(dir, name), 0o644);
    }
    const start = snapshot(dir);
    const instance = journal.createJournal(path.join(dir, NAME), run.maxBytes ? { maxBytes: run.maxBytes } : undefined);
    const steps = [];
    for (const step of run.steps) {
      let outcome;
      try {
        if (step.op === 'open') outcome = { result: parsedOf(await instance.open()) };
        else if (step.op === 'append') outcome = { result: (await instance.append(JSON.parse(step.record))) ?? null };
        else if (step.op === 'compact') outcome = { result: (await instance.compact(step.records.map((t) => JSON.parse(t)))) ?? null };
        else if (step.op === 'moveAside') {
          const moved = await instance.moveAside(step.tag);
          outcome = { result: moved === null ? null : path.basename(moved) };
        } else throw new Error(`unknown op ${step.op}`);
      } catch (error) {
        if (!error.code) throw error;
        outcome = { error: error.code };
      }
      steps.push({ ...step, ...outcome, size: instance.size, ...snapshot(dir) });
    }
    out.push({ name: run.name, maxBytes: run.maxBytes ?? null, ...start, steps });
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return out;
}

async function buildJournal(checkout, meta) {
  const journal = require(path.join(checkout, 'src/main/lib/durable-journal.js'));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-journal-vectors-'));
  try {
    return {
      meta,
      constants: {
        name: NAME,
        defaultMaxBytes: DEFAULT_MAX_BYTES,
        intentReadBytes: INTENT_READ_BYTES,
        intentFileBytes: INTENT_FILE_BYTES,
        fileMode: journal.FILE_MODE,
      },
      encode: encodeCases(journal),
      parse: parseCases(journal),
      read: await readCases(journal, root),
      journal: await runCases(journal, root),
    };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

module.exports = { buildJournal, lineOf };
