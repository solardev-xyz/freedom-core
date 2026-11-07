'use strict';

// rad.blob (design 0008, "The blob API", "Ranges", "Errors" and "Tests
// first"): a blob's raw bytes, or a byte range of them, and its head
// `{ oid, size, binary, range }`.
//
// The reference has no raw endpoint and reads no Range header: today a
// blob reaches a page only as `/blob/<rev>/<path>`, the add-on's JSON
// (`{ binary, name, content? }`), which `rad.read`'s `blob_at` serves. So
// each file's `main` is that route's answer from the reference's own
// radicle-embedded.js and radicle-api-protocol.js, through radicle-reads.js'
// harness with a scripted add-on: what main shows of the file today, and how
// it answers libradicle's errors (404 by its message test, else 500). What
// `rad.blob` adds is the design's (`source: design`): the head, the bytes,
// the ranges, the size cap, and main's HTTP answer built on them, checked
// here against the browser's pending `blob-api` and `size-caps` contract
// tests (src/main/radicle-backend.contract.test.js on integration/rust-core).
//
// `binary` is libgit2's rule (`git_blob_is_binary`), which the add-on's
// `blob_at` gives today: its first 8000 bytes hold a NUL, a UTF-16 or
// UTF-32 byte order mark, or fewer than 128 printable bytes for each
// non-printable one. It is ported here, and the service's tests check it
// against libradicle on the same files.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { loadMain } = require('./radicle-reads');

// Where the reference looks for the add-on (radicle-reads.js').
const ADDON = '/freedom-core-vectors/libradicle.node';

const RID = 'rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5';
const REV = 'a'.repeat(40);
/** The largest blob rad.blob serves, and a data frame's most. */
const BLOB = 64 * 1024 * 1024;
const CHUNK = 64 * 1024;

const text = (value) => JSON.stringify(value);
const error = (message) => text({ error: message });
const bytes = (...parts) => Buffer.concat(parts.map((p) => (typeof p === 'string' ? Buffer.from(p, 'latin1') : Buffer.from(p))));
const repeat = (byte, n) => Buffer.alloc(n, byte);

/** libgit2's `git_str_detect_bom`: the mark's kind and its length. */
function bom(buf) {
  if (buf.length < 2) return ['none', 0];
  const [a, b, c, d] = buf;
  if (a === 0x00 && buf.length >= 4 && b === 0x00 && c === 0xfe && d === 0xff) return ['utf32-be', 4];
  if (a === 0xef && buf.length >= 3 && b === 0xbb && c === 0xbf) return ['utf8', 3];
  if (a === 0xfe && b === 0xff) return ['utf16-be', 2];
  if (a === 0xff && b === 0xfe) return buf.length >= 4 && c === 0x00 && d === 0x00 ? ['utf32-le', 4] : ['utf16-le', 2];
  return ['none', 0];
}

/** libgit2's `git_blob_is_binary`: `git_str_is_binary` of the first 8000
 * bytes. */
function isBinary(content) {
  const buf = content.subarray(0, 8000);
  const [kind, skip] = bom(buf);
  if (kind !== 'none' && kind !== 'utf8') return true;
  let printable = 0;
  let nonprintable = 0;
  for (const c of buf.subarray(skip)) {
    if ((c > 0x1f && c !== 0x7f) || c === 0x08 || c === 0x1b || c === 0x0c) printable += 1;
    else if (c === 0x00) return true;
    else if (![0x20, 0x09, 0x0a, 0x0c, 0x0d, 0x0b].includes(c)) nonprintable += 1;
  }
  return (printable >> 7) < nonprintable;
}

/** A blob's object ID: SHA-1 of `blob <size>\0` and its content. */
const oidOf = (content) => crypto.createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${content.length}\0`), content])).digest('hex');

// The fixture: each file's path, mode and content. A file larger than a few
// KiB is given by its one repeated byte (`fill`).
const README = bytes('# Blob fixture\n\nA repository for rad.blob and its ranges.\n');
const FILES = [
  { path: 'README.md', content: README },
  { path: 'one.txt', content: bytes('x') },
  { path: 'empty.txt', content: bytes() },
  { path: 'image.png', content: bytes([0x89], 'PNG\r\n', [0x1a, 0x0a, 0, 0, 0, 0x0d], 'IHDR', [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]) },
  { path: 'latin1.txt', content: bytes('caf', [0xe9], ' cr', [0xe8], 'me\n') },
  { path: 'bom-utf8.txt', content: bytes([0xef, 0xbb, 0xbf], 'hello\n') },
  { path: 'utf16.txt', content: bytes([0xff, 0xfe], 'h', [0], 'i', [0], '\n', [0]) },
  { path: 'controls.bin', content: bytes(repeat(0x01, 129), 'abc') },
  { path: 'late-nul.txt', content: bytes(repeat(0x61, 8000), [0], 'tail\n') },
  { path: 'dir/inner.txt', content: bytes('inner\n') },
  { path: 'link', mode: '120000', content: bytes('README.md') },
  { path: 'cap.bin', fill: 0x62, size: BLOB },
  { path: 'big.bin', fill: 0x61, size: BLOB + 1 },
];
// A submodule: a gitlink to a commit the repository doesn't have.
const SUBMODULE = { path: 'sub', mode: '160000', commit: '07'.repeat(20) };

const filled = new Map();
const contentOf = (f) => {
  if (f.fill === undefined) return f.content;
  if (!filled.has(f)) filled.set(f, repeat(f.fill, f.size));
  return filled.get(f);
};

/** Main's parse of a Range header, as 0008 says it ("Ranges"): a single
 * `bytes=` range into `rad.blob`'s `range`; several ranges, or a header
 * that doesn't parse, give none. */
function parseRange(header) {
  if (header === null) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header);
  if (!m || (m[1] === '' && m[2] === '')) return null;
  const n = (s) => Number(s);
  if (m[1] === '') return { suffix: n(m[2]) };
  if (m[2] === '') return { start: n(m[1]) };
  return n(m[1]) <= n(m[2]) ? { start: n(m[1]), end: n(m[2]) } : null;
}

/** 0008's "Ranges": the range normalized against `size`, or `null` when
 * it is outside the blob. */
function span(range, size) {
  if (size === 0) return null;
  const last = size - 1;
  let start;
  let end;
  if ('suffix' in range) {
    if (range.suffix === 0) return null;
    [start, end] = [Math.max(0, size - range.suffix), last];
  } else {
    [start, end] = [range.start, 'end' in range ? Math.min(range.end, last) : last];
  }
  return start > last ? null : { start, end };
}

/** A body's bytes: hex, or a repeated byte past a few KiB. */
function body(file, start, end) {
  if (end < start) return null;
  if (file.fill !== undefined) return { fill: file.fill.toString(16).padStart(2, '0'), len: end - start + 1 };
  return { hex: contentOf(file).subarray(start, end + 1).toString('hex') };
}

/** rad.blob's answer for `file` with `params` (0008, "The blob API"). */
function expectFor(file, params) {
  const content = contentOf(file);
  const size = content.length;
  if (size > BLOB) return { error: { code: 'too_large', message: `${size} bytes is over the limit of ${BLOB}` } };
  let range = null;
  if (params.range !== null) {
    range = span(params.range, size);
    if (range === null) return { error: { code: 'range_not_satisfiable', data: { size } } };
  }
  const oid = oidOf(content);
  if (params.head_only) return { head: { oid, size, range }, body: null };
  const [start, end] = range === null ? [0, size - 1] : [range.start, range.end];
  return { head: { oid, size, binary: isBinary(content), range }, body: body(file, start, end) };
}

/** Main's HTTP answer built on rad.blob's (0008, "Ranges" and "Errors"). */
function httpOf(expect) {
  if (expect.error) {
    const status = { too_large: 413, range_not_satisfiable: 416, not_found: 404, failed: 500 }[expect.error.code];
    const headers = expect.error.code === 'range_not_satisfiable' ? { 'content-range': `bytes */${expect.error.data.size}` } : {};
    return { status, headers };
  }
  const { size, range } = expect.head;
  if (range === null) return { status: 200, headers: { 'content-length': String(size) } };
  return {
    status: 206,
    headers: { 'content-length': String(range.end - range.start + 1), 'content-range': `bytes ${range.start}-${range.end}/${size}` },
  };
}

/** The add-on's `blobAt` text for `file` (libradicle's `json::blob`). */
function blobText(file) {
  const content = contentOf(file);
  const name = file.path.split('/').pop();
  return isBinary(content) ? text({ binary: true, name }) : text({ binary: false, name, content: content.toString('utf8') });
}

const S = README.length;
/** Each file's ranges, as Range headers main gets. */
const HEADERS = {
  'README.md': [
    null, 'bytes=0-9', 'bytes=5-', 'bytes=-10', `bytes=5-${S + 1000}`, `bytes=${S}-`, 'bytes=0-1,4-5',
    'bytes=0-0', `bytes=${S - 1}-`, `bytes=${S - 1}-${S - 1}`, `bytes=-${S}`, `bytes=-${S + 5}`, 'bytes=-1', 'bytes=-0',
    `bytes=${S}-${S + 10}`, 'bytes=999999-', `bytes=0-${2 ** 53 - 1}`, 'bytes=5-2', 'bytes=abc', 'bytes=-', 'items=0-9',
  ],
  'one.txt': [null, 'bytes=0-0', 'bytes=0-', 'bytes=-1', 'bytes=-5', 'bytes=1-', 'bytes=0-7'],
  'empty.txt': [null, 'bytes=0-', 'bytes=0-0', 'bytes=-1', 'bytes=-0'],
  'image.png': [null, 'bytes=1-3'],
  'latin1.txt': [null, 'bytes=3-3'],
  'bom-utf8.txt': [null],
  'utf16.txt': [null],
  'controls.bin': [null],
  'late-nul.txt': [null, 'bytes=7998-8002'],
  'dir/inner.txt': [null],
  link: [null],
  'cap.bin': [null, 'bytes=-10', `bytes=${BLOB - 1}-`, `bytes=${CHUNK - 1}-${CHUNK}`],
  'big.bin': [null, 'bytes=0-0'],
};

// libradicle's errors, as the add-on's `blobAt` gives them at v0.8.0 (its
// texts in the browser's contract vectors): a missing path, an object that
// isn't a blob, and a missing repository; each through main's `/blob/`.
const ERRORS = [
  ['missing-path', 'missing.txt', "the path 'missing.txt' does not exist in the given tree; class=Tree (14); code=NotFound (-3)"],
  ['missing-dir', 'nodir/x.txt', "the path 'nodir' does not exist in the given tree; class=Tree (14); code=NotFound (-3)"],
  ['under-a-file', 'README.md/x', "the path 'README.md/x' does not exist in the given tree; class=Tree (14); code=NotFound (-3)"],
  ['directory', 'dir', 'not a file: dir'],
  ['submodule', 'sub', 'not a file: sub'],
];

/** `rad.blob`'s params that don't parse: `invalid_argument`. `$rid` and
 * `$revision` are the fixture's. */
const INVALID = [
  ['range-start-after-end', { range: { start: 5, end: 2 } }],
  ['range-negative', { range: { start: -1 } }],
  ['range-float', { range: { start: 1.5 } }],
  ['range-string', { range: 'bytes=0-9' }],
  ['range-several', { range: [{ start: 0, end: 1 }, { start: 4, end: 5 }] }],
  ['range-array', { range: [0, 9] }],
  ['params-array', '$array'],
  ['range-empty', { range: {} }],
  ['range-end-alone', { range: { end: 9 } }],
  ['range-two-shapes', { range: { start: 0, suffix: 1 } }],
  ['range-unknown-member', { range: { start: 0, end: 1, unit: 'bytes' } }],
  ['head-only-not-boolean', { head_only: 'yes' }],
  ['unknown-param', { offset: 0 }],
  ['revision-uppercase', { revision: '$REVISION' }],
  ['revision-short', { revision: 'abc' }],
  ['rid', { rid: 'rad:not-a-repository' }],
  ['path-missing', { path: null }],
];

async function mainOf(main, addonText, path) {
  const { world, protocol } = main;
  world.script = [{ export: 'blobAt', args: [RID, REV, path], text: addonText }];
  world.calls = [];
  world.warnings = [];
  world.unscripted = [];
  const response = await protocol.serveRepoApi(RID, `/blob/${REV}/${path}`, { allowPrivate: true });
  const answer = { status: response.status, body: await response.text() };
  assert.deepEqual(world.unscripted, [], path);
  assert.ok(world.script[0].used, path);
  return answer;
}

/** The browser's pending contract tests, on this fixture: what they expect
 * of main's answers. */
function checkContract(cases) {
  const of = (path, method, header) => cases.find((c) => c.path === path && c.method === method && c.header === header);
  const expectHttp = (path, header, status, headers, method = 'GET') => {
    const c = of(path, method, header);
    assert.ok(c, `${path} ${method} ${header}`);
    assert.deepEqual(c.http, { status, headers }, `${path} ${method} ${header}`);
  };
  const len = (n) => ({ 'content-length': String(n) });
  // 'ranges: 206 with Content-Range, an end past EOF clamped'
  for (const [header, start, end] of [['bytes=0-9', 0, 9], ['bytes=5-', 5, S - 1], ['bytes=-10', S - 10, S - 1], [`bytes=5-${S + 1000}`, 5, S - 1]]) {
    expectHttp('README.md', header, 206, { ...len(end - start + 1), 'content-range': `bytes ${start}-${end}/${S}` });
    assert.equal(of('README.md', 'GET', header).expect.body.hex, README.subarray(start, end + 1).toString('hex'));
  }
  // 'a start past EOF is 416; several ranges are the whole blob'
  expectHttp('README.md', `bytes=${S}-`, 416, { 'content-range': `bytes */${S}` });
  expectHttp('README.md', 'bytes=0-1,4-5', 200, len(S));
  assert.equal(of('README.md', 'GET', 'bytes=0-1,4-5').expect.body.hex, README.toString('hex'));
  // 'a zero-length blob: 200 with no range, 416 with one'
  expectHttp('empty.txt', null, 200, len(0));
  assert.equal(of('empty.txt', 'GET', null).expect.body, null);
  expectHttp('empty.txt', 'bytes=0-', 416, { 'content-range': 'bytes */0' });
  // 'HEAD answers as GET would, with no body, with and without a range'
  for (const header of [null, 'bytes=0-9', 'bytes=999999-']) {
    assert.deepEqual(of('README.md', 'HEAD', header).http, of('README.md', 'GET', header).http, `HEAD ${header}`);
    assert.equal(of('README.md', 'HEAD', header).expect.body ?? null, null);
  }
  // 'a blob over 64 MiB is too_large: refused by the read, 413 at both handlers'
  expectHttp('big.bin', null, 413, {});
  expectHttp('big.bin', null, 413, {}, 'HEAD');
}

async function buildRadicleBlob(checkout, meta) {
  const previous = process.env.FREEDOM_RADICLE_ADDON;
  process.env.FREEDOM_RADICLE_ADDON = ADDON;
  try {
    const main = loadMain(checkout);
    const files = [];
    for (const f of FILES) {
      const content = contentOf(f);
      const entry = { path: f.path, mode: f.mode || '100644' };
      if (f.fill === undefined) entry.hex = content.toString('hex');
      else Object.assign(entry, { fill: f.fill.toString(16).padStart(2, '0') });
      Object.assign(entry, { size: content.length, oid: oidOf(content), binary: isBinary(content) });
      // What main shows of it today. A large file's JSON, which is as long
      // as it is, isn't recorded.
      if (f.fill === undefined) {
        const addon = blobText(f);
        entry.main = await mainOf(main, addon, f.path);
        assert.deepEqual(entry.main, { status: 200, body: addon }, f.path);
      }
      files.push(entry);
    }
    files.push({ path: SUBMODULE.path, mode: SUBMODULE.mode, commit: SUBMODULE.commit });

    const cases = [];
    for (const f of FILES) {
      for (const header of HEADERS[f.path]) {
        for (const method of ['GET', 'HEAD']) {
          const params = { range: parseRange(header), head_only: method === 'HEAD' };
          const expect = expectFor(f, params);
          const id = `${f.path} ${method} ${header ?? '(no range)'}`;
          cases.push({ id, path: f.path, method, header, params, expect, http: httpOf(expect) });
        }
      }
    }
    assert.equal(new Set(cases.map((c) => c.id)).size, cases.length);
    checkContract(cases);

    const errors = [];
    for (const [id, path, message] of ERRORS) {
      const answer = await mainOf(main, error(message), path);
      const code = answer.status === 404 ? 'not_found' : 'failed';
      assert.deepEqual(answer, { status: code === 'not_found' ? 404 : 500, body: error(message) }, id);
      for (const [method, header] of [['GET', null], ['HEAD', null], ['GET', 'bytes=0-0']]) {
        const params = { range: parseRange(header), head_only: method === 'HEAD' };
        const expect = { error: { code, message } };
        errors.push({ id: `${id} ${method} ${header ?? '(no range)'}`, path, method, header, params, addon: error(message), main: answer, expect, http: httpOf(expect) });
      }
    }
    assert.ok(errors.some((e) => e.expect.error.code === 'not_found'));
    assert.ok(errors.some((e) => e.expect.error.code === 'failed'));

    const invalid = INVALID.map(([id, over]) => {
      // The params as an array of their values.
      if (over === '$array') return { id, params: ['$rid', '$revision', 'README.md'], expect: { error: { code: 'invalid_argument' } } };
      const params = { rid: '$rid', revision: '$revision', path: 'README.md', ...over };
      for (const [k, v] of Object.entries(params)) if (v === null) delete params[k];
      return { id, params, expect: { error: { code: 'invalid_argument' } } };
    });

    // Coverage the Rust side relies on.
    for (const code of ['too_large', 'range_not_satisfiable']) assert.ok(cases.some((c) => c.expect.error?.code === code), code);
    for (const status of [200, 206]) assert.ok(cases.some((c) => c.http.status === status && c.method === 'GET'), status);
    assert.ok(files.some((f) => f.binary) && files.some((f) => f.binary === false));

    return {
      meta,
      formats: {
        files: 'The fixture repository, one commit: each file\'s path, git mode, content (`hex`, or `fill`, one byte repeated `size` times), blob `oid`, `size` and `binary` (libgit2\'s `git_blob_is_binary`, as the add-on gives it), and `main`: what the reference answers for it today at `/blob/<rev>/<path>` (serveRepoApi with allowPrivate, the add-on scripted with libradicle\'s `blob_at` JSON for that content). A file given by `fill` has no `main`: its JSON is as long as it is (and past 64 MiB rad.blob refuses it, deviation `size-caps`). The `160000` entry is a submodule: a gitlink to `commit`.',
        cases: 'rad.blob for a file (`source: design`, 0008 "The blob API" and "Ranges"): `header` is the Range header main gets and `params` what main sends for it (a single `bytes=` range parsed; several, or one that doesn\'t parse, none); `method` HEAD sends `head_only`. `expect` is the head (`oid`, `size`, `binary` but not for HEAD, `range` served or null) and the body (`hex`, or `fill` repeated `len` times; null for none: no stream), or the error (`code`, `data`). `http` is main\'s answer on it: status, Content-Length and Content-Range. The browser\'s pending blob-api and size-caps contract tests are checked against these.',
        errors: 'libradicle\'s errors for a path (the add-on\'s v0.8.0 texts): the scripted `addon` answer, `main` (the reference\'s `/blob/` answer: 404 by its message test, else 500, with `{"error": message}`), and rad.blob\'s `expect`: `not_found` or `failed` with the same message, before any range.',
        invalid: 'rad.blob params that don\'t parse (`source: design`): `invalid_argument`. `$rid` and `$revision` stand for the fixture\'s; `$REVISION` for its revision in upper case.',
      },
      constants: { blob: BLOB, chunk: CHUNK },
      files,
      cases,
      errors,
      invalid,
    };
  } finally {
    if (previous === undefined) delete process.env.FREEDOM_RADICLE_ADDON;
    else process.env.FREEDOM_RADICLE_ADDON = previous;
  }
}

module.exports = { buildRadicleBlob };
