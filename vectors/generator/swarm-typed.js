'use strict';

// Design 0015's typed form of a request's params ("Main's encoding of a
// request") and of the values the reference answers with, as
// vectors/swarm.json writes them. The validators read JavaScript types,
// which JSON loses, so every value is tagged:
//
//   { "string": s }            a well-formed string
//   { "string_json": t }       a string with a lone surrogate, as its JSON text t
//   { "number": "1.5" }        String(n), "-0" for negative zero, "NaN", "Infinity", "-Infinity"
//   { "bigint": "123" }        its decimal text
//   { "boolean": b }  { "null": true }  { "undefined": true }
//   { "array": [v, …] }        holes as { "hole": true }
//   { "object": [[k, v], …] }  own enumerable string keys, in order
//   { "bytes": n, "kind": k, "base64": b }   a value normalizeBytes accepts, where a method
//   { "bytes": n, "kind": k, "part": i }     reads bytes; past 64 KiB the core pulls it as part i
//   { "string_bytes": n, "base64": b }       a string where a method reads data: its UTF-8
//   { "string_bytes": n, "part": i }         (Buffer.from(s, 'utf-8'), a lone surrogate as U+FFFD)
//
// `kind` is `Buffer`, `Uint8Array`, `ArrayBuffer` or `BufferJSON` (`{ type:
// 'Buffer', data: [...] }`, whose bytes are Buffer.from(data)'s). A value at a
// data position that normalizeBytes refuses keeps its plain tag.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const INLINE_BYTES = 64 * 1024;

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function numberText(n) {
  if (Object.is(n, -0)) return '-0';
  return String(n);
}

/**
 * `value` as a typed tree. `dataAt(path)` says what a position reads:
 * `'data'` (bytes, or a string as its UTF-8), `'bytes'` (bytes only: a string
 * there keeps its tag), or nothing.
 */
function encode(value, { dataAt = () => false, parts = null, seeds = new WeakMap(), path = [], digestOver = Infinity } = {}) {
  const recurse = (child, key) => encode(child, { dataAt, parts, seeds, path: [...path, key], digestOver });
  if (typeof value === 'string' && value.length > digestOver) {
    // A long answer string: its length in UTF-16 units and the SHA-256 of its UTF-8.
    return { string_digest: value.length, sha256: sha256(Buffer.from(value, 'utf8')) };
  }
  const reads = dataAt(path);
  if (reads && (reads === 'data' || typeof value !== 'string')) {
    const bytes = dataBytes(value);
    if (bytes) {
      const tag = typeof value === 'string' ? { string_bytes: bytes.length } : { bytes: bytes.length, kind: bytes.kind };
      if (bytes.length <= INLINE_BYTES) return { ...tag, base64: Buffer.from(bytes.view).toString('base64') };
      assert.ok(parts, 'a large value needs a parts list');
      // A large value's bytes: content(seed, n), or a string that repeats a
      // short unit (`repeat`, `count`).
      const source = typeof value === 'string' ? repeatOf(value) : seeds.get(value);
      assert.ok(source, 'a large value must come from content(seed, n) or repeat a short string');
      const described = source.seed !== undefined ? { seed: source.seed } : { repeat: source.repeat, count: source.count };
      parts.push({ part: parts.length, ...described, length: bytes.length, sha256: sha256(bytes.view) });
      return { ...tag, part: parts.length - 1 };
    }
  }
  if (value === undefined) return { undefined: true };
  if (value === null) return { null: true };
  switch (typeof value) {
    case 'string': {
      // A string with a lone surrogate, as its JSON text (whose escapes every
      // JSON reader takes); a long string that repeats a short unit, as its
      // unit and count.
      if (!value.isWellFormed()) return { string_json: JSON.stringify(value) };
      const repeat = value.length > INLINE_BYTES ? repeatOf(value) : null;
      return repeat ? { string_repeat: repeat.repeat, count: repeat.count } : { string: value };
    }
    case 'number': return { number: numberText(value) };
    case 'bigint': return { bigint: value.toString() };
    case 'boolean': return { boolean: value };
    default: break;
  }
  if (Array.isArray(value)) {
    const items = [];
    for (let i = 0; i < value.length; i++) items.push(i in value ? recurse(value[i], i) : { hole: true });
    return { array: items };
  }
  assert.equal(typeof value, 'object', `no typed form for ${typeof value}`);
  if (Buffer.isBuffer(value) || value instanceof Uint8Array || value instanceof ArrayBuffer) {
    // Bytes where no method reads them: their kind and bytes, all the same.
    const view = value instanceof ArrayBuffer ? new Uint8Array(value) : value;
    return { bytes_elsewhere: view.byteLength, kind: kindOf(value), base64: Buffer.from(view).toString('base64') };
  }
  return { object: Object.keys(value).map((key) => [key, recurse(value[key], key)]) };
}

/** `{ repeat, count }` when `text` is a short unit repeated, else null. */
function repeatOf(text) {
  for (let n = 1; n <= 16 && n <= text.length; n++) {
    const unit = text.slice(0, n);
    if (text.length % n === 0 && unit.repeat(text.length / n) === text) return { repeat: unit, count: text.length / n };
  }
  return null;
}

function kindOf(value) {
  if (Buffer.isBuffer(value)) return 'Buffer';
  if (value instanceof Uint8Array) return 'Uint8Array';
  if (value instanceof ArrayBuffer) return 'ArrayBuffer';
  return 'BufferJSON';
}

/** The bytes normalizeBytes (or a string's UTF-8) gives for `value`, or null. */
function dataBytes(value) {
  if (typeof value === 'string') {
    const view = Buffer.from(value, 'utf-8');
    return { view, length: view.length, kind: 'string' };
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return { view: value, length: value.byteLength, kind: kindOf(value) };
  if (value instanceof ArrayBuffer) return { view: new Uint8Array(value), length: value.byteLength, kind: 'ArrayBuffer' };
  if (value && typeof value === 'object' && value.type === 'Buffer' && Array.isArray(value.data)) {
    const view = Buffer.from(value.data);
    return { view, length: view.length, kind: 'BufferJSON' };
  }
  return null;
}

/** Whether JSON keeps `value` exactly (no bigint, undefined, -0, NaN or infinity, no lone surrogate issue). */
function jsonExact(value) {
  if (value === null) return true;
  switch (typeof value) {
    case 'string': return value.isWellFormed();
    case 'boolean': return true;
    case 'number': return Number.isFinite(value) && !Object.is(value, -0);
    case 'object': break;
    default: return false;
  }
  if (Array.isArray(value)) return value.every((item, i) => i in value && jsonExact(item));
  if (Object.getPrototypeOf(value) !== Object.prototype) return false;
  return Object.values(value).every(jsonExact);
}

// An answer's strings past this many units are written as their digest.
const ANSWER_STRING_UNITS = 8192;

function hasLongString(value) {
  if (typeof value === 'string') return value.length > ANSWER_STRING_UNITS;
  if (value && typeof value === 'object') return Object.values(value).some(hasLongString);
  return false;
}

/**
 * An answer as the vectors write it: `{ key: value }` when JSON keeps it,
 * else `{ key_typed: … }` (also when a string in it is past 8,192 units,
 * which the typed form writes as its digest).
 */
function answer(key, value) {
  if (jsonExact(value) && !hasLongString(value)) return { [key]: value };
  return { [`${key}_typed`]: encode(value, { digestOver: ANSWER_STRING_UNITS }) };
}

module.exports = { encode, answer, jsonExact, dataBytes, INLINE_BYTES };
