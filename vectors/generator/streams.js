'use strict';

// Stream frame vectors (design 0007, implementation step 3). No reference
// implementation exists yet: freedom-browser's frame.js gains the stream
// kinds in step 6. So every case and every outcome here is the design's
// (0007, "Frames"), written out by hand below; nothing is computed by a model
// of the rules. fc-protocol's tests replay them, and frame.js will.
//
// The generator only lays the cases out. It builds frame bytes from their
// parts (a length field, a kind, an ID, a payload) and checks every case's
// shape, so a typo fails generation instead of passing as an expectation.
//
// The formats are in the file's `formats` member.

const assert = require('node:assert/strict');

const KINDS = { json: 0x01, data: 0x02, end: 0x03, abort: 0x04, credit: 0x05 };
const ID_BYTES = 8;
const WINDOW = 128 * 1024;
const MAX_DATA = 64 * 1024;
const MAX_ABORT_JSON = 1024;
const MAX_PULL = 64 * 1024;
const SMALL_FRAME = 4 * 1024;
const WRITER_DATA_CAP = 16 * 1024 * 1024;
const MAX_PAYLOAD = 1024 * 1024;
const MAX_ID = 2 ** 53 - 1;
const ABORT_CODES = ['cancelled', 'internal', 'body_stream_error', 'stopped', 'busy'];
const SIDES = ['receiver', 'sender', 'core'];

const FORMATS = {
  body_bytes: 'Byte k of stream id\'s body is ((id mod 251) + (k mod 251)) mod 251, with k counted from the body\'s start.',
  bytes: 'A list of parts, concatenated: {"hex": "<lowercase hex>"} or {"fill": [byte, count]}.',
  frames: 'Decoding. `side` is the decoder: "receiver" (main, after a handshake that granted stream), "sender" (the service, likewise) or "core" (a freedom-cored connection, which never grants stream). `input` is fed whole, and in any chunking the outcome is the same. `expect.frames` lists every frame decoded, as ["json", text], ["data", id, bytes], ["end", id], ["abort", id, code, message] or ["credit", id, n]. `expect.truncated` means the input stops inside a frame: EOF there truncates it. `expect.error` is the first failure\'s category, from the header check, the ID or the payload; frames before it are not asserted.',
  encodings: '`frame` encodes to exactly `hex`, or is refused with `error` and nothing written. `frame` is as in `frames`.',
  sender: 'The service\'s side. Steps run in order. A step with `do` is an action with its `expect`ed result: ["request", id] main\'s request (ok, or a protocol error); ["cancel", id] main\'s cancel ("cancelled": the reply or abort is queued and the work is to stop; "late": nothing changes); ["credit", id, n] main\'s credit frame ("taken" into the stream\'s account, "late" for a stream that has ended, or a protocol error); ["head", id, body] the response that heads request id, opening a stream if body is true; ["reply", id] the request\'s one reply without a body (an error, or a result); ["push", id, n] the producer offers its next n body bytes (`taken` says how many were queued; the producer keeps the rest); ["finish", id] the end, after every byte queued; ["abort", id, code]. Producer refusals are `refused`: gone, unknown, answered, not_open, ended, too_large or closed. A step with `write` takes frames from the writer until it has none, and they must be exactly those listed; `write_some` takes exactly those listed and may leave more. Written frames are ["head", id], ["reply", id], ["cancelled", id] (the reply a cancel made the request\'s only one), ["data", id, offset, length] (bytes of the body from offset), ["end", id] and ["abort", id, code]. `check` compares the writer\'s held bytes (queued body bytes across streams) and, per ID, whether the request is live, its producer\'s room (the window\'s room within the writer\'s, null without a body that takes bytes) and its queued bytes (null without a body). A push takes as much as the room allows, except that one the writer\'s cap would cut below 4 KiB takes nothing. `repeat` runs its step that many times. `config.data_cap` replaces the writer\'s 16 MiB cap. After a protocol error, every main step reports the same error, every producer step is refused with `closed`, and nothing is written.',
  receiver: 'Main\'s side. ["request", id] main sends request id (ok, or request_order for main\'s own bug); ["reply", id, opens] its reply arrives, a head with body: true when opens ("deliver", "retired", or a protocol error); ["data", id, n] a data frame with the service\'s next n bytes of stream id; ["end", id]; ["abort", id, code]. Frames give "data", "end" (bytes are left to pull), "end_drained" (nothing is left: the record and ring are gone), "abort", "dropped" (the stream is retiring), or a protocol error. ["pull", id, max] the consumer pulls: null without a record, else the chunk as [offset, length] of the body, the credit to send (null for none) and whether it is the last. ["cancel", id] a local cancel: "send_cancel", "freed" (end had arrived: nothing is sent) or "nothing". `check` compares, per ID, the record (null for none) with its state (pending, retired_pending, open, eof, retiring), whether its ring is allocated, the bytes in it, and received and returned bytes; and the outstanding records. After a protocol error, every frame and reply reports the same error.',
};

// ---------------------------------------------------------------------------
// Bytes

const be32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const hex = (b) => Buffer.from(b).toString('hex');
const H = (b) => ({ hex: hex(b) });
const fill = (byte, count) => ({ fill: [byte, count] });
const partLength = (p) => (p.hex !== undefined ? p.hex.length / 2 : p.fill[1]);
const ascii = (text) => H(Buffer.from(text, 'utf8'));

// Merges neighbouring hex parts.
function joined(parts) {
  const out = [];
  for (const part of parts) {
    const last = out[out.length - 1];
    if (part.hex !== undefined && last && last.hex !== undefined) last.hex += part.hex;
    else if (part.hex === undefined || part.hex.length) out.push({ ...part });
  }
  return out;
}

// A frame: a u32 length of everything after it (the kind and the payload,
// unless `len` says otherwise), the kind, then the payload's parts.
function framed(kind, payload, len) {
  const size = payload.reduce((n, p) => n + partLength(p), 0);
  return joined([H(Buffer.concat([be32(len ?? size + 1), Buffer.from([kind])])), ...payload]);
}

const stream = (kind, id, after = [], len) => framed(kind, [H(be64(id)), ...after], len);
const dataFrame = (id, body) => stream(KINDS.data, id, [body]);
const endFrame = (id) => stream(KINDS.end, id);
const abortFrame = (id, json) => stream(KINDS.abort, id, [typeof json === 'string' ? ascii(json) : json]);
const creditFrame = (id, n) => stream(KINDS.credit, id, [H(be32(n))]);
const jsonFrame = (text) => framed(KINDS.json, [ascii(text)]);
const abortJson = (code, message) => JSON.stringify({ code, message });

// ---------------------------------------------------------------------------
// Decoding

function frameCases() {
  const cases = [];
  const add = (id, rule, side, input, expect) => cases.push({ id, rule, side, input: joined(input.flat()), expect });
  const ok = (...frames) => ({ frames });

  // The four kinds, each from the side that sends it.
  add('data-one-byte', 'data: 1 to 65 536 body bytes after the ID', 'receiver',
    [dataFrame(42, H([0xff]))], ok(['data', 42, H([0xff])]));
  add('data-max', 'data: 1 to 65 536 body bytes after the ID', 'receiver',
    [dataFrame(42, fill(0xab, MAX_DATA))], ok(['data', 42, fill(0xab, MAX_DATA)]));
  add('end', 'end: the ID alone (exactly 8 bytes)', 'receiver', [endFrame(42)], ok(['end', 42]));
  add('abort', 'abort: JSON { code, message }', 'receiver',
    [abortFrame(42, abortJson('internal', 'x'))], ok(['abort', 42, 'internal', 'x']));
  for (const code of ABORT_CODES) {
    add(`abort-code-${code}`, 'abort codes (0007, Errors)', 'receiver',
      [abortFrame(42, abortJson(code, 'm'))], ok(['abort', 42, code, 'm']));
  }
  add('abort-whitespace', 'abort: JSON, with JSON\'s whitespace', 'receiver',
    [abortFrame(42, ' {\n\t"message" : "m" ,"code":"busy"}\r\n')], ok(['abort', 42, 'busy', 'm']));
  add('abort-escaped', 'abort: JSON escapes are read as JSON reads them', 'receiver',
    [abortFrame(42, '{"code":"stopped","message":"a\\"b\\\\c\\u00e9"}')], ok(['abort', 42, 'stopped', 'a"b\\c' + String.fromCharCode(0xe9)]));
  {
    const message = 'm'.repeat(MAX_ABORT_JSON - abortJson('busy', '').length);
    assert.equal(abortJson('busy', message).length, MAX_ABORT_JSON);
    add('abort-max', 'abort: at most 1 KiB of JSON after the ID', 'receiver',
      [abortFrame(42, abortJson('busy', message))], ok(['abort', 42, 'busy', message]));
    add('abort-overlong', 'abort: at most 1 KiB of JSON after the ID', 'receiver',
      [abortFrame(42, abortJson('busy', message + 'm'))], { error: 'stream_length' });
  }
  add('credit', 'credit: a u32 big-endian above zero (exactly 12 bytes)', 'sender',
    [creditFrame(42, 65536)], ok(['credit', 42, 65536]));
  add('credit-max', 'credit: any u32 above zero decodes; the account checks it', 'sender',
    [creditFrame(42, 0xffffffff)], ok(['credit', 42, 0xffffffff]));
  add('json-on-a-stream-connection', 'kind 0x01 is always taken', 'receiver',
    [jsonFrame('{"type":"cancel","id":1}')], ok(['json', '{"type":"cancel","id":1}']));
  add('json-on-the-service', 'kind 0x01 is always taken', 'sender',
    [jsonFrame('{}')], ok(['json', '{}']));
  add('back-to-back', 'frames in sequence: a head, data, end', 'receiver',
    [jsonFrame('{"type":"response","id":41,"result":{"body":true}}'), dataFrame(41, H([1, 2, 3])), endFrame(41)],
    ok(['json', '{"type":"response","id":41,"result":{"body":true}}'], ['data', 41, H([1, 2, 3])], ['end', 41]));
  add('id-max', 'the stream ID is a request ID: at most 2^53 - 1', 'receiver', [endFrame(MAX_ID)], ok(['end', MAX_ID]));

  // Fixed and bounded lengths, checked at the header.
  add('data-empty', 'an empty data frame is a protocol error', 'receiver', [stream(KINDS.data, 42)], { error: 'data_empty' });
  add('data-overlong', 'data: at most 65 536 bytes after the ID', 'receiver',
    [dataFrame(42, fill(0xab, MAX_DATA + 1))], { error: 'stream_length' });
  add('end-overlong', 'end: exactly 8 bytes', 'receiver', [stream(KINDS.end, 42, [H([0])])], { error: 'stream_length' });
  add('end-short', 'end: exactly 8 bytes', 'receiver',
    [framed(KINDS.end, [H(be64(42).subarray(0, 7))])], { error: 'stream_length' });
  add('abort-id-only', 'abort: JSON after the ID', 'receiver', [stream(KINDS.abort, 42)], { error: 'stream_length' });
  add('credit-overlong', 'credit: exactly 12 bytes', 'sender',
    [stream(KINDS.credit, 42, [H([0, 0, 1, 0, 0])])], { error: 'stream_length' });
  add('credit-short', 'credit: exactly 12 bytes', 'sender',
    [stream(KINDS.credit, 42, [H([0, 1, 0])])], { error: 'stream_length' });
  for (const [kind, name] of [[KINDS.data, 'data'], [KINDS.end, 'end'], [KINDS.abort, 'abort']]) {
    add(`${name}-shorter-than-its-id`, 'each payload starts with the 8-byte stream ID', 'receiver',
      [framed(kind, [H([0, 0, 0])])], { error: 'stream_length' });
  }
  // The header alone decides: no payload byte is needed, or read.
  add('length-checked-before-the-payload', 'the payload length is checked against the kind before anything else', 'sender',
    [H(Buffer.concat([be32(MAX_PAYLOAD + 1), Buffer.from([KINDS.credit])]))], { error: 'stream_length' });
  add('empty-data-checked-before-the-payload', 'the payload length is checked against the kind before anything else', 'receiver',
    [H(Buffer.concat([be32(1 + ID_BYTES), Buffer.from([KINDS.data])]))], { error: 'data_empty' });
  add('frame-over-one-mib', 'any frame: at most 1 MiB of payload (0001)', 'receiver',
    [H(Buffer.concat([be32(MAX_PAYLOAD + 2), Buffer.from([KINDS.data])]))], { error: 'bad_length' });
  add('frame-length-zero', 'any frame: the length counts the kind byte (0001)', 'receiver',
    [H(Buffer.concat([be32(0), Buffer.from([KINDS.end])]))], { error: 'bad_length' });

  // Truncated input: EOF inside a frame.
  add('truncated-payload', 'EOF inside a frame truncates it', 'receiver',
    [H(Buffer.concat([be32(1 + ID_BYTES + 100), Buffer.from([KINDS.data]), be64(42)])), fill(0xab, 50)],
    { frames: [], truncated: true });
  add('truncated-header', 'EOF inside a frame truncates it', 'receiver', [H([0, 0, 0])], { frames: [], truncated: true });
  add('truncated-after-a-frame', 'EOF inside a frame truncates it', 'receiver',
    [endFrame(41), H(be32(9))], { frames: [['end', 41]], truncated: true });

  // IDs.
  add('id-zero', 'the stream ID is a request ID: 1 to 2^53 - 1', 'receiver', [endFrame(0)], { error: 'stream_id' });
  add('id-over-2-53', 'the stream ID is a request ID: 1 to 2^53 - 1', 'receiver', [endFrame(2 ** 53)], { error: 'stream_id' });
  add('id-all-ones', 'the stream ID is a request ID: 1 to 2^53 - 1', 'sender',
    [framed(KINDS.credit, [H(Buffer.alloc(8, 0xff)), H(be32(1))])], { error: 'stream_id' });

  // Payloads.
  add('credit-zero', 'credit: above zero', 'sender', [creditFrame(42, 0)], { error: 'credit_zero' });
  for (const [id, json] of [
    ['not-json', 'code=busy'],
    ['array', '["busy","m"]'],
    ['unknown-code', '{"code":"deadline","message":"m"}'],
    ['code-case', '{"code":"Busy","message":"m"}'],
    ['extra-member', '{"code":"busy","message":"m","data":{}}'],
    ['missing-message', '{"code":"busy"}'],
    ['missing-code', '{"message":"m"}'],
    ['duplicate-code', '{"code":"busy","code":"internal","message":"m"}'],
    ['message-not-a-string', '{"code":"busy","message":7}'],
    ['code-not-a-string', '{"code":1,"message":"m"}'],
    ['trailing-text', '{"code":"busy","message":"m"}x'],
  ]) {
    add(`abort-${id}`, 'abort: JSON { code, message }, a known code, nothing else', 'receiver',
      [abortFrame(42, json)], { error: 'abort_payload' });
  }
  add('abort-not-utf8', 'abort: JSON { code, message }', 'receiver',
    [abortFrame(42, H(Buffer.concat([Buffer.from('{"code":"busy","message":"'), Buffer.from([0xff]), Buffer.from('"}')])))],
    { error: 'abort_payload' });

  // Direction: data, end and abort are the service's; credit is main's.
  for (const [name, frame] of [['data', dataFrame(42, H([1]))], ['end', endFrame(42)], ['abort', abortFrame(42, abortJson('busy', 'm'))]]) {
    add(`${name}-from-main`, 'stream data sent by main is a protocol error', 'sender', [frame], { error: 'stream_direction' });
  }
  add('credit-from-the-service', 'credit sent by the service is a protocol error', 'receiver',
    [creditFrame(42, 1)], { error: 'stream_direction' });

  // Both wrong: the length is checked against the kind before anything
  // else, so a frame in the wrong direction with a wrong length is a length
  // error.
  add('end-overlong-from-main', 'the payload length is checked against the kind before anything else, direction included', 'sender',
    [stream(KINDS.end, 42, [H([0])])], { error: 'stream_length' });
  add('data-empty-from-main', 'the payload length is checked against the kind before anything else, direction included', 'sender',
    [stream(KINDS.data, 42)], { error: 'data_empty' });
  add('credit-short-from-the-service', 'the payload length is checked against the kind before anything else, direction included', 'receiver',
    [stream(KINDS.credit, 42, [H([0, 1, 0])])], { error: 'stream_length' });
  add('abort-overlong-from-main', 'the payload length is checked against the kind before anything else, direction included', 'sender',
    [H(Buffer.concat([be32(1 + ID_BYTES + MAX_ABORT_JSON + 1), Buffer.from([KINDS.abort])]))], { error: 'stream_length' });

  // Kinds a connection doesn't take.
  for (const kind of [KINDS.data, KINDS.end, KINDS.abort, KINDS.credit]) {
    add(`core-refuses-kind-${kind}`, 'freedom-cored\'s connections never grant stream', 'core',
      [framed(kind, [H(be64(1)), H([0, 0, 0, 1])])], { error: 'unknown_kind' });
  }
  for (const kind of [0x06, 0x0f]) {
    add(`reserved-kind-${kind}`, 'kinds 0x06 to 0x0F stay reserved', 'receiver',
      [framed(kind, [H(be64(1))])], { error: 'unknown_kind' });
  }
  add('fragments-not-granted', 'a stream connection takes no fragment kinds (frames: ["stream"])', 'receiver',
    [framed(0x13, [])], { error: 'unknown_kind' });
  return cases;
}

function encodingCases() {
  const cases = [];
  const add = (id, frame, hexOrError) => cases.push(typeof hexOrError === 'string'
    ? { id, frame, hex: hexOrError } : { id, frame, ...hexOrError });
  // Written out byte by byte.
  add('data', ['data', 42, H([0xff])], '0000000a02000000000000002aff');
  add('data-max-id', ['data', MAX_ID, H([1, 2])], '0000000b02001fffffffffffff0102');
  add('end', ['end', 42], '0000000903000000000000002a');
  add('credit', ['credit', 42, WINDOW], '0000000d05000000000000002a00020000');
  add('abort-cancelled', ['abort', 42, 'cancelled', 'Cancelled'],
    '0000003304000000000000002a' + hex(Buffer.from('{"code":"cancelled","message":"Cancelled"}')));
  add('abort-body-stream-error', ['abort', 7, 'body_stream_error', 'upstream body failed'],
    '0000004604' + '0000000000000007' + hex(Buffer.from('{"code":"body_stream_error","message":"upstream body failed"}')));
  for (const c of cases) {
    // The length field matches what follows it.
    const bytes = Buffer.from(c.hex, 'hex');
    assert.equal(bytes.readUInt32BE(0), bytes.length - 4, c.id);
  }
  add('data-empty', ['data', 42, H([])], { error: 'data_empty' });
  add('data-overlong', ['data', 42, fill(0, MAX_DATA + 1)], { error: 'stream_length' });
  add('id-zero', ['end', 0], { error: 'stream_id' });
  add('id-over-2-53', ['credit', 2 ** 53, 1], { error: 'stream_id' });
  add('credit-zero', ['credit', 42, 0], { error: 'credit_zero' });
  add('abort-overlong', ['abort', 42, 'internal', 'x'.repeat(MAX_ABORT_JSON)], { error: 'stream_length' });
  return cases;
}

// ---------------------------------------------------------------------------
// The service's side

const S = {
  request: (id, expect = 'ok') => ({ do: ['request', id], expect }),
  cancel: (id, expect) => ({ do: ['cancel', id], expect }),
  credit: (id, n, expect = 'taken') => ({ do: ['credit', id, n], expect }),
  head: (id, body, expect = 'ok') => ({ do: ['head', id, body], expect }),
  reply: (id, expect = 'ok') => ({ do: ['reply', id], expect }),
  push: (id, n, taken = n) => ({ do: ['push', id, n], expect: typeof taken === 'number' ? { taken } : taken }),
  finish: (id, expect = 'ok') => ({ do: ['finish', id], expect }),
  abort: (id, code, expect = 'ok') => ({ do: ['abort', id, code], expect }),
  write: (...frames) => ({ write: frames }),
  writeSome: (...frames) => ({ write_some: frames }),
  check: (held, streams = {}) => ({ check: { ...(held === null ? {} : { held }), streams } }),
  repeat: (count, step) => ({ repeat: count, ...step }),
};
const refused = (name) => ({ refused: name });
const error = (category) => ({ error: category });
const W = {
  head: (id) => ['head', id],
  reply: (id) => ['reply', id],
  cancelled: (id) => ['cancelled', id],
  data: (id, offset, length) => ['data', id, offset, length],
  end: (id) => ['end', id],
  abort: (id, code) => ['abort', id, code],
};
const live = (room, queued) => ({ live: true, room, queued });
const gone = { live: false, room: null, queued: null };

function senderCases() {
  const cases = [];
  const add = (id, rule, steps, config) => cases.push({ id, rule, ...(config ? { config } : {}), steps });

  // Order.
  add('head-data-end', 'the sequence is fixed: the head, then data, then exactly one terminal', [
    S.request(41), S.head(41, true), S.push(41, 100), S.finish(41),
    S.write(W.head(41), W.data(41, 0, 100), W.end(41)),
    S.check(0, { 41: gone }),
  ]);
  add('head-without-body', 'a head that says body: false opens no stream', [
    S.request(41), S.head(41, false), S.push(41, 1, refused('not_open')), S.finish(41, refused('not_open')),
    S.write(W.head(41)),
    S.check(0, { 41: gone }),
  ]);
  add('data-queued-behind-an-unwritten-head', 'no data before the head: data queued behind it waits for it', [
    S.request(41), S.head(41, true), S.push(41, 10),
    S.check(10, { 41: live(WINDOW - 10, 10) }),
    S.request(42), S.reply(42),
    S.write(W.head(41), W.reply(42), W.data(41, 0, 10)),
    S.check(0, { 41: live(WINDOW - 10, 0), 42: gone }),
  ]);
  add('no-body-before-the-head', 'no data before the head', [
    S.request(41), S.push(41, 1, refused('not_open')), S.finish(41, refused('not_open')),
    S.abort(41, 'internal', refused('not_open')),
    S.head(41, true), S.push(41, 1),
    S.write(W.head(41), W.data(41, 0, 1)),
  ]);
  add('end-after-a-full-queue', 'a full data queue, then EOF: end comes after the last data', [
    S.request(41), S.head(41, true), S.push(41, WINDOW + 1, WINDOW), S.push(41, 1, 0), S.finish(41),
    S.check(WINDOW, { 41: live(null, WINDOW) }),
    S.write(W.head(41), W.data(41, 0, MAX_DATA), W.data(41, MAX_DATA, MAX_DATA), W.end(41)),
    S.check(0, { 41: gone }),
  ]);
  add('end-after-data-that-waited-for-credit', 'end is written only after the stream\'s last data frame', [
    S.request(41), S.head(41, true), S.push(41, 200000, WINDOW),
    S.write(W.head(41), W.data(41, 0, MAX_DATA), W.data(41, MAX_DATA, MAX_DATA)),
    S.credit(41, MAX_DATA), S.push(41, 68928, MAX_DATA),
    S.write(W.data(41, WINDOW, MAX_DATA)),
    S.credit(41, MAX_DATA), S.push(41, 3392), S.finish(41),
    S.write(W.data(41, WINDOW + MAX_DATA, 3392), W.end(41)),
  ]);
  add('end-waits-behind-other-streams', 'each stream is a FIFO; the writer serves streams round-robin', [
    S.request(41), S.request(42), S.head(41, true), S.head(42, true),
    S.push(41, 100000), S.finish(41), S.push(42, 10),
    S.write(W.head(41), W.head(42), W.data(41, 0, MAX_DATA), W.data(42, 0, 10), W.data(41, MAX_DATA, 100000 - MAX_DATA), W.end(41)),
  ]);
  add('finish-twice', 'exactly one terminal', [
    S.request(41), S.head(41, true), S.finish(41), S.finish(41, refused('ended')), S.push(41, 1, refused('ended')),
    S.write(W.head(41), W.end(41)),
    S.finish(41, refused('gone')), S.abort(41, 'internal', refused('gone')),
  ]);
  add('one-head-or-reply', 'exactly one reply per request (0001)', [
    S.request(41), S.head(41, true), S.head(41, true, refused('answered')), S.reply(41, refused('answered')),
    S.request(42), S.reply(42), S.reply(42, refused('answered')), S.head(42, false, refused('answered')),
    S.head(43, true, refused('unknown')), S.push(43, 1, refused('unknown')),
    S.write(W.head(41), W.reply(42)),
    S.reply(42, refused('gone')), S.head(40, true, refused('gone')),
  ]);

  // Abort.
  add('abort-purges-queued-data', 'abort with data queued: it purges the stream\'s unwritten data, and nothing of the stream follows it', [
    S.request(41), S.head(41, true), S.push(41, 1000),
    S.write(W.head(41), W.data(41, 0, 1000)),
    S.push(41, 50000), S.finish(41), S.abort(41, 'internal'),
    S.check(0, { 41: { live: true, room: null, queued: 0 } }),
    S.push(41, 1, refused('gone')), S.finish(41, refused('gone')), S.abort(41, 'busy', refused('gone')),
    S.write(W.abort(41, 'internal')),
    S.check(0, { 41: gone }),
  ]);
  add('abort-jumps-the-queue', 'abort is the one frame that jumps the queue', [
    S.request(41), S.request(42), S.head(41, true), S.head(42, true), S.push(41, 100), S.push(42, 100),
    S.writeSome(W.head(41), W.head(42)),
    S.abort(42, 'busy'),
    S.write(W.abort(42, 'busy'), W.data(41, 0, 100)),
  ]);
  add('abort-behind-an-unwritten-head', 'the sequence is fixed: an abort queued before its head is written follows the head', [
    S.request(41), S.head(41, true), S.push(41, 100), S.finish(41), S.abort(41, 'internal'),
    S.write(W.head(41), W.abort(41, 'internal')),
  ]);
  add('abort-replaces-a-queued-end', 'abort purges: an end not yet written goes with the data', [
    S.request(41), S.head(41, true), S.writeSome(W.head(41)), S.push(41, 100), S.finish(41), S.abort(41, 'stopped'),
    S.write(W.abort(41, 'stopped')),
  ]);
  add('abort-after-end-written', 'nothing of a stream is written after its terminal', [
    S.request(41), S.head(41, true), S.finish(41), S.write(W.head(41), W.end(41)),
    S.abort(41, 'internal', refused('gone')), S.write(),
  ]);
  add('abort-needs-a-body', 'an abort truncates a body; a request without one gets a reply', [
    S.request(41), S.abort(41, 'internal', refused('not_open')),
    S.head(41, false), S.abort(41, 'internal', refused('not_open')),
    S.request(42), S.reply(42), S.abort(42, 'internal', refused('not_open')),
    S.abort(43, 'internal', refused('unknown')),
    S.write(W.head(41), W.reply(42)),
  ]);

  // Cancel.
  add('cancel-an-unwritten-head', 'cancel against an unwritten head: the head is dropped, cancelled is the only reply, no stream opens', [
    S.request(41), S.head(41, true), S.push(41, 100), S.finish(41),
    S.cancel(41, 'cancelled'),
    S.check(0, { 41: { live: true, room: null, queued: null } }),
    S.push(41, 1, refused('gone')), S.head(41, true, refused('gone')), S.reply(41, refused('gone')),
    S.write(W.cancelled(41)),
    S.check(0, { 41: gone }),
    S.push(41, 1, refused('gone')),
  ]);
  add('cancel-an-unwritten-head-without-body', 'cancel against an unwritten head, body: false too', [
    S.request(41), S.head(41, false), S.cancel(41, 'cancelled'), S.write(W.cancelled(41)),
  ]);
  add('cancel-an-unwritten-head-with-its-abort-queued', 'cancel against an unwritten head: cancelled is the request\'s only reply', [
    S.request(41), S.head(41, true), S.push(41, 100), S.abort(41, 'internal'),
    S.cancel(41, 'cancelled'), S.write(W.cancelled(41)),
  ]);
  add('cancel-a-working-request', 'a cancel before any reply: cancelled is the reply, and the work\'s late head is refused', [
    S.request(41), S.cancel(41, 'cancelled'),
    S.head(41, true, refused('gone')), S.reply(41, refused('gone')),
    S.write(W.cancelled(41)),
    S.head(41, true, refused('gone')),
  ]);
  add('cancel-an-open-stream', 'once the head is written, a cancel gives abort { code: "cancelled" }', [
    S.request(41), S.head(41, true), S.push(41, 1000), S.writeSome(W.head(41)),
    S.cancel(41, 'cancelled'), S.check(0, { 41: { live: true, room: null, queued: 0 } }),
    S.push(41, 1, refused('gone')),
    S.write(W.abort(41, 'cancelled')),
  ]);
  add('cancel-with-end-queued', 'a cancel aborts unless end is already written', [
    S.request(41), S.head(41, true), S.push(41, 100), S.finish(41), S.writeSome(W.head(41)),
    S.cancel(41, 'cancelled'), S.write(W.abort(41, 'cancelled')),
  ]);
  add('cancel-after-end-written', 'once end is written, a cancel is late and ignored', [
    S.request(41), S.head(41, true), S.push(41, 100), S.finish(41),
    S.write(W.head(41), W.data(41, 0, 100), W.end(41)),
    S.cancel(41, 'late'), S.write(),
  ]);
  add('cancel-after-abort-queued', 'one terminal: a cancel after the abort is queued is late', [
    S.request(41), S.head(41, true), S.writeSome(W.head(41)), S.abort(41, 'internal'),
    S.cancel(41, 'late'), S.write(W.abort(41, 'internal')),
  ]);
  add('cancel-after-reply-queued', 'one reply: a cancel after it is queued is late', [
    S.request(41), S.reply(41), S.cancel(41, 'late'), S.write(W.reply(41)),
  ]);
  add('cancel-twice', 'one reply per request', [
    S.request(41), S.cancel(41, 'cancelled'), S.cancel(41, 'late'), S.write(W.cancelled(41)), S.cancel(41, 'late'),
  ]);
  add('cancel-unknown-ids', 'a cancel for an ID this side doesn\'t hold changes nothing (as freedom-cored)', [
    S.request(41), S.cancel(40, 'late'), S.cancel(42, 'late'), S.write(),
    S.request(42), S.reply(42), S.write(W.reply(42)),
  ]);

  // Credit.
  add('debit-at-queueing', 'debit happens when data is queued: sent - credited + len <= 128 KiB', [
    S.request(41), S.head(41, true), S.push(41, 100000),
    S.check(100000, { 41: live(WINDOW - 100000, 100000) }),
    S.push(41, 40000, WINDOW - 100000),
    S.write(W.head(41), W.data(41, 0, MAX_DATA), W.data(41, MAX_DATA, MAX_DATA)),
    S.check(0, { 41: live(0, 0) }),
  ]);
  add('credit-makes-room', 'credit returns window: the producer may queue that much more', [
    S.request(41), S.head(41, true), S.push(41, WINDOW),
    S.write(W.head(41), W.data(41, 0, MAX_DATA), W.data(41, MAX_DATA, MAX_DATA)),
    S.push(41, 1, 0),
    S.credit(41, 1000), S.check(0, { 41: live(1000, 0) }),
    S.push(41, 5000, 1000),
    S.write(W.data(41, WINDOW, 1000)),
  ]);
  add('credit-overgrant', 'credit beyond what was sent is a protocol error', [
    S.request(41), S.head(41, true), S.push(41, 100), S.write(W.head(41), W.data(41, 0, 100)),
    S.credit(41, 100), S.credit(41, 1, error('credit_overgrant')),
    S.request(42, error('credit_overgrant')), S.cancel(41, error('credit_overgrant')), S.credit(41, 1, error('credit_overgrant')),
    S.push(41, 1, refused('closed')), S.head(41, true, refused('closed')),
    S.write(),
  ]);
  add('credit-duplicate', 'duplicate credit: the sum may not pass what was sent', [
    S.request(41), S.head(41, true), S.push(41, 1000), S.write(W.head(41), W.data(41, 0, 1000)),
    S.credit(41, 600), S.credit(41, 600, error('credit_overgrant')),
  ]);
  add('credit-before-any-data', 'credit beyond what was sent: nothing was', [
    S.request(41), S.credit(41, 1, error('credit_overgrant')),
  ]);
  add('credit-for-an-unwritten-head', 'credit beyond what was sent: nothing was', [
    S.request(41), S.head(41, true), S.credit(41, 1, error('credit_overgrant')),
  ]);
  add('credit-for-a-reply', 'credit beyond what was sent: a reply has no body', [
    S.request(41), S.reply(41), S.credit(41, 1, error('credit_overgrant')),
  ]);
  add('credit-counts-queued-bytes', 'sent counts the bytes queued for the stream', [
    S.request(41), S.head(41, true), S.push(41, 100), S.credit(41, 100), S.credit(41, 1, error('credit_overgrant')),
  ]);
  add('credit-above-the-highest-id', 'a frame for a stream ID above the highest request ID seen is a protocol error', [
    S.request(41), S.credit(42, 1, error('stream_unknown')),
  ]);
  add('credit-for-an-ended-stream', 'credit for a stream that has ended is late and ignored: it can cross a terminal', [
    S.request(41), S.head(41, true), S.push(41, 100), S.finish(41),
    S.write(W.head(41), W.data(41, 0, 100), W.end(41)),
    S.credit(41, 100, 'late'), S.credit(41, 0xffffffff, 'late'),
    S.credit(40, 5, 'late'),
    S.request(42), S.write(),
  ]);
  add('credit-racing-end', 'until its end is written, a stream\'s credit is still checked', [
    S.request(41), S.head(41, true), S.push(41, 100), S.finish(41),
    S.writeSome(W.head(41), W.data(41, 0, 100)),
    S.credit(41, 100), S.credit(41, 1, error('credit_overgrant')),
  ]);
  add('credit-racing-abort', 'no refund after a purge: credit within what was sent is taken, and late once the abort is written', [
    S.request(41), S.head(41, true), S.push(41, 1000), S.writeSome(W.head(41), W.data(41, 0, 1000)),
    S.push(41, 5000), S.abort(41, 'internal'),
    S.credit(41, 1000), S.credit(41, 5000), S.credit(41, 1, error('credit_overgrant')),
  ]);
  add('credit-after-abort-written', 'credit crossing an abort is late and ignored', [
    S.request(41), S.head(41, true), S.push(41, 1000), S.writeSome(W.head(41), W.data(41, 0, 1000)),
    S.abort(41, 'internal'), S.write(W.abort(41, 'internal')),
    S.credit(41, 1000, 'late'),
  ]);

  // Coalescing.
  add('coalesce-small-pushes', 'a data frame carries as much of the pending body as the window and 64 KiB allow', [
    S.request(41), S.head(41, true),
    S.repeat(1000, S.push(41, 100)),
    S.write(W.head(41), W.data(41, 0, MAX_DATA), W.data(41, MAX_DATA, 100000 - MAX_DATA)),
  ]);
  add('one-byte-pushes-at-full-window', 'one-byte pushes at full window: coalesced, and bounded by the window', [
    S.request(41), S.head(41, true),
    S.repeat(WINDOW, S.push(41, 1)),
    S.push(41, 1, 0),
    S.check(WINDOW, { 41: live(0, WINDOW) }),
    S.write(W.head(41), W.data(41, 0, MAX_DATA), W.data(41, MAX_DATA, MAX_DATA)),
    S.check(0, { 41: live(0, 0) }),
  ]);
  add('small-frame-all-that-is-pending', 'a frame under 4 KiB is written when it is all that is pending', [
    S.request(41), S.head(41, true), S.writeSome(W.head(41)),
    S.push(41, 10), S.write(W.data(41, 0, 10)),
    S.push(41, 1), S.write(W.data(41, 10, 1)),
  ]);
  add('small-frame-all-the-credit-allows', 'a frame under 4 KiB is written when it is all the credit allows', [
    S.request(41), S.head(41, true), S.push(41, WINDOW),
    S.write(W.head(41), W.data(41, 0, MAX_DATA), W.data(41, MAX_DATA, MAX_DATA)),
    S.credit(41, 10), S.push(41, MAX_DATA, 10),
    S.write(W.data(41, WINDOW, 10)),
  ]);
  add('frames-at-most-64k', 'data frames carry at most 65 536 bytes', [
    S.request(41), S.head(41, true), S.push(41, 70000),
    S.write(W.head(41), W.data(41, 0, MAX_DATA), W.data(41, MAX_DATA, 70000 - MAX_DATA)),
  ]);
  add('empty-push', 'an empty push queues nothing', [
    S.request(41), S.head(41, true), S.push(41, 0), S.write(W.head(41)),
  ]);

  // The writer.
  add('round-robin', 'stream FIFOs round-robin, one frame per stream that has queued data', [
    S.request(41), S.request(42), S.request(43),
    S.head(41, true), S.head(42, true), S.head(43, true),
    S.push(41, WINDOW), S.push(42, WINDOW), S.push(43, WINDOW),
    S.write(W.head(41), W.head(42), W.head(43),
      W.data(41, 0, MAX_DATA), W.data(42, 0, MAX_DATA), W.data(43, 0, MAX_DATA),
      W.data(41, MAX_DATA, MAX_DATA), W.data(42, MAX_DATA, MAX_DATA), W.data(43, MAX_DATA, MAX_DATA)),
  ]);
  add('control-first', 'the writer serves the control queue first: responses, aborts and replies to cancel', [
    S.request(41), S.head(41, true), S.push(41, WINDOW),
    S.writeSome(W.head(41), W.data(41, 0, MAX_DATA)),
    S.request(42), S.reply(42), S.request(43), S.head(43, false), S.request(44), S.cancel(44, 'cancelled'),
    S.write(W.reply(42), W.head(43), W.cancelled(44), W.data(41, MAX_DATA, MAX_DATA)),
  ]);
  add('writer-data-cap', 'the writer holds at most its cap of data; a producer waits for room', [
    S.request(41), S.request(42), S.head(41, true), S.head(42, true),
    S.push(41, WINDOW), S.push(42, WINDOW, MAX_DATA),
    S.check(WINDOW + MAX_DATA, { 41: live(0, WINDOW), 42: live(0, MAX_DATA) }),
    S.writeSome(W.head(41), W.head(42), W.data(41, 0, MAX_DATA)),
    S.check(WINDOW, { 41: live(0, MAX_DATA), 42: live(MAX_DATA, MAX_DATA) }),
    S.push(42, WINDOW, MAX_DATA),
    S.write(W.data(42, 0, MAX_DATA), W.data(41, MAX_DATA, MAX_DATA), W.data(42, MAX_DATA, MAX_DATA)),
  ], { data_cap: WINDOW + MAX_DATA });
  add('writer-cap-keeps-frames-large', 'a frame under 4 KiB is written only when it is all that is pending or all the credit allows: a push the writer\'s cap would cut below 4 KiB waits', [
    S.request(41), S.request(42), S.head(41, true), S.head(42, true),
    S.push(41, WINDOW),
    S.push(42, 5000, 0), S.push(42, 800),
    S.check(WINDOW + 800, { 42: live(200, 800) }),
    S.writeSome(W.head(41), W.head(42), W.data(41, 0, MAX_DATA)),
    S.push(42, 5000),
    S.write(W.data(42, 0, 5800), W.data(41, MAX_DATA, MAX_DATA)),
  ], { data_cap: WINDOW + 1000 });
  add('controls-without-writer-room', 'a saturated writer: credit and cancel still take effect, with nothing written', [
    S.request(40), S.head(40, true), S.push(40, MAX_DATA), S.write(W.head(40), W.data(40, 0, MAX_DATA)),
    S.request(41), S.head(41, true), S.push(41, WINDOW),
    S.check(WINDOW, { 40: live(0, 0), 41: live(0, WINDOW) }),
    S.credit(40, MAX_DATA), S.check(WINDOW, { 40: live(0, 0) }),
    S.cancel(41, 'cancelled'),
    S.check(0, { 40: live(WINDOW, 0) }),
    S.push(40, WINDOW),
    S.write(W.cancelled(41), W.data(40, MAX_DATA, MAX_DATA), W.data(40, WINDOW, MAX_DATA)),
  ], { data_cap: WINDOW });

  // Request IDs.
  add('request-ids-increase', 'request IDs strictly increase within a connection; the stream rules rely on it', [
    S.request(41), S.request(41, error('request_order')), S.request(42, error('request_order')),
  ]);
  add('request-ids-never-go-back', 'request IDs strictly increase within a connection', [
    S.request(41), S.request(40, error('request_order')),
  ]);

  // Cycles: the paused writer holds only what the live requests need.
  {
    const steps = [];
    for (let id = 100; id < 132; id += 1) {
      steps.push(S.request(id), S.head(id, true), S.push(id, WINDOW), S.cancel(id, 'cancelled'), S.check(0));
    }
    steps.push(S.write(...Array.from({ length: 32 }, (_, i) => W.cancelled(100 + i))));
    steps.push(S.check(0, { 100: gone, 131: gone }));
    add('cancel-cycles-before-the-head', 'repeated cancel and new-request cycles with a paused writer: nothing is held', steps);
  }
  {
    const steps = [];
    const ids = Array.from({ length: 16 }, (_, i) => 200 + i);
    for (const id of ids) steps.push(S.request(id), S.head(id, true));
    steps.push(S.writeSome(...ids.map(W.head)));
    for (const id of ids) steps.push(S.push(id, WINDOW), S.cancel(id, 'cancelled'), S.check(0));
    steps.push(S.write(...ids.map((id) => W.abort(id, 'cancelled'))));
    steps.push(S.check(0, { 200: gone, 215: gone }));
    add('cancel-cycles-after-the-head', 'repeated cancels of open streams with a paused writer: each purge frees its data', steps);
  }
  {
    // The writer takes only control frames between cycles, so it never
    // reaches the streams: stream 40's data waits behind every cycle.
    const steps = [S.request(40), S.head(40, true), S.writeSome(W.head(40))];
    for (let k = 1; k <= 32; k += 1) {
      const id = 99 + k;
      const code = k % 2 ? 'cancelled' : 'internal';
      steps.push(S.request(id), S.head(id, true), S.push(id, 1), S.push(40, 1), S.writeSome(W.head(id)));
      steps.push(k % 2 ? S.cancel(id, 'cancelled') : S.abort(id, 'internal'));
      steps.push(S.writeSome(W.abort(id, code)), S.check(k, { [id]: gone, 40: live(WINDOW - k, k) }));
    }
    steps.push(S.write(W.data(40, 0, 32)));
    add('cancel-cycles-with-the-writer-busy', 'repeated control-only cancels and aborts while another stream waits: each terminated stream leaves the writer\'s schedule', steps);
  }
  return cases;
}

// ---------------------------------------------------------------------------
// Main's side

const R = {
  request: (id, expect = 'ok') => ({ do: ['request', id], expect }),
  reply: (id, opens, expect = 'deliver') => ({ do: ['reply', id, opens], expect }),
  data: (id, n, expect = 'data') => ({ do: ['data', id, n], expect }),
  end: (id, expect) => ({ do: ['end', id], expect }),
  abort: (id, code, expect = 'abort') => ({ do: ['abort', id, code], expect }),
  pull: (id, max, expect) => ({ do: ['pull', id, max], expect }),
  cancel: (id, expect) => ({ do: ['cancel', id], expect }),
  check: (streams, outstanding) => ({ check: { streams, ...(outstanding === undefined ? {} : { outstanding }) } }),
  repeat: (count, step) => ({ repeat: count, ...step }),
};
const chunk = (offset, length, credit, eof = false) => ({ chunk: [offset, length], credit, eof });
const open = (fields) => ({ state: 'open', ...fields });
const opened = (id) => [R.request(id), R.reply(id, true)];

function receiverCases() {
  const cases = [];
  const add = (id, rule, steps) => cases.push({ id, rule, steps });

  add('pull-returns-credit', 'a pull copies up to 64 KiB out and credits those bytes', [
    ...opened(41), R.data(41, 100),
    R.check({ 41: open({ ring: true, buffered: 100, received: 100, returned: 0 }) }),
    R.pull(41, MAX_PULL, chunk(0, 100, 100)),
    R.check({ 41: open({ ring: true, buffered: 0, received: 100, returned: 100 }) }),
    R.pull(41, MAX_PULL, chunk(100, 0, null)),
    R.end(41, 'end_drained'), R.check({ 41: null }, 0),
  ]);
  add('ring-at-first-data', 'the ring is allocated at the stream\'s first data', [
    R.request(41), R.check({ 41: { state: 'pending' } }),
    R.reply(41, true), R.check({ 41: open({ ring: false, buffered: 0 }) }),
    R.data(41, 1), R.check({ 41: open({ ring: true, buffered: 1 }) }),
  ]);
  add('end-only-records-eof', 'a paused consumer with a small body whose end arrives first: every byte is still delivered', [
    ...opened(41), R.data(41, 100), R.end(41, 'end'),
    R.check({ 41: { state: 'eof', ring: true, buffered: 100, received: 100, returned: 0 } }),
    R.pull(41, 30, chunk(0, 30, null)),
    R.pull(41, MAX_PULL, chunk(30, 70, null, true)),
    R.check({ 41: null }, 0),
    R.pull(41, MAX_PULL, null),
  ]);
  add('end-with-nothing-left', 'the ring is freed once the consumer has drained it after EOF', [
    ...opened(41), R.data(41, 100), R.pull(41, MAX_PULL, chunk(0, 100, 100)),
    R.end(41, 'end_drained'), R.check({ 41: null }), R.pull(41, 1, null),
  ]);
  add('end-without-data', 'a body of no bytes: the head, then end', [
    ...opened(41), R.end(41, 'end_drained'), R.check({ 41: null }),
  ]);
  add('pull-at-most-64k', 'a pull copies up to 64 KiB', [
    ...opened(41), R.data(41, MAX_DATA), R.data(41, MAX_DATA),
    R.pull(41, 1 << 20, chunk(0, MAX_PULL, MAX_PULL)),
    R.pull(41, 1 << 20, chunk(MAX_PULL, MAX_PULL, MAX_PULL)),
  ]);
  add('window-overrun', 'data beyond the window (received - returned > 128 KiB) is a protocol error', [
    ...opened(41), R.data(41, MAX_DATA), R.data(41, MAX_DATA), R.data(41, 1, error('window_overrun')),
    R.data(41, 1, error('window_overrun')), R.reply(41, false, error('window_overrun')),
  ]);
  add('window-after-credit', 'the window counts what main has returned', [
    ...opened(41), R.data(41, MAX_DATA), R.data(41, MAX_DATA),
    R.pull(41, 1000, chunk(0, 1000, 1000)),
    R.data(41, 1000), R.data(41, 1, error('window_overrun')),
  ]);
  add('one-byte-frames-at-full-window', 'one-byte frames at full window: one ring, never more than the window', [
    ...opened(41),
    R.repeat(WINDOW, R.data(41, 1)),
    R.check({ 41: open({ ring: true, buffered: WINDOW, received: WINDOW, returned: 0 }) }),
    R.data(41, 1, error('window_overrun')),
  ]);
  add('full-window-burst', 'full-window bursts: the ring never grows', [
    ...opened(41), R.data(41, MAX_DATA), R.data(41, MAX_DATA),
    R.pull(41, MAX_PULL, chunk(0, MAX_PULL, MAX_PULL)),
    R.data(41, MAX_DATA),
    R.pull(41, MAX_PULL, chunk(MAX_PULL, MAX_PULL, MAX_PULL)),
    R.pull(41, MAX_PULL, chunk(2 * MAX_PULL, MAX_PULL, MAX_PULL)),
    R.check({ 41: open({ ring: true, buffered: 0, received: 3 * MAX_DATA, returned: 3 * MAX_DATA }) }),
  ]);
  add('streams-have-their-own-windows', 'the window is per stream', [
    ...opened(41), ...opened(42),
    R.data(41, MAX_DATA), R.data(42, MAX_DATA), R.data(41, MAX_DATA), R.data(42, MAX_DATA),
    R.pull(42, MAX_PULL, chunk(0, MAX_PULL, MAX_PULL)),
    R.data(42, 1), R.data(41, 1, error('window_overrun')),
  ]);
  add('credit-stops-at-eof', 'after end nothing more can come: pulls send no credit', [
    ...opened(41), R.data(41, 200), R.pull(41, 100, chunk(0, 100, 100)), R.end(41, 'end'),
    R.pull(41, 100, chunk(100, 100, null, true)),
  ]);

  // Order.
  add('data-before-the-head', 'no data before the head', [
    R.request(41), R.data(41, 1, error('stream_not_open')),
  ]);
  add('end-before-the-head', 'no terminal before the head', [
    R.request(41), R.end(41, error('stream_not_open')),
  ]);
  add('abort-before-the-head', 'no terminal before the head', [
    R.request(41), R.abort(41, 'internal', error('stream_not_open')),
  ]);
  add('data-for-a-head-without-body', 'a head that says body: false opens no stream', [
    R.request(41), R.reply(41, false), R.data(41, 1, error('stream_not_open')),
  ]);
  add('data-after-an-error-reply', 'a reply without a body opens no stream', [
    R.request(41), R.reply(41, false), R.end(41, error('stream_not_open')),
  ]);
  add('data-above-the-highest-id', 'a frame for a stream ID above the highest request ID is a protocol error', [
    R.request(41), R.data(42, 1, error('stream_unknown')),
  ]);
  add('end-above-the-highest-id', 'a frame for a stream ID above the highest request ID is a protocol error', [
    ...opened(41), R.end(42, error('stream_unknown')),
  ]);
  add('second-end', 'a second terminal frame is a protocol error', [
    ...opened(41), R.end(41, 'end_drained'), R.end(41, error('stream_not_open')),
  ]);
  add('abort-after-end', 'a second terminal frame is a protocol error', [
    ...opened(41), R.data(41, 10), R.end(41, 'end'), R.abort(41, 'internal', error('stream_not_open')),
  ]);
  add('end-after-abort', 'a second terminal frame is a protocol error', [
    ...opened(41), R.abort(41, 'internal'), R.end(41, error('stream_not_open')),
  ]);
  add('data-after-end', 'the sequence is fixed: nothing after the terminal', [
    ...opened(41), R.data(41, 10), R.end(41, 'end'), R.data(41, 1, error('stream_not_open')),
  ]);
  add('abort-frees-at-once', 'on abort the stream errors at once and its bytes are dropped', [
    ...opened(41), R.data(41, 1000), R.abort(41, 'body_stream_error'),
    R.check({ 41: null }, 0), R.pull(41, MAX_PULL, null),
  ]);

  // Replies.
  add('unsolicited-reply', 'a response to no pending request is a protocol error (0001)', [
    R.request(41), R.reply(42, false, error('unsolicited_response')),
  ]);
  add('duplicate-reply', 'exactly one reply per request (0001)', [
    R.request(41), R.reply(41, false), R.reply(41, false, error('unsolicited_response')),
  ]);
  add('duplicate-head', 'exactly one reply per request (0001)', [
    ...opened(41), R.reply(41, true, error('unsolicited_response')),
  ]);
  add('request-ids-increase', 'main\'s request IDs strictly increase', [
    R.request(41), R.request(41, error('request_order')), R.request(40, error('request_order')), R.request(42),
  ]);

  // Retirement.
  add('cancel-an-open-stream', 'a local cancel discards the queued bytes, sends cancel and no more credit, and keeps a record until the terminal', [
    ...opened(41), R.data(41, 1000), R.cancel(41, 'send_cancel'),
    R.check({ 41: { state: 'retiring', ring: false, buffered: 0 } }, 1),
    R.pull(41, MAX_PULL, null),
    R.data(41, 500, 'dropped'), R.end(41, 'dropped'),
    R.check({ 41: null }, 0),
    R.data(41, 1, error('stream_not_open')),
  ]);
  add('cancel-ends-with-an-abort', 'the retirement record lasts until the terminal frame', [
    ...opened(41), R.data(41, 10), R.cancel(41, 'send_cancel'),
    R.abort(41, 'cancelled', 'dropped'), R.check({ 41: null }, 0),
    R.abort(41, 'cancelled', error('stream_not_open')),
  ]);
  add('retiring-data-is-dropped-unchecked', 'data arriving for a retiring stream is dropped as it is read', [
    ...opened(41), R.data(41, MAX_DATA), R.data(41, MAX_DATA), R.cancel(41, 'send_cancel'),
    R.data(41, MAX_DATA, 'dropped'), R.data(41, MAX_DATA, 'dropped'), R.end(41, 'dropped'),
  ]);
  add('cancel-before-the-head-then-cancelled', 'retirement until the reply arrives', [
    R.request(41), R.cancel(41, 'send_cancel'), R.check({ 41: { state: 'retired_pending' } }, 1),
    R.reply(41, false, 'retired'), R.check({ 41: null }, 0),
  ]);
  add('cancel-before-the-head-then-the-head', 'a head that crossed the cancel opens a retiring stream', [
    R.request(41), R.cancel(41, 'send_cancel'), R.reply(41, true, 'retired'),
    R.check({ 41: { state: 'retiring' } }, 1),
    R.data(41, 100, 'dropped'), R.abort(41, 'cancelled', 'dropped'), R.check({ 41: null }, 0),
  ]);
  add('cancel-before-the-head-data-is-still-early', 'no data before the head, retired or not', [
    R.request(41), R.cancel(41, 'send_cancel'), R.data(41, 1, error('stream_not_open')),
  ]);
  add('cancel-after-end', 'once end has arrived nothing is cancelled: the bytes left are dropped', [
    ...opened(41), R.data(41, 10), R.end(41, 'end'), R.cancel(41, 'freed'), R.check({ 41: null }, 0),
  ]);
  add('cancel-twice', 'one cancel per request', [
    R.request(41), R.cancel(41, 'send_cancel'), R.cancel(41, 'nothing'),
    ...opened(42), R.cancel(42, 'send_cancel'), R.cancel(42, 'nothing'),
    R.cancel(43, 'nothing'),
  ]);
  add('retiring-counts-as-outstanding', 'retiring requests count against main\'s outstanding requests', [
    R.request(41), ...opened(42), R.request(43), R.cancel(41, 'send_cancel'), R.cancel(42, 'send_cancel'),
    R.check({}, 3), R.reply(43, false), R.check({}, 2),
  ]);
  return cases;
}

// ---------------------------------------------------------------------------
// Shape checks: every case is well formed before it is written.

// IDs up to 2^53, the first invalid one, which JSON and JS still carry exactly.
const isId = (n) => Number.isInteger(n) && n >= 0 && n <= 2 ** 53;
const isCount = (n) => Number.isSafeInteger(n) && n >= 0;

function checkBytes(parts, where) {
  assert.ok(Array.isArray(parts), where);
  for (const p of parts) {
    if (p.hex !== undefined) assert.match(p.hex, /^([0-9a-f]{2})*$/, where);
    else assert.ok(Array.isArray(p.fill) && p.fill.length === 2 && isCount(p.fill[0]) && p.fill[0] < 256 && isCount(p.fill[1]), where);
  }
}

function checkFrame(f, where) {
  assert.ok(Array.isArray(f), where);
  const [kind, ...rest] = f;
  if (kind === 'json') assert.ok(rest.length === 1 && typeof rest[0] === 'string', where);
  else if (kind === 'data') { assert.ok(rest.length === 2 && isId(rest[0]), where); checkBytes([rest[1]], where); }
  else if (kind === 'end') assert.ok(rest.length === 1 && isId(rest[0]), where);
  else if (kind === 'abort') assert.ok(rest.length === 3 && isId(rest[0]) && ABORT_CODES.includes(rest[1]) && typeof rest[2] === 'string', where);
  else if (kind === 'credit') assert.ok(rest.length === 2 && isId(rest[0]) && isCount(rest[1]), where);
  else assert.fail(`${where}: frame ${JSON.stringify(f)}`);
}

const CATEGORIES = ['bad_length', 'unknown_kind', 'stream_length', 'data_empty', 'stream_direction', 'stream_id',
  'abort_payload', 'credit_zero', 'request_order', 'stream_unknown', 'stream_not_open', 'credit_overgrant',
  'window_overrun', 'unsolicited_response'];
const REFUSALS = ['gone', 'unknown', 'answered', 'not_open', 'ended', 'too_large', 'closed'];
const isError = (e) => e && typeof e === 'object' && CATEGORIES.includes(e.error) && Object.keys(e).length === 1;
const isRefusal = (e) => e && typeof e === 'object' && REFUSALS.includes(e.refused) && Object.keys(e).length === 1;

function checkWritten(f, where) {
  assert.ok(Array.isArray(f), where);
  const [kind, id, ...rest] = f;
  assert.ok(isId(id), where);
  if (['head', 'reply', 'cancelled', 'end'].includes(kind)) assert.equal(rest.length, 0, where);
  else if (kind === 'data') assert.ok(rest.length === 2 && isCount(rest[0]) && rest[1] >= 1 && rest[1] <= MAX_DATA, where);
  else if (kind === 'abort') assert.ok(rest.length === 1 && ABORT_CODES.includes(rest[0]), where);
  else assert.fail(`${where}: written ${JSON.stringify(f)}`);
}

function checkSenderStep(step, where) {
  if (step.write || step.write_some) {
    for (const f of step.write || step.write_some) checkWritten(f, where);
    return;
  }
  if (step.check) {
    assert.ok(step.check.held === undefined || isCount(step.check.held), where);
    for (const [id, s] of Object.entries(step.check.streams)) {
      assert.ok(isId(Number(id)), where);
      assert.deepEqual(Object.keys(s).sort(), ['live', 'queued', 'room'], where);
    }
    return;
  }
  const { do: action, expect } = step;
  assert.ok(Array.isArray(action), where);
  const [name, id, arg] = action;
  assert.ok(isId(id), where);
  if (step.repeat !== undefined) assert.ok(isCount(step.repeat), where);
  switch (name) {
    case 'request': assert.ok(expect === 'ok' || isError(expect), where); break;
    case 'cancel': assert.ok(['cancelled', 'late'].includes(expect) || isError(expect), where); break;
    case 'credit': assert.ok(isCount(arg) && (['taken', 'late'].includes(expect) || isError(expect)), where); break;
    case 'head': assert.ok(typeof arg === 'boolean' && (expect === 'ok' || isRefusal(expect)), where); break;
    case 'reply': case 'finish': assert.ok(expect === 'ok' || isRefusal(expect), where); break;
    case 'push': assert.ok(isCount(arg) && ((isCount(expect.taken) && expect.taken <= arg) || isRefusal(expect)), where); break;
    case 'abort': assert.ok(ABORT_CODES.includes(arg) && (expect === 'ok' || isRefusal(expect)), where); break;
    default: assert.fail(`${where}: ${name}`);
  }
}

function checkReceiverStep(step, where) {
  if (step.check) {
    for (const [id, s] of Object.entries(step.check.streams)) {
      assert.ok(isId(Number(id)), where);
      if (s !== null) {
        assert.ok(['pending', 'retired_pending', 'open', 'eof', 'retiring'].includes(s.state), where);
        for (const key of Object.keys(s)) assert.ok(['state', 'ring', 'buffered', 'received', 'returned'].includes(key), where);
      }
    }
    assert.ok(step.check.outstanding === undefined || isCount(step.check.outstanding), where);
    return;
  }
  const { do: action, expect } = step;
  const [name, id, arg] = action;
  assert.ok(isId(id), where);
  switch (name) {
    case 'request': assert.ok(expect === 'ok' || isError(expect), where); break;
    case 'reply': assert.ok(typeof arg === 'boolean' && (['deliver', 'retired'].includes(expect) || isError(expect)), where); break;
    case 'data': assert.ok(arg >= 1 && arg <= MAX_DATA && (['data', 'dropped'].includes(expect) || isError(expect)), where); break;
    case 'end': assert.ok(['end', 'end_drained', 'dropped'].includes(expect) || isError(expect), where); break;
    case 'abort': assert.ok(ABORT_CODES.includes(arg) && (['abort', 'dropped'].includes(expect) || isError(expect)), where); break;
    case 'pull': assert.ok(isCount(arg) && (expect === null
      || (isCount(expect.chunk[0]) && isCount(expect.chunk[1]) && (expect.credit === null || expect.credit > 0) && typeof expect.eof === 'boolean')), where); break;
    case 'cancel': assert.ok(['send_cancel', 'freed', 'nothing'].includes(expect), where); break;
    default: assert.fail(`${where}: ${name}`);
  }
}

function checkCases(cases, checkStep) {
  const ids = new Set();
  for (const c of cases) {
    assert.ok(!ids.has(c.id), `duplicate id ${c.id}`);
    ids.add(c.id);
    assert.equal(typeof c.rule, 'string', c.id);
    c.steps.forEach((step, i) => checkStep(step, `${c.id} step ${i}`));
  }
}

function buildStreams(meta) {
  const frames = frameCases();
  const encodings = encodingCases();
  const sender = senderCases();
  const receiver = receiverCases();
  const ids = new Set();
  for (const c of frames) {
    assert.ok(!ids.has(c.id), c.id);
    ids.add(c.id);
    assert.ok(SIDES.includes(c.side), c.id);
    checkBytes(c.input, c.id);
    if (c.expect.error !== undefined) assert.ok(CATEGORIES.includes(c.expect.error) && Object.keys(c.expect).length === 1, c.id);
    else for (const f of c.expect.frames) checkFrame(f, c.id);
  }
  for (const c of encodings) {
    checkFrame(c.frame, c.id);
    assert.ok((c.hex === undefined) !== (c.error === undefined), c.id);
    if (c.error !== undefined) assert.ok(CATEGORIES.includes(c.error), c.id);
  }
  checkCases(sender, checkSenderStep);
  checkCases(receiver, checkReceiverStep);
  return {
    meta,
    source: 'design 0007 (Frames): every outcome is the design\'s, written by hand in vectors/generator/streams.js; no reference implementation exists yet',
    constants: {
      kinds: KINDS,
      id_bytes: ID_BYTES,
      window: WINDOW,
      max_data: MAX_DATA,
      max_abort_json: MAX_ABORT_JSON,
      max_pull: MAX_PULL,
      small_frame: SMALL_FRAME,
      writer_data_cap: WRITER_DATA_CAP,
      max_payload: MAX_PAYLOAD,
      max_id: MAX_ID,
      abort_codes: ABORT_CODES,
      cancelled_message: 'Cancelled',
    },
    formats: FORMATS,
    categories: CATEGORIES,
    refusals: REFUSALS,
    frames,
    encodings,
    sender,
    receiver,
  };
}

module.exports = { buildStreams };
