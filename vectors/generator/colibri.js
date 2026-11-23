'use strict';

// Design 0014's vectors (COL-1): the reference's Colibri adapter run whole,
// over the real c4w.wasm, in scripted worlds. Nothing is reimplemented
// (AGENTS rule 5): each case loads the colibri reference's own
// `colibri-runtime.js` and `colibri-worker.js` (the chain-data worker's
// service, `createColibriService`, driven in this thread as the worker's
// message loop drives it) or `checkpoint-verifier-worker.js`
// (`verifyCheckpoint`), fresh, over the package as installed. A recording
// layer wraps the WASM module's exports and its storage, so every call into
// the C core is recorded with its arguments and return: method support,
// context creation, every step's status text verbatim (pointers replaced by
// indices), every answer and error, frees, decodes and verifications, and
// the store's gets, sets and deletes. `globalThis.fetch` answers from the
// captures in `vectors/fixtures/colibri/` (`generator/colibri-capture.js`
// made them once from the live servers), and the clock is each case's
// captured instant, so the freshness bound is fixed too.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const { createRequire } = Module;
const contract = require('./colibri-contract');

// Node's own loader, as it is when generate.js requires this file: other
// harnesses wrap Module._load for their stubs and leave the wrappers on, and
// a case loads the reference's modules through Node's alone.
const NODE_LOAD = Module._load;

const COLIBRI_VERSION = '3.0.3';
// c4w.wasm of @corpus-core/colibri-stateless 3.0.3 (freedom-browser's
// docs/audits/evidence/colibri-v3-2026-09/README.md, "3.0.3 re-validation").
const C4W_SHA256 = '3244888b2582b0a6e2d627f358c8d6283c6d65509583a0a644e789a3e7fd4f56';
const FIXTURES = path.resolve(__dirname, '../fixtures/colibri');
// Results longer than this are recorded as a digest: the step's status text,
// recorded whole, carries them.
const INLINE_RESULT = 4096;
const REFERENCE_FILES = [
  'src/main/ens/colibri-runtime.js',
  'src/main/ens/colibri-worker.js',
  'src/main/myotis/checkpoint-verifier.js',
  'src/main/myotis/checkpoint-verifier-worker.js',
  'src/shared/endpoint-sources.json',
];

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const keyOf = (url, method, body) => `${method} ${url}${body === null ? '' : ` ${body}`}`;
// fetch_from_servers' URL (`cjs/http.js:5-14`).
const joinPath = (base, url) => (!url ? base : base.endsWith('/') ? base + url : `${base}${url.startsWith('/') ? url : `/${url}`}`);

/** The colibri reference: its checkout, the package it installs, and main's server table. */
function loadColibriReference(checkout) {
  const require = createRequire(path.join(checkout, 'package.json'));
  const cjs = path.dirname(require.resolve('@corpus-core/colibri-stateless'));
  const root = path.dirname(cjs);
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.version, COLIBRI_VERSION, 'The colibri reference must install @corpus-core/colibri-stateless 3.0.3');
  assert.equal(sha256(fs.readFileSync(path.join(root, 'c4w.wasm'))), C4W_SHA256, 'c4w.wasm differs from 3.0.3\'s');
  const { default_config: defaults } = require(path.join(cjs, 'chains.generated.js'));
  const provers = JSON.parse(fs.readFileSync(path.join(checkout, 'src/shared/endpoint-sources.json'), 'utf8'))['colibri-corpus'].coverage;
  // Main's server table under the default-host answer (design 0014, Open
  // questions 1): the registry's prover, and the package's own lists for the
  // other types, in handle_request's order (`cjs/http.js:151-168`). The
  // package's RPC hosts are the reference's only: main's table has none.
  const servers = Object.fromEntries([1, 100].map((chain) => {
    const config = defaults[String(chain)];
    const prover = [provers[String(chain)]];
    return [chain, {
      prover,
      beacon_api: [...config.beacon_apis, ...prover],
      checkpointz: [...config.checkpointz, ...config.beacon_apis, ...prover],
      eth_rpc: [...config.rpcs],
    }];
  }));
  return { checkout, require, cjs, root, servers };
}

/** Drops every module of the checkout and of the package, for a fresh WASM instance. */
function dropModules(reference) {
  for (const id of Object.keys(require.cache)) {
    if (id.startsWith(path.join(reference.checkout, 'src') + path.sep) || id.startsWith(reference.root + path.sep)) {
      delete require.cache[id];
    }
  }
}

/** The fixtures: captured sessions; their bodies are files named by digest. */
function loadFixtures(dir = FIXTURES) {
  const file = path.join(dir, 'sessions.json');
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : { meta: null, sessions: {} };
}

function bodyBytes(sha, dir = FIXTURES) {
  const bytes = fs.readFileSync(path.join(dir, 'bodies', `${sha}.bin`));
  assert.equal(sha256(bytes), sha, `Fixture body ${sha} is damaged`);
  return bytes;
}

// ---------------------------------------------------------------------------
// The recording layer.

class Recorder {
  constructor() {
    this.events = [];
    this.ctx = new Map();
    this.req = new Map();
    this.answered = new Set();
    this.nextCtx = 0;
    this.nextReq = 0;
    // Every data request a step returned: { index, request, operation }.
    this.requests = [];
  }
  ctxIndex(pointer, create = false) {
    if (create || !this.ctx.has(pointer)) this.ctx.set(pointer, this.nextCtx++);
    return this.ctx.get(pointer);
  }
  // A pointer the C core reuses after its request was answered is a new request.
  reqIndex(pointer) {
    if (!this.req.has(pointer) || this.answered.has(this.req.get(pointer))) this.req.set(pointer, this.nextReq++);
    return this.req.get(pointer);
  }
}

function instrumentModule(c4w, recorder, state) {
  if (c4w.__colibriVectors) return;
  c4w.__colibriVectors = true;
  const text = (pointer) => (pointer ? c4w.UTF8ToString(pointer) : null);
  const bytesAt = (pointer, length) => Buffer.from(c4w.HEAPU8.subarray(pointer, pointer + length));
  const record = (event) => recorder.events.push(event);
  const wrap = (name, fn) => {
    const original = c4w[name];
    assert.equal(typeof original, 'function', `c4w.${name}`);
    c4w[name] = (...args) => fn(original, ...args);
  };
  // Step texts: request pointers become indices.
  const status = (raw, ctx) => {
    const parsed = JSON.parse(raw);
    const pointers = Array.isArray(parsed?.requests) ? parsed.requests.map((request) => request.req_ptr) : [];
    const indices = new Map(pointers.map((pointer) => [pointer, recorder.reqIndex(pointer)]));
    let seen = 0;
    const replaced = raw.replace(/"req_ptr": ([0-9]+)/g, (_, pointer) => {
      seen += 1;
      assert.ok(indices.has(Number(pointer)), 'every req_ptr in a step\'s text is one of its requests');
      return `"req_ptr": ${indices.get(Number(pointer))}`;
    });
    assert.equal(seen, pointers.length, 'each request\'s pointer appears once in its step\'s text');
    for (const request of parsed?.requests ?? []) {
      recorder.requests.push({ index: indices.get(request.req_ptr), ctx, request, operation: state.operation, requestIndex: state.requestIndex });
    }
    return replaced;
  };
  wrap('_c4w_get_method_type', (fn, chain, method, params, flags) => {
    const event = { op: 'method_type', chain: String(chain), method: text(method), params: text(params), flags };
    event.type = fn(chain, method, params, flags);
    record(event);
    return event.type;
  });
  wrap('_c4w_create_rpc_ctx', (fn, method, params, chain, proverFlags, verifyFlags, mode) => {
    const event = { op: 'create', method: text(method), params: text(params), chain: String(chain), prover_flags: proverFlags, verify_flags: verifyFlags, mode };
    const pointer = fn(method, params, chain, proverFlags, verifyFlags, mode);
    event.ctx = pointer ? recorder.ctxIndex(pointer, true) : null;
    record(event);
    return pointer;
  });
  wrap('_c4w_rpc_ctx_set_min_latest_block_ts', (fn, ctx, ts) => {
    record({ op: 'min_latest_block_ts', ctx: recorder.ctxIndex(ctx), ts: String(ts) });
    return fn(ctx, ts);
  });
  wrap('_c4w_execute_rpc_ctx', (fn, ctx) => {
    const index = recorder.ctxIndex(ctx);
    let result;
    try {
      result = fn(ctx);
    } catch (error) {
      record({ op: 'step', ctx: index, trap: `${error.name}: ${error.message}` });
      throw error;
    }
    record({ op: 'step', ctx: index, status: status(c4w.UTF8ToString(result), index) });
    return result;
  });
  wrap('_c4w_req_set_response', (fn, request, data, length, node) => {
    const index = recorder.reqIndex(request);
    const bytes = bytesAt(data, length);
    const event = { op: 'response', req: index, node, bytes: length, sha256: sha256(bytes) };
    // An answer no recorded fetch served (the checkpoint check builds its
    // own from main's fetches): its bytes, so a replay outside this harness
    // (COL-2's native one) can give the C core the same answer.
    if (!state.served.has(event.sha256)) {
      const text = bytes.toString('utf8');
      if (Buffer.from(text, 'utf8').equals(bytes)) event.body = text;
      else event.body_hex = bytes.toString('hex');
    }
    record(event);
    recorder.answered.add(index);
    state.bodies.set(index, length);
    return fn(request, data, length, node);
  });
  wrap('_c4w_req_set_error', (fn, request, error, node) => {
    const index = recorder.reqIndex(request);
    record({ op: 'error', req: index, node, error: text(error) });
    recorder.answered.add(index);
    return fn(request, error, node);
  });
  wrap('_c4w_free_rpc_ctx', (fn, ctx) => {
    record({ op: 'free', ctx: recorder.ctxIndex(ctx) });
    return fn(ctx);
  });
  wrap('_c4w_decode_proof', (fn, proof, length) => {
    const sha = sha256(bytesAt(proof, length));
    const result = fn(proof, length);
    const decoded = text(result);
    record({ op: 'decode', bytes: length, sha256: sha, result: decoded === null ? null : { chars: decoded.length, sha256: sha256(decoded) } });
    return result;
  });
  wrap('_c4w_create_verify_ctx', (fn, proof, length, method, args, chain, checkpoint, witnessKeys, flags, minTs) => {
    const event = { op: 'verify_create', bytes: length, sha256: sha256(bytesAt(proof, length)), method: text(method), args: text(args),
      chain: String(chain), trusted_checkpoint: text(checkpoint), witness_keys: text(witnessKeys), flags, min_latest_block_ts: String(minTs) };
    const pointer = fn(proof, length, method, args, chain, checkpoint, witnessKeys, flags, minTs);
    event.ctx = pointer ? recorder.ctxIndex(pointer, true) : null;
    record(event);
    return pointer;
  });
  wrap('_c4w_verify_proof', (fn, ctx) => {
    const index = recorder.ctxIndex(ctx);
    const result = fn(ctx);
    record({ op: 'verify', ctx: index, status: status(c4w.UTF8ToString(result), index) });
    return result;
  });
  wrap('_c4w_free_verify_ctx', (fn, ctx) => {
    record({ op: 'verify_free', ctx: recorder.ctxIndex(ctx) });
    return fn(ctx);
  });
  // Not reached by the paths recorded here; any call is recorded.
  for (const name of ['_c4w_set_checkpoint', '_c4w_reset_caches', '_c4w_rpc_ctx_set_proxy_urls',
    '_c4w_rpc_ctx_set_witness_keys', '_c4w_get_current_version_number']) {
    wrap(name, (fn, ...args) => {
      record({ op: name.replace('_c4w_', ''), args: args.map(String) });
      return fn(...args);
    });
  }
  // A local prover fails the case: the reference has #1081.
  for (const name of ['_c4w_create_proof_ctx', '_c4w_execute_proof_ctx', '_c4w_free_proof_ctx']) {
    wrap(name, (fn, ...args) => {
      state.fatal ??= new Error(`The reference called ${name}: a local prover ran`);
      return fn(...args);
    });
  }
  // The store: whatever the host registers on this instance.
  let wrapped = null;
  Object.defineProperty(c4w, 'storage', {
    configurable: true,
    get: () => wrapped,
    set: (storage) => {
      wrapped = storage && {
        get: (key) => {
          const value = storage.get(key);
          record({ op: 'store_get', key, ...(value ? { bytes: value.length, sha256: sha256(value) } : { found: false }) });
          return value;
        },
        set: (key, value) => {
          record({ op: 'store_set', key, bytes: value.length, sha256: sha256(value) });
          return storage.set(key, value);
        },
        del: (key) => {
          record({ op: 'store_del', key });
          return storage.del(key);
        },
      };
    },
  });
}

/**
 * Loads the reference fresh, with the recording layer on every WASM instance
 * colibri-runtime.js provides (the first, and any after a trap).
 */
function loadRuntime(reference, recorder, state) {
  dropModules(reference);
  const upstream = reference.require(path.join(reference.cjs, 'runtime.js'));
  const setProvider = upstream.setRuntimeProvider;
  upstream.setRuntimeProvider = (provider) => setProvider(async () => {
    const runtime = await provider();
    const wasm = require.cache[path.join(reference.cjs, 'wasm.js')];
    instrumentModule(await wasm.exports.getC4w(), recorder, state);
    return runtime;
  });
  const runtime = reference.require(path.join(reference.checkout, 'src/main/ens/colibri-runtime.js'));
  assert.equal(runtime.clientVersion, contract.CLIENT_VERSION);
  state.noLocalProving = runtime.NO_LOCAL_PROVING_ERROR;
  return runtime;
}

// ---------------------------------------------------------------------------
// Worlds: each fetch answered by a case's rules, then by its session's captures.

/** The data request a fetch serves, and the server it went to (index in main's table). */
function linkFetch(recorder, servers, url, body) {
  for (const entry of recorder.requests) {
    if (recorder.answered.has(entry.index)) continue;
    const { request } = entry;
    if ((request.payload === undefined ? null : JSON.stringify(request.payload)) !== body) continue;
    const list = servers[request.type] ?? [];
    const index = list.findIndex((server) => joinPath(server, request.url) === url);
    if (index >= 0) return { req: entry.index, type: request.type, index };
  }
  return null;
}

/** A Response for an answer spec, and what the vector records of it. */
function answer(spec) {
  if (spec.transport) return { throw: new TypeError(spec.transport), record: { transport: spec.transport } };
  let bytes;
  let derived;
  if (spec.flip !== undefined) {
    bytes = Buffer.from(spec.base.bytes);
    const offset = spec.flip === 'middle' ? Math.floor(bytes.length / 2) : spec.flip;
    bytes[offset] ^= 1;
    derived = { flip: offset, of: spec.base.response.sha256 };
  } else if (spec.body !== undefined) {
    bytes = Buffer.from(spec.body);
    // The text itself, so a replay outside this harness (COL-2's native
    // one) can give the C core the same bytes.
    derived = { scripted: true, body: bytes.toString('utf8') };
  } else if (spec.from) {
    bytes = spec.from.bytes;
    if (spec.from.response.error) return { throw: new TypeError(spec.from.response.error), record: { transport: spec.from.response.error } };
  } else {
    throw new Error('Unknown answer');
  }
  const status = spec.status ?? spec.from?.response.status ?? spec.base?.response.status ?? 200;
  const headers = spec.headers ?? spec.from?.headers ?? spec.base?.headers ?? {};
  return {
    response: () => new Response(bytes, { status, headers }),
    record: { status, bytes: bytes.length, sha256: sha256(bytes), ...(derived ? { derived } : {}) },
  };
}

function poolEntry(exchange, dir) {
  return {
    ...exchange,
    get bytes() { return exchange.response.sha256 ? bodyBytes(exchange.response.sha256, dir) : null; },
    headers: exchange.response.content_type ? { 'content-type': exchange.response.content_type } : {},
  };
}

/** The session's capture pool, keyed by request. */
function sessionPool(session, dir) {
  const pool = new Map();
  for (const exchange of session?.exchanges ?? []) {
    const key = keyOf(exchange.url, exchange.method, exchange.body ?? null);
    assert.ok(!pool.has(key), `A session answers each request once: ${key.slice(0, 200)}`);
    pool.set(key, poolEntry(exchange, dir));
  }
  return pool;
}

// ---------------------------------------------------------------------------
// Running a case.

async function withGlobals(clock, fn) {
  const saved = { now: Date.now, fetch: globalThis.fetch, cwd: process.cwd(), env: process.env.C4_DISABLE_NATIVE,
    warn: console.warn, error: console.error, load: Module._load };
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-vectors-'));
  const cwd = path.join(scratch, 'cwd');
  fs.mkdirSync(cwd);
  try {
    // The package's default store is Node's fs at the working directory: an
    // empty one, checked empty after.
    process.chdir(cwd);
    Module._load = NODE_LOAD;
    Date.now = () => clock.now;
    console.warn = () => {};
    console.error = () => {};
    const result = await fn(scratch);
    assert.deepEqual(fs.readdirSync(cwd), [], 'The reference wrote to its working directory');
    return result;
  } finally {
    process.chdir(saved.cwd);
    Module._load = saved.load;
    Date.now = saved.now;
    globalThis.fetch = saved.fetch;
    if (saved.env === undefined) delete process.env.C4_DISABLE_NATIVE;
    else process.env.C4_DISABLE_NATIVE = saved.env;
    console.warn = saved.warn;
    console.error = saved.error;
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function resultRecord(value) {
  if (value === undefined) return { result_undefined: true };
  const json = JSON.stringify(value);
  return json.length <= INLINE_RESULT ? { result: value } : { result_json: { chars: json.length, sha256: sha256(json) } };
}

/** Each request's clock: captured, or (capture) now, another case's, plus an offset. */
function clockOf(kase, index, { live, session }) {
  if (!live) {
    const clocks = session?.clocks?.[kase.id];
    assert.ok(Array.isArray(clocks) && clocks.length === kase.requests.length, `No captured clock for ${kase.id}`);
    return clocks[index];
  }
  const base = kase.clockOf && index === 0 ? live.clocks[kase.clockOf][0] : live.now();
  return base + (kase.requests[index].clockOffset ?? 0);
}

/**
 * Runs one case. `live` (capture only) fetches what the session lacks from
 * the network and records it; otherwise anything unscripted fails the case.
 */
async function runCase(reference, kase, { session, stores, live = null, dir = FIXTURES }) {
  const pool = live ? live.pool : sessionPool(session, dir);
  const params = live ? live.params : session?.params ?? {};
  const recorder = new Recorder();
  const state = { operation: null, requestIndex: null, fatal: null, bodies: new Map(), used: new Set(), served: new Set() };
  const use = (entry) => state.used.add(keyOf(entry.url, entry.method, entry.body ?? null));
  const clock = { now: 0 };
  const clocks = [];
  const servers = reference.servers[kase.chain];
  const lookup = (request) => {
    const entry = pool.get(keyOf(request.url, request.method, request.body));
    if (!entry) throw new Error(`${kase.id}: nothing captured for ${request.url}`);
    use(entry);
    return entry;
  };
  const fetchStub = async (input, init = {}) => {
    const url = String(input);
    const method = init.method ?? 'GET';
    const body = init.body === undefined ? null : String(init.body);
    const link = linkFetch(recorder, servers, url, body);
    const event = { op: 'fetch', ...(link ? { req: link.req, server: link.type, index: link.index } : {}),
      url, method, headers: { ...(init.headers ?? {}) }, ...(body === null ? {} : { body }) };
    recorder.events.push(event);
    const request = { url, method, body, server: link, payload: body === null ? null : JSON.parse(body) };
    let reply;
    try {
      const rule = (kase.rules ?? []).find((candidate) => candidate.match(request));
      if (rule) {
        event.rule = rule.name;
        const spec = typeof rule.answer === 'function' ? rule.answer(request, { pool, lookup }) : rule.answer;
        if (spec.from) use(spec.from);
        reply = answer(spec);
      } else {
        const key = keyOf(url, method, body);
        let exchange = pool.get(key);
        if (!exchange && live) {
          // One request asked twice in a round goes to the network once.
          if (!live.inflight.has(key)) {
            live.inflight.set(key, live.fetch({ url, method, headers: event.headers, body }).then((captured) => {
              const entry = poolEntry(captured, live.dir);
              pool.set(key, entry);
              return entry;
            }));
          }
          exchange = await live.inflight.get(key);
        }
        if (!exchange) throw new Error(`Unscripted fetch: ${key.slice(0, 300)}`);
        use(exchange);
        reply = answer({ from: exchange });
      }
    } catch (error) {
      state.fatal ??= new Error(`${kase.id}: ${error.message}`);
      throw new TypeError('unscripted');
    }
    event.reply = reply.record;
    if (reply.record.sha256) state.served.add(reply.record.sha256);
    if (reply.throw) throw reply.throw;
    return reply.response();
  };
  const outcome = await withGlobals(clock, async (scratch) => {
    globalThis.fetch = fetchStub;
    if (kase.kind === 'checkpoint') return runCheckpoint(reference, kase, recorder, state, clock);
    const runtime = loadRuntime(reference, recorder, state);
    const { createColibriService } = reference.require(path.join(reference.checkout, 'src/main/ens/colibri-worker.js'));
    let storageDir = null;
    if (!kase.private) {
      storageDir = path.join(scratch, 'colibri');
      fs.mkdirSync(storageDir);
      for (const [key, value] of kase.store ? stores.get(kase.store) : []) fs.writeFileSync(path.join(storageDir, key), value);
    }
    const posts = [];
    const service = createColibriService({ runtime, storageDir, post: (message) => posts.push(message) });
    await service.init();
    const outcomes = [];
    const requests = [];
    for (const [index, request] of kase.requests.entries()) {
      if (live && request.wait) await new Promise((resolve) => setTimeout(resolve, request.wait));
      if (live && request.before) await request.before(live, kase.chain);
      clock.now = clockOf(kase, index, { live, session });
      clocks.push(clock.now);
      const value = typeof request.params === 'function' ? request.params(params) : request.params;
      const sees = Array.isArray(value) ? value : value ? [value] : [];
      requests.push({ method: request.method, params: value, clock: clock.now });
      state.operation = { method: request.method, params: value, sees, chain: kase.chain, zk: kase.zk };
      state.requestIndex = index;
      recorder.events.push({ op: 'request', index });
      const before = posts.length;
      await service.handle({ type: 'request', id: index + 1, clientId: 1,
        config: { chainId: kase.chain, proverUrl: servers.prover[0], zkProof: kase.zk }, method: request.method, params: value });
      const mine = posts.slice(before);
      const result = mine.find((message) => message.type === 'result');
      assert.ok(result, `${kase.id}: no result`);
      const traps = mine.filter((message) => message.type === 'trap').map((message) => message.message);
      outcomes.push({
        ...(result.ok ? { ok: true, ...resultRecord(result.result) } : { ok: false, error: result.error, ...(result.retry ? { retry: true } : {}) }),
        ...(traps.length ? { traps } : {}),
      });
      if (kase.discover && live && result.ok) Object.assign(live.params, kase.discover(index, result));
    }
    const store = storageDir
      ? new Map(fs.readdirSync(storageDir).sort().map((key) => [key, fs.readFileSync(path.join(storageDir, key))]))
      : null;
    return { requests, outcomes, store };
  });
  if (state.fatal) throw state.fatal;
  return { recorder, state, outcome, clocks };
}

/** A checkpoint case: `verifyCheckpoint` over the reference's runtime, its fetch from the evidence. */
async function runCheckpoint(reference, kase, recorder, state, clock) {
  const runtime = loadRuntime(reference, recorder, state);
  const { verifyCheckpoint } = reference.require(path.join(reference.checkout, 'src/main/myotis/checkpoint-verifier-worker.js'));
  const capture = kase.capture(reference);
  clock.now = capture.now;
  state.operation = { checkpoint: true, chain: kase.chain };
  state.requestIndex = 0;
  recorder.events.push({ op: 'checkpoint', chain: kase.chain });
  const fetch = async (url, options = {}) => {
    const event = { op: 'main_fetch', url: String(url), method: options.method ?? 'GET', ...(options.body ? { body: options.body } : {}) };
    recorder.events.push(event);
    const reply = capture.fetch(String(url), options);
    if (reply.proof) {
      event.variant = 'checkpoint_proof';
      event.reply = { status: 200, bytes: reply.proof.length, sha256: sha256(reply.proof) };
      // A proof the case changed (a flipped bit): how, as a fetch's flipped
      // body is recorded, so a replay outside this harness can rebuild it.
      const original = capture.proofs.find((proof) => proof.length === reply.proof.length);
      if (original && !original.equals(reply.proof)) {
        const offsets = [...reply.proof.keys()].filter((i) => reply.proof[i] !== original[i]);
        assert.ok(offsets.length === 1 && (reply.proof[offsets[0]] ^ original[offsets[0]]) === 1,
          `${kase.id}: a changed proof differs from its capture in one flipped bit`);
        event.reply.derived = { flip: offsets[0], of: sha256(original) };
      }
      return new Response(reply.proof);
    }
    if (reply.missing) {
      event.reply = { transport: reply.missing };
      throw new Error(reply.missing);
    }
    event.reply = { status: reply.status, bytes: Buffer.byteLength(reply.body), sha256: sha256(reply.body) };
    return new Response(reply.body, { status: reply.status });
  };
  let outcome;
  try {
    outcome = { ok: true, checkpoint: await verifyCheckpoint(kase.chain, { fetch, now: () => clock.now, runtime }) };
  } catch (error) {
    outcome = { ok: false, code: error.code ?? null };
  }
  return { requests: [{ checkpoint: kase.chain, clock: clock.now }], outcomes: [outcome], store: null, proofs: capture.proofs };
}

// ---------------------------------------------------------------------------
// The vectors.

const digests = (store) => store && Object.fromEntries([...store].map(([key, value]) => [key, { bytes: value.length, sha256: sha256(value) }]));

/** The design's adapter outcome for a refusal or an error text: main's createError, then the worker's cut. */
function adapterOutcome(reference, method, params, text) {
  const { ProviderRpcError } = reference.require(path.join(reference.cjs, 'types.js'));
  const { serializeError } = reference.require(path.join(reference.checkout, 'src/main/ens/colibri-worker.js'));
  return serializeError(ProviderRpcError.createError(new Error(text), { method, params }));
}

async function buildColibri(checkout, meta, options = {}) {
  const load = Module._load;
  Module._load = NODE_LOAD;
  try {
    return await build(checkout, meta, options);
  } finally {
    Module._load = load;
  }
}

async function build(checkout, meta, { partial = false }) {
  const reference = loadColibriReference(checkout);
  const fixtures = loadFixtures();
  assert.equal(fixtures.meta?.colibriBrowserCommit, meta.freedomBrowserCommit, 'The captures were made from another colibri reference');
  const { CASES, UR_CALL } = require('./colibri-cases');
  checkUrCall(reference, UR_CALL);
  const stores = new Map();
  const used = new Map(Object.keys(fixtures.sessions).map((id) => [id, new Set()]));
  const reached = new Map(contract.VARIANTS.map((variant) => [variant, { cases: [], chains: new Set(), largest_body: 0 }]));
  const cases = [];
  for (const kase of CASES) {
    const session = kase.kind === 'checkpoint' ? null : fixtures.sessions[kase.session];
    if (kase.kind !== 'checkpoint') assert.ok(session, `${kase.id}: session ${kase.session} was never captured`);
    const run = await runCase(reference, kase, { session, stores });
    if (run.outcome.store) stores.set(kase.id, run.outcome.store);
    if (kase.kind !== 'checkpoint') for (const key of run.state.used) used.get(kase.session).add(key);
    if (kase.kind === 'checkpoint') {
      for (const proof of run.outcome.proofs) bodyBytes(sha256(proof));
    }
    // The fetch contract, from the request side.
    const contractRows = [];
    // Deviations that change no request keep the contract's checks.
    const contractApplies = !kase.deviation || ['fetch-error-text', 'checked-decode'].includes(kase.deviation);
    for (const entry of run.recorder.requests) {
      const variant = contract.classify(entry.request, entry.operation, reference.servers[kase.chain]);
      contractRows.push({ req: entry.index, variant });
      if (contractApplies) {
        assert.ok(variant, `${kase.id}: request ${entry.index} matches no variant its operation allows: ${JSON.stringify(entry.request).slice(0, 400)}`);
      }
      if (variant && contractApplies) {
        const row = reached.get(variant);
        if (!row.cases.includes(kase.id)) row.cases.push(kase.id);
        row.chains.add(kase.chain);
        row.largest_body = Math.max(row.largest_body, run.state.bodies.get(entry.index) ?? 0);
      }
    }
    if (kase.kind === 'checkpoint') {
      // The checkpoint row: main's one proof fetch, then at most 8 roots.
      const events = run.recorder.events;
      const proofs = events.filter((event) => event.variant === 'checkpoint_proof');
      assert.equal(proofs.length, 1, `${kase.id}: one checkpoint_proof`);
      assert.ok(events.indexOf(proofs[0]) < events.findIndex((event) => event.op === 'verify' || event.op === 'step' || event.op === 'decode'),
        `${kase.id}: checkpoint_proof comes first`);
      assert.ok(contractRows.filter((row) => row.variant === 'checkpoint_root').length <= 8, `${kase.id}: at most 8 checkpoint_root`);
    }
    for (const event of run.recorder.events) {
      if (event.variant === 'checkpoint_proof') {
        const row = reached.get('checkpoint_proof');
        if (!row.cases.includes(kase.id)) row.cases.push(kase.id);
        row.chains.add(kase.chain);
        row.largest_body = Math.max(row.largest_body, event.reply.bytes);
      }
    }
    const record = {
      id: kase.id, kind: kase.kind, chain: kase.chain,
      ...(kase.kind === 'checkpoint' ? { evidence: kase.files } : {
        zk: kase.zk, session: kase.session, store: kase.store ? { from: kase.store, entries: digests(stores.get(kase.store)) } : null,
        ...(kase.private ? { private: true } : {}),
      }),
      ...(kase.rules?.length ? { rules: kase.rules.map((rule) => rule.name) } : {}),
      ...(kase.deviation ? { deviation: kase.deviation } : {}),
      requests: run.outcome.requests,
      trace: run.recorder.events,
      contract: contractRows,
      outcomes: run.outcome.outcomes,
      ...(kase.kind === 'checkpoint' ? {} : { store_after: digests(run.outcome.store) }),
    };
    if (kase.deviation === 'checked-decode') {
      // The decode refuses the proof (null); the check's outcome is the same.
      record.design = { decode: null, outcomes: run.outcome.outcomes };
    } else if (kase.design) {
      // Refused before any context: no step, no fetch, and main's adapter error.
      const [{ method, params }] = run.outcome.requests;
      const text = typeof kase.design === 'function' ? kase.design(session.params) : kase.design;
      record.design = { refused: text, fetches: 0, outcomes: [{ ok: false, error: adapterOutcome(reference, method, params, text) }] };
    } else if (kase.designFetchError) {
      // Deviation fetch-error-text: main's fetch text names URLs as <url>
      // and is cut to 2,000 units, before the C core's and createError's
      // prefixes; the adapter's message is cut after them.
      const failure = run.recorder.events.find((event) => event.op === 'error');
      const fetchText = failure.error.replace(/https?:\/\/[^\s"'<>]+/gi, '<url>').slice(0, 2000);
      const [{ method, params }] = run.outcome.requests;
      // #1081's prefix, the reference's own constant.
      record.design = { fetch_error: fetchText, outcomes: [{ ok: false, error: adapterOutcome(reference, method, params, `${run.state.noLocalProving}: ${fetchText}`) }] };
    }
    cases.push(record);
  }
  // Every capture answers some case: the fixtures hold nothing else.
  if (!partial) {
    for (const [id, session] of Object.entries(fixtures.sessions)) {
      for (const exchange of session.exchanges) {
        assert.ok(used.get(id).has(keyOf(exchange.url, exchange.method, exchange.body ?? null)), `Session ${id} holds a capture no case reads: ${exchange.url}`);
      }
    }
  }
  // The fetch contract, from the variant side.
  const variants = {};
  for (const [variant, row] of reached) {
    assert.ok(partial || row.cases.length, `No case reaches the fetch-contract variant ${variant}`);
    variants[variant] = { cases: row.cases, chains: [...row.chains].sort((a, b) => a - b), largest_body: row.largest_body };
  }
  return {
    meta,
    reference: {
      colibri_version: COLIBRI_VERSION,
      client_version: contract.CLIENT_VERSION,
      c4w_wasm_sha256: C4W_SHA256,
      files: REFERENCE_FILES,
      captures: fixtures.meta,
    },
    servers: reference.servers,
    variants,
    cases,
  };
}

/** The UR call is ENS's: rebuilt with the reference's ethers through a BrowserProvider. */
function checkUrCall(reference, call) {
  const ethers = reference.require('ethers');
  const iface = new ethers.Interface(['function resolve(bytes name, bytes data) view returns (bytes result, address resolver)']);
  const inner = new ethers.Interface(['function addr(bytes32 node) view returns (address)']).encodeFunctionData('addr', [ethers.namehash('vitalik.eth')]);
  const data = iface.encodeFunctionData('resolve', [ethers.dnsEncode('vitalik.eth', 255), inner]);
  assert.equal(call.data, data, 'The Universal Resolver call is ENS\'s');
  assert.equal(call.to, '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe'.toLowerCase());
}

module.exports = {
  COLIBRI_VERSION, C4W_SHA256, FIXTURES, REFERENCE_FILES,
  loadColibriReference, loadFixtures, bodyBytes, runCase, buildColibri, sha256, keyOf, poolEntry,
};
