'use strict';

// Replay vectors for design 0005: the pinned chain-data router
// (src/main/networks/chain-data-router.js), with the real blockscout-logs.js
// and the Ant bridge's real router options, run whole in scripted worlds.
// Every scenario gets fresh modules (no adaptive, slot, log-range or
// cooldown state survives), the reference's own fake timers, and a
// declarative world: each chain's registry snapshot, Myotis' readiness,
// status samples and outcomes per operation (its manager's thrown errors
// included), Colibri's outcomes, every JSON-RPC endpoint, Blockscout's pages
// and the DNS answers a redirect needs. Unscripted I/O fails the generation.
// No reference code is copied: the harness stubs the router's modules and
// global fetch, and only reads the router's state tables through accessors
// appended to the original source.
//
// Each scenario records its input (world, steps, calls) and, for every
// call, its result or thrown error with its settlement time; for every
// step, the router's state tables (adaptive routes, Myotis slots, Colibri's
// in-flight work, log-range learning, Blockscout cooldowns); and every I/O
// request: a JSON-RPC exchange (URL, body with its `id` normalized to 0),
// a Blockscout page and each HTTP hop and DNS lookup inside it, a Myotis or
// Colibri operation with its outcome, and Myotis' status samples. Each has
// its virtual start time, its end time and outcome (answered, failed,
// aborted, or still open when the scenario ends), the call that made it,
// and the answer it got, so a replay serves the recorded answer to the
// matching request instead of re-creating the world.
//
// Scripted answers come at once unless they name a delay, as the suites'
// mocks do. A ported call carries the settle time its test asserts
// (`expect_settle_ms`, or a bound), and a fixture that drifts from it fails
// the generation.
//
// Encodings. Every value the reference produced or was given, and every
// call's params, is JSON text in a string field (`*_json`), never a JSON
// value in the file: so no value can pass for an encoding, and every value
// JSON.parse can make survives, lone surrogates (as escapes), any nesting,
// -0 (written "-0") and ±Infinity (written ±1e400, which JSON.parse reads
// back as such) included. A present `undefined` is a field of its own
// (`*_undefined: true`), never a value. A text over 64 KiB is written in
// its field's repeat form (`*_json_repeat`, `body_repeat`): { head, unit,
// count, tail, length, sha256 }, the text being head + unit × count + tail.
// An object the router returned or threw is a list of entries in property
// order, each { key, json | json_repeat | undefined }. Worlds, steps and
// state tables are plain JSON the harness writes itself. Instants inside
// the state tables are virtual milliseconds (the reference's Date.now()
// minus EPOCH); 0 stays 0, the reference's "unset".

const crypto = require('node:crypto');
const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const { AsyncLocalStorage } = require('node:async_hooks');

// Virtual time starts here; recorded times are milliseconds after it.
const EPOCH = 1_760_000_000_000;
// Virtual time one step may take before its calls count as pending.
const MAX_STEP_MS = 10 * 60_000;
// How long a scripted answer takes unless it names a delay: none, as the
// suites' mocks resolve at once.
const DEFAULT_DELAY_MS = 0;
// Texts longer than this are written in their repeat form.
const LARGE_TEXT = 64 * 1024;
// The nesting plain JSON the harness writes may have.
const PLAIN_DEPTH = 32;
const MYOTIS_NAMES = { 1: 'Ethereum', 100: 'Gnosis' };

/** A text as head + unit × count + tail, verified, or null. */
function repeatOf(text) {
  let best = null;
  for (let unit = 1; unit <= 16; unit += 1) {
    // The longest run of positions i where text[i] === text[i + unit]: the
    // span [start, end + unit) repeats with period `unit`.
    let runStart = 0;
    let start = 0;
    let end = 0;
    for (let i = 0; i + unit < text.length; i += 1) {
      if (text.charCodeAt(i) !== text.charCodeAt(i + unit)) {
        runStart = i + 1;
      } else if (i + 1 - runStart > end - start) {
        start = runStart;
        end = i + 1;
      }
    }
    const count = Math.floor((end + unit - start) / unit);
    const candidate = { head: text.slice(0, start), unit: text.slice(start, start + unit), count, tail: text.slice(start + count * unit) };
    if (!best || candidate.head.length + candidate.tail.length < best.head.length + best.tail.length) best = candidate;
    if (best.head.length + best.tail.length < 1024) break;
  }
  if (!best || best.head.length + best.tail.length > 4096) return null;
  if (best.head + best.unit.repeat(best.count) + best.tail !== text) throw new Error('repeat form: expansion mismatch');
  return { ...best, length: text.length, sha256: crypto.createHash('sha256').update(text, 'utf8').digest('hex') };
}

/** A world's repeat macro ({ head, unit, count, tail }) as its text. */
function repeated({ head = '', unit, count, tail = '' }) {
  return head + unit.repeat(count) + tail;
}

/**
 * The JSON text of a value JSON.parse could have made, as JSON.stringify
 * writes it (keys in property order, strings escaped, lone surrogates as
 * \uXXXX), except that -0 is "-0" and ±Infinity ±1e400, which JSON.parse
 * reads back as such. A nested undefined, NaN or anything but JSON data
 * fails the generation: no record could keep it.
 */
function jsonText(value, at = 'value') {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (Object.is(value, -0)) return '-0';
      if (value === Infinity) return '1e400';
      if (value === -Infinity) return '-1e400';
      if (Number.isNaN(value)) throw new Error(`${at}: NaN has no JSON text`);
      return JSON.stringify(value);
    case 'object': {
      const item = (child, where) => {
        if (child === undefined) throw new Error(`${where}: a nested undefined has no record`);
        return jsonText(child, where);
      };
      if (Array.isArray(value)) return `[${value.map((child, i) => item(child, `${at}[${i}]`)).join(',')}]`;
      return `{${Object.keys(value).map((key) => `${JSON.stringify(key)}:${item(value[key], `${at}.${key}`)}`).join(',')}}`;
    }
    default:
      throw new Error(`${at}: a ${typeof value} has no JSON text`);
  }
}

/** A text field, or its repeat form when it is over 64 KiB. */
function textField(name, text) {
  if (text.length <= LARGE_TEXT) return { [name]: text };
  const repeat = repeatOf(text);
  if (!repeat) throw new Error(`${name}: a ${text.length}-character text has no repeat form`);
  return { [`${name}_repeat`]: repeat };
}

/** A value as `<name>_json` (its text), `<name>_json_repeat`, or `<name>_undefined: true`. */
function jsonField(name, value) {
  const prefix = name ? `${name}_` : '';
  if (value === undefined) return { [`${prefix}undefined`]: true };
  return textField(`${prefix}json`, jsonText(value, name || 'value'));
}

/** An object's own enumerable properties, in order: { key, json | json_repeat | undefined }. */
function entriesOf(object) {
  return Object.keys(object).map((key) => ({ key, ...jsonField('', object[key]) }));
}

/** A call's value: an object as its entries, anything else as `value_json`. */
function recordValue(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? { value: entriesOf(value) } : jsonField('value', value);
}

/** A thrown value: its class, name, message and own enumerable properties, in order. */
function recordError(error) {
  if (!(error instanceof Error) && error?.constructor?.name !== 'DOMException') return { class: typeof error, ...jsonField('value', error) };
  return { class: error.constructor?.name ?? 'Error', name: error.name, ...jsonField('message', error.message), props: entriesOf(error) };
}

/**
 * Plain JSON the harness writes (worlds, steps, state tables, the I/O
 * records' frames), copied and checked: well-formed strings of at most
 * 64 KiB, finite numbers other than -0, shallow nesting. Keys whose value
 * is undefined are left out, as JSON.stringify leaves them.
 */
function plain(value, at = 'value', depth = 0) {
  if (depth > PLAIN_DEPTH) throw new Error(`${at}: nested too deep for plain JSON`);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (!value.isWellFormed() || value.length > LARGE_TEXT) throw new Error(`${at}: not a plain string`);
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error(`${at}: ${value} is not a plain number`);
    return value;
  }
  if (Array.isArray(value)) return value.map((item, i) => plain(item, `${at}[${i}]`, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) {
      if (value[key] === undefined) continue;
      if (!key.isWellFormed()) throw new Error(`${at}: a key that is not well formed`);
      out[key] = plain(value[key], `${at}.${key}`, depth + 1);
    }
    return out;
  }
  throw new Error(`${at}: a ${typeof value} is not plain JSON`);
}

// Read-only accessors appended to the pinned sources (as chain.js's
// observers are): the router's state tables, and Blockscout's page reads,
// which the harness wraps to record each page as one operation.
const ROUTER_STATE = `
;module.exports.__state = () => ({
  adaptive: [...adaptiveSourceState].map(([key, value]) => [key, { ...value }]),
  myotis_slots: [...myotisSlots].map(([chain, slots]) => [chain, { in_flight: slots.inFlight, waiting: slots.waiters.length }]),
  colibri_in_flight: colibriInFlight.size,
  colibri_routes: [...colibriInFlightByRoute],
  log_range: [...logRangeState].map(([key, value]) => [key, { ...value }]),
  log_index_cool_until: [...logIndexCoolUntil],
  log_index_pair_cool_until: [...logIndexPairCoolUntil],
});
`;
const BLOCKSCOUT_PAGES = `
;module.exports.__observePages = (wrap) => { fetchPage = wrap(fetchPage); };
`;

/**
 * Loads fresh copies of the router, blockscout-logs.js and the Ant bridge.
 * `stubs` stands in for the router's own requires; `dns` for
 * blockscout-logs.js's node:dns. `restore` removes the hook and evicts
 * every checkout module under src/, so no state survives into the next
 * scenario; a failed load restores before throwing.
 */
function loadReference(checkout, stubs, dns) {
  const src = path.join(checkout, 'src');
  const main = path.join(src, 'main');
  const routerFile = path.join(main, 'networks', 'chain-data-router.js');
  const blockscoutFile = path.join(main, 'networks', 'blockscout-logs.js');
  const bridgeFile = path.join(main, 'swarm', 'ant-chain-bridge.js');
  const evict = () => {
    for (const key of Object.keys(Module._cache)) if (key.startsWith(src + path.sep)) delete Module._cache[key];
  };
  const originalLoad = Module._load;
  const restore = () => {
    Module._load = originalLoad;
    evict();
  };
  Module._load = function load(request, parent, isMain) {
    if (parent?.filename === routerFile && Object.hasOwn(stubs, request)) return stubs[request];
    if (parent?.filename === blockscoutFile && request === 'node:dns') return dns;
    if (request === 'electron' && parent?.filename?.startsWith(src + path.sep)) throw new Error('the replay loads no Electron module');
    return originalLoad.call(this, request, parent, isMain);
  };
  const compile = (filename, extra = '') => {
    const mod = new Module(filename, null);
    mod.filename = filename;
    mod.paths = Module._nodeModulePaths(path.dirname(filename));
    Module._cache[filename] = mod;
    mod._compile(fs.readFileSync(filename, 'utf8') + extra, filename);
    mod.loaded = true;
    return mod.exports;
  };
  try {
    evict();
    // blockscout-logs.js first: the router's require finds this copy.
    const blockscout = compile(blockscoutFile, BLOCKSCOUT_PAGES);
    const router = compile(routerFile, ROUTER_STATE);
    const bridge = compile(bridgeFile);
    return { router, blockscout, bridge, restore };
  } catch (err) {
    restore();
    throw err;
  }
}

// The Myotis manager's and child process's own errors, by class, with
// their texts (myotis-manager.js runningInstance, verifiedRequest,
// broadcastRejected and sendRawTransaction; myotis-process.js unavailable).
// The classes are design 0005's ("Myotis read outcomes"), and the
// broadcast's; a scenario names one with `throws`, and the record keeps it.
const MYOTIS_ERRORS = {
  not_running: { make: (chain) => new Error(`${MYOTIS_NAMES[chain]} Myotis client is not running`) },
  not_ready: { make: (chain) => new Error(`${MYOTIS_NAMES[chain]} Myotis verified reader is not ready`) },
  state_changed: { make: () => Object.assign(new Error('Myotis state changed while the request was running'), { code: 'MYOTIS_UNAVAILABLE' }) },
  queue_full: { make: () => Object.assign(new Error('Myotis request queue is full'), { code: 'MYOTIS_UNAVAILABLE' }) },
  queue_deadline: { make: () => Object.assign(new Error('Myotis queue deadline exceeded'), { code: 'MYOTIS_UNAVAILABLE' }) },
  caller_deadline: { make: () => Object.assign(new Error('Myotis caller deadline exceeded'), { code: 'MYOTIS_UNAVAILABLE' }) },
  rejected: { make: (_chain, outcome) => Object.assign(new Error(outcome.reason), { code: -32000, myotisRefusal: 'rejected' }) },
  // In band: the client answered without a hash (sendRawTransaction).
  uncertain: { make: () => Object.assign(new Error('Myotis broadcast outcome uncertain; reconcile the original signed transaction'), { code: 'MYOTIS_BROADCAST_UNCERTAIN' }) },
  // Dispatched, then a deadline, an exit or a stop (myotis-process.js).
  uncertain_dispatched: { make: () => Object.assign(new Error('Myotis broadcast outcome uncertain; check the signed transaction hash before retrying'), { code: 'MYOTIS_BROADCAST_UNCERTAIN' }) },
  error: { make: (_chain, outcome) => new Error(outcome.message) },
};

const hex = (n) => `0x${n.toString(16)}`;

/** A step as recorded: plain JSON, each call's params as their JSON text. */
function recordStep(step) {
  const recordCall = (call) => Object.fromEntries(Object.entries(call).flatMap(([key, value]) => (
    key === 'params' ? Object.entries(jsonField('params', value)) : [[key, plain(value, `call.${key}`)]])));
  return Object.fromEntries(Object.entries(step).flatMap(([key, value]) => {
    if (value === undefined) return [];
    return [[key, key === 'calls' ? value.map(recordCall) : plain(value, `step.${key}`)]];
  }));
}

/** Runs one scenario and returns its record. Every global it changes is restored on every path. */
async function runScenario(checkout, FakeTimers, scenario) {
  const world = structuredClone(scenario.world);
  const io = [];
  const violations = [];
  const expectations = [];
  const callStore = new AsyncLocalStorage();
  // The innermost operation an I/O request belongs to: a Blockscout read
  // holds its pages, a page its HTTP hops and DNS lookups.
  const withinStore = new AsyncLocalStorage();
  let stepIndex = -1;
  let clock = null;
  const now = () => Date.now() - EPOCH;
  const record = (entry) => {
    const owner = callStore.getStore();
    const within = withinStore.getStore();
    if (!owner && entry.kind !== 'event') violations.push(`${entry.kind} outside any call`);
    const item = {
      id: io.length,
      step: owner?.step ?? stepIndex,
      ...(owner ? { call: owner.call } : {}),
      t: now(),
      ...entry,
      ...(within === undefined ? {} : { within }),
      end: null,
      outcome: 'open',
    };
    io.push(item);
    return item;
  };
  const close = (item, outcome) => {
    if (item.outcome !== 'open') return;
    item.outcome = outcome;
    item.end = now();
  };
  const delayOf = (answer, fallback = DEFAULT_DELAY_MS) => answer?.delay ?? fallback;
  // Runs `fn` after `delay` virtual ms; at 0, in a microtask, as an
  // already-settled promise would (a 0 ms timer set inside another timer's
  // callback fires 1 ms later under fake timers). Returns a canceller.
  const later = (fn, delay) => {
    if (delay > 0) {
      const timer = setTimeout(fn, delay);
      return () => clearTimeout(timer);
    }
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) fn();
    });
    return () => { cancelled = true; };
  };

  // A plan: an answer, a list of plans by call index (the last repeats), or
  // { rules: [{ when, then }], else } picked by the request.
  const pick = (plan, ctx) => {
    if (Array.isArray(plan)) return pick(plan[Math.min(ctx.nth, plan.length - 1)], ctx);
    if (plan && typeof plan === 'object' && Array.isArray(plan.rules)) {
      for (const rule of plan.rules) if (matches(rule.when, ctx)) return pick(rule.then, ctx);
      return plan.else === undefined ? null : pick(plan.else, ctx);
    }
    return plan ?? null;
  };
  const matches = (when, ctx) => Object.entries(when).every(([key, value]) => {
    switch (key) {
      case 'method': return ctx.method === value;
      case 'spanOver': return ctx.span !== null && ctx.span > value;
      case 'spanAtMost': return ctx.span !== null && ctx.span <= value;
      case 'toBlock': return ctx.to === value;
      default: throw new Error(`scenario ${scenario.id}: unknown rule condition ${key}`);
    }
  });
  // 'to-473', 'from', 42: a block number relative to the request's filter.
  const blockOf = (expression, ctx) => {
    if (typeof expression === 'number') return expression;
    const match = /^(from|to)([+-]\d+)?$/.exec(expression);
    if (!match) throw new Error(`scenario ${scenario.id}: bad block expression ${expression}`);
    return (match[1] === 'from' ? ctx.from : ctx.to) + Number(match[2] ?? 0);
  };
  // An eth_getLogs answer built from the request's filter: `blocks` names
  // each log's block; `inRange` takes world.logs within [from, to] (the
  // newest `newest` blocks only, when set), then `set` and `omit` change
  // every entry (or only the first, with `first`).
  const logsFor = (spec, ctx) => {
    if (spec.blocks) return spec.blocks.map((expression) => ({ blockNumber: hex(blockOf(expression, ctx)), ...(spec.logIndex ? { logIndex: spec.logIndex } : {}) }));
    const from = spec.newest ? Math.max(ctx.from, ctx.to - spec.newest + 1) : ctx.from;
    const logs = (world.logs ?? []).filter((log) => {
      const block = parseInt(log.blockNumber, 16);
      return block >= from && block <= ctx.to;
    }).map((log) => ({ ...log }));
    for (const [index, log] of logs.entries()) {
      if (spec.first && index > 0) break;
      Object.assign(log, spec.set ?? {});
      for (const key of spec.omit ?? []) delete log[key];
    }
    return logs;
  };

  // JSON-RPC endpoints: world.rpc[url] is a plan of answers. An answer is
  // { result } or { error } (a 200 JSON-RPC body), { result_repeat } (a
  // result string given by a repeat macro), { logs } (built from the
  // filter), { noResult } (a body without one), { body } (raw text, with
  // `status`), { status } (a non-2xx with `text`), { fail } (fetch rejects
  // with that TypeError) or { hang } (no answer until aborted), each with an
  // optional `delay`.
  const rpcCalls = new Map();
  const rpcExchange = (url, init) => {
    const text = String(init.body);
    const parsed = JSON.parse(text);
    const prefix = `{"jsonrpc":"2.0","id":${parsed.id},`;
    if (!text.startsWith(prefix) || parsed.id !== Date.now()) throw new Error(`scenario ${scenario.id}: unexpected JSON-RPC body`);
    const item = record({ kind: 'rpc', url, method: parsed.method, ...textField('body', `{"jsonrpc":"2.0","id":0,${text.slice(prefix.length)}`) });
    if (!URL.canParse(url)) {
      // undici refuses it before any I/O.
      item.answer = { refused: 'Failed to parse URL' };
      close(item, 'refused');
      return Promise.reject(new TypeError(`Failed to parse URL from ${url}`));
    }
    const signal = init.signal;
    if (signal?.aborted) {
      close(item, 'aborted');
      return Promise.reject(signal.reason);
    }
    const nth = rpcCalls.get(url) ?? 0;
    rpcCalls.set(url, nth + 1);
    const filter = parsed.method === 'eth_getLogs' ? parsed.params?.[0] : null;
    const from = typeof filter?.fromBlock === 'string' ? parseInt(filter.fromBlock, 16) : null;
    const to = typeof filter?.toBlock === 'string' ? parseInt(filter.toBlock, 16) : null;
    const ctx = { nth, method: parsed.method, from, to, span: from !== null && to !== null && !Number.isNaN(from + to) ? to - from + 1 : null };
    if (!world.rpc || !Object.hasOwn(world.rpc, url)) violations.push(`undeclared RPC endpoint ${url}`);
    let answer = pick(world.rpc?.[url], ctx);
    if (!answer) {
      violations.push(`unscripted ${parsed.method} at ${url}`);
      answer = { error: { code: -32601, message: 'unscripted' } };
    }
    return new Promise((resolve, reject) => {
      let cancel = () => {};
      const onAbort = () => {
        cancel();
        close(item, 'aborted');
        reject(signal.reason);
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      if (answer.hang) return;
      cancel = later(() => {
        signal?.removeEventListener('abort', onAbort);
        if (answer.fail) {
          item.answer = { fail: answer.fail };
          close(item, 'failed');
          reject(new TypeError(answer.fail));
          return;
        }
        const status = answer.status ?? 200;
        let body;
        if ('body' in answer) body = answer.body;
        else if ('error' in answer) body = JSON.stringify({ jsonrpc: '2.0', id: 1, error: answer.error });
        else if ('result' in answer) body = JSON.stringify({ jsonrpc: '2.0', id: 1, result: answer.result });
        else if (answer.result_repeat) body = JSON.stringify({ jsonrpc: '2.0', id: 1, result: repeated(answer.result_repeat) });
        else if (answer.logs) body = JSON.stringify({ jsonrpc: '2.0', id: 1, result: logsFor(answer.logs, ctx) });
        else if (answer.noResult) body = '{"jsonrpc":"2.0","id":1}';
        else if (answer.status) body = answer.text ?? '';
        else throw new Error(`scenario ${scenario.id}: an answer with nothing to send at ${url}`);
        if (!(status >= 200 && status <= 599)) throw new Error(`scenario ${scenario.id}: status ${status}`);
        item.answer = { status, ...textField('body', body) };
        close(item, 'answered');
        resolve(new Response([204, 205, 304].includes(status) ? null : body, { status, headers: { 'content-type': 'application/json' } }));
      }, delayOf(answer));
    });
  };

  // Blockscout and the hosts its redirects reach: world.blockscout[host] is
  // a plan of answers, each { transfers } (Blockscout's list for the
  // queried address, served newest first, 50 to a page, before the page's
  // block_number/index), { status, headers, page | text } (`page` a JSON
  // value sent as the body), { redirect } (a `status` 3xx, 302 by default,
  // to that location), { fail } or { hang }.
  const blockscoutCalls = new Map();
  const blockscoutPage = (transfers, url, pageSize = 50) => {
    const query = new URL(url).searchParams;
    const block = Number(query.get('block_number'));
    const index = Number(query.get('index'));
    const before = transfers
      .filter((item) => item.block_number < block || (item.block_number === block && item.log_index < index))
      .sort((x, y) => y.block_number - x.block_number || y.log_index - x.log_index);
    const page = before.slice(0, pageSize);
    const last = page.at(-1);
    return {
      items: page,
      next_page_params: before.length > pageSize ? { block_number: last.block_number, index: last.log_index, items_count: pageSize } : null,
    };
  };
  const blockscoutExchange = (url, init) => {
    const host = new URL(url).host;
    const item = record({ kind: 'blockscout', url });
    const signal = init.signal;
    if (signal?.aborted) {
      close(item, 'aborted');
      return Promise.reject(signal.reason);
    }
    const nth = blockscoutCalls.get(host) ?? 0;
    blockscoutCalls.set(host, nth + 1);
    if (!world.blockscout || !Object.hasOwn(world.blockscout, host)) violations.push(`undeclared Blockscout host ${host}`);
    let answer = pick(world.blockscout?.[host], { nth });
    if (!answer) {
      violations.push(`unscripted Blockscout read at ${host}`);
      answer = { status: 404, text: '' };
    }
    return new Promise((resolve, reject) => {
      let cancel = () => {};
      const onAbort = () => {
        cancel();
        close(item, 'aborted');
        reject(signal.reason);
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      if (answer.hang) return;
      cancel = later(() => {
        signal?.removeEventListener('abort', onAbort);
        if (answer.fail) {
          item.answer = { fail: answer.fail };
          close(item, 'failed');
          reject(new TypeError(answer.fail));
          return;
        }
        let status = answer.status ?? 200;
        const headers = { ...(answer.headers ?? {}) };
        let body;
        if (answer.redirect) {
          status = answer.status ?? 302;
          headers.location = answer.redirect;
          body = '';
        } else if (answer.transfers) {
          body = JSON.stringify(blockscoutPage(answer.transfers, url, answer.pageSize));
          headers['content-type'] = 'application/json';
        } else if ('page' in answer) {
          body = JSON.stringify(answer.page);
          headers['content-type'] = 'application/json';
        } else {
          body = answer.text ?? '';
        }
        item.answer = { status, headers: plain(headers, 'headers'), ...textField('body', body) };
        close(item, 'answered');
        resolve(new Response([204, 205, 304].includes(status) ? null : body, { status, headers }));
      }, delayOf(answer));
    });
  };
  // JSON-RPC is POSTed (requestRpcUrl); Blockscout's pages are GETs.
  const fakeFetch = (input, init = {}) => ((init.method ?? 'GET') === 'POST' ? rpcExchange(String(input), init) : blockscoutExchange(String(input), init));

  // DNS for blockscout-logs.js's redirect check: world.dns[host] is
  // { addresses: [{ address, family }] }, { fail: code } or { hang }.
  const dns = {
    promises: {
      lookup: (host, options) => {
        const item = record({ kind: 'dns', host, ...jsonField('options', options) });
        if (!world.dns || !Object.hasOwn(world.dns, host)) violations.push(`undeclared DNS name ${host}`);
        const answer = world.dns?.[host] ?? { fail: 'ENOTFOUND' };
        return new Promise((resolve, reject) => {
          if (answer.hang) return;
          later(() => {
            if (answer.fail) {
              item.answer = { fail: answer.fail };
              close(item, 'failed');
              reject(Object.assign(new Error(`getaddrinfo ${answer.fail} ${host}`), { code: answer.fail }));
              return;
            }
            item.answer = jsonField('addresses', answer.addresses);
            close(item, 'answered');
            resolve(structuredClone(answer.addresses));
          }, delayOf(answer));
        });
      },
    },
  };

  // Myotis: world.myotis[chain] is { ready, status, ops: { [op]: plan } }.
  // An outcome is { payload } (what the manager returns), { throws: class }
  // (MYOTIS_ERRORS, with `reason` or `message` where the class takes one)
  // or { hang }, each with an optional `delay`. `status` is a plan of
  // getStatus() samples (the last repeats); a { throws } sample throws
  // synchronously.
  const myotisCounts = new Map();
  const nthOf = (key) => {
    const n = myotisCounts.get(key) ?? 0;
    myotisCounts.set(key, n + 1);
    return n;
  };
  const myotisChain = (chainId) => world.myotis?.[String(chainId)] ?? {};
  // `make` builds the thrown error; `errorClass` names it in the record.
  const settleOp = (item, outcome, make, errorClass) => new Promise((resolve, reject) => {
    if (outcome.hang) return;
    const settle = () => {
      if (make) {
        const error = make();
        item.answer = { thrown: recordError(error), ...(errorClass ? { class: errorClass } : {}) };
        close(item, 'answered');
        reject(error);
        return;
      }
      item.answer = 'payload' in outcome ? jsonField('payload', outcome.payload) : jsonField('result', outcome.result);
      close(item, 'answered');
      resolve(structuredClone('payload' in outcome ? outcome.payload : outcome.result));
    };
    const delay = delayOf(outcome);
    // At 0 the operation settles as an async function that throws or
    // returns before its first await.
    if (delay === 0) settle();
    else setTimeout(settle, delay);
  });
  const myotisOp = (op, chainId, params) => {
    const item = record({ kind: 'verified-op', host: 'myotis', op, chain: Number(chainId), ...jsonField('params', params) });
    const ops = myotisChain(chainId).ops ?? {};
    let outcome = pick(ops[op], { nth: nthOf(`${chainId} ${op}`) });
    if (!outcome) {
      violations.push(`unscripted Myotis ${op} on chain ${chainId}`);
      outcome = { throws: 'error', message: 'unscripted' };
    }
    if (outcome.throws !== undefined && !MYOTIS_ERRORS[outcome.throws]) throw new Error(`scenario ${scenario.id}: unknown Myotis error ${outcome.throws}`);
    return outcome.throws === undefined
      ? settleOp(item, outcome, null)
      : settleOp(item, outcome, () => MYOTIS_ERRORS[outcome.throws].make(Number(chainId), outcome), outcome.throws);
  };
  const MYOTIS = {
    NETWORKS: new Map([[1, {}], [100, {}]]),
    isReady: (chainId) => myotisChain(chainId).ready === true,
    getStatus: (chainId) => {
      const item = record({ kind: 'myotis-status', chain: Number(chainId) });
      const sample = pick(myotisChain(chainId).status, { nth: nthOf(`${chainId} status`) });
      item.end = item.t;
      item.outcome = 'answered';
      if (sample?.throws) {
        const error = new Error(sample.throws);
        item.answer = { thrown: recordError(error) };
        throw error;
      }
      item.answer = jsonField('status', sample);
      return sample === null ? null : structuredClone(sample);
    },
    getAccount: (address, chainId) => myotisOp('account', chainId, { address }),
    getCode: (address, chainId) => myotisOp('code', chainId, { address }),
    getStorageAt: (address, slot, chainId) => myotisOp('storage', chainId, { address, slot }),
    ethCallTx: ({ chainId, tx, block }) => myotisOp('call_tx', chainId, { tx, block }),
    estimateGas: ({ chainId, tx, block }) => myotisOp('estimate_tx', chainId, { tx, block }),
    feeEstimate: (chainId) => myotisOp('fee', chainId, {}),
    sendRawTransaction: (raw, chainId) => myotisOp('broadcast', chainId, { raw }),
  };

  // Colibri: world.colibri is a plan of outcomes over every request, by
  // `method` and call index: { result }, { error: { message, code?, data? } }
  // or { hang }, each with an optional `delay`.
  let colibriCount = 0;
  const COLIBRI = {
    requestViaColibri: (chainId, method, params, options) => {
      const item = record({ kind: 'verified-op', host: 'colibri', op: 'request', chain: Number(chainId), ...jsonField('params', { method, params, deadline_ms: options?.deadlineMs }) });
      let outcome = pick(world.colibri, { nth: colibriCount++, method });
      if (!outcome) {
        violations.push(`unscripted Colibri ${method}`);
        outcome = { error: { message: 'unscripted' } };
      }
      if (outcome.error) {
        const { message, ...fields } = outcome.error;
        return settleOp(item, outcome, () => Object.assign(new Error(message), fields));
      }
      return settleOp(item, outcome, null);
    },
  };

  // The registry: world.chains[chain] is { network, rpc, prover, sources },
  // with world.sourceList for isUserConfiguredRpc.
  const chainOf = (chainId) => world.chains?.[String(chainId)];
  const REGISTRY = {
    getNetwork: (chainId) => chainOf(chainId)?.network ?? null,
    getEndpoints: (chainId, role) => [...(chainOf(chainId)?.[role] ?? [])],
    getEndpointSources: (chainId) => structuredClone(chainOf(chainId)?.sources ?? []),
    getEndpointSourceList: () => structuredClone(world.sourceList ?? []),
  };

  // A scripted event during a step: Myotis readiness or a registry change.
  const fire = (event) => {
    const item = record({ kind: 'event', event: plain(event, 'event') });
    item.end = item.t;
    item.outcome = 'fired';
    for (const [chain, change] of Object.entries(event.myotis ?? {})) {
      world.myotis ??= {};
      world.myotis[chain] = { ...(world.myotis[chain] ?? {}), ...structuredClone(change) };
    }
    for (const [chain, change] of Object.entries(event.chains ?? {})) {
      world.chains ??= {};
      world.chains[chain] = { ...(world.chains[chain] ?? {}), ...structuredClone(change) };
    }
  };

  const undo = [];
  try {
    const originalFetch = globalThis.fetch;
    undo.push(() => { globalThis.fetch = originalFetch; });
    globalThis.fetch = fakeFetch;
    clock = FakeTimers.install({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'], now: EPOCH });
    undo.push(() => clock.uninstall());
    const loaded = loadReference(checkout, {
      './network-registry': REGISTRY,
      '../myotis/myotis-manager': MYOTIS,
      '../ens/colibri-resolver': COLIBRI,
      '../logger': { verbose() {}, info() {}, warn() {}, error() {}, debug() {} },
    }, dns);
    undo.push(loaded.restore);
    const { router, blockscout, bridge } = loaded;
    // A Blockscout read (fetchBlockscoutTransferLogs, as the router calls
    // it through the module's exports) and each page it fetches.
    const fetchTransfers = blockscout.fetchBlockscoutTransferLogs;
    blockscout.fetchBlockscoutTransferLogs = function observedRead(filter, toBlock, options) {
      const item = record({ kind: 'blockscout-read', ...jsonField('filter', filter), to_block: toBlock, timeout_ms: options?.timeoutMs });
      return withinStore.run(item.id, () => fetchTransfers(filter, toBlock, options)).then(
        (list) => {
          item.answer = jsonField('transfers', list);
          close(item, 'answered');
          return list;
        },
        (error) => {
          item.answer = { thrown: recordError(error) };
          close(item, 'failed');
          throw error;
        }
      );
    };
    blockscout.__observePages((fetchPage) => function observedPage(url, options) {
      const item = record({ kind: 'blockscout-page', url, budget_ms: options.deadline - Date.now() });
      return withinStore.run(item.id, () => fetchPage(url, options)).then(
        (body) => {
          // The page is the JSON of its last hop's body.
          item.answer = { hop: io.filter((entry) => entry.kind === 'blockscout' && entry.within === item.id).at(-1).id };
          close(item, 'answered');
          return body;
        },
        (error) => {
          item.answer = { thrown: recordError(error) };
          close(item, 'failed');
          throw error;
        }
      );
    });
    const RANKERS = { request: () => router.ERROR_RANK.REQUEST, ant: bridge.rankLogScanError };
    const CAPS = { ant: bridge.logScanRangeCap };

    // A call's options as the router takes them. `profile: 'ant_scan'` is
    // the Ant bridge's eth_getLogs options; `options` holds router options
    // no production caller passes alone (named functions included).
    const optionsOf = (call, signal) => {
      const options = {};
      if (call.include_trust) options.includeTrust = true;
      if (call.origin !== undefined) options.routingContext = { origin: call.origin };
      if (call.background) options.background = true;
      if (call.profile === 'ant_scan') Object.assign(options, bridge.LOG_SCAN_ROUTER_OPTIONS);
      else if (call.profile !== undefined) throw new Error(`scenario ${scenario.id}: unknown profile ${call.profile}`);
      for (const [key, value] of Object.entries(call.options ?? {})) {
        if (key === 'rankError') options.rankError = RANKERS[value];
        else if (key === 'rangeCapOf') options.rangeCapOf = CAPS[value];
        else if (['directTimeoutMs', 'quorumTimeoutMs', 'excludeSources', 'includeSources'].includes(key)) options[key] = structuredClone(value);
        else throw new Error(`scenario ${scenario.id}: unknown option ${key}`);
      }
      if (signal) options.signal = signal;
      return options;
    };
    // Starts a call now. The Ant bridge always passes a signal; others get
    // one when the call aborts (`abort_at`, after its start).
    const start = (call, owner) => {
      call.started = now();
      return callStore.run(owner, () => {
        const controller = call.abort_at !== undefined || call.signal ? new AbortController() : null;
        if (call.abort_at !== undefined) setTimeout(() => controller.abort(), call.abort_at);
        return Promise.resolve().then(() => {
          switch (call.fn) {
            case 'request':
              return router.request(call.chain, call.method, structuredClone(call.params), optionsOf(call, controller?.signal));
            case 'getFeeQuote':
              return router.getFeeQuote(call.chain);
            case 'broadcastRawTransaction':
              return router.broadcastRawTransaction(call.chain, call.raw, controller ? { signal: controller.signal } : undefined);
            default:
              throw new Error(`scenario ${scenario.id}: unknown call ${call.fn}`);
          }
        });
      });
    };
    // Advances virtual time event by event until every promise settles, so a
    // settlement time is exact and what follows starts from it.
    const settleAll = async (promises) => {
      const results = promises.map(() => null);
      promises.forEach((promise, i) => promise.then(
        (value) => { results[i] = { ...recordValue(value), settled: now() }; },
        (error) => { results[i] = { thrown: recordError(error), settled: now() }; }
      ));
      const done = () => results.every(Boolean);
      const limit = Date.now() + MAX_STEP_MS;
      await clock.tickAsync(0);
      while (!done() && clock.countTimers() > 0 && Date.now() < limit) await clock.nextAsync();
      for (let i = 0; i < 10 && !done(); i += 1) await new Promise((resolve) => setImmediate(resolve));
      return results.map((result) => result ?? { pending: true });
    };
    const stateOf = () => {
      const at = (value) => (value > 0 ? value - EPOCH : value);
      const raw = router.__state();
      const state = {
        adaptive: raw.adaptive.map(([key, value]) => [key, { ...value, openUntil: at(value.openUntil) }]),
        // A chain with nothing in flight and nothing waiting is as good as absent.
        myotis_slots: raw.myotis_slots.filter(([, slots]) => slots.in_flight > 0 || slots.waiting > 0),
        colibri_in_flight: raw.colibri_in_flight,
        colibri_routes: raw.colibri_routes,
        log_range: raw.log_range.map(([key, value]) => [key, {
          ...value, capUntil: at(value.capUntil), slowUntil: at(value.slowUntil), coolUntil: at(value.coolUntil),
        }]),
        log_index_cool_until: raw.log_index_cool_until.map(([key, value]) => [key, at(value)]),
        log_index_pair_cool_until: raw.log_index_pair_cool_until.map(([key, value]) => [key, at(value)]),
      };
      // Empty tables are left out.
      return plain(Object.fromEntries(Object.entries(state).filter(([, value]) => (Array.isArray(value) ? value.length > 0 : value > 0))), 'state');
    };

    const steps = [];
    for (const [index, definition] of scenario.steps.entries()) {
      const step = structuredClone(definition);
      if (step.after) await clock.tickAsync(step.after);
      stepIndex = index;
      if (step.world) {
        for (const [key, value] of Object.entries(step.world)) world[key] = structuredClone(value);
      }
      const at = now();
      for (const event of step.events ?? []) setTimeout(() => fire(event), event.at);
      let results;
      if (step.driver) {
        // A caller's loop (Ant's log scans): each call starts when the one
        // before it settles, and its outcome picks the next.
        ({ calls: step.calls, results } = await drive(step.driver, async (call, i) => {
          let error = null;
          const [result] = await settleAll([start(call, { step: index, call: i }).catch((caught) => {
            error = caught;
            throw caught;
          })]);
          return { result, error };
        }, bridge));
      } else {
        const calls = step.calls;
        results = await settleAll(calls.map((call, i) => {
          const owner = { step: index, call: i };
          return call.at ? new Promise((resolve) => setTimeout(resolve, call.at)).then(() => start(call, owner)) : start(call, owner);
        }));
      }
      // The settle times the ported test asserts (`expect_settle_ms`, or a
      // bound, `expect_settle_max_ms`), after the call's start: a fixture
      // that drifts from its source fails the generation.
      step.calls.forEach((call, i) => {
        const took = results[i].settled === undefined ? null : results[i].settled - call.started;
        if (call.expect_settle_ms !== undefined && took !== call.expect_settle_ms) {
          expectations.push(`step ${index} call ${i} settled after ${took} ms, not ${call.expect_settle_ms}`);
        }
        if (call.expect_settle_max_ms !== undefined && !(took !== null && took <= call.expect_settle_max_ms)) {
          expectations.push(`step ${index} call ${i} settled after ${took} ms, over ${call.expect_settle_max_ms}`);
        }
      });
      steps.push({ at, ...recordStep(step), results, state: stateOf() });
    }
    // Let stragglers finish, so a late answer nobody waits for is recorded
    // as answered rather than left open.
    const limit = Date.now() + MAX_STEP_MS;
    while (clock.countTimers() > 0 && Date.now() < limit) await clock.nextAsync();
    if (violations.length > 0) throw new Error(`scenario ${scenario.id}: unscripted I/O: ${[...new Set(violations)].join('; ')}`);
    if (expectations.length > 0) throw new Error(`scenario ${scenario.id}: ${expectations.join('; ')}`);
    return {
      id: scenario.id,
      from: scenario.from,
      ...(scenario.deviation ? { deviation: scenario.deviation } : {}),
      world: plain(scenario.world, 'world'),
      steps,
      io: plain(io, 'io'),
    };
  } finally {
    for (const fn of undo.reverse()) fn();
  }
}

/**
 * Ant's own scan loops, run over the bridge's replies (antErrorReply,
 * antShrinksLogScanOn): `halve` asks eth_getLogs over `span` blocks ending
 * at `head`, halving the span on a reply Ant shrinks on, until an answer or
 * another failure (ant-log-scan-routing.test.js's antScan); `wallet` scans
 * [from, to] in windows, halving on such a reply and doubling after an
 * answer (Ant v0.5.59's scan_logs_with, ant-log-index-routing.test.js's
 * antWalletScan).
 */
async function drive(driver, run, bridge) {
  const calls = [];
  const results = [];
  const ask = async (window) => {
    // Ant's filter, its block range in place: { address, fromBlock, toBlock, topics }.
    const { address, topics } = driver.filter ?? {};
    const filter = { ...(address === undefined ? {} : { address }), ...window, ...(topics === undefined ? {} : { topics }) };
    const call = {
      fn: 'request', chain: 100, method: 'eth_getLogs', params: [filter], background: true, profile: 'ant_scan', signal: true,
      ...(driver.expect_settle_ms === undefined ? {} : { expect_settle_ms: driver.expect_settle_ms }),
    };
    calls.push(call);
    const { result, error } = await run(call, calls.length - 1);
    results.push(result);
    if (result.value) return { answered: true };
    if (!error) throw new Error('an Ant scan request never settled');
    return { answered: false, shrinks: bridge.antShrinksLogScanOn(bridge.antErrorReply('eth_getLogs', error).message) };
  };
  if (driver.kind === 'halve') {
    for (let span = driver.span; span >= 1; span = Math.floor(span / 2)) {
      const got = await ask({ fromBlock: hex(driver.head - span + 1), toBlock: hex(driver.head) });
      if (got.answered || !got.shrinks) break;
    }
  } else if (driver.kind === 'wallet') {
    let start = driver.from;
    let chunk = Math.min(driver.chunk, driver.to - driver.from + 1);
    while (start <= driver.to && calls.length < driver.maxRequests) {
      const end = Math.min(start + chunk - 1, driver.to);
      const got = await ask({ fromBlock: hex(start), toBlock: hex(end) });
      if (got.answered) {
        start = end + 1;
        chunk = Math.min(chunk * 2, driver.chunk);
      } else if (got.shrinks && chunk > 1) {
        chunk = Math.max(1, Math.floor(chunk / 2));
      } else {
        break;
      }
    }
  } else {
    throw new Error(`unknown driver ${driver.kind}`);
  }
  return { calls, results };
}

// ---------------------------------------------------------------------------
// Scenario building blocks. A scenario is { id, from, world, steps }: `from`
// names the test it ports (file:line at the pinned commit) or the design
// case it pins. A step is { after?, world?, events?, calls } or
// { after?, world?, driver }: `after` advances virtual time first (timers
// fire), `world` replaces those top-level world keys, `events` fire `at` ms
// into the step. A call is { fn, chain, method, params, include_trust?,
// origin?, background?, profile?, options?, signal?, at?, abort_at? }:
// `profile: 'ant_scan'` is the Ant bridge's eth_getLogs options, `options`
// router options no production caller passes on their own, `signal` an
// AbortSignal passed though never aborted (the bridge always passes one),
// `at` a start that many ms into the step, `abort_at` an abort that many ms
// after the call starts.

const RPC = 'https://rpc.example';
const PROVER = 'https://prover.example';
const url = (name) => `https://${name}.example`;
const [A, B, C, D] = ['a', 'b', 'c', 'd'].map(url);
const MYOTIS_BLOCK = 25_684_159;

const req = (chain, method, params, extra = {}) => ({ fn: 'request', chain, method, params, ...extra });
const fee = (chain, extra = {}) => ({ fn: 'getFeeQuote', chain, ...extra });
const send = (chain, raw, extra = {}) => ({ fn: 'broadcastRawTransaction', chain, raw, ...extra });
/** A step: a step object as it is, a list of calls, or one call. */
const stepOf = (item) => (Array.isArray(item) ? { calls: item } : item.calls || item.driver ? item : { calls: [item] });
const scenario = (id, from, world, ...steps) => ({ id, from, world, steps: steps.map(stepOf) });
/** A chain's registry entry. */
const chainEntry = (network, rpc = [], prover = [], extra = {}) => ({ network, rpc, prover, ...extra });
/** Myotis ready on `chain` with these operations. */
const myotisOn = (chain, ops = {}, extra = {}) => ({ [chain]: { ready: true, status: { optimisticBlockNumber: MYOTIS_BLOCK }, ops, ...extra } });
const ok = (result, delay) => ({ result, ...(delay === undefined ? {} : { delay }) });
/** A call option: the ported test says the call settles `ms` after it starts. */
const settles = (ms) => ({ expect_settle_ms: ms });
const rpcError = (code, message, extra = {}) => ({ error: { code, message, ...extra } });

// chain-data-router.test.js's defaults: chains 1 and 100 both answer the
// same registry, one RPC endpoint, one prover, Myotis ready.
const ROUTER_NETWORK = {
  access: { readOrder: ['myotis', 'colibri', 'direct'], broadcastOrder: ['myotis', 'direct'] },
  quorum: { k: 3, m: 2, timeoutMs: 1000 },
};
const ACCOUNT = { verifyMethod: 'headerChain', exists: true, balanceWei: '42', nonce: 3 };
const routerWorld = ({ network = ROUTER_NETWORK, endpoints = [RPC], prover = [PROVER], myotis = {}, ...rest } = {}) => ({
  chains: { 1: chainEntry(network, endpoints, prover), 100: chainEntry(network, endpoints, prover) },
  myotis: { ...myotisOn(1), ...myotisOn(100), ...myotis },
  ...rest,
});
const T = (line) => `chain-data-router.test.js:${line}`;

/** chain-data-router.test.js, describe 'chain-data-router'. */
function routerScenarios(tx) {
  const call = (data) => [{ to: '0xabc', data }, 'latest'];
  const fullTx = {
    from: '0x1111111111111111111111111111111111111111',
    to: '0x2222222222222222222222222222222222222222',
    data: '0x3e12cc2e',
    value: '0x1',
    gas: '0x5208',
    maxFeePerGas: '0x3b9aca00',
    maxPriorityFeePerGas: '0x1',
    nonce: '0x7',
    chainId: '0x64',
    type: '0x4',
    accessList: [{ address: '0x3333333333333333333333333333333333333333', storageKeys: [] }],
    authorizationList: [{
      address: '0x05ae73c5925d843864ae6f261f3175de2ebcd963',
      nonce: '0x0', chainId: '0x64', yParity: '0x1', r: '0x9a3b', s: '0x0c5d',
    }],
  };
  const swap = { origin: 'https://swap.example' };
  const colibriFirst = { access: { readOrder: ['colibri', 'direct'] }, quorum: { timeoutMs: 5000 } };
  const myotisFirst = { access: { readOrder: ['myotis', 'direct'] }, quorum: { timeoutMs: 5000 } };
  const target = (index) => `0x${String(index + 1).padStart(40, '0')}`;
  const ABC = [A, B, C];
  const quorumOnly = { access: { readOrder: ['quorum'] }, quorum: { k: 3, m: 2, timeoutMs: 5000 } };
  const quorumDirect = { access: { readOrder: ['quorum', 'direct'] }, quorum: { k: 3, m: 2, timeoutMs: 5000 } };
  const outOfGas = rpcError(-32000, 'Out of gas');
  return [
    scenario('router-myotis-balance', T(79), routerWorld({ myotis: myotisOn(100, { account: { payload: ACCOUNT } }) }),
      req(100, 'eth_getBalance', ['0xabc', 'latest'])),
    scenario('router-myotis-account-unverified', T(93), routerWorld({
      myotis: myotisOn(1, { account: { payload: { verifyMethod: null, failReason: 'beaconNotSynced', exists: true, balanceWei: '42', nonce: 3 } } }),
      colibri: ok('0x7'),
    }), req(1, 'eth_getBalance', ['0xabc', 'latest']), req(1, 'eth_getTransactionCount', ['0xabc', 'latest'])),
    scenario('router-myotis-account-absent', T(101), routerWorld({
      myotis: myotisOn(1, { account: { payload: { verifyMethod: 'headerChain', exists: false, balanceWei: null, nonce: -1 } } }),
    }), req(1, 'eth_getBalance', ['0xabc', 'latest']), req(1, 'eth_getTransactionCount', ['0xabc', 'latest'])),
    scenario('router-myotis-code', T(110), routerWorld({
      myotis: myotisOn(1, { code: [{ payload: { verifyMethod: 'headerChain', codeHex: '0x6080ABCD' } }, { payload: { verifyMethod: 'headerChain', codeHex: '0x' } }] }),
    }), req(1, 'eth_getCode', ['0xabc', 'latest']), req(1, 'eth_getCode', ['0xabc'])),
    scenario('router-myotis-code-not-served', T(120), routerWorld({
      myotis: myotisOn(1, { code: [
        { payload: { verifyMethod: null, failReason: 'noPeers', codeHex: '0x60' } },
        { payload: { verifyMethod: 'headerChain', codeHex: '0x6' } },
        { payload: { verifyMethod: 'headerChain', codeHex: null } },
      ] }),
      colibri: ok('0x60'),
    }), req(1, 'eth_getCode', ['0xabc', 'latest']), req(1, 'eth_getCode', ['0xabc', 'latest']), req(1, 'eth_getCode', ['0xabc', 'latest'])),
    scenario('router-myotis-storage', T(130), routerWorld({
      myotis: myotisOn(100, { storage: [{ payload: { verifyMethod: 'headerChain', valueHex: '0x2A' } }, { payload: { verifyMethod: 'headerChain', valueHex: null } }] }),
    }), req(100, 'eth_getStorageAt', ['0xabc', '0x0', 'latest']), req(100, 'eth_getStorageAt', ['0xabc', '0x0'])),
    scenario('router-myotis-tagged-state-reads', T(142), routerWorld({ colibri: ok('0x') }),
      req(1, 'eth_getCode', ['0xabc', 'finalized']), req(1, 'eth_getStorageAt', ['0xabc', '0x0', '0x10'])),
    scenario('router-myotis-revert-final', T(152), routerWorld({
      myotis: myotisOn(1, {
        call_tx: { payload: { status: 'revert', dataHex: '0x08c379a0abcd' } },
        estimate_tx: { payload: { status: 'revert', dataHex: '0x08c379a0abcd' } },
      }),
    }), req(1, 'eth_call', [{ to: '0xabc' }]), req(1, 'eth_estimateGas', [{ to: '0xabc' }])),
    scenario('router-myotis-unavailable-shapes', T(161), routerWorld({
      myotis: myotisOn(1, { call_tx: [{ payload: { status: 'unavailable', reason: 'cancelled' } }, { payload: { error: 'deadline exceeded' } }] }),
      colibri: ok('0xfallback'),
    }), req(1, 'eth_call', [{ to: '0xabc' }]), req(1, 'eth_call', [{ to: '0xabc' }])),
    scenario('router-myotis-broadcast-rejected', T(169), routerWorld({
      myotis: myotisOn(1, { broadcast: { throws: 'rejected', reason: 'nonce too low: next nonce 5, tx nonce 4' } }),
    }), send(1, tx.mainnet.raw)),
    scenario('router-myotis-broadcast-in-band-failure', T(179), routerWorld({
      myotis: myotisOn(1, { broadcast: { payload: { error: 'connection lost' } } }),
    }), send(1, tx.mainnet.raw)),
    scenario('router-pending-nonce-to-colibri', T(186), routerWorld({
      myotis: myotisOn(100, { account: { payload: { verifyMethod: 'headerChain', exists: true, nonce: 3 } } }),
      colibri: ok('0x5'),
    }), req(100, 'eth_getTransactionCount', ['0xabc', 'pending'])),
    scenario('router-historical-balance-to-colibri', T(204), routerWorld({
      myotis: myotisOn(100, { account: { payload: { verifyMethod: 'headerChain', exists: true, balanceWei: '42' } } }),
      colibri: ok('0x1'),
    }), req(100, 'eth_getBalance', ['0xabc', '0x1234'])),
    scenario('router-tagged-estimate-to-colibri', T(215), routerWorld({ colibri: ok('0x5208') }),
      req(100, 'eth_estimateGas', [{ to: '0xabc' }, 'pending'])),
    scenario('router-historical-call-to-colibri', T(225), routerWorld({ colibri: ok('0xhistoric') }),
      req(100, 'eth_call', [{ to: '0xabc', data: '0x70a08231' }, '0x10d4f00'])),
    scenario('router-state-overrides-to-colibri', T(235), routerWorld({ colibri: ok('0xsimulated') }),
      req(100, 'eth_call', [{ to: '0xabc', data: '0x70a08231' }, 'latest', { '0xabc': { balance: '0x1' } }])),
    scenario('router-myotis-whole-transaction', T(252), routerWorld({
      myotis: myotisOn(100, { call_tx: { payload: { status: 'ok', resultHex: '0x2a' } }, estimate_tx: { payload: { status: 'ok', gas: 61000 } } }),
    }), req(100, 'eth_call', [fullTx, 'latest']), req(100, 'eth_estimateGas', [fullTx])),
    ...['eth_call', 'eth_estimateGas'].map((method) => scenario(
      `router-myotis-invalid-params-${method === 'eth_call' ? 'call' : 'estimate'}`, T(287), routerWorld({
        myotis: myotisOn(100, { [method === 'eth_call' ? 'call_tx' : 'estimate_tx']: [
          { payload: { error: 'invalid transaction object: chainId 1 does not match this node\'s chain (100)', code: -32602 } },
          { payload: { status: 'ok', resultHex: '0x2a', gas: 21000 } },
        ] }),
      }), req(100, method, [{ to: '0xabc', chainId: '0x1' }]), req(100, method, [{ to: '0xabc' }]))),
    scenario('router-myotis-invalid-params-account', T(308), routerWorld({
      myotis: myotisOn(1, { account: { payload: { error: 'invalid address (expected 20-byte hex)', code: -32602 } } }),
    }), req(1, 'eth_getBalance', ['0xnot-an-address', 'latest'])),
    scenario('router-myotis-capability-refusals', T(320), routerWorld({
      myotis: myotisOn(1, { call_tx: [
        'block 23000000 carries an EIP-7843 slot number, so it is an Amsterdam block, but this build\'s fork table puts it before Amsterdam; refusing to run it under the older fork\'s rules',
        'block 23000000 is an Amsterdam block but its header has no slot number (EIP-7843); refusing to run SLOTNUM against a made-up value',
        'the call ran out of this node\'s 30000000-gas call budget, below the 50000000 gas it allows',
      ].map((error) => ({ payload: { error, code: -32602 } })) }),
      colibri: ok('0xelsewhere'),
    }), req(1, 'eth_call', [{ to: '0xabc' }]), req(1, 'eth_call', [{ to: '0xabc' }]), req(1, 'eth_call', [{ to: '0xabc' }])),
    scenario('router-myotis-blob-transaction', T(332), routerWorld({
      myotis: myotisOn(1, { estimate_tx: { payload: { status: 'ok', gas: 21000 } } }),
      colibri: ok('0x5208'),
    }), req(1, 'eth_estimateGas', [{ to: '0xabc', blobVersionedHashes: ['0x01' + '00'.repeat(31)], maxFeePerBlobGas: '0x1' }]),
    req(1, 'eth_estimateGas', [{ to: '0xabc', blobVersionedHashes: [] }])),
    scenario('router-myotis-infeasible', T(345), routerWorld({
      myotis: myotisOn(1, {
        estimate_tx: [
          { payload: { status: 'infeasible', reason: 'gas required exceeds allowance (21000)' } },
          { payload: { status: 'infeasible', reason: 'insufficient funds for transfer' } },
        ],
        call_tx: [
          { payload: { status: 'infeasible', reason: 'err: insufficient funds for gas * price + value: address 0x1111111111111111111111111111111111111111 have 0 want 21000 (supplied gas 21000)' } },
          { payload: { status: 'infeasible', reason: 'out of gas' } },
        ],
      }),
    }), ...['eth_estimateGas', 'eth_estimateGas', 'eth_call', 'eth_call'].map((method) => req(1, method, [{ to: '0xabc', gas: '0x5208' }]))),
    scenario('router-myotis-head-state-call', T(361), routerWorld({ myotis: myotisOn(100, { call_tx: { payload: { resultHex: '0x2a' } } }) }),
      req(100, 'eth_call', [{ to: '0xabc', data: '0x70a08231' }, 'latest'])),
    scenario('router-myotis-trust', T(373), routerWorld({ myotis: myotisOn(1, { call_tx: { payload: { resultHex: '0x2a' } } }) }),
      req(1, 'eth_call', [{ to: '0xabc', data: '0x70a08231' }, 'latest'], { include_trust: true })),
    scenario('router-myotis-trust-head-moved', T(401), routerWorld({
      myotis: myotisOn(1, { call_tx: { payload: { resultHex: '0x2a' } } }, { status: [{ optimisticBlockNumber: MYOTIS_BLOCK }, { optimisticBlockNumber: MYOTIS_BLOCK + 1 }] }),
    }), req(1, 'eth_call', [{ to: '0xabc', data: '0x70a08231' }, 'latest'], { include_trust: true })),
    scenario('router-myotis-no-payload-to-colibri', T(417), routerWorld({
      myotis: myotisOn(100, { code: { payload: null } }),
      colibri: ok('0x6000'),
    }), req(100, 'eth_getCode', ['0xabc', 'latest'])),
    scenario('router-colibri-deadline', T(433), routerWorld({
      network: { access: { readOrder: ['colibri', 'direct'] }, quorum: { timeoutMs: 7000 } },
      colibri: ok('0x1'),
    }), req(100, 'eth_call', [{ to: '0xabc', data: '0x' }, 'latest']), req(100, 'eth_call', [{ to: '0xabc', data: '0x01' }, 'latest'], { origin: 'https://app.example' })),
    scenario('router-myotis-broadcast-uncertain', T(451), routerWorld({ myotis: myotisOn(100, { broadcast: { throws: 'uncertain_dispatched' } }) }),
      send(100, tx.gnosis.raw)),
    scenario('router-myotis-broadcast', T(460), routerWorld({ myotis: myotisOn(100, { broadcast: { payload: { txHash: tx.gnosis.hash } } }) }),
      send(100, tx.gnosis.raw)),
    scenario('router-fee-quote-myotis', T(470), routerWorld({ myotis: myotisOn(100, { fee: { payload: { gasPriceWei: '100', maxPriorityFeePerGasWei: '2' } } }) }),
      fee(100)),
    scenario('router-fee-quote-inconsistent', T(491), routerWorld({ myotis: myotisOn(100, { fee: { payload: { gasPriceWei: '3727', maxPriorityFeePerGasWei: '1000000000' } } }) }),
      fee(100)),
    scenario('router-fee-quote-direct-same-endpoint', T(506), routerWorld({
      network: { access: { readOrder: ['direct'] }, quorum: { timeoutMs: 1000 } },
      endpoints: [url('primary'), url('secondary')],
      rpc: { [url('primary')]: { rules: [{ when: { method: 'eth_gasPrice' }, then: ok('0xebd') }], else: ok('0x1') }, [url('secondary')]: ok('0x1') },
    }), fee(100)),
    scenario('router-filter-on-direct', T(539), routerWorld({ rpc: { [RPC]: ok('0xfilter') } }),
      req(1, 'eth_newFilter', [{ address: '0xabc' }])),
    scenario('router-quorum-hex-quantities', T(554), {
      chains: { 1: chainEntry({ access: { readOrder: ['quorum', 'direct'] }, quorum: { k: 2, m: 2, timeoutMs: 1000 } }, [A, B]) },
      myotis: { 1: { ready: false } },
      rpc: { [A]: ok('0x5208'), [B]: ok('0x5208') },
    }, req(1, 'eth_estimateGas', [{ from: '0xabc', to: '0xdef', value: '1000000000000000000' }])),
    scenario('router-direct-hex-quantities', T(587), routerWorld({
      network: { access: { readOrder: ['direct'] }, quorum: { timeoutMs: 1000 } },
      myotis: { 1: { ready: false } },
      rpc: { [RPC]: ok('0x1') },
    }), req(1, 'eth_call', [{ to: '0xabc', value: '10', gas: '21000' }, 'latest'])),
    scenario('router-myotis-estimate-hex', T(603), routerWorld({ myotis: myotisOn(100, { estimate_tx: { payload: { status: 'ok', gas: 21000 } } }) }),
      req(100, 'eth_estimateGas', [{ to: '0xabc', value: '1000000000000000000' }])),
    ...[['numbers', { chainId: 100, type: 2 }], ['decimal-strings', { chainId: '100', type: '2' }], ['zero-padded-hex', { chainId: '0x064', type: '0x02' }]]
      .map(([label, fields]) => scenario(`router-myotis-chain-id-type-${label}`, T(618), routerWorld({
        myotis: myotisOn(100, { call_tx: { payload: { status: 'ok', resultHex: '0x2a' } }, estimate_tx: { payload: { status: 'ok', gas: 21000 } } }),
      }), req(100, 'eth_call', [{ to: '0xabc', data: '0x70a08231', ...fields }, 'latest']), req(100, 'eth_estimateGas', [{ to: '0xabc', ...fields }]))),
    scenario('router-myotis-legacy-type-zero', T(640), routerWorld({ myotis: myotisOn(1, { call_tx: { payload: { status: 'ok', resultHex: '0x2a' } } }) }),
      req(1, 'eth_call', [{ to: '0xabc', type: 0 }, 'latest'])),
    scenario('router-myotis-gas-refused', T(649), routerWorld({
      myotis: myotisOn(1, { estimate_tx: ['21000', '0x5208', 21000.5, 2 ** 53, -1].map((gas) => ({ payload: { status: 'ok', gas } })) }),
      colibri: ok('0x5208'),
    }), ...Array.from({ length: 5 }, () => req(1, 'eth_estimateGas', [{ to: '0xabc' }]))),
    scenario('router-myotis-input-alias-call', T(665), routerWorld({ myotis: myotisOn(1, { call_tx: { payload: { resultHex: '0x2a' } } }) }),
      req(1, 'eth_call', [{ to: '0xabc', input: '0x70a08231' }, 'latest'])),
    scenario('router-myotis-input-alias-estimate', T(676), routerWorld({ myotis: myotisOn(1, { estimate_tx: { payload: { status: 'ok', gas: 54000 } } }) }),
      req(1, 'eth_estimateGas', [{ to: '0xabc', input: '0xa9059cbb' }])),
    scenario('router-input-alias-rpc', T(687), routerWorld({
      network: { access: { readOrder: ['direct'] }, quorum: { timeoutMs: 1000 } },
      myotis: { 1: { ready: false } },
      rpc: { [RPC]: ok('0x1') },
    }), req(1, 'eth_call', [{ to: '0xabc', input: '0x70a08231' }, 'latest'])),
    scenario('router-myotis-input-over-empty-data', T(702), routerWorld({ myotis: myotisOn(1, { call_tx: { payload: { resultHex: '0x2a' } } }) }),
      req(1, 'eth_call', [{ to: '0xabc', data: '0x', input: '0x70a08231' }, 'latest'])),
    scenario('router-myotis-data-input-conflict', T(715), routerWorld({
      myotis: myotisOn(100, { call_tx: { payload: { error: "invalid transaction object: both 'data' and 'input' are set and not equal; use 'input'", code: -32602 } } }),
      colibri: ok('0xlenient'),
    }), req(100, 'eth_call', [{ to: '0xabc', data: '0x70a08231', input: '0xa9059cbb' }, 'latest'])),
    scenario('router-broadcast-direct-when-myotis-not-ready', T(734), routerWorld({
      myotis: { 1: { ready: false } },
      rpc: { [RPC]: ok(tx.mainnet.hash) },
    }), send(1, tx.mainnet.raw)),
    scenario('router-final-rpc-error-kept', T(751), routerWorld({
      network: { access: { readOrder: ['direct'] }, quorum: { timeoutMs: 1000 } },
      rpc: { [RPC]: rpcError(3, 'execution reverted', { data: '0x08c379a0' }) },
    }), req(1, 'eth_call', [{ to: '0xabc', data: '0xdeadbeef' }, 'latest'])),
    scenario('router-custom-chain-default-order', T(772), {
      chains: { 777: chainEntry({ access: {}, quorum: { timeoutMs: 1000 } }, [RPC]) },
      rpc: { [RPC]: ok('0x6000') },
    }, req(777, 'eth_getCode', ['0xabc', 'latest'])),
    scenario('router-colibri-interactive-bypass', T(789), routerWorld({
      network: colibriFirst,
      colibri: { hang: true },
      rpc: { [RPC]: ok('0xrpc', 0) },
    }), req(1, 'eth_call', call('0x1234'), { ...swap, ...settles(2000) }), req(1, 'eth_call', call('0x1234'), { ...swap, ...settles(0) })),
    scenario('router-excluded-source', T(814), routerWorld({
      network: colibriFirst,
      colibri: ok('0xcolibri'),
      rpc: { [RPC]: ok('0xrpc') },
    }), req(100, 'eth_call', [{}, 'latest'], { options: { excludeSources: ['colibri'] } }), req(100, 'eth_call', [{}, 'latest'])),
    scenario('router-getlogs-never-colibri', T(839), routerWorld({
      network: colibriFirst,
      colibri: ok(['0xtruncated']),
      rpc: { [RPC]: ok(['0xlog']) },
    }), req(100, 'eth_getLogs', [{ fromBlock: '0x0', toBlock: 'latest' }], { origin: 'https://app.example' }), req(100, 'eth_getLogs', [{}])),
    scenario('router-exclusion-named-no-source', T(861), routerWorld({ network: { access: { readOrder: ['colibri'] }, quorum: { timeoutMs: 5000 } } }),
      req(100, 'eth_getLogs', [{}]), req(100, 'eth_call', [{}, 'latest'], { options: { excludeSources: ['colibri'] } })),
    scenario('router-exclusion-named-all-failed', T(879), routerWorld({
      network: { access: { readOrder: ['colibri', 'myotis'] }, quorum: { timeoutMs: 5000 } },
      myotis: { 100: { ready: false } },
    }), req(100, 'eth_getLogs', [{}])),
    scenario('router-myotis-interactive-bypass', T(891), routerWorld({
      network: myotisFirst,
      myotis: myotisOn(1, { call_tx: { payload: { resultHex: '0xlate' }, delay: 5000 } }),
      rpc: { [RPC]: ok('0xrpc', 0) },
    }), req(1, 'eth_call', [{ to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', data: '0x1234' }, 'latest'], { ...swap, ...settles(2000) }),
    req(1, 'eth_call', [{ to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', data: '0x1234' }, 'latest'], { ...swap, ...settles(0) })),
    scenario('router-myotis-noncancellable-no-starvation', T(923), routerWorld({
      network: myotisFirst,
      myotis: myotisOn(1, { call_tx: { hang: true } }),
      rpc: { [RPC]: ok('0xrpc', 0) },
    }), Array.from({ length: 6 }, (_, i) => req(1, 'eth_call', [{ to: target(i), data: '0x1234' }, 'latest'], { ...swap, ...settles(2000) }))),
    scenario('router-myotis-late-read-keeps-slot', T(951), routerWorld({
      network: myotisFirst,
      myotis: myotisOn(1, { call_tx: [{ payload: { resultHex: '0xlate' }, delay: 2100 }, { payload: { resultHex: '0xverified' } }] }),
      rpc: { [RPC]: ok('0xrpc', 0) },
    }), req(1, 'eth_call', [{ to: '0x1111111111111111111111111111111111111111', data: '0x1234' }, 'latest'], { ...swap, ...settles(2000) }),
    req(1, 'eth_call', [{ to: '0x2222222222222222222222222222222222222222', data: '0x1234' }, 'latest'], { ...swap, ...settles(100) })),
    scenario('router-myotis-serialized', T(983), routerWorld({
      network: myotisFirst,
      myotis: myotisOn(1, { call_tx: [{ payload: { resultHex: '0x2a' } }, { payload: { resultHex: '0x12' } }] }),
    }), [req(1, 'eth_call', [{ to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', data: '0x70a08231' }, 'latest'], settles(0)),
      req(1, 'eth_call', [{ to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', data: '0x313ce567' }, 'latest'], settles(0))]),
    scenario('router-myotis-terminal-concurrent', T(1021), routerWorld({
      network: { access: { readOrder: ['myotis'] }, quorum: { timeoutMs: 5000 } },
      myotis: myotisOn(1, { account: { payload: ACCOUNT } }),
    }), [req(1, 'eth_getBalance', ['0xabc', 'latest']), req(1, 'eth_getTransactionCount', ['0xabc', 'latest'])]),
    scenario('router-myotis-queue-full', T(1038), routerWorld({
      network: myotisFirst,
      myotis: myotisOn(1, { call_tx: { hang: true } }),
      rpc: { [RPC]: ok('0xrpc', 0) },
    }), Array.from({ length: 18 }, (_, i) => req(1, 'eth_call', [{ to: target(i), data: '0x1234' }, 'latest'], settles(i === 17 ? 0 : 5000)))),
    scenario('router-myotis-status-throw-releases-slot', T(1066), routerWorld({
      network: { access: { readOrder: ['myotis', 'direct'] }, quorum: { timeoutMs: 500 } },
      myotis: myotisOn(1, { call_tx: { payload: { resultHex: '0x2a' } } }, { status: [{ throws: 'native getStatus binding failed' }, { optimisticBlockNumber: MYOTIS_BLOCK }] }),
      rpc: { [RPC]: ok('0xrpc') },
    }), req(1, 'eth_call', [{ to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', data: '0x1234' }, 'latest'], { include_trust: true }),
    req(1, 'eth_call', [{ to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', data: '0x1234' }, 'latest'], { include_trust: true })),
    // The cooldown opens for 15, 30 and then 60 s: each step starts at the
    // boundary the test probes (the direct answer comes at once).
    scenario('router-colibri-cooldown-escalation', T(1092), routerWorld({
      network: colibriFirst,
      colibri: [ok('0xlate', 2000), ok('0xlate', 2000), ok('0xlate', 2000), ok('0xverified')],
      rpc: { [RPC]: ok('0xrpc', 0) },
    }), ...[[0, 2000], [0, 0], [15_000, 2000], [29_999, 0], [1, 2000], [59_999, 0], [1, 0], [0, 0]]
      .map(([after, ms]) => ({ after, calls: [req(1, 'eth_call', call('0x1234'), { ...swap, ...settles(ms) })] }))),
    scenario('router-colibri-capacity-demotion', T(1145), routerWorld({
      network: colibriFirst,
      colibri: { error: { message: 'prover execution failed: Out of gas' } },
      rpc: { [RPC]: ok('0xrpc') },
    }), ...[
      ['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'https://swap.example'],
      ['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'https://swap.example'],
      ['0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'https://swap.example'],
      ['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'https://other.example'],
    ].map(([to, origin]) => req(1, 'eth_call', [{ to, data: '0x1234' }, 'latest'], { origin }))),
    scenario('router-colibri-route-limit', T(1181), routerWorld({
      network: colibriFirst,
      colibri: { hang: true },
      rpc: { [RPC]: ok('0xrpc', 0) },
    }), [2000, 2000, 0].map((ms) => req(1, 'eth_call', call('0x1234'), { ...swap, ...settles(ms) }))),
    scenario('router-quorum-settles-at-m', T(1206), {
      chains: { 1: chainEntry(quorumOnly, ABC) },
      rpc: { [A]: ok('0x42'), [B]: ok('0x42'), [C]: { hang: true } },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
    scenario('router-quorum-carries-past-deadline', T(1239), {
      chains: { 1: chainEntry(quorumDirect, [A, B, C, D]) },
      rpc: { [A]: [{ hang: true }, ok('0xrpc', 0)], [B]: { hang: true }, [C]: { hang: true }, [D]: ok('0xrpc', 0) },
    }, req(1, 'eth_call', call('0x1234'), { ...swap, ...settles(5000) }), req(1, 'eth_call', call('0x1234'), { ...swap, ...settles(0) })),
    scenario('router-quorum-no-extension-before-colibri', T(1285), {
      chains: { 1: chainEntry({ access: { readOrder: ['quorum', 'colibri', 'direct'] }, quorum: { k: 3, m: 2, timeoutMs: 5000 } }, ABC, [PROVER]) },
      rpc: { [A]: { hang: true }, [B]: { hang: true }, [C]: { hang: true } },
      colibri: ok('0xverified'),
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { ...swap, ...settles(2000) })),
    scenario('router-quorum-wallet-read-stays-verified', T(1318), {
      chains: { 1: chainEntry(quorumDirect, ABC) },
      rpc: Object.fromEntries(ABC.map((u) => [u, ok('0x42', 3000)])),
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], settles(3000))),
    scenario('router-quorum-last-source', T(1353), {
      chains: { 1: chainEntry(quorumOnly, ABC) },
      rpc: Object.fromEntries(ABC.map((u) => [u, ok('0x42', 3000)])),
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { ...swap, ...settles(3000) })),
    scenario('router-colibri-last-source', T(1388), routerWorld({
      network: { access: { readOrder: ['colibri'] }, quorum: { timeoutMs: 5000 } },
      colibri: ok('0xverified', 3000),
    }), req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { ...swap, ...settles(3000) })),
    scenario('router-myotis-last-source', T(1410), routerWorld({
      network: { access: { readOrder: ['myotis'] }, quorum: { timeoutMs: 5000 } },
      myotis: myotisOn(1, { call_tx: { payload: { resultHex: '0xverified' }, delay: 3000 } }),
    }), req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { ...swap, ...settles(3000) })),
    scenario('router-quorum-member-reused-as-direct', T(1432), {
      chains: { 1: chainEntry(quorumDirect, ABC) },
      rpc: { [A]: [ok('0x42', 20), ok('0xnext')], [B]: outOfGas, [C]: outOfGas },
    }, req(1, 'eth_call', call('0x1234'), { include_trust: true, ...swap }), req(1, 'eth_call', call('0x1234'), { include_trust: true, ...swap })),
    scenario('router-quorum-partial-without-direct', T(1490), {
      chains: { 1: chainEntry(quorumOnly, ABC) },
      rpc: { [A]: ok('0xsingle'), [B]: outOfGas, [C]: outOfGas },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
  ];
}

/** chain-data-router.test.js, describe 'Ant bridge cancellation' and its #496 cases. */
function cancellationScenarios(tx) {
  const network = { access: { readOrder: ['myotis', 'direct'], broadcastOrder: ['myotis', 'direct'] } };
  const base = (extra = {}) => ({ chains: { 100: chainEntry(network, [RPC]) }, myotis: myotisOn(100), ...extra });
  const THREE = [A, B, C];
  const quorumOnly = { access: { readOrder: ['quorum'] }, quorum: { k: 3, m: 2, timeoutMs: 5000 } };
  const range50k = rpcError(-32005, 'query exceeds max block range 50000');
  // #496: a Gnosis RPC cuts a wide answer to its newest blocks.
  const HEAD = 48_574_494;
  const FULL = [{ fromBlock: hex(16_514_506), toBlock: hex(HEAD) }];
  const log = (block) => ({ blockNumber: hex(block), logIndex: '0x0' });
  const TAIL = [log(HEAD - 473), log(HEAD - 10)];
  const fullOrEarlier = (earlier) => ({ rules: [{ when: { toBlock: HEAD }, then: ok(TAIL) }], else: earlier });
  const cutEarlier = { logs: { blocks: ['to-5'], logIndex: '0x0' } };
  const colibriDirect = (rpc) => ({
    chains: { 100: chainEntry({ access: { readOrder: ['colibri', 'direct'] }, quorum: { timeoutMs: 5000 } }, [A, B], [PROVER]) },
    rpc,
  });
  return [
    ...['read', 'broadcast'].map((kind) => scenario(`cancel-${kind}-no-fallthrough`, T(1533), base({
      myotis: myotisOn(100, { [kind === 'read' ? 'account' : 'broadcast']: { throws: 'error', message: 'node stopped', delay: 20 } }),
    }), kind === 'read'
      ? req(100, 'eth_getBalance', ['0xabc', 'latest'], { abort_at: 10 })
      : send(100, tx.gnosis.raw, { abort_at: 10 }))),
    scenario('cancel-background-never-queues', T(1548), base({
      chains: { 100: chainEntry(network, [url('one')]) },
      myotis: myotisOn(100, { call_tx: [{ payload: { resultHex: '0x1' }, delay: 50 }, { payload: { resultHex: '0x2a' } }] }),
      rpc: { [url('one')]: ok('0xrpc') },
    }), [
      req(100, 'eth_call', [{ to: `0x${'1'.padStart(40, '0')}`, data: '0x1234' }, 'latest']),
      req(100, 'eth_call', [{ to: `0x${'1'.padStart(40, '0')}`, data: '0x1234' }, 'latest'], { background: true, at: 5 }),
    ], req(100, 'eth_call', [{ to: `0x${'1'.padStart(40, '0')}`, data: '0x1234' }, 'latest'], { background: true })),
    scenario('cancel-direct-timeout-widened-never-narrowed', T(1567), {
      chains: { 100: chainEntry({ access: { readOrder: ['direct'] }, quorum: { timeoutMs: 5000 } }, [url('one')]) },
      rpc: { [url('one')]: { hang: true } },
    }, req(100, 'eth_getLogs', [{}], { options: { directTimeoutMs: 60000 }, ...settles(60000) }), req(100, 'eth_getLogs', [{}], { options: { directTimeoutMs: 10 }, ...settles(5000) })),
    scenario('cancel-quorum-timeout-widened-never-narrowed', T(1598), {
      chains: { 100: chainEntry(quorumOnly, [A, B]) },
      rpc: { [A]: { hang: true }, [B]: { hang: true } },
    }, req(100, 'eth_getLogs', [{}], { options: { quorumTimeoutMs: 30000 }, ...settles(30000) }), req(100, 'eth_getLogs', [{}], { options: { quorumTimeoutMs: 10 }, ...settles(5000) })),
    scenario('cancel-range-not-learned-without-cap-reader', T(1634), {
      chains: { 100: chainEntry(quorumOnly, THREE) },
      rpc: { [A]: ok([]), [B]: ok([]), [C]: rpcError(-32701, 'exceed maximum block range: 50000') },
    }, ...[0, 1].map(() => req(100, 'eth_getLogs', [{ fromBlock: '0x1', toBlock: '0x1000000' }], { options: { rankError: 'request' } }))),
    scenario('cancel-quorum-reverts-aggregate', T(1663), {
      chains: { 100: chainEntry(quorumOnly, THREE) },
      rpc: Object.fromEntries(THREE.map((u) => [u, rpcError(3, 'execution reverted', { data: '0xdeadbeef' })])),
    }, req(100, 'eth_call', [{ to: '0x0000000000000000000000000000000000000001', data: '0x' }, 'latest'])),
    scenario('cancel-range-limit-not-kept-without-rank', T(1680), {
      chains: { 100: chainEntry({ access: { readOrder: ['quorum', 'direct'] }, quorum: { k: 3, m: 2, timeoutMs: 5000 } }, [...THREE, D]) },
      rpc: { [A]: { hang: true }, [B]: range50k, [C]: range50k, [D]: range50k },
    }, req(100, 'eth_getLogs', [{}], { options: { directTimeoutMs: 60000 } })),
    scenario('cancel-broadcast-later-timeout-wins', T(1712), {
      chains: { 100: chainEntry({ access: { broadcastOrder: ['myotis', 'direct'] }, quorum: { timeoutMs: 5000 } }, [A, B]) },
      myotis: { 100: { ready: false } },
      rpc: { [A]: rpcError(-32005, 'rate limit exceeded'), [B]: { hang: true } },
    }, send(100, tx.gnosis.raw, settles(5000))),
    scenario('cancel-broadcast-no-second-rpc', T(1736), {
      chains: { 100: chainEntry({ access: { broadcastOrder: ['direct'] } }, [url('one'), url('two')]) },
      // The test's fetch aborts the caller and fails at once: here both at
      // 10 ms, the abort first.
      rpc: { [url('one')]: { fail: 'disconnected', delay: 10 }, [url('two')]: ok(tx.gnosis.hash) },
    }, send(100, tx.gnosis.raw, { abort_at: 10 })),
    scenario('cancel-filter-names-sources', T(1761), {
      chains: { 1: chainEntry({ access: { readOrder: ['myotis', 'colibri', 'quorum'] }, quorum: { timeoutMs: 5000 } }, [RPC], [PROVER]) },
      myotis: myotisOn(1),
    }, req(1, 'eth_newFilter', [{}])),
    scenario('truncation-earlier-logs-fail-at-once', T(1805), colibriDirect({ [A]: fullOrEarlier(cutEarlier), [B]: fullOrEarlier(cutEarlier) }),
      req(100, 'eth_getLogs', FULL)),
    scenario('truncation-empty-earlier-window-accepted', T(1824), colibriDirect({ [A]: fullOrEarlier(ok([])), [B]: fullOrEarlier(ok([])) }),
      req(100, 'eth_getLogs', FULL)),
    scenario('truncation-failed-check-accepted', T(1833), colibriDirect({
      [A]: fullOrEarlier(rpcError(-32005, 'query exceeds max block range 10000')),
      [B]: fullOrEarlier(rpcError(-32005, 'query exceeds max block range 10000')),
    }), req(100, 'eth_getLogs', FULL)),
    scenario('truncation-direct-check-one-attempt', T(1842), {
      chains: { 100: chainEntry({ access: { readOrder: ['direct'] }, quorum: { timeoutMs: 5000 } }, THREE) },
      rpc: Object.fromEntries(THREE.map((u) => [u, fullOrEarlier({ hang: true })])),
    }, req(100, 'eth_getLogs', FULL, settles(5000))),
    scenario('truncation-direct-check-asks-answering-endpoint', T(1875), {
      chains: { 100: chainEntry({ access: { readOrder: ['direct'] }, quorum: { timeoutMs: 5000 } }, [A, C]) },
      rpc: { [A]: { hang: true }, [C]: fullOrEarlier(cutEarlier) },
    }, req(100, 'eth_getLogs', FULL, settles(5000))),
    scenario('truncation-direct-check-reused-member', T(1906), {
      chains: { 100: chainEntry({ access: { readOrder: ['quorum', 'direct'] }, quorum: { k: 3, m: 2, timeoutMs: 5000 } }, THREE) },
      rpc: { [A]: { hang: true }, [B]: fullOrEarlier(cutEarlier), [C]: ok([]) },
    }, req(100, 'eth_getLogs', FULL)),
    {
      // Five answers that are not checked: each step one shape, one request.
      ...scenario('truncation-unchecked-shapes', T(1944), colibriDirect({ [A]: ok([]), [B]: ok([]) })),
      steps: [
        [FULL, []],
        [FULL, [log(HEAD - 1000), log(HEAD)]],
        [[{ fromBlock: hex(HEAD - 2000 + 2), toBlock: hex(HEAD) }], TAIL],
        [[{ fromBlock: FULL[0].fromBlock, toBlock: 'latest' }], TAIL],
        [FULL, [{ logIndex: '0x0' }]],
      ].map(([params, result]) => ({ world: { rpc: { [A]: ok(result), [B]: ok(result) } }, calls: [req(100, 'eth_getLogs', params)] })),
    },
    scenario('truncation-quorum-agreed-checked-through-quorum', T(1960), {
      chains: { 100: chainEntry({ access: { readOrder: ['quorum', 'direct'] }, quorum: { k: 2, m: 2, timeoutMs: 5000 } }, [A, B]) },
      rpc: { [A]: fullOrEarlier(cutEarlier), [B]: fullOrEarlier(cutEarlier) },
    }, req(100, 'eth_getLogs', FULL)),
  ];
}

// ant-log-scan-routing.test.js: Ant's eth_getLogs through the bridge's
// options. Endpoints answer at once unless a case names a delay.
const ANT_REPLIES = {
  range: rpcError(-32005, 'query exceeds max block range 50000'),
  timeoutReply: rpcError(-32000, 'query timeout exceeded'),
  endpoint: rpcError(-32601, 'the method eth_getLogs does not exist/is not available'),
  throttle: rpcError(-32005, 'project ID request rate exceeded'),
  limitExceeded: rpcError(-32005, 'limit exceeded'),
  rethLag: rpcError(-32000, 'block range extends beyond current head block: requested 0x2000, head 0x1000'),
  erigonLag: rpcError(-32000, 'requested block range [4096, 8192] is beyond latest executed block 4000 (node is still syncing)'),
  logCap: rpcError(-32005, 'query exceeds limit of 10000 logs'),
  rangesOver: rpcError(-32000, 'ranges over 10000 blocks are not supported'),
  nethermindCap: rpcError(-32602, 'Block range 50000 exceeds the maximum of 10000 blocks per logs request. Use a narrower fromBlock/toBlock range or increase Receipt.MaxBlockDepth.'),
  publicnodeCap: rpcError(-32701, 'exceed maximum block range: 50000'),
  429: { status: 429, text: '{}' },
  down: { fail: 'fetch failed' },
  success: ok(['LOGS']),
  hang: { hang: true },
};
/** A behaviour by name, answering at once or `after` ms later. */
const ant = (kind, after = 0) => ({ ...ANT_REPLIES[kind], ...(ANT_REPLIES[kind].hang ? {} : { delay: after }) });
const ANT_HEAD = 48_560_000;
const ANT_FULL_HISTORY = ANT_HEAD - 16_514_506 + 1;
const logsOver = (span) => [{ fromBlock: hex(ANT_HEAD - span + 1), toBlock: hex(ANT_HEAD) }];
/** One Ant eth_getLogs, the way the bridge routes it. */
const antLogs = (params = [{}], extra = {}) => req(100, 'eth_getLogs', params, { background: true, profile: 'ant_scan', signal: true, ...extra });
// The endpoints #484 measured, by span: publicnode refuses over 50,000 and
// hands its 10,000-block backend's refusal through between; dRPC's free
// plan refuses over 10,000.
const PUBLICNODE = { rules: [{ when: { spanOver: 50_000 }, then: ant('publicnodeCap') }, { when: { spanOver: 10_000 }, then: ant('nethermindCap') }], else: ant('success') };
const DRPC = { rules: [{ when: { spanOver: 10_000 }, then: ant('rangesOver') }], else: ant('success') };
const FULL = ant('success');
/** The bridge's world: endpoint name -> plan; Myotis ready and Colibri answering, neither asked. */
const antWorld = (rpcs, network = { access: { readOrder: ['myotis', 'colibri', 'quorum', 'direct'] }, quorum: { k: 3, m: 2, timeoutMs: 5000 } }) => ({
  chains: { 100: chainEntry(network, Object.keys(rpcs).map(url), [PROVER]) },
  myotis: myotisOn(100),
  colibri: ok(['LOGS']),
  rpc: Object.fromEntries(Object.entries(rpcs).map(([name, plan]) => [url(name), typeof plan === 'string' ? ant(plan) : plan])),
});
const S = (line) => `ant-log-scan-routing.test.js:${line}`;

function antScanScenarios() {
  const halve = (span = ANT_FULL_HISTORY, extra = {}) => ({ driver: { kind: 'halve', head: ANT_HEAD, span, ...extra } });
  // Every case asserts when Ant's request settles (`at`).
  const at = (ms) => antLogs([{}], settles(ms));
  const matrix = {
    '3of3': (kind) => ({ a: kind, b: kind, c: kind, d: 'success' }),
    '2of3': (kind) => ({ a: kind, b: kind, c: 'down', d: 'success' }),
    '1of3': (kind) => ({ a: kind, b: 'down', c: 'down', d: 'success' }),
  };
  const kinds = ['range', 'timeoutReply', 'endpoint', 'hang', 'success'];
  const kebab = (kind) => kind.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
  // Behaviours by the requested filter: #496's dense BZZ Transfer scan, cut
  // to its newest ~474 blocks once it matches too many logs.
  const dense = (over) => ({
    rules: [{ when: { spanOver: over }, then: { logs: { blocks: ['to-473', 'to-2'] }, delay: 0 } }],
    else: { logs: { blocks: ['from', 'to'] }, delay: 0 },
  });
  const MANY = { ...rpcError(-32005, 'query returned more than 10000 results'), delay: 0 };
  const recentOr = (earlier) => ({ rules: [{ when: { toBlock: ANT_HEAD }, then: { logs: { blocks: [ANT_HEAD - 120] }, delay: 0 } }], else: earlier });
  return [
    scenario('ant-scan-quorum-only', S(294), antWorld({ a: 'success', b: 'success', c: 'success' }), at(0)),
    {
      // Colibri would answer each of these; it is never asked.
      ...scenario('ant-scan-colibri-never-asked', S(303), antWorld({ a: 'down', b: 'down', c: 'down' })),
      steps: [ok(['LOGS']), rpcError(-32005, 'query exceeds max block range 50000'), rpcError(-32000, 'query timeout exceeded'), { hang: true }]
        .map((colibri) => ({ world: { colibri }, calls: [at(0)] })),
    },
    scenario('ant-scan-one-answer-does-not-settle', S(319), antWorld({ a: 'success', b: 'down', c: 'down', d: 'success' }), at(0)),
    scenario('ant-scan-no-quorum-reply', S(328), antWorld({ a: 'success', b: 'down', c: 'down' }), antLogs()),
    ...Object.entries(matrix).flatMap(([pattern, rpcs]) => kinds.map((kind) => scenario(
      `ant-scan-members-${pattern}-${kebab(kind)}`, S(375), antWorld(rpcs(kind)), at(pattern !== '1of3' && kind === 'hang' ? 30_000 : 0)))),
    scenario('ant-scan-range-after-endpoint-ends-quorum', S(385), antWorld({ a: 'endpoint', b: ant('range', 1000), c: 'hang' }), at(1000)),
    scenario('ant-scan-endpoint-after-range-kept', S(390), antWorld({ a: ant('endpoint', 1000), b: 'range', c: 'hang' }), at(1000)),
    scenario('ant-scan-timeouts-after-range-kept', S(395), antWorld({ a: 'hang', b: 'range', c: 'hang' }), at(30_000)),
    scenario('ant-scan-timeout-replaces-endpoint-error', S(401), antWorld({ a: 'endpoint', b: 'hang', c: 'hang' }), at(30_000)),
    scenario('ant-scan-answer-does-not-outvote-ranges', S(406), antWorld({ a: 'success', b: 'range', c: 'range' }), at(0)),
    scenario('ant-scan-two-answers-beat-failure', S(411), antWorld({ a: ant('success', 1000), b: 'endpoint', c: ant('success', 2000) }), at(2000)),
    scenario('ant-scan-r1-f1-upstream-wording', S(422), antWorld({ a: 'down', b: 'range', c: 'range' }), at(0)),
    scenario('ant-scan-r4-f1-hung-member-range-final', S(428), antWorld({ a: 'hang', b: 'range', c: 'range', d: 'range' }), at(0)),
    ...['429', 'endpoint', 'down'].map((kind) => scenario(`ant-scan-r6-f1-range-survives-${kind}`, S(436),
      antWorld({ a: 'range', b: ant(kind, 100), c: 'hang' }), at(100))),
    ...['throttle', 'limitExceeded', 'rethLag', 'erigonLag'].map((kind) => scenario(`ant-scan-${kebab(kind)}-two-agree`, S(450),
      antWorld({ a: kind, b: 'success', c: 'success' }), at(0))),
    scenario('ant-scan-all-throttled', S(458), antWorld({ a: 'throttle', b: 'throttle', c: 'throttle' }), at(0)),
    ...['limitExceeded', 'logCap'].map((kind) => scenario(`ant-scan-r2-f2-all-${kebab(kind)}`, S(463),
      antWorld({ a: kind, b: kind, c: kind }), at(0))),
    ...[['logCap', 'down'], ['logCap', '429'], ['logCap', 'throttle'], ['limitExceeded', 'down'], ['limitExceeded', '429'], ['rangesOver', 'down']]
      .flatMap(([kind, others]) => [
        scenario(`ant-scan-r3-f1-${kebab(kind)}-then-${others}`, S(479), antWorld({ a: kind, b: ant(others, 100), c: 'hang' }), at(100)),
        scenario(`ant-scan-r3-f1-${others}-then-${kebab(kind)}`, S(479), antWorld({ a: ant(kind, 100), b: others, c: 'hang' }), at(100)),
      ]),
    scenario('ant-scan-r3-f1-cap-loses-to-timeout', S(506), antWorld({ a: 'logCap', b: 'timeoutReply', c: 'hang' }), at(0)),
    scenario('ant-scan-r3-f1-cap-loses-to-answers', S(506), antWorld({ a: 'logCap', b: 'success', c: 'success' }), at(0)),
    scenario('ant-scan-r3-f1-lag-not-kept', S(513), antWorld({ a: 'rethLag', b: 'down', c: 'down' }), antLogs()),
    scenario('ant-scan-caps-full-history-one-answer', S(529), antWorld({ a: FULL, b: FULL, c: PUBLICNODE, d: DRPC }), halve(ANT_FULL_HISTORY, settles(0))),
    scenario('ant-scan-caps-capped-endpoint-left-out', S(536), antWorld({ a: FULL, b: PUBLICNODE, c: FULL }),
      antLogs(logsOver(ANT_FULL_HISTORY)), antLogs(logsOver(ANT_FULL_HISTORY), settles(0)), antLogs(logsOver(10_000))),
    scenario('ant-scan-caps-fourth-endpoint-joins', S(547), antWorld({ a: FULL, b: PUBLICNODE, c: DRPC, d: FULL }),
      antLogs(logsOver(ANT_FULL_HISTORY), settles(0)), antLogs(logsOver(ANT_FULL_HISTORY))),
    scenario('ant-scan-caps-two-down-second-round', S(557), antWorld({ a: 'down', b: 'down', c: 'success', d: 'success' }), antLogs(logsOver(5000), settles(0))),
    scenario('ant-scan-caps-widest-servable-span', S(563), antWorld({ a: FULL, b: PUBLICNODE, c: DRPC }),
      antLogs(logsOver(40_000)), antLogs(logsOver(40_000)), antLogs(logsOver(ANT_FULL_HISTORY), settles(0))),
    scenario('ant-scan-caps-shrink-to-capped-windows', S(578), antWorld({ a: FULL, b: 'down', c: PUBLICNODE, d: DRPC }), halve(ANT_FULL_HISTORY, settles(0))),
    scenario('ant-scan-caps-full-history-endpoint-fails-later', S(590),
      antWorld({ a: ant('success', 100), b: [ant('success', 100), ant('down')], c: PUBLICNODE }),
      antLogs(logsOver(ANT_FULL_HISTORY)), antLogs(logsOver(ANT_FULL_HISTORY), settles(0))),
    scenario('ant-scan-caps-hung-endpoint-cools-down', S(607), antWorld({ a: FULL, b: 'hang', c: PUBLICNODE }),
      antLogs(logsOver(ANT_FULL_HISTORY), settles(30_000)), antLogs(logsOver(10_000), settles(0)), { after: 30_000, calls: [antLogs(logsOver(10_000))] }),
    scenario('ant-scan-caps-expire', S(626), antWorld({ a: FULL, b: PUBLICNODE, c: FULL }),
      antLogs(logsOver(ANT_FULL_HISTORY)),
      { world: { rpc: antWorld({ a: FULL, b: FULL, c: FULL }).rpc }, calls: [antLogs(logsOver(ANT_FULL_HISTORY))] },
      { after: 30 * 60_000, calls: [antLogs(logsOver(ANT_FULL_HISTORY))] },
      antLogs(logsOver(ANT_FULL_HISTORY))),
    scenario('ant-scan-caps-upstream-timeout-brief', S(640), antWorld({ a: FULL, b: 'timeoutReply', c: 'timeoutReply' }),
      antLogs(logsOver(500)),
      { world: { rpc: antWorld({ a: FULL, b: FULL, c: FULL }).rpc }, calls: [antLogs(logsOver(2000))] },
      { after: 30_000, calls: [antLogs(logsOver(2000))] }),
    scenario('ant-scan-caps-timed-out-span-holds', S(661), antWorld({ a: FULL, b: [ant('timeoutReply'), ant('success')], c: FULL }),
      antLogs(logsOver(4000)), antLogs(logsOver(4000)), antLogs(logsOver(1000)), antLogs(logsOver(4000)),
      { after: 30_000, calls: [antLogs(logsOver(4000))] }),
    scenario('ant-scan-caps-result-count-not-learned', S(678), antWorld({ a: MANY, b: MANY, c: MANY }),
      antLogs(logsOver(20_000)),
      { world: { rpc: antWorld({ a: FULL, b: FULL, c: FULL }).rpc }, calls: [antLogs(logsOver(20_000))] }),
    scenario('ant-scan-caps-all-down', S(696), antWorld({ a: 'down', b: 'down', c: 'down' }), halve(ANT_FULL_HISTORY, settles(0)), antLogs(logsOver(ANT_FULL_HISTORY), settles(0))),
    scenario('ant-scan-truncation-halves-until-complete', S(723), antWorld({ a: dense(400_000), b: dense(400_000), c: dense(400_000) }), halve()),
    scenario('ant-scan-truncation-narrow-window-checked', S(742), antWorld({ a: dense(10_000), b: dense(10_000), c: dense(10_000) }), antLogs(logsOver(15_000))),
    ...[['timeout-reply', ant('timeoutReply')], ['hang', ant('hang')]].map(([label, failure]) => scenario(
      `ant-scan-truncation-check-${label}-leaves-no-cooldown`, S(757),
      antWorld({ a: recentOr(failure), b: recentOr(failure), c: recentOr(failure) }),
      antLogs(logsOver(30_000)), antLogs(logsOver(30_000)))),
    scenario('ant-scan-truncation-sparse-recent-accepted', S(773),
      antWorld({ a: recentOr(ok([], 0)), b: recentOr(ok([], 0)), c: recentOr(ok([], 0)) }), antLogs(logsOver(ANT_FULL_HISTORY))),
  ];
}

// ant-log-index-routing.test.js: Ant's first wallet scan, with Blockscout's
// log index paired with a full-history RPC (#529). The wallet's xBZZ
// transfers on chain (world.logs) as eth_getLogs entries, and Blockscout's
// token-transfer items for them.
const XBZZ = '0xdBF3Ea6F5beE45c02255B2c26a16F300502F68da';
const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const DEPLOY_BLOCK = 16_514_506;
const INDEX_HEAD = 48_607_023;
const WALLET = '0x000000000000000000000000971f31aaeac713b47aa55e50c06409afc1de46b9';
const POSTAGE = '0x00000000000000000000000045a1502382541cd610cc9068e88727426b696293';
const BLOCKSCOUT = 'gnosis.blockscout.com';
const transferLog = (block, logIndex, to = POSTAGE, from = WALLET) => ({
  address: XBZZ.toLowerCase(),
  topics: [TRANSFER, from, to],
  data: `0x${(block % 997).toString(16).padStart(64, '0')}`,
  blockNumber: hex(block),
  transactionHash: `0x${block.toString(16).padStart(56, '0')}${logIndex.toString(16).padStart(8, '0')}`,
  transactionIndex: hex(logIndex % 7),
  blockHash: `0x${block.toString(16).padStart(64, 'b')}`,
  logIndex: hex(logIndex),
  removed: false,
});
const WALLET_LOGS = [
  transferLog(20_000_000, 3),
  transferLog(33_623_226, 1),
  transferLog(36_258_280, 9),
  transferLog(40_000_000, 2),
  transferLog(45_768_216, 4),
  transferLog(48_202_680, 0),
  transferLog(INDEX_HEAD - 10, 5),
];
const blockscoutItem = (log) => ({
  block_hash: log.blockHash,
  block_number: parseInt(log.blockNumber, 16),
  from: { hash: `0x${log.topics[1].slice(26)}` },
  log_index: parseInt(log.logIndex, 16),
  to: { hash: `0x${log.topics[2].slice(26)}` },
  token: { address_hash: XBZZ },
  token_type: 'ERC-20',
  total: { decimals: '16', value: BigInt(log.data).toString() },
  transaction_hash: log.transactionHash,
  type: 'token_transfer',
});
const transfers = (logs, extra = {}) => ({ transfers: logs.map(blockscoutItem), delay: 0, ...extra });
const walletFilter = (from, to) => [{ address: XBZZ, fromBlock: hex(from), toBlock: hex(to), topics: [TRANSFER, WALLET] }];
const walletLogs = (from = DEPLOY_BLOCK, to = INDEX_HEAD, extra = {}) => antLogs(walletFilter(from, to), extra);
const IN_RANGE = { logs: { inRange: true }, delay: 0 };
const CAP_10K = { ...rpcError(-32701, 'exceed maximum block range: 10000'), delay: 0 };
const CAPPED = { rules: [{ when: { spanOver: 10_000 }, then: CAP_10K }], else: IN_RANGE };
const INDEX_DEFAULTS = { gnosischain: IN_RANGE, publicnode: CAPPED, drpc: CAPPED };
/** The wallet-scan world: endpoint name -> plan, Blockscout's answers. */
const indexWorld = (rpcs = INDEX_DEFAULTS, blockscout = transfers(WALLET_LOGS), extra = {}) => ({
  chains: { 100: chainEntry({ access: { readOrder: ['myotis', 'colibri', 'quorum', 'direct'] }, quorum: { k: 3, m: 2, timeoutMs: 5000 } }, Object.keys(rpcs).map(url), [PROVER]) },
  rpc: Object.fromEntries(Object.entries(rpcs).map(([name, plan]) => [url(name), plan])),
  logs: WALLET_LOGS,
  blockscout: { [BLOCKSCOUT]: blockscout },
  ...extra,
});
const walletScan = (from = DEPLOY_BLOCK, to = INDEX_HEAD) => ({
  driver: { kind: 'wallet', from, to, chunk: 50_000_000, maxRequests: 20_000, filter: { address: XBZZ, topics: [TRANSFER, WALLET] } },
});
const X = (line) => `ant-log-index-routing.test.js:${line}`;

function antIndexScenarios() {
  const hangOver = (capped) => ({
    rules: [
      ...(capped ? [{ when: { spanOver: 10_000 }, then: CAP_10K }] : []),
      { when: { spanAtMost: 1000 }, then: { hang: true } },
    ],
    else: IN_RANGE,
  });
  const spoilFirst = (change) => ({ rules: [{ when: { spanOver: 10_000 }, then: { logs: { inRange: true, first: true, ...change }, delay: 0 } }], else: IN_RANGE });
  const first = WALLET_LOGS[0];
  const spoils = {
    'no-block-hash': { omit: ['blockHash'] },
    'short-block-hash': { set: { blockHash: first.blockHash.slice(0, 40) } },
    'two-word-value': { set: { data: `${first.data}${'0'.repeat(64)}` } },
    'recipient-not-address': { set: { topics: [first.topics[0], first.topics[1], `0x${'f'.repeat(64)}`] } },
    'sender-not-address': { set: { topics: [first.topics[0], `0x01${first.topics[1].slice(4)}`, first.topics[2]] } },
    removed: { set: { removed: true } },
  };
  // 101 transfers, three pages: the test's 500 read the same way (the
  // budget runs out on the third page).
  const MANY = Array.from({ length: 101 }, (_, i) => transferLog(DEPLOY_BLOCK + 1000 * i, 1));
  const TOO_MANY = { status: 429, headers: { 'x-ratelimit-reset': '344628' }, text: '{"message":"Too many requests"}', delay: 0 };
  // The suite's bound on a scan that gives Blockscout up: the scan budget
  // (the widened quorum timeout) plus its 100 ms polling step.
  const WITHIN_BUDGET = { expect_settle_max_ms: 30_100 };
  return [
    scenario('ant-index-first-wallet-scan', X(286), indexWorld(), walletScan()),
    scenario('ant-index-blockscout-down-window-by-window', X(302), indexWorld(INDEX_DEFAULTS, { fail: 'fetch failed', delay: 0 }), walletScan(INDEX_HEAD - 200_000)),
    scenario('ant-index-pairs-leading-part', X(314), indexWorld(), walletLogs(), walletLogs()),
    scenario('ant-index-only-compared-fields', X(352), indexWorld({
      ...INDEX_DEFAULTS, gnosischain: { logs: { inRange: true, set: { transactionIndex: '0x3e7', blockTimestamp: '0x1' } }, delay: 0 },
    }), walletLogs(), walletLogs()),
    ...[['down', { fail: 'fetch failed', delay: 0 }], ['429', TOO_MANY], ['missing-old-log', transfers(WALLET_LOGS.filter((log) => log !== WALLET_LOGS[1]))]]
      .map(([label, blockscout]) => scenario(`ant-index-blockscout-${label}-falls-back`, X(388), indexWorld(INDEX_DEFAULTS, blockscout),
        walletLogs(), walletLogs(), walletLogs(DEPLOY_BLOCK, INDEX_HEAD - 1))),
    scenario('ant-index-429-named-reset', X(408), indexWorld(INDEX_DEFAULTS, TOO_MANY),
      walletLogs(), walletLogs(), { after: 344_000, calls: [walletLogs()] }, { after: 1_000, calls: [walletLogs()] }),
    scenario('ant-index-blockscout-hung', X(421), indexWorld(INDEX_DEFAULTS, { hang: true }), walletLogs(), walletLogs(DEPLOY_BLOCK, INDEX_HEAD, WITHIN_BUDGET)),
    scenario('ant-index-slow-multipage-budget', X(433), indexWorld(INDEX_DEFAULTS, transfers(MANY, { delay: 12_000 })),
      walletLogs(), walletLogs(DEPLOY_BLOCK, INDEX_HEAD, WITHIN_BUDGET), walletLogs(DEPLOY_BLOCK, INDEX_HEAD - 1)),
    scenario('ant-index-late-blockscout-tail-budget', X(451), indexWorld(INDEX_DEFAULTS, transfers(WALLET_LOGS, { delay: 24_000 })),
      walletLogs(),
      { world: { rpc: indexWorld({ gnosischain: hangOver(false), publicnode: hangOver(true), drpc: hangOver(true) }).rpc }, calls: [walletLogs(DEPLOY_BLOCK, INDEX_HEAD, WITHIN_BUDGET)] }),
    scenario('ant-index-tail-rounds-share-budget', X(475), indexWorld({ gnosischain: IN_RANGE, publicnode: CAPPED, drpc: CAPPED, fourth: CAPPED, fifth: CAPPED }),
      walletLogs(),
      { world: { rpc: indexWorld({ gnosischain: hangOver(false), publicnode: hangOver(true), drpc: hangOver(true), fourth: hangOver(true), fifth: hangOver(true) }).rpc }, calls: [walletLogs(DEPLOY_BLOCK, INDEX_HEAD, WITHIN_BUDGET)] }),
    scenario('ant-index-blockscout-slower-than-budget', X(505), indexWorld(INDEX_DEFAULTS, transfers(WALLET_LOGS, { delay: 28_000 })), walletLogs(), walletLogs(DEPLOY_BLOCK, INDEX_HEAD, WITHIN_BUDGET)),
    scenario('ant-index-caller-abort-cools-blockscout', X(515), indexWorld(INDEX_DEFAULTS, { hang: true }),
      walletLogs(), walletLogs(DEPLOY_BLOCK, INDEX_HEAD, { abort_at: 3000 }), walletLogs(),
      { after: 61_000, world: { blockscout: { [BLOCKSCOUT]: transfers(WALLET_LOGS) } }, calls: [walletLogs()] }),
    scenario('ant-index-hung-pair-rpc', X(529), indexWorld({ ...INDEX_DEFAULTS, gnosischain: [IN_RANGE, { rules: [{ when: { spanOver: 10_000 }, then: { hang: true } }], else: IN_RANGE }] }),
      walletLogs(), walletLogs(DEPLOY_BLOCK, INDEX_HEAD, WITHIN_BUDGET)),
    scenario('ant-index-lagging-blockscout-agrees', X(542), indexWorld(INDEX_DEFAULTS, transfers(WALLET_LOGS.filter((log) => log !== WALLET_LOGS[6]))), walletScan()),
    scenario('ant-index-truncated-rpc-never-accepted', X(551), indexWorld({ ...INDEX_DEFAULTS, gnosischain: { logs: { inRange: true, newest: 475 }, delay: 0 } }),
      walletLogs(), walletLogs()),
    ...Object.entries(spoils).map(([label, change]) => scenario(`ant-index-malformed-pair-entry-${label}`, X(565), indexWorld(),
      walletLogs(),
      { world: { rpc: indexWorld({ ...INDEX_DEFAULTS, gnosischain: spoilFirst(change) }).rpc }, calls: [walletLogs()] },
      { world: { rpc: indexWorld().rpc }, calls: [walletLogs()] },
      { after: 30 * 60_000 + 1, calls: [walletLogs()] },
      walletLogs())),
    scenario('ant-index-tail-quorum-malformed', X(613), indexWorld(Object.fromEntries(['gnosischain', 'publicnode', 'drpc'].map((name) => [name, {
      rules: [
        ...(name === 'gnosischain' ? [] : [{ when: { spanOver: 10_000 }, then: CAP_10K }]),
        { when: { spanAtMost: 1000 }, then: { logs: { inRange: true, omit: ['blockHash'] }, delay: 0 } },
      ],
      else: IN_RANGE,
    }]))), walletLogs(), walletLogs()),
    scenario('ant-index-capped-blockscout-page-disagrees', X(631), indexWorld(INDEX_DEFAULTS, transfers(WALLET_LOGS.slice(-3, -1))), walletLogs(), walletLogs()),
    scenario('ant-index-no-full-history-pair', X(640), indexWorld({ a: CAPPED, b: CAPPED, c: CAPPED }), walletLogs(), walletLogs(), walletLogs()),
    scenario('ant-index-pair-rpc-fails-blockscout-not-cooled', X(655), indexWorld({ ...INDEX_DEFAULTS, gnosischain: [IN_RANGE, { fail: 'fetch failed', delay: 0 }, IN_RANGE] }),
      walletLogs(), walletLogs(), { after: 31_000, calls: [walletLogs()] }),
    scenario('ant-index-two-full-history-quorum', X(673), indexWorld({ a: IN_RANGE, b: IN_RANGE, c: CAPPED }), walletScan()),
    scenario('ant-index-routine-tail-quorum', X(682), indexWorld(), walletLogs(), walletLogs(INDEX_HEAD - 999, INDEX_HEAD)),
    scenario('ant-index-page-without-include-never-blockscout', X(690), indexWorld(),
      ...[0, 1].map(() => req(100, 'eth_getLogs', walletFilter(DEPLOY_BLOCK, INDEX_HEAD), {
        options: { excludeSources: ['myotis', 'colibri', 'direct'], quorumTimeoutMs: 30_000, rankError: 'ant', rangeCapOf: 'ant' },
      }))),
    scenario('ant-index-other-filters-never-blockscout', X(702), indexWorld(),
      ...[0, 1].map(() => antLogs([{ ...walletFilter(DEPLOY_BLOCK, INDEX_HEAD)[0], topics: [`0x${'5'.repeat(64)}`] }]))),
    scenario('ant-index-order-without-quorum', X(713), {
      ...indexWorld(),
      chains: { 100: chainEntry({ access: { readOrder: ['myotis', 'colibri', 'direct'] }, quorum: { k: 3, m: 2, timeoutMs: 5000 } }, ['gnosischain', 'publicnode', 'drpc'].map(url), [PROVER]) },
    }, walletLogs()),
  ];
}

// ant-chain-bridge.router.test.js: the bridge's options over a 500 ms
// configured quorum timeout.
function bridgeRouterScenarios() {
  const world = (rpcs) => antWorld(rpcs, { access: { readOrder: ['myotis', 'colibri', 'quorum', 'direct'] }, quorum: { k: 3, m: 2, timeoutMs: 500 } });
  const R = (line) => `ant-chain-bridge.router.test.js:${line}`;
  const range = rpcError(-32005, 'query exceeds max block range 50000');
  return [
    scenario('bridge-router-range-limit-forwarded', R(69), world({ a: range, b: range, c: range }), antLogs()),
    scenario('bridge-router-slow-members-agree', R(81), world({ a: ok([], 700), b: ok([], 700), c: ok([], 700) }), antLogs()),
    scenario('bridge-router-single-answer-no-settle', R(97), world({ a: ok(['ok']), b: 'down', c: 'down', d: 'down' }), antLogs()),
    scenario('bridge-router-fourth-joins', R(110), world({ a: 'down', b: 'down', c: ok(['ok']), d: ok(['ok']) }), antLogs([{ fromBlock: '0x1', toBlock: '0x2710' }])),
    scenario('bridge-router-endpoint-error-two-agree', R(128), world({ a: ok([]), b: ok([]), c: rpcError(-32601, 'the method eth_getLogs does not exist') }), antLogs()),
  ];
}

// blockscout-logs.test.js's paging, page checks, cooldowns, redirects and
// DNS, through the router: each scenario first lets the quorum learn the
// capped endpoints' caps, then asks a span only Blockscout can pair.
function blockscoutScenarios() {
  const L = (line) => `blockscout-logs.test.js:${line}`;
  const PAIR_TO = INDEX_HEAD - 1000;
  const query = `?type=ERC-20&filter=from&token=${XBZZ.toLowerCase()}&block_number=${PAIR_TO + 1}&index=0`;
  const PAGE = `https://${BLOCKSCOUT}/api/v2/addresses/0x${WALLET.slice(26)}/token-transfers${query}`;
  const two = (id, line, blockscout, extra = {}) => scenario(id, L(line), indexWorld(INDEX_DEFAULTS, blockscout, extra), walletLogs(), walletLogs());
  const item = (block, change = {}) => ({ ...blockscoutItem(transferLog(block, 0)), ...change });
  const OTHER = `0x${'1'.repeat(40)}`;
  const pageOf = (value) => ({ page: value, delay: 0 });
  const page = (items, more = false) => pageOf({ items, next_page_params: more ? { block_number: items.at(-1).block_number, index: items.at(-1).log_index, items_count: 50 } : null });
  const PUBLIC = { addresses: [{ address: '104.18.12.34', family: 4 }], delay: 0 };
  const redirect = (location, status = 302) => ({ redirect: location, status, delay: 0 });
  const OTHER_PARTY = `0x${'0'.repeat(24)}${'7'.repeat(40)}`;
  const ELSEWHERE = `0x${'0'.repeat(24)}${'2'.repeat(40)}`;
  const INCOMING = [transferLog(21_000_000, 1, WALLET, OTHER_PARTY), transferLog(39_000_000, 4, WALLET, OTHER_PARTY), transferLog(INDEX_HEAD - 20, 2, WALLET, OTHER_PARTY)];
  // 41 transfers in the paired span, one to a page.
  const MANY = Array.from({ length: 41 }, (_, i) => transferLog(DEPLOY_BLOCK + 10_000 * (i + 1), 1));
  return [
    // A recipient scan reads the wallet's incoming transfers (filter=to); a
    // scan by sender and recipient reads by sender and keeps that recipient.
    scenario('blockscout-recipient-scan', L(322), {
      ...indexWorld(INDEX_DEFAULTS, transfers(INCOMING)),
      logs: INCOMING,
    }, ...[0, 1].map(() => antLogs([{ address: XBZZ, fromBlock: hex(DEPLOY_BLOCK), toBlock: hex(INDEX_HEAD), topics: [TRANSFER, null, WALLET] }]))),
    scenario('blockscout-sender-and-recipient-scan', L(336), indexWorld(INDEX_DEFAULTS, transfers([...WALLET_LOGS, transferLog(30_000_000, 7, ELSEWHERE)])),
      ...[0, 1].map(() => antLogs([{ address: XBZZ, fromBlock: hex(DEPLOY_BLOCK), toBlock: hex(INDEX_HEAD), topics: [TRANSFER, WALLET, POSTAGE] }]))),
    // Pages of three: two full ones, then one whose transfer is older than
    // fromBlock, which ends the read.
    two('blockscout-pages-until-from-block', 356, transfers([transferLog(DEPLOY_BLOCK - 5, 2), ...WALLET_LOGS], { pageSize: 3 })),
    two('blockscout-empty-page-not-last', 373, pageOf({ items: [], next_page_params: { block_number: 1, index: 0 } })),
    two('blockscout-over-40-pages', 379, transfers(MANY, { pageSize: 1 })),
    two('blockscout-transfer-after-to-block', 390, page([item(PAIR_TO + 1)])),
    two('blockscout-transfer-other-sender', 390, page([item(30_000_000, { from: { hash: OTHER } })])),
    two('blockscout-transfer-other-token', 390, page([item(30_000_000, { token: { address_hash: OTHER } })])),
    two('blockscout-transfer-malformed', 390, page([item(30_000_000, { transaction_hash: '0x12' })])),
    two('blockscout-transfers-out-of-order', 390, page([item(20_000_000), item(30_000_000)])),
    two('blockscout-same-transfer-twice', 390, page([item(20_000_000), item(20_000_000)])),
    two('blockscout-page-repeats-last-transfer', 405, [page([item(30_000_000), item(20_000_000)], true), page([item(20_000_000)])]),
    {
      // A 429's named reset, clamped to 1-15 minutes, or 5 minutes when it
      // names none: each read waits out the cooldown before.
      ...scenario('blockscout-429-cooldown-bounds', L(413), indexWorld(INDEX_DEFAULTS, { status: 429, headers: { 'x-ratelimit-reset': '344628' }, text: '{"message":"Too many requests"}', delay: 0 })),
      steps: [
        { calls: [walletLogs()] },
        { calls: [walletLogs()] },
        { after: 344_628, world: { blockscout: { [BLOCKSCOUT]: { status: 429, headers: { 'x-ratelimit-reset': '10' }, text: '{}', delay: 0 } } }, calls: [walletLogs()] },
        { after: 60_000, world: { blockscout: { [BLOCKSCOUT]: { status: 429, headers: { 'x-ratelimit-reset': String(10 * 3600_000) }, text: '{}', delay: 0 } } }, calls: [walletLogs()] },
        { after: 15 * 60_000, world: { blockscout: { [BLOCKSCOUT]: { status: 429, headers: { 'retry-after': '90' }, text: '{}', delay: 0 } } }, calls: [walletLogs()] },
        { after: 90_000, world: { blockscout: { [BLOCKSCOUT]: { status: 429, text: '{}', delay: 0 } } }, calls: [walletLogs()] },
      ],
    },
    two('blockscout-http-500', 432, { status: 500, text: 'oops', delay: 0 }),
    two('blockscout-not-json', 432, { text: '<html>', delay: 0 }),
    two('blockscout-refusal', 432, pageOf({ message: 'Invalid address format' })),
    two('blockscout-items-not-a-list', 432, pageOf({ items: {}, next_page_params: null })),
    two('blockscout-no-next-page-params', 432, pageOf({ items: [] })),
    two('blockscout-throttle-in-body', 432, pageOf({ message: 'Too many requests. Increase limits' })),
    two('blockscout-redirect-off-https', 432, redirect(PAGE.replace('https:', 'http:'), 307)),
    two('blockscout-redirect-without-location', 432, { status: 302, text: '', delay: 0 }),
    two('blockscout-transport-failure', 432, { fail: 'fetch failed', delay: 0 }),
    // A redirect off Blockscout's origin is resolved before it is followed.
    two('blockscout-redirect-followed', 469, redirect(PAGE.replace(`https://${BLOCKSCOUT}`, 'https://gnosisscan.io'), 301), {
      blockscout: { [BLOCKSCOUT]: redirect(PAGE.replace(`https://${BLOCKSCOUT}`, 'https://gnosisscan.io'), 301), 'gnosisscan.io': transfers(WALLET_LOGS) },
      dns: { 'gnosisscan.io': PUBLIC },
    }),
    two('blockscout-redirect-loop', 502, redirect('/api?again=1')),
    ...[['loopback', 'https://127.0.0.1/api'], ['mapped-private', 'https://[::ffff:10.0.0.1]/api'], ['localhost-name', 'https://wallet.localhost/api']]
      .map(([label, location]) => two(`blockscout-redirect-local-host-${label}`, 511, redirect(location))),
    two('blockscout-redirect-dns-local', 577, redirect('https://127.0.0.1.nip.io/api'), {
      dns: { '127.0.0.1.nip.io': { addresses: [{ address: '104.18.12.34', family: 4 }, { address: '192.168.1.10', family: 4 }], delay: 0 } },
    }),
    two('blockscout-redirect-dns-fails', 598, redirect('https://nowhere.example/api'), { dns: { 'nowhere.example': { fail: 'ENOTFOUND', delay: 0 } } }),
    two('blockscout-redirect-same-origin', 615, [redirect('/api?x=1'), page([])]),
    two('blockscout-dns-hang', 625, redirect('https://slow.example/api'), { dns: { 'slow.example': { hang: true } } }),
  ];
}

// ---------------------------------------------------------------------------
// Design 0005's named boundary cases, as the reference behaves (its
// restatement in "The router machine", "Broadcast" and "Fee quotes").

/** An answer whose result is an ERC-8244 html() document of `bytes` bytes of 'a', ABI-encoded: a repeat macro. */
function htmlDocument(bytes) {
  const word = (n) => n.toString(16).padStart(64, '0');
  const padding = (32 - (bytes % 32)) % 32;
  return { result_repeat: { head: `0x${word(32)}${word(bytes)}`, unit: '61', count: bytes, tail: '00'.repeat(padding) } };
}

function boundaryScenarios(ethers, tx) {
  const D_ = 'design 0005';
  const ABC = [A, B, C];
  const net = (readOrder, quorum = { k: 3, m: 2, timeoutMs: 5000 }, extra = {}) => ({ access: { readOrder, broadcastOrder: ['myotis', 'direct'] }, quorum, ...extra });
  const w = (chain, network, endpoints) => ({ chains: { [chain]: chainEntry(network, endpoints, [PROVER]) } });
  const revert = rpcError(3, 'execution reverted', { data: '0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004626f6f6d00000000000000000000000000000000000000000000000000000000' });
  const HEAD = 48_574_494;
  const FULL = [{ fromBlock: hex(16_514_506), toBlock: hex(HEAD) }];
  const TAIL = [{ blockNumber: hex(HEAD - 473), logIndex: '0x0' }, { blockNumber: hex(HEAD - 10), logIndex: '0x0' }];
  const fullOr = (earlier) => ({ rules: [{ when: { toBlock: HEAD }, then: ok(TAIL) }], else: earlier });
  const html = ethers.id('html()').slice(0, 10);
  const app = '0x5555555555555555555555555555555555555555';
  const web3 = { include_trust: true, origin: `web3://${app}:1` };
  const swap = { origin: 'https://swap.example' };
  const target = (index) => `0x${String(index + 1).padStart(40, '0')}`;
  const sendWorld = (endpoints, rpc, extra = {}) => ({
    chains: { 1: chainEntry({ access: { broadcastOrder: ['direct'] }, quorum: { timeoutMs: 5000 } }, endpoints) },
    rpc,
    ...extra,
  });
  const nodeRefusal = (message) => rpcError(-32000, message);
  // A JSON escape, \uXXXX, built here: the source holds no escapes to decode.
  const U = (hex) => `${String.fromCharCode(92)}u${hex}`;
  const nested = (n) => '['.repeat(n) + ']'.repeat(n);
  // One Direct endpoint that answers a raw body; each step its own body.
  const direct = () => ({ ...w(1, net(['direct']), [A]), rpc: { [A]: { body: '{"jsonrpc":"2.0","id":1,"result":"0x"}' } } });
  const rpcBody = (text) => ({ world: { rpc: { [A]: { body: text } } }, calls: [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])] });
  // A quorum of two over raw results: each step one pair, a's first.
  const agreement = (id, pairs) => ({
    ...scenario(id, `${D_}: Answers, agreement`, w(1, net(['quorum'], { k: 2, m: 2, timeoutMs: 5000 }), [A, B])),
    steps: pairs.map(([first, second]) => ({
      world: { rpc: { [A]: { body: `{"jsonrpc":"2.0","id":1,"result":${first}}` }, [B]: { body: `{"jsonrpc":"2.0","id":1,"result":${second}}`, delay: 10 } } },
      calls: [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { include_trust: true })],
    })),
  });
  return [
    // An html() document at its 8 MiB limit is 16,777,346 hex characters,
    // its minimal JSON-RPC answer 16,777,382 bytes: the router takes it
    // through a quorum of three like any other answer, and one byte over
    // the limit too (the limit is the web3: handler's, not the router's).
    {
      ...scenario('boundary-html-8mib-through-quorum', `${D_}: Transport, html()`, w(1, net(['quorum', 'direct']), ABC)),
      steps: [8 * 1024 * 1024, 8 * 1024 * 1024 + 1].map((bytes) => ({
        world: { rpc: Object.fromEntries(ABC.map((u) => [u, htmlDocument(bytes)])) },
        calls: [req(1, 'eth_call', [{ to: app, data: html }, 'latest'], web3)],
      })),
    },
    // k = m = 3: b answers first with {"b":1,"a":2}, a later with
    // {"a":2,"b":1}, c fails. Direct returns a's answer (the lowest index
    // that answered), key order a, b.
    scenario('boundary-direct-lower-index-answered-later', `${D_}: Quorum, directFallback`, {
      ...w(1, net(['quorum', 'direct'], { k: 3, m: 3, timeoutMs: 5000 }), ABC),
      rpc: { [A]: ok({ a: 2, b: 1 }, 50), [B]: ok({ b: 1, a: 2 }, 10), [C]: { fail: 'fetch failed', delay: 100 } },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { include_trust: true })),
    // Bodies without `result` answer undefined, and undefined agrees with
    // undefined (a batch-shaped body too).
    scenario('boundary-quorum-agrees-without-result', `${D_}: Answers, undefined`, {
      ...w(1, net(['quorum']), ABC),
      rpc: { [A]: { noResult: true }, [B]: { body: '[]' }, [C]: { hang: true } },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { include_trust: true })),
    // undefined and null disagree; Direct takes a's undefined, reused as it is.
    scenario('boundary-quorum-undefined-null-disagree', `${D_}: Answers, undefined`, {
      ...w(1, net(['quorum', 'direct']), ABC),
      rpc: { [A]: { noResult: true }, [B]: ok(null), [C]: { fail: 'fetch failed', delay: 20 } },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
    scenario('boundary-truncation-quorum-probe-fails', `${D_}: Logs, truncation check`, {
      ...w(100, net(['quorum', 'direct'], { k: 2, m: 2, timeoutMs: 5000 }), [A, B, C]),
      rpc: { [A]: fullOr(rpcError(-32603, 'internal error')), [B]: fullOr(rpcError(-32603, 'internal error')), [C]: ok([]) },
    }, req(100, 'eth_getLogs', FULL)),
    scenario('boundary-truncation-quorum-probe-empty', `${D_}: Logs, truncation check`, {
      ...w(100, net(['quorum', 'direct'], { k: 2, m: 2, timeoutMs: 5000 }), [A, B, C]),
      rpc: { [A]: fullOr(ok([])), [B]: fullOr(ok([])), [C]: ok([]) },
    }, req(100, 'eth_getLogs', FULL)),
    // The probe finds logs: the request ends at once, though Direct has an
    // endpoint the quorum never asked.
    scenario('boundary-truncation-with-direct-left', `${D_}: Logs, truncation check`, {
      ...w(100, net(['quorum', 'direct'], { k: 2, m: 2, timeoutMs: 5000 }), [A, B, C]),
      rpc: { [A]: fullOr(ok([{ blockNumber: hex(HEAD - 600), logIndex: '0x0' }])), [B]: fullOr(ok([{ blockNumber: hex(HEAD - 600), logIndex: '0x0' }])), [C]: ok([]) },
    }, req(100, 'eth_getLogs', FULL)),
    // Reverts are member failures: with an untried endpoint Direct asks it
    // and its revert is the answer; with none, an earlier source's revert
    // survives as the last error; one answering member beats the reverts.
    scenario('boundary-quorum-reverts-direct-untried', `${D_}: Quorum, errors`, {
      ...w(1, net(['quorum', 'direct']), [A, B, C, D]),
      rpc: Object.fromEntries([A, B, C, D].map((u) => [u, revert])),
    }, req(1, 'eth_call', [{ to: '0xabc', data: '0x12345678' }, 'latest'])),
    scenario('boundary-quorum-reverts-colibri-revert-survives', `${D_}: Colibri; Direct, Gnosis`, {
      ...w(100, net(['colibri', 'quorum', 'direct']), ABC),
      colibri: { error: { message: 'execution reverted', code: 3, data: revert.error.data } },
      rpc: Object.fromEntries(ABC.map((u) => [u, revert])),
    }, req(100, 'eth_call', [{ to: '0xabc', data: '0x12345678' }, 'latest'])),
    scenario('boundary-quorum-reverts-one-answer', `${D_}: Quorum, errors`, {
      ...w(1, net(['quorum', 'direct']), ABC),
      rpc: { [A]: revert, [B]: revert, [C]: ok('0x01', 20) },
    }, req(1, 'eth_call', [{ to: '0xabc', data: '0x12345678' }, 'latest'], { include_trust: true })),
    // Fee quotes and their downgrades.
    ...[
      ['priority-equals-gas-price', { gasPriceWei: '100', maxPriorityFeePerGasWei: '100' }],
      ['priority-zero', { gasPriceWei: '100', maxPriorityFeePerGasWei: '0' }],
      ['priority-over-gas-price', { gasPriceWei: '100', maxPriorityFeePerGasWei: '101' }],
      ['priority-negative', { gasPriceWei: '100', maxPriorityFeePerGasWei: '-1' }],
      ['no-priority', { gasPrice: '100' }],
    ].map(([label, payload]) => scenario(`boundary-fee-myotis-${label}`, `${D_}: Fee quotes`, {
      ...w(1, net(['myotis', 'direct']), [RPC]),
      myotis: myotisOn(1, { fee: { payload } }),
    }, fee(1))),
    scenario('boundary-fee-myotis-non-positive-gas-price', `${D_}: Fee quotes`, {
      ...w(1, net(['myotis', 'colibri', 'direct']), [RPC]),
      myotis: myotisOn(1, { fee: { payload: { gasPriceWei: '0', maxPriorityFeePerGasWei: '0' } } }),
      colibri: { rules: [{ when: { method: 'eth_gasPrice' }, then: ok('0x5') }], else: ok('0x1') },
    }, fee(1)),
    scenario('boundary-fee-quorum-priority-disagrees', `${D_}: Fee quotes`, {
      ...w(1, net(['quorum', 'direct']), ABC),
      rpc: Object.fromEntries(ABC.map((u, i) => [u, { rules: [{ when: { method: 'eth_gasPrice' }, then: ok('0x3b9aca00') }], else: ok(hex(i + 1)) }])),
    }, fee(1)),
    scenario('boundary-fee-direct-priority-unparseable', `${D_}: Fee quotes`, {
      ...w(1, net(['direct']), [A, B]),
      rpc: {
        [A]: { rules: [{ when: { method: 'eth_gasPrice' }, then: ok('0x10') }], else: ok('-0x1') },
        [B]: { rules: [{ when: { method: 'eth_gasPrice' }, then: ok('0x10') }], else: ok('0x11') },
      },
    }, fee(1)),
    scenario('boundary-fee-direct-gas-price-fails-first', `${D_}: Fee quotes`, {
      ...w(1, net(['direct']), [A, B]),
      rpc: {
        [A]: { status: 503, text: 'unavailable' },
        [B]: { rules: [{ when: { method: 'eth_gasPrice' }, then: ok('0x3b9aca00') }], else: { fail: 'fetch failed' } },
      },
    }, fee(1)),
    scenario('boundary-fee-all-sources-unavailable', `${D_}: Fee quotes`, {
      chains: { 1: chainEntry(net(['myotis', 'colibri', 'quorum', 'direct']), [], []) },
      myotis: { 1: { ready: false } },
    }, fee(1)),
    // Broadcasts: Direct re-sends the same bytes on any error, and the
    // last error wins, a lost reply's included.
    scenario('boundary-broadcast-resends-until-accepted', `${D_}: Broadcast`, sendWorld(ABC, {
      [A]: nodeRefusal('nonce too low: next nonce 8, tx nonce 7'),
      [B]: nodeRefusal('insufficient funds for gas * price + value'),
      [C]: ok(tx.mainnet.hash),
    }), send(1, tx.mainnet.raw)),
    scenario('boundary-broadcast-last-error-wins', `${D_}: Broadcast`, sendWorld([A, B], {
      [A]: nodeRefusal('already known'),
      [B]: { status: 429, text: '' },
    }), send(1, tx.mainnet.raw)),
    ...[['already-known', 'already known'], ['nonce-too-low', 'nonce too low: next nonce 8, tx nonce 7']].map(([label, message]) => scenario(
      `boundary-broadcast-lost-reply-then-${label}`, `${D_}: Broadcast`, sendWorld([A, B], {
        [A]: { hang: true },
        [B]: nodeRefusal(message),
      }), send(1, tx.mainnet.raw))),
    scenario('boundary-broadcast-refusal-after-ambiguous', `${D_}: Broadcast, Refusals`, sendWorld([A, B], {
      [A]: { status: 502, text: 'bad gateway' },
      [B]: nodeRefusal('replacement transaction underpriced'),
    }), send(1, tx.mainnet.raw)),
    scenario('boundary-broadcast-mined-bytes-nonce-too-low', `${D_}: Broadcast`, sendWorld([A, B], {
      [A]: nodeRefusal('nonce too low: next nonce 8, tx nonce 7'),
      [B]: nodeRefusal('nonce too low'),
    }), send(1, tx.mainnet.raw)),
    scenario('boundary-broadcast-other-hash-accepted', `${D_}: Broadcast, Attempts`, sendWorld([A], { [A]: ok(`0x${'ab'.repeat(32)}`) }), send(1, tx.mainnet.raw)),
    scenario('boundary-broadcast-cancel-after-send', `${D_}: Broadcast`, sendWorld([A, B], { [A]: { hang: true }, [B]: ok(tx.mainnet.hash) }),
      send(1, tx.mainnet.raw, { abort_at: 1000 })),
    scenario('boundary-broadcast-myotis-uncertain-in-band', `${D_}: Broadcast classes`, {
      ...w(100, net(['myotis', 'direct']), [A]),
      myotis: myotisOn(100, { broadcast: { throws: 'uncertain' } }),
    }, send(100, tx.gnosis.raw)),
    scenario('boundary-broadcast-myotis-odd-payload', `${D_}: Broadcast classes`, {
      ...w(100, net(['myotis', 'direct']), [A]),
      myotis: myotisOn(100, { broadcast: { payload: { txHash: tx.gnosis.hash, status: 'revert' } } }),
    }, send(100, tx.gnosis.raw)),
    scenario('boundary-broadcast-myotis-not-sent-then-direct', `${D_}: Broadcast classes`, {
      ...w(100, net(['myotis', 'direct']), [A]),
      myotis: myotisOn(100, { broadcast: { throws: 'queue_deadline', delay: 10_000 } }),
      rpc: { [A]: ok(tx.gnosis.hash) },
    }, send(100, tx.gnosis.raw)),
    scenario('boundary-broadcast-myotis-not-running-last-error', `${D_}: Broadcast classes`, {
      ...w(100, net(['myotis', 'direct']), []),
      myotis: myotisOn(100, { broadcast: { throws: 'not_running' } }),
    }, send(100, tx.gnosis.raw)),
    scenario('boundary-broadcast-unknown-broadcaster', `${D_}: Broadcast`, {
      chains: { 1: chainEntry({ access: { broadcastOrder: ['quorum', 'colibri'] } }, [A]) },
    }, send(1, tx.mainnet.raw)),
    // The adaptive bypass.
    scenario('boundary-adaptive-quorum-deadline-not-a-timeout', `${D_}: Adaptive bypass`, {
      ...w(1, net(['quorum', 'colibri', 'direct']), ABC),
      rpc: Object.fromEntries(ABC.map((u) => [u, { hang: true }])),
      colibri: ok('0xverified'),
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], swap), req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], swap)),
    scenario('boundary-adaptive-capacity-survives-success', `${D_}: Adaptive bypass`, {
      ...w(1, net(['colibri', 'direct']), [RPC]),
      colibri: [{ error: { message: 'execution gas limit reached' } }, ok('0x2a', 20)],
      rpc: { [RPC]: ok('0xrpc') },
    }, [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], swap), req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], swap)],
    req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], swap)),
    scenario('boundary-adaptive-route-target-case', `${D_}: Adaptive bypass`, {
      ...w(1, net(['colibri', 'direct']), [RPC]),
      colibri: { error: { message: 'out of gas' } },
      rpc: { [RPC]: ok('0xrpc') },
    }, req(1, 'eth_call', [{ to: ` 0x${'AB'.repeat(20)}`, data: '0x01' }, 'latest'], swap),
    req(1, 'eth_call', [{ to: `0x${'ab'.repeat(20)}`, data: '0x02' }, 'latest'], swap),
    req(1, 'eth_call', [{ to: `0x${'ab'.repeat(20)}`, data: '0x03' }, 'latest'], { origin: '  https://swap.example  ' }),
    req(1, 'eth_call', [{ to: `0x${'ab'.repeat(20)}`, data: '0x04' }, 'latest'], { origin: 'https://Swap.example' })),
    // isCapacityFailure(error): an error's own failureKind first, then the
    // pattern on safeErrorMessage's text, not the raw message: whitespace
    // runs collapse, long hex is elided, and the text is cut at 500 units.
    ...[
      ['boundary-adaptive-capacity-whitespace', { message: 'out  of gas' }],
      ['boundary-adaptive-capacity-past-500-units', { message: `${'x'.repeat(510)} out of gas` }],
      ['boundary-adaptive-capacity-hex-elided', { message: `0x${'ab'.repeat(300)} out of gas` }],
      ['boundary-adaptive-capacity-failure-kind', { message: 'prover busy', failureKind: 'capacity' }],
    ].map(([id, error]) => scenario(id, `${D_}: Adaptive bypass, capacity`, {
      ...w(1, net(['colibri', 'direct']), [RPC]),
      colibri: { error },
      rpc: { [RPC]: ok('0xrpc') },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], swap), req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], swap))),
    scenario('boundary-origin-not-interactive', `${D_}: Adaptive bypass, origin`, {
      ...w(1, net(['colibri', 'direct']), [RPC]),
      colibri: ok('0xverified', 3000),
      rpc: { [RPC]: ok('0xrpc') },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { origin: 'https://swap.example\u0001' }),
    req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { origin: `https://${'x'.repeat(2041)}` }),
    req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { origin: '   ' })),
    // Myotis' slot.
    scenario('boundary-myotis-waiter-abandons-at-deadline', `${D_}: Myotis, admission`, {
      ...w(1, net(['myotis', 'direct']), [RPC]),
      myotis: myotisOn(1, { call_tx: [{ payload: { resultHex: '0x1' }, delay: 3000 }, { payload: { resultHex: '0x3' } }] }),
      rpc: { [RPC]: ok('0xrpc') },
    }, [req(1, 'eth_call', [{ to: target(0) }, 'latest']), req(1, 'eth_call', [{ to: target(1) }, 'latest'], { ...swap, at: 5 })],
    req(1, 'eth_call', [{ to: target(2) }, 'latest'])),
    scenario('boundary-myotis-budget-covers-wait', `${D_}: Myotis, admission`, {
      ...w(1, net(['myotis', 'direct']), [RPC]),
      myotis: myotisOn(1, { call_tx: [{ payload: { resultHex: '0x1' }, delay: 1500 }, { payload: { resultHex: '0x2' }, delay: 800 }] }),
      rpc: { [RPC]: ok('0xrpc') },
    }, [req(1, 'eth_call', [{ to: target(0) }, 'latest']), req(1, 'eth_call', [{ to: target(1) }, 'latest'], swap)]),
    scenario('boundary-myotis-unsupported-method-holds-slot', `${D_}: Methods and sources; open question 4`, {
      ...w(1, net(['myotis', 'direct']), [RPC]),
      myotis: myotisOn(1, { call_tx: { payload: { resultHex: '0x1' }, delay: 300 } }),
      rpc: { [RPC]: ok('0x10') },
    }, [req(1, 'eth_call', [{ to: target(0) }, 'latest']), req(1, 'eth_blockNumber', [], { at: 5 })]),
    // The adapter's own errors, each the last error with its text and code.
    // The child process gives up on a read 10 s after it is asked: while
    // still queued (queue deadline) or once dispatched (caller deadline).
    // The source's budget here is 15 s, so the child's deadline comes first.
    ...[
      ['not-running', 'not_running', 0], ['state-changed', 'state_changed', 0], ['queue-full', 'queue_full', 0],
      ['queue-deadline', 'queue_deadline', 10_000], ['caller-deadline', 'caller_deadline', 10_000],
    ].map(([label, throws, delay]) => scenario(
      `boundary-myotis-${label}-last-error`, `${D_}: Myotis read outcomes`, {
        ...w(1, net(['myotis', 'quorum'], { k: 3, m: 2, timeoutMs: 15_000 }), [RPC]),
        myotis: myotisOn(1, { call_tx: { throws, delay } }),
      }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], settles(delay)))),
    scenario('boundary-myotis-unexpected-response-last-error', `${D_}: Myotis, outcomes`, {
      ...w(1, net(['myotis', 'quorum']), [RPC]),
      myotis: myotisOn(1, { call_tx: { payload: { status: 'ok' } } }),
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
    scenario('boundary-myotis-readiness-sampled-live', `${D_}: Myotis; deviation myotis-readiness`, {
      ...w(1, net(['myotis', 'direct']), [RPC]),
      myotis: myotisOn(1, { call_tx: { throws: 'state_changed', delay: 10 } }),
      rpc: { [RPC]: ok('0xrpc') },
    }, { events: [{ at: 5, myotis: { 1: { ready: false } } }], calls: [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])] },
    req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
    // Colibri.
    scenario('boundary-colibri-global-limit', `${D_}: Colibri, admission`, {
      ...w(1, net(['colibri', 'direct']), [RPC]),
      colibri: { hang: true },
      rpc: { [RPC]: ok('0xrpc') },
    }, Array.from({ length: 9 }, (_, i) => req(1, 'eth_call', [{ to: target(i), data: '0x1234' }, 'latest'], swap))),
    scenario('boundary-colibri-errors-fall-through', `${D_}: Colibri`, {
      ...w(1, net(['colibri', 'direct']), [RPC]),
      colibri: [{ error: { message: 'proof verification failed', code: -32000, data: '0x01' } }, { error: { message: 'Colibri prover timed out' } }],
      rpc: { [RPC]: ok('0xrpc') },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest']), req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
    scenario('boundary-colibri-revert-last-error', `${D_}: Colibri`, {
      ...w(1, net(['colibri', 'quorum']), [RPC]),
      colibri: { error: { message: 'execution reverted', code: 3, data: '0x08c379a0' } },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
    // Configuration.
    scenario('boundary-registry-change-mid-request', `${D_}: deviation config-change`, {
      ...w(1, net(['quorum', 'direct']), [A, B, C, D]),
      rpc: { [A]: { hang: true }, [B]: { hang: true }, [C]: { hang: true }, [D]: ok('0xrpc'), [url('e')]: ok('0xnew') },
    }, { events: [{ at: 1000, chains: { 1: chainEntry(net(['quorum', 'direct']), [A, B, C, url('e')]) } }], calls: [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])] }),
    scenario('boundary-order-duplicates-and-unknown', `${D_}: deviation order-validation`, {
      chains: { 1: chainEntry(net(['colibri', 'nope', 'colibri', 'direct']), [], []) },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
    {
      // k, m and the timeout as the router clamps them: k=0 is 3, m=5 is
      // k, 100 ms is 500; strings count as their numbers.
      ...scenario('boundary-quorum-clamps', `${D_}: Configuration; deviation quorum-clamps`, w(1, net(['quorum']), ABC)),
      steps: [
        { world: { chains: { 1: chainEntry(net(['quorum'], { k: 0, m: 5, timeoutMs: 100 }), ABC, [PROVER]) }, rpc: Object.fromEntries(ABC.map((u) => [u, ok('0x1', 400)])) }, calls: [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { include_trust: true })] },
        { world: { chains: { 1: chainEntry(net(['quorum'], { k: 0, m: 5, timeoutMs: 100 }), ABC, [PROVER]) }, rpc: Object.fromEntries(ABC.map((u) => [u, ok('0x1', 600)])) }, calls: [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])] },
        { world: { chains: { 1: chainEntry(net(['quorum'], { k: '2', m: 'x', timeoutMs: 'abc' }), ABC, [PROVER]) }, rpc: Object.fromEntries(ABC.map((u) => [u, ok('0x1', 4000)])) }, calls: [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { include_trust: true })] },
      ],
    },
    // Trust labels: a user's own endpoint, a keyed one, and an endpoint URL
    // that doesn't parse (its host '' is left out of every list).
    {
      ...scenario('boundary-direct-user-configured-trust', `${D_}: Direct; Replies, endpoint references`, {
        ...w(1, net(['direct']), [A, B]),
        sourceList: [{ id: 'mine', builtin: false }, { id: 'keyed', builtin: false, keyed: true }, { id: 'pub', builtin: true }],
        rpc: { [A]: ok('0x1'), [B]: ok('0x2') },
      }),
      steps: [
        [[{ id: 'mine', coverage: { 1: A } }], [A, B]],
        [[{ id: 'keyed', keyed: true, coverage: { 1: A } }], [A, B]],
        [[{ id: 'pub', coverage: { 1: A } }], [A, B]],
        [[{ id: 'mine', coverage: { 1: B } }], [B, A]],
      ].map(([sources, endpoints]) => ({
        world: { chains: { 1: chainEntry(net(['direct']), endpoints, [PROVER], { sources }) } },
        calls: [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { include_trust: true })],
      })),
    },
    scenario('boundary-unparseable-endpoint-host', `${D_}: Replies, endpointHost`, {
      ...w(1, net(['quorum', 'direct']), [A, B, 'not a url']),
      rpc: { [A]: ok('0x1'), [B]: ok('0x1') },
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { include_trust: true })),
    {
      ...scenario('boundary-colibri-trust', `${D_}: Colibri, trust`, { ...w(1, net(['colibri']), []), colibri: ok('0x2a') }),
      steps: [
        [{ zkProof: false }, [PROVER]],
        [{}, ['https://prover.example:8443/zk', 'https://second.example']],
        [{ zkProof: null }, ['not a url']],
      ].map(([extra, prover]) => ({
        world: { chains: { 1: chainEntry(net(['colibri'], undefined, extra), [], prover) } },
        calls: [req(1, 'eth_call', [{ to: '0xabc' }, 'latest'], { include_trust: true })],
      })),
    },
    // The recorder keeps every value apart from its own encodings: a result
    // or error data that happens to look like one, and a missing result.
    {
      ...scenario('boundary-result-literal-undefined-tag', `${D_}: Replay, recorded`, direct()),
      steps: [
        rpcBody('{"jsonrpc":"2.0","id":1,"result":{"$undefined":true}}'),
        rpcBody('{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":{"$undefined":true}}}'),
      ],
    },
    {
      ...scenario('boundary-result-literal-repeat-tag', `${D_}: Replay, recorded`, direct()),
      steps: [
        rpcBody('{"jsonrpc":"2.0","id":1,"result":{"$repeat":{"head":"","unit":"x","count":2,"tail":""}}}'),
        rpcBody('{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":{"$repeat":{"head":"","unit":"x","count":2,"tail":""}}}}'),
      ],
    },
    {
      ...scenario('boundary-result-empty-body', `${D_}: Answers, undefined`, direct()),
      steps: [rpcBody('{}'), rpcBody('{"jsonrpc":"2.0","id":1,"result":null}'), rpcBody('{"jsonrpc":"2.0","id":1,"error":{"message":"m"}}')],
    },
    // Nesting: the body is one level, so a result of 511 nested arrays is
    // 512 in all. The reference reads any depth; the core refuses a body
    // deeper than 512 (deviation json-depth).
    scenario('boundary-json-depth-512', `${D_}: Answers, depth`, {
      ...w(1, net(['quorum']), ABC),
      rpc: Object.fromEntries(ABC.map((u) => [u, { body: `{"jsonrpc":"2.0","id":1,"result":${nested(511)}}` }])),
    }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
    {
      ...scenario('boundary-json-depth-513', `${D_}: Answers, depth; deviation json-depth`, {
        ...w(1, net(['quorum']), ABC),
        rpc: Object.fromEntries(ABC.map((u) => [u, { body: `{"jsonrpc":"2.0","id":1,"result":${nested(512)}}` }])),
      }, req(1, 'eth_call', [{ to: '0xabc' }, 'latest'])),
      deviation: 'json-depth',
    },
    // Agreement is stableValue's: pairs that agree and pairs that don't,
    // a answering first (its value is the one returned), b 10 ms later.
    agreement('boundary-agreement-duplicate-keys', [
      ['{"a":1,"a":2}', '{"a":2}'],
      [`{"a":1,"${U('0061')}":2}`, '{"a":2}'],
      ['{"a":1,"a":2}', '{"a":1}'],
    ]),
    agreement('boundary-agreement-number-spellings', [
      ['1e2', '100'],
      ['1E+2', '100.0'],
      ['-0', '0'],
      ['9007199254740993', '9007199254740992'],
      ['0.1', '0.10000000000000001'],
      ['1e400', 'null'],
      ['1', '"1"'],
    ]),
    agreement('boundary-agreement-proto-key', [
      ['{"__proto__":1,"b":2}', '{"b":2,"__proto__":1}'],
      ['{"__proto__":{"a":1}}', '{"a":1}'],
      ['{"__proto__":1}', '{}'],
    ]),
    agreement('boundary-agreement-lone-surrogates', [
      [`"${U('d800')}"`, `"${U('D800')}"`],
      [`"${U('d800')}"`, `"${U('fffd')}"`],
      [`{"${U('d800')}":1}`, `{"${U('fffd')}":1}`],
      [`"${U('d83d')}${U('de00')}"`, '"\u{1F600}"'],
    ]),
    scenario('boundary-unsupported-requests', `${D_}: Methods and sources`, w(1, net(['direct']), [RPC]),
      req(1, 'eth_sendTransaction', [{}]), req(999, 'eth_blockNumber', []), fee(999), send(999, tx.mainnet.raw)),
  ];
}

/**
 * Signed transactions for the broadcasts, from the first test wallet (see
 * signing.json): `raw` and its keccak-256 `hash`. ethers signs
 * deterministically (RFC 6979), so the bytes never change.
 */
function signedTransactions(ethers, privateKey) {
  const wallet = new ethers.Wallet(privateKey);
  const sign = (fields) => {
    const tx = ethers.Transaction.from(fields);
    tx.signature = wallet.signingKey.sign(tx.unsignedHash);
    return { raw: tx.serialized, hash: tx.hash };
  };
  const to = '0x' + '11'.repeat(20);
  return {
    mainnet: sign({ type: 2, chainId: 1, nonce: 7, gasLimit: 21000n, maxFeePerGas: 30_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n, to, value: 10n ** 15n }),
    gnosis: sign({ type: 2, chainId: 100, nonce: 7, gasLimit: 21000n, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n, to, value: 10n ** 15n }),
  };
}

/** Every scenario, in file order. */
function scenarioDefinitions(ethers, privateKey) {
  const tx = signedTransactions(ethers, privateKey);
  const scenarios = [
    ...routerScenarios(tx),
    ...cancellationScenarios(tx),
    ...antScanScenarios(),
    ...antIndexScenarios(),
    ...bridgeRouterScenarios(),
    ...blockscoutScenarios(),
    ...boundaryScenarios(ethers, tx),
  ];
  const ids = new Set();
  for (const { id } of scenarios) {
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id)) throw new Error(`scenario id ${id} is not kebab-case`);
    if (ids.has(id)) throw new Error(`scenario id ${id} is used twice`);
    ids.add(id);
  }
  return scenarios;
}

function loadFakeTimers(checkout) {
  return Module.createRequire(path.join(checkout, 'package.json'))('@sinonjs/fake-timers');
}

async function buildChainReplay(checkout, ethers, privateKey, meta) {
  const FakeTimers = loadFakeTimers(checkout);
  const scenarios = [];
  for (const definition of scenarioDefinitions(ethers, privateKey)) scenarios.push(await runScenario(checkout, FakeTimers, definition));
  return {
    meta,
    encodings: {
      json: 'every value the reference produced or was given (results, thrown properties, operation params and answers, call params) is JSON text in a string field: <name>_json, or json in an entry; -0 is written -0 and ±Infinity ±1e400, which JSON.parse reads back as such; lone surrogates are escapes',
      undefined: 'a present undefined is a field of its own, <name>_undefined: true (undefined: true in an entry), never a value',
      entries: 'an object the router returned or threw is a list of { key, json | json_repeat | undefined } in property order',
      repeat: 'a text over 64 KiB is <field>_repeat: { head, unit, count, tail, length, sha256 }, the text being head + unit × count + tail (length in UTF-16 units, sha256 of its UTF-8)',
      plain: 'worlds, steps, state tables and the frames of the records are plain JSON the harness writes itself; a world\'s result_repeat is a repeat macro for a result string',
      times: `virtual milliseconds after the scenario's start (Date.now() ${EPOCH}); in state tables 0 stays 0, the reference's unset`,
      rpc_body: 'the request body as sent, with its id (Date.now()) replaced by 0',
      expect_settle_ms: 'on a call: how long after its start the ported test says it settles (expect_settle_max_ms: at most); generation fails otherwise',
    },
    scenarios,
  };
}

module.exports = {
  buildChainReplay, runScenario, scenarioDefinitions, loadFakeTimers, signedTransactions,
  jsonText, jsonField, entriesOf, recordError, recordValue, textField, plain, repeatOf, EPOCH,
};
