'use strict';

// Replay vectors for design 0004: the pinned resolvers (ens-resolver.js and
// tezos-domains-resolver.js), run whole in a scripted world. Every scenario
// gets a fresh module (no shared cache, anchor or quarantine), seeded
// Math.random, the reference's own fake timers, no ambient resolver
// environment, and a declarative script for every endpoint, gateway and
// verifier. Undeclared hosts and unscripted requests fail the generation.
//
// Each scenario records its input (seed, world, steps), every result with
// its settlement time, and every I/O request: virtual start time, full
// params, HTTP batch, end time and outcome (answered, cancelled, or still
// open when the scenario ends), and the answer it got: so a replay serves
// the recorded answer to the matching request instead of re-creating the
// world. Verifier adapters' whole operations are recorded too
// (`verified-op`), next to the raw calls they make. Present-`undefined` keys are kept as
// {"$undefined":true}.
//
// Deviation vectors (`deviation`, `patches`) run the reference patched in
// memory to do what the core does at one of design 0004's bounds, so the
// core reproduces them exactly like any other scenario. Each records its
// patches (the edits themselves) and the unpatched reference's results
// (`unpatched`); generation fails unless the patches change the results or
// the I/O. `world.bounds` lowers a bound for both sides.

const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const vm = require('node:vm');
const { AsyncLocalStorage } = require('node:async_hooks');
const { EventEmitter } = require('node:events');

const EPOCH = 1_760_000_000_000;
// Virtual time one step may take before it counts as pending.
const MAX_STEP_MS = 10 * 60_000;
// Environment the resolvers read: cleared while a scenario runs.
const RESOLVER_ENV = ['ETH_RPC', 'TEZOS_RPC', 'C4_DISABLE_NATIVE'];
const WNS = '0x0000000000696760e15f265e828db644a0c242eb';
const GNS = '0x9d51d507bc7264d4fe8ad1cf7fe191933a0a81d6';
// Inner and NameNFT selectors: contenthash(bytes32), addr(bytes32),
// addr(bytes32,uint256), reverseResolve(address).
const SELECTORS = { '0xbc1c58d1': 'contenthash', '0x3b3b57de': 'addr', '0xf1cb7e06': 'addr-multicoin', '0x9af8b7aa': 'reverse' };
const HEAD = 20_000_000;
const UR = '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe';
const GATEWAY_FLAGS = ['redirect', 'credentials', 'useSessionCookies', 'cache', 'bypassCustomProtocolHandlers'];

/** mulberry32, the same seeded generator for every run. */
function seeded(seed) {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** JSON with present-undefined keys kept as markers. */
// Design 0004's bounds, as the core applies them. A deviation vector may
// lower one in `world.bounds` so that its boundary fits a small vector; the
// core reads the same field.
const BOUNDS = {
  ccipUrls: 32,
  answerBytes: 720 * 1024,
  replyHex: 8192,
  prefetches: 32,
  messageBytes: 1024 * 1024,
  replyBytes: 960 * 1024,
  cacheBytes: 8 * 1024 * 1024,
  decodeBytes: 4 * 1024 * 1024,
  sessions: 32,
  callers: 256,
  callersPerSession: 64,
  deadlineMs: 120_000,
};

// The core's frame check (deviation `request-size`): a request's payload
// strings, serialized, plus 4 KiB for its envelope, within the frame.
// Bytes, as the core measures UTF-8.
const FITS = `function __fits(parts, limit) {
  return parts.reduce((n, part) => n + Buffer.byteLength(JSON.stringify(part), 'utf8'), 0) + 4096 <= limit;
}`;

// A result as the core holds it, for measuring. Where a result names
// endpoints (trust.agreed, dissented, queried and prover; groups[].urls),
// the core holds { ref: endpoint } in place of the host or URL main
// publishes. Only those paths: record data is left as it is. `refOf` gives
// the endpoint behind a published string, or undefined.
function __toCore(value, refOf) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  const one = (text) => {
    const endpoint = typeof text === 'string' ? refOf(text) : undefined;
    return endpoint === undefined ? text : { ref: endpoint };
  };
  const list = (items) => (Array.isArray(items) ? items.map(one) : items);
  const core = { ...value };
  if (value.trust && typeof value.trust === 'object' && !Array.isArray(value.trust)) {
    const trust = { ...value.trust };
    for (const key of ['agreed', 'dissented', 'queried']) if (key in trust) trust[key] = list(trust[key]);
    if ('prover' in trust) trust.prover = one(trust.prover);
    core.trust = trust;
  }
  if (Array.isArray(value.groups)) {
    core.groups = value.groups.map((group) => (group && typeof group === 'object' && 'urls' in group ? { ...group, urls: list(group.urls) } : group));
  }
  return core;
}

// The serialized size of a result as the core measures it. Results
// publish hosts (ENS, Tezos conflict groups), so hostOf records the
// endpoint URL behind each one: a host that two URLs produced can't be
// told apart, and the patch refuses to measure it. Tezos' agreed list
// publishes whole URLs, which map directly.
const CORE_SIZE = `${__toCore.toString()}
var __hostSources = new Map();
function __noteHost(host, url) {
  if (!__hostSources.has(host)) __hostSources.set(host, new Set());
  __hostSources.get(host).add(url);
}
var __ambiguousHost = null;
function __refOf(host) {
  const urls = __hostSources.get(host);
  if (!urls) return undefined;
  if (urls.size > 1) {
    // Recorded as well as thrown: the resolver may catch the throw.
    __ambiguousHost = host;
    throw new Error('core size: one host from several endpoint URLs');
  }
  return [...urls][0];
}
// \`endpoints\`: those published as whole URLs (Tezos' agreed list).
function __coreSize(value, endpoints = []) {
  const refOf = (text) => (endpoints.includes(text) ? text : __refOf(text));
  return Buffer.byteLength(JSON.stringify(__toCore(value, refOf)), 'utf8');
}
module.exports.__coreSize = __coreSize;
module.exports.__ambiguousHost = () => __ambiguousHost;`;
// Deviation `cache-bytes`: a cache's bytes (UTF-8 keys, results as the
// core holds them), evicting as capCache does.
const CAP_BYTES = `function __capBytes(cache, limit, endpoints = []) {
  const size = (key, entry) => Buffer.byteLength(key, 'utf8') + __coreSize(entry.result, endpoints);
  let bytes = 0;
  for (const [key, entry] of cache) bytes += size(key, entry);
  const now = Date.now();
  for (const [key, entry] of cache) {
    if (bytes <= limit) return;
    if (entry.expiresAt <= now) {
      cache.delete(key);
      bytes -= size(key, entry);
    }
  }
  for (const [key, entry] of cache) {
    if (bytes <= limit) return;
    cache.delete(key);
    bytes -= size(key, entry);
  }
}`;
// Tezos' result cache, where its resolver inserts.
const TEZOS_CACHE = '  resultCache.set(normalized, { result, expiresAt: Date.now() + cacheDuration(result) });\n  capCache(resultCache);\n';
const HOST_SOURCES = ['function hostOf(url) {\n  try { return new URL(url).host; }\n  catch { return url; }\n}\n',
  'function hostOf(url) {\n  const host = __hostOf(url);\n  __noteHost(host, url);\n  return host;\n}\nfunction __hostOf(url) {\n  try { return new URL(url).host; }\n  catch { return url; }\n}\n'];
// The legs' CCIP deps, shared by the patches that bound it.
const LEG_DEPS = 'var __legDeps = {};';

// The core's RFC 3339 reading (deviation `tezos-expiry`), as
// fc_naming::session::tezos::parse_rfc3339 implements it: a full date, or a
// date-time with `T`, seconds, an optional fraction and `Z` or ±hh:mm.
const PARSE_RFC3339 = `function __parseRfc3339(text) {
  const digits = (part, length) => (part.length === length && /^[0-9]+$/.test(part) ? Number(part) : null);
  const t = text.indexOf('T');
  const date = (t < 0 ? text : text.slice(0, t)).split('-');
  if (date.length !== 3) return Number.NaN;
  const [year, month, day] = [digits(date[0], 4), digits(date[1], 2), digits(date[2], 2)];
  if (year === null || month === null || day === null || month < 1 || month > 12) return Number.NaN;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = month === 2 ? (leap ? 29 : 28) : [4, 6, 9, 11].includes(month) ? 30 : 31;
  if (day < 1 || day > days) return Number.NaN;
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * ((month + 9) % 12) + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  let ms = (era * 146097 + doe - 719468) * 86400000;
  if (t < 0) return ms;
  const time = text.slice(t + 1);
  let clock;
  let offset = 0;
  if (time.endsWith('Z')) {
    clock = time.slice(0, -1);
  } else {
    const at = Math.max(time.lastIndexOf('+'), time.lastIndexOf('-'));
    if (at < 0) return Number.NaN;
    clock = time.slice(0, at);
    const hm = time.slice(at + 1).split(':');
    if (hm.length !== 2) return Number.NaN;
    const [oh, om] = [digits(hm[0], 2), digits(hm[1], 2)];
    if (oh === null || om === null || oh > 23 || om > 59) return Number.NaN;
    offset = (time[at] === '-' ? -1 : 1) * (oh * 3600000 + om * 60000);
  }
  const dot = clock.indexOf('.');
  const fields = (dot < 0 ? clock : clock.slice(0, dot)).split(':');
  if (fields.length !== 3) return Number.NaN;
  const [h, mi, sec] = fields.map((field) => digits(field, 2));
  if (h === null || mi === null || sec === null) return Number.NaN;
  if (h > 24 || mi > 59 || sec > 59 || (h === 24 && (mi > 0 || sec > 0))) return Number.NaN;
  let millis = 0;
  if (dot >= 0) {
    const fraction = clock.slice(dot + 1);
    if (!/^[0-9]+$/.test(fraction)) return Number.NaN;
    millis = Number((fraction + '000').slice(0, 3));
  }
  ms += (h * 3600 + mi * 60 + sec) * 1000 + millis;
  return ms - offset;
}`;

// Deviation patches (design 0004, Deviations): the reference changed in
// memory to do what the core does at one of its bounds. A deviation
// vector is the patched reference's trace, which the core reproduces
// exactly; it records its patches, and the unpatched results it differs
// from. `source` edits a module (each `find` must occur exactly once;
// `append` adds helpers at the module's end, where function declarations
// still hoist); `harness` patches main's side, played by this harness.
const PATCHES = {
  'ccip-urls': (b) => ({
    text: `A quorum leg's CCIP-Read round tries the first ${b.ccipUrls} gateway URLs.`,
    source: {
      'ens-resolver.js': {
        edits: [['ccipReadFetch({ to: sender }, callData, urls, ccipSignal', `ccipReadFetch({ to: sender }, callData, __firstUrls(urls, ${b.ccipUrls}), ccipSignal`]],
        append: ['function __firstUrls(urls, n) {\n  return { *[Symbol.iterator]() { for (let i = 0; i < Math.min(urls.length, n); i += 1) yield urls[i]; } };\n}'],
      },
    },
  }),
  'reply-shortening': (b) => ({
    text: `Conflict groups' resolvedData and unsupported results' contentHash longer than ${b.replyHex} characters keep their first and last ${b.replyHex / 2}.`,
    source: {
      'ens-resolver.js': {
        edits: [
          ['groups.push({ resolvedData: bytes, urls', `groups.push({ resolvedData: __shortenHex(bytes, ${b.replyHex}), urls`],
          ['contentHash: consensus.resolvedData,', `contentHash: __shortenHex(consensus.resolvedData, ${b.replyHex}),`],
          ['contentHash: innerBytes,', `contentHash: __shortenHex(innerBytes, ${b.replyHex}),`],
        ],
        append: ['function __shortenHex(hex, max) {\n  return typeof hex === \'string\' && hex.length > max ? hex.slice(0, max / 2) + hex.slice(hex.length - max / 2) : hex;\n}'],
      },
    },
  }),
  'tezos-expiry': () => ({
    text: 'Tezos expiries are read as RFC 3339; anything else is unreadable (NaN), as an unparsable date is today.',
    source: {
      'tezos-domains-resolver.js': {
        edits: [
          ['const expiresAt = expiry ? Date.parse(expiry) : Number.NaN;', 'const expiresAt = expiry ? __parseRfc3339(expiry) : Number.NaN;'],
          ["const expiryMs = Date.parse(result.expiry || '');", "const expiryMs = __parseRfc3339(result.expiry || '');"],
        ],
        append: [PARSE_RFC3339],
      },
    },
  }),
  'response-caps': (b) => ({
    text: `Answer bodies over ${b.answerBytes} bytes fail: an RPC answer as a network error (a provider failure), a quorum leg's gateway answer as too large (the next gateway), a Tezos node's as over the size limit (a failed endpoint). Verifier adapters' own CCIP keeps its 4 MiB cap.`,
    harness: ['rpc-answer-cap'],
    source: {
      'ens/ccip-fetch.js': {
        edits: [
          ["if (Number(response.headers.get('content-length')) > CCIP_MAX_RESPONSE_BYTES) {", "if (Number(response.headers.get('content-length')) > (deps.maxResponseBytes ?? CCIP_MAX_RESPONSE_BYTES)) {"],
          ['if (size > CCIP_MAX_RESPONSE_BYTES) {', 'if (size > (deps.maxResponseBytes ?? CCIP_MAX_RESPONSE_BYTES)) {'],
        ],
        append: [],
      },
      'ens-resolver.js': { edits: [[', ccipSignal);', ', ccipSignal, __legDeps);']], append: [LEG_DEPS, `__legDeps.maxResponseBytes = ${b.answerBytes};`] },
      'tezos-domains-resolver.js': { edits: [['const MAX_RPC_RESPONSE_BYTES = 5 * 1024 * 1024;', `const MAX_RPC_RESPONSE_BYTES = ${b.answerBytes};`]], append: [] },
    },
  }),
  'request-size': (b) => ({
    text: `A quorum leg's gateway request or CCIP callback whose payload, serialized (UTF-8) with a 4 KiB envelope, exceeds ${b.messageBytes} bytes is never sent: the gateway is skipped, and a callback fails its leg as CCIP_GATEWAY_FAILED.`,
    source: {
      'ens/ccip-fetch.js': {
        edits: [["      const url = template.replaceAll('{sender}', sender).replaceAll('{data}', data);\n",
          // Only where the legs pass a bound (deps): verifier adapters'
          // own CCIP is main's, unchanged.
          "      const url = template.replaceAll('{sender}', sender).replaceAll('{data}', data);\n      if (deps.maxRequestBytes != null && !__fits([url, template.includes('{data}') ? '' : JSON.stringify({ sender, data })], deps.maxRequestBytes)) throw new Error('CCIP request too large');\n"]],
        append: [FITS],
      },
      'ens-resolver.js': {
        edits: [
          [', ccipSignal);', ', ccipSignal, __legDeps);'],
          ["        const raw = await provider.call({\n          to: sender,\n          data: callback + abi.encode(['bytes', 'bytes'], [response, extraData]).slice(2),\n",
            `        if (!__fits([callback + abi.encode(['bytes', 'bytes'], [response, extraData]).slice(2)], ${b.messageBytes})) {\n          throw Object.assign(new Error('CCIP gateways unavailable or returned invalid data'), { code: 'CCIP_GATEWAY_FAILED' });\n        }\n        const raw = await provider.call({\n          to: sender,\n          data: callback + abi.encode(['bytes', 'bytes'], [response, extraData]).slice(2),\n`],
        ],
        append: [FITS, LEG_DEPS, `__legDeps.maxRequestBytes = ${b.messageBytes};`],
      },
    },
  }),
  'reply-size': (b) => ({
    text: `A result over ${b.replyBytes} bytes, serialized (UTF-8, as the core holds it: endpoints as references), is never cached, and its callers get "result too large".`,
    harness: ['reply-size'],
    source: {
      'ens-resolver.js': {
        edits: [HOST_SOURCES, ['  cache.set(normalized, { result, expiresAt: Date.now() + ttl });\n  capCache(cache);\n',
          `  if (__coreSize(result) <= ${b.replyBytes}) {\n    cache.set(normalized, { result, expiresAt: Date.now() + ttl });\n    capCache(cache);\n  }\n`]],
        append: [CORE_SIZE],
      },
      'tezos-domains-resolver.js': {
        edits: [HOST_SOURCES, [TEZOS_CACHE, `  if (__coreSize(result, endpoints) <= ${b.replyBytes}) {\n  ${TEZOS_CACHE.replaceAll('\n  ', '\n    ')}  }\n`]],
        append: [CORE_SIZE],
      },
    },
  }),
  'cache-bytes': (b) => ({
    text: `Each result cache also holds at most ${b.cacheBytes} bytes (UTF-8 key plus the result serialized as the core holds it), evicting as capCache does: expired entries first, then the oldest.`,
    source: {
      'ens-resolver.js': {
        edits: [HOST_SOURCES, ['  cache.set(normalized, { result, expiresAt: Date.now() + ttl });\n  capCache(cache);\n',
          `  cache.set(normalized, { result, expiresAt: Date.now() + ttl });\n  capCache(cache);\n  __capBytes(cache, ${b.cacheBytes});\n`]],
        append: [CORE_SIZE, CAP_BYTES],
      },
      'tezos-domains-resolver.js': {
        edits: [HOST_SOURCES, [TEZOS_CACHE, `${TEZOS_CACHE}  __capBytes(resultCache, ${b.cacheBytes}, endpoints);\n`]],
        append: [CORE_SIZE, CAP_BYTES],
      },
    },
  }),
  'decode-budget': (b) => ({
    text: `An OffchainLookup whose decoded strings and bytes exceed ${b.decodeBytes} bytes is malformed, failing as an ABI decode does (BUFFER_OVERRUN).`,
    source: {
      'ens-resolver.js': {
        edits: [["        ['address', 'string[]', 'bytes', 'bytes4', 'bytes'], '0x' + data.slice(10)\n      );\n",
          `        ['address', 'string[]', 'bytes', 'bytes4', 'bytes'], '0x' + data.slice(10)\n      );\n      __decodeBudget(urls, callData, extraData, ${b.decodeBytes});\n`]],
        append: [`function __decodeBudget(urls, callData, extraData, limit) {
  let out = (callData.length - 2) / 2 + (extraData.length - 2) / 2;
  for (let i = 0; i < urls.length; i += 1) {
    // A URL that won't decode (bad UTF-8) is unreadable here, so it isn't
    // counted, though the core counts its bytes; it fails where the
    // gateway loop reaches it. No vector puts one near the budget.
    try { out += Buffer.byteLength(urls[i], 'utf8'); } catch { /* see above */ }
  }
  if (out > limit) throw ethers.makeError('decode budget exceeded', 'BUFFER_OVERRUN');
}`],
      },
    },
  }),
  'admission': (b) => ({
    text: `Admission: at most ${b.sessions} running sessions, ${b.callers} waiting callers and ${b.callersPerSession} callers per session; a caller over a limit, a cache hit included, is answered busy at once.`,
    source: {
      'ens-resolver.js': {
        edits: [
          ['  const key = chainCacheKey(normalized, chainId);\n  const cached = cache.get(key);\n',
            `  if (__admission.callers >= ${b.callers}) throw __busy();\n  const key = chainCacheKey(normalized, chainId);\n  const cached = cache.get(key);\n`],
          ['    log.info(`[ens] ${label} joining in-flight resolution for ${nameForLog(normalized)}`);\n    return existing;\n',
            `    log.info(\`[ens] \${label} joining in-flight resolution for \${nameForLog(normalized)}\`);\n    if ((__admission.joined.get(existing) ?? 0) >= ${b.callersPerSession}) throw __busy();\n    return __admit(existing);\n`],
          ['  let promise;\n  promise = resolveAcrossStableLifecycle(', `  if (__admission.sessions.size >= ${b.sessions}) throw __busy();\n  let promise;\n  promise = resolveAcrossStableLifecycle(`],
          ['  inFlightResolves.set(dedupKey, promise);\n  return promise;\n', '  inFlightResolves.set(dedupKey, promise);\n  __admission.sessions.add(promise);\n  const __end = () => __admission.sessions.delete(promise);\n  promise.then(__end, __end);\n  return __admit(promise);\n'],
        ],
        // Sessions and their callers by identity: a session the in-flight
        // table retired (a lifecycle change) still runs, and counts.
        append: [`var __admission = { callers: 0, sessions: new Set(), joined: new Map() };
function __busy() {
  return Object.assign(new Error('busy'), { protocol: 'busy' });
}
function __admit(session) {
  __admission.callers += 1;
  __admission.joined.set(session, (__admission.joined.get(session) ?? 0) + 1);
  const leave = () => {
    __admission.callers -= 1;
    __admission.joined.set(session, __admission.joined.get(session) - 1);
  };
  session.then(leave, leave);
  return session;
}`],
      },
    },
  }),
  'overall-deadline': (b) => ({
    text: `A session ends ${b.deadlineMs} ms after it starts: its callers get deadline, its outstanding I/O is cancelled, and it makes no more. The reference's abandoned work can't be stopped, only cut off from I/O, so the patch holds only for one step with one call (enforced); that nothing is cached is the core's own test.`,
    harness: ['overall-deadline'],
  }),
  'prefetch-set': (b) => ({
    text: `A prefetch is kept after agreed_data in a set of ${b.prefetches}; past that the oldest is aborted.`,
    source: {
      'ens-resolver.js': {
        edits: [["  if (outcome.kind !== 'agreed_data' && prefetchHandle) {\n    try { prefetchHandle.abort(); } catch { /* never propagate */ }\n  }\n",
          `  if (outcome.kind !== 'agreed_data' && prefetchHandle) {\n    try { prefetchHandle.abort(); } catch { /* never propagate */ }\n  } else if (prefetchHandle && prefetchHandle !== NOOP_PREFETCH) __keepPrefetch(prefetchHandle, ${b.prefetches});\n`]],
        // `settled` is the harness handle's: a prefetch that finished
        // leaves the set, as its request completes in the core.
        append: ['var __kept = [];\nfunction __keepPrefetch(handle, n) {\n  __kept = __kept.filter((kept) => !kept.settled);\n  if (handle.settled) return;\n  __kept.push(handle);\n  while (__kept.length > n) __kept.shift().abort();\n}'],
      },
    },
  }),
};

/** A scenario's patches, resolved against its bounds. */
function patchesOf(scenario) {
  const bounds = { ...BOUNDS, ...(scenario.world?.bounds ?? {}) };
  return (scenario.patches ?? []).map((id) => {
    if (!PATCHES[id]) throw new Error(`scenario ${scenario.id}: unknown patch ${id}`);
    return { id, ...PATCHES[id](bounds) };
  });
}

function describe(value) {
  return JSON.parse(JSON.stringify(value, (_k, v) => (v === undefined ? { $undefined: true } : v)));
}

/**
 * Loads a fresh copy of a src/main module. `stubs` maps module paths
 * (relative to src/main, without .js) to stand-ins, whoever requires them;
 * the module is registered in the module cache so lazy dependents (the
 * Myotis and Colibri adapters) see this same instance. `restore` removes
 * the hook and evicts every checkout module under src/, so no state
 * survives into the next scenario; a failed load restores before throwing.
 */
function loadModule(checkout, stubs, file, wrappers = {}, sources = {}) {
  const src = path.join(checkout, 'src');
  const main = path.join(src, 'main');
  const filename = path.join(main, file);
  // `sources` maps module paths to a deviation's source patch (see
  // PATCHES): each edit's text must occur exactly once.
  const patchBy = new Map(Object.entries(sources).map(([rel, patch]) => [path.join(main, rel), patch]));
  const sourceOf = (name) => {
    const text = fs.readFileSync(name, 'utf8');
    const patch = patchBy.get(name);
    return patch ? patchedSource(text, patch, path.relative(main, name)) : text;
  };
  const compiled = (name, parent) => {
    if (!Module._cache[name]) {
      const mod = new Module(name, parent);
      mod.filename = name;
      mod.paths = Module._nodeModulePaths(path.dirname(name));
      Module._cache[name] = mod;
      mod._compile(sourceOf(name), name);
      mod.loaded = true;
    }
    return Module._cache[name].exports;
  };
  const byPath = new Map(Object.entries(stubs).map(([rel, stub]) => [path.join(main, `${rel}.js`), stub]));
  // `wrappers` maps module paths to functions of the real exports: the real
  // module loads, and its dependents get the wrapped exports.
  const wrapBy = new Map(Object.entries(wrappers).map(([rel, wrap]) => [path.join(main, `${rel}.js`), wrap]));
  const wrapped = new Map();
  const evict = () => {
    for (const key of Object.keys(Module._cache)) if (key.startsWith(src + path.sep)) delete Module._cache[key];
  };
  const originalLoad = Module._load;
  const restore = () => {
    Module._load = originalLoad;
    evict();
  };
  Module._load = function load(request, parent, isMain) {
    if (request === 'electron' && parent?.filename?.startsWith(checkout)) return stubs.electron;
    if (parent?.filename?.startsWith(main)) {
      let resolved = null;
      try {
        resolved = Module._resolveFilename(request, parent, isMain);
      } catch {
        resolved = null;
      }
      if (resolved && byPath.has(resolved)) return byPath.get(resolved);
      const load = () => (patchBy.has(resolved) ? compiled(resolved, parent) : originalLoad.call(this, request, parent, isMain));
      if (resolved && wrapBy.has(resolved)) {
        if (!wrapped.has(resolved)) wrapped.set(resolved, wrapBy.get(resolved)(load()));
        return wrapped.get(resolved);
      }
      if (resolved && patchBy.has(resolved)) return load();
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    evict();
    return { exports: compiled(filename, null), restore };
  } catch (err) {
    restore();
    throw err;
  }
}

/** A module's source with a deviation's edits applied (see PATCHES). */
function patchedSource(source, patch, file) {
  let text = source;
  for (const [find, replace] of patch.edits) {
    const count = text.split(find).length - 1;
    if (count !== 1) throw new Error(`patch for ${file}: ${count} matches for ${JSON.stringify(find)}`);
    text = text.replace(find, () => replace);
  }
  return patch.append.length > 0 ? `${text}\n${patch.append.join('\n')}\n` : text;
}

/**
 * Runs one scenario and returns its record. Every global it changes
 * (environment, Math.random, ethers' transport, timers and Date, the
 * module loader) is restored on every path, setup failures included. The
 * scenario object is never modified.
 */
async function runScenario(checkout, ethers, FakeTimers, scenario) {
  const system = scenario.system ?? 'ens';
  const world = structuredClone(scenario.world);
  const bounds = { ...BOUNDS, ...(world.bounds ?? {}) };
  const patches = patchesOf(scenario);
  const harnessPatch = (name) => patches.some((patch) => patch.harness?.includes(name));
  if (harnessPatch('overall-deadline') && (scenario.steps.length !== 1 || (scenario.steps[0].calls ?? [null]).length !== 1)) {
    throw new Error(`scenario ${scenario.id}: overall-deadline holds for one step with one call`);
  }
  const sources = {};
  for (const patch of patches) {
    for (const [file, { edits, append }] of Object.entries(patch.source ?? {})) {
      sources[file] ??= { edits: [], append: [] };
      // Patches may share an edit or a helper (the legs' deps): once each.
      const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
      for (const edit of edits) if (!sources[file].edits.some((e) => same(e, edit))) sources[file].edits.push(edit);
      for (const code of append) if (!sources[file].append.includes(code)) sources[file].append.push(code);
    }
  }
  // Every patch applies and compiles before the scenario runs: a module
  // the resolver loads lazily would otherwise fail inside a fallback path.
  for (const [file, patch] of Object.entries(sources)) {
    const name = path.join(checkout, 'src', 'main', file);
    vm.compileFunction(patchedSource(fs.readFileSync(name, 'utf8'), patch, file), ['exports', 'require', 'module', '__filename', '__dirname'], { filename: name });
  }
  const io = [];
  const violations = [];
  const listeners = [];
  let myotisEpoch = 1;
  let stepIndex = -1;
  let http = 0;
  let clock = null;
  const now = () => Date.now() - EPOCH;
  const hostOf = (url) => new URL(url).host;
  const plan = (host) => world.hosts?.[host] || {};
  const declared = (host) => (world.endpoints ?? []).some((url) => hostOf(url) === host);
  // An exchange a verifier operation makes inside main's adapter is that
  // operation's business: it carries the operation's id as `within`.
  // Steps whose session met its deadline (deviation `overall-deadline`):
  // their work makes no more I/O.
  const deadSteps = new Set();
  const record = (entry, op = insideOperation.getStore()?.op) => {
    if (deadSteps.has(stepIndex)) return null;
    const within = op;
    const item = { id: io.length, step: stepIndex, t: now(), ...entry, ...(within === undefined ? {} : { within }), end: null, outcome: 'open' };
    io.push(item);
    return item;
  };
  const close = (item, outcome) => {
    if (item.outcome !== 'open') return;
    item.outcome = outcome;
    item.end = now();
  };

  // A call's kind: the UR's resolve (by its inner call) or reverse, a CCIP
  // callback, or a WNS/GNS NameNFT call ('wns:addr', say).
  const callKind = (to, data) => {
    const target = String(to).toLowerCase();
    if (target === WNS || target === GNS) return `${target === WNS ? 'wns' : 'gns'}:${SELECTORS[data.slice(0, 10)] ?? 'unknown'}`;
    if (data.startsWith('0x9061b923')) {
      const [, inner] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes', 'bytes'], '0x' + data.slice(10));
      return `resolve:${SELECTORS[inner.slice(0, 10)] ?? 'unknown'}`;
    }
    return data.startsWith('0x5d78a217') ? 'reverse' : 'callback';
  };
  const pickAnswer = (tables, kind) => {
    const general = kind.startsWith('resolve:') ? 'resolve' : kind;
    for (const table of tables) {
      const answer = table?.[kind] ?? table?.[general] ?? table?.['*'];
      if (answer) return answer;
    }
    return null;
  };

  // JSON-RPC endpoints, behind ethers' FetchRequest transport.
  const block = (n, fork) => ({
    number: ethers.toQuantity(n), hash: ethers.id(`${fork ? 'fork' : 'block'}${n}`), parentHash: ethers.id(`parent${n}`),
    timestamp: '0x1', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1', gasUsed: '0x0',
    miner: '0x' + '00'.repeat(20), extraData: '0x', baseFeePerGas: '0x1', transactions: [],
  });
  const unscripted = (what) => {
    violations.push(what);
    return { error: { code: -32601, message: 'unscripted' } };
  };
  const answerRpc = (host, r) => {
    const p = plan(host);
    switch (r.method) {
      case 'eth_chainId':
        return { result: '0x1' };
      case 'eth_blockNumber':
        return { result: ethers.toQuantity(p.head ?? HEAD) };
      case 'eth_getBlockByNumber': {
        const tag = r.params[0];
        const n = tag === 'finalized' ? (p.finalized ?? (p.head ?? HEAD) - 64) : Number(tag);
        if (!Number.isSafeInteger(n)) return unscripted(`block ${tag} at ${host}`);
        return { result: block(n, p.fork) };
      }
      case 'eth_call': {
        const { to, data } = r.params[0];
        const kind = callKind(to, data);
        const answer = pickAnswer([p.calls, world.calls], kind);
        if (!answer) return unscripted(`${kind} call to ${host}`);
        if (answer.rpc_error) return { error: answer.rpc_error };
        if (answer.hang) return { hang: true };
        return { result: answer.data };
      }
      default:
        return unscripted(`${r.method} at ${host}`);
    }
  };
  // ethers' native getUrl, observably: a cancel rejects CANCELLED on the
  // next tick (its listeners run from setTimeout 0) and a reply that finds
  // the signal cancelled rejects too; req.timeout is an inactivity timer
  // that rejects TIMEOUT. Neither stops the HTTP exchange itself (ethers
  // passes its AbortSignal under an option Node ignores), so an entry's
  // outcome follows the exchange and `rejected` records the promise.
  const rpcTransport = (req, signal) => {
    if (signal?.cancelled) return Promise.reject(ethers.makeError('request cancelled before sending', 'CANCELLED'));
    const host = hostOf(req.url);
    http += 1;
    const body = JSON.parse(Buffer.from(req.body).toString());
    const batch = Array.isArray(body) ? body : [body];
    const entries = batch.map((r) => record({
      kind: 'rpc', host, http, method: r.method, params: r.params,
      ...(r.method === 'eth_call' ? { call: callKind(r.params[0].to, r.params[0].data) } : {}),
    }));
    if (entries.includes(null)) return new Promise(() => {});
    if (!declared(host)) violations.push(`undeclared RPC endpoint ${host}`);
    const p = plan(host);
    const answers = p.status ? [] : batch.map((r) => ({ id: r.id, ...answerRpc(host, r) }));
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (message, code) => {
        if (settled) return;
        settled = true;
        for (const item of entries) item.rejected = { at: now(), code };
        reject(ethers.makeError(message, code));
      };
      signal?.addListener(() => fail('request cancelled', 'CANCELLED'));
      // Node's socket timer is off at zero.
      const inactivity = req.timeout > 0 ? setTimeout(() => fail('request timeout', 'TIMEOUT'), req.timeout) : null;
      if (p.hang || answers.some((a) => a.hang)) return;
      setTimeout(() => {
        // Cancelled at a session's deadline: the exchange never answers.
        if (entries.every((item) => item.outcome === 'cancelled')) return;
        clearTimeout(inactivity);
        for (const item of entries) close(item, 'answered');
        // `pad` grows each answer by a member JSON-RPC readers ignore.
        const padding = p.pad ? { pad: 'x'.repeat(p.pad) } : {};
        const out = answers.map(({ id, result, error }) => (error ? { jsonrpc: '2.0', id, error, ...padding } : { jsonrpc: '2.0', id, result, ...padding }));
        const answer = p.status
          ? { status: p.status, body: 'unavailable' }
          : { status: 200, body: JSON.stringify(Array.isArray(body) ? out : out[0]) };
        for (const item of entries) item.answer = answer;
        if (signal?.cancelled) {
          fail('cancelled', 'CANCELLED');
          return;
        }
        // Deviation `response-caps`: main delivers the body, and the core
        // refuses it as a transport failure.
        if (harnessPatch('rpc-answer-cap') && Buffer.byteLength(answer.body) > bounds.answerBytes) {
          fail('response too large', 'NETWORK_ERROR');
          return;
        }
        if (settled) return;
        settled = true;
        resolve({ statusCode: answer.status, statusMessage: p.status ? 'Unavailable' : 'OK', headers: p.status ? {} : { 'content-type': 'application/json' }, body: Buffer.from(answer.body) });
      }, p.delay ?? 10);
    });
  };

  // CCIP gateways, through a fake electron.net ClientRequest: abort()
  // cancels delivery and is recorded; a response arrives whole.
  const netRequest = (options) => {
    const req = new EventEmitter();
    const headers = {};
    let body = null;
    let item = null;
    let timer = null;
    req.setHeader = (name, value) => { headers[name.toLowerCase()] = value; };
    req.write = (chunk) => { body = String(chunk); };
    req.abort = () => {
      if (!item || item.outcome !== 'open') return;
      clearTimeout(timer);
      close(item, 'cancelled');
      req.emit('abort');
      req.emit('close');
    };
    req.end = () => {
      const host = hostOf(options.url);
      const g = world.gateways?.[host];
      item = record({
        kind: 'gateway', host, method: options.method, url: options.url, headers, body,
        flags: Object.fromEntries(GATEWAY_FLAGS.map((flag) => [flag, options[flag]])),
      });
      if (!item) return;
      if (!g) violations.push(`undeclared gateway ${host}`);
      if (!g || g.hang) return;
      timer = setTimeout(() => {
        if (item.outcome !== 'open') return;
        if (g.redirect) {
          item.answer = { redirect: g.redirect };
          close(item, 'redirected');
          req.emit('redirect', 302, options.method, g.redirect, { location: [g.redirect] });
          return;
        }
        item.answer = { status: g.status ?? 200, body: g.body ?? JSON.stringify({ data: '0x' }) };
        close(item, 'answered');
        const res = new EventEmitter();
        Object.assign(res, { statusCode: g.status ?? 200, statusMessage: 'OK', headers: {}, pause() {}, resume() {}, destroy() {} });
        req.emit('response', res);
        res.emit('data', Buffer.from(item.answer.body));
        res.emit('end');
      }, g.delay ?? 10);
    };
    return req;
  };

  // Verifiers: { data } is proven return data, { revert } proven revert
  // data, { unavailable: true } a verifier that cannot answer.
  const verified = (source, state, to, data, op) => {
    const kind = callKind(to, data);
    const item = record({ kind: 'verified', host: source, method: 'eth_call', params: [{ to, data }, 'latest'], call: kind }, op);
    const answer = pickAnswer([state.calls], kind);
    if (!answer) violations.push(`unscripted ${kind} call to ${source}`);
    return new Promise((resolve) => setTimeout(() => {
      item.answer = answer?.data ? { data: answer.data } : answer?.revert ? { revert: answer.revert } : { unavailable: true };
      close(item, 'answered');
      resolve(answer ?? {});
    }, state.delay ?? 10));
  };
  const myotis = () => world.myotis ?? {};
  const colibri = () => world.colibri ?? {};
  // A verifier adapter's whole operation, as design 0004's shell.verified
  // carries it: its params, and its outcome without text (a result, the
  // proven revert data, or a failure class).
  const insideOperation = new AsyncLocalStorage();
  const failureClass = (err) => {
    // myotisManager's verifiedRequest: Myotis' state changed while a raw
    // request was running.
    if (err?.code === 'MYOTIS_UNAVAILABLE') return 'lifecycle';
    if (err?.code === 'TIMEOUT') return 'timeout';
    return 'error';
  };
  const revertOf = (err) => {
    const data = err?.data ?? err?.info?.error?.data;
    return typeof data === 'string' && /^0x[0-9a-f]*$/i.test(data) ? data : null;
  };
  // `toAnswer` maps a returned value to the recorded reply (default: the
  // value itself). The reply is the outcome the reference receives: main
  // runs no epoch check of its own, so a success that crossed an
  // availability change is still a success, and the caller's own check
  // (tryMyotisPath's) decides (design 0004, Verified operations).
  const operation = (host, op, params, run, toAnswer = (value) => ({ result: describe(value) })) => {
    const item = record({ kind: 'verified-op', host, op, params });
    return insideOperation.run({ op: item.id }, run).then(
      (value) => {
        item.answer = toAnswer(value);
        close(item, 'answered');
        return value;
      },
      (err) => {
        const revert = revertOf(err);
        item.answer = revert ? { revert } : { failure: failureClass(err) };
        close(item, 'answered');
        throw err;
      }
    );
  };
  const wrappers = {
    'ens/myotis-resolver': (real) => ({
      ...real,
      resolveRecord: (params) => operation('myotis', 'record', {
        method: params.method, name: params.name ?? null, address: params.addressHex ?? null, coinType: String(params.coinType ?? 60n),
      }, () => real.resolveRecord(params)),
    }),
    'ens/colibri-resolver': (real) => ({
      ...real,
      resolveCallViaColibri: (name, callData, callResolver) => operation('colibri', 'resolve', {
        name, callData, nameNft: callResolver?.name === 'nameNftResolverCall',
      }, () => real.resolveCallViaColibri(name, callData, callResolver)),
      resolveReverseViaColibri: (addressBytes, coinType) => operation('colibri', 'reverse', {
        address: ethers.hexlify(addressBytes), coinType: String(coinType ?? 60n),
      }, () => real.resolveReverseViaColibri(addressBytes, coinType)),
    }),
  };
  const MYOTIS = {
    onAvailabilityTransition: (listener) => { listeners.push(listener); },
    isEnabled: () => myotis().enabled ?? false,
    isReady: () => myotis().ready ?? false,
    getAvailabilityEpoch: () => myotisEpoch,
    getStatus: () => ({ state: myotis().ready ? 'ready' : 'stopped', optimisticBlockNumber: myotis().block ?? null }),
    ethCall: ({ to, data }) => {
      const call = async () => {
        const epoch = myotisEpoch;
        const answer = await verified('myotis', myotis(), to, data);
        // myotisManager's verifiedRequest: a call that outlived its epoch
        // or readiness throws.
        if (myotisEpoch !== epoch || !(myotis().ready ?? false)) {
          throw Object.assign(new Error('Myotis state changed while the request was running'), { code: 'MYOTIS_UNAVAILABLE' });
        }
        if (answer.data) return { status: 'ok', resultHex: answer.data };
        if (answer.revert) return { status: 'revert', dataHex: answer.revert };
        return { status: 'error' };
      };
      // The resolver's own NameNFT calls are whole operations (with the
      // block number it reads next); calls inside a record operation are
      // that operation's raw calls.
      if (insideOperation.getStore()) return call();
      // The resolver reads the optimistic block right after a successful
      // call; anything but `ok` with result data makes it throw.
      return operation('myotis', 'call', { to, data }, call, (value) => (
        value.status === 'ok' && typeof value.resultHex === 'string'
          ? { result: { resultHex: value.resultHex, optimisticBlockNumber: myotis().block ?? null } }
          : { failure: 'error' }
      ));
    },
  };
  // Colibri requests queued by operations: { method, params, op }.
  const colibriSends = [];
  const COLIBRI_HOST = {
    ensureWorker: async () => {},
    createClient: () => ({
      async request({ method, params }) {
        // The client knows its chain: answered locally, without I/O.
        if (method === 'eth_chainId') return '0x1';
        if (method !== 'eth_call') {
          violations.push(`Colibri ${method}`);
          throw new Error(`unscripted Colibri ${method}`);
        }
        // ethers sends this from its provider's drain timer, which has lost
        // the caller's context: the operation is the one that queued these
        // exact params (see the BrowserProvider wrapper below).
        const queued = colibriSends.findIndex((q) => q.method === method && q.params === JSON.stringify(params));
        const op = queued >= 0 ? colibriSends.splice(queued, 1)[0].op : undefined;
        const answer = await verified('colibri', colibri(), params[0].to, params[0].data, op);
        if (answer.data) return answer.data;
        if (answer.revert) throw Object.assign(new Error('execution reverted'), { code: 3, data: answer.revert });
        throw new Error('Colibri proof unavailable');
      },
      destroy() {},
      on() {},
      removeListener() {},
    }),
  };

  // Tezos nodes, behind the resolver's fetchImpl parameter.
  const json = (status, value) => new Response(value === undefined ? '' : JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
  const tezosNode = (host, p, method, route) => {
    if (p.fail) return json(500, { error: 'down' });
    const level = p.level ?? TEZ_HEAD;
    if (route === '/chains/main/chain_id') return json(200, p.chain ?? 'NetXdQprcVkpaWU');
    if (route === '/chains/main/blocks/head/header') return json(200, p.pad ? { level, pad: 'x'.repeat(p.pad) } : { level });
    let m = route.match(/^\/chains\/main\/blocks\/(\d+)\/hash$/);
    if (m) return p.anchorFail ? json(500, { error: 'anchor' }) : json(200, `BL${p.fork ? 'fork' : 'main'}${m[1]}`);
    m = route.match(/^\/chains\/main\/blocks\/[^/]+\/context\/(.*)$/);
    const rest = m?.[1] ?? '';
    if (method === 'POST' && rest === `contracts/${TEZ_PROXY}/script/normalized`) return json(200, tezProxyScript());
    if (method === 'POST' && rest === `contracts/${TEZ_REGISTRY}/script/normalized`) {
      return p.scriptFail ? json(500, { error: 'script' }) : json(200, tezRegistryScript());
    }
    if (rest.startsWith('big_maps/1264/')) {
      if (p.recordFail) return json(500, { error: 'record' });
      const rec = p.record !== undefined ? p.record : world.record;
      return rec === null ? json(404) : json(200, rec);
    }
    if (rest.startsWith('big_maps/1265/')) return json(200, { string: p.expiry ?? world.expiry });
    violations.push(`unscripted Tezos ${method} ${route} at ${host}`);
    return json(404);
  };
  const fetchImpl = (url, init = {}) => {
    const { host, pathname } = new URL(url);
    const method = init.method ?? 'GET';
    const item = record({ kind: 'tezos', host, method, path: pathname, body: init.body ?? null });
    if (!item) return new Promise(() => {});
    if (!declared(host)) violations.push(`undeclared Tezos endpoint ${host}`);
    const p = plan(host);
    return new Promise((resolve, reject) => {
      let timer = null;
      const abort = () => {
        clearTimeout(timer);
        close(item, 'cancelled');
        reject(Object.assign(new Error('This operation was aborted'), { name: 'AbortError' }));
      };
      if (init.signal?.aborted) return abort();
      init.signal?.addEventListener('abort', abort, { once: true });
      if (p.hang) return;
      timer = setTimeout(async () => {
        if (item.outcome !== 'open') return;
        init.signal?.removeEventListener('abort', abort);
        const response = tezosNode(host, p, method, pathname);
        const text = await response.clone().text();
        item.answer = { status: response.status, body: text };
        close(item, 'answered');
        resolve(response);
      }, p.delay ?? 10);
    });
  };

  const common = {
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    'private/private-log-context': { runWithPrivateLogContext: (_p, fn) => fn(), redactForLog: (v) => v },
    'private/private-windows': { isPrivateWebContents: () => false },
  };
  const stubs = system === 'tezos' ? { ...common, electron: { ipcMain: { handle() {} } } } : {
    ...common,
    electron: {
      ipcMain: { handle() {} },
      net: { request: netRequest },
      session: { defaultSession: { resolveProxy: async () => 'DIRECT' } },
    },
    'networks/network-registry': {
      getEndpoints: (chain, kind) => {
        if (chain !== 1) return [];
        if (kind === 'rpc') return world.endpoints;
        if (kind === 'prover') return colibri().prover ? [colibri().prover] : [];
        return [];
      },
      getNetwork: () => world.network,
      getEndpointSources: () => world.sources ?? [],
      getEndpointSourceList: () => world.sourceList ?? [],
      invalidate() {},
    },
    'ens-prefetch': {
      prefetchGatewayUrl: (uri) => {
        const item = record({ kind: 'prefetch', host: null, uri });
        // After a session's deadline the step makes no more I/O.
        if (!item) return { abort() {}, settled: true };
        // `world.prefetchMs` (when set) is how long a prefetch runs before
        // it finishes; otherwise it is still open when the scenario ends.
        if (world.prefetchMs > 0) {
          setTimeout(() => {
            if (item.outcome !== 'open') return;
            item.answer = {};
            close(item, 'answered');
          }, world.prefetchMs);
        }
        return { abort: () => close(item, 'cancelled'), get settled() { return item.outcome !== 'open'; } };
      },
      NOOP_HANDLE: { abort() {} },
    },
    'myotis/myotis-manager': MYOTIS,
    'ens/colibri-worker-host': COLIBRI_HOST,
  };

  // A scripted event during a step: a Myotis availability transition.
  const fire = (event) => {
    record({ kind: 'event', host: null, event });
    if (event.myotis) {
      world.myotis = { ...myotis(), ...event.myotis };
      myotisEpoch += 1;
      for (const listener of listeners) listener({ chainId: 1, ready: myotis().ready ?? false, reason: 'scripted', epoch: myotisEpoch });
    }
    for (const item of io) if (item.kind === 'event') close(item, 'fired');
  };

  // Advances virtual time event by event until every call settles, so a
  // settlement time is exact and the next step starts from it.
  const settleAll = async (promises) => {
    const results = promises.map(() => null);
    promises.forEach((promise, i) => promise.then(
      (value) => { results[i] = { value: describe(value), settled: now() }; },
      (error) => {
        // A protocol error (deviations `admission`, `overall-deadline`) is
        // not a thrown resolution.
        results[i] = error?.protocol ? { protocol: error.protocol, settled: now() } : { thrown: String(error?.message ?? error), settled: now() };
      }
    ));
    const done = () => results.every(Boolean);
    const limit = Date.now() + MAX_STEP_MS;
    await clock.tickAsync(0);
    while (!done() && clock.countTimers() > 0 && Date.now() < limit) await clock.nextAsync();
    for (let i = 0; i < 10 && !done(); i += 1) await new Promise((resolve) => setImmediate(resolve));
    return results.map((result) => result ?? { pending: true });
  };

  const undo = [];
  try {
    const env = Object.fromEntries(RESOLVER_ENV.map((key) => [key, process.env[key]]));
    undo.push(() => {
      for (const [key, value] of Object.entries(env)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    });
    for (const key of RESOLVER_ENV) delete process.env[key];

    const random = Math.random;
    undo.push(() => { Math.random = random; });
    Math.random = seeded(scenario.seed ?? 7);

    // Colibri's BrowserProvider sends each request from a shared drain
    // timer; note the operation each request was queued under.
    const browserSend = ethers.BrowserProvider.prototype.send;
    undo.push(() => { ethers.BrowserProvider.prototype.send = browserSend; });
    ethers.BrowserProvider.prototype.send = function send(method, params) {
      colibriSends.push({ method, params: JSON.stringify(params), op: insideOperation.getStore()?.op });
      return browserSend.call(this, method, params);
    };

    const previousGetUrl = new ethers.FetchRequest('https://snapshot.invalid').getUrlFunc;
    undo.push(() => ethers.FetchRequest.registerGetUrl(previousGetUrl));
    ethers.FetchRequest.registerGetUrl(rpcTransport);

    clock = FakeTimers.install({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'], now: EPOCH });
    undo.push(() => clock.uninstall());

    const loaded = system === 'tezos'
      ? loadModule(checkout, stubs, 'tezos-domains-resolver.js', {}, sources)
      : loadModule(checkout, stubs, 'ens-resolver.js', wrappers, sources);
    undo.push(loaded.restore);
    // `$fetch` drives one FetchRequest through the RPC transport, with its
    // real cancel signal: self-tests use it for the transport's semantics.
    const probeFetch = async (url, { timeout, cancelAt } = {}) => {
      const req = new ethers.FetchRequest(url);
      req.body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] });
      if (timeout !== undefined) req.timeout = timeout;
      if (cancelAt !== undefined) setTimeout(() => req.cancel(), cancelAt);
      const response = await req.send();
      return { status: response.statusCode };
    };
    // Deviation `reply-size`: a result too large to reply with.
    const replyLimit = (value) => {
      if (harnessPatch('reply-size')) {
        // Hosts map through their recorded sources (CORE_SIZE); Tezos' agreed
        // list publishes its endpoints' whole URLs.
        const size = loaded.exports.__coreSize(value, system === 'tezos' ? world.endpoints ?? [] : []);
        if (size > bounds.replyBytes) throw new Error('result too large');
      }
      return value;
    };
    // Deviation `overall-deadline`: the step's one session ends at its
    // deadline, cancelling what it has outstanding.
    const deadline = (promise) => (!harnessPatch('overall-deadline') ? promise : new Promise((resolve, reject) => {
      const step = stepIndex;
      const timer = setTimeout(() => {
        deadSteps.add(step);
        for (const item of io) if (item.step === step && item.outcome === 'open' && item.kind !== 'event') close(item, 'cancelled');
        reject(Object.assign(new Error('deadline'), { protocol: 'deadline' }));
      }, bounds.deadlineMs);
      promise.then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
    }));
    const invoke = ({ fn, args = [] }) => deadline(Promise.resolve().then(() => (fn === '$fetch' ? probeFetch(...args) : system === 'tezos'
      ? loaded.exports[fn](...args, { fetchImpl, endpoints: world.endpoints })
      : loaded.exports[fn](...args)))).then(replyLimit);

    const steps = [];
    for (const [index, step] of scenario.steps.entries()) {
      if (step.after) await clock.tickAsync(step.after);
      stepIndex = index;
      if (step.world) Object.assign(world, structuredClone(step.world));
      const at = now();
      for (const event of step.events ?? []) setTimeout(() => fire(event), event.at);
      // A call's `at` starts it that long into the step, as events do.
      const start = (call) => (call.at ? new Promise((resolve) => setTimeout(resolve, call.at)).then(() => invoke(call)) : invoke(call));
      const results = await settleAll((step.calls ?? [step.call]).map(start));
      if (loaded.exports.__ambiguousHost?.()) {
        throw new Error(`scenario ${scenario.id}: core size: one host from several endpoint URLs`);
      }
      steps.push(describe({ at, ...step, results }));
    }
    // Let stragglers finish, so a late answer nobody waits for is recorded
    // as answered rather than left open.
    const limit = Date.now() + MAX_STEP_MS;
    while (clock.countTimers() > 0 && Date.now() < limit) await clock.nextAsync();
    if (violations.length > 0) throw new Error(`scenario ${scenario.id}: unscripted I/O: ${[...new Set(violations)].join('; ')}`);
    const deviation = scenario.deviation ? { deviation: scenario.deviation, patches: describe(patches) } : {};
    return { id: scenario.id, system, seed: scenario.seed ?? 7, ...deviation, world: describe(scenario.world), steps, io: describe(io) };
  } finally {
    for (const fn of undo.reverse()) fn();
  }
}

const TEZ_HEAD = 9_000_000;
const TEZ_PROXY = 'KT1F7JKNqwaoLzRsMio1MQC7zv3jG9dHcDdJ';
const TEZ_REGISTRY = 'KT1' + 'Rg'.repeat(16) + 'x';
const tezProxyScript = () => ({
  code: [
    { prim: 'parameter', args: [{ prim: 'unit' }] },
    { prim: 'storage', args: [{ prim: 'pair', args: [{ prim: 'address', annots: ['%contract'] }, { prim: 'address', annots: ['%owner'] }] }] },
  ],
  storage: { prim: 'Pair', args: [{ string: TEZ_REGISTRY }, { string: 'tz1' + 'b'.repeat(33) }] },
});
const TEZ_RECORD_TYPE = {
  prim: 'pair',
  args: [
    { prim: 'map', args: [{ prim: 'string' }, { prim: 'bytes' }], annots: ['%data'] },
    { prim: 'option', args: [{ prim: 'bytes' }], annots: ['%expiry_key'] },
  ],
};
const tezRegistryScript = () => ({
  code: [{
    prim: 'storage',
    args: [{ prim: 'pair', args: [
      { prim: 'big_map', args: [{ prim: 'bytes' }, TEZ_RECORD_TYPE], annots: ['%records'] },
      { prim: 'big_map', args: [{ prim: 'bytes' }, { prim: 'timestamp' }], annots: ['%expiry_map'] },
    ] }],
  }],
  storage: { prim: 'Pair', args: [{ int: '1264' }, { int: '1265' }] },
});
/** A record: `data` maps keys to JSON values (bytes of their JSON text). */
const tezRecord = (data, expiryKey = 'abcd') => ({
  prim: 'Pair',
  args: [
    Object.entries(data).map(([key, value]) => ({ prim: 'Elt', args: [{ string: key }, { bytes: Buffer.from(JSON.stringify(value)).toString('hex') }] })),
    expiryKey ? { prim: 'Some', args: [{ bytes: expiryKey }] } : { prim: 'None' },
  ],
});

// The cache-bytes vector's budget: a cached content result takes about
// 510 bytes, so two fit and three don't, each with a wide margin (the core
// measures its own serialization of the same result).
const CACHE_BYTES = 1280;
const ENDPOINTS = ['https://a.rpc.example', 'https://b.rpc.example', 'https://c.rpc.example', 'https://d.rpc.example'];
const QUORUM_NETWORK = { verification: { order: ['quorum'], preferVerified: false }, quorum: { k: 3, m: 2, timeoutMs: 5000, anchor: 'latest', anchorTtlMs: 30000 } };
const content = (name = 'vitalik.eth') => ({ fn: 'resolveEnsContent', args: [name] });

/** Every scenario, ENS then Tezos. */
function scenarioDefinitions(ethers) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const contentAnswer = (contenthash) => ({ data: coder.encode(['bytes', 'address'], [coder.encode(['bytes'], [contenthash]), '0x' + '22'.repeat(20)]) });
  const GOOD = contentAnswer('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f');
  const EVIL = contentAnswer('0xe40101fa011b20' + 'ee'.repeat(32));
  const lookup = '0x556f1830' + coder.encode(['address', 'string[]', 'bytes', 'bytes4', 'bytes'], [UR, ['https://gw.example/{sender}/{data}.json'], '0x0102', '0xdeadbeef', '0x09']).slice(2);
  const OFFCHAIN = { rpc_error: { code: 3, message: 'execution reverted', data: lookup } };
  const ADDRESS = { data: coder.encode(['bytes', 'address'], [coder.encode(['address'], ['0x' + 'ab'.repeat(20)]), '0x' + '22'.repeat(20)]) };
  const GATEWAY = (delay) => ({ 'gw.example': { delay, body: JSON.stringify({ data: '0xcafe' }) } });
  const lookupVia = (hosts) => ({
    rpc_error: {
      code: 3,
      message: 'execution reverted',
      data: '0x556f1830' + coder.encode(['address', 'string[]', 'bytes', 'bytes4', 'bytes'], [UR, hosts.map((host) => `https://${host}/{sender}/{data}.json`), '0x0102', '0xdeadbeef', '0x09']).slice(2),
    },
  });
  const base = (extra) => ({ endpoints: ENDPOINTS, network: QUORUM_NETWORK, calls: { resolve: GOOD, callback: GOOD }, ...extra });
  const order = (methods, preferVerified = false) => ({ ...QUORUM_NETWORK, verification: { order: methods, preferVerified } });
  const one = (id, world, call = content()) => ({ id, world, steps: [{ call }] });
  return [
    one('quorum-agree', base({})),
    one('quorum-slow-endpoint-head', base({ hosts: { 'b.rpc.example': { delay: 6000 } } })),
    one('quorum-one-liar', base({ hosts: { 'c.rpc.example': { calls: { resolve: EVIL } } } })),
    one('quorum-two-colluding', base({ hosts: { 'c.rpc.example': { calls: { resolve: EVIL } }, 'd.rpc.example': { calls: { resolve: EVIL } } } })),
    one('ccip-fast-gateway', base({ calls: { resolve: OFFCHAIN, callback: GOOD }, gateways: GATEWAY(100) })),
    {
      id: 'ccip-slow-gateway-then-another-name',
      world: base({ calls: { resolve: OFFCHAIN, callback: GOOD }, gateways: GATEWAY(6000) }),
      // The gateway recovers: the next name reuses the anchor and the
      // endpoints (no quarantine after a gateway timeout).
      steps: [{ call: content() }, { after: 100, world: { gateways: GATEWAY(10) }, call: content('nick.eth') }],
    },
    // Gateways in list order: an HTTP error and a redirect fall through.
    one('ccip-gateway-errors-fall-through', base({
      calls: { resolve: lookupVia(['gw1.example', 'gw2.example', 'gw3.example']), callback: GOOD },
      gateways: { 'gw1.example': { status: 500 }, 'gw2.example': { redirect: 'https://elsewhere.example/x' }, 'gw3.example': { body: JSON.stringify({ data: '0xcafe' }) } },
    })),
    // Every gateway fails: an error leg, without quarantine.
    one('ccip-all-gateways-fail', base({ calls: { resolve: lookupVia(['gw1.example']), callback: GOOD }, gateways: { 'gw1.example': { status: 500 } } })),
    one('single-source-two-endpoints', base({ endpoints: ENDPOINTS.slice(0, 2) })),
    one('anchor-hash-split', base({ hosts: { 'c.rpc.example': { fork: true }, 'd.rpc.example': { fork: true } } })),
    one('anchor-finalized', base({ network: { ...QUORUM_NETWORK, quorum: { ...QUORUM_NETWORK.quorum, anchor: 'finalized' } } })),
    one('node-errors-agree', base({ calls: { resolve: { rpc_error: { code: -32000, message: 'header not found' } } } })),
    // A verified answer lives 15 minutes; an unverified one a minute.
    { id: 'cache-boundary-verified', world: base({}), steps: [{ call: content() }, { call: content() }, { after: 899_999, call: content() }, { after: 1, call: content() }] },
    { id: 'cache-boundary-unverified', world: base({ endpoints: ENDPOINTS.slice(0, 2) }), steps: [{ call: content() }, { after: 59_999, call: content() }, { after: 1, call: content() }] },
    {
      // b answers HTTP 503: quarantined for 60 s. An expired entry is
      // dropped before b is retried, so each later failure starts again
      // at 60 s; b rejoins once it recovers.
      id: 'quarantine-expiry-resets',
      world: base({ hosts: { 'b.rpc.example': { status: 503 } } }),
      steps: [
        { call: content('vitalik.eth') },
        { after: 30_000, call: content('nick.eth') },
        { after: 31_000, call: content('brantly.eth') },
        { after: 61_000, call: content('jesse.eth') },
        { after: 61_000, world: { hosts: {} }, call: content('luc.eth') },
        { after: 1_000, call: content('ens.eth') },
      ],
    },
    {
      // Two concurrent lookups both fail on b within one entry: 120 s.
      id: 'quarantine-doubles-on-overlapping-failures',
      world: base({ hosts: { 'b.rpc.example': { status: 503 } }, calls: { resolve: GOOD, 'resolve:addr': ADDRESS, callback: GOOD } }),
      steps: [
        { calls: [content(), { fn: 'resolveEnsAddress', args: ['vitalik.eth'] }] },
        { after: 61_000, call: content('nick.eth') },
        { after: 60_000, call: content('brantly.eth') },
      ],
    },
    {
      // Same label and name share one lookup; content and address don't,
      // and each probes the anchor.
      id: 'dedup-concurrent',
      world: base({ calls: { resolve: GOOD, 'resolve:addr': ADDRESS, callback: GOOD } }),
      steps: [{ calls: [content(), content(), { fn: 'resolveEnsAddress', args: ['vitalik.eth'] }] }],
    },
    { id: 'settings-invalidation', world: base({}), steps: [{ call: content() }, { call: { fn: 'invalidateCachedProvider' } }, { call: content() }] },
    {
      id: 'direct-user-configured',
      world: base({ network: order(['direct']), sources: [{ id: 'mine', coverage: { 1: ENDPOINTS[0] } }], sourceList: [{ id: 'mine', builtin: false }] }),
      steps: [{ call: content() }],
    },
    one('direct-builtin', base({ network: order(['direct']), sources: [{ id: 'pub', coverage: { 1: ENDPOINTS[0] } }], sourceList: [{ id: 'pub', builtin: true }] })),
    ...addressAndReverse(ethers, base, one),
    ...verifiedPaths(ethers, base, one, order, GOOD, lookup),
    ...deviationScenarios(ethers, base, GOOD, lookupVia, contentAnswer),
    ...tezosScenarios(),
  ];
}

/**
 * Deviation vectors (design 0004, Deviations): the reference patched to do
 * what the core does at a bound (see PATCHES). Bounds are lowered where the
 * real one would take a large vector.
 */
function deviationScenarios(ethers, base, GOOD, lookupVia, contentAnswer) {
  const deviation = (id, world, steps = [{ call: content() }]) => ({ id: `deviation-${id}`, deviation: id, patches: [id], world, steps });
  // A long unsupported contenthash: 8,202 hex characters with its 0x.
  const long = (byte) => contentAnswer('0x' + byte.repeat(4100));
  const twoGateways = (first) => ({ resolve: lookupVia(['gw-big.example', 'gw.example']), callback: GOOD, ...first });
  // The direct method on https://a.rpc.example, with another configured
  // URL on the same host.
  const SAME_HOST = {
    endpoints: [...ENDPOINTS, `https://a.rpc.example/${'p'.repeat(1000)}`],
    network: { ...QUORUM_NETWORK, verification: { order: ['direct'], preferVerified: false } },
    sources: [{ id: 'pub', coverage: { 1: ENDPOINTS[0] } }],
    sourceList: [{ id: 'pub', builtin: true }],
  };
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const revert = (data) => ({ rpc_error: { code: 3, message: 'execution reverted', data } });
  const offchain = (urls, callData = '0x0102', extraData = '0x09') => revert('0x556f1830' + coder.encode(
    ['address', 'string[]', 'bytes', 'bytes4', 'bytes'], [UR, urls, callData, '0xdeadbeef', extraData]).slice(2));
  // An OffchainLookup whose URL array points every entry at one string,
  // which ethers decodes once per entry.
  const aliasedLookup = (url, copies) => {
    const word = (n) => n.toString(16).padStart(64, '0');
    const pad = (hex) => hex + '0'.repeat((64 - (hex.length % 64)) % 64);
    const urls = word(copies) + word(copies * 32).repeat(copies) + word(url.length) + pad(Buffer.from(url).toString('hex'));
    const bytes = (hex) => word((hex.length - 2) / 2) + pad(hex.slice(2));
    const callData = bytes('0x0102');
    const at = 160 + urls.length / 2;
    const head = UR.slice(2).toLowerCase().padStart(64, '0') + word(160) + word(at) + 'deadbeef'.padEnd(64, '0') + word(at + callData.length / 2);
    return revert('0x556f1830' + head + urls + callData + bytes('0x09'));
  };
  return [
    // Three gateway URLs and a bound of two: the reference reaches the
    // working third gateway, the core gives up after two.
    deviation('ccip-urls', base({
      bounds: { ccipUrls: 2 },
      calls: { resolve: lookupVia(['gw-a.example', 'gw-b.example', 'gw.example']), callback: GOOD },
      gateways: { 'gw-a.example': { status: 500 }, 'gw-b.example': { status: 500 }, 'gw.example': { body: JSON.stringify({ data: '0xcafe' }) } },
    })),
    deviation('reply-shortening', base({ calls: { resolve: long('ab'), callback: GOOD } })),
    {
      // Four different long answers: a conflict whose groups carry them.
      ...deviation('reply-shortening', base({
        hosts: Object.fromEntries(['ab', 'cd', 'ef', '12'].map((byte, i) => [new URL(ENDPOINTS[i]).host, { calls: { resolve: long(byte) } }])),
      })),
      id: 'deviation-reply-shortening-groups',
    },
    // An endpoint whose answers outgrow the cap fails as a provider.
    deviation('response-caps', base({ bounds: { answerBytes: 4096 }, hosts: { 'd.rpc.example': { pad: 5000 } } }), [
      { call: content() },
      { after: 1000, call: content('alice.eth') },
    ]),
    {
      // A gateway answer over the cap: the next gateway answers instead.
      ...deviation('response-caps', base({
        bounds: { answerBytes: 4096 },
        calls: twoGateways({}),
        gateways: { 'gw-big.example': { body: JSON.stringify({ data: '0xbeef', pad: 'x'.repeat(5000) }) }, 'gw.example': { body: JSON.stringify({ data: '0xcafe' }) } },
      })),
      id: 'deviation-response-caps-gateway',
    },
    // Two agreed lookups and a set of one: the second aborts the first's
    // prefetch.
    deviation('prefetch-set', base({ bounds: { prefetches: 1 } }), [
      { call: content() },
      { after: 1000, call: content('alice.eth') },
    ]),
    {
      // A set of two. B's prefetch finishes, so C's hand-off still fits
      // beside A; D's then aborts A.
      ...deviation('prefetch-set', base({ bounds: { prefetches: 2 } }), [
        { call: content('a.eth') },
        { after: 1000, world: { prefetchMs: 10 }, call: content('b.eth') },
        { after: 1000, world: { prefetchMs: 0 }, call: content('c.eth') },
        { after: 1000, call: content('d.eth') },
      ]),
      id: 'deviation-prefetch-set-finished',
    },
    {
      // Every endpoint answers at its own pace, so the second lookup's
      // first answer comes before its agreement: the hand-off, and the
      // abort, wait for the agreement.
      ...deviation('prefetch-set', base({ bounds: { prefetches: 1 } }), [
        { call: content() },
        { after: 1000, world: { hosts: { 'b.rpc.example': { delay: 100 }, 'c.rpc.example': { delay: 200 }, 'd.rpc.example': { delay: 300 } } }, call: content('alice.eth') },
      ]),
      id: 'deviation-prefetch-set-late-agreement',
    },
    {
      // Both together: B's prefetch finishes before its wave agrees, so
      // its hand-off keeps nothing and A survives; C's aborts A.
      ...deviation('prefetch-set', base({ bounds: { prefetches: 1 } }), [
        { call: content() },
        { after: 1000, world: { prefetchMs: 10, hosts: { 'b.rpc.example': { delay: 100 }, 'c.rpc.example': { delay: 200 }, 'd.rpc.example': { delay: 300 } } }, call: content('alice.eth') },
        { after: 1000, world: { prefetchMs: 0, hosts: {} }, call: content('bob.eth') },
      ]),
      id: 'deviation-prefetch-set-finished-before-agreement',
    },
    // A 3,000-byte callData makes both gateway requests (GET and POST)
    // too large for an 8 KiB frame.
    deviation('request-size', base({
      bounds: { messageBytes: 8192 },
      calls: { resolve: offchain(['https://gw.example/{sender}/{data}.json', 'https://gw-post.example/lookup'], '0x' + 'ab'.repeat(3000)), callback: GOOD },
      gateways: { 'gw.example': { body: JSON.stringify({ data: '0xcafe' }) }, 'gw-post.example': { body: JSON.stringify({ data: '0xcafe' }) } },
    })),
    {
      // The gateway's 2,500 bytes and 2,000 of extraData: a callback too
      // large for the frame.
      ...deviation('request-size', base({
        bounds: { messageBytes: 8192 },
        calls: { resolve: offchain(['https://gw.example/{sender}/{data}.json'], '0x0102', '0x' + '09'.repeat(2000)), callback: GOOD },
        gateways: { 'gw.example': { body: JSON.stringify({ data: '0x' + 'cd'.repeat(2500) }) } },
      })),
      id: 'deviation-request-size-callback',
    },
    // A 6,000-character unsupported content hash: the result outgrows a
    // 4 KiB reply, so it is never cached and the second lookup resolves
    // again.
    deviation('reply-size', base({ bounds: { replyBytes: 4096 }, calls: { resolve: contentAnswer('0x' + 'ab'.repeat(3000)), callback: GOOD } }), [
      { call: content() },
      { after: 1000, call: content() },
    ]),
    // Three cached results outgrow the byte budget: the first is evicted,
    // so looking it up again resolves anew.
    deviation('cache-bytes', base({ bounds: { cacheBytes: CACHE_BYTES } }), [
      { call: content('a.eth') },
      { after: 1000, call: content('b.eth') },
      { after: 1000, call: content('c.eth') },
      { after: 1000, call: content('a.eth') },
    ]),
    // One 600-character URL referenced eight times: 4,800 decoded bytes
    // from a much smaller lookup.
    deviation('decode-budget', base({
      bounds: { decodeBytes: 4096 },
      calls: { resolve: aliasedLookup(`https://gw.example/{sender}/{data}.json?pad=${'x'.repeat(556)}`, 8), callback: GOOD },
      gateways: { 'gw.example': { body: JSON.stringify({ data: '0xcafe' }) } },
    })),
    // One session at a time, two callers per session: the third caller of
    // a running session and a second session are both busy.
    deviation('admission', base({ bounds: { sessions: 1, callersPerSession: 2 } }), [
      { calls: [content(), content(), content(), content('alice.eth')] },
    ]),
    {
      // One waiting caller in all: a cache hit is refused while another
      // caller waits.
      ...deviation('admission', base({ bounds: { callers: 1 } }), [
        { call: content() },
        { after: 1000, calls: [content('alice.eth'), content()] },
      ]),
      id: 'deviation-admission-callers',
    },
    {
      // A name of 100 é: the result is 684 UTF-16 units but 784 bytes as
      // the core serializes it, so a 734-byte bound refuses it.
      ...deviation('reply-size', base({ bounds: { replyBytes: 734 } }), [
        { call: content('é'.repeat(100) + '.eth') },
        { after: 1000, call: content('é'.repeat(100) + '.eth') },
      ]),
      id: 'deviation-reply-size-unicode',
    },
    {
      // Two configured URLs on one host: the direct method uses the short
      // one, so its result is 492 bytes as the core holds it (the other
      // URL's 1,000-character path doesn't count), and it is cached. A name
      // of three 100-é labels makes a larger result, which is refused.
      ...deviation('reply-size', base({ ...SAME_HOST, bounds: { replyBytes: 1000 } }), [
        { call: content() },
        { after: 1000, call: content() },
        { after: 1000, call: content(`${'é'.repeat(100)}.${'é'.repeat(100)}.${'é'.repeat(100)}.eth`) },
      ]),
      id: 'deviation-reply-size-same-host',
    },
    {
      // The same world: two 497-byte entries fit 1,000 bytes and a third
      // evicts the oldest, so b.eth is still cached and a.eth is not.
      ...deviation('cache-bytes', base({ ...SAME_HOST, bounds: { cacheBytes: 1000 } }), [
        { call: content('a.eth') },
        { after: 1000, call: content('b.eth') },
        { after: 1000, call: content('c.eth') },
        { after: 1000, call: content('b.eth') },
        { after: 1000, call: content('a.eth') },
      ]),
      id: 'deviation-cache-bytes-same-host',
    },
    {
      // One session at a time. A lifecycle change at 5 ms retires the first
      // lookup's in-flight entry, but it still runs, so a second name at
      // 10 ms is busy.
      ...deviation('admission', base({ bounds: { sessions: 1 } }), [
        {
          calls: [content(), { ...content('alice.eth'), at: 10 }],
          events: [{ at: 5, myotis: { ready: false } }],
        },
      ]),
      id: 'deviation-admission-lifecycle-overlap',
    },
    // Every endpoint answers after a second; the session ends at 300 ms.
    deviation('overall-deadline', base({
      bounds: { deadlineMs: 300 },
      hosts: Object.fromEntries(ENDPOINTS.map((url) => [new URL(url).host, { delay: 1000 }])),
    })),
  ];
}

/** Myotis and Colibri, alone, in the method order, and across transitions. */
function verifiedPaths(ethers, base, one, order, GOOD, lookup) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const notFound = ethers.id('ResolverNotFound(bytes)').slice(0, 10) + coder.encode(['bytes'], ['0x00']).slice(2);
  const COLIBRI = (calls) => ({ prover: 'https://prover.example', calls });
  return [
    one('myotis-verified', base({ network: order(['myotis', 'colibri', 'quorum']), myotis: { enabled: true, ready: true, calls: { resolve: GOOD } } })),
    one('myotis-not-ready-falls-to-quorum', base({ network: order(['myotis', 'quorum']), myotis: { enabled: true, ready: false } })),
    one('colibri-verified', base({ network: order(['colibri', 'quorum']), colibri: COLIBRI({ resolve: GOOD }) })),
    one('colibri-resolver-not-found', base({ network: order(['colibri', 'quorum']), colibri: COLIBRI({ resolve: { revert: notFound } }) })),
    one('colibri-unavailable-falls-to-quorum', base({ network: order(['colibri', 'quorum']), colibri: COLIBRI({ resolve: { unavailable: true } }) })),
    // Colibri with ethers' built-in CCIP-Read, and two operations at once:
    // every raw call belongs to its own operation.
    one('colibri-ccip', base({
      network: order(['colibri']),
      colibri: COLIBRI({ resolve: { revert: lookup }, callback: GOOD }),
      gateways: { 'gw.example': { delay: 50, body: JSON.stringify({ data: '0xcafe' }) } },
    })),
    {
      id: 'colibri-concurrent',
      world: base({ network: order(['colibri']), colibri: COLIBRI({ resolve: GOOD }) }),
      steps: [{ calls: [content(), content('nick.eth')] }],
    },
    one('myotis-ccip', base({
      network: order(['myotis', 'quorum']),
      myotis: { enabled: true, ready: true, calls: { resolve: { revert: lookup }, callback: GOOD } },
      gateways: { 'gw.example': { delay: 50, body: JSON.stringify({ data: '0xcafe' }) } },
    })),
    {
      // Availability changes during the operation's gateway fetch, between
      // its raw calls. MyotisProvider checks the epoch the operation started
      // with before each call, so the callback is never sent: the operation
      // fails (`error`), the order continues to quorum, and the attempt,
      // which crossed the change, restarts through Myotis.
      id: 'myotis-lifecycle-between-calls',
      world: base({
        network: order(['myotis', 'quorum']),
        myotis: { enabled: true, ready: true, calls: { resolve: { revert: lookup }, callback: GOOD } },
        gateways: { 'gw.example': { delay: 50, body: JSON.stringify({ data: '0xcafe' }) } },
      }),
      steps: [{ call: content(), events: [{ at: 30, myotis: { ready: true } }] }],
    },
    // Quorum can only reach one source (two endpoints): unverified, held
    // while Myotis is tried, which then answers verified.
    one('prefer-verified-holds-unverified', base({ endpoints: ['https://a.rpc.example', 'https://b.rpc.example'], network: order(['quorum', 'myotis'], true), myotis: { enabled: true, ready: true, calls: { resolve: GOOD } } })),
    {
      // Myotis becomes ready while quorum is resolving: the result is
      // discarded and the lookup restarts, now through Myotis.
      id: 'myotis-ready-mid-flight',
      world: base({ network: order(['myotis', 'quorum']), myotis: { enabled: true, ready: false, calls: { resolve: GOOD } } }),
      steps: [{ call: content(), events: [{ at: 30, myotis: { ready: true } }] }],
    },
    {
      // Three transitions, each during an attempt: the lookup gives up.
      id: 'lifecycle-flapping',
      world: base({}),
      steps: [{ call: content(), events: [{ at: 30, myotis: { ready: false } }, { at: 75, myotis: { ready: false } }, { at: 100, myotis: { ready: false } }] }],
    },
  ];
}

/** Address and reverse lookups, ENS and WNS/GNS. */
function addressAndReverse(ethers, base, one) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const ACCOUNT = '0x' + 'ab'.repeat(20);
  const urAddress = (address) => ({ data: coder.encode(['bytes', 'address'], [coder.encode(['address'], [address]), '0x' + '22'.repeat(20)]) });
  const urMulticoin = (bytes) => ({ data: coder.encode(['bytes', 'address'], [coder.encode(['bytes'], [bytes]), '0x' + '22'.repeat(20)]) });
  const urReverse = (name) => ({ data: coder.encode(['string', 'address', 'address'], [name, '0x' + '22'.repeat(20), '0x' + '33'.repeat(20)]) });
  const mismatch = ethers.id('ReverseAddressMismatch(string,bytes)').slice(0, 10) + coder.encode(['string', 'bytes'], ['claimed.eth', '0x']).slice(2);
  const nftString = (text) => ({ data: coder.encode(['string'], [text]) });
  const nftAddress = (address) => ({ data: coder.encode(['address'], [address]) });
  const nftBytes = (bytes) => ({ data: coder.encode(['bytes'], [bytes]) });
  const address = (name, chainId) => ({ fn: 'resolveEnsAddress', args: chainId === undefined ? [name] : [name, chainId] });
  const reverse = { fn: 'resolveEnsReverse', args: [ACCOUNT] };
  return [
    one('address-agree', base({ calls: { resolve: urAddress(ACCOUNT) } }), address('vitalik.eth')),
    one('address-multicoin-base', base({ calls: { resolve: urMulticoin(ACCOUNT) } }), address('vitalik.eth', 8453)),
    one('address-zero-is-no-address', base({ calls: { resolve: urAddress(ethers.ZeroAddress) } }), address('vitalik.eth')),
    {
      // A label of 150 é is 300 bytes: ethers' dnsEncode(name, 255) refuses
      // it in every leg, with its own message. One of exactly 255 bytes
      // resolves.
      id: 'ens-label-over-255-bytes',
      world: base({}),
      steps: [
        { call: content(`${'é'.repeat(150)}.eth`) },
        { after: 1000, call: address(`${'é'.repeat(150)}.eth`) },
        { after: 1000, call: content(`${'a'.repeat(255)}.eth`) },
      ],
    },
    one('reverse-agree', base({ calls: { reverse: urReverse('vitalik.eth') } }), reverse),
    one('reverse-mismatch', base({ calls: { reverse: { rpc_error: { code: 3, message: 'execution reverted', data: mismatch } } } }), reverse),
    one('reverse-ens-empty-then-wns', base({ calls: { reverse: urReverse(''), 'wns:reverse': nftString('alice.wei'), 'wns:addr': nftAddress(ACCOUNT), 'gns:reverse': nftString('') } }), reverse),
    one('reverse-ens-and-wns-empty-then-gns', base({ calls: { reverse: urReverse(''), 'wns:reverse': nftString(''), 'gns:reverse': nftString('bob.gwei'), 'gns:addr': nftAddress(ACCOUNT) } }), reverse),
    one('reverse-wns-claim-fails-forward-then-gns-empty', base({ calls: { reverse: urReverse(''), 'wns:reverse': nftString('alice.wei'), 'wns:addr': nftAddress('0x' + 'cd'.repeat(20)), 'gns:reverse': nftString('') } }), reverse),
    one('gns-content', base({ calls: { 'gns:contenthash': nftBytes('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f') } }), content('bob.gwei')),
    one('wns-content', base({ calls: { 'wns:contenthash': nftBytes('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f') } }), content('alice.wei')),
    one('wns-address-on-l2', base({}), address('alice.wei', 8453)),
    // Through Myotis: the ENS reverse is a record operation; WNS calls are
    // the resolver's own NameNFT operations, with the optimistic block.
    one('myotis-reverse-then-wns', base({
      network: { ...QUORUM_NETWORK, verification: { order: ['myotis'], preferVerified: false } },
      myotis: { enabled: true, ready: true, block: 23_456_789, calls: { reverse: urReverse(''), 'wns:reverse': nftString('alice.wei'), 'wns:addr': nftAddress(ACCOUNT) } },
    }), reverse),
    {
      // Availability changes during the WNS forward check of a Myotis
      // reverse. readMyotisReverse catches that failure itself, keeps the
      // unverified claim and tries GNS; tryMyotisReverse's check around the
      // whole method then throws MYOTIS_LIFECYCLE_CHANGED, and the lookup
      // restarts through Myotis at once, with no quorum I/O.
      id: 'myotis-reverse-lifecycle-forward-check',
      world: base({
        network: { ...QUORUM_NETWORK, verification: { order: ['myotis', 'quorum'], preferVerified: false } },
        myotis: { enabled: true, ready: true, block: 23_456_789, calls: { reverse: urReverse(''), 'wns:reverse': nftString('alice.wei'), 'wns:addr': nftAddress(ACCOUNT), 'gns:reverse': nftString('') } },
        calls: { reverse: urReverse(''), 'wns:reverse': nftString('alice.wei'), 'wns:addr': nftAddress(ACCOUNT), 'gns:reverse': nftString('') },
      }),
      steps: [{ call: reverse, events: [{ at: 25, myotis: { ready: true } }] }],
    },
    one('myotis-wns-content', base({
      network: { ...QUORUM_NETWORK, verification: { order: ['myotis'], preferVerified: false } },
      myotis: { enabled: true, ready: true, block: 23_456_789, calls: { 'wns:contenthash': nftBytes('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f') } },
    }), content('alice.wei')),
    // A NameNFT call that doesn't succeed is a failed operation; the
    // order moves on to quorum.
    one('myotis-wns-call-unavailable', base({
      network: { ...QUORUM_NETWORK, verification: { order: ['myotis', 'quorum'], preferVerified: false } },
      myotis: { enabled: true, ready: true, block: 23_456_789, calls: { 'wns:contenthash': { unavailable: true } } },
      calls: { 'wns:contenthash': nftBytes('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f') },
    }), content('alice.wei')),
    one('myotis-wns-call-revert', base({
      network: { ...QUORUM_NETWORK, verification: { order: ['myotis', 'quorum'], preferVerified: false } },
      myotis: { enabled: true, ready: true, block: 23_456_789, calls: { 'wns:contenthash': { revert: '0x12345678' } } },
      calls: { 'wns:contenthash': nftBytes('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f') },
    }), content('alice.wei')),
    // Availability changes in the middle of each kind of operation.
    {
      id: 'myotis-record-lifecycle-mid-operation',
      world: base({
        network: { ...QUORUM_NETWORK, verification: { order: ['myotis', 'quorum'], preferVerified: false } },
        myotis: { enabled: true, ready: true, calls: { resolve: urAddress(ACCOUNT) } },
        calls: { resolve: urAddress(ACCOUNT) },
      }),
      steps: [{ call: address('vitalik.eth'), events: [{ at: 5, myotis: { ready: true } }] }],
    },
    {
      id: 'myotis-call-lifecycle-mid-operation',
      world: base({
        network: { ...QUORUM_NETWORK, verification: { order: ['myotis', 'quorum'], preferVerified: false } },
        myotis: { enabled: true, ready: true, block: 23_456_789, calls: { 'wns:contenthash': nftBytes('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f') } },
        calls: { 'wns:contenthash': nftBytes('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f') },
      }),
      steps: [{ call: content('alice.wei'), events: [{ at: 5, myotis: { ready: true } }] }],
    },
  ];
}

/** Tezos Domains: the pinned resolver with a scripted node per endpoint. */
function tezosScenarios() {
  const T = ['https://t1.tez.example', 'https://t2.tez.example', 'https://t3.tez.example'];
  const SITE = 'ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/';
  const base = (extra) => ({ endpoints: T, record: tezRecord({ 'web:content_url': SITE, 'td:ttl': 600 }), expiry: '2030-01-01T00:00:00Z', ...extra });
  const tez = (name = 'alice.tez') => ({ fn: 'resolveTezosDomain', args: [name] });
  const one = (id, world, steps = [{ call: tez() }]) => ({ id, system: 'tezos', world, steps });
  return [
    one('tezos-agree', base({}), [{ call: tez() }, { after: 1000, call: tez() }, { after: 60_000, call: tez('bob.tez') }]),
    one('tezos-one-liar', base({ hosts: { 't2.tez.example': { record: tezRecord({ 'web:content_url': 'https://evil.example/' }) } } })),
    one('tezos-head-outlier', base({ hosts: { 't3.tez.example': { level: TEZ_HEAD - 61 } } })),
    one('tezos-heads-scattered', base({ hosts: { 't1.tez.example': { level: TEZ_HEAD - 200 }, 't3.tez.example': { level: TEZ_HEAD + 200 } } })),
    one('tezos-anchor-split', base({ hosts: { 't2.tez.example': { fork: true } } })),
    one('tezos-two-down', base({ hosts: { 't1.tez.example': { fail: true }, 't2.tez.example': { hang: true } } }), [{ call: tez() }, { after: 1000, call: tez() }]),
    one('tezos-all-down', base({ hosts: { 't1.tez.example': { fail: true }, 't2.tez.example': { fail: true }, 't3.tez.example': { fail: true } } }), [{ call: tez() }, { after: 1000, call: tez() }]),
    one('tezos-expired', base({ expiry: '2020-01-01T00:00:00Z' })),
    one('tezos-expiry-unparseable', base({ expiry: 'not a date' })),
    one('tezos-redirect', base({ record: tezRecord({ 'web:redirect_url': 'https://alice.example/' }) })),
    one('tezos-no-website', base({ record: tezRecord({ 'td:ttl': 60 }, null) })),
    // No td:ttl: the result has `ttl` present and undefined.
    one('tezos-no-website-no-ttl', base({ record: tezRecord({}) })),
    one('tezos-no-record', base({ record: null }), [{ call: tez() }, { after: 29_999, call: tez() }, { after: 1, call: tez() }]),
    one('tezos-registry-script-fails', base({ hosts: { 't1.tez.example': { scriptFail: true } } })),
    one('tezos-invalid-name', base({}), [{ call: tez('alice.eth') }]),
    // No anchor hash at all, and no successful lookup: distinct errors.
    one('tezos-no-anchor', base({ hosts: Object.fromEntries(T.map((url) => [new URL(url).host, { anchorFail: true }])) })),
    one('tezos-all-lookups-fail', base({ hosts: Object.fromEntries(T.map((url) => [new URL(url).host, { scriptFail: true }])) })),
    // A lookup failing on cached discovery rediscovers once, then gives up.
    one('tezos-cached-discovery-lookup-fails', base({}), [
      { call: tez() },
      { after: 1000, world: { hosts: { 't1.tez.example': { recordFail: true } } }, call: tez('bob.tez') },
    ]),
    // Deviation vectors (see deviationScenarios): a past expiry in a
    // format only V8 reads, and a node whose answers outgrow the cap.
    { ...one('deviation-tezos-expiry', base({ expiry: 'Wed, 01 Jan 2020 00:00:00 GMT' })), deviation: 'tezos-expiry', patches: ['tezos-expiry'] },
    { ...one('deviation-response-caps-tezos', base({ bounds: { answerBytes: 4096 }, hosts: { 't3.tez.example': { pad: 5000 } } })), deviation: 'response-caps', patches: ['response-caps'] },
    // A head conflict: its groups publish hosts, the core holds
    // references, so it is 401 bytes, not 353, and a 377-byte bound
    // refuses it.
    {
      ...one('deviation-reply-size-tezos-conflict', base({ bounds: { replyBytes: 377 }, hosts: { 't1.tez.example': { level: TEZ_HEAD - 200 }, 't3.tez.example': { level: TEZ_HEAD + 200 } } })),
      deviation: 'reply-size',
      patches: ['reply-size'],
    },
    // A result too large to reply is never cached: the second lookup
    // resolves again.
    {
      ...one('deviation-reply-size-tezos-uncached', base({ bounds: { replyBytes: 400 } }), [{ call: tez() }, { after: 1000, call: tez() }]),
      deviation: 'reply-size',
      patches: ['reply-size'],
    },
  ];
}

function loadFakeTimers(checkout) {
  return Module.createRequire(path.join(checkout, 'package.json'))('@sinonjs/fake-timers');
}

async function buildNamingReplay(checkout, ethers, meta) {
  const FakeTimers = loadFakeTimers(checkout);
  const out = [];
  for (const scenario of scenarioDefinitions(ethers)) {
    const run = await runScenario(checkout, ethers, FakeTimers, scenario);
    if (scenario.deviation) {
      // The deviation must show: the unpatched reference differs in its
      // results or its I/O.
      const plain = await runScenario(checkout, ethers, FakeTimers, { ...scenario, deviation: undefined, patches: [] });
      const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
      if (same(plain.steps, run.steps) && same(plain.io, run.io)) throw new Error(`deviation vector ${scenario.id}: the patches change nothing`);
      run.unpatched = plain.steps.map((step) => step.results);
    }
    out.push(run);
  }
  return { meta, scenarios: out };
}

module.exports = { buildNamingReplay, runScenario, scenarioDefinitions, loadFakeTimers, PATCHES, __toCore };
