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

const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
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
function loadModule(checkout, stubs, file, wrappers = {}) {
  const src = path.join(checkout, 'src');
  const main = path.join(src, 'main');
  const filename = path.join(main, file);
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
      if (resolved && wrapBy.has(resolved)) {
        if (!wrapped.has(resolved)) wrapped.set(resolved, wrapBy.get(resolved)(originalLoad.call(this, request, parent, isMain)));
        return wrapped.get(resolved);
      }
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    evict();
    const mod = new Module(filename, null);
    mod.filename = filename;
    mod.paths = Module._nodeModulePaths(path.dirname(filename));
    Module._cache[filename] = mod;
    mod._compile(fs.readFileSync(filename, 'utf8'), filename);
    mod.loaded = true;
    return { exports: mod.exports, restore };
  } catch (err) {
    restore();
    throw err;
  }
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
  const record = (entry) => {
    const item = { id: io.length, step: stepIndex, t: now(), ...entry, end: null, outcome: 'open' };
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
        clearTimeout(inactivity);
        for (const item of entries) close(item, 'answered');
        const out = answers.map(({ id, result, error }) => (error ? { jsonrpc: '2.0', id, error } : { jsonrpc: '2.0', id, result }));
        const answer = p.status
          ? { status: p.status, body: 'unavailable' }
          : { status: 200, body: JSON.stringify(Array.isArray(body) ? out : out[0]) };
        for (const item of entries) item.answer = answer;
        if (signal?.cancelled) {
          fail('cancelled', 'CANCELLED');
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
      if (!g) violations.push(`undeclared gateway ${host}`);
      if (!g || g.hang) return;
      timer = setTimeout(() => {
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
  const verified = (source, state, to, data) => {
    const kind = callKind(to, data);
    const item = record({ kind: 'verified', host: source, method: 'eth_call', params: [{ to, data }, 'latest'], call: kind });
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
    if (err?.code === 'MYOTIS_LIFECYCLE_CHANGED' || err?.code === 'MYOTIS_UNAVAILABLE') return 'lifecycle';
    if (err?.code === 'TIMEOUT') return 'timeout';
    return 'error';
  };
  const revertOf = (err) => {
    const data = err?.data ?? err?.info?.error?.data;
    return typeof data === 'string' && /^0x[0-9a-f]*$/i.test(data) ? data : null;
  };
  const operation = (host, op, params, run) => {
    const item = record({ kind: 'verified-op', host, op, params });
    return insideOperation.run(true, run).then(
      (value) => {
        item.answer = { result: describe(value) };
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
        const answer = await verified('myotis', myotis(), to, data);
        if (answer.data) return { status: 'ok', resultHex: answer.data };
        if (answer.revert) return { status: 'revert', dataHex: answer.revert };
        return { status: 'error' };
      };
      // The resolver's own NameNFT calls are whole operations (with the
      // block number it reads next); calls inside a record operation are
      // that operation's raw calls.
      if (insideOperation.getStore()) return call();
      return operation('myotis', 'call', { to, data }, async () => ({ ...(await call()), optimisticBlockNumber: myotis().block ?? null }));
    },
  };
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
        const answer = await verified('colibri', colibri(), params[0].to, params[0].data);
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
    if (route === '/chains/main/blocks/head/header') return json(200, { level });
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
        return { abort: () => close(item, 'cancelled') };
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
      (error) => { results[i] = { thrown: String(error?.message ?? error), settled: now() }; }
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

    const previousGetUrl = new ethers.FetchRequest('https://snapshot.invalid').getUrlFunc;
    undo.push(() => ethers.FetchRequest.registerGetUrl(previousGetUrl));
    ethers.FetchRequest.registerGetUrl(rpcTransport);

    clock = FakeTimers.install({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'], now: EPOCH });
    undo.push(() => clock.uninstall());

    const loaded = system === 'tezos'
      ? loadModule(checkout, stubs, 'tezos-domains-resolver.js')
      : loadModule(checkout, stubs, 'ens-resolver.js', wrappers);
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
    const invoke = ({ fn, args = [] }) => Promise.resolve().then(() => (fn === '$fetch' ? probeFetch(...args) : system === 'tezos'
      ? loaded.exports[fn](...args, { fetchImpl, endpoints: world.endpoints })
      : loaded.exports[fn](...args)));

    const steps = [];
    for (const [index, step] of scenario.steps.entries()) {
      if (step.after) await clock.tickAsync(step.after);
      stepIndex = index;
      if (step.world) Object.assign(world, structuredClone(step.world));
      const at = now();
      for (const event of step.events ?? []) setTimeout(() => fire(event), event.at);
      const results = await settleAll((step.calls ?? [step.call]).map(invoke));
      steps.push(describe({ at, ...step, results }));
    }
    // Let stragglers finish, so a late answer nobody waits for is recorded
    // as answered rather than left open.
    const limit = Date.now() + MAX_STEP_MS;
    while (clock.countTimers() > 0 && Date.now() < limit) await clock.nextAsync();
    if (violations.length > 0) throw new Error(`scenario ${scenario.id}: unscripted I/O: ${[...new Set(violations)].join('; ')}`);
    return { id: scenario.id, system, seed: scenario.seed ?? 7, world: describe(scenario.world), steps, io: describe(io) };
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
    ...tezosScenarios(),
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
    one('myotis-ccip', base({
      network: order(['myotis', 'quorum']),
      myotis: { enabled: true, ready: true, calls: { resolve: { revert: lookup }, callback: GOOD } },
      gateways: { 'gw.example': { delay: 50, body: JSON.stringify({ data: '0xcafe' }) } },
    })),
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
    one('myotis-wns-content', base({
      network: { ...QUORUM_NETWORK, verification: { order: ['myotis'], preferVerified: false } },
      myotis: { enabled: true, ready: true, block: 23_456_789, calls: { 'wns:contenthash': nftBytes('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f') } },
    }), content('alice.wei')),
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
  ];
}

function loadFakeTimers(checkout) {
  return Module.createRequire(path.join(checkout, 'package.json'))('@sinonjs/fake-timers');
}

async function buildNamingReplay(checkout, ethers, meta) {
  const FakeTimers = loadFakeTimers(checkout);
  const out = [];
  for (const scenario of scenarioDefinitions(ethers)) out.push(await runScenario(checkout, ethers, FakeTimers, scenario));
  return { meta, scenarios: out };
}

module.exports = { buildNamingReplay, runScenario, scenarioDefinitions, loadFakeTimers };
