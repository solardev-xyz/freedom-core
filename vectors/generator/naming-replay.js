'use strict';

// Replay vectors for design 0004: the pinned ens-resolver.js, run whole in
// a scripted world. Every scenario gets a fresh resolver (no shared cache,
// anchor or quarantine), seeded Math.random, the reference's own fake
// timers, and a declarative script for every JSON-RPC endpoint and CCIP
// gateway. Each records the requests made (virtual time, endpoint, method,
// block pinning, call selector) and the result, with present-`undefined`
// keys kept as {"$undefined":true}.

const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const EPOCH = 1_760_000_000_000;
const WNS = '0x0000000000696760e15f265e828db644a0c242eb';
const GNS = '0x9d51d507bc7264d4fe8ad1cf7fe191933a0a81d6';
// Inner and NameNFT selectors: contenthash(bytes32), addr(bytes32),
// addr(bytes32,uint256), reverseResolve(address).
const SELECTORS = { '0xbc1c58d1': 'contenthash', '0x3b3b57de': 'addr', '0xf1cb7e06': 'addr-multicoin', '0x9af8b7aa': 'reverse' };
const HEAD = 20_000_000;
const UR = '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe';

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
 * Loads a fresh ens-resolver.js. `stubs` maps module paths (relative to
 * src/main, without .js) to stand-ins, whoever requires them; the resolver
 * is registered in the module cache so its lazy dependents (the Myotis and
 * Colibri adapters) see this same instance. `restore` evicts every checkout
 * module, so no state survives into the next scenario.
 */
function loadResolver(checkout, stubs, file = 'ens-resolver.js') {
  const main = path.join(checkout, 'src/main');
  const filename = path.join(main, file);
  const byPath = new Map(Object.entries(stubs).map(([rel, stub]) => [path.join(main, `${rel}.js`), stub]));
  const originalLoad = Module._load;
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
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  const evict = () => {
    for (const key of Object.keys(Module._cache)) if (key.startsWith(path.join(checkout, 'src'))) delete Module._cache[key];
  };
  evict();
  const mod = new Module(filename, null);
  mod.filename = filename;
  mod.paths = Module._nodeModulePaths(path.dirname(filename));
  Module._cache[filename] = mod;
  mod._compile(fs.readFileSync(filename, 'utf8'), filename);
  mod.loaded = true;
  return { resolver: mod.exports, restore: () => { Module._load = originalLoad; evict(); } };
}

/**
 * Runs one scenario. `world`:
 *   endpoints: registry RPC URLs, in order
 *   network: registry.getNetwork(1) (verification, quorum)
 *   hosts: per host { delay, head, fork, calls: { resolve, callback, reverse, '*' } }
 *     where a call answer is { data } | { rpc_error: { code, message, data? } } | { hang: true }
 *   gateways: per host { delay, status, body }
 *   call: { fn, args }, then: optional second call after `after` virtual ms
 */
async function runScenario(checkout, ethers, FakeTimers, scenario) {
  const { world } = scenario;
  const requests = [];
  const now = () => Date.now() - EPOCH;
  const hostOf = (url) => new URL(url).host;
  const plan = (host) => world.hosts?.[host] || {};

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
  const answerRpc = (host, r) => {
    const p = plan(host);
    switch (r.method) {
      case 'eth_chainId':
        return { result: '0x1' };
      case 'eth_blockNumber':
        return { result: ethers.toQuantity(p.head ?? HEAD) };
      case 'eth_getBlockByNumber': {
        const n = Number(r.params[0]);
        return {
          result: {
            number: ethers.toQuantity(n), hash: ethers.id(`${p.fork ? 'fork' : 'block'}${n}`), parentHash: ethers.id(`parent${n}`),
            timestamp: '0x1', nonce: '0x0000000000000000', difficulty: '0x0', gasLimit: '0x1', gasUsed: '0x0',
            miner: '0x' + '00'.repeat(20), extraData: '0x', baseFeePerGas: '0x1', transactions: [],
          },
        };
      }
      case 'eth_call': {
        const { to, data } = r.params[0];
        const kind = callKind(to, data);
        const answer = pickAnswer([p.calls, world.calls], kind);
        if (!answer) throw new Error(`unscripted ${kind} call to ${host}`);
        if (answer.rpc_error) return { error: answer.rpc_error };
        if (answer.hang) return { hang: true };
        return { result: answer.data };
      }
      default:
        throw new Error(`unscripted ${r.method}`);
    }
  };

  ethers.FetchRequest.registerGetUrl(async (req) => {
    const host = hostOf(req.url);
    const body = JSON.parse(Buffer.from(req.body).toString());
    const batch = Array.isArray(body) ? body : [body];
    const t = now();
    const answers = batch.map((r) => {
      const block = r.method === 'eth_call' ? r.params[1] : r.params?.[0];
      requests.push({ t, host, method: r.method, block: typeof block === 'string' ? block : null, selector: r.params?.[0]?.data?.slice(0, 10) ?? null });
      return { id: r.id, ...answerRpc(host, r) };
    });
    if (answers.some((a) => a.hang)) await new Promise(() => {});
    await new Promise((resolve) => setTimeout(resolve, plan(host).delay ?? 10));
    const out = answers.map(({ id, result, error }) => (error ? { jsonrpc: '2.0', id, error } : { jsonrpc: '2.0', id, result }));
    return { statusCode: 200, statusMessage: 'OK', headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(Array.isArray(body) ? out : out[0])) };
  });

  // The gateway transport, through a fake electron.net.
  const netRequest = (options) => {
    const req = new EventEmitter();
    req.setHeader = () => {};
    req.write = () => {};
    req.abort = () => req.emit('abort');
    req.end = () => {
      const host = hostOf(options.url);
      const g = world.gateways?.[host] || {};
      requests.push({ t: now(), host, method: `gateway ${options.method}`, block: null, selector: null });
      setTimeout(() => {
        const res = new EventEmitter();
        Object.assign(res, { statusCode: g.status ?? 200, statusMessage: 'OK', headers: {}, pause() {}, resume() {}, destroy() {} });
        req.emit('response', res);
        res.emit('data', Buffer.from(g.body ?? JSON.stringify({ data: '0x' })));
        res.emit('end');
      }, g.delay ?? 10);
    };
    return req;
  };

  const ELECTRON = {
    ipcMain: { handle() {} },
    net: { request: netRequest },
    session: { defaultSession: { resolveProxy: async () => 'DIRECT' } },
  };
  // Verified answers: { data } is proven return data, { revert } proven
  // revert data; anything else is an unavailable verifier.
  const verifiedAnswer = (source, to, data) => {
    const answer = pickAnswer([source.calls], callKind(to, data));
    requests.push({ t: now(), host: source.id, method: 'verified eth_call', block: 'latest', selector: data.slice(0, 10) });
    return answer;
  };
  const myotis = world.myotis ?? { enabled: false, ready: false };
  const MYOTIS = {
    onAvailabilityTransition() {},
    isEnabled: () => myotis.enabled ?? false,
    isReady: () => myotis.ready ?? false,
    getAvailabilityEpoch: () => 1,
    getStatus: () => ({ state: myotis.ready ? 'ready' : 'stopped', optimisticBlockNumber: myotis.block ?? null }),
    ethCall: async ({ to, data }) => {
      const answer = verifiedAnswer({ id: 'myotis', calls: myotis.calls }, to, data);
      await new Promise((resolve) => setTimeout(resolve, myotis.delay ?? 10));
      if (answer?.data) return { status: 'ok', resultHex: answer.data };
      if (answer?.revert) return { status: 'revert', dataHex: answer.revert };
      return { status: 'error' };
    },
  };
  const colibri = world.colibri ?? {};
  const COLIBRI_HOST = {
    ensureWorker: async () => {},
    createClient: () => ({
      async request({ method, params }) {
        if (method === 'eth_chainId') return '0x1';
        if (method !== 'eth_call') throw new Error(`unscripted Colibri ${method}`);
        const { to, data } = params[0];
        const answer = verifiedAnswer({ id: 'colibri', calls: colibri.calls }, to, data);
        await new Promise((resolve) => setTimeout(resolve, colibri.delay ?? 10));
        if (answer?.data) return answer.data;
        if (answer?.revert) throw Object.assign(new Error('execution reverted'), { code: 3, data: answer.revert });
        throw new Error('Colibri proof unavailable');
      },
      destroy() {},
      on() {},
      removeListener() {},
    }),
  };
  const stubs = {
    electron: ELECTRON,
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    'networks/network-registry': {
      getEndpoints: (chain, kind) => {
        if (chain !== 1) return [];
        if (kind === 'rpc') return world.endpoints;
        if (kind === 'prover') return colibri.prover ? [colibri.prover] : [];
        return [];
      },
      getNetwork: () => world.network,
      getEndpointSources: () => world.sources ?? [],
      getEndpointSourceList: () => world.sourceList ?? [],
    },
    'ens-prefetch': { prefetchGatewayUrl: () => ({ abort() {} }), NOOP_HANDLE: { abort() {} } },
    'myotis/myotis-manager': MYOTIS,
    'ens/colibri-worker-host': COLIBRI_HOST,
    'private/private-log-context': { runWithPrivateLogContext: (_p, fn) => fn(), redactForLog: (v) => v },
    'private/private-windows': { isPrivateWebContents: () => false },
  };

  const random = Math.random;
  Math.random = seeded(world.seed ?? 7);
  const clock = FakeTimers.install({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'], now: EPOCH });
  const { resolver, restore } = loadResolver(checkout, stubs);
  try {
    const run = async ({ fn, args }) => {
      let done = false;
      let outcome;
      resolver[fn](...args).then(
        (value) => { done = true; outcome = { value: describe(value) }; },
        (error) => { done = true; outcome = { thrown: error.message }; }
      );
      // Advance virtual time until the call settles (bounded).
      for (let i = 0; !done && i < 4000; i += 1) await clock.tickAsync(25);
      return done ? outcome : { pending: true };
    };
    const calls = [];
    const first = await run(scenario.call);
    calls.push({ call: scenario.call, at: 0, requests: requests.splice(0), ...first, elapsed: now() });
    for (const next of scenario.then ?? []) {
      await clock.tickAsync(next.after ?? 0);
      // The world can change between calls (a gateway recovering, say).
      Object.assign(world, next.world ?? {});
      const start = now();
      const out = await run(next.call);
      calls.push({ call: next.call, at: start, requests: requests.splice(0), ...out, elapsed: now() - start });
    }
    return calls;
  } finally {
    clock.uninstall();
    Math.random = random;
    restore();
  }
}

/**
 * Runs one Tezos Domains scenario: the pinned tezos-domains-resolver.js
 * with a scripted Tezos node per endpoint behind its `fetchImpl` parameter.
 * `world.endpoints` is passed as its `endpoints` parameter (the IPC path
 * reads TEZOS_RPC and the defaults instead).
 */
async function runTezosScenario(checkout, FakeTimers, scenario) {
  const { world } = scenario;
  const requests = [];
  const now = () => Date.now() - EPOCH;
  const json = (status, body) => new Response(body === undefined ? '' : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  const node = (plan, method, route) => {
    if (plan.fail) return json(500, { error: 'down' });
    const level = plan.level ?? TEZ_HEAD;
    if (route === '/chains/main/chain_id') return json(200, plan.chain ?? 'NetXdQprcVkpaWU');
    if (route === '/chains/main/blocks/head/header') return json(200, { level });
    let m = route.match(/^\/chains\/main\/blocks\/(\d+)\/hash$/);
    if (m) return json(200, `BL${plan.fork ? 'fork' : 'main'}${m[1]}`);
    m = route.match(/^\/chains\/main\/blocks\/([^/]+)\/context\/(.*)$/);
    if (!m) return json(404);
    const [, , rest] = m;
    if (method === 'POST' && rest === `contracts/${TEZ_PROXY}/script/normalized`) return json(200, tezProxyScript());
    if (method === 'POST' && rest === `contracts/${TEZ_REGISTRY}/script/normalized`) {
      return plan.scriptFail ? json(500, { error: 'script' }) : json(200, tezRegistryScript());
    }
    if (rest.startsWith('big_maps/1264/')) {
      const record = plan.record ?? world.record;
      return record === null ? json(404) : json(200, record);
    }
    if (rest.startsWith('big_maps/1265/')) return json(200, { string: plan.expiry ?? world.expiry });
    return json(404);
  };

  const fetchImpl = (url, init = {}) => {
    const { host, pathname } = new URL(url);
    const plan = world.hosts?.[host] || {};
    const method = init.method ?? 'GET';
    requests.push({ t: now(), host, method, path: pathname });
    return new Promise((resolve, reject) => {
      const abort = () => reject(Object.assign(new Error('This operation was aborted'), { name: 'AbortError' }));
      if (init.signal?.aborted) return abort();
      init.signal?.addEventListener('abort', abort, { once: true });
      if (plan.hang) return;
      setTimeout(() => resolve(node(plan, method, pathname)), plan.delay ?? 10);
    });
  };

  const stubs = {
    electron: { ipcMain: { handle() {} } },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    'private/private-log-context': { runWithPrivateLogContext: (_p, fn) => fn(), redactForLog: (v) => v },
    'private/private-windows': { isPrivateWebContents: () => false },
  };
  const clock = FakeTimers.install({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'], now: EPOCH });
  const { resolver, restore } = loadResolver(checkout, stubs, 'tezos-domains-resolver.js');
  try {
    const run = async (name) => {
      let done = false;
      let outcome;
      resolver.resolveTezosDomain(name, { fetchImpl, endpoints: world.endpoints }).then(
        (value) => { done = true; outcome = { value: describe(value) }; },
        (error) => { done = true; outcome = { thrown: error.message }; }
      );
      for (let i = 0; !done && i < 4000; i += 1) await clock.tickAsync(25);
      return done ? outcome : { pending: true };
    };
    const calls = [];
    const first = await run(scenario.call.args[0]);
    calls.push({ call: scenario.call, at: 0, requests: requests.splice(0), ...first, elapsed: now() });
    for (const next of scenario.then ?? []) {
      await clock.tickAsync(next.after ?? 0);
      Object.assign(world, next.world ?? {});
      const start = now();
      const out = await run(next.call.args[0]);
      calls.push({ call: next.call, at: start, requests: requests.splice(0), ...out, elapsed: now() - start });
    }
    return calls;
  } finally {
    clock.uninstall();
    restore();
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

function tezosScenarios() {
  const T = ['https://t1.tez.example', 'https://t2.tez.example', 'https://t3.tez.example'];
  const SITE = 'ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/';
  const base = (extra) => ({ endpoints: T, record: tezRecord({ 'web:content_url': SITE, 'td:ttl': 600 }), expiry: '2030-01-01T00:00:00Z', ...extra });
  const tez = { fn: 'resolveTezosDomain', args: ['alice.tez'] };
  return [
    { id: 'tezos-agree', world: base({}), call: tez, then: [{ after: 1000, call: tez }, { after: 60_000, call: { fn: 'resolveTezosDomain', args: ['bob.tez'] } }] },
    { id: 'tezos-one-liar', world: base({ hosts: { 't2.tez.example': { record: tezRecord({ 'web:content_url': 'https://evil.example/' }) } } }), call: tez },
    { id: 'tezos-head-outlier', world: base({ hosts: { 't3.tez.example': { level: TEZ_HEAD - 61 } } }), call: tez },
    { id: 'tezos-heads-scattered', world: base({ hosts: { 't1.tez.example': { level: TEZ_HEAD - 200 }, 't3.tez.example': { level: TEZ_HEAD + 200 } } }), call: tez },
    { id: 'tezos-anchor-split', world: base({ hosts: { 't2.tez.example': { fork: true } } }), call: tez },
    { id: 'tezos-two-down', world: base({ hosts: { 't1.tez.example': { fail: true }, 't2.tez.example': { hang: true } } }), call: tez, then: [{ after: 1000, call: tez }] },
    { id: 'tezos-all-down', world: base({ hosts: { 't1.tez.example': { fail: true }, 't2.tez.example': { fail: true }, 't3.tez.example': { fail: true } } }), call: tez, then: [{ after: 1000, call: tez }] },
    { id: 'tezos-expired', world: base({ expiry: '2020-01-01T00:00:00Z' }), call: tez },
    { id: 'tezos-expiry-unparseable', world: base({ expiry: 'not a date' }), call: tez },
    { id: 'tezos-redirect', world: base({ record: tezRecord({ 'web:redirect_url': 'https://alice.example/' }) }), call: tez },
    { id: 'tezos-no-website', world: base({ record: tezRecord({ 'td:ttl': 60 }, null) }), call: tez },
    { id: 'tezos-no-record', world: base({ record: null }), call: tez, then: [{ after: 31_000, call: tez }] },
    { id: 'tezos-registry-script-fails-once', world: base({ hosts: { 't1.tez.example': { scriptFail: true } } }), call: tez },
    { id: 'tezos-invalid-name', world: base({}), call: { fn: 'resolveTezosDomain', args: ['alice.eth'] } },
  ];
}

const ENDPOINTS = ['https://a.rpc.example', 'https://b.rpc.example', 'https://c.rpc.example', 'https://d.rpc.example'];
const QUORUM_NETWORK = { verification: { order: ['quorum'], preferVerified: false }, quorum: { k: 3, m: 2, timeoutMs: 5000, anchor: 'latest', anchorTtlMs: 30000 } };

function scenarios(ethers) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const contentAnswer = (contenthash) => ({ data: coder.encode(['bytes', 'address'], [coder.encode(['bytes'], [contenthash]), '0x' + '22'.repeat(20)]) });
  const GOOD = contentAnswer('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f');
  const EVIL = contentAnswer('0xe40101fa011b20' + 'ee'.repeat(32));
  const lookup = '0x556f1830' + coder.encode(['address', 'string[]', 'bytes', 'bytes4', 'bytes'], [UR, ['https://gw.example/{sender}/{data}.json'], '0x0102', '0xdeadbeef', '0x09']).slice(2);
  const OFFCHAIN = { rpc_error: { code: 3, message: 'execution reverted', data: lookup } };
  const base = (extra) => ({ endpoints: ENDPOINTS, network: QUORUM_NETWORK, calls: { resolve: GOOD, callback: GOOD }, ...extra });
  const content = { fn: 'resolveEnsContent', args: ['vitalik.eth'] };
  return [
    { id: 'quorum-agree', world: base({}), call: content },
    { id: 'quorum-slow-endpoint-head', world: base({ hosts: { 'b.rpc.example': { delay: 6000 } } }), call: content },
    { id: 'quorum-one-liar', world: base({ hosts: { 'c.rpc.example': { calls: { resolve: EVIL } } } }), call: content },
    { id: 'quorum-two-colluding', world: base({ hosts: { 'c.rpc.example': { calls: { resolve: EVIL } }, 'd.rpc.example': { calls: { resolve: EVIL } } } }), call: content },
    { id: 'ccip-fast-gateway', world: base({ calls: { resolve: OFFCHAIN, callback: GOOD }, gateways: { 'gw.example': { delay: 100, body: JSON.stringify({ data: '0xcafe' }) } } }), call: content },
    {
      id: 'ccip-slow-gateway-then-another-name',
      world: base({ calls: { resolve: OFFCHAIN, callback: GOOD }, gateways: { 'gw.example': { delay: 6000, body: JSON.stringify({ data: '0xcafe' }) } } }),
      call: content,
      // The gateway recovers: does the next name reuse the anchor and the
      // endpoints (no quarantine after a gateway timeout)?
      then: [{ after: 100, world: { gateways: { 'gw.example': { delay: 10, body: JSON.stringify({ data: '0xcafe' }) } } }, call: { fn: 'resolveEnsContent', args: ['nick.eth'] } }],
    },
    { id: 'single-source-two-endpoints', world: base({ endpoints: ENDPOINTS.slice(0, 2) }), call: content },
    { id: 'anchor-hash-split', world: base({ hosts: { 'c.rpc.example': { fork: true }, 'd.rpc.example': { fork: true } } }), call: content },
    { id: 'node-errors-agree', world: base({ calls: { resolve: { rpc_error: { code: -32000, message: 'header not found' } } } }), call: content },
    ...addressAndReverse(ethers, base),
    ...verifiedPaths(ethers, base, GOOD, lookup),
  ];
}

/** Myotis and Colibri, alone and in the method order. */
function verifiedPaths(ethers, base, GOOD, lookup) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const notFound = ethers.id('ResolverNotFound(bytes)').slice(0, 10) + coder.encode(['bytes'], ['0x00']).slice(2);
  const order = (methods, preferVerified = false) => ({ ...QUORUM_NETWORK, verification: { order: methods, preferVerified } });
  const content = { fn: 'resolveEnsContent', args: ['vitalik.eth'] };
  return [
    { id: 'myotis-verified', world: base({ network: order(['myotis', 'colibri', 'quorum']), myotis: { enabled: true, ready: true, calls: { resolve: GOOD } } }), call: content },
    { id: 'myotis-not-ready-falls-to-quorum', world: base({ network: order(['myotis', 'quorum']), myotis: { enabled: true, ready: false } }), call: content },
    { id: 'colibri-verified', world: base({ network: order(['colibri', 'quorum']), colibri: { prover: 'https://prover.example', calls: { resolve: GOOD } } }), call: content },
    { id: 'colibri-resolver-not-found', world: base({ network: order(['colibri', 'quorum']), colibri: { prover: 'https://prover.example', calls: { resolve: { revert: notFound } } } }), call: content },
    {
      id: 'myotis-ccip',
      world: base({ network: order(['myotis', 'quorum']), myotis: { enabled: true, ready: true, calls: { resolve: { revert: lookup }, callback: GOOD } }, gateways: { 'gw.example': { delay: 50, body: JSON.stringify({ data: '0xcafe' }) } } }),
      call: content,
    },
    {
      id: 'prefer-verified-holds-unverified',
      // Quorum can only reach one source (two endpoints): unverified, held
      // while Myotis is tried, which then answers verified.
      world: base({ endpoints: ENDPOINTS.slice(0, 2), network: order(['quorum', 'myotis'], true), myotis: { enabled: true, ready: true, calls: { resolve: GOOD } } }),
      call: content,
    },
  ];
}

/** Address and reverse lookups, ENS and WNS/GNS. */
function addressAndReverse(ethers, base) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const ACCOUNT = '0x' + 'ab'.repeat(20);
  const urAddress = (address) => ({ data: coder.encode(['bytes', 'address'], [coder.encode(['address'], [address]), '0x' + '22'.repeat(20)]) });
  const urMulticoin = (bytes) => ({ data: coder.encode(['bytes', 'address'], [coder.encode(['bytes'], [bytes]), '0x' + '22'.repeat(20)]) });
  const urReverse = (name) => ({ data: coder.encode(['string', 'address', 'address'], [name, '0x' + '22'.repeat(20), '0x' + '33'.repeat(20)]) });
  const mismatch = ethers.id('ReverseAddressMismatch(string,bytes)').slice(0, 10) + coder.encode(['string', 'bytes'], ['claimed.eth', '0x']).slice(2);
  const nftString = (text) => ({ data: coder.encode(['string'], [text]) });
  const nftAddress = (address) => ({ data: coder.encode(['address'], [address]) });
  const nftBytes = (bytes) => ({ data: coder.encode(['bytes'], [bytes]) });
  return [
    { id: 'address-agree', world: base({ calls: { resolve: urAddress(ACCOUNT) } }), call: { fn: 'resolveEnsAddress', args: ['vitalik.eth'] } },
    { id: 'address-multicoin-base', world: base({ calls: { resolve: urMulticoin(ACCOUNT) } }), call: { fn: 'resolveEnsAddress', args: ['vitalik.eth', 8453] } },
    { id: 'address-zero-is-no-address', world: base({ calls: { resolve: urAddress(ethers.ZeroAddress) } }), call: { fn: 'resolveEnsAddress', args: ['vitalik.eth'] } },
    { id: 'reverse-agree', world: base({ calls: { reverse: urReverse('vitalik.eth') } }), call: { fn: 'resolveEnsReverse', args: [ACCOUNT] } },
    { id: 'reverse-mismatch', world: base({ calls: { reverse: { rpc_error: { code: 3, message: 'execution reverted', data: mismatch } } } }), call: { fn: 'resolveEnsReverse', args: [ACCOUNT] } },
    {
      id: 'reverse-ens-empty-then-wns',
      world: base({ calls: { reverse: urReverse(''), 'wns:reverse': nftString('alice.wei'), 'wns:addr': nftAddress(ACCOUNT), 'gns:reverse': nftString('') } }),
      call: { fn: 'resolveEnsReverse', args: [ACCOUNT] },
    },
    { id: 'wns-content', world: base({ calls: { 'wns:contenthash': nftBytes('0xe3010170122073a0d88f400948a45b350423e94a7834ce96ef990fdb5da450d49f8bfed52c1f') } }), call: { fn: 'resolveEnsContent', args: ['alice.wei'] } },
    { id: 'wns-address-on-l2', world: base({}), call: { fn: 'resolveEnsAddress', args: ['alice.wei', 8453] } },
  ];
}

async function buildNamingReplay(checkout, ethers, meta) {
  const referenceRequire = Module.createRequire(path.join(checkout, 'package.json'));
  const FakeTimers = referenceRequire('@sinonjs/fake-timers');
  const out = [];
  for (const scenario of scenarios(ethers)) {
    out.push({ id: scenario.id, calls: await runScenario(checkout, ethers, FakeTimers, scenario) });
  }
  for (const scenario of tezosScenarios()) {
    out.push({ id: scenario.id, calls: await runTezosScenario(checkout, FakeTimers, scenario) });
  }
  return { meta, scenarios: out };
}

module.exports = { buildNamingReplay, runScenario };
