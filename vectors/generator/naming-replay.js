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

function loadResolver(checkout, stubs) {
  const filename = path.join(checkout, 'src/main/ens-resolver.js');
  const source = fs.readFileSync(filename, 'utf8');
  const originalLoad = Module._load;
  Module._load = function load(request, parent, isMain) {
    if (parent && parent.filename === filename && Object.hasOwn(stubs, request)) return stubs[request];
    if (request === 'electron' && parent?.filename?.startsWith(checkout)) return stubs.electron;
    return originalLoad.call(this, request, parent, isMain);
  };
  const mod = new Module(filename, null);
  mod.filename = filename;
  mod.paths = Module._nodeModulePaths(path.dirname(filename));
  mod._compile(source, filename);
  return { resolver: mod.exports, restore: () => { Module._load = originalLoad; } };
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
        const data = r.params[0].data;
        const kind = data.startsWith('0x9061b923') ? 'resolve' : data.startsWith('0x5d78a217') ? 'reverse' : 'callback';
        const answer = p.calls?.[kind] ?? p.calls?.['*'] ?? world.calls?.[kind] ?? world.calls?.['*'];
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
  const stubs = {
    electron: ELECTRON,
    './logger': { info() {}, warn() {}, error() {}, debug() {} },
    './networks/network-registry': {
      getEndpoints: (chain, kind) => (chain === 1 && kind === 'rpc' ? world.endpoints : []),
      getNetwork: () => world.network,
      getEndpointSources: () => world.sources ?? [],
      getEndpointSourceList: () => world.sourceList ?? [],
    },
    './ens-prefetch': { prefetchGatewayUrl: () => ({ abort() {} }), NOOP_HANDLE: { abort() {} } },
    './myotis/myotis-manager': { onAvailabilityTransition() {}, getStatus: () => ({ state: 'stopped' }), isReady: () => false },
    './private/private-log-context': { runWithPrivateLogContext: (_p, fn) => fn(), redactForLog: (v) => v },
    './private/private-windows': { isPrivateWebContents: () => false },
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
  ];
}

async function buildNamingReplay(checkout, ethers, meta) {
  const referenceRequire = Module.createRequire(path.join(checkout, 'package.json'));
  const FakeTimers = referenceRequire('@sinonjs/fake-timers');
  const out = [];
  for (const scenario of scenarios(ethers)) {
    out.push({ id: scenario.id, calls: await runScenario(checkout, ethers, FakeTimers, scenario) });
  }
  return { meta, scenarios: out };
}

module.exports = { buildNamingReplay, runScenario };
