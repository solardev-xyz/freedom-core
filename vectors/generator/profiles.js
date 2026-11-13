'use strict';

// Design 0013's profile catalog (step PRF-3), from the profiles reference's
// own src/main/profile-catalog.js and profile-resolver.js: freedom-browser's
// integration/rust-core at PROFILES_REFERENCE_COMMIT (generate.js). Its
// profile modules are byte for byte those of integration's head when this
// file was written (2f0c571f). They require one package, proper-lockfile,
// which the profiles reference doesn't install: it is resolved from the
// main reference's install, the same version (4.1.2, the same integrity in
// both lockfiles), and named in the meta. Nothing else is stubbed.
//
// What the reference decides, and the generator records:
// - the pure functions: `sanitizeProfileId` and its refusals,
//   `displayNameFromId`, `hashPath` and `getCheckoutId`, the dev ports'
//   offset and `getManagedPorts`, `allocateSlot`, `rebaseNodeConfig`,
//   `fillMissingNodeConfig` and `normalizeIpfsMode`;
// - proper-lockfile's staleness decision (`checkSync`, with `Date.now`
//   held) at, just before and just after each stale time;
// - scenarios: the reference's own operations (`resolveProfile`,
//   `createProfile`, `renameProfile`, `importProfile`,
//   `updateProfileNodeConfig`, `getReservedManagedPorts`,
//   `listProfileSummaries`, and `validateProfileDeletion`, the delete's
//   refusals, as `delete-validate`, whose value is `valid` where it throws
//   nothing) run in order on one app root on disk under a
//   fixed clock, each step's result (or refusal) and every file's text after
//   it. The app root lives in a temp directory, whose path is written
//   `/vectors` throughout, so the core replays it at that path.
//
// A refusal is the reference's message; an unsupported catalog its message
// too; a file that isn't JSON is `unreadable` (the reference's SyntaxError,
// whose text is V8's) and a TypeError `malformed`.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const { createRequire } = Module;

const ROOT = '/vectors';
const T0 = '2026-11-01T10:00:00.000Z';
// The dev checkout hash the node configurations run under.
const NODES_HASH = '0000002a';

/** Requires the reference's profile modules, with `proper-lockfile` from the
 * main reference's install. */
function loadModules(checkout, mainCheckout) {
  const mainRequire = createRequire(path.join(mainCheckout, 'package.json'));
  const lockfilePath = mainRequire.resolve('proper-lockfile');
  const original = Module._resolveFilename;
  Module._resolveFilename = function resolve(request, parent, ...rest) {
    if (request === 'proper-lockfile') return lockfilePath;
    return original.call(this, request, parent, ...rest);
  };
  try {
    return {
      catalog: require(path.join(checkout, 'src/main/profile-catalog.js')),
      resolver: require(path.join(checkout, 'src/main/profile-resolver.js')),
      switchScheme: require(path.join(checkout, 'src/main/profile-switch-scheme.js')),
      lockfile: require(lockfilePath),
    };
  } finally {
    Module._resolveFilename = original;
  }
}

function classify(error) {
  if (error.code === 'PROFILE_SWITCH_REJECTED') {
    return { outcome: 'switch_refused', message: error.message };
  }
  if (error instanceof SyntaxError) return { error: 'unreadable' };
  if (error instanceof TypeError) return { error: 'malformed' };
  if (error.message.startsWith('Unsupported profile catalog: ')) {
    return { error: 'unsupported', message: error.message };
  }
  return { error: 'refused', message: error.message };
}

function attempt(fn) {
  try {
    return { value: fn() };
  } catch (error) {
    return classify(error);
  }
}

function buildPure({ catalog }) {
  const sanitize = [
    'Work', '  Spaced Out  ', 'UPPER_case-1', 'a/b', 'a\\b', '.', '..', '', '   ', '...',
    '-', '--x--', 'émoji 🎉 test', '\u00a0nbsp\u00a0', '\ufeffbom', 'İstanbul', 'ΣΑΣ',
    'tab\tsep', 'a.b', 'KELVIN\u212a', 'default', 'x__y', '\u2028line\u2029', '\u0085nel',
  ].map((input) => {
    const result = attempt(() => catalog.sanitizeProfileId(input));
    return 'value' in result ? { input, id: result.value } : { input, ...result };
  });
  const displayNames = [
    'default', 'work', 'work-stuff', 'a__b--c', '-x-', '---', 'ß-straße', 'é', '1abc', 'x_',
    '𝒳-y', 'automation',
  ].map((id) => ({ id, name: catalog.displayNameFromId(id) }));
  const paths = ['/', '/home/user/freedom-browser', 'C:\\Users\\user\\fb', 'ünïcode/路径'];
  const hashes = paths.map((p) => ({ path: p, hash: catalog.hashPath(p), checkoutId: catalog.getCheckoutId(p) }));
  const checkoutHashes = ['00000000', 'ffffffff', '0000002a', '12abcdef', catalog.hashPath('/')];
  const devPortOffsets = checkoutHashes.map((checkoutHash) => ({
    checkoutHash,
    offset: catalog.getDevPortOffset(checkoutHash),
  }));
  const ports = [];
  for (const slot of [0, 1, 2, 99, -1]) {
    ports.push({ slot, dev: false, checkoutHash: null, ports: catalog.getManagedPorts(slot) });
    for (const checkoutHash of [null, ...checkoutHashes]) {
      ports.push({
        slot,
        dev: true,
        checkoutHash,
        ports: catalog.getManagedPorts(slot, { dev: true, checkoutHash: checkoutHash ?? undefined }),
      });
    }
  }
  const slotCatalogs = [
    [],
    [{ slot: 0 }],
    [{ slot: 1 }, { slot: 2 }],
    [{ slot: 0 }, { slot: 2 }],
    [{ slot: '1' }, { slot: -1 }, { slot: 1.5 }, {}],
    [{ slot: 1 }, { slot: 3 }, { slot: 2 }],
  ];
  const allocateSlot = [];
  for (const profiles of slotCatalogs) {
    for (const id of ['default', 'x']) {
      allocateSlot.push({ profiles: JSON.stringify(profiles), id, slot: catalog.allocateSlot({ profiles }, id) });
    }
  }
  const nodeInputs = [
    {},
    {
      bee: { mode: 'external', externalApi: 'http://127.0.0.1:1633', verify: false, apiPort: 'x' },
      ipfs: { mode: 'external', externalGateway: 'https://gw.example', verify: true, extra: 1 },
      myotis: { mode: 'disabled' },
      radicle: { mode: 'disabled' },
      tor: { mode: 'external', externalSocks: '127.0.0.1:9050', socksPort: 9150 },
    },
    { ipfs: { mode: 'bogus' }, bee: { mode: '' }, tor: null, myotis: 'disabled' },
    { bee: 'str' },
    { bee: { apiPort: 1.5, p2pPort: 7000, 7: 'seven' }, tor: { socksPort: -3, extra: [1] } },
    { ipfs: { mode: 'disabled', externalGateway: '' }, radicle: { mode: 'managed', other: true } },
  ];
  const nodeConfigs = [];
  for (const [i, nodes] of nodeInputs.entries()) {
    for (const [slot, dev] of [[2, false], [0, true]]) {
      nodeConfigs.push({
        id: `nodes-${i}-${dev ? 'dev' : 'packaged'}`,
        nodes: JSON.stringify(nodes),
        slot,
        dev,
        checkoutHash: dev ? NODES_HASH : null,
        rebased: JSON.stringify(rebase(catalog, nodes, slot, dev)),
        filled: JSON.stringify(fill(catalog, nodes, slot, dev)),
      });
    }
  }
  return { sanitize, displayNames, hashes, devPortOffsets, ports, allocateSlot, nodeConfigs };
}

// The node functions aren't exported: reach them through the operations
// that use them, on a scratch app root. importProfile rebases a
// profile.json's nodes onto its slot's ports; ensureProfile fills a
// record's.
function rebase(catalog, nodes, slot, dev) {
  return scratch((appRoot) => {
    const dir = path.join(appRoot, 'Profiles', 'x');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'profile.json'), JSON.stringify({ slot, nodes }));
    const options = dev ? { dev, checkoutHash: NODES_HASH, now: T0 } : { now: T0 };
    return catalog.importProfile(appRoot, 'x', options).record.nodes;
  });
}

function fill(catalog, nodes, slot, dev) {
  return scratch((appRoot) => {
    const dir = path.join(appRoot, 'Profiles', 'x');
    fs.writeFileSync(path.join(appRoot, 'profile-registry.json'), JSON.stringify({
      version: 1,
      profiles: [{ id: 'x', displayName: 'X', dir, slot, nodes }],
    }));
    const options = dev ? { dev, checkoutHash: NODES_HASH, now: T0 } : { now: T0 };
    return catalog.ensureProfile(appRoot, 'x', options).record.nodes;
  });
}

function scratch(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-profiles-scratch-'));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function buildLock({ lockfile }) {
  const cases = [];
  scratch((dir) => {
    const target = path.join(dir, 'target');
    const lockDir = path.join(dir, 'target.lock');
    fs.writeFileSync(target, '');
    fs.mkdirSync(lockDir);
    const now = 1_800_000_000_000;
    const realNow = Date.now;
    try {
      for (const [what, staleMs] of [['catalog', 30000], ['profile', 30000], ['profile-dev', 5000], ['floor', 10]]) {
        const effective = Math.max(staleMs, 2000);
        for (const ageMs of [effective - 1, effective, effective + 1]) {
          const mtime = new Date(now - ageMs);
          fs.utimesSync(lockDir, mtime, mtime);
          Date.now = () => now;
          const locked = lockfile.checkSync(target, { lockfilePath: lockDir, realpath: false, stale: staleMs });
          Date.now = realNow;
          cases.push({ lock: what, staleMs, ageMs, locked });
        }
      }
    } finally {
      Date.now = realNow;
    }
  });
  return cases;
}

// --- Scenarios ---------------------------------------------------------------

/** Every file under `root` but the catalog lock's target (its createdAt is
 * the wall clock) and lock directory, as text, and every directory. */
function snapshot(root) {
  const files = {};
  const dirs = [];
  const walk = (dir, rel) => {
    for (const name of fs.readdirSync(dir).sort()) {
      if (name === 'profile-registry.write-lock-target' || name === 'profile-registry.write.lock') continue;
      const full = path.join(dir, name);
      const relName = rel ? `${rel}/${name}` : name;
      const stat = fs.lstatSync(full);
      if (stat.isDirectory()) {
        dirs.push(relName);
        walk(full, relName);
      } else {
        files[relName] = fs.readFileSync(full, 'utf8');
      }
    }
  };
  walk(root, '');
  return { files, dirs };
}

function lay(root, files, dirs) {
  for (const dir of dirs) fs.mkdirSync(path.join(root, dir), { recursive: true });
  for (const [name, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), text.replaceAll(ROOT, root));
  }
}

function runStep(modules, scenario, appRoot, step) {
  const { catalog, resolver } = modules;
  const options = scenario.dev ? { dev: true, checkoutHash: scenario.checkoutHash } : {};
  switch (step.op) {
    case 'open': {
      const args = step.args;
      const argv = ['freedom'];
      if (args.profile !== undefined) argv.push('--profile', args.profile);
      if (args.runtime) argv.push('--runtime');
      if (args.switchUrl !== undefined) argv.push(args.switchUrl);
      const env = {};
      if (args.envProfile !== undefined) env.FREEDOM_PROFILE = args.envProfile;
      if (scenario.dev) env.FREEDOM_DEV_HOME = appRoot;
      const app = {
        isPackaged: !scenario.dev,
        getPath: (name) => {
          assert.equal(name, 'userData');
          return appRoot;
        },
      };
      const running = step.running || [];
      const profile = resolver.resolveProfile(app, {
        argv,
        env,
        now: step.now,
        platform: 'linux',
        repoRoot: scenario.dev ? '/' : undefined,
        isProfileLocked: (p) => running.includes(p.id),
      });
      if (scenario.dev) assert.equal(profile.checkoutHash, scenario.checkoutHash);
      return {
        outcome: 'opened',
        switchOnly: profile.switchOnly === true,
        id: profile.id,
        displayName: profile.displayName,
        userDataDir: profile.userDataDir,
        catalogPath: profile.catalogPath,
        metadata: JSON.stringify(profile.metadata),
      };
    }
    case 'create':
      return JSON.stringify(catalog.createProfile(appRoot, { id: step.id, displayName: step.displayName }, { ...options, now: step.now }));
    case 'rename':
      return JSON.stringify(catalog.renameProfile(appRoot, step.id, step.displayName));
    case 'import':
      return JSON.stringify(catalog.importProfile(appRoot, step.id, { ...options, now: step.now }));
    case 'update-nodes':
      return JSON.stringify(catalog.updateProfileNodeConfig({
        appRoot,
        userDataDir: step.userDataDir.replaceAll(ROOT, path.dirname(appRoot)),
        id: step.id,
        metadata: JSON.parse(step.metadata),
      }, step.protocol, JSON.parse(step.updates)));
    case 'reserved-ports':
      return JSON.stringify([...catalog.getReservedManagedPorts(appRoot, { ...options, excludeProfileId: step.exclude })]);
    case 'list':
      return JSON.stringify(catalog.listProfileSummaries(appRoot, { activeProfileId: step.active }));
    case 'delete-validate':
      // Returns nothing; what it decides is whether it throws, and with what.
      catalog.validateProfileDeletion(appRoot, step.id, step.confirm);
      return 'valid';
    default:
      throw new Error(`unknown step ${step.op}`);
  }
}

const catalogText = (profiles) => JSON.stringify({ version: 1, profiles }, null, 2);
const at = (minute) => `2026-11-01T10:${String(minute).padStart(2, '0')}:00.000Z`;

function scenarios(modules) {
  const DEV = modules.catalog.hashPath('/');
  return [
    {
      id: 'packaged-first-run',
      dev: false,
      files: {},
      dirs: [],
      steps: [
        { op: 'open', args: {}, now: at(1) },
        { op: 'open', args: { profile: 'Work' }, now: at(2) },
        { op: 'open', args: {}, now: at(3) },
        { op: 'open', args: { runtime: true }, now: at(4) },
        { op: 'open', args: { envProfile: 'Personal Stuff' }, now: at(5) },
        { op: 'open', args: { profile: '', envProfile: '' }, now: at(6) },
        { op: 'create', displayName: '  Family  ', now: at(7) },
        { op: 'create', displayName: 'Family', now: at(8) },
        { op: 'create', id: 'Fun Times', displayName: 'Games', now: at(9) },
        { op: 'create', id: 'x', displayName: '   ', now: at(10) },
        { op: 'create', displayName: '', now: at(10) },
        { op: 'rename', id: 'WORK', displayName: '  Work, renamed ' },
        { op: 'rename', id: 'missing', displayName: 'Nope' },
        { op: 'rename', id: 'work', displayName: ' ' },
        { op: 'list', active: 'work' },
        { op: 'reserved-ports', exclude: 'work' },
        { op: 'reserved-ports' },
        {
          op: 'update-nodes', id: 'work', userDataDir: `${ROOT}/app/Profiles/work`, protocol: 'bee',
          metadata: '{}', updates: JSON.stringify({ mode: 'external', externalApi: 'http://127.0.0.1:1633', verify: false }),
        },
        {
          op: 'update-nodes', id: 'work', userDataDir: `${ROOT}/app/Profiles/work`, protocol: 'ipfs',
          metadata: '{}', updates: JSON.stringify({ mode: 'external', externalGateway: 'https://gw.example', backend: 'kubo' }),
        },
        {
          op: 'update-nodes', id: 'work', userDataDir: `${ROOT}/app/Profiles/work`, protocol: 'myotis',
          metadata: '{}', updates: JSON.stringify({ mode: 'disabled', extra: 1 }),
        },
        {
          op: 'update-nodes', id: 'work', userDataDir: `${ROOT}/app/Profiles/work`, protocol: 'radicle',
          metadata: '{}', updates: JSON.stringify({ mode: 'disabled' }),
        },
        {
          op: 'update-nodes', id: 'work', userDataDir: `${ROOT}/app/Profiles/work`, protocol: 'tor',
          metadata: '{}', updates: 'null',
        },
        {
          op: 'update-nodes', id: 'work', userDataDir: `${ROOT}/app/Profiles/work`, protocol: 'swarm',
          metadata: '{}', updates: '{}',
        },
        {
          op: 'update-nodes', id: 'gone', userDataDir: `${ROOT}/app/Profiles/gone`, protocol: 'bee',
          metadata: JSON.stringify({ version: 1, id: 'gone', nodes: { tor: { mode: 'managed' } } }),
          updates: JSON.stringify({ mode: 'disabled' }),
        },
        { op: 'open', args: { switchUrl: 'x-freedom-profile:work' }, running: ['work'], now: at(20) },
        { op: 'open', args: { switchUrl: 'x-freedom-profile:family' }, running: ['work'], now: at(21) },
        { op: 'open', args: { switchUrl: 'x-freedom-profile:nobody' }, running: ['nobody'], now: at(22) },
        { op: 'open', args: { switchUrl: 'x-freedom-profile:Work' }, running: ['work'], now: at(23) },
        { op: 'open', args: { profile: 'family', switchUrl: 'x-freedom-profile:work' }, running: [], now: at(24) },
        { op: 'open', args: { profile: '../x' }, now: at(25) },
        { op: 'open', args: { profile: '   ' }, now: at(26) },
        { op: 'list' },
      ],
    },
    {
      id: 'dev-first-run',
      dev: true,
      checkoutHash: DEV,
      files: {},
      dirs: [],
      steps: [
        { op: 'open', args: { profile: 'work' }, now: at(1) },
        { op: 'open', args: {}, now: at(2) },
        { op: 'create', displayName: 'Second', now: at(3) },
        { op: 'reserved-ports', exclude: 'second' },
        { op: 'list', active: 'default' },
      ],
    },
    {
      id: 'adopt-and-import',
      dev: false,
      files: {
        'app/profile-registry.json': catalogText([
          { id: 'default', displayName: 'My Profile', dir: `${ROOT}/app`, slot: 0, createdAt: at(0), lastOpenedAt: at(0), nodes: {} },
        ]),
        'app/profile.json': JSON.stringify({ version: 1, id: 'default', displayName: 'Mine', slot: 0, extra: 'kept' }),
        'app/Profiles/old/profile.json': JSON.stringify({
          version: 1, id: 'old', displayName: 'Old One', slot: 5, createdAt: '2025-01-01T00:00:00.000Z',
          nodes: { bee: { mode: 'external', externalApi: 'http://localhost:1633', verify: true }, ipfs: { mode: 'disabled' } },
        }),
        'app/Profiles/clash/profile.json': JSON.stringify({ displayName: 'Clash', slot: 0 }),
        'app/Profiles/nulled/profile.json': 'null',
      },
      dirs: ['app/Profiles/stray', 'app/Profiles/Bad_Name', 'app/Profiles/-dash'],
      steps: [
        { op: 'list', active: 'default' },
        { op: 'open', args: { profile: 'old' }, now: at(1) },
        { op: 'open', args: { profile: 'stray' }, now: at(2) },
        { op: 'open', args: { profile: 'nulled' }, now: at(3) },
        { op: 'import', id: 'stray', now: at(4) },
        { op: 'import', id: 'Clash', now: at(5) },
        { op: 'import', id: 'default', now: at(6) },
        { op: 'import', id: 'missing', now: at(6) },
        { op: 'import', id: 'Bad_Name', now: at(6) },
        { op: 'import', id: 'old', now: at(6) },
        { op: 'list', active: 'stray' },
        { op: 'reserved-ports' },
        { op: 'open', args: {}, now: at(7) },
      ],
    },
    {
      id: 'fill-missing',
      dev: false,
      files: {
        'app/profile-registry.json': catalogText([
          {
            id: 'work', displayName: 'Work', dir: `${ROOT}/app/Profiles/work`, slot: 3, createdAt: at(0), lastOpenedAt: at(0),
            nodes: { bee: { mode: 'external', apiPort: '1', p2pPort: 5000, externalApi: 'http://b' }, ipfs: { mode: 'external', externalGateway: 'https://g', verify: false } },
            note: 'kept',
          },
          { id: 'default', displayName: 'My Profile', dir: `${ROOT}/app`, slot: 0, createdAt: at(0), lastOpenedAt: at(1) },
        ]),
        'app/Profiles/work/profile.json': JSON.stringify({ version: 1, id: 'work', displayName: 'Work (file)', slot: 3, nodes: { tor: { mode: 'external', externalSocks: '127.0.0.1:9050' } }, z: 1 }, null, 2),
      },
      dirs: [],
      steps: [
        { op: 'list' },
        { op: 'open', args: { profile: 'work' }, now: at(2) },
        { op: 'open', args: { profile: 'work' }, now: at(2) },
        { op: 'open', args: {}, now: at(3) },
        { op: 'reserved-ports', exclude: 'default' },
      ],
    },
    {
      id: 'last-opened-and-fallback',
      dev: false,
      files: {
        'app/profile-registry.json': catalogText([
          { id: 'a', displayName: 'A', dir: `${ROOT}/app/Profiles/a`, slot: 1, lastOpenedAt: at(5) },
          { id: 'b', displayName: 'B', dir: `${ROOT}/app/Profiles/b`, slot: 2, lastOpenedAt: at(9) },
          { id: 'c', displayName: 'C', dir: `${ROOT}/app/Profiles/c`, slot: 3, lastOpenedAt: at(9) },
          { id: '', displayName: 'Empty', dir: `${ROOT}/app/Profiles/e`, slot: 4, lastOpenedAt: at(59) },
          { id: 'd', displayName: 'D', dir: `${ROOT}/app/Profiles/d`, slot: 5 },
        ]),
      },
      dirs: [],
      steps: [{ op: 'open', args: {}, now: at(10) }],
    },
    {
      id: 'fallback-first-registered',
      dev: false,
      files: {
        'app/profile-registry.json': catalogText([
          { id: 'zeta', displayName: 'Zeta', dir: `${ROOT}/app/Profiles/zeta`, slot: 7 },
          { id: 'alpha', displayName: 'Alpha', dir: `${ROOT}/app/Profiles/alpha`, slot: 2 },
        ]),
      },
      dirs: [],
      steps: [{ op: 'open', args: {}, now: at(1) }, { op: 'open', args: { runtime: true }, now: at(2) }],
    },
    {
      id: 'fallback-default',
      dev: true,
      checkoutHash: DEV,
      files: {
        'app/profile-registry.json': catalogText([
          { id: 'zeta', displayName: 'Zeta', dir: `${ROOT}/app/Profiles/zeta`, slot: 7 },
          { id: 'default', displayName: 'My Profile', dir: `${ROOT}/app/Profiles/default`, slot: 0 },
        ]),
      },
      dirs: [],
      steps: [{ op: 'open', args: {}, now: at(1) }],
    },
    {
      id: 'slots',
      dev: false,
      files: {
        'app/profile-registry.json': catalogText([
          { id: 'default', dir: `${ROOT}/app`, slot: 0 },
          { id: 'one', dir: `${ROOT}/app/Profiles/one`, slot: 1 },
          { id: 'three', dir: `${ROOT}/app/Profiles/three`, slot: 3 },
          { id: 'neg', dir: `${ROOT}/app/Profiles/neg`, slot: -1 },
          { id: 'frac', dir: `${ROOT}/app/Profiles/frac`, slot: 2.5 },
          { id: 'text', dir: `${ROOT}/app/Profiles/text`, slot: '4' },
        ]),
      },
      dirs: [],
      steps: [
        { op: 'create', displayName: 'Two', now: at(1) },
        { op: 'create', displayName: 'Four', now: at(2) },
        { op: 'list' },
        { op: 'reserved-ports' },
      ],
    },
    { id: 'unsupported-version', dev: false, files: { 'app/profile-registry.json': '{"version":2,"profiles":[]}' }, dirs: [], steps: [{ op: 'open', args: {}, now: at(1) }, { op: 'list' }, { op: 'create', displayName: 'X', now: at(1) }] },
    { id: 'unsupported-profiles', dev: false, files: { 'app/profile-registry.json': '{"version":1,"profiles":{}}' }, dirs: [], steps: [{ op: 'open', args: { profile: 'x' }, now: at(1) }, { op: 'reserved-ports' }] },
    { id: 'unsupported-null', dev: false, files: { 'app/profile-registry.json': 'null' }, dirs: [], steps: [{ op: 'open', args: {}, now: at(1) }] },
    { id: 'unreadable-catalog', dev: false, files: { 'app/profile-registry.json': '{"version":1,' }, dirs: [], steps: [{ op: 'open', args: {}, now: at(1) }, { op: 'rename', id: 'a', displayName: 'b' }] },
    {
      id: 'unreadable-metadata',
      dev: false,
      files: {
        'app/profile-registry.json': catalogText([{ id: 'default', displayName: 'My Profile', dir: `${ROOT}/app`, slot: 0 }]),
        'app/profile.json': '{oops',
      },
      dirs: [],
      steps: [{ op: 'open', args: {}, now: at(1) }, { op: 'list' }, { op: 'rename', id: 'default', displayName: 'Mine' }],
    },
    {
      id: 'delete-validate',
      dev: false,
      files: {
        'app/profile-registry.json': catalogText([
          { id: 'default', displayName: 'My Profile', dir: `${ROOT}/app`, slot: 0 },
          { id: 'work', displayName: 'Work', dir: `${ROOT}/app/Profiles/work`, slot: 1 },
          { id: 'nameless', dir: `${ROOT}/app/Profiles/nameless`, slot: 2 },
          { id: 'blank', displayName: '', dir: `${ROOT}/app/Profiles/blank`, slot: 3 },
          { id: 'numbered', displayName: 5, dir: `${ROOT}/app/Profiles/numbered`, slot: 4 },
          { id: 'outside', displayName: 'Outside', dir: `${ROOT}/elsewhere/outside`, slot: 5 },
          { id: 'root', displayName: 'Root', dir: `${ROOT}/app`, slot: 6 },
          { id: 'sibling', displayName: 'Sibling', dir: `${ROOT}/app-other`, slot: 7 },
          { id: 'dotdot', displayName: 'Dot Dot', dir: `${ROOT}/app/Profiles/../../dotdot`, slot: 8 },
          { id: 'trailing', displayName: 'Trailing', dir: `${ROOT}/app/Profiles/trailing/`, slot: 9 },
          { id: 'nodir', displayName: 'No Dir', dir: 42, slot: 10 },
          { id: 'profiles', displayName: 'Profiles', dir: `${ROOT}/app/Profiles`, slot: 11 },
        ]),
      },
      dirs: [],
      steps: [
        { op: 'delete-validate', id: 'work', confirm: 'Work' },
        { op: 'delete-validate', id: '  WORK ', confirm: 'Work' },
        { op: 'delete-validate', id: 'work', confirm: 'work' },
        { op: 'delete-validate', id: 'work', confirm: 'Work ' },
        { op: 'delete-validate', id: 'work', confirm: '' },
        { op: 'delete-validate', id: 'missing', confirm: 'Missing' },
        { op: 'delete-validate', id: '../work', confirm: 'Work' },
        { op: 'delete-validate', id: '   ', confirm: '' },
        { op: 'delete-validate', id: 'default', confirm: 'My Profile' },
        { op: 'delete-validate', id: 'nameless', confirm: 'Nameless' },
        { op: 'delete-validate', id: 'blank', confirm: '' },
        { op: 'delete-validate', id: 'blank', confirm: 'Blank' },
        { op: 'delete-validate', id: 'numbered', confirm: '5' },
        { op: 'delete-validate', id: 'outside', confirm: 'Outside' },
        { op: 'delete-validate', id: 'outside', confirm: 'wrong' },
        { op: 'delete-validate', id: 'root', confirm: 'Root' },
        { op: 'delete-validate', id: 'sibling', confirm: 'Sibling' },
        { op: 'delete-validate', id: 'dotdot', confirm: 'Dot Dot' },
        { op: 'delete-validate', id: 'trailing', confirm: 'Trailing' },
        { op: 'delete-validate', id: 'nodir', confirm: 'No Dir' },
        { op: 'delete-validate', id: 'profiles', confirm: 'Profiles' },
      ],
    },
    {
      id: 'delete-validate-last',
      dev: false,
      files: {
        'app/profile-registry.json': catalogText([
          { id: 'work', displayName: 'Work', dir: `${ROOT}/app/Profiles/work`, slot: 1 },
        ]),
      },
      dirs: [],
      steps: [
        { op: 'delete-validate', id: 'work', confirm: 'Work' },
        { op: 'delete-validate', id: 'work', confirm: 'nope' },
        { op: 'delete-validate', id: 'missing', confirm: 'Missing' },
      ],
    },
    {
      id: 'delete-validate-no-catalog',
      dev: false,
      files: {},
      dirs: [],
      steps: [{ op: 'delete-validate', id: 'default', confirm: 'My Profile' }],
    },
    {
      id: 'delete-validate-null-records',
      dev: false,
      files: {
        'app/profile-registry.json': JSON.stringify({
          version: 1,
          profiles: [
            5,
            { id: 'a', displayName: 'A', dir: `${ROOT}/app/Profiles/a` },
            null,
            { id: 'b', displayName: 'B', dir: `${ROOT}/app/Profiles/b` },
          ],
        }),
      },
      dirs: [],
      steps: [
        { op: 'delete-validate', id: 'a', confirm: 'A' },
        { op: 'delete-validate', id: 'b', confirm: 'B' },
        { op: 'delete-validate', id: 'c', confirm: 'C' },
      ],
    },
    {
      id: 'delete-validate-unsupported',
      dev: false,
      files: { 'app/profile-registry.json': '{"version":2,"profiles":[]}' },
      dirs: [],
      steps: [{ op: 'delete-validate', id: 'work', confirm: 'Work' }],
    },
    {
      id: 'null-record',
      dev: false,
      files: { 'app/profile-registry.json': '{"version":1,"profiles":[null]}' },
      dirs: [],
      steps: [{ op: 'open', args: {}, now: at(1) }, { op: 'list' }],
    },
  ];
}

function buildScenarios(modules) {
  const out = [];
  for (const scenario of scenarios(modules)) {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-profiles-'));
    try {
      const appRoot = path.join(base, 'app');
      lay(base, scenario.files, scenario.dirs);
      const subst = (text) => text.replaceAll(base, ROOT);
      const steps = scenario.steps.map((step) => {
        // What main passes the core for a switch: the id the URL names, or
        // empty for none.
        if (step.op === 'open' && step.args.switchUrl !== undefined) {
          step.args.switch = modules.switchScheme.parseProfileSwitchUrl(step.args.switchUrl) ?? '';
        }
        let result;
        try {
          const value = runStep(modules, scenario, appRoot, step);
          result = typeof value === 'string' ? { value: subst(value) } : { value: JSON.parse(subst(JSON.stringify(value))) };
        } catch (error) {
          const classified = classify(error);
          if (classified.message) classified.message = subst(classified.message);
          result = classified;
        }
        const after = snapshot(base);
        for (const name of Object.keys(after.files)) after.files[name] = subst(after.files[name]);
        return { ...step, result, files: after.files, dirs: after.dirs };
      });
      out.push({ ...scenario, steps });
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  }
  return out;
}

function buildProfiles(checkout, mainCheckout, meta) {
  const modules = loadModules(checkout, mainCheckout);
  return {
    meta,
    description: 'Design 0013 (PRF-3): the profile catalog, from the reference\'s profile-catalog.js and profile-resolver.js. Scenario paths are under /vectors, the temp directory they ran in; texts are each file\'s bytes after the step.',
    root: ROOT,
    ...buildPure(modules),
    lockStaleness: buildLock(modules),
    scenarios: buildScenarios(modules),
  };
}

module.exports = { buildProfiles };
