'use strict';

// Design 0013's interop harness (PRF-3): the profiles reference's own
// catalog code (freedom-browser's profile-catalog.js, with proper-lockfile)
// and freedom-cored's catalog subcommands on one app root.
//
// - In a loop, at once: three reference processes and three subcommand loops,
//   each creating profiles and renaming them. The catalog stays valid JSON
//   in the reference's form, no record is lost, and every rename holds.
// - The catalog's write lock both ways: the reference holds it past 10 s
//   while the subcommands wait, and a subcommand holds it past 10 s while
//   the reference waits. Neither takes over a live lock: the holder's
//   refresh moves the lock's mtime, the waiter is refused throughout, and
//   the holder finishes uncompromised.
// - A dead holder's lock, each way: the reference takes over a killed
//   subcommand's, and a subcommand a killed reference process's, once it is
//   more than 30 s old, and not before. Real time can't hit a millisecond,
//   so each refusal is checked only where the attempt ended before the
//   lock reached 30 s (its every decision was earlier), and a takeover only
//   where the lock was past 30 s before the attempt began; the exact
//   29,999, 30,000 and 30,001 ms decisions are profiles.json's vectors,
//   replayed on both sides.
//
// Needs FREEDOM_CORED, a freedom-cored built with the `testhooks` feature
// (FREEDOM_CORED_TEST_PROFILE_HOLD), and the references:
// FREEDOM_BROWSER_APPROVALS_CHECKOUT (the profiles reference) and
// FREEDOM_BROWSER_CHECKOUT (whose install has proper-lockfile), as
// generate.js takes them. CI's vectors job runs it after building
// freedom-cored.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const Module = require('node:module');

const REFERENCE = process.env.FREEDOM_BROWSER_CHECKOUT || '/root/herdr/freedom-browser';
const PROFILES_REFERENCE = process.env.FREEDOM_BROWSER_APPROVALS_CHECKOUT
  || '/root/herdr/freedom-browser-wt/approvals-reference';
const CORED = process.env.FREEDOM_CORED;
const ACTOR = path.join(__dirname, 'interop-actor.js');
const STALE_MS = 30000;
const ACTOR_ENV = {
  ...process.env,
  FREEDOM_BROWSER_CHECKOUT: REFERENCE,
  FREEDOM_BROWSER_APPROVALS_CHECKOUT: PROFILES_REFERENCE,
};

/** The reference's profile-catalog.js, in this process. */
function loadCatalog() {
  const mainRequire = Module.createRequire(path.join(REFERENCE, 'package.json'));
  const lockfilePath = mainRequire.resolve('proper-lockfile');
  const original = Module._resolveFilename;
  Module._resolveFilename = function resolve(request, parent, ...rest) {
    if (request === 'proper-lockfile') return lockfilePath;
    return original.call(this, request, parent, ...rest);
  };
  try {
    return require(path.join(PROFILES_REFERENCE, 'src/main/profile-catalog.js'));
  } finally {
    Module._resolveFilename = original;
  }
}

assert.ok(CORED && fs.existsSync(CORED), 'FREEDOM_CORED must name a testhooks build of freedom-cored');
const catalog = loadCatalog();

function appRoot() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-interop-'));
  return { dir, app: path.join(dir, 'app') };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** A process's exit, stdout and stderr. */
function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

function cored(args, env = {}) {
  return run(CORED, args, { env: { ...process.env, ...env } });
}

/** `profile create`, its exit and its result. */
async function create(app, displayName, env) {
  const out = await cored(['profile', 'create', '--app-root', app, '--display-name', displayName], env);
  let result = null;
  try {
    result = JSON.parse(out.stdout);
  } catch {
    // An exit without a result is checked by its code.
  }
  return { ...out, result };
}

function lockDir(app) {
  return path.join(app, catalog.PROFILE_CATALOG_LOCK_DIR);
}

function mtimeMs(dir) {
  return fs.statSync(dir).mtime.getTime();
}

/** Sets the lock directory's mtime to `ms`, as a holder that died then left it. */
function setMtime(dir, ms) {
  const time = new Date(ms);
  fs.utimesSync(dir, time, time);
}

async function waitFor(file) {
  const until = Date.now() + 20000;
  while (!fs.existsSync(file)) {
    assert.ok(Date.now() < until, `${file} never appeared`);
    await sleep(10);
  }
}

function catalogText(app) {
  return fs.readFileSync(path.join(app, catalog.PROFILE_REGISTRY_FILE), 'utf8');
}

/** The catalog as the reference reads it, checked for its form. */
function checkedCatalog(app) {
  const text = catalogText(app);
  const parsed = JSON.parse(text);
  // The reference's own text: JSON.stringify(…, null, 2).
  assert.equal(text, JSON.stringify(parsed, null, 2));
  assert.equal(parsed.version, 1);
  const loaded = catalog.loadCatalog(app);
  assert.deepEqual(loaded, parsed);
  const ids = parsed.profiles.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length, 'ids are unique');
  const slots = parsed.profiles.map((p) => p.slot);
  assert.equal(new Set(slots).size, slots.length, 'slots are unique');
  return parsed;
}

/** A subcommand loop: `count` creates, each renamed, tried again while busy. */
async function subcommandWriter(app, prefix, count) {
  const changes = [];
  let busy = 0;
  for (let i = 0; i < count; i += 1) {
    const displayName = `${prefix} ${i}`;
    let out;
    for (;;) {
      out = await create(app, displayName);
      if (out.code !== 75) break;
      busy += 1;
    }
    assert.equal(out.code, 0, `${prefix} create: ${out.stdout}${out.stderr}`);
    const id = out.result.record.id;
    changes.push({ created: id });
    const renamed = `${displayName} renamed`;
    for (;;) {
      out = await cored(['profile', 'rename', '--app-root', app, '--id', id, '--display-name', renamed]);
      if (out.code !== 75) break;
      busy += 1;
    }
    assert.equal(out.code, 0, `${prefix} rename: ${out.stdout}${out.stderr}`);
    changes.push({ renamed: id, displayName: renamed });
  }
  return { changes, busy };
}

/** A reference process's loop (interop-actor.js writer). */
async function referenceWriter(app, prefix, count) {
  const out = await run(process.execPath, [ACTOR, 'writer', app, prefix, String(count)], { env: ACTOR_ENV });
  assert.equal(out.code, 0, out.stderr);
  const lines = out.stdout.trim().split('\n').map((line) => JSON.parse(line));
  const { busy } = lines.pop();
  return { changes: lines, busy };
}

test('the reference and the subcommands in a loop on one catalog', async (t) => {
  const { dir, app } = appRoot();
  try {
    const count = 15;
    const results = await Promise.all([
      referenceWriter(app, 'js a', count),
      referenceWriter(app, 'js b', count),
      referenceWriter(app, 'js c', count),
      subcommandWriter(app, 'core a', count),
      subcommandWriter(app, 'core b', count),
      subcommandWriter(app, 'core c', count),
    ]);
    const parsed = checkedCatalog(app);
    const expected = new Map();
    for (const { changes } of results) {
      for (const change of changes) {
        if (change.created) expected.set(change.created, null);
        if (change.renamed) expected.set(change.renamed, change.displayName);
      }
    }
    assert.equal(expected.size, 6 * count);
    // No record lost, every rename kept, and each profile.json agreeing.
    for (const [id, displayName] of expected) {
      const record = parsed.profiles.find((p) => p.id === id);
      assert.ok(record, `record ${id} lost`);
      assert.equal(record.displayName, displayName, id);
      const metadata = catalog.readProfileMetadata(record.dir);
      assert.equal(metadata.displayName, displayName, id);
      assert.equal(metadata.id, id);
    }
    assert.equal(parsed.profiles.length, expected.size);
    // Contention past each side's own retries, for the record.
    const busy = results.reduce((sum, r) => sum + r.busy, 0);
    t.diagnostic(`refused as busy and tried again: ${busy}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the reference holds the write lock past 10 s while the subcommands wait', async () => {
  const { dir, app } = appRoot();
  try {
    catalog.createProfile(app, { displayName: 'First' });
    const before = catalogText(app);
    const marker = path.join(dir, 'held');
    const holder = spawn(process.execPath, [ACTOR, 'hold', app, marker], {
      env: ACTOR_ENV,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let holderOut = '';
    let holderErr = '';
    holder.stdout.on('data', (chunk) => { holderOut += chunk; });
    holder.stderr.on('data', (chunk) => { holderErr += chunk; });
    const exited = new Promise((resolve) => holder.on('close', resolve));
    await waitFor(marker);
    const taken = mtimeMs(lockDir(app));
    const until = Date.now() + 12000;
    let tries = 0;
    while (Date.now() < until) {
      const out = await create(app, `Waiting ${tries}`);
      assert.equal(out.code, 75, `a subcommand took a live lock: ${out.stdout}${out.stderr}`);
      assert.deepEqual(out.result, { error: 'busy' });
      assert.equal(catalogText(app), before);
      tries += 1;
      await sleep(300);
    }
    // proper-lockfile refreshed it past its update period, and it is fresh.
    const refreshed = mtimeMs(lockDir(app));
    assert.ok(refreshed > taken, 'the reference refreshed its lock');
    assert.ok(Date.now() - refreshed < STALE_MS);
    holder.stdin.end();
    assert.equal(await exited, 0, holderErr);
    assert.deepEqual(JSON.parse(holderOut), { released: true });
    const out = await create(app, 'After');
    assert.equal(out.code, 0, out.stderr);
    checkedCatalog(app);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a subcommand holds the write lock past 10 s while the reference waits', async () => {
  const { dir, app } = appRoot();
  try {
    catalog.createProfile(app, { displayName: 'First' });
    const before = catalogText(app);
    const marker = path.join(dir, 'held');
    const release = path.join(dir, 'release');
    const holding = create(app, 'Held', { FREEDOM_CORED_TEST_PROFILE_HOLD: `${marker}=${release}` });
    await waitFor(marker);
    const taken = mtimeMs(lockDir(app));
    const until = Date.now() + 12000;
    while (Date.now() < until) {
      // The profile manager's call, with its retries.
      assert.throws(
        () => catalog.createProfile(app, { displayName: 'Waiting' }),
        (error) => error.code === 'ELOCKED',
        'the reference took a live lock',
      );
      assert.equal(catalogText(app), before);
      await sleep(300);
    }
    const refreshed = mtimeMs(lockDir(app));
    assert.ok(refreshed > taken, 'the subcommand refreshed its lock');
    assert.ok(Date.now() - refreshed < STALE_MS);
    fs.writeFileSync(release, '');
    const out = await holding;
    assert.equal(out.code, 0, `the holder finished compromised: ${out.stdout}${out.stderr}`);
    assert.equal(out.result.record.id, 'held');
    assert.equal(catalog.createProfile(app, { displayName: 'After' }).record.id, 'after');
    checkedCatalog(app);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * Tries `attempt` on a dead holder's lock until one try is conclusive both
 * ways: refused while the lock was under 30 s old at the try's end, then
 * taken once it was past 30 s before the try began. Before each try the
 * lock directory is there with no holder (made again if a try took it), its
 * mtime set `margin` ms short of 30 s, or 1 ms past it. `attempt` resolves
 * to whether it took the lock.
 */
async function deadHolder(app, margin, attempt) {
  const lock = lockDir(app);
  let refused = false;
  for (let trial = 0; trial < 6 && !refused; trial += 1) {
    if (!fs.existsSync(lock)) fs.mkdirSync(lock);
    const mtime = Date.now() - STALE_MS + margin * 2 ** trial;
    setMtime(lock, mtime);
    const took = await attempt();
    const ended = Date.now();
    if (ended - mtime <= STALE_MS) {
      // Every decision of the try came before the lock was 30 s old.
      assert.equal(took, false, `taken over at ${ended - mtime} ms or less`);
      refused = true;
    }
  }
  assert.ok(refused, 'no try ended before the lock was 30 s old');
  if (!fs.existsSync(lock)) fs.mkdirSync(lock);
  setMtime(lock, Date.now() - STALE_MS - 1);
  assert.equal(await attempt(), true, 'not taken over past 30 s');
  assert.ok(!fs.existsSync(lock), 'let go after the takeover');
}

test('the reference takes over a dead subcommand\'s lock past 30 s, not before', async () => {
  const { dir, app } = appRoot();
  try {
    catalog.createProfile(app, { displayName: 'First' });
    const marker = path.join(dir, 'held');
    const child = spawn(CORED, ['profile', 'create', '--app-root', app, '--display-name', 'Killed'], {
      env: { ...process.env, FREEDOM_CORED_TEST_PROFILE_HOLD: `${marker}=${path.join(dir, 'never')}` },
      stdio: 'ignore',
    });
    const exited = new Promise((resolve) => child.on('close', (code, signal) => resolve(signal)));
    await waitFor(marker);
    child.kill('SIGKILL');
    assert.equal(await exited, 'SIGKILL');
    assert.ok(fs.existsSync(lockDir(app)), 'the dead holder left its lock');
    const before = catalogText(app);
    // One decision a try (no retries), so the margin can be small.
    await deadHolder(app, 25, async () => {
      try {
        catalog.withCatalogWriteLock(app, () => undefined, { retries: 0 });
        return true;
      } catch (error) {
        assert.equal(error.code, 'ELOCKED');
        return false;
      }
    });
    assert.equal(catalogText(app), before);
    assert.equal(catalog.createProfile(app, { displayName: 'After' }).record.id, 'after');
    checkedCatalog(app);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a subcommand takes over a dead reference holder\'s lock past 30 s, not before', async () => {
  const { dir, app } = appRoot();
  try {
    catalog.createProfile(app, { displayName: 'First' });
    const marker = path.join(dir, 'held');
    const holder = spawn(process.execPath, [ACTOR, 'hold', app, marker], {
      env: ACTOR_ENV,
      stdio: ['pipe', 'ignore', 'ignore'],
    });
    const exited = new Promise((resolve) => holder.on('close', (code, signal) => resolve(signal)));
    await waitFor(marker);
    holder.kill('SIGKILL');
    assert.equal(await exited, 'SIGKILL');
    assert.ok(fs.existsSync(lockDir(app)), 'the dead holder left its lock');
    // A subcommand retries five times, 50 to 250 ms apart, and starts as a
    // process: its decisions span about a second.
    let n = 0;
    await deadHolder(app, 1500, async () => {
      n += 1;
      const before = catalogText(app);
      const out = await create(app, `Try ${n}`);
      if (out.code === 75) {
        assert.deepEqual(out.result, { error: 'busy' });
        assert.equal(catalogText(app), before);
        return false;
      }
      assert.equal(out.code, 0, out.stderr);
      return true;
    });
    checkedCatalog(app);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
