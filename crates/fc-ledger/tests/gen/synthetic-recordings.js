'use strict';

// The synthetic Ledger recordings device_recordings.rs replays until the
// real ones exist (design 0016, LDG-3's C1): freedom-browser's own recorder,
// scripts/ledger-record.js, run whole against the fake node-hid
// (test/helpers/fake-node-hid.js) and a scripted Ethereum app holding the
// public test phrase, with simulated hands doing what each step asks. The
// scripted app and the hands are scripts/ledger-record.test.js's (at
// freedom-browser 2210097b), copied here because that test doesn't export
// them; everything else is the browser checkout's, loaded with createRequire
// anchored in it, so the APDUs are main's own stream as the recorder plays it.
//
//   node crates/fc-ledger/tests/gen/synthetic-recordings.js --freedom-browser <checkout>
//
// <checkout> is a freedom-browser checkout of integration/rust-core with its
// packages installed. It writes ../data/ledger-devices-synthetic/: a Nano S
// Plus (every field step of the device session) and a Nano S (the hash-only
// steps), each file as the recorder wrote it, with `meta.synthetic` added
// and the firmware "synthetic", so that nobody takes them for device
// evidence. Timings and `recordedAt` differ on every run.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRequire } = require('node:module');

const OUTPUT = path.join(__dirname, '..', 'data', 'ledger-devices-synthetic');
const USAGE = 'Usage: node crates/fc-ledger/tests/gen/synthetic-recordings.js --freedom-browser <checkout>';
const FIRMWARE = 'synthetic';
// As scripts/ledger-record.test.js: an APDU answered after HELD_MS is held
// (R2), and the simulated user spends SCROLL_MS on each of the Mail's values.
const HELD_MS = 80;
const SCROLL_MS = 120;
const SYNTHETIC =
  "Not device evidence: freedom-browser's scripts/ledger-record.js run against the fake node-hid " +
  '(test/helpers/fake-node-hid.js) and a scripted Ethereum app holding the public test phrase, with simulated ' +
  'hands, by freedom-core crates/fc-ledger/tests/gen/synthetic-recordings.js. Real recordings go in ' +
  'vectors/ledger-devices/.';

function parseArgs(argv) {
  if (argv.length !== 2 || argv[0] !== '--freedom-browser') throw new Error(USAGE);
  return { browser: path.resolve(argv[1]) };
}

/** The scripted Ethereum app behind the fake node-hid (ledger-record.test.js's scriptedLedger). */
function scriptedLedger(fake, ethers, cases, bindTypedData, appAnswer, { fields = true } = {}) {
  const { HDNodeWallet, SigningKey, computeAddress, concat, decodeRlp, hashMessage, keccak256 } = ethers;
  const hex = (bytes) => Buffer.from(bytes).toString('hex');
  const digests = new Map();
  for (const source of Object.values(cases.cases)) {
    if (source.operation !== 'sign.typed_data') continue;
    const { typed_data: typedData, expected_hash: expectedHash } = source.request;
    const body = source.apdus
      ? source.apdus.slice(2, -1)
      : bindTypedData({ typedData, expectedHash }).apdus.map(hex);
    digests.set(body.join(''), expectedHash);
  }
  const state = { step: null, hands: 'none', blind: false };
  const root = HDNodeWallet.fromPhrase(
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    '',
    'm'
  );
  const reset = () => Object.assign(state, { tx: null, msg: null, typed: [], prompt: null, queued: [] });
  reset();

  const decodePath = (data) => {
    const elements = [];
    for (let k = 0; k < data[0]; k++) elements.push(data.readUInt32BE(1 + 4 * k));
    return { elements, length: 1 + 4 * data[0] };
  };
  const pathOf = (elements) =>
    'm/' + elements.map((e) => (e >= 0x80000000 ? `${e - 0x80000000}'` : String(e))).join('/');
  const rlpLength = (bytes) => {
    if (bytes.length === 0) return null;
    const b = bytes[0];
    if (b <= 0xf7) return 1 + (b - 0xc0);
    const width = b - 0xf7;
    if (bytes.length < 1 + width) return null;
    return 1 + width + Number(BigInt(`0x${hex(bytes.subarray(1, 1 + width))}`));
  };
  const keyAt = (elements) => root.derivePath(pathOf(elements)).signingKey;
  const reply = (channel, answer, ms = 2) =>
    setTimeout(() => fake.ledger.answerOn(channel, Buffer.from(answer, 'hex')), ms);

  function signed(elements, digest, v) {
    const sig = keyAt(elements).sign(digest);
    return Buffer.concat([
      Buffer.from([v(sig.yParity)]),
      Buffer.from(sig.r.slice(2), 'hex'),
      Buffer.from(sig.s.slice(2), 'hex'),
      Buffer.from('9000', 'hex'),
    ]).toString('hex');
  }

  function address(data) {
    const key = keyAt(decodePath(data).elements);
    const pub = Buffer.from(SigningKey.computePublicKey(key.publicKey, false).slice(2), 'hex');
    const text = Buffer.from(computeAddress(key.publicKey).slice(2), 'latin1');
    return Buffer.concat([Buffer.from([65]), pub, Buffer.from([40]), text, Buffer.from('9000', 'hex')]).toString(
      'hex'
    );
  }

  function prompt(channel, answer) {
    if (state.hands === 'reject') return reply(channel, '6985', 5);
    if (state.hands === 'unplug') return setTimeout(() => fake.unplug(), 10);
    if (state.hands === 'leave') {
      state.prompt = { channel };
      return null;
    }
    return reply(channel, answer(), 5);
  }

  function transaction(p1, data, channel) {
    if (p1 === 0x00) {
      const p = decodePath(data);
      state.tx = { elements: p.elements, bytes: data.subarray(p.length) };
    } else {
      state.tx.bytes = Buffer.concat([state.tx.bytes, data]);
    }
    const t = state.tx.bytes;
    const typed = t[0] < 0x80;
    const body = typed ? t.subarray(1) : t;
    const total = rlpLength(body);
    if (total === null || body.length < total) return reply(channel, '9000');
    const items = decodeRlp(body);
    if ((typed ? items[7] : items[5]) !== '0x' && !state.blind) return reply(channel, '6a80');
    const { elements } = state.tx;
    state.tx = null;
    const chainPrime = Number(BigInt(`0x${items[6].slice(2, 10) || '0'}`));
    return prompt(channel, () =>
      signed(elements, keccak256(t), (parity) => (typed ? parity : (chainPrime * 2 + 35 + parity) & 0xff))
    );
  }

  function message(p1, data, channel) {
    if (p1 === 0x00) {
      const p = decodePath(data);
      state.msg = { elements: p.elements, length: data.readUInt32BE(p.length), bytes: data.subarray(p.length + 4) };
    } else {
      state.msg.bytes = Buffer.concat([state.msg.bytes, data]);
    }
    if (state.msg.bytes.length < state.msg.length) return reply(channel, '9000');
    const { elements, bytes } = state.msg;
    state.msg = null;
    return prompt(channel, () => signed(elements, hashMessage(bytes), (parity) => 27 + parity));
  }

  function handle(apdu, channel) {
    const [cla, ins, p1, p2] = apdu;
    const data = apdu.subarray(5);
    if (cla === 0xb0 && ins === 0x01) return reply(channel, appAnswer);
    if (ins === 0x02) {
      state.typed = [];
      if (p1 === 0x01) return prompt(channel, () => address(data));
      return reply(channel, address(data));
    }
    if (ins === 0x04) return transaction(p1, data, channel);
    if (ins === 0x08) return message(p1, data, channel);
    if (ins === 0x1a || ins === 0x1c) {
      if (!fields) return reply(channel, '6d00');
      state.typed.push(hex(apdu));
      const value = ins === 0x1c && p1 === 0x00 && p2 === 0xff;
      return reply(channel, '9000', value && state.step === 'typed-mail' ? SCROLL_MS : 2);
    }
    if (ins === 0x0c) {
      const p = decodePath(data);
      const digest =
        p2 === 0x01 ? digests.get(state.typed.join('')) : keccak256(concat(['0x1901', data.subarray(p.length)]));
      if (!digest) return reply(channel, '6a80');
      return prompt(channel, () => signed(p.elements, digest, (parity) => 27 + parity));
    }
    return reply(channel, '6d00');
  }

  fake.ledger.respond = (apdu, { channel }) => {
    if (state.prompt && state.prompt.channel !== channel) {
      // The device still shows an older request.
      state.queued.push({ apdu, channel });
      if (state.hands === 'reject-old' && state.queued.length === 1) {
        setTimeout(() => {
          const old = state.prompt;
          state.prompt = null;
          fake.ledger.answerOn(old.channel, Buffer.from('6985', 'hex'));
          for (const queued of state.queued.splice(0)) handle(queued.apdu, queued.channel);
        }, 20);
      }
    } else {
      handle(apdu, channel);
    }
    return { hold: true };
  };

  return { state, reset };
}

/** Hands that do what each step asks, and the answers a person types (ledger-record.test.js's simulatedHands). */
function simulatedHands(ledger, fake) {
  const said = [];
  return {
    said,
    say: (text) => said.push(text),
    ask: async (key) => {
      if (key === 'firmware') return FIRMWARE;
      if (key === 'blind-on') ledger.state.blind = true;
      if (key === 'replugged') {
        ledger.reset();
        fake.plug();
      }
      if (key === 'hashes-match') return 'y';
      if (key === 'retry' || key === 'connect') return 'n';
      return '';
    },
    step: ({ id, hands }) => Object.assign(ledger.state, { step: id, hands }),
  };
}

async function record(browser, model, fields, dir) {
  const req = createRequire(path.join(browser, 'package.json'));
  const recorder = req('./scripts/ledger-record.js');
  const cases = req('./scripts/ledger-record-cases.json');
  const { createFakeNodeHid, inProcessHosts, APP_ANSWER } = req('./test/helpers/fake-node-hid.js');
  const { HidHost } = req('./src/main/wallet/ledger/hid-device.js');
  const { bindTypedData } = req('./src/main/wallet/ledger/apdu-binding.js');
  const ethers = req('ethers');

  const fake = createFakeNodeHid();
  const ledger = scriptedLedger(fake, ethers, cases, bindTypedData, APP_ANSWER, { fields });
  const hands = simulatedHands(ledger, fake);
  const host = new HidHost({ launch: inProcessHosts(fake), idleMs: null });
  const out = path.join(dir, `ledger-devices-${model}.json`);
  let code;
  try {
    code = await recorder.run(['--model', model, '--out', out], {
      io: hands,
      host,
      heldMs: HELD_MS,
      cancelAfterMs: 30,
    });
  } finally {
    host.kill();
  }
  if (code !== 0) throw new Error(`the recorder exited ${code} for ${model}:\n${hands.said.join('\n')}`);
  if (fake.violations.length) throw new Error(`the fake node-hid saw violations: ${JSON.stringify(fake.violations)}`);
  const recording = JSON.parse(fs.readFileSync(out, 'utf8'));
  if (recording.meta.complete !== true) throw new Error(`${model}: the recording isn't complete`);
  // `synthetic` first, so it is the first thing anyone reading the file sees.
  recording.meta = { synthetic: SYNTHETIC, ...recording.meta };
  return recording;
}

async function main(argv) {
  const { browser } = parseArgs(argv);
  process.env.NODE_ENV = 'test';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-devices-synthetic-'));
  try {
    const recordings = [
      ['nanoSP', await record(browser, 'nanoSP', true, dir)],
      ['nanoS', await record(browser, 'nanoS', false, dir)],
    ];
    fs.mkdirSync(OUTPUT, { recursive: true });
    for (const name of fs.readdirSync(OUTPUT)) fs.rmSync(path.join(OUTPUT, name));
    for (const [model, recording] of recordings) {
      // The recorder's own layout (JSON.stringify(…, null, 1)).
      fs.writeFileSync(path.join(OUTPUT, `ledger-devices-${model}.json`), `${JSON.stringify(recording, null, 1)}\n`);
      console.log(`${model}: ${recording.cases.length} cases`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

main(process.argv.slice(2)).then(
  () => process.exit(0),
  (err) => {
    console.error(err.message ?? err);
    process.exit(1);
  }
);
