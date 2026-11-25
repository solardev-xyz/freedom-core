'use strict';

// icu-root-ascii.json: ICU's root collation (`Intl.Collator('und')`, which
// is what the reference's `localeCompare` gives for an English locale) over
// printable ASCII, as node's ICU orders it. src/js/collate.rs checks its
// port against each list (design 0015, SWM-4's D8).
//
//   node icu-root-ascii.js > icu-root-ascii.json
//
// - `singles`: the 95 printable characters, sorted.
// - `pairs`: every string of two printable characters (9,025), with the
//   empty string and the singles, sorted.
// - `triples`: every string of three characters from a small alphabet of
//   letters in both cases, digits and punctuation, sorted.
// - `strings`: seeded random strings and permission-key-like ones, sorted.
// - `compared`: seeded random pairs from `strings`, each with the sign of
//   the comparison.
// - `outside`: pairs with a character outside printable ASCII, each with
//   ICU's sign: the core compares those by code unit instead (deviation
//   `collation`), and the test pins where the two differ.
//
// It fails if `localeCompare` and `Intl.Collator('und')` ever disagree on
// the lists, or if two different printable strings compare equal.

const collator = new Intl.Collator('und');
const compare = (a, b) => Math.sign(collator.compare(a, b));

const printable = [];
for (let c = 0x20; c < 0x7f; c += 1) printable.push(String.fromCharCode(c));

// A small PRNG (mulberry32), so the file is the same at every run.
let seed = 0x5eed_0015;
function random() {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = (items) => items[Math.floor(random() * items.length)];

function sorted(strings) {
  const out = [...new Set(strings)].sort(collator.compare);
  for (let i = 1; i < out.length; i += 1) {
    if (compare(out[i - 1], out[i]) !== -1) throw new Error(`a tie: ${JSON.stringify([out[i - 1], out[i]])}`);
  }
  for (let i = 0; i < out.length; i += 1) {
    const j = Math.floor(random() * out.length);
    if (Math.sign(out[i].localeCompare(out[j])) !== compare(out[i], out[j])) {
      throw new Error(`localeCompare differs: ${JSON.stringify([out[i], out[j]])}`);
    }
  }
  return out;
}

const singles = sorted(printable);

const pairs = [''];
pairs.push(...printable);
for (const a of printable) for (const b of printable) pairs.push(a + b);

const small = ['a', 'A', 'b', 'B', 'z', 'Z', '0', '9', '-', '_', '.', ' ', '/', ':', '~', '$'];
const triples = [];
for (const a of small) for (const b of small) for (const c of small) triples.push(a + b + c);

const strings = [];
const skewed = [...'aAbBcCxXyYzZ019-_./: ~$@'];
for (let n = 0; n < 1500; n += 1) {
  const length = Math.floor(random() * 12);
  let s = '';
  for (let i = 0; i < length; i += 1) s += random() < 0.7 ? pick(skewed) : pick(printable);
  strings.push(s);
}
for (const host of ['app', 'App', 'APP', 'app-1', 'app_1', 'app.1', 'b', 'B', 'zeta', 'Zeta']) {
  for (const scheme of ['https://', 'http://', 'bzz://', 'ens:', 'ipfs://', '']) {
    strings.push(`${scheme}${host}.example`);
    strings.push(`${scheme}${host}.eth`);
  }
}
const stringsSorted = sorted(strings);

const compared = [];
for (let n = 0; n < 1500; n += 1) {
  const a = pick(stringsSorted);
  const b = pick(stringsSorted);
  compared.push([a, b, compare(a, b)]);
}

const outside = [
  ['é', 'f'],
  ['e', 'é'],
  ['É', 'e'],
  ['a\tb', 'a'],
  ['a\u0000', 'a'],
  ['ab\u007f', 'ab'],
  ['B', 'aé'],
  ['straße', 'strasse'],
  ['日本', 'z'],
  ['\u{1F600}', 'a'],
].map(([a, b]) => [a, b, compare(a, b)]);

process.stdout.write(`${JSON.stringify({
  meta: {
    node: process.version,
    icu: process.versions.icu,
    unicode: process.versions.unicode,
    cldr: process.versions.cldr,
    locale: collator.resolvedOptions().locale,
  },
  singles,
  pairs: sorted(pairs),
  triples: sorted(triples),
  strings: stringsSorted,
  compared,
  outside,
}, null, 0)}\n`);
