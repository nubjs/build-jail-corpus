// Cases for how a record decides its own `provenance.venue`. `node --test harness/v2/venue-provenance.test.mjs`.
//
// ⛔ WHY THIS FILE EXISTS. `venue` defaulted to `local`, so a run on the corpus VM with
// `NUB_CORPUS_VENUE` unset wrote `venue: "local"` — a WRONG value that reads exactly like a right
// one. Venue is provenance, so a wrong value poisons the ability to re-examine the record later
// rather than merely the current answer, and a venue comparison between two records that both claim
// `local` cannot attribute a difference at all.
//
// Every case here drives the REAL CLI and reads the REAL record it wrote, because the defect was in
// the seam between the environment and the written file — a unit test of a resolver function would
// have stepped over exactly that seam.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const HERE = import.meta.dirname;
const TOOL = join(HERE, 'record.mjs');

// A minimal driver log that parses to a complete record, so nothing else can be the reason a field
// is missing.
const LOG = [
  '### thing@1.0.0   (/tmp/v2-xxxx)',
  '  VENUE-INTERPRETER /home/nub/node',
  '  VENUE-STORE-LAYOUT isolated',
  '  => MINIMUM {"network":true}   (observed, then verified)',
].join('\n');

// ⛔ The env is REPLACED, not merged. Inheriting the runner's environment would let an ambient
// NUB_CORPUS_VENUE or GITHUB_ACTIONS decide the answer, and the test would pass or fail according
// to where it ran — which is the very confusion this field exists to remove. PATH is kept so node
// can spawn at all.
const write = (env) => {
  const dir = mkdtempSync(join(tmpdir(), 'venue-'));
  const log = join(dir, 'driver.txt');
  writeFileSync(log, LOG);
  const r = spawnSync(process.execPath, [TOOL,
    '--log', log, '--pkg', 'thing', '--version', '1.0.0',
    '--out', join(dir, 'runs'), '--rc', '0', '--platform', 'linux-x64', '--duration-ms', '1000'],
  { encoding: 'utf8', env: { PATH: process.env.PATH, HOME: dir, ...env } });
  const rec = JSON.parse(readFileSync(
    join(dir, 'runs', 'linux-x64', 'thing', '1.0.0', 'results.json'), 'utf8'));
  return { venue: rec.provenance.venue, stderr: (r.stderr ?? '') + (r.stdout ?? ''), rc: r.status };
};

test('an UNDECLARED venue is recorded as "unknown", never a plausible guess', () => {
  const { venue } = write({});
  assert.equal(venue, 'unknown',
    'an unset NUB_CORPUS_VENUE must surface as unknown IN THE DATA — `local` is a wrong value '
    + 'that is indistinguishable from a correct one');
});

test('an undeclared venue WARNS, naming the variable and the value written', () => {
  const { stderr } = write({});
  assert.match(stderr, /NUB_CORPUS_VENUE/,
    'the warning must name the variable, or an operator cannot act on it');
  assert.match(stderr, /unknown/,
    'the warning must name the value actually being recorded');
});

test('a DECLARED venue is taken verbatim, and warns about nothing', () => {
  for (const v of ['vm', 'local', 'ci']) {
    const { venue, stderr } = write({ NUB_CORPUS_VENUE: v });
    assert.equal(venue, v, `a declared venue must be recorded as declared, got ${venue}`);
    assert.doesNotMatch(stderr, /NUB_CORPUS_VENUE is not set/,
      `declaring ${v} must not warn — a warning that fires when nothing is wrong trains its reader `
      + 'to skip it');
  }
});

test('GITHUB_ACTIONS is `ci`, and that is the ONE non-inference', () => {
  // Not a guess: the runner sets this itself, so it is an assertion by the venue about the venue.
  const { venue } = write({ GITHUB_ACTIONS: 'true' });
  assert.equal(venue, 'ci');
});

test('GITHUB_ACTIONS outranks a declared venue', () => {
  const { venue } = write({ GITHUB_ACTIONS: 'true', NUB_CORPUS_VENUE: 'vm' });
  assert.equal(venue, 'ci', 'a record written on a real runner must say ci whatever the operator set');
});

// ── the negative controls: prove venue is NEVER inferred ──────────────────────────────────────

test('⛔ CI alone does NOT make the venue `ci`', () => {
  // `CI=1` is set on plenty of non-CI machines and is an ENVIRONMENT axis the harness measures
  // separately (`ciEnvSet`). Reading it as the venue would collapse two independent axes into one —
  // the exact mistake VENUE-PORTABILITY.md's R3 calls out.
  const { venue } = write({ CI: '1' });
  assert.equal(venue, 'unknown', 'CI is not evidence of the venue; it has its own field');
});

test('⛔ a VM-shaped interpreter path does NOT make the venue `vm`', () => {
  // The log says the interpreter is `/home/nub/node`, which is the corpus VM's layout. Inferring
  // `vm` from it would be a guess wearing a fact's clothing — and it would be wrong on any laptop
  // whose user happens to be `nub`.
  const { venue } = write({});
  assert.equal(venue, 'unknown',
    'the venue must come from the operator, never from a path that merely looks like a known box');
});

test('the record is still written, and rc stays 0, when the venue is unknown', () => {
  // ⛔ The warning must not become a refusal. A measurement that ran is worth keeping with an
  // honest `unknown` far more than it is worth discarding over a label.
  const { rc, venue } = write({});
  assert.equal(rc, 0, 'an undeclared venue is a labelling gap, not a measurement failure');
  assert.equal(venue, 'unknown');
});
