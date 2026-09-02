// The egress-axis provenance field.
//
// ⛔ THE LOAD-BEARING CASE IS THE THIRD ONE: a falsification control that passed WITHOUT a network
// case must not read as `ENFORCED`. That is an adjacent-artifact substitution — a filesystem case
// vouching for egress — and it is the same class of error as the measurement this field reports on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  NET_ENFORCEMENT_ENV, NET_ENFORCEMENT_MARKER, netEnforcementValue, netEnforcementFromFalsify,
} from './net-enforcement.mjs';

const HERE = import.meta.dirname;

/** A `falsify.mjs --json` report holding just the fields this module reads. */
const report = (...results) => ({ overall: 'PASS', results });
const kase = (name, removed, verdict, extra = {}) => ({
  case: name, removed, verdict, pkg: `${name}-pkg`, version: '1.0.0', insufficient: {}, ...extra,
});

test('the UNSET default is an explicit negative — the whole reason the field exists', () => {
  // ⛔ A probe measured a package as needing no network from a driver run outside the batch runner.
  // Nothing downstream could say so, because "no control covered this" and "this field is new" looked
  // identical. An absent value that reads as fine would rebuild that hole one layer up.
  const v = netEnforcementValue({});
  assert.match(v, /^NOT-VERIFIED \(/);
  assert.ok(!v.includes('ENFORCED ('), 'the negative must not be mistakable for the positive');
  assert.match(v, new RegExp(NET_ENFORCEMENT_ENV));
});

test('an empty or whitespace-only variable is unset, not a pass', () => {
  // `sudo -E`, a CI matrix defining a name with no value, and an exported empty string all land here.
  for (const value of ['', '   ', '\t']) {
    assert.match(netEnforcementValue({ [NET_ENFORCEMENT_ENV]: value }), /^NOT-VERIFIED \(/);
  }
});

test('a green control with no network case does NOT read as ENFORCED', () => {
  // linux runs `write.deps` (`@apollo/rover`) alongside its network case. On a platform carrying only
  // the filesystem one, `falsify.mjs` still exits 0 — and it has established nothing about egress.
  const v = netEnforcementFromFalsify(report(kase('write.deps', 'write.deps', 'PASS')), 'linux');
  assert.match(v, /^NOT-VERIFIED \(/);
  assert.match(v, /none of which removes 'network'/);
});

test('a passing network case reads as ENFORCED and names what was refused', () => {
  const v = netEnforcementFromFalsify(report(
    kase('write.deps', 'write.deps', 'PASS'),
    kase('network', 'network', 'PASS', { pkg: 'hugo-extended', version: '0.141.0' }),
  ), 'linux');
  assert.match(v, /^ENFORCED \(falsify network case, /);
  assert.match(v, /hugo-extended@0\.141\.0/);
});

test('a network case that did not pass is a negative that names its verdict', () => {
  const v = netEnforcementFromFalsify(report(kase('network', 'network', 'INCONCLUSIVE')), 'linux');
  assert.match(v, /^NOT-VERIFIED \(/);
  assert.match(v, /network=INCONCLUSIVE/);
  // An unreadable or shapeless report is the same answer, never an optimistic one.
  assert.match(netEnforcementFromFalsify(null, 'linux'), /^NOT-VERIFIED \(/);
});

test('the value is one line, because driver.out is parsed line-wise', () => {
  const v = netEnforcementValue({ [NET_ENFORCEMENT_ENV]: 'ENFORCED (falsify network case,\n  wrapped)' });
  assert.ok(!v.includes('\n'), `multi-line value: ${v}`);
});

test('⛔ ALL THREE DRIVERS EMIT IT, AND record.mjs SUBSTITUTES A NEGATIVE WHEN THEY DO NOT', () => {
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    assert.ok(src.includes('net-enforcement'),
      `${d} never asks net-enforcement.mjs for a value, so its records cannot say whether egress was attested`);
    // ⛔ THE LITERAL TOKEN MUST BE AT THE DRIVER'S EMISSION SITE, not composed in the module.
    // `marker-contract.test.mjs` scans driver sources for `echo "  MARKER …"`, so a module-composed
    // name reads to it as a field `record.mjs` parses and nothing emits — which is how this landed
    // half-wired the first time.
    assert.match(src, new RegExp(`(?:echo|console\\.log)[^\\n]*"\\s\\s${NET_ENFORCEMENT_MARKER}\\b|\`\\s\\s${NET_ENFORCEMENT_MARKER}\\b`),
      `${d} does not spell ${NET_ENFORCEMENT_MARKER} at its own emission site`);
  }
  // The record-side half: a driver that never emitted the marker must still produce a NEGATIVE, so
  // the field can never be absent from `provenance`.
  const rec = fs.readFileSync(path.join(HERE, 'record.mjs'), 'utf8');
  assert.match(rec, /netEnforcement: p\.netEnforcement\s*\n?\s*\?\?\s*'NOT-VERIFIED/,
    'record.mjs must default netEnforcement to an explicit negative, never to null');
});
