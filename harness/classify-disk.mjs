#!/usr/bin/env node
// Split the `write:"disk"` population into the three things it actually contains.
//
// ⛔ THE COUNT IS NOT A FILESYSTEM-CAPABILITY NUMBER, AND READING IT AS ONE COSTS DAYS. On Windows
// `write:"disk"` DECLINES the AppContainer/LowBox token rather than widening a grant, so it is the
// absence of confinement — and it is the only rung a token-incompatible package can pass. Asking
// "which path does this package need" about such a package has no answer, because no path is the
// answer. That question was asked, at length, before this classifier existed.
//
// The discriminator needs no new measurement: it reads cells already present in every record.
//
//   TOKEN  no confined cell reaches the control's exit code, but the write:"disk" cell does
//          => an AppContainer/LowBox incompatibility. No catalog grant addresses it.
//   GATE   the zero-capability cell ALREADY reaches the control
//          => the package needs nothing; the record is an artifact of v1's cell predicate, a
//             path-set match that could not re-match under nub's junction-based layout.
//   PATH   some confined cell reaches the control, but the zero-capability one does not
//          => a real, narrow need — typically `network`, occasionally `write.userHome + network`.
//
// On win32 (2,239 records): 63 TOKEN / 26 GATE / 7 PATH of 96. Excluding the two structurally-known
// families (@ffmpeg-installer, @ffprobe-installer, 14 records) leaves 82 eligible: 49 TOKEN (60%) /
// 26 GATE (32%) / 7 PATH (8%).
//
// ⛔⛔ TREAT THAT SPLIT AS A HYPOTHESIS WITH A KNOWN FALSE POSITIVE, NOT A MEASURED PARTITION.
// This classifier reads v1 CELL DATA, and a v1 `rc != 0` means EITHER "the grant was insufficient"
// OR "the v1 harness was broken for this package" — the two are indistinguishable from here. So
// every defect in v1 propagates straight into the labels.
//
// MEASURED COUNTEREXAMPLE: `electron-chromedriver@33.4.9` presents the exact TOKEN signature
// (`confinedOk 0/52` — not one confined cell reaches control) and yet v2 VERIFIES it at
// `{write:{deps,userHome},network}`, rc=0, missing=0. The arithmetic here is right about its input;
// the input was wrong. Counting only packages where v2 has independently measured an answer, the
// discriminator is 7 of 8, not the clean sweep an earlier revision of this comment claimed.
//
// The TOKEN reading is still well-supported for the packages where v2 confirms it: those report
// `missing=0` with `rc=1` — every artifact produced, process still failing, which a blocked path
// cannot explain — and they are non-monotonic, since adding `read:"disk"` makes the run WORSE than
// the rung below it. But "well-supported for the confirmed members" is not "true of all 49", and
// the difference is exactly the kind of over-claim this project keeps paying for.
//
// ⇒ THE NUMBER THAT NEEDS NO DISCRIMINATOR, and therefore the one to quote: 26 of 82 (32%) install
// at the ZERO-capability rung with rc=0. That is read straight off the cells with no inference.
//
// ⛔ THE SELF-CHECK BELOW IS NOT DECORATION. Every wrong answer in this corpus came from an
// instrument nobody validated — a scope-aware record walk that silently dropped all 31 scoped
// packages and reported 65 where the truth was 96, a grep that matched a flag name, a filter
// compared against its own input. This script REFUSES to print a distribution unless it first
// reproduces two families whose answers were established independently of it. Run it and read
// the header: a FAIL there means the numbers below it are an artifact, not a finding.

import fs from 'node:fs';
import path from 'node:path';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const RUNS = arg('--runs', 'records/runs');
const PLATFORM = arg('--platform', 'win32-x64');

// ⛔ PLATFORM COMES FROM THE RECORD PATH, NEVER `provenance.platform`. The provenance field has been
// wrong in real records; the directory a record was published into has not.
const root = path.join(RUNS, PLATFORM);
if (!fs.existsSync(root)) {
  console.error(`no records at ${root}`);
  process.exit(2);
}

const records = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name === 'results.json') {
      try {
        records.push([p, JSON.parse(fs.readFileSync(p, 'utf8'))]);
      } catch {
        /* a half-written record is not a classification input */
      }
    }
  }
})(root);

/** A cell that actually RAN carries a non-null rc; CONTROL rows carry a null index. */
const ran = (r) => (r.cells ?? []).filter((c) => c.index !== null && c.rc !== null && c.rc !== undefined);
const control = (r) => (r.cells ?? []).find((c) => c.index === null && /CONTROL/.test(String(c.state ?? '')));

const classify = (r) => {
  const ctl = control(r);
  if (!ctl || ctl.rc === null || ctl.rc === undefined) return 'NO-CONTROL';
  const cells = ran(r);
  // "Confined" = every rung except the ones that surrender confinement outright.
  const confined = cells.filter((c) => !/write.*disk|everything/i.test(String(c.state ?? '')));
  const okConfined = confined.filter((c) => c.rc === ctl.rc);
  const empty = cells.find((c) => c.index === 0 || /^\(nothing\)|nothing/i.test(String(c.state ?? '')));
  if (empty && empty.rc === ctl.rc) return 'GATE';
  return okConfined.length > 0 ? 'PATH' : 'TOKEN';
};

const disk = records.filter(([, r]) => r.verdict === 'MINIMUM' && r.grant && r.grant.write === 'disk');

// ── The self-check. Two families whose answers were established independently of this script. ───
//
// ⛔ ABSENT AND DISAGREEING ARE DIFFERENT OUTCOMES AND MUST NOT COLLAPSE. Reading "the control
// family is not on this platform" as "the classifier got it wrong" is the same error this project
// already paid for once, when a driver read a VOID arm — nothing measured — as a failed arm and
// climbed past a grant it never tested. A control that is absent tells you the control does not
// APPLY here; only a control that is present and answers wrong condemns the instrument.
// Each control is {platform, label, bucket, pattern, why, negate}. `bucket` is what `classify` must
// return; `label` is what to call it in the output, because the same bucket means "token-incompatible"
// on win32 and "genuinely wide" elsewhere. `negate` flips the assertion to "must NOT be in it".
//
// ⛔ A CONTROL CARRIES THE PLATFORM IT WAS ESTABLISHED ON, AND APPLYING IT ELSEWHERE IS A CATEGORY
// ERROR THIS FILE ALREADY COMMITTED ONCE. The `/proc/self/stat` census is a LINUX result. Five of
// those same package NAMES are also at write:"disk" on win32 — for the unrelated LowBox-token
// reason — so running the Linux control against win32 records reported a FAIL that said nothing
// about the classifier. Same name, same rung, different mechanism, different platform: the answer
// is only "known" where it was measured.
const CONTROLS = [
  ['win32-x64', 'TOKEN', 'TOKEN', /@ffmpeg-installer|@ffprobe-installer/, 'established a LowBox-token incompatibility; a fix moved 0 of 5'],
  ['win32-x64', 'GATE', 'GATE', /\/husky\/|\/lefthook\//, 're-measured under v2 to {} and {write:{deps}} respectively'],
  // ⛔ THIS ONE CAME FROM A DIFFERENT INSTRUMENT AND THAT IS WHY IT COUNTS. The Linux population
  // was censused by TRACING — a `/proc/self/stat` refusal three processes down, reached through
  // libuv's `uv_resident_set_memory` — and landed on 7 of 8, the eighth (`iedriver@4.0.0`) holding
  // a stale record. This classifier reads only cell exit codes and knows nothing of `/proc`, yet
  // independently puts those same 7 in the wide bucket and `iedriver` alone outside it.
  //
  // Two instruments sharing no machinery, agreeing on all eight INCLUDING which one is the odd one
  // out, is the strongest evidence available here that the cell arithmetic tracks something real
  // rather than the shape of the ladder. Both directions are pinned below, because a control that
  // only checks the majority would still pass if the classifier swept everything into one bucket.
  ['linux-x64', 'WIDE', 'TOKEN', /\/(@nuxt\+components|@opencode-ai\+cli|@tensorflow\+tfjs-backend-wasm|codeceptjs|dotnet-2\.0\.0|postman-code-generators|react-native-purchases)\//, 'the 7 traced members of the /proc/self/stat residual census'],
  // The negative half. Without it, a classifier that swept EVERYTHING into the wide bucket would
  // still pass the line above — and sweeping is the most likely way this breaks.
  ['linux-x64', 'WIDE', 'TOKEN', /\/iedriver\//, 'the 8th census member, whose record is STALE — must fall OUTSIDE the wide bucket', true],
];
let disagreed = false;
let applicable = 0;
const checkLines = [];
for (const [plat, label, bucket, pat, why, negate] of CONTROLS) {
  if (plat !== PLATFORM) continue;
  const hit = disk.filter(([p]) => pat.test(p));
  if (hit.length === 0) {
    checkLines.push(`  n/a  ${label.padEnd(5)} — no member of this family is at write:"disk" here`);
    continue;
  }
  applicable++;
  const inBucket = hit.map(([, r]) => classify(r)).filter((g) => g === bucket).length;
  const agree = negate ? hit.length - inBucket : inBucket;
  const ok = agree === hit.length;
  if (!ok) disagreed = true;
  checkLines.push(
    `  ${ok ? 'ok  ' : 'FAIL'} ${negate ? 'NOT ' : ''}${label.padEnd(5)} n=${String(hit.length).padStart(2)} agree=${agree}  (${why})`,
  );
}

// ⛔ THE VOCABULARY IS PER-PLATFORM BECAUSE THE MECHANISM IS. On win32 the wide bucket means the
// AppContainer token was declined, so no grant addresses it. Everywhere else `relax_fs_to_full_disk`
// genuinely widens the filesystem, so the same bucket means the package really did need something
// broad. Printing "AppContainer-incompatible" against a Linux record names a mechanism that does not
// exist on the platform — which is the unreproduced-claim failure this project bans, committed by
// this very file until the wording was moved here.
const WIDE_MEANS =
  PLATFORM === 'win32-x64'
    ? 'AppContainer-incompatible, where no catalog grant is the answer'
    : 'genuinely wide — on Linux the known cause is the /proc/self/stat residual (wiki/research/linux-procfs-residual.md)';

console.log(`platform ${PLATFORM}: ${records.length} records, ${disk.length} MINIMUM with write:"disk"\n`);
console.log('instrument self-check:');
console.log(checkLines.length ? checkLines.join('\n') : '  (no control family was established on this platform)');
if (disagreed) {
  console.error(
    '\n⛔ SELF-CHECK FAILED — a control family that IS present here answered wrong, so the\n' +
      '   distribution below would be an artifact. Fix the classifier; do not read the numbers.',
  );
  process.exit(1);
}
if (disk.length === 0) {
  console.log(`\nno write:"disk" records on ${PLATFORM} — nothing to classify, and that is the good outcome.`);
  process.exit(0);
}
if (applicable === 0) {
  console.log(
    `\n⚠ NO CONTROL FAMILY WAS ESTABLISHED ON ${PLATFORM}. The cell arithmetic still runs, but nothing\n` +
      '  below has been checked against an independently-known answer — treat it as a lead, not a finding.',
  );
}

const tally = {};
const byClass = {};
for (const [p, r] of disk) {
  const c = classify(r);
  tally[c] = (tally[c] ?? 0) + 1;
  (byClass[c] ??= []).push(r.pkg);
}
console.log('\nfull population:');
for (const [k, v] of Object.entries(tally).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${k.padEnd(10)} ${String(v).padStart(3)}  (${((100 * v) / disk.length).toFixed(0)}%)`);
}

// The two structurally-known families are excluded from the actionable population because
// re-measuring them tells you nothing: the mechanism is settled and no grant addresses it.
const STRUCTURAL = /^@ffmpeg-installer\/|^@ffprobe-installer\//;
const eligible = disk.filter(([, r]) => !STRUCTURAL.test(r.pkg));
const eTally = {};
for (const [, r] of eligible) {
  const c = classify(r);
  eTally[c] = (eTally[c] ?? 0) + 1;
}
console.log(`\neligible (minus ${disk.length - eligible.length} structurally-known family records):`);
for (const [k, v] of Object.entries(eTally).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${k.padEnd(10)} ${String(v).padStart(3)}  (${((100 * v) / eligible.length).toFixed(0)}%)`);
}
const over = (eTally.GATE ?? 0) + (eTally.PATH ?? 0);
// ⛔ THE TWO HALVES OF THIS SENTENCE DO NOT CARRY THE SAME CONFIDENCE, AND FLATTENING THEM IS THE
// OVER-CLAIM THE HEADER WARNS ABOUT. The GATE count is read straight off the cells — a package that
// reaches the control at the ZERO-capability rung needs nothing, with no inference. The wide count
// is an INFERENCE from v1 `rc` data that cannot distinguish "insufficient grant" from "broken v1
// harness", and it already has one measured false positive.
console.log(
  `\n⇒ ${eTally.GATE ?? 0} of ${eligible.length} need NOTHING (read off the cells, no inference) and ` +
    `${over} total are over-granted by the v1 gate.\n` +
    `  ${eTally.TOKEN ?? 0} LOOK ${WIDE_MEANS} — but that is a HYPOTHESIS from v1 cell data, ` +
    `not a measurement.\n  Confirm any individual one with v2 before citing it; the discriminator ` +
    `is 7 of 8 where v2 has checked.`,
);

if (process.argv.includes('--list')) {
  for (const k of ['TOKEN', 'GATE', 'PATH']) {
    if (byClass[k]) console.log(`\n${k}:\n  ${[...new Set(byClass[k])].sort().join('\n  ')}`);
  }
}
