# What stops the corpus runner measuring, per platform

Written 2026-08-22, after re-measuring all 1,529 `BROKEN-*` records and unblocking the jail gate.
Each entry is a defect someone still has to fix; none of them is in this harness.

## linux-x64 — MEASURING

Unblocked and proven. Two drain slices measured 189 records. The falsification gate passes:

```
── network: hugo-extended@0.141.0 — drop 'network' from {"network":true}
   wrong-cold  INSUFFICIENT  installRc=1 artifacts=9/12 missing=3 refusal=seen detectors=rc+gate
falsify: PASS — 2/2 case(s) detected their wrong grant
```

## darwin-arm64 — BLOCKED: nub cannot materialise a tree on a cold store

falsify's control arm never installs, so every darwin case is unattributable. The driver says why:

```
── DIRECT: does hugo-extended@0.141.0 install under EXACTLY {} ?
EVICT[at-grant] no store at /Users/runner/.cache/nub/pm/store yet (first arm on this box)
=> HARNESS-ERROR: Nub could not materialize the tree with --ignore-scripts; no lifecycle script ran
```

The grant is not the problem — the tree is never built, on the FIRST arm on a box with no store yet.
DTrace is available on the runner (the `dtrace gate` step passes), so this is not a tracing gap.

## win32-x64 — BLOCKED: the jail denies without saying so

falsify's second case fails on the refusal TEXT, not on the denial:

```
wrong-cold  INSUFFICIENT  installRc=0 artifacts=7/8 missing=1 refusal=— detectors=gate
⛔ /WARN_(AUBE|NUB)_JAIL_NET_DENIED|blocked network access/ : MISS
   /github\.com|raw\.githubusercontent\.com/               : hit
```

The artifact gate fired, so the jail DID withhold something. But nothing in the logs says a network
access was denied, so the harness cannot distinguish enforcement from an operation that was never
attempted — which is the one thing falsify exists to establish. Case 1 passes, so the lane is not
wholly broken.

## Corpus hygiene — three records predate the current provenance

`@sitespeed.io/chromedriver@90.0.4430-24`, `electron-prebuilt@0.24.0`, `electron-prebuilt@0.28.3`.
`harness/v2/invalidation.json` invalidates records from before epoch 3, and these three fail
`verify-corpus.mjs`, so every drain run ends RED even when every record it measured committed fine.

What is established: the discriminator is two provenance fields, `cwdResolved` and
`cwdUnplaceableWrites` — a record measured today is otherwise identical in shape to these. Marking
the queue rows `pending` does NOT help, because the gate reads the record FILES, not the queue. A
targeted `packages=` run does not rewrite them either, with or without `force=true`, and why that is
so is NOT established.

## Checked and NOT a harness gap — ERESOLVE

30 CONFIRMED rows fail with `ERESOLVE`, all of them at FETCH. It looks like a candidate for
`--legacy-peer-deps`, and it is not: **27 of the 30 are at era >= 16**, where npm 8+ enforces peer
ranges by design, so the era-appropriate installer would refuse them too. Those are genuine
dependency conflicts and the records are right.

Only 3 rows (era 4, whose npm 2/3 enforced nothing) are a venue artifact — the fetch always runs on
the harness's modern npm, because the era npm is chosen from metadata the fetch has not produced
yet. Three rows does not justify restructuring the arm, and loosening peer resolution for everything
would turn 27 correct refusals into fabricated passes.

## What would move the remaining 883

| rows | needs |
| ---: | --- |
| ~150 | a runner image with **Visual Studio 2015/2017** — old node-gyp cannot detect a modern VS, and no hosted image ships one. Self-hosted, or nothing. |
| ~260 | nothing — platform mismatches, a CDN host that is NXDOMAIN, redis built from source, `node-waf`, POSIX `./script` under cmd.exe. These records are correct. |
| 431 | the darwin and win32 defects above, which gate their platforms entirely |
