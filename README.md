# build-jail corpus

Measures, for every npm package that runs an install script, the **minimum OS capability its
lifecycle scripts actually need** — and persists every run so a result can be re-read, re-checked,
and audited later.

This repo exists because the runs cannot live in `nubjs/nub`:

- **The records are the deliverable and they are big.** ~50 KB per package-version including
  per-cell logs. A full three-platform corpus is ~6,750 records / ~340 MB. They are gitignored in
  the nub tree (`.gitignore:157`), which means today every measurement exists in exactly ONE place,
  on a disposable VM.
- **The corpus runs arbitrary third-party install scripts.** That belongs in a private repo with
  its own CI, not in the public product repo.

## Where the nub binary comes from — the one cross-repo coupling

The harness needs a nub built with `--features nub-cli/build-jail-catalog-override`, which is a
**development-only** feature: it lets the probe swap the compiled-in catalog per cell. Without it
every cell silently measures the shipped catalog instead, and the whole run is meaningless.

**The workflow takes a nub commit SHA as a dispatch input**, checks out `nubjs/nub` at that SHA,
builds with the feature, and caches the artifact. Deliberately not a submodule:

- every run records exactly which nub it measured, in its own provenance;
- a re-run of an old corpus is reproducible by SHA;
- nothing here silently follows nub's default branch.

## Layout

| path | what |
|---|---|
| `harness/` | the probe: `search.mjs` (the grant search), `run-batch.sh` (the driver), `collate.mjs` (records → catalog), `watch-sweep.mjs` / `digest.mjs` (reading results), `baseline.json` (the floor every jailed script gets) |
| `inputs/` | worklists. `worklist-macos-final.txt` is the 2,250-entry production corpus |
| `workflows/` | `corpus-probe.yml` (one shard) and `corpus-fanout.yml` (a shard RANGE via matrix) |
| `records/` | run records, per platform. **These are tracked — that is the point of this repo.** |

## Running it

```sh
# one shard, and the ONLY loop worth debugging with — reuse the binary to skip the ~25 min build
gh workflow run corpus-probe.yml -f runner=windows-latest \
  -f shard_index=0 -f shard_count=150 -f reuse_binary_from=<run-id>

# many shards at once
gh workflow run corpus-fanout.yml -f runner=windows-latest \
  -f shard_from=0 -f shard_to=19 -f shard_count=150 -f reuse_binary_from=<run-id>
```

⛔ **`corpus-fanout.yml` only dispatches if it is on the DEFAULT branch.** `workflow_dispatch` lists
workflows registered from the default branch only — a workflow that has never run and is not on
`main` returns 404. In `nubjs/nub` this forced a loop of `corpus-probe` dispatches instead; here the
fanout can simply live on `main`.

## Reading results — the traps that cost real time

- **`collate.mjs` takes `--runs`, not a positional.** Given a positional it reads **0 records and
  still writes a catalog file** — a plausible-looking artifact from nothing.
- **The collator is the best defect-finder here.** Run it periodically, not just at the end. It has
  caught: records spanning several harness revisions, `HARNESS-*` verdicts hiding in a generic
  bucket, and packages whose `default` grant came from a stale version.
- **`--stale-harness`** re-measures only records taken under a different harness revision, instead of
  `--force` redoing everything.
- **A `HARNESS-*` verdict is NOT a measurement** and does not satisfy the resume check — those
  packages re-run automatically.

## What the verdicts mean

| verdict | meaning |
|---|---|
| `MINIMUM` | measured — the grant recorded is the minimum that reproduces the control |
| `BROKEN-IN-ENVIRONMENT` | fails here AND a reference PM fails identically — the environment, not nub |
| `BROKEN-WITHOUT-JAIL-TOO` | fails IDENTICALLY with the jail off — a nub PM/linker or packaging bug, **never** a jail defect |
| `BROKEN-EVEN-WITH-EVERYTHING` | the jail IS implicated: fails jailed, succeeds unjailed, reference PMs succeed |
| `REFUSED-MALICIOUS` | the OSV screen refused something in the tree; `maliciousAdvisories` names what |
| `CONTROL-ONLY` | fixture health check, not a measurement |

**`BROKEN-WITHOUT-JAIL-TOO` exists because the oracles cannot tell "nub's PM is wrong" from "nub's
jail is wrong".** Only a jail-off control can. Across macOS/Linux/Windows it has exonerated the jail
38 consecutive times; every one of those would otherwise have been counted against it.

⛔ Its one weakness, which must not be lost: under load the jail-off cell can fail transiently and
mislabel a REAL jail defect as harmless — the dangerous direction. It is sound only because defect
verdicts are re-verified SERIALLY after the batch drains, on a quiet box.

## ⛔ WHAT THIS REPO MUST CARRY ON DAY ONE — the gate, not just the harness

Six defects shipped in this harness while its MEASUREMENT layer was correct throughout. Every one
produced a catalog that parsed cleanly and granted nothing, or a record that measured right and
serialised nothing. **None was caught by a test**, because every existing test asserted the
HAND-MAINTAINED compiled-in table — nothing ever compared GENERATOR output against a CONSUMER.

`gates/generated_catalog_round_trip.rs` closes exactly that. It parses a GENERATED v2 catalog and
asserts its egress grants reach the lookup the jail actually uses, including a version-banded package
whose current releases need no egress. **Port it before the first corpus run**, not after: a repo
running 2,250 packages x 3 platforms and committing results will produce a great deal of
confidently-empty data before anyone notices.

### The six, so they are not re-introduced

| # | defect | how it hid |
|---|---|---|
| 1 | jail-off control used a deleted opt-out | a cell that cannot differ from the control only ever AGREES with it — which is the shape of "not the jail" |
| 2 | npm-6 `_cacache` race | lands on the CONTROL; the double-control cannot catch it because both attempts share the busy window |
| 3 | Windows path handling | `new URL().pathname` doubles the drive letter; `file://${argv[1]}` is silently false — both degrade to a NO-OP, not an error |
| 4 | `grantFor` returned `undefined` | `g[0]` on `{default: grant}` after the array->object migration; records carried a human LABEL and no structure |
| 5 | `.store` bookkeeping dirs became package names | inert until the grant set became a catalog table |
| 6 | a v2 override never fed the egress table | **in nub, not the harness** — macOS/Linux deny egress in-kernel and never reach that code, so it looked like a Windows platform defect |

### Two traps that cost the most time

- **TWO PARSERS.** `catalog_v2::parse` takes `packages[<name>].default.network` (what this harness
  emits; `catalog_override` tries it FIRST). `catalog::parse` is v1 and wants
  `networkHosts`/`packageGrants`. Asserting a v2 document against the v1 parser fails with
  `` `networkHosts` must be an array `` — which reads as a generator defect and is not one.
- **A CORRELATION IS NOT THE VARIABLE.** A 6x scoped-vs-unscoped skew in the Windows failure rate
  pointed hard at the exact-match name lookup. Splitting on BOTH variables killed it: scoped packages
  with no network need failed 0% of the time. Scope merely correlates with needing egress.

### Recovery, if a serialisation bug ever recurs

Records store `state` (a label) and `cost`. `STATES` is an exhaustive `read x write x network`
product and each label is built deterministically from its cost atoms, so a label names exactly ONE
state and `grantForState` (states.mjs — one definition, two callers) reconstructs the grant EXACTLY.
That is why the ~2,500 records written while (4) was live needed re-COLLATION, not re-measurement:
macOS went 0 -> 63 packages with real capabilities, Linux 0 -> 93 and 0 -> 97.
