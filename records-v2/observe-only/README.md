# observe-only ledger — every `BROKEN-*` record, re-measured

`BROKEN-WITHOUT-JAIL-TOO` and `BROKEN-UNJAILED-NUB` cover 1,529 of the corpus's 6,880 records, and
every jail number ever quoted silently excludes them. This lane re-measures **all 1,529** through an
arm that gives each package what it was published against, and records why each one that still fails,
fails.

## The run (2026-08-22, run 32566183450)

| platform | records | era chosen | era Node pinned |
| --- | ---: | ---: | ---: |
| linux-x64 | 461 | 461 | 405 |
| darwin-arm64 | 498 | 498 | 443 |
| win32-x64 | 570 | 570 | 519 |
| **total** | **1529** | **1529** | **1367** |

| disposition | n | meaning |
| --- | ---: | --- |
| `CONFIRMED` | 900 | still fails, and the row says why |
| `STALE-RECORD` | 595 | **installs today.** The exclusion was wrong for 39% of the bucket. |
| `NUB-UNMEASURED` | 30 | npm succeeds; the nub half is [its own lane](../nub-unjailed/README.md) |
| `UNMEASURED-TIMEOUT` | 3 | hit the wall-clock cap; **not** a package verdict |
| `CHANGED` | 1 | npm now fails where it used to succeed |

**All 900 CONFIRMED rows carry a cause.** Every measured row also carries a 40-line `tail`, so a
later change to how causes are extracted can be re-evaluated against what the run saw instead of
re-running against a registry that has moved on.

## What "gives each package what it was published against" means

Each of these was added because its absence was silently producing package verdicts:

- **An era Node**, chosen from the package's publish date and raised by its `engines`.
- **A dependency tree resolved as of that date** (`npm install --before=…`), because an era Node
  alone still pulls today's transitive deps and chokes on their syntax.
- **The era's own npm**, resolved per platform — a modern npm running its node-gyp under an era Node
  fails with `TypeError: name.replaceAll is not a function`.
- **The binaries the lifecycle scripts actually invoke**, installed at the same date. Not the whole
  devDependency closure: `@paypal/paypal-js@2.1.8` declares 29 devDeps and fails with all of them,
  and succeeds with the one it uses.
- **A Python its node-gyp era accepts** — 2.7 below Node 8, and no newer than 3.9 through Node 14,
  because Python 3.10 removed `collections.MutableMapping` and 3.11 removed the `'rU'` open mode,
  both of which old gyp reads its own source with.
- **An activated MSVC environment on Windows**, because node-gyp's own Visual Studio detection
  overruns its stdout buffer on the runner image.
- **A sanitised PATH**, so a tool that happens to sit on the runner is not mistaken for one the
  package provides.

## What is left, named

Two populations still fail for a reason no harness change can reach, and the ledger records both with
the era attached rather than filing them against the package:

| n | where | why |
| ---: | --- | --- |
| 99 | win32, eras 0-14 | old native addons do not build against a modern MSVC. 61 never reach the compiler — node-gyp 3.x-5.x cannot detect a Visual Studio newer than it, and no hosted image ships VS 2015 or 2017; the other 38 now get all the way to `msbuild` and fail there |
| 103 | all | `@sitespeed.io/edgedriver` hardcodes `msedgedriver.azureedge.net`, which is **NXDOMAIN**; the successor host 404s that version |
| 34 | all | `redis-memory-server` compiles Redis from source and fails on a modern C compiler |

## Two exclusions this file does not hide

`win32` records are measured on `windows-2022`. The `windows-2025` label now routes to an image
carrying Visual Studio 18, which no released node-gyp can identify — on that image every native
Windows build fails identically, which tells you nothing about the package.

`NUB-UNMEASURED` is **not** an exoneration of nub. Those 30 records are ones npm installs; whether
nub does is decided in the [nub-unjailed lane](../nub-unjailed/README.md), not here.

## Reading it

```sh
# the split
jq -r .disposition records-v2/observe-only/ledger-2026-08-22.ndjson | sort | uniq -c

# what still fails, and why
jq -r 'select(.disposition=="CONFIRMED") | "\(.platform)\t\(.spec)\t\(.firstError)"' \
  records-v2/observe-only/ledger-2026-08-22.ndjson

# everything the run saw for one record
jq -r 'select(.spec=="heapdump@0.3.9") | .tail' records-v2/observe-only/ledger-2026-08-22.ndjson
```
