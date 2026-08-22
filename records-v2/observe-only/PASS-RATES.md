# The jail's pass rates, with the excluded fifth accounted for

Every number quoted about the build jail is computed over a population that silently omits the
`BROKEN-*` bucket — 1,529 of 6,880 records, 22.2% of the corpus. This file states what that exclusion
was hiding, now that **all 1,529** have been re-measured.

## As the corpus stood

| | n | |
| --- | ---: | --- |
| records | 6,880 | |
| `BROKEN-*`, excluded from every jail claim | 1,529 | 22.2% of the corpus |
| measurable population | 5,351 | |
| `MINIMUM` — the jail needed nothing extra | 4,917 | **91.9% of measurable**, 71.5% of all records |

The 91.9% is the number that gets quoted. Its denominator excludes a fifth of the corpus on the
grounds that those packages install for nobody.

## What the re-measurement found

All 1,529 were re-measured through an arm that supplies what each package was published against —
era Node, era npm, a dependency tree resolved as of its publish date, the binaries its lifecycle
scripts invoke, the Python its node-gyp era accepts, and an activated MSVC on Windows.

| | n |
| --- | ---: |
| re-measured | 1,529 |
| **install today** — the exclusion was wrong | **506** |
| genuinely still broken, every one with a cause attached | 990 |
| npm installs it; the nub half is its own lane | 30 |
| npm now fails where it used to succeed | 1 |
| hit the wall-clock cap, no verdict | 2 |

**A third of the bucket installs.** The exclusion was not describing dead packages; it was largely
describing an observation environment that gave old packages a modern toolchain.

## What that does to the denominator

| | before | after |
| --- | ---: | ---: |
| excluded from every jail claim | 1,529 | 1,023 |
| excluded share of the corpus | 22.2% | **14.9%** |
| measurable population | 5,351 | 5,857 |

## ⛔ This file does NOT restate the pass rate, and neither should you

The 506 records were shown to **install**. They were not measured **with the jail on**. A pass rate
needs a jail verdict for every record in its denominator, and these 506 have none yet — they are
re-queued for the corpus runner, and the number moves when that runs, not before.

Quoting `4,917 / 5,857 = 83.9%` would be worse than quoting the old figure, because it would put 506
records in the denominator with no measurement behind them. The honest statement today is:

> The jail needed nothing extra for 4,917 records. 1,023 records could not be measured at all. 506
> records previously counted as unmeasurable do install, and are awaiting a jail verdict.

The floor that IS safe to state: even if all 506 turned out to need a grant, the jail's
needed-nothing-extra count does not fall — it can only rise.
