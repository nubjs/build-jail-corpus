# The jail's pass rates, with the excluded fifth accounted for

Every number quoted about the build jail is computed over a population that silently omits the
`BROKEN-*` bucket — 1,529 of 6,880 records, 22.2% of the corpus. This file states what that
exclusion was hiding, and what it becomes now that part of the bucket has been re-measured.

## As the corpus stood

| | n | |
| --- | ---: | --- |
| records | 6,880 | |
| `BROKEN-*`, excluded from every jail claim | 1,529 | 22.2% of the corpus |
| measurable population | 5,351 | |
| `MINIMUM` — the jail needed nothing extra | 4,917 | **91.9% of measurable**, 71.5% of all records |

The 91.9% is the number that gets quoted. It is computed over a denominator that excludes a fifth
of the corpus on the grounds that those packages install for nobody.

## What the re-measurement found

959 of the 1,529 have been re-measured through an arm that supplies what each package was
published against — era Node, a dependency tree resolved as of its publish date, the binaries its
lifecycle scripts invoke, the Python its node-gyp era accepts.

| | n |
| --- | ---: |
| re-measured | 959 |
| **install today** — the exclusion was wrong | **311** |
| genuinely still broken, now with a cause attached | 615 |
| npm installs it, nub half needs a nub arm | 22 |
| npm now fails, so the record's premise is gone | 9 |
| capped | 2 |
| not yet re-measured (win32) | 570 |

## The restated claim

The measurable population grows from **5,351 to 5,662**, and the excluded share falls from
**22.2% to 17.7%** of the corpus.

⛔ **No new `MINIMUM` rate can be quoted yet, and quoting one would be the same error again.** The
310 re-queued records have been shown to INSTALL; they have not been measured WITH THE JAIL. Their
grant requirements are unknown. What changes today is the denominator claim, not the numerator:
311 records were excluded as unmeasurable and are not unmeasurable.

The honest form of the current number is therefore: **91.9% of a population that excludes 22.2% of
the corpus, at least 311 of which were excluded in error.** The 310 must flow through a real jailed
measurement before any pass rate covers them.

## Why the exclusion was wrong

The verdicts were reached by an observe arm that is a CONSUMER install: it never installed a
dependency's devDependencies, ran every package on whatever Node the harness carried, and resolved
every dependency tree against today's registry regardless of publish date. A package that fails for
any of those reasons failed the OBSERVATION, not the install — and was recorded as the latter.
