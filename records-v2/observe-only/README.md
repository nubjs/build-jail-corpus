# Observe-only ledger — what the `BROKEN-*` bucket actually is

`ledger-2026-08-21.ndjson` re-measures the 1,529 records the corpus files as
`BROKEN-WITHOUT-JAIL-TOO` or `BROKEN-UNJAILED-NUB`, through a repaired observe arm.

## Why these records needed re-measuring

The original verdicts were reached in an environment that withheld things the packages need. The
observe arm is a CONSUMER install, so it never installed a dependency's devDependencies; it ran
every package on whatever Node the harness happened to carry; and it resolved every dependency
tree against today's registry regardless of when the package was published. A package that fails
for any of those reasons is an OBSERVATION failure, not a dead package — and the corpus recorded
it as the latter.

The repaired arm gives each package: the Node current when it was published, a dependency tree
resolved as of its own publish date, the binaries its lifecycle scripts invoke, the Python its
node-gyp era accepts, a PATH built rather than inherited, and a process-group cap.

## The result, over 959 measured records

| disposition | n | meaning |
| --- | ---: | --- |
| `CONFIRMED` | 615 | still fails, and now carries the installer's own first error |
| `STALE-RECORD` | 311 | installs today; the record is wrong |
| `NUB-UNMEASURED` | 22 | npm installs it; the nub half needs an arm that runs nub |
| `CHANGED` | 9 | npm now fails, so the record's premise is gone |
| `UNMEASURED-TIMEOUT` | 2 | capped; deliberately NOT a package verdict |

**About a third of the bucket installs today.** 848 of these rows carry a real era-Node pin,
where previously no record in the corpus carried one at all.

## What is NOT in this file, and why

⛔ **The 570 win32 rows are excluded.** All of them returned `fetchRc=127`: npm ships as a `.cmd`
shim on Windows and `spawnSync` without a shell cannot execute one, so npm never ran. Every row
"confirmed" the record it was meant to re-test, with no era pin and no error text — a 100% verdict
with zero evidence. Committing them would put 570 false `CONFIRMED`s into the corpus as evidence.
win32 must be re-measured with `npm.cmd`; the runner now refuses to start at all if `npm --version`
fails, so this cannot recur silently.

⛔ **`NUB-UNMEASURED` is not an exoneration.** `BROKEN-UNJAILED-NUB` means "npm installs it, nub
does not". This runner drives npm only, so a succeeding arm re-confirms the half that was never in
doubt. An earlier pass called those rows `STALE-RECORD`, which would have reported 22 open nub
defects as fixed. They are closed separately by a jail-off nub arm.

## Reading a row

`previous` is the corpus verdict; `verdict` is what the repaired arm found; `disposition` compares
them. `eraPinned`, `before`, `scaffold` and `python` record what the arm supplied, so a row can be
judged on what it actually ran rather than on what was intended.
