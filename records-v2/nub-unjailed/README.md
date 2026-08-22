# nub-unjailed ledger — the records where npm succeeds and nub was recorded as failing

`BROKEN-UNJAILED-NUB` is the only verdict in the 1,529-record broken population that nub itself
produced. The other 1,481 are decided by npm before nub is ever invoked, which is what the
[observe-only](../observe-only/README.md) lane measures. This lane re-runs the 31 that name nub, with
the jail OFF, and asks whether nub still cannot install what npm can.

## What the run measured (2026-08-22, run 32557281871)

| outcome | rows | meaning |
| --- | --- | --- |
| `NUB-INSTALLS` | 20 | nub installs it today. The record is stale. |
| `NUB-REFUSED` | 9 | nub declined it on purpose. **Not a defect.** |
| `NUB-DEFECT` | 2 | nub fails where npm succeeds, for no policy reason. |

Every row carries the tail of each log nub wrote (`i.log`, `a.log`, `n.log`, `fetch.log`,
`security-resolve.log`), so any later change to how outcomes are classified can be re-evaluated
against what the run actually saw rather than by re-running it.

## A refusal is a decision, and the error CODE does not tell you which you have

Nine rows are nub's security and policy screens working as designed. Five say so plainly — three
`ERR_NUB_MALICIOUS_PACKAGE`, two `ERR_NUB_TRUST_DOWNGRADE`. The other four are the trap: they surface
as `ERR_NUB_REGISTRY_ERROR`, which reads like a failed fetch, and only the body says otherwise.

```
ERR_NUB_REGISTRY_ERROR
  × failed to resolve dependencies
  ╰─▶ registry error for nan: uses exotic specifier "github:JCMais/nan#fix/electron-failures"
      which is blocked by blockExoticSubdeps (declared by node-libcurl)
```

Two consequences for anyone reading this ledger or changing its classifier. Classifying on the error
code alone files four deliberate policy blocks as bugs. And nub renders that diagnostic as a
hanging-indent block, so `blocked by` and the policy name land on different lines whenever the
specifier is long enough to push the wrap — a first attempt that matched the raw text found six
refusals where nine exist, missing exactly the three that wrapped early.

This also settles the `netlify-cli` version boundary, which looked like a regression worth bisecting:
22.4.0 and 23.9.5 trip a trust downgrade, 26.2.0 and 27.0.1 do not.

## The two defects

| package | what nub does |
| --- | --- |
| `@progress/kendo-licensing@0.1.2` | `sh: 1: ./bin/update-kendo-license.js: Permission denied` — the bin script is not left executable, and npm leaves it executable |
| `@typescript-tools/rust-implementation@7.0.8` | `ENOENT: no such file or directory, unlink '.../node_modules/.bin/monorepo'` |

## Reading it

```sh
# the outcome split
jq -r .outcome records-v2/nub-unjailed/ledger-2026-08-22.ndjson | sort | uniq -c

# every defect, with its cause
jq -r 'select(.outcome=="NUB-DEFECT") | "\(.spec)\t\(.firstError)"' records-v2/nub-unjailed/ledger-2026-08-22.ndjson

# why a particular row was called a refusal
jq -r 'select(.spec=="web3@2.0.0-alpha.1") | .logs["security-resolve.log"]' records-v2/nub-unjailed/ledger-2026-08-22.ndjson
```
