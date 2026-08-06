#!/bin/bash
# KNOWN-ANSWER fixture for "does a write to the jail's temp dir need a write grant?"
#
# THE QUESTION. `observe.mjs` classifies any write that falls under no catalog-expressible scope as
# `outside` and prints `⛔ N writes OUTSIDE project/home`. On the 45 linux-x64 v2 records, 10 records
# carry that flag and every one of them is a `/tmp` path. OBSERVE runs UNJAILED, so `os.tmpdir()`
# there is the real, shared `/tmp`. Under the jail it is not: `build_jail_surface` inserts `$tmp: rw`
# (`compiler/preset.rs`), which is `TmpMode::Private`, and on Linux `backend/linux.rs` implements that
# as bubblewrap `--bind <per-run-dir> /tmp` plus `insert_tmp_env(..., "/tmp")`. So the write should
# land in already-granted space and cost NOTHING.
#
# ⛔ THAT IS A MECHANISM READ OFF SOURCE, WHICH IS A LEAD AND NOT A MEASUREMENT. This fixture is the
# measurement, and it is built so it can come back NO.
#
# THE FOUR TARGETS, chosen so the answer is known in advance for two of them:
#
#   A  os.tmpdir()/…      expected ALLOW under the jail — the redirect's whole purpose
#   B  literal "/tmp/…"   expected ALLOW *on Linux only*, and this row is the point: the bind mount
#                         relocates the PATH, so a hardcoded `/tmp` write is redirected exactly like
#                         an `os.tmpdir()` one. On macOS the same mode is an env redirect plus an
#                         SBPL deny over the shared roots, so B is expected to DIVERGE from A there.
#   C  <real $HOME>/…     expected DENY — the NEGATIVE CONTROL. The jail redirects `HOME`, but C is
#                         an ABSOLUTE path baked in at pack time, so it still names the real home.
#                         If C is allowed the jail did not engage and NO row here means anything.
#   D  /var/tmp/…         expected DENY — the SECOND negative control, and the sharpest row. The
#                         bind covers `/tmp` and nothing else, so `/var/tmp` is ordinary ungranted
#                         disk. `observe.mjs` puts C and D in the SAME `outside` bucket as A and B,
#                         which is exactly why "outside" cannot be read as "free".
#
# ⛔ THE UNJAILED ARM IS NOT CEREMONY. All four writes must succeed there. A fixture whose C or D
# write fails for an ordinary reason (a read-only dir, a missing parent) would produce a jailed arm
# that looks perfectly confined while measuring a broken fixture.
#
# ⛔ A UNIQUE PACKAGE NAME PER ARM, so no replay path exists at all. nub memoises a lifecycle outcome
# on package identity and relinks an already-materialised store entry without re-running the script
# (see the three-guard note in `measure.sh`). A fresh name per arm closes all three by construction
# rather than by eviction, which is available here because the fixture is ours to name.
#
# ⛔ Exit codes are captured on their own line, never through a pipe.
set -u
WORK="${1:?usage: tmp-write-fixture.sh <workdir> <nub-binary>}"
NUB="${2:?usage: tmp-write-fixture.sh <workdir> <nub-binary>}"
mkdir -p "$WORK" || exit 1
WORK="$(cd "$WORK" && pwd)"

# The absolute out-of-jail targets, created and proven writable BEFORE either arm. `REALHOME` is
# captured here, in the harness, precisely because the jail rewrites `HOME` for the child.
REALHOME="$HOME"
OUTSIDE_C="$REALHOME/tmpprobe-outside"
OUTSIDE_D="/var/tmp/tmpprobe-outside"
mkdir -p "$OUTSIDE_C" "$OUTSIDE_D" || exit 1

# ── The fixture package. Its postinstall NEVER FAILS: it attempts all four writes, records the
# outcome of each, and exits 0. One arm therefore yields FOUR independent bits instead of the single
# pass/fail an exit code carries — and a jail denial cannot be confused with the script crashing.
build_fixture () {
  # ⛔ TWO STATEMENTS, NOT ONE `local a=… b=$a`. Bash expands every word of a command BEFORE `local`
  # performs any assignment, so the second word would read an unbound `$name` and `set -u` aborts.
  local name="$1"
  local dir="$WORK/src-$name"
  rm -rf "$dir"; mkdir -p "$dir" || return 1
  cat > "$dir/package.json" <<EOF
{ "name": "$name", "version": "1.0.0", "scripts": { "postinstall": "node postinstall.js" } }
EOF
  # The targets are baked in as DATA, not read from the environment: the jail scrubs the env, so an
  # env-carried path would arrive empty inside the jail and the row would silently test nothing.
  cat > "$dir/targets.json" <<EOF
{ "C": "$OUTSIDE_C", "D": "$OUTSIDE_D" }
EOF
  cat > "$dir/postinstall.js" <<'EOF'
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const t = JSON.parse(fs.readFileSync(path.join(__dirname, 'targets.json'), 'utf8'));
const tag = 'p' + process.pid;
const attempt = (label, target) => {
  try { fs.writeFileSync(target, 'x'); return { label, target, result: 'ALLOW' }; }
  catch (e) { return { label, target, result: 'DENY', code: e.code, msg: String(e.message).slice(0, 120) }; }
};
const rows = [
  attempt('A', path.join(os.tmpdir(), 'A-ostmpdir-' + tag)),
  attempt('B', '/tmp/B-hardcoded-' + tag),
  attempt('C', path.join(t.C, 'C-realhome-' + tag)),
  attempt('D', path.join(t.D, 'D-vartmp-' + tag)),
];
// `os.tmpdir()` and the raw env, so "were A and B the same path?" is answered by the arm itself
// rather than inferred from the backend's source.
const report = {
  tag,
  osTmpdir: os.tmpdir(),
  env: { TMPDIR: process.env.TMPDIR ?? null, TMP: process.env.TMP ?? null, HOME: process.env.HOME ?? null },
  rows,
};
fs.writeFileSync(path.join(__dirname, 'report.json'), JSON.stringify(report, null, 2));
for (const r of rows) console.log(`FIXTURE ${r.label} ${r.result} ${r.target}${r.code ? ' ' + r.code : ''}`);
console.log('FIXTURE tmpdir ' + os.tmpdir());
process.exit(0);
EOF
  ( cd "$dir" && npm pack --silent > "$WORK/pack-$name.out" 2>&1 )
  local prc=$?
  [ "$prc" -eq 0 ] || { echo "  ⛔ npm pack failed for $name"; cat "$WORK/pack-$name.out"; return 1; }
  echo "$dir/$name-1.0.0.tgz"
}

# Read the four rows back out of the arm. `find -L` because nub's isolated layout makes every
# node_modules entry a symlink into the machine-global store — a bare `find` sees nothing.
read_report () {
  local armdir="$1"
  local rep
  rep=$(find -L "$armdir/node_modules" -name report.json -maxdepth 4 2>/dev/null | head -1)
  [ -n "$rep" ] || { echo "  ⛔ NO report.json — the postinstall never ran, so this arm measured nothing"; return 3; }
  node -e '
    const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    console.log("     os.tmpdir() = " + r.osTmpdir + "   TMPDIR=" + r.env.TMPDIR + "   HOME=" + r.env.HOME);
    for (const row of r.rows) console.log("     " + row.label + "  " + row.result.padEnd(6) + row.target + (row.code ? "  (" + row.code + ")" : ""));
  ' "$rep"
  node -e '
    const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    console.log(r.rows.map(x => x.label + "=" + x.result).join(" "));
  ' "$rep" > "$armdir/verdict.txt"
  return 0
}

# ── ARM 1: UNJAILED. Every row must be ALLOW or the fixture itself is broken. ─────────────────
echo "── ARM 1  UNJAILED CONTROL (all four writes must succeed)"
NAME1="tmpprobe-unjailed-$$"
TGZ1=$(build_fixture "$NAME1") || exit 1
A1="$WORK/arm-unjailed"; mkdir -p "$A1"
printf '{"name":"a1","version":"1.0.0","dependencies":{"%s":"file:%s"}}\n' "$NAME1" "$TGZ1" > "$A1/package.json"
( cd "$A1" && npm install --no-audit --no-fund > "$A1/i.log" 2>&1 )
echo "  npm rc=$?"
read_report "$A1"; R1=$?
V1=$(cat "$A1/verdict.txt" 2>/dev/null)
if [ "$R1" -ne 0 ] || [ "$V1" != "A=ALLOW B=ALLOW C=ALLOW D=ALLOW" ]; then
  echo "  ⛔ THE UNJAILED CONTROL DID NOT PASS ALL FOUR ROWS ($V1)."
  echo "     The fixture, not the jail, is what this run would be measuring. STOPPING."
  exit 1
fi
echo "  ✓ control good — all four targets are writable when nothing confines the script"

# ── ARM 2: JAILED at the EMPTY grant. ────────────────────────────────────────────────────────
echo
echo "── ARM 2  JAILED at grant {} (no write scope, no network)"
NAME2="tmpprobe-jailed-$$"
TGZ2=$(build_fixture "$NAME2") || exit 1
A2="$WORK/arm-jailed"; mkdir -p "$A2"
printf '{"name":"a2","version":"1.0.0","dependencies":{"%s":"file:%s"}}\n' "$NAME2" "$TGZ2" > "$A2/package.json"
printf '{"install":{"buildJail":true}}\n' > "$A2/nub.jsonc"
printf 'side-effects-cache=false\n' > "$A2/.npmrc"
# The empty grant cannot be spelled as an entry — nub rejects an entry that widens nothing and then
# falls back to the COMPILED-IN catalog, which trips the override assertion below. Express it by
# OMITTING the package, carrying a sentinel for an unrelated name so the override still engages.
# (Same construction, and the same reason, as `measure.sh`.)
printf '{"packages":{"__tmpprobe_empty_grant_sentinel__":{"default":{"network":true}}}}\n' > "$A2/cat.json"
( cd "$A2"
  NUB_BUILD_JAIL_CATALOG="$A2/cat.json" "$NUB" install > "$A2/i.log" 2>&1
  NUB_BUILD_JAIL_CATALOG="$A2/cat.json" "$NUB" approve-builds --all > "$A2/a.log" 2>&1 )
echo "  nub rc=$?"
OVR=$(cat "$A2"/*.log | grep -c 'catalog OVERRIDDEN'); REJ=$(cat "$A2"/*.log | grep -c 'REJECTED')
echo "  OVERRIDDEN=$OVR REJECTED=$REJ"
if [ "$OVR" -lt 1 ] || [ "$REJ" -ne 0 ]; then
  echo "  ⛔ VOID — the override did not engage, so nub ran the COMPILED-IN catalog and nothing"
  echo "     about the stated grant was measured. Not a result."
  sed 's/^     /       /' "$A2"/*.log | tail -30
  exit 3
fi
grep -qE 'running build scripts for' "$A2"/*.log 2>/dev/null \
  || echo "  ⛔ no 'running build scripts' line — the script may not have run"
read_report "$A2"; R2=$?
V2=$(cat "$A2/verdict.txt" 2>/dev/null)

# ── ARM 3: where did B actually land? A PERMISSION result and a REDIRECT result are different
# claims, and only this one settles the second. If the bind mount is doing the work, the host's
# shared /tmp never sees the file the jailed script wrote to "/tmp".
echo
echo "── ARM 3  REDIRECT CHECK — did the jailed B write reach the HOST's /tmp?"
HOSTHITS=$(ls /tmp 2>/dev/null | grep -c '^B-hardcoded-')
echo "  host /tmp entries matching B-hardcoded-*: $HOSTHITS"
[ "$HOSTHITS" -eq 0 ] && echo "  ⇒ the write was REDIRECTED, not merely permitted" \
                      || echo "  ⇒ the write reached the SHARED host /tmp — the redirect did NOT engage"

echo
echo "══ VERDICT"
echo "  unjailed: $V1"
echo "  jailed{}: $V2"
case "$V2" in
  "A=ALLOW B=ALLOW C=DENY D=DENY")
    echo "  ⇒ CONFIRMED: both temp writes are free under the empty grant, and the two ungranted"
    echo "    controls are refused — so the jail was enforcing while they passed." ;;
  *"C=ALLOW"*|*"D=ALLOW"*)
    echo "  ⛔ A NEGATIVE CONTROL PASSED. The jail let an ungranted write through, so the A/B rows"
    echo "    prove nothing about the temp redirect. Do not read a confirmation off this run." ;;
  *)
    echo "  ⇒ REFUTED or PARTIAL: a temp write was refused at the empty grant. The '$V2' row set is"
    echo "    the finding — a temp write DOES cost a grant on this platform." ;;
esac
