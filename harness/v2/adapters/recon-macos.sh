#!/bin/bash
# Ground truth about the two macOS instruments, harvested in ONE run.
#
# The adapter is written against a schema nobody here could verify locally, because both instruments
# require root and the dev host has no passwordless sudo. So this script does not assume: it drives a
# known set of operations and dumps what each tool ACTUALLY prints, including the two format
# questions that decide whether the adapter is sound at all —
#
#   Q1  Does eslogger carry pid, ppid, the full path, and the open flags? Under which key names?
#   Q2  At what path LENGTH does fs_usage start silently tail-truncating?
#
# Runs as root. Never fails the job on a negative answer — a negative answer is the finding.
set -uo pipefail
OUT="${1:?usage: recon-macos.sh <outdir>}"
mkdir -p "$OUT"
[ "$(id -u)" -eq 0 ] || { echo "recon-macos.sh must run as root"; exit 2; }
REALUSER="${SUDO_USER:-$(stat -f '%Su' /dev/console)}"
echo "recon: root=yes real-user=$REALUSER  SIP=$(csrutil status 2>&1 | tr -d '\n')"

# A workspace OUTSIDE /tmp. /tmp is inside the jail's private-temp redirect, so a fixture there
# cannot test a filesystem claim at all — it has already produced one wrong all-clear.
WORK="$(sudo -u "$REALUSER" mktemp -d "/Users/$REALUSER/recon-XXXXXX")" \
  || WORK="$(mktemp -d "$HOME/recon-XXXXXX")"
echo "recon: work=$WORK"

# ── Q1: eslogger schema ───────────────────────────────────────────────────────────────────────
/usr/bin/eslogger open create unlink rename exec fork > "$OUT/es-raw.json" 2>&1 &
ES=$!
sleep 4    # subscription latency; the sample loop below is the actual proof it was live

sudo -u "$REALUSER" /bin/sh -c "
  echo hello > '$WORK/es-write.txt'
  cat '$WORK/es-write.txt' > /dev/null
  mv '$WORK/es-write.txt' '$WORK/es-renamed.txt'
  rm -f '$WORK/es-renamed.txt'
" > "$OUT/es-driver.log" 2>&1
sleep 3
kill -INT $ES 2>/dev/null; sleep 1; kill -9 $ES 2>/dev/null; wait $ES 2>/dev/null

echo "recon: eslogger lines=$(wc -l < "$OUT/es-raw.json" | tr -d ' ')"
# One pretty sample per event type, plus the flattened key list — the key list is what the adapter's
# extraction must match, so print it explicitly rather than making a human diff two blobs of JSON.
/usr/bin/python3 - "$OUT/es-raw.json" "$OUT/es-schema.txt" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
seen, out = {}, []
for line in open(src, errors='replace'):
    line = line.strip()
    if not line.startswith('{'): continue
    try: r = json.loads(line)
    except Exception: continue
    ev = r.get('event') or {}
    k = next(iter(ev), '?')
    if k in seen: continue
    seen[k] = r
def flat(o, p=''):
    if isinstance(o, dict):
        for k, v in o.items(): yield from flat(v, f'{p}.{k}' if p else k)
    elif isinstance(o, list):
        if o: yield from flat(o[0], p + '[0]')
    else: yield (p, o)
for k, r in seen.items():
    out.append(f'===== EVENT TYPE: {k} =====')
    out.append(json.dumps(r, indent=2)[:4000])
    out.append(f'----- flattened keys for {k} -----')
    for kk, vv in flat(r):
        if any(s in kk for s in ('pid','path','fflag','flag','token','executable','filename','dir')):
            out.append(f'  {kk} = {vv!r}')
    out.append('')
out.append(f'EVENT TYPES SEEN: {sorted(seen)}')
open(dst, 'w').write('\n'.join(out))
print('\n'.join(out)[:6000])
PY

# ── Q2: fs_usage truncation threshold + the sh/zsh exclusion + the refusal format ─────────────
# Build paths of increasing length and see exactly where the printed path stops being absolute.
/usr/bin/fs_usage -w -f filesys -f network > "$OUT/fsu-raw.txt" 2>&1 &
FU=$!
sleep 3

sudo -u "$REALUSER" /bin/sh -c '
  W="$1"
  for n in 40 80 120 160 200 240 300 400; do
    d="$W/len$n"; mkdir -p "$d"
    # pad the LAST component out so the full path length lands near $n
    pad=""; while [ $(( ${#d} + ${#pad} + 6 )) -lt $n ]; do pad="${pad}xxxxx"; done
    f="$d/f${pad}.txt"
    echo t > "$f" 2>/dev/null
    echo "MARK len=$n actual=${#f} $f"
  done
  # a genuine EACCES, and a successful openat near-miss
  echo secret > "$W/denied.txt"; chmod 000 "$W/denied.txt"
  cat "$W/denied.txt" > /dev/null 2>&1; echo "MARK eacces rc=$?"
' _ "$WORK" > "$OUT/fsu-driver.log" 2>&1
sleep 3
kill -INT $FU 2>/dev/null; sleep 1; kill -9 $FU 2>/dev/null; wait $FU 2>/dev/null

echo "recon: fs_usage lines=$(wc -l < "$OUT/fsu-raw.txt" | tr -d ' ')"
{
  echo "##### DRIVER MARKS (expected path lengths) #####"; cat "$OUT/fsu-driver.log"
  echo; echo "##### does fs_usage see a process named sh at all? #####"
  echo "lines whose command is sh:   $(grep -cE '[[:space:]]sh\.[0-9]+[[:space:]]*$' "$OUT/fsu-raw.txt")"
  echo "lines whose command is bash: $(grep -cE '[[:space:]]bash\.[0-9]+[[:space:]]*$' "$OUT/fsu-raw.txt")"
  echo; echo "##### long-path samples (look for a path NOT starting with /) #####"
  grep -E 'len(40|80|120|160|200|240|300|400)' "$OUT/fsu-raw.txt" | head -40
  echo; echo "##### candidate refusal lines (bracketed errno 1/13/30) #####"
  grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+(F=[0-9]+)?[[:space:]]*\[[[:space:]]*(1|13|30)\]' "$OUT/fsu-raw.txt" | head -20
  echo; echo "##### THE NEAR-MISS: openat dirfd rendered [ N]/relpath in the PATHNAME column #####"
  grep -E '\[[0-9]+\]/' "$OUT/fsu-raw.txt" | head -10
  echo; echo "##### network #####"
  grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[[:space:]]+(socket|connect)' "$OUT/fsu-raw.txt" | head -20
} > "$OUT/fsu-analysis.txt" 2>&1
cat "$OUT/fsu-analysis.txt"
rm -rf "$WORK"
echo "recon: done"
