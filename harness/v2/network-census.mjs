// The driver's own attributed NETWORK census, and the question it answers: did the lifecycle subtree
// actually reach the network, and did anything positively establish that it did not?
//
// ⛔⛔ WHY THIS EXISTS, AND IT IS THE SAME HOLE `write-census.mjs` CLOSES ON A DIFFERENT AXIS.
// `artifact-gate.mjs` decides a drop arm by walking the package's own directory and checking the
// artefacts are there. A network fetch that a WARM CACHE made unnecessary leaves that check
// completely satisfied — every artefact present, `rc=0` — while the capability the script genuinely
// needs on a cold machine has just been proven "unnecessary". The gate cannot see the difference
// between "never needed the network" and "did not need it THIS time".
//
// ⛔ THIS IS NOT HYPOTHETICAL AND IT ALREADY COST A SHIPPED INSTALL. `harness/overrides` carries a
// hand-written entry for `electron` recording exactly this: the generated macOS overlay came out
// `{"write": null, "network": null}`, and in an overlay `null` REMOVES — so on macOS electron got no
// egress at all. Its postinstall downloads its binary from github.com, so `nub install
// electron@33.4.11` on a cold cache exits 1 with `getaddrinfo ENOTFOUND github.com`, reproduced
// twice. That override closes the one case proven to break a real install and says the remaining
// entries "want the same cold-cache re-measurement".
//
// MEASURED on the committed corpus, and this is the shape the census catches:
// `electron-chromedriver@33.4.9` (darwin) recorded TWO real HTTPS connections in its OBSERVE arm —
// `185.199.108.133:443` and `172.182.252.133:443` — and its `VERIFY[nar-no-network]` arm still came
// back `rc=0 artifacts=11/11`. The observe arm says the script went to the network; the drop arm says
// it did not have to. Only one of those was measured on a cold cache.
//
// ⛔ SO THE RULE IS THE MIRROR OF THE HOME-WRITE ONE: a POSITIVE peer count with no CLEAN denial
// witness refuses the drop. It can only ever WITHHOLD — no verdict here licenses a narrowing that
// was not already licensed — so it strengthens the asymmetry rather than relaxing it.
//
// ⛔ A LEAF MODULE, IMPORTING NOTHING, FOR THE REASON `write-census.mjs` SPELLS OUT AT LENGTH. Its
// natural second consumer is `record.mjs`, which applies the rule at MEASUREMENT time — and
// `stale-adjudication.mjs` already imports `parseDriverLog` FROM `record.mjs`, so a census that
// imported anything upward would close a cycle. A cycle here does not throw: these are `const`
// exports, so the importer silently receives `undefined` and the guard is disarmed with no error
// anywhere. Nothing above this file may be imported into it.

// ⛔ THREE SPELLINGS, AND ONLY THE `distinct peers` SUFFIX IS COMMON TO ALL THREE. `observe-macos.mjs`
// prints `AF_INET connects: N   distinct peers: N`, `observe.mjs` `AF_INET sockets: N   distinct
// peers: N`, and `classify.mjs` the bare `distinct peers: N`. Anchoring on the leading token would
// silently return "no census" for a whole platform, which reads as UNKNOWN.
//
// ⛔ AND THE PEER COUNT IS THE FIELD TO READ, NOT THE SOCKET/CONNECT COUNT. MEASURED over the
// corpus: 106 linux logs print `AF_INET sockets: 0   distinct peers: 2` — the socket counter and the
// peer set are populated from different events, and reading the first would score a run that reached
// two hosts as having reached none. That is a false CLEAR, in the under-grant direction.
const NETWORK_HEADER = /^\s*==\s*NETWORK\b/;
const SECTION = /^\s*==\s/;
const PEERS = /\bdistinct peers:\s*(\d+)\b/;

const linesOf = (log) => (Array.isArray(log) ? log : String(log).split(/\r?\n/));

/**
 * Distinct network peers the driver attributed to the lifecycle subtree, or `null` when the log
 * carries no `== NETWORK` block at all.
 *
 * ⛔ A PRESENT BLOCK WITH NO `distinct peers` ROW IS `null`, NOT ZERO — unlike the write census,
 * where an absent bucket inside a present block genuinely means "no members". Here the row is the
 * only thing the block carries, so its absence means the block was not understood rather than that
 * nothing happened, and guessing zero would be a false CLEAR.
 */
export const networkPeers = (log) => {
  let inBlock = false;
  let peers = null;
  for (const l of linesOf(log)) {
    if (NETWORK_HEADER.test(l)) { inBlock = true; continue; }
    if (!inBlock) continue;
    if (SECTION.test(l)) { inBlock = false; continue; }
    const m = PEERS.exec(l);
    if (m) peers = Number(m[1]);
  }
  return peers;
};

export const NET_REFUSE = 'REFUSE';
export const NET_CLEAR = 'CLEAR';
export const NET_UNKNOWN = 'UNKNOWN';

/**
 * May a descent DROP `network` on the strength of this log?
 *
 * Exactly two things license it, and both are positive evidence: a census that RAN and attributed no
 * peer to the subtree, or a `CLEAN` denial witness on the drop arm — a live, jailed,
 * subtree-attributed trace in which the script never asked to connect. `WITNESSED`, `VOID`,
 * `UNSUPPORTED` and absent all mean "not established" and license nothing.
 *
 * ⛔ THE CALLER DECIDES WHAT `UNKNOWN` MEANS, exactly as `homeDropVerdict` leaves that to its two
 * call sites. A live recorder may reasonably treat an absent census as vetoing nothing; a reader
 * re-adjudicating an ARCHIVED log cannot, because it can never go back and run the census.
 *
 * ⛔ A LOOPBACK DNS PEER COUNTS, AND THAT IS THE SAFE DIRECTION RATHER THAN AN OVERSIGHT. A linux log
 * bills `127.0.0.53:53` — systemd-resolved — as a peer, so a run that only resolved a name scores
 * REFUSE here. Refusing costs a record its narrowing; clearing it on a resolver call that preceded a
 * cache hit would cost an install. Splitting loopback out is a change to make with a measurement in
 * hand, not by inspection.
 */
export const networkDropVerdict = ({ log, witness }) => {
  const peers = networkPeers(log);
  if (peers === null) {
    return {
      verdict: NET_UNKNOWN,
      peers: null,
      reason: 'the log carries no `== NETWORK` census, so whether the script reached the network was '
        + 'never established',
    };
  }
  if (peers === 0) {
    return { verdict: NET_CLEAR, peers, reason: 'the census ran and attributed no network peer to the lifecycle subtree' };
  }
  if (witness === 'CLEAN') {
    return {
      verdict: NET_CLEAR,
      peers,
      reason: `OBSERVE attributed ${peers} network peer(s) to the subtree, but the drop arm's own `
        + 'jailed trace shows it never attempted a connection (DENIAL-WITNESS CLEAN)',
    };
  }
  return {
    verdict: NET_REFUSE,
    peers,
    reason: `OBSERVE attributed ${peers} network peer(s) to the lifecycle subtree and no denial witness `
      + 'came back CLEAN, so the passing drop arm is as consistent with a WARM CACHE having satisfied '
      + 'the fetch as with the capability being unnecessary — the artifact gate cannot tell a fetch '
      + 'that did not happen from one that did not need to',
  };
};
