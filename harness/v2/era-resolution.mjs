// The OTHER half of an era, and without it the era Node pin measures a runtime nobody ever ran.
//
// ⛔ THE FINDING THIS EXISTS FOR. Pinning the Node does not recreate the era, because the dependency
// TREE is still resolved fresh from today's registry. Measured on Node 4.9.1:
//
//   optipng-bin@0.2.6 -> mocha -> debug@4.4.3   `let` outside strict  -> SyntaxError
//   electron-chromedriver@0.33.4 -> request -> tough-cookie -> psl@1.15.0  spread -> SyntaxError
//
// Neither is the package, the registry or TLS — all three were tested and refuted. They are MODERN
// transitive dependencies that an old Node cannot parse.
//
// ⛔ AND `primordials is not defined` IS THE SAME MECHANISM IN REVERSE — an exactly-pinned OLD
// dependency (`graceful-fs@3.0.12`) on a NEW Node. That is why the measurements show a working BAND
// rather than a floor: without dated resolution the Node must be new enough to PARSE today's
// transitive deps and old enough to still provide what the pinned old ones expect, and for the
// 37-record primordials class that band is exactly 6-10.
//
// With dated resolution the band problem disappears, because both ends move together. MEASURED:
// `electron-chromedriver@0.33.4` on Node 4.9.1 is rc=1 (SyntaxError) with today's tree and rc=0 with
// `--before=2015-10-12`.
//
// ⛔ RESOLVE WITH A MODERN npm, EXECUTE WITH THE ERA NODE. `--before` needs npm >= 6.9, which the era
// Node does not ship — and does not need to. Splitting resolution from execution maps exactly onto
// the corpus's existing two-step shape (`npm install --ignore-scripts`, then `npm rebuild`).

/** Milliseconds added to a publish timestamp when forming `--before`.
 *
 *  ⛔ WITHOUT THIS THE TARGET PACKAGE EXCLUDES ITSELF, and the error does not look like an off-by-one.
 *  `--before=2015-10-11` for a package published 2015-10-11T21:02:00Z returns
 *  `npm error code ETARGET / No matching version found for electron-chromedriver@0.33.4 with a date
 *  before 10/10/2015, 5:00:00 PM` — npm floors a bare date to local midnight, which lands BEFORE the
 *  publish instant. A full day is used rather than a second because the floor is applied in the
 *  RUNNER's timezone, which the harness does not control. */
export const PUBLISH_MARGIN_MS = 24 * 60 * 60 * 1000;

/** The `--before` value for a package published at `publishedAt`, or null when there is no usable date.
 *
 *  Returns a full ISO instant rather than a bare date so npm has nothing left to floor. */
export function beforeFor(publishedAt) {
  const t = publishedAt ? Date.parse(publishedAt) : NaN;
  if (!Number.isFinite(t)) return null;
  return new Date(t + PUBLISH_MARGIN_MS).toISOString();
}

/** The fetch arguments for an observe arm.
 *
 *  ⛔ THE RECORD MUST SAY WHETHER RESOLUTION WAS DATED, because it changes what the measurement MEANS:
 *  a dated tree describes the install the package's author shipped against, not the one a user gets
 *  today. Both are worth measuring and they are not the same thing, so an undeclared choice between
 *  them is the invisible normalisation this harness keeps paying for. */
export function fetchArgs({ spec, publishedAt, dated = true }) {
  const before = dated ? beforeFor(publishedAt) : null;
  return {
    args: ['install', '--no-audit', '--no-fund', '--ignore-scripts',
      ...(before ? [`--before=${before}`] : []), spec],
    before,
    marker: before
      ? `ERA-RESOLUTION DATED ${before} (deps as of the package's own publish date + 1d)`
      : `ERA-RESOLUTION UNDATED (${publishedAt ? 'disabled' : 'no usable publish date'}) — the tree is TODAY's`,
  };
}

// CLI, for the two shell drivers. They already hold `NODE_SELECTION` from `era-node.mjs`, which
// carries `publishedAt` — so this takes that JSON on stdin rather than re-querying the registry.
// A second lookup would be a second answer, which is how the era pin and the record came to
// disagree once already.
//
//   usage: printf '%s' "$NODE_SELECTION" | node era-resolution.mjs --spec <pkg@ver> [--undated]
//   stdout: line 1 = the `--before=…` argument (EMPTY when undated), line 2 = the marker
if (import.meta.filename === process.argv[1]) {
  const arg = (n) => { const i = process.argv.indexOf(`--${n}`); return i === -1 ? undefined : process.argv[i + 1]; };
  const spec = arg('spec');
  if (!spec) { process.stderr.write('usage: era-resolution.mjs --spec <pkg@version> [--undated] < NODE_SELECTION\n'); process.exit(2); }
  let raw = ''; for await (const chunk of process.stdin) raw += chunk;
  let publishedAt = null;
  try { publishedAt = JSON.parse(raw).publishedAt ?? null; } catch { /* stays null; the marker says so */ }
  const r = fetchArgs({ spec, publishedAt, dated: !process.argv.includes('--undated') });
  process.stdout.write(`${r.before ? `--before=${r.before}` : ''}\n${r.marker}\n`);
}
