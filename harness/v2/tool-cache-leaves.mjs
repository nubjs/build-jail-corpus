// The read-write leaves nub carves out of its OWN tool cache, named once for every reader.
//
// ⛔⛔ WHY THIS IS A MODULE RATHER THAN THREE ARRAY LITERALS. The list has already grown once — from
// `npm-prefix` alone to all three — and that growth is the defect this file exists to make
// un-repeatable. `preset.rs` `push_rw_path`s the three in ONE loop with no `cfg`, so a confined
// script gets every one of them for free on every platform; a reader that knows about fewer bills a
// FREE write as a real-home write and synthesizes `write.userHome`, which is authority over the
// whole user home, to reach a directory the jail created for the package and pointed it at.
//
// MEASURED, and the number is why the list is shared rather than copied: at the point the third leaf
// landed (`0492dce58`), 72 committed records — 28 darwin, 44 linux — carried a positive `userHome`
// census whose every listed path was inside `electron-cache`. Not one of them needed the home. The
// carve-out was one third done for the whole of that era because the leaf names lived in two array
// literals that had to be edited together and were not.
//
// ⛔ THIS FILE IMPORTS NOTHING, DELIBERATELY. Its readers include `write-census.mjs`, which sits
// below `record.mjs` and `stale-adjudication.mjs` precisely to stay out of an import cycle — and a
// cycle there does not throw, it hands the importer `undefined` and disarms a guard silently. A leaf
// with no imports of its own cannot re-introduce one.
//
// ⛔ THE SCOPE IS THE LEAVES AND NEVER `tools` ITSELF, and that is a security boundary rather than
// tidiness. `tools` also holds the node-gyp bootstraps nub installs for its own use and executes on
// every later install, so a write grant spanning the directory would let one package's lifecycle
// script replace a binary every subsequent install then runs. `preset.rs` states the same rule at
// the same place. Adding a leaf here is safe; widening to the parent is not.

/** The leaf NAMES, which are nub's constants. The PARENT is always a declared venue root — never a
 *  hardcoded `~/.cache/nub` pattern, which is what portability rule R2 forbids. */
export const TOOL_CACHE_LEAVES = ['npm-prefix', 'ms-playwright', 'electron-cache'];

/**
 * The absolute read-write leaf paths for one venue, from that venue's DECLARED roots.
 *
 * ⛔ NULL-SAFE ON BOTH ROOTS, because `null` is a capture ANSWERING that this venue has no such root
 * rather than a capture failing to say. The correct response is an empty contribution, never a throw
 * and never a path built from the string "null". Callers that care about the difference between "no
 * carve-out because there is no root" and "no carve-out because nobody asked" should say so in their
 * own log; `observe.mjs` and `observe-macos.mjs` both do.
 *
 * ⛔ `npmPrefix` IS UNIONED IN RATHER THAN REPLACED, AND THE REDUNDANCY IS DELIBERATE. Both POSIX
 * drivers declare `npmPrefix` as `${toolsDir}/npm-prefix`, so the derived set already covers it —
 * but a capture that declares `npmPrefix` while leaving `toolsDir` null would otherwise silently
 * LOSE the carve-out it used to have, and losing a carve-out bills a free write, which is the
 * over-grant this whole module exists to stop. Keeping both cannot widen past what the jail grants:
 * every member is a path `push_rw_path` covers.
 */
export const toolCacheRw = ({ toolsDir = null, npmPrefix = null } = {}) => [
  ...(toolsDir ? TOOL_CACHE_LEAVES.map((l) => `${toolsDir}/${l}`) : []),
  ...(npmPrefix ? [npmPrefix] : []),
];
