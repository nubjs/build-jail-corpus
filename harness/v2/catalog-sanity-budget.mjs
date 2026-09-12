// `packages.mjs` serializes fourteen cold arms. Each grants 300s to install and 30s to probe:
// 14 * (300 + 30) = 4,620s. This leaves 3 minutes for process/setup overhead without allowing a
// hung fixture to consume the workflow's entire 210-minute two-subject budget.
export const OVERRIDE_TIMEOUT_MS = 30_000;
export const FIXTURE_TIMEOUT_MS = Object.freeze({
  packages: 4_800_000,
  network: 300_000,
  'relocated-store': 300_000,
});
