// Fetch the small, version-independent registry facts a record needs to remain collatable later.
// The production population manifest will eventually be the authority for demand weights, but a
// measurement cannot safely become a catalog default without knowing what `latest` meant when it
// ran. Both endpoints are deliberately narrow; fetching a package's full packument for every row
// makes old, high-churn packages needlessly expensive.

const json = async (url, fetchImpl) => {
  const response = await fetchImpl(url, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
  return response.json();
};

export async function fetchPackageStanding(pkg, {
  fetchImpl = globalThis.fetch,
  now = Date.now(),
} = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('no fetch implementation is available');
  const encoded = encodeURIComponent(pkg);
  const distTagsUrl = `https://registry.npmjs.org/-/package/${encoded}/dist-tags`;
  const downloadsUrl = `https://api.npmjs.org/downloads/point/last-week/${encoded}`;
  const [tags, downloads] = await Promise.all([
    json(distTagsUrl, fetchImpl),
    json(downloadsUrl, fetchImpl),
  ]);
  if (typeof tags?.latest !== 'string' || !tags.latest) {
    throw new Error(`${pkg} registry metadata has no latest dist-tag`);
  }
  if (!Number.isSafeInteger(downloads?.downloads) || downloads.downloads < 0) {
    throw new Error(`${pkg} download metadata has no non-negative weekly count`);
  }
  return {
    observedAt: new Date(now).toISOString(),
    latestVersion: tags.latest,
    weeklyDownloads: downloads.downloads,
    sources: { distTags: distTagsUrl, weeklyDownloads: downloadsUrl },
  };
}
