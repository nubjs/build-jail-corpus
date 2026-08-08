import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fetchPackageStanding } from './package-standing.mjs';

test('package standing records a dated latest tag and demand weight from narrow endpoints', async () => {
  const seen = [];
  const fetchImpl = async (url) => {
    seen.push(url);
    return {
      ok: true,
      json: async () => url.includes('dist-tags') ? { latest: '2.0.0' } : { downloads: 123_456 },
    };
  };
  const standing = await fetchPackageStanding('@scope/demo', {
    fetchImpl, now: Date.parse('2026-08-08T00:00:00.000Z'),
  });
  assert.deepEqual(standing, {
    observedAt: '2026-08-08T00:00:00.000Z',
    latestVersion: '2.0.0',
    weeklyDownloads: 123_456,
    sources: {
      distTags: 'https://registry.npmjs.org/-/package/%40scope%2Fdemo/dist-tags',
      weeklyDownloads: 'https://api.npmjs.org/downloads/point/last-week/%40scope%2Fdemo',
    },
  });
  assert.equal(seen.length, 2);
});

test('package standing fails closed when latest or the demand weight is missing', async () => {
  const result = (tags, downloads) => fetchPackageStanding('demo', {
    fetchImpl: async (url) => ({
      ok: true,
      json: async () => url.includes('dist-tags') ? tags : downloads,
    }),
  });
  await assert.rejects(result({}, { downloads: 1 }), /latest dist-tag/);
  await assert.rejects(result({ latest: '1.0.0' }, {}), /weekly count/);
});
