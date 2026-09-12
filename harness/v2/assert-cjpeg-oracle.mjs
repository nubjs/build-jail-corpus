import fs from 'node:fs';

const [reportPath] = process.argv.slice(2);
if (!reportPath) throw new Error('usage: assert-cjpeg-oracle.mjs <falsify.json>');

const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
const arms = report.results?.[0]?.arms ?? [];
const labels = arms.map((arm) => arm.label);
const expected = ['wrong-cold', 'right', 'wrong-warm'];
if (labels.join(',') !== expected.join(',')) {
  throw new Error(`expected ${expected.join(',')}; got ${labels.join(',') || '<none>'}`);
}
for (const arm of arms) {
  if (!Array.isArray(arm.cjpegOracle) || arm.cjpegOracle.length !== 1) {
    throw new Error(`expected one cjpeg oracle record for ${arm.label}`);
  }
}
