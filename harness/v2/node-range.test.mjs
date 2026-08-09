import assert from 'node:assert/strict';
import { test } from 'node:test';
import { satisfiesNodeRange } from './node-range.mjs';

test('common Node engine range forms are evaluated without treating unknown syntax as compatible', () => {
  const cases = [
    ['v18.20.8', '>=18.19.0', true],
    ['18.18.2', '>=18.19.0', false],
    ['22.23.2', '^18.17.0 || >=20.5.0', true],
    ['19.9.0', '^18.17.0 || >=20.5.0', false],
    ['14.21.3', '14 || 16 || 18', true],
    ['15.14.0', '14 || 16 || 18', false],
    ['20.20.2', '>=18 <21', true],
    ['21.7.3', '>=18 <21', false],
    ['18.19.9', '18.19.x', true],
    ['18.20.8', '18.19.x', false],
    ['20.20.2', '<=20', true],
    ['21.0.0', '<=20', false],
    ['20.20.2', '>20', false],
    ['21.0.0', '>20', true],
    ['18.20.8', '=18', true],
    ['18.18.2', '18.19.x', false],
    ['16.20.2', '14.0.0 - 16.20.2', true],
    ['17.0.0', '14.0.0 - 16.20.2', false],
    ['20.20.2', '18 - 20', true],
    ['21.7.3', '18 - 20', false],
    ['20.20.2', '18.19 - 20.20', true],
    ['21.0.0', '18.19 - 20.20', false],
    ['0.10.48', '>= 0.8.0 && < 0.11.0', true],
    ['22.23.2', '>= 0.8.0 && < 0.11.0', false],
    ['0.2.5', '^0.2.3', true],
    ['0.3.0', '^0.2.3', false],
    ['18.20.8', 'workspace:*', null],
    ['18.20.8', '<18 || workspace:*', null],
  ];
  for (const [version, range, expected] of cases) {
    assert.equal(satisfiesNodeRange(version, range), expected, `${version} ${range}`);
  }
});
