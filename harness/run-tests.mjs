#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const roots = process.argv.slice(2);
if (roots.length === 0) roots.push('harness');

const tests = [];
const visit = (entry) => {
  const stat = fs.statSync(entry);
  if (!stat.isDirectory()) {
    if (entry.endsWith('.test.mjs')) tests.push(entry);
    return;
  }

  for (const child of fs.readdirSync(entry, { withFileTypes: true })) {
    const childPath = path.join(entry, child.name);
    if (child.isDirectory()) visit(childPath);
    else if (child.isFile() && child.name.endsWith('.test.mjs')) tests.push(childPath);
  }
};

for (const root of roots) visit(root);
tests.sort();

if (tests.length === 0) {
  console.error(`no harness tests discovered under: ${roots.join(', ')}`);
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...tests], { stdio: 'inherit' });
if (result.error) {
  console.error(`could not launch the harness test suite: ${result.error.message}`);
  process.exit(1);
}
if (result.signal) {
  console.error(`the harness test suite was terminated by ${result.signal}`);
  process.exit(1);
}
process.exit(result.status ?? 1);
