import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const helper = path.join(import.meta.dirname, 'macos-verify.sh');
const posix = process.platform !== 'win32';

for (const [install, approve, expected] of [[0, 0, 0], [23, 0, 1], [0, 31, 1], [23, 31, 1]]) {
  test(`macOS verifier preserves install=${install} and approve=${approve}`, { skip: !posix }, () => {
    const arm = fs.mkdtempSync(path.join(os.tmpdir(), 'macos-verify-'));
    try {
      const nub = path.join(arm, 'nub');
      fs.writeFileSync(nub, `#!/bin/bash
if [ "$1" = install ]; then echo install; exit ${install}; fi
if [ "$1" = approve-builds ]; then echo approve; exit ${approve}; fi
exit 99
`, { mode: 0o755 });

      const result = spawnSync('/bin/bash', [helper, arm, nub], { encoding: 'utf8' });
      assert.equal(result.status, expected);
      assert.equal(fs.readFileSync(path.join(arm, 'i.log'), 'utf8').trim(), 'install');
      assert.equal(fs.readFileSync(path.join(arm, 'a.log'), 'utf8').trim(), 'approve');
      assert.equal(fs.readFileSync(path.join(arm, 'verify-status'), 'utf8'),
        `install=${install} approve=${approve}\n`);
    } finally {
      fs.rmSync(arm, { recursive: true, force: true });
    }
  });
}
