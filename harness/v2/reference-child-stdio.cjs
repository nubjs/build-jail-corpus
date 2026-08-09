'use strict';

const childProcess = require('node:child_process');

const originalSpawn = childProcess.spawn;
childProcess.spawn = function spawnWithDiagnosticCapture(command, args, options) {
  const child = Reflect.apply(originalSpawn, this, arguments);
  setImmediate(() => {
    for (const [name, stream] of [['stdout', child.stdout], ['stderr', child.stderr]]) {
      if (!stream || stream.listenerCount('data') || stream.listenerCount('readable')) continue;
      let announced = false;
      stream.on('data', (chunk) => {
        if (!announced) {
          process.stderr.write(`\nREFERENCE-CHILD-${name.toUpperCase()} ${String(command)}\n`);
          announced = true;
        }
        process.stderr.write(chunk);
      });
    }
  });
  return child;
};
