import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  DEFAULT_REFERENCE_PROFILE,
  loadReferenceProfile,
  referenceHostCommands,
  referenceHostToolchainCommands,
  referenceHostToolchainEnvironment,
} from './reference-profile.mjs';

export function provisionReferenceHost(profile, platform = process.platform, execute = spawnSync) {
  const packageCommands = referenceHostCommands(profile, platform);
  for (const [command, ...args] of packageCommands) {
    const result = execute(command, args, { stdio: 'inherit', env: process.env });
    if (result.error || result.status !== 0) {
      throw new Error(`reference profile host command failed: ${[command, ...args].join(' ')} `
        + `(${result.error?.message ?? `exit ${result.status}`})`);
    }
  }
  const toolchainEnv = { ...process.env, ...referenceHostToolchainEnvironment(profile, platform) };
  if (toolchainEnv.RUSTUP_HOME) fs.mkdirSync(toolchainEnv.RUSTUP_HOME, { recursive: true });
  const toolchainCommands = referenceHostToolchainCommands(profile, platform);
  for (const [command, ...args] of toolchainCommands) {
    const result = execute(command, args, { stdio: 'inherit', env: toolchainEnv });
    if (result.error || result.status !== 0) {
      throw new Error(`reference profile host command failed: ${[command, ...args].join(' ')} `
        + `(${result.error?.message ?? `exit ${result.status}`})`);
    }
  }
  return [...packageCommands, ...toolchainCommands];
}

const parseArgs = (argv) => {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (!['--profile', '--platform'].includes(argv[i]) || argv[i + 1] == null) {
      throw new Error(`unknown or incomplete option ${argv[i]}`);
    }
    options[argv[i].slice(2)] = argv[++i];
  }
  return options;
};

function cli(argv) {
  const options = parseArgs(argv);
  const file = path.resolve(options.profile ?? DEFAULT_REFERENCE_PROFILE);
  const profile = loadReferenceProfile(file);
  const platform = options.platform ?? process.platform;
  const commands = provisionReferenceHost(profile, platform);
  console.log(`REFERENCE-PROFILE-HOST ${profile.id} ${platform} ${commands.length} command(s)`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { cli(process.argv.slice(2)); }
  catch (error) { console.error(`REFERENCE-PROFILE-HOST-ERROR ${error.message}`); process.exitCode = 2; }
}
