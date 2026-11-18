#!/usr/bin/env node
const { spawn } = require('child_process');
const os = require('os');
const key = os.platform() + '-' + os.arch();
const ext = os.platform() === 'win32' ? '.exe' : '';
try {
  const bin = require.resolve('@4madeus/' + key + '/bin/4madeus' + ext);
  spawn(bin, process.argv.slice(2), { stdio: 'inherit' }).on('exit', c => process.exit(c ?? 1));
} catch {
  console.error('[4madeus] Binary not found for ' + key + '. Build with: cargo install --git https://github.com/northbluesea/4madeus');
  process.exit(1);
}
