const { sandboxRun } = require('./dryinstall-core.linux-x64-gnu.node');

const result = sandboxRun(
  'node',
  ['/home/vboxuser/dryinstall/test-malicious/index.js'],
  true,
  false,
  false
);

console.log('Result:', result);
