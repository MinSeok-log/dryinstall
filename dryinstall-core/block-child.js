const Module = require('module');
const orig = Module._load;
Module._load = function(request, ...args) {
  if (request === 'child_process') {
    console.log('[sandbox] ✓ child_process BLOCKED');
    return {
      execSync: () => { throw new Error('BLOCKED'); },
      exec: () => { throw new Error('BLOCKED'); },
      spawn: () => { throw new Error('BLOCKED'); },
      spawnSync: () => { throw new Error('BLOCKED'); },
    };
  }
  return orig.call(this, request, ...args);
};
