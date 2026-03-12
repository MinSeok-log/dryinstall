const path = require('path');
const crypto = require('crypto');

module.exports = {
  greet: (name) => `Hello, ${name}!`,
  hash: (str) => crypto.createHash('sha256').update(str).digest('hex'),
  joinPath: (...args) => path.join(...args),
};