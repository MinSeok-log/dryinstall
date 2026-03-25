'use strict';

const https = require('https');
const crypto = require('crypto');
const logger = require('./logger');

const REGISTRY = 'https://registry.npmjs.org';

function computeTarballHash(tarballUrl) {
  return new Promise((resolve, reject) => {
    https.get(tarballUrl, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        return computeTarballHash(res.headers.location).then(resolve).catch(reject);
      }
      const hash = crypto.createHash('sha512');
      res.on('data', chunk => hash.update(chunk));
      res.on('end', () => resolve(`sha512-${hash.digest('base64')}`));
      res.on('error', reject);
    }).on('error', reject);
  });
}

function parseIntegrity(integrity) {
  if (!integrity) return null;
  const dash = integrity.indexOf('-');
  if (dash < 0) return null;
  return { algo: integrity.slice(0, dash), hash: integrity.slice(dash + 1), full: integrity };
}

async function verifyHash(pkgName, version, tarballUrl, registryIntegrity) {
  logger.verbose(`[dryinstall:hash] Verifying integrity: ${pkgName}@${version}`);

  if (!registryIntegrity) {
    logger.verbose(`[dryinstall:hash] No integrity field — skipping verification`);
    return { verified: null, reason: 'no_integrity' };
  }

  const expected = parseIntegrity(registryIntegrity);
  if (!expected) return { verified: null, reason: 'parse_error' };

  let actual;
  try {
    actual = await computeTarballHash(tarballUrl);
  } catch (err) {
    logger.verbose(`[dryinstall:hash] Could not compute hash: ${err.message}`);
    return { verified: null, reason: 'download_error' };
  }

  const matched = actual === expected.full;
  if (matched) {
    logger.verbose(`[dryinstall:hash] Integrity verified: ${pkgName}@${version}`);
    return { verified: true, expected: expected.full, actual };
  }
  return { verified: false, expected: expected.full, actual, mismatch: true };
}

function reportHashMismatch(pkgName, version, result) {
  if (result.verified !== false) return;
  console.log('');
  console.log(`\x1b[31m┌──────────────────────────────────────────────────────────┐\x1b[0m`);
  console.log(`\x1b[31m│        ✗  INTEGRITY MISMATCH DETECTED                    │\x1b[0m`);
  console.log(`\x1b[31m│  Package  : \x1b[1m${(pkgName+'@'+version).padEnd(47)}\x1b[0m\x1b[31m│\x1b[0m`);
  console.log(`\x1b[31m│  Expected : \x1b[0m${(result.expected||'').slice(0,48).padEnd(48)}\x1b[31m│\x1b[0m`);
  console.log(`\x1b[31m│  Actual   : \x1b[0m${(result.actual||'').slice(0,48).padEnd(48)}\x1b[31m│\x1b[0m`);
  console.log(`\x1b[31m└──────────────────────────────────────────────────────────┘\x1b[0m`);
  console.log(`\x1b[31m  ✗ The tarball content does not match the registry record.\x1b[0m`);
  console.log('');
}

module.exports = { verifyHash, reportHashMismatch };