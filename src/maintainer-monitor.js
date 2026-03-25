'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const logger = require('./logger');

const REGISTRY  = 'https://registry.npmjs.org';
const CACHE_FILE = path.join(os.homedir(), '.dryinstall-maintainers.json');

function loadCache() {
  try { if (fs.existsSync(CACHE_FILE)) return JSON.parse(fs.readFileSync(CACHE_FILE, 'utf-8')); } catch {}
  return {};
}

function saveCache(cache) {
  try { fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2)); } catch {}
}

function fetchPackageMeta(pkgName) {
  return new Promise((resolve) => {
    const encoded = pkgName.startsWith('@') ? '@' + pkgName.slice(1).replace('/', '%2F') : pkgName;
    https.get(`${REGISTRY}/${encoded}`, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
    }).on('error', () => resolve(null));
  });
}

function extractMaintainers(meta, version) {
  if (!meta) return [];
  const vMeta = meta.versions?.[version];
  if (!vMeta) return [];
  return (vMeta.maintainers || []).map(m => m.name || m.email || String(m));
}

function findPreviousVersion(versions, currentVersion) {
  const cur = currentVersion.replace(/[^0-9.]/g, '').split('.').map(Number);
  const sorted = versions.filter(v => v !== currentVersion).sort((a, b) => {
    const pa = a.replace(/[^0-9.]/g,'').split('.').map(Number);
    const pb = b.replace(/[^0-9.]/g,'').split('.').map(Number);
    for (let i=0;i<3;i++) { const d=(pb[i]||0)-(pa[i]||0); if(d!==0) return d; }
    return 0;
  });
  for (const v of sorted) {
    const pv = v.replace(/[^0-9.]/g,'').split('.').map(Number);
    let lower = false;
    for (let i=0;i<3;i++) {
      if((pv[i]||0)<(cur[i]||0)){lower=true;break;}
      if((pv[i]||0)>(cur[i]||0)) break;
    }
    if (lower) return v;
  }
  return null;
}

async function checkMaintainerChange(pkgName, currentVersion) {
  logger.verbose(`[dryinstall:maintainer] Checking maintainer history: ${pkgName}`);

  const meta = await fetchPackageMeta(pkgName);
  if (!meta) {
    logger.verbose(`[dryinstall:maintainer] Could not fetch package metadata`);
    return { skipped: true };
  }

  const versions = Object.keys(meta.versions || {});
  const currentMaintainers = extractMaintainers(meta, currentVersion);
  if (currentMaintainers.length === 0) return { skipped: true, reason: 'no_maintainer_data' };

  const cache = loadCache();
  const cached = cache[pkgName];
  let added = [], removed = [], prevVersion = null, prevMaintainers = [];

  if (cached) {
    prevMaintainers = cached.maintainers || [];
    prevVersion = cached.version;
    added   = currentMaintainers.filter(m => !prevMaintainers.includes(m));
    removed = prevMaintainers.filter(m => !currentMaintainers.includes(m));
  } else {
    prevVersion = findPreviousVersion(versions, currentVersion);
    if (prevVersion) {
      prevMaintainers = extractMaintainers(meta, prevVersion);
      added   = currentMaintainers.filter(m => !prevMaintainers.includes(m));
      removed = prevMaintainers.filter(m => !currentMaintainers.includes(m));
    }
  }

  cache[pkgName] = { version: currentVersion, maintainers: currentMaintainers, updatedAt: new Date().toISOString() };
  saveCache(cache);

  if (added.length === 0 && removed.length === 0) {
    logger.verbose(`[dryinstall:maintainer] No maintainer changes detected`);
    return { clean: true, currentMaintainers };
  }

  const fullTakeover = removed.length > 0 && removed.length === prevMaintainers.length;
  const risk = fullTakeover ? 'CRITICAL' : added.length > 0 ? 'HIGH' : 'MED';
  return { clean: false, risk, fullTakeover, currentMaintainers, prevMaintainers, prevVersion, added, removed };
}

function reportMaintainerChange(pkgName, result) {
  if (result.skipped || result.clean) return;
  const color = result.risk === 'CRITICAL' ? '\x1b[31m' : '\x1b[33m';
  console.log('');
  console.log(`${color}┌──────────────────────────────────────────────────────────┐\x1b[0m`);
  console.log(`${color}│        ⚠  MAINTAINER CHANGE DETECTED                     │\x1b[0m`);
  console.log(`${color}│  Package  : \x1b[1m${pkgName.padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}│  Risk     : \x1b[1m${result.risk.padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}└──────────────────────────────────────────────────────────┘\x1b[0m`);
  if (result.added.length > 0) { console.log(`\x1b[31m  ✗ New maintainers: ${result.added.join(', ')}\x1b[0m`); }
  if (result.removed.length > 0) { console.log(`\x1b[33m  ⚠ Removed: ${result.removed.join(', ')}\x1b[0m`); }
  if (result.fullTakeover) { console.log(`\x1b[31m  ✗ ALL previous maintainers removed — possible account takeover.\x1b[0m`); }
  console.log('');
}

module.exports = { checkMaintainerChange, reportMaintainerChange };