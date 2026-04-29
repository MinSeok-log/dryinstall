'use strict';

const https = require('https');
const zlib = require('zlib');
const tar = require('tar');
const path = require('path');
const logger = require('./logger');

const DANGER_PATTERNS = [
  { pattern: /child_process|exec\s*\(|spawn\s*\(/g,  label: 'child_process execution',  severity: 'CRITICAL' },
  { pattern: /https?\.request|https?\.get|fetch\s*\(/g, label: 'network request',        severity: 'HIGH' },
  { pattern: /fs\.writeFile|fs\.appendFile|fs\.unlink/g, label: 'filesystem write',      severity: 'HIGH' },
  { pattern: /process\.env/g,                          label: 'env variable access',     severity: 'HIGH' },
  { pattern: /require\s*\(\s*['"]child_process['"]\s*\)/g, label: 'child_process import', severity: 'CRITICAL' },
  { pattern: /eval\s*\(|Function\s*\(/g,               label: 'dynamic code execution',  severity: 'CRITICAL' },
  { pattern: /base64|atob|btoa/g,                      label: 'encoding/obfuscation',    severity: 'MED' },
  { pattern: /\.ssh|id_rsa|\.npmrc|\.aws/g,            label: 'credential file access',  severity: 'CRITICAL' },
  { pattern: /curl|wget/g,                             label: 'shell download tool',      severity: 'HIGH' },
  { pattern: /crypto\.createCipher|crypto\.createDecipher/g, label: 'crypto operation', severity: 'MED' },
];

const REGISTRY = 'https://registry.npmjs.org';
const REQUEST_TIMEOUT_MS = 10000;
const MAX_REGISTRY_BYTES = 5 * 1024 * 1024;

function withTimeout(req, reject) {
  req.setTimeout(REQUEST_TIMEOUT_MS, () => {
    req.destroy(new Error(`request timed out after ${REQUEST_TIMEOUT_MS}ms`));
  });
  req.on('error', reject);
  return req;
}

function fetchVersionList(pkgName) {
  return new Promise((resolve, reject) => {
    const encoded = pkgName.startsWith('@')
      ? '@' + pkgName.slice(1).replace('/', '%2F')
      : pkgName;

    const req = https.get(`${REGISTRY}/${encoded}`, { headers: { Accept: 'application/json' } }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`registry returned HTTP ${res.statusCode}`));
        return;
      }

      let data = '';
      let size = 0;
      res.on('data', c => {
        size += c.length;
        if (size > MAX_REGISTRY_BYTES) {
          req.destroy(new Error('registry response too large'));
          return;
        }
        data += c;
      });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ versions: Object.keys(json.versions || {}), distTags: json['dist-tags'] || {}, allMeta: json.versions });
        } catch { reject(new Error('parse error')); }
      });
    });

    withTimeout(req, reject);
  });
}

function shouldSkipEntry(entryPath) {
  const parts = entryPath.split('/').map(part => part.toLowerCase());
  return parts.includes('node_modules') ||
    parts.includes('test') ||
    parts.includes('tests') ||
    parts.includes('__tests__') ||
    parts.includes('spec');
}

function normalizeEntryPath(entryPath) {
  return path.posix.normalize(entryPath).replace(/^[^/]+\//, '');
}

function extractJsFiles(tarballUrl, redirectsLeft = 3) {
  return new Promise((resolve, reject) => {
    const files = new Map();

    const req = https.get(tarballUrl, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        res.resume();
        if (!res.headers.location || redirectsLeft <= 0) {
          reject(new Error('too many tarball redirects'));
          return;
        }
        const nextUrl = new URL(res.headers.location, tarballUrl).toString();
        extractJsFiles(nextUrl, redirectsLeft - 1).then(resolve).catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`tarball returned HTTP ${res.statusCode}`));
        return;
      }

      res.pipe(zlib.createGunzip())
        .pipe(tar.t({
          onentry: (entry) => {
            if (!/\.(js|mjs|cjs)$/.test(entry.path)) { entry.resume(); return; }
            if (shouldSkipEntry(entry.path)) { entry.resume(); return; }
            let content = '';
            entry.on('data', chunk => content += chunk.toString());
            entry.on('end', () => files.set(normalizeEntryPath(entry.path), content));
          }
        }))
        .on('finish', () => resolve(files))
        .on('error', reject);
    });

    withTimeout(req, reject);
  });
}

function parseSemver(version) {
  const match = String(version).trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.+)?$/);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split('.') : [],
  };
}

function compareIdentifiers(a, b) {
  const aNum = /^\d+$/.test(a);
  const bNum = /^\d+$/.test(b);
  if (aNum && bNum) return Number(a) - Number(b);
  if (aNum) return -1;
  if (bNum) return 1;
  return a.localeCompare(b);
}

function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return String(a).localeCompare(String(b));

  for (const key of ['major', 'minor', 'patch']) {
    if (pa[key] !== pb[key]) return pa[key] - pb[key];
  }
  if (pa.prerelease.length === 0 && pb.prerelease.length === 0) return 0;
  if (pa.prerelease.length === 0) return 1;
  if (pb.prerelease.length === 0) return -1;

  const len = Math.max(pa.prerelease.length, pb.prerelease.length);
  for (let i = 0; i < len; i++) {
    if (pa.prerelease[i] === undefined) return -1;
    if (pb.prerelease[i] === undefined) return 1;
    const cmp = compareIdentifiers(pa.prerelease[i], pb.prerelease[i]);
    if (cmp !== 0) return cmp;
  }
  return 0;
}

function findPreviousVersion(versions, currentVersion) {
  return versions
    .filter(v => v !== currentVersion && parseSemver(v) && compareSemver(v, currentVersion) < 0)
    .sort((a, b) => compareSemver(b, a))[0] || null;
}

function analyzePatternDiff(prevFiles, currFiles) {
  const findings = [];
  for (const [filename, currContent] of currFiles) {
    const isNewFile = !prevFiles.has(filename);
    const prevContent = isNewFile ? '' : prevFiles.get(filename);
    for (const { pattern, label, severity } of DANGER_PATTERNS) {
      const prevCount = (prevContent.match(pattern) || []).length;
      const currCount = (currContent.match(pattern) || []).length;
      const added = currCount - prevCount;
      if (added > 0) findings.push({ filename, label, severity, added, prevCount, currCount, isNewFile });
    }
  }
  return findings;
}

async function analyzeVersionDiff(pkgName, currentVersion) {
  logger.verbose(`[dryinstall:diff] Analyzing version diff for: ${pkgName}@${currentVersion}`);

  let versionData;
  try { versionData = await fetchVersionList(pkgName); }
  catch {
    logger.verbose(`[dryinstall:diff] Could not fetch version list — skipping diff`);
    return { skipped: true };
  }

  const prevVersion = findPreviousVersion(versionData.versions, currentVersion);
  if (!prevVersion) {
    logger.verbose(`[dryinstall:diff] No previous version found — first release`);
    return { skipped: true, reason: 'first_release' };
  }

  logger.verbose(`[dryinstall:diff] Comparing: v${prevVersion} → v${currentVersion}`);

  const prevTarball = versionData.allMeta[prevVersion]?.dist?.tarball;
  const currTarball = versionData.allMeta[currentVersion]?.dist?.tarball;
  if (!prevTarball || !currTarball) return { skipped: true, reason: 'no_tarball' };

  let prevFiles, currFiles;
  try {
    [prevFiles, currFiles] = await Promise.all([extractJsFiles(prevTarball), extractJsFiles(currTarball)]);
  } catch (err) {
    logger.verbose(`[dryinstall:diff] Could not extract files: ${err.message}`);
    return { skipped: true, reason: 'extract_error' };
  }

  const findings = analyzePatternDiff(prevFiles, currFiles);
  if (findings.length === 0) {
    logger.verbose(`[dryinstall:diff] No new dangerous patterns detected`);
    return { clean: true, prevVersion, currentVersion };
  }
  return { clean: false, prevVersion, currentVersion, findings };
}

function reportDiff(pkgName, result) {
  if (result.skipped || result.clean) return;
  const criticals = result.findings.filter(f => f.severity === 'CRITICAL');
  const overallSeverity = criticals.length > 0 ? 'CRITICAL' : result.findings.some(f=>f.severity==='HIGH') ? 'HIGH' : 'MED';
  const color = overallSeverity === 'CRITICAL' ? '\x1b[31m' : '\x1b[33m';
  console.log('');
  console.log(`${color}┌──────────────────────────────────────────────────────────┐\x1b[0m`);
  console.log(`${color}│        ⚠  VERSION DIFF — SUSPICIOUS CHANGES DETECTED     │\x1b[0m`);
  console.log(`${color}│  Package  : \x1b[1m${pkgName.padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}│  Severity : \x1b[1m${overallSeverity.padEnd(48)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}└──────────────────────────────────────────────────────────┘\x1b[0m`);
  result.findings.forEach(f => {
    const fc = f.severity==='CRITICAL'?'\x1b[31m':f.severity==='HIGH'?'\x1b[33m':'\x1b[36m';
    console.log(`${fc}  [${f.severity}] ${f.label}${f.isNewFile?' (new file)':''}\x1b[0m`);
    console.log(`\x1b[90m          file: ${f.filename}  +${f.added} added\x1b[0m`);
  });
}

module.exports = { analyzeVersionDiff, reportDiff };
