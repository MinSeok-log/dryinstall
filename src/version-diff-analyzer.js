'use strict';

const https = require('https');
const zlib = require('zlib');
const tar = require('tar');
const path = require('path');
const fs = require('fs');
const os = require('os');
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

function fetchVersionList(pkgName) {
  return new Promise((resolve, reject) => {
    const encoded = pkgName.startsWith('@')
      ? '@' + pkgName.slice(1).replace('/', '%2F')
      : pkgName;

    https.get(`${REGISTRY}/${encoded}`, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ versions: Object.keys(json.versions || {}), distTags: json['dist-tags'] || {}, allMeta: json.versions });
        } catch { reject(new Error('parse error')); }
      });
    }).on('error', reject);
  });
}

function extractJsFiles(tarballUrl) {
  return new Promise((resolve, reject) => {
    const files = new Map();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dryinstall-diff-'));

    https.get(tarballUrl, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        return extractJsFiles(res.headers.location).then(resolve).catch(reject);
      }
      res.pipe(zlib.createGunzip())
        .pipe(tar.t({
          onentry: (entry) => {
            if (!/\.(js|mjs|cjs)$/.test(entry.path)) { entry.resume(); return; }
            if (entry.path.includes('node_modules') || entry.path.includes('test') || entry.path.includes('spec')) { entry.resume(); return; }
            let content = '';
            entry.on('data', chunk => content += chunk.toString());
            entry.on('end', () => files.set(entry.path.replace(/^[^/]+\//, ''), content));
          }
        }))
        .on('finish', () => { try { fs.rmSync(tmpDir, { recursive: true }); } catch {} resolve(files); })
        .on('error', reject);
    }).on('error', reject);
  });
}

function findPreviousVersion(versions, currentVersion) {
  const cur = currentVersion.replace(/[^0-9.]/g, '').split('.').map(Number);
  const sorted = versions.filter(v => v !== currentVersion).sort((a, b) => {
    const pa = a.replace(/[^0-9.]/g, '').split('.').map(Number);
    const pb = b.replace(/[^0-9.]/g, '').split('.').map(Number);
    for (let i = 0; i < 3; i++) { const d = (pb[i]||0)-(pa[i]||0); if (d!==0) return d; }
    return 0;
  });
  for (const v of sorted) {
    const pv = v.replace(/[^0-9.]/g, '').split('.').map(Number);
    let lower = false;
    for (let i = 0; i < 3; i++) {
      if ((pv[i]||0) < (cur[i]||0)) { lower = true; break; }
      if ((pv[i]||0) > (cur[i]||0)) break;
    }
    if (lower) return v;
  }
  return null;
}

function analyzePatternDiff(prevFiles, currFiles) {
  const findings = [];
  for (const [filename, currContent] of currFiles) {
    const prevContent = prevFiles.get(filename) || '';
    for (const { pattern, label, severity } of DANGER_PATTERNS) {
      const added = (currContent.match(pattern)||[]).length - (prevContent.match(pattern)||[]).length;
      if (added > 0) findings.push({ filename, label, severity, added, prevCount: (prevContent.match(pattern)||[]).length, currCount: (currContent.match(pattern)||[]).length });
    }
  }
  for (const [filename, currContent] of currFiles) {
    if (prevFiles.has(filename)) continue;
    for (const { pattern, label, severity } of DANGER_PATTERNS) {
      const matches = (currContent.match(pattern)||[]).length;
      if (matches > 0) findings.push({ filename, label, severity, added: matches, prevCount: 0, currCount: matches, isNewFile: true });
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