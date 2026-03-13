'use strict';

const https = require('https');
const crypto = require('crypto');
const zlib = require('zlib');
const tar = require('tar');
const path = require('path');
const fs = require('fs');
const os = require('os');

/**
 * Version Diff Analyzer — 버전 간 코드 변경사항 분석
 *
 * 공격 시나리오:
 *   lib v1.0.1 → 정상
 *   lib v1.0.2 → 악성 코드 추가 (version poisoning)
 *   lib v1.0.3 → 정상 (탐지 회피)
 *
 * 탐지 방법:
 *   이전 버전과 현재 버전의 JS 파일을 비교
 *   위험 패턴이 새로 추가됐으면 경고
 */

// ── 위험 패턴 정의 ──────────────────────────────────────
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

/**
 * registry에서 버전 목록 조회
 */
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
          const versions = Object.keys(json.versions || {});
          const distTags = json['dist-tags'] || {};
          resolve({ versions, distTags, allMeta: json.versions });
        } catch { reject(new Error('parse error')); }
      });
    }).on('error', reject);
  });
}

/**
 * tarball 다운로드 후 JS 파일 추출
 * @returns {Map<filename, content>}
 */
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
            // JS 파일만 분석
            if (!/\.(js|mjs|cjs)$/.test(entry.path)) {
              entry.resume();
              return;
            }
            // node_modules 내부, 테스트 파일 제외
            if (entry.path.includes('node_modules') ||
                entry.path.includes('test') ||
                entry.path.includes('spec')) {
              entry.resume();
              return;
            }

            let content = '';
            entry.on('data', chunk => content += chunk.toString());
            entry.on('end', () => {
              // package/ 접두사 제거
              const cleanPath = entry.path.replace(/^[^/]+\//, '');
              files.set(cleanPath, content);
            });
          }
        }))
        .on('finish', () => {
          try { fs.rmSync(tmpDir, { recursive: true }); } catch {}
          resolve(files);
        })
        .on('error', reject);
    }).on('error', reject);
  });
}

/**
 * 이전 버전 찾기 (semver 기준 직전 버전)
 */
function findPreviousVersion(versions, currentVersion) {
  const sorted = versions
    .filter(v => v !== currentVersion)
    .sort((a, b) => {
      const pa = a.replace(/[^0-9.]/g, '').split('.').map(Number);
      const pb = b.replace(/[^0-9.]/g, '').split('.').map(Number);
      for (let i = 0; i < 3; i++) {
        const d = (pb[i] || 0) - (pa[i] || 0);
        if (d !== 0) return d;
      }
      return 0;
    });

  // 현재 버전보다 낮은 것 중 가장 가까운 버전
  const cur = currentVersion.replace(/[^0-9.]/g, '').split('.').map(Number);
  for (const v of sorted) {
    const pv = v.replace(/[^0-9.]/g, '').split('.').map(Number);
    let lower = false;
    for (let i = 0; i < 3; i++) {
      if ((pv[i] || 0) < (cur[i] || 0)) { lower = true; break; }
      if ((pv[i] || 0) > (cur[i] || 0)) break;
    }
    if (lower) return v;
  }
  return null;
}

/**
 * 두 파일 집합 간 위험 패턴 diff 분석
 */
function analyzePatternDiff(prevFiles, currFiles) {
  const findings = [];

  for (const [filename, currContent] of currFiles) {
    const prevContent = prevFiles.get(filename) || '';

    for (const { pattern, label, severity } of DANGER_PATTERNS) {
      const prevMatches = (prevContent.match(pattern) || []).length;
      const currMatches = (currContent.match(pattern) || []).length;
      const added = currMatches - prevMatches;

      if (added > 0) {
        // 새로 추가된 위험 패턴
        findings.push({ filename, label, severity, added, prevCount: prevMatches, currCount: currMatches });
      }
    }
  }

  // 이전 버전에 없던 새 파일에서 발견된 패턴
  for (const [filename, currContent] of currFiles) {
    if (prevFiles.has(filename)) continue;
    for (const { pattern, label, severity } of DANGER_PATTERNS) {
      const matches = (currContent.match(pattern) || []).length;
      if (matches > 0) {
        findings.push({ filename, label, severity, added: matches, prevCount: 0, currCount: matches, isNewFile: true });
      }
    }
  }

  return findings;
}

/**
 * 메인 분석 함수
 */
async function analyzeVersionDiff(pkgName, currentVersion) {
  console.log(`\x1b[36m[dryinstall:diff] Analyzing version diff for: ${pkgName}@${currentVersion}\x1b[0m`);

  let versionData;
  try {
    versionData = await fetchVersionList(pkgName);
  } catch {
    console.log(`\x1b[33m[dryinstall:diff] ⚠ Could not fetch version list — skipping diff\x1b[0m`);
    return { skipped: true };
  }

  const prevVersion = findPreviousVersion(versionData.versions, currentVersion);
  if (!prevVersion) {
    console.log(`\x1b[32m[dryinstall:diff] ✓ No previous version found — first release\x1b[0m`);
    return { skipped: true, reason: 'first_release' };
  }

  console.log(`\x1b[36m[dryinstall:diff] Comparing: v${prevVersion} → v${currentVersion}\x1b[0m`);

  const prevTarball = versionData.allMeta[prevVersion]?.dist?.tarball;
  const currTarball = versionData.allMeta[currentVersion]?.dist?.tarball;

  if (!prevTarball || !currTarball) {
    return { skipped: true, reason: 'no_tarball' };
  }

  let prevFiles, currFiles;
  try {
    [prevFiles, currFiles] = await Promise.all([
      extractJsFiles(prevTarball),
      extractJsFiles(currTarball),
    ]);
  } catch (err) {
    console.log(`\x1b[33m[dryinstall:diff] ⚠ Could not extract files: ${err.message}\x1b[0m`);
    return { skipped: true, reason: 'extract_error' };
  }

  const findings = analyzePatternDiff(prevFiles, currFiles);

  if (findings.length === 0) {
    console.log(`\x1b[32m[dryinstall:diff] ✓ No new dangerous patterns detected\x1b[0m`);
    return { clean: true, prevVersion, currentVersion };
  }

  return { clean: false, prevVersion, currentVersion, findings };
}

/**
 * diff 결과 출력
 */
function reportDiff(pkgName, result) {
  if (result.skipped || result.clean) return;

  const criticals = result.findings.filter(f => f.severity === 'CRITICAL');
  const highs     = result.findings.filter(f => f.severity === 'HIGH');
  const meds      = result.findings.filter(f => f.severity === 'MED');

  const overallSeverity = criticals.length > 0 ? 'CRITICAL' : highs.length > 0 ? 'HIGH' : 'MED';
  const color = overallSeverity === 'CRITICAL' ? '\x1b[31m' : '\x1b[33m';

  console.log('');
  console.log(`${color}┌──────────────────────────────────────────────────────────┐\x1b[0m`);
  console.log(`${color}│        ⚠  VERSION DIFF — SUSPICIOUS CHANGES DETECTED     │\x1b[0m`);
  console.log(`${color}├──────────────────────────────────────────────────────────┤\x1b[0m`);
  console.log(`${color}│  Package  : \x1b[1m${pkgName.padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}│  Change   : \x1b[0mv${result.prevVersion} → v${result.currentVersion}${''.padEnd(Math.max(0, 46 - result.prevVersion.length - result.currentVersion.length - 4))}${color}│\x1b[0m`);
  console.log(`${color}│  Severity : \x1b[1m${overallSeverity.padEnd(48)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}└──────────────────────────────────────────────────────────┘\x1b[0m`);
  console.log('');

  result.findings.forEach(f => {
    const fc = f.severity === 'CRITICAL' ? '\x1b[31m' : f.severity === 'HIGH' ? '\x1b[33m' : '\x1b[36m';
    const newFile = f.isNewFile ? ' (new file)' : '';
    console.log(`${fc}  [${f.severity}] ${f.label}${newFile}\x1b[0m`);
    console.log(`\x1b[90m          file   : ${f.filename}\x1b[0m`);
    console.log(`\x1b[90m          before : ${f.prevCount} occurrence(s)\x1b[0m`);
    console.log(`\x1b[90m          after  : ${f.currCount} occurrence(s)  (+${f.added} added)\x1b[0m`);
  });
  console.log('');

  if (overallSeverity === 'CRITICAL') {
    console.log(`\x1b[31m  ✗ Critical patterns were added in this version update.\x1b[0m`);
    console.log(`\x1b[31m    This may be a Version Poisoning attack.\x1b[0m`);
  } else {
    console.log(`\x1b[33m  ⚠ Suspicious patterns were added in this version update.\x1b[0m`);
    console.log(`\x1b[33m    Review carefully before proceeding.\x1b[0m`);
  }
  console.log('');
}

module.exports = { analyzeVersionDiff, reportDiff };
