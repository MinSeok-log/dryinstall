'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Maintainer Monitor — 메인테이너 변경 감지
 *
 * 공격 시나리오 (Maintainer Account Takeover):
 *   1. 공격자가 기존 메인테이너 계정 탈취
 *   2. 정상 패키지에 악성코드 삽입하여 새 버전 배포
 *   3. 개발자는 공식 패키지로 믿고 업데이트
 *
 *   실제 사례:
 *   - ua-parser-js (2021) — 메인테이너 계정 탈취 후 악성 버전 배포
 *   - coa (2021) — 동일 패턴
 *   - event-stream (2018) — 새 메인테이너에게 권한 이전 후 악성코드
 *
 * 탐지 방법:
 *   1. 현재 버전 메인테이너 vs 이전 버전 메인테이너 비교
 *   2. 새로 추가된 메인테이너 경고
 *   3. 로컬 캐시(.dryinstall-maintainers.json)에 기록 → 다음 설치 시 비교
 *   4. 메인테이너 수가 급격히 변하면 경고
 */

const REGISTRY = 'https://registry.npmjs.org';
const CACHE_FILE = path.join(os.homedir(), '.dryinstall-maintainers.json');

/**
 * 메인테이너 캐시 로드
 */
function loadCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      return JSON.parse(fs.readFileSync(CACHE_FILE, 'utf-8'));
    }
  } catch {}
  return {};
}

/**
 * 메인테이너 캐시 저장
 */
function saveCache(cache) {
  try {
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2));
  } catch {}
}

/**
 * npm registry에서 패키지 전체 메타 조회
 */
function fetchPackageMeta(pkgName) {
  return new Promise((resolve, reject) => {
    const encoded = pkgName.startsWith('@')
      ? '@' + pkgName.slice(1).replace('/', '%2F')
      : pkgName;

    https.get(`${REGISTRY}/${encoded}`, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode === 404) return resolve(null);
        try { resolve(JSON.parse(data)); }
        catch { resolve(null); }
      });
    }).on('error', () => resolve(null));
  });
}

/**
 * 버전별 메인테이너 추출
 */
function extractMaintainers(meta, version) {
  if (!meta) return [];
  const vMeta = meta.versions?.[version];
  if (!vMeta) return [];
  return (vMeta.maintainers || []).map(m => m.name || m.email || String(m));
}

/**
 * 이전 버전 찾기
 */
function findPreviousVersion(versions, currentVersion) {
  const cur = currentVersion.replace(/[^0-9.]/g, '').split('.').map(Number);
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
 * 메인 탐지 함수
 */
async function checkMaintainerChange(pkgName, currentVersion) {
  console.log(`\x1b[36m[dryinstall:maintainer] Checking maintainer history: ${pkgName}\x1b[0m`);

  const meta = await fetchPackageMeta(pkgName);
  if (!meta) {
    console.log(`\x1b[33m[dryinstall:maintainer] ⚠ Could not fetch package metadata\x1b[0m`);
    return { skipped: true };
  }

  const versions = Object.keys(meta.versions || {});
  const currentMaintainers = extractMaintainers(meta, currentVersion);

  if (currentMaintainers.length === 0) {
    return { skipped: true, reason: 'no_maintainer_data' };
  }

  // ── 1. 로컬 캐시와 비교 ──────────────────────────────
  const cache = loadCache();
  const cacheKey = pkgName;
  const cached = cache[cacheKey];

  let added = [];
  let removed = [];
  let prevVersion = null;
  let prevMaintainers = [];

  if (cached) {
    // 캐시된 메인테이너와 비교
    prevMaintainers = cached.maintainers || [];
    prevVersion = cached.version;
    added   = currentMaintainers.filter(m => !prevMaintainers.includes(m));
    removed = prevMaintainers.filter(m => !currentMaintainers.includes(m));
  } else {
    // 캐시 없으면 이전 버전과 비교
    prevVersion = findPreviousVersion(versions, currentVersion);
    if (prevVersion) {
      prevMaintainers = extractMaintainers(meta, prevVersion);
      added   = currentMaintainers.filter(m => !prevMaintainers.includes(m));
      removed = prevMaintainers.filter(m => !currentMaintainers.includes(m));
    }
  }

  // ── 2. 캐시 업데이트 ─────────────────────────────────
  cache[cacheKey] = {
    version: currentVersion,
    maintainers: currentMaintainers,
    updatedAt: new Date().toISOString(),
  };
  saveCache(cache);

  // ── 3. 위험도 판단 ────────────────────────────────────
  if (added.length === 0 && removed.length === 0) {
    console.log(`\x1b[32m[dryinstall:maintainer] ✓ No maintainer changes detected\x1b[0m`);
    return { clean: true, currentMaintainers };
  }

  // 기존 메인테이너 전원 제거 + 새 메인테이너 추가 → 매우 위험
  const fullTakeover = removed.length > 0 && removed.length === prevMaintainers.length;
  const risk = fullTakeover ? 'CRITICAL' : added.length > 0 ? 'HIGH' : 'MED';

  return {
    clean: false,
    risk,
    fullTakeover,
    currentMaintainers,
    prevMaintainers,
    prevVersion,
    added,
    removed,
  };
}

/**
 * 결과 출력
 */
function reportMaintainerChange(pkgName, result) {
  if (result.skipped || result.clean) return;

  const color = result.risk === 'CRITICAL' ? '\x1b[31m' : '\x1b[33m';

  console.log('');
  console.log(`${color}┌──────────────────────────────────────────────────────────┐\x1b[0m`);
  console.log(`${color}│        ⚠  MAINTAINER CHANGE DETECTED                     │\x1b[0m`);
  console.log(`${color}├──────────────────────────────────────────────────────────┤\x1b[0m`);
  console.log(`${color}│  Package  : \x1b[1m${pkgName.padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}│  Risk     : \x1b[1m${result.risk.padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  if (result.prevVersion) {
    console.log(`${color}│  Compared : \x1b[0mv${result.prevVersion} → current${''.padEnd(Math.max(0, 39 - result.prevVersion.length))}${color}│\x1b[0m`);
  }
  console.log(`${color}└──────────────────────────────────────────────────────────┘\x1b[0m`);
  console.log('');

  if (result.added.length > 0) {
    console.log(`\x1b[31m  ✗ New maintainers added (${result.added.length}):\x1b[0m`);
    result.added.forEach(m => console.log(`\x1b[31m      + ${m}\x1b[0m`));
  }
  if (result.removed.length > 0) {
    console.log(`\x1b[33m  ⚠ Maintainers removed (${result.removed.length}):\x1b[0m`);
    result.removed.forEach(m => console.log(`\x1b[33m      - ${m}\x1b[0m`));
  }

  console.log('');
  console.log(`\x1b[90m  Current maintainers: ${result.currentMaintainers.join(', ')}\x1b[0m`);

  if (result.fullTakeover) {
    console.log('');
    console.log(`\x1b[31m  ✗ ALL previous maintainers removed — possible account takeover.\x1b[0m`);
    console.log(`\x1b[31m    Similar pattern to ua-parser-js (2021) and coa (2021) attacks.\x1b[0m`);
  }
  console.log('');
}

module.exports = { checkMaintainerChange, reportMaintainerChange };
