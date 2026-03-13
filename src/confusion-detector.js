'use strict';

const https = require('https');

/**
 * Dependency Confusion Attack 탐지기
 *
 * 공격 원리:
 *   내부 패키지(@company/pkg)와 같은 이름으로
 *   public npm에 더 높은 버전을 올려두면
 *   npm이 public 버전을 우선 설치 → 악성 코드 실행
 *
 * 탐지 방법:
 *   1. scoped 패키지(@scope/name) 여부 확인
 *   2. public npm registry에 같은 이름 존재 여부 조회
 *   3. 존재하면 버전 비교 → 높은 버전이 public에 있으면 위험
 */

const REGISTRY = 'https://registry.npmjs.org';

/**
 * npm registry에서 패키지 정보 조회
 */
function fetchPackageInfo(pkgName) {
  return new Promise((resolve) => {
    // @scope/name → @scope%2Fname (슬래시만 인코딩)
    const encoded = pkgName.startsWith('@')
      ? '@' + pkgName.slice(1).replace('/', '%2F')
      : pkgName;
    const url = `${REGISTRY}/${encoded}`;

    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 404) return resolve(null); // public에 없음
        try {
          const json = JSON.parse(data);
          resolve(json);
        } catch {
          resolve(null);
        }
      });
    }).on('error', () => resolve(null));
  });
}

/**
 * 버전 비교 (semver 간소화)
 * 반환: 1 (a > b), -1 (a < b), 0 (같음)
 */
function compareVersions(a, b) {
  const pa = a.replace(/[^0-9.]/g, '').split('.').map(Number);
  const pb = b.replace(/[^0-9.]/g, '').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}

/**
 * Dependency Confusion 탐지 메인 함수
 *
 * @param {string} pkgName  - 설치하려는 패키지명
 * @param {string} localVersion - 로컬/private 버전 (없으면 null)
 * @returns {Object} { confused: bool, publicVersion, risk }
 */
async function detectConfusion(pkgName, localVersion = null) {
  const isScoped = pkgName.startsWith('@');

  // scoped 패키지가 아니면 Dependency Confusion 해당 없음
  if (!isScoped) {
    return { confused: false };
  }

  console.log(`\x1b[36m[dryinstall:confusion] Checking public registry for: ${pkgName}\x1b[0m`);

  const info = await fetchPackageInfo(pkgName);

  // public npm에 없으면 안전
  if (!info || !info['dist-tags']) {
    console.log(`\x1b[32m[dryinstall:confusion] ✓ Not found on public registry — safe\x1b[0m`);
    return { confused: false };
  }

  const publicVersion = info['dist-tags'].latest;

  // public에 존재함 → 위험 가능성
  let risk = 'LOW';
  let confused = false;

  if (localVersion) {
    const cmp = compareVersions(publicVersion, localVersion);
    if (cmp > 0) {
      // public 버전이 더 높음 → 전형적인 Dependency Confusion
      risk = 'HIGH';
      confused = true;
    } else {
      risk = 'MED'; // public에 존재하지만 버전은 낮음
    }
  } else {
    // 로컬 버전 모름 → public에 존재한다는 것 자체가 의심
    risk = 'MED';
    confused = true;
  }

  return { confused, publicVersion, localVersion, risk };
}

/**
 * 탐지 결과 출력
 */
function reportConfusion(pkgName, result) {
  if (!result.confused) return;

  const riskColor = result.risk === 'HIGH' ? '\x1b[31m' : '\x1b[33m';

  console.log('');
  console.log(`${riskColor}┌──────────────────────────────────────────────────────────┐\x1b[0m`);
  console.log(`${riskColor}│        ⚠  DEPENDENCY CONFUSION DETECTED                  │\x1b[0m`);
  console.log(`${riskColor}├──────────────────────────────────────────────────────────┤\x1b[0m`);
  console.log(`${riskColor}│  Package : \x1b[1m${pkgName.padEnd(48)}\x1b[0m${riskColor}│\x1b[0m`);
  console.log(`${riskColor}│  Public  : \x1b[0mv${(result.publicVersion || '?').padEnd(47)}${riskColor}│\x1b[0m`);
  if (result.localVersion) {
    console.log(`${riskColor}│  Local   : \x1b[0mv${(result.localVersion || '?').padEnd(47)}${riskColor}│\x1b[0m`);
  }
  console.log(`${riskColor}│  Risk    : \x1b[1m${result.risk.padEnd(48)}\x1b[0m${riskColor}│\x1b[0m`);
  console.log(`${riskColor}└──────────────────────────────────────────────────────────┘\x1b[0m`);
  console.log('');

  if (result.risk === 'HIGH') {
    console.log(`\x1b[31m  ✗ Public version (${result.publicVersion}) is HIGHER than local (${result.localVersion})\x1b[0m`);
    console.log(`\x1b[31m    npm may install the PUBLIC (malicious) version instead.\x1b[0m`);
    console.log(`\x1b[31m    This is a classic Dependency Confusion Attack pattern.\x1b[0m`);
  } else {
    console.log(`\x1b[33m  ⚠ This scoped package exists on public npm registry.\x1b[0m`);
    console.log(`\x1b[33m    Verify this is the intended package before proceeding.\x1b[0m`);
  }
  console.log('');
}

module.exports = { detectConfusion, reportConfusion };
