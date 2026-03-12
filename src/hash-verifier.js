'use strict';

const https = require('https');
const crypto = require('crypto');

/**
 * Hash Verification — tarball 무결성 검증
 *
 * 공격 시나리오:
 *   1. 공격자가 정상 패키지 소스 복제
 *   2. 악성 코드 삽입
 *   3. 같은 버전(v1.0.0)으로 public npm에 올림
 *   4. confusion-detector는 버전이 같아서 통과
 *   5. 하지만 tarball SHA256이 다름 → hash-verifier가 탐지
 *
 * 검증 방법:
 *   npm registry가 제공하는 shasum/integrity 값과
 *   실제 다운로드한 tarball의 해시를 비교
 */

const REGISTRY = 'https://registry.npmjs.org';

/**
 * registry에서 패키지 메타데이터 조회
 */
function fetchMeta(pkgName, version) {
  return new Promise((resolve, reject) => {
    const encoded = pkgName.startsWith('@')
      ? '@' + pkgName.slice(1).replace('/', '%2F')
      : pkgName;
    const url = `${REGISTRY}/${encoded}/${version}`;

    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 404) return resolve(null);
        try { resolve(JSON.parse(data)); }
        catch { resolve(null); }
      });
    }).on('error', reject);
  });
}

/**
 * tarball 다운로드 후 SHA512 계산
 */
function computeTarballHash(tarballUrl) {
  return new Promise((resolve, reject) => {
    https.get(tarballUrl, (res) => {
      // 리다이렉트 처리
      if (res.statusCode === 302 || res.statusCode === 301) {
        return computeTarballHash(res.headers.location).then(resolve).catch(reject);
      }

      const hash = crypto.createHash('sha512');
      res.on('data', chunk => hash.update(chunk));
      res.on('end', () => {
        const digest = hash.digest('base64');
        resolve(`sha512-${digest}`);
      });
      res.on('error', reject);
    }).on('error', reject);
  });
}

/**
 * integrity 문자열 파싱
 * "sha512-abc123==" → { algo: 'sha512', hash: 'abc123==' }
 */
function parseIntegrity(integrity) {
  if (!integrity) return null;
  const dash = integrity.indexOf('-');
  if (dash < 0) return null;
  return {
    algo: integrity.slice(0, dash),
    hash: integrity.slice(dash + 1),
    full: integrity,
  };
}

/**
 * 메인 검증 함수
 *
 * @param {string} pkgName    - 패키지명
 * @param {string} version    - 버전
 * @param {string} tarballUrl - 실제 다운로드 URL
 * @param {string} registryIntegrity - registry가 제공한 integrity 값
 * @returns {Object} { verified, expected, actual, mismatch }
 */
async function verifyHash(pkgName, version, tarballUrl, registryIntegrity) {
  console.log(`\x1b[36m[dryinstall:hash] Verifying integrity: ${pkgName}@${version}\x1b[0m`);

  if (!registryIntegrity) {
    console.log(`\x1b[33m[dryinstall:hash] ⚠ No integrity field — skipping verification\x1b[0m`);
    return { verified: null, reason: 'no_integrity' };
  }

  const expected = parseIntegrity(registryIntegrity);
  if (!expected) {
    return { verified: null, reason: 'parse_error' };
  }

  let actual;
  try {
    actual = await computeTarballHash(tarballUrl);
  } catch (err) {
    console.log(`\x1b[33m[dryinstall:hash] ⚠ Could not compute hash: ${err.message}\x1b[0m`);
    return { verified: null, reason: 'download_error' };
  }

  const matched = actual === expected.full;

  if (matched) {
    console.log(`\x1b[32m[dryinstall:hash] ✓ Integrity verified: ${pkgName}@${version}\x1b[0m`);
    return { verified: true, expected: expected.full, actual };
  } else {
    return {
      verified: false,
      expected: expected.full,
      actual,
      mismatch: true,
    };
  }
}

/**
 * 해시 불일치 경고 출력
 */
function reportHashMismatch(pkgName, version, result) {
  if (result.verified !== false) return;

  console.log('');
  console.log(`\x1b[31m┌──────────────────────────────────────────────────────────┐\x1b[0m`);
  console.log(`\x1b[31m│        ✗  INTEGRITY MISMATCH DETECTED                    │\x1b[0m`);
  console.log(`\x1b[31m├──────────────────────────────────────────────────────────┤\x1b[0m`);
  console.log(`\x1b[31m│  Package  : \x1b[1m${(pkgName + '@' + version).padEnd(47)}\x1b[0m\x1b[31m│\x1b[0m`);
  console.log(`\x1b[31m│  Expected : \x1b[0m${(result.expected || '').slice(0, 48).padEnd(48)}\x1b[31m│\x1b[0m`);
  console.log(`\x1b[31m│  Actual   : \x1b[0m${(result.actual || '').slice(0, 48).padEnd(48)}\x1b[31m│\x1b[0m`);
  console.log(`\x1b[31m│  Risk     : \x1b[1m${'CRITICAL'.padEnd(48)}\x1b[0m\x1b[31m│\x1b[0m`);
  console.log(`\x1b[31m└──────────────────────────────────────────────────────────┘\x1b[0m`);
  console.log('');
  console.log(`\x1b[31m  ✗ The tarball content does not match the registry record.\x1b[0m`);
  console.log(`\x1b[31m    This package may have been tampered with.\x1b[0m`);
  console.log(`\x1b[31m    Possible attack: cloned package with injected malicious code.\x1b[0m`);
  console.log('');
}

module.exports = { verifyHash, reportHashMismatch };
