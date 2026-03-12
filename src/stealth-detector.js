'use strict';

const https = require('https');
const zlib = require('zlib');
const tar = require('tar');
const path = require('path');
const fs = require('fs');
const os = require('os');

/**
 * Stealth Backdoor Detector
 *
 * 공격 패턴:
 *   1. 환경 조건부 실행 — CI/CD 서버에서만 악성코드 실행
 *      if(process.env.CI){ runMalware() }
 *
 *   2. 타겟 공격 — 특정 회사/서버에서만 실행
 *      if(hostname.includes("corp")){ stealSecrets() }
 *
 *   3. IP 기반 타겟 — AWS/GCP 등 클라우드에서만 실행
 *      if(ip.startsWith("172.16")){ ... }
 *
 *   4. Time Bomb — 특정 날짜/시간 이후 실행
 *      if(Date.now() > 1700000000000){ runMalware() }
 *
 *   5. Hidden Code — base64/난독화로 정적 분석 우회
 *      eval(Buffer.from("ZXZpbA==","base64").toString())
 *
 * 탐지 방법:
 *   tarball 내 JS 파일을 정적 분석하여 위험 패턴 조합 탐지
 */

// ── 스텔스 패턴 정의 ────────────────────────────────────
const STEALTH_PATTERNS = [
  // 환경 조건부 실행
  {
    id: 'ENV_CONDITIONAL',
    pattern: /if\s*\(\s*process\.env\.(CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS|TRAVIS|CIRCLECI|BUILD|DEPLOY)\s*\)/g,
    label: 'CI/CD environment conditional execution',
    severity: 'CRITICAL',
    description: '빌드/배포 환경에서만 실행되는 조건부 코드',
  },
  // 호스트네임 타겟 공격
  {
    id: 'HOSTNAME_TARGET',
    pattern: /os\.hostname\(\)|require\('os'\)\.hostname|hostname\(\).*includes|hostname\(\).*startsWith/g,
    label: 'hostname-based targeting',
    severity: 'HIGH',
    description: '특정 회사/서버 호스트명 기반 타겟 공격',
  },
  // IP 범위 체크
  {
    id: 'IP_TARGET',
    pattern: /\b(172\.16|10\.\d+\.\d+|192\.168|169\.254)\b.*exec|networkInterfaces.*exec|getNetworkInterfaces/g,
    label: 'IP range targeting',
    severity: 'HIGH',
    description: '내부 네트워크 IP 기반 타겟 공격',
  },
  // Time Bomb — 특정 날짜 이후 실행
  {
    id: 'TIME_BOMB',
    pattern: /Date\.now\(\)\s*[>]=\s*\d{10,13}|new Date\(\)\s*[>]=?\s*new Date\(['"][0-9\-]+['"]\)/g,
    label: 'time bomb — date-triggered execution',
    severity: 'CRITICAL',
    description: '특정 날짜/시간 이후 실행되는 지연 공격',
  },
  // setTimeout 장기 지연 실행 (1시간 이상)
  {
    id: 'DELAYED_EXEC',
    pattern: /setTimeout\s*\([^,]+,\s*(\d{7,})\s*\)/g,
    label: 'long-delay execution (possible time bomb)',
    severity: 'HIGH',
    description: '1시간 이상 지연 후 코드 실행',
  },
  // Hidden Code — base64 eval
  {
    id: 'BASE64_EVAL',
    pattern: /eval\s*\(\s*(?:Buffer\.from|atob)\s*\([^)]+(?:base64|hex)[^)]*\)/g,
    label: 'base64/hex encoded eval (obfuscation)',
    severity: 'CRITICAL',
    description: 'base64 인코딩으로 정적 분석 우회',
  },
  // Function 생성자 동적 코드 실행
  {
    id: 'DYNAMIC_FUNCTION',
    pattern: /new\s+Function\s*\(\s*['"`][^'"` ]{20,}/g,
    label: 'dynamic Function constructor with long string',
    severity: 'CRITICAL',
    description: 'Function 생성자로 난독화된 코드 실행',
  },
  // process.env 대량 수집 + 외부 전송
  {
    id: 'ENV_EXFIL',
    pattern: /JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.keys\s*\(\s*process\.env\s*\)/g,
    label: 'environment variable mass collection',
    severity: 'CRITICAL',
    description: '환경변수 전체 수집 후 외부 전송 의심',
  },
  // 클라우드 메타데이터 API 접근
  {
    id: 'CLOUD_METADATA',
    pattern: /169\.254\.169\.254|metadata\.google\.internal|instance-data\.ec2\.internal/g,
    label: 'cloud metadata API access',
    severity: 'CRITICAL',
    description: 'AWS/GCP/Azure 인스턴스 메타데이터 탈취 시도',
  },
  // Protestware 패턴 — 무한루프
  {
    id: 'PROTESTWARE',
    pattern: /while\s*\(\s*true\s*\)\s*\{[^}]{0,100}(console\.log|process\.stdout)/g,
    label: 'infinite loop with output (possible protestware)',
    severity: 'HIGH',
    description: '의도적 무한 루프로 서비스 다운 유발',
  },
];

const REGISTRY = 'https://registry.npmjs.org';

/**
 * tarball에서 JS 파일 추출
 */
function extractJsFiles(tarballUrl) {
  return new Promise((resolve, reject) => {
    const files = new Map();

    https.get(tarballUrl, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        return extractJsFiles(res.headers.location).then(resolve).catch(reject);
      }

      res.pipe(zlib.createGunzip())
        .pipe(tar.t({
          onentry: (entry) => {
            if (!/\.(js|mjs|cjs)$/.test(entry.path)) { entry.resume(); return; }
            if (entry.path.includes('node_modules') ||
                entry.path.includes('.min.js')) { entry.resume(); return; }

            let content = '';
            entry.on('data', chunk => content += chunk.toString());
            entry.on('end', () => {
              const cleanPath = entry.path.replace(/^[^/]+\//, '');
              files.set(cleanPath, content);
            });
          }
        }))
        .on('finish', () => resolve(files))
        .on('error', reject);
    }).on('error', reject);
  });
}

/**
 * 단일 파일 스텔스 패턴 분석
 */
function analyzeFile(filename, content) {
  const findings = [];

  for (const def of STEALTH_PATTERNS) {
    const matches = content.match(def.pattern);
    if (!matches || matches.length === 0) continue;

    // 주변 컨텍스트 추출 (매칭 위치 앞뒤 80자)
    const idx = content.search(def.pattern);
    const context = content.slice(Math.max(0, idx - 40), idx + 80)
      .replace(/\n/g, ' ').trim();

    findings.push({
      id: def.id,
      label: def.label,
      severity: def.severity,
      description: def.description,
      filename,
      count: matches.length,
      context,
    });
  }

  return findings;
}

/**
 * 메인 탐지 함수
 */
async function detectStealth(pkgName, tarballUrl) {
  console.log(`\x1b[36m[dryinstall:stealth] Scanning for backdoor patterns: ${pkgName}\x1b[0m`);

  let files;
  try {
    files = await extractJsFiles(tarballUrl);
  } catch (err) {
    console.log(`\x1b[33m[dryinstall:stealth] ⚠ Could not extract files: ${err.message}\x1b[0m`);
    return { skipped: true };
  }

  const allFindings = [];
  for (const [filename, content] of files) {
    const findings = analyzeFile(filename, content);
    allFindings.push(...findings);
  }

  if (allFindings.length === 0) {
    console.log(`\x1b[32m[dryinstall:stealth] ✓ No stealth patterns detected\x1b[0m`);
    return { clean: true };
  }

  return { clean: false, findings: allFindings };
}

/**
 * 탐지 결과 출력
 */
function reportStealth(pkgName, result) {
  if (result.skipped || result.clean) return;

  const criticals = result.findings.filter(f => f.severity === 'CRITICAL');
  const highs     = result.findings.filter(f => f.severity === 'HIGH');

  const overallSeverity = criticals.length > 0 ? 'CRITICAL' : 'HIGH';
  const color = overallSeverity === 'CRITICAL' ? '\x1b[31m' : '\x1b[33m';

  console.log('');
  console.log(`${color}┌──────────────────────────────────────────────────────────┐\x1b[0m`);
  console.log(`${color}│        ⚠  STEALTH BACKDOOR PATTERN DETECTED              │\x1b[0m`);
  console.log(`${color}├──────────────────────────────────────────────────────────┤\x1b[0m`);
  console.log(`${color}│  Package  : \x1b[1m${pkgName.padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}│  Findings : \x1b[1m${String(result.findings.length).padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}│  Severity : \x1b[1m${overallSeverity.padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}└──────────────────────────────────────────────────────────┘\x1b[0m`);
  console.log('');

  result.findings.forEach((f, i) => {
    const fc = f.severity === 'CRITICAL' ? '\x1b[31m' : '\x1b[33m';
    console.log(`${fc}  [${i + 1}] [${f.severity}] ${f.label}\x1b[0m`);
    console.log(`\x1b[90m       file    : ${f.filename}\x1b[0m`);
    console.log(`\x1b[90m       detail  : ${f.description}\x1b[0m`);
    console.log(`\x1b[90m       context : ...${f.context.slice(0, 60)}...\x1b[0m`);
    console.log('');
  });
}

module.exports = { detectStealth, reportStealth };
