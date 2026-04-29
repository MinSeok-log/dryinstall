'use strict';

/**
 * Reporter
 * 차단 이유 + 해결 방법을 명확하게 출력
 * cli.js의 _printSecurityReport 대체
 */

const C = {
  RESET:  '\x1b[0m',
  BOLD:   '\x1b[1m',
  RED:    '\x1b[31m',
  GREEN:  '\x1b[32m',
  YELLOW: '\x1b[33m',
  CYAN:   '\x1b[36m',
  GRAY:   '\x1b[90m',
  WHITE:  '\x1b[97m',
};

// 차단 이유 → 사람이 읽을 수 있는 설명 + 해결법 매핑
const BLOCK_EXPLANATIONS = {
  cve: {
    title:   'Known CVE Vulnerability',
    icon:    '🔴',
    why:     'This package has critical or high severity vulnerabilities in the npm advisory database.',
    fix:     [
      'Find an alternative package',
      'Pin to a patched version: dryinstall install {pkg}@{safe_version}',
      'Override (not recommended): dryinstall install {pkg} --level=0',
    ],
  },
  confusion: {
    title:   'Dependency Confusion Attack',
    icon:    '🔴',
    why:     'A public package with the same name exists with a higher version than your private package. npm would install the public (attacker\'s) version.',
    fix:     [
      'Verify the package is the one you intended',
      'Use scoped packages: @yourorg/package-name',
      'Override if you trust this: dryinstall install {pkg} --allow-confusion',
    ],
  },
  hash: {
    title:   'Integrity Mismatch',
    icon:    '🔴',
    why:     'The package tarball SHA512 does not match the registry checksum. The package may have been tampered with after publishing.',
    fix:     [
      'Do not install this package',
      'Report to npm security: https://www.npmjs.com/support',
      'Try a different version: dryinstall install {pkg}@{other_version}',
    ],
  },
  version_diff: {
    title:   'Version Poisoning Detected',
    icon:    '🔴',
    why:     'Dangerous patterns (eval, child_process exec, network requests) were added between the previous and current version. This is a known supply chain attack pattern.',
    fix:     [
      'Pin to the last safe version: dryinstall install {pkg}@{prev_version}',
      'Check the changelog: https://www.npmjs.com/package/{pkg}',
      'Override if you trust the change: dryinstall install {pkg} --skip-version-diff',
    ],
  },
  stealth: {
    title:   'Stealth Backdoor Detected',
    icon:    '🔴',
    why:     'The package contains code that activates only under specific conditions (CI environment, specific hostname, time-based trigger, etc.).',
    fix:     [
      'Do not install this package',
      'Review the source: https://unpkg.com/{pkg}/',
      'Report to npm: https://www.npmjs.com/support',
    ],
  },
  maintainer: {
    title:   'Maintainer Takeover Detected',
    icon:    '🔴',
    why:     'All previous maintainers were removed and replaced. This is the exact pattern used in the ua-parser-js (2021) and coa (2021) supply chain attacks.',
    fix:     [
      'Wait for the community to verify the new maintainer',
      'Pin to a previous safe version',
      'Override if you trust the new owner: dryinstall install {pkg} --allow-maintainer-change',
    ],
  },
  lifecycle: {
    title:   'Lifecycle Script Blocked',
    icon:    '⚠️',
    why:     'This package runs code automatically during install (postinstall, preinstall, etc.). dryinstall blocks all install-time execution by default.',
    fix:     [
      'Allow interactively: dryinstall install {pkg} --interactive',
      'Always allow this package: dryinstall install {pkg} --allow-package={pkg}',
      'Or add to ~/.dryinstallrc: { "alwaysAllow": ["{pkg}"] }',
    ],
  },
};

/**
 * 차단 이유 카드 출력
 * @param {string} pkg
 * @param {string} reason  - 키: cve | confusion | hash | version_diff | stealth | maintainer
 * @param {object} detail  - 추가 컨텍스트 (optional)
 */
function printBlockCard(pkg, reason, detail = {}) {
  const exp = BLOCK_EXPLANATIONS[reason];
  if (!exp) return;

  const line = '─'.repeat(56);
  console.log(`\n${C.RED}${line}${C.RESET}`);
  console.log(`${C.BOLD}${C.WHITE}  ${exp.icon}  BLOCKED — ${exp.title}${C.RESET}`);
  console.log(`${C.RED}${line}${C.RESET}`);
  console.log(`${C.BOLD}  Package:${C.RESET} ${pkg}`);

  if (detail.version)  console.log(`${C.BOLD}  Version:${C.RESET} ${detail.version}`);
  if (detail.hook)     console.log(`${C.BOLD}  Script: ${C.RESET} ${detail.hook}: ${detail.cmd || ''}`);
  if (detail.pattern)  console.log(`${C.BOLD}  Pattern:${C.RESET} ${detail.pattern}`);
  if (detail.extra)    console.log(`${C.BOLD}  Detail: ${C.RESET} ${detail.extra}`);

  console.log(`\n${C.BOLD}  Why was this blocked?${C.RESET}`);
  console.log(`  ${C.YELLOW}${exp.why}${C.RESET}`);

  console.log(`\n${C.BOLD}  How to fix:${C.RESET}`);
  exp.fix.forEach((f, i) => {
    const text = f
      .replace(/{pkg}/g, pkg)
      .replace(/{version}/g, detail.version || 'x.x.x')
      .replace(/{prev_version}/g, detail.prevVersion || 'x.x.x')
      .replace(/{safe_version}/g, detail.safeVersion || 'x.x.x')
      .replace(/{other_version}/g, detail.otherVersion || 'x.x.x');
    console.log(`  ${C.GRAY}${i + 1}.${C.RESET} ${text}`);
  });

  console.log(`${C.RED}${line}${C.RESET}\n`);
}

/**
 * 전체 설치 후 Security Report
 * @param {object} report
 * {
 *   pkg, version,
 *   scanned,         총 스캔 패키지 수
 *   blocked: [       차단된 항목
 *     { pkg, reason, hook?, cmd?, pattern?, severity }
 *   ],
 *   passed: [],      통과한 검사 목록
 *   duration,        소요시간(ms)
 * }
 */
function printSecurityReport(report) {
  const line = '═'.repeat(56);
  const { pkg, version, scanned, blocked = [], passed = [], duration } = report;

  const criticals = blocked.filter(b => b.severity === 'CRITICAL' || b.reason !== 'lifecycle');
  const warnings  = blocked.filter(b => b.severity !== 'CRITICAL' && b.reason === 'lifecycle');

  console.log(`\n${C.CYAN}${line}${C.RESET}`);
  console.log(`${C.BOLD}${C.CYAN}  dryinstall Security Report${C.RESET}`);
  console.log(`${C.CYAN}${line}${C.RESET}`);

  console.log(`\n  ${C.BOLD}Package    ${C.RESET}: ${pkg}@${version}`);
  console.log(`  ${C.BOLD}Scanned    ${C.RESET}: ${scanned} packages`);
  if (duration) {
    console.log(`  ${C.BOLD}Duration   ${C.RESET}: ${(duration / 1000).toFixed(1)}s`);
  }

  // ── 통과한 검사 ─────────────────────────────────────
  if (passed.length > 0) {
    console.log(`\n  ${C.BOLD}${C.GREEN}Passed checks:${C.RESET}`);
    passed.forEach(p => {
      console.log(`  ${C.GREEN}  ✓${C.RESET}  ${p}`);
    });
  }

  // ── 차단된 항목 ─────────────────────────────────────
  if (blocked.length > 0) {
    console.log(`\n  ${C.BOLD}Blocked (${blocked.length}):${C.RESET}`);

    // 위험도별 그룹
    if (criticals.length > 0) {
      console.log(`\n  ${C.RED}${C.BOLD}  Critical blocks:${C.RESET}`);
      criticals.forEach(b => {
        const exp = BLOCK_EXPLANATIONS[b.reason] || {};
        console.log(`  ${C.RED}  ✗${C.RESET}  ${b.pkg}${b.version ? '@' + b.version : ''}`);
        console.log(`       ${C.GRAY}reason: ${exp.title || b.reason}${C.RESET}`);
        if (b.pattern) console.log(`       ${C.GRAY}pattern: ${b.pattern}${C.RESET}`);
      });
    }

    if (warnings.length > 0) {
      console.log(`\n  ${C.YELLOW}${C.BOLD}  Lifecycle scripts blocked:${C.RESET}`);
      const grouped = {};
      warnings.forEach(b => {
        if (!grouped[b.pkg]) grouped[b.pkg] = [];
        grouped[b.pkg].push(b.hook || '?');
      });
      Object.entries(grouped).slice(0, 5).forEach(([p, hooks]) => {
        console.log(`  ${C.YELLOW}  ⚠${C.RESET}  ${p}  ${C.GRAY}(${hooks.join(', ')})${C.RESET}`);
      });
      const rest = Object.keys(grouped).length - 5;
      if (rest > 0) {
        console.log(`  ${C.GRAY}     ... and ${rest} more packages${C.RESET}`);
      }

      // 해결법 한 줄 안내
      const firstPkg = Object.keys(grouped)[0];
      if (firstPkg) {
        console.log(`\n  ${C.GRAY}  To allow interactively:${C.RESET}`);
        console.log(`  ${C.GRAY}    dryinstall install ${firstPkg} --interactive${C.RESET}`);
      }
    }
  }

  // ── 최종 결론 ────────────────────────────────────────
  console.log('');
  if (criticals.length === 0) {
    console.log(`  ${C.GREEN}✓${C.RESET}  Install completed with dryinstall protection`);
    console.log(`  ${C.GREEN}✓${C.RESET}  High-risk install behavior blocked or avoided`);
  } else {
    console.log(`  ${C.RED}✗${C.RESET}  Install blocked — ${criticals.length} critical issue(s) found`);
  }

  console.log(`${C.CYAN}${line}${C.RESET}\n`);
}

/**
 * 빠른 인라인 경고 (상세 카드 없이)
 * @param {string} msg
 * @param {'warn'|'info'|'error'} level
 */
function log(msg, level = 'info') {
  const prefix = {
    info:  `${C.CYAN}[dryinstall]${C.RESET}`,
    warn:  `${C.YELLOW}[dryinstall]${C.RESET}`,
    error: `${C.RED}[dryinstall]${C.RESET}`,
  }[level] || `${C.CYAN}[dryinstall]${C.RESET}`;
  console.log(`${prefix} ${msg}`);
}

module.exports = { printBlockCard, printSecurityReport, log };
