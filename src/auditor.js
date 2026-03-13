'use strict';

const { execSync } = require('child_process');

/**
 * Auditor
 * npm audit로 알려진 취약점 검사
 * Layer 1 — 알려진 CVE 탐지
 */
class Auditor {
  constructor() {
    this.results = [];
  }

  /**
   * 특정 패키지 audit 실행
   * @param {string} pkgName
   * @returns {{ safe: boolean, vulnerabilities: array }}
   */
  audit(pkgName, version) {
    const displayName = version ? `${pkgName}@${version}` : pkgName;
    console.log(`\x1b[36m[dryinstall:audit] Checking: ${displayName}\x1b[0m`);

    try {
      const os = require('os');
      const tmpDir = require('path').join(os.tmpdir(), `dryinstall-audit-${Date.now()}`);
      const fs = require('fs');

      fs.mkdirSync(tmpDir, { recursive: true });

      fs.writeFileSync(`${tmpDir}/package.json`, JSON.stringify({
        name: 'dryinstall-audit-tmp',
        version: '1.0.0',
        dependencies: { [pkgName]: version || 'latest' }
      }, null, 2));

      // npm install --package-lock-only (실제 설치 없이 lock 파일만 생성)
      execSync('npm install --package-lock-only --ignore-scripts', {
        cwd: tmpDir,
        stdio: 'pipe',
        timeout: 30000,
      });

      // npm audit --json
      let auditOutput;
      try {
        execSync('npm audit --json', {
          cwd: tmpDir,
          stdio: 'pipe',
          timeout: 15000,
        });
        // exit code 0 = 취약점 없음
        auditOutput = { vulnerabilities: {} };
      } catch (auditErr) {
        // npm audit는 취약점 발견 시 exit code 1 반환
        try {
          auditOutput = JSON.parse(auditErr.stdout?.toString() || '{}');
        } catch {
          auditOutput = { vulnerabilities: {} };
        }
      }

      // 정리
      fs.rmSync(tmpDir, { recursive: true, force: true });

      // 결과 파싱
      const vulns = auditOutput.vulnerabilities || {};
      const vulnList = Object.entries(vulns).map(([name, info]) => ({
        name,
        severity: info.severity,
        via: info.via?.map(v => typeof v === 'string' ? v : v.title).join(', '),
      }));

      const hasCritical = vulnList.some(v => ['critical', 'high'].includes(v.severity));

      if (vulnList.length === 0) {
        console.log(`\x1b[32m[dryinstall:audit] ✓ No known vulnerabilities in ${displayName}\x1b[0m`);
      } else {
        vulnList.forEach(v => {
          const color = v.severity === 'critical' || v.severity === 'high' ? '\x1b[31m' : '\x1b[33m';
          console.log(`${color}[dryinstall:audit] ${v.severity.toUpperCase()}: ${v.name} — ${v.via}\x1b[0m`);
        });
      }

      const result = { safe: !hasCritical, vulnerabilities: vulnList };
      this.results.push({ pkg: pkgName, ...result });
      return result;

    } catch (err) {
      console.warn(`\x1b[33m[dryinstall:audit] Could not audit ${pkgName}: ${err.message}\x1b[0m`);
      // audit 실패해도 설치는 진행 (프로토타입)
      return { safe: true, vulnerabilities: [] };
    }
  }

  report() {
    if (this.results.length === 0) return;
    console.log('\n\x1b[36m[dryinstall:audit] Audit Summary:\x1b[0m');
    this.results.forEach(r => {
      const status = r.safe ? '\x1b[32m✓ SAFE\x1b[0m' : '\x1b[31m✗ VULNERABLE\x1b[0m';
      console.log(`  ${r.pkg}: ${status} (${r.vulnerabilities.length} issues)`);
    });
  }
}

module.exports = new Auditor();