'use strict';

const { execSync } = require('child_process');
const logger = require('./logger');

/**
 * Auditor
 * npm audit로 알려진 취약점 검사
 * Layer 1 — 알려진 CVE 탐지
 */
class Auditor {
  constructor() {
    this.results = [];
  }

  audit(pkgName, version) {
    const displayName = version ? `${pkgName}@${version}` : pkgName;
    logger.verbose(`[dryinstall:audit] Checking: ${displayName}`);

    try {
      const os   = require('os');
      const path = require('path');
      const fs   = require('fs');
      const tmpDir = path.join(os.tmpdir(), `dryinstall-audit-${Date.now()}`);

      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(`${tmpDir}/package.json`, JSON.stringify({
        name: 'dryinstall-audit-tmp',
        version: '1.0.0',
        dependencies: { [pkgName]: version || 'latest' }
      }, null, 2));

      execSync('npm install --package-lock-only --ignore-scripts', {
        cwd: tmpDir, stdio: 'pipe', timeout: 30000,
      });

      let auditOutput;
      try {
        execSync('npm audit --json', {
          cwd: tmpDir, stdio: 'pipe', timeout: 15000,
        });
        auditOutput = { vulnerabilities: {} };
      } catch (auditErr) {
        try {
          auditOutput = JSON.parse(auditErr.stdout?.toString() || '{}');
        } catch {
          auditOutput = { vulnerabilities: {} };
        }
      }

      fs.rmSync(tmpDir, { recursive: true, force: true });

      const vulns    = auditOutput.vulnerabilities || {};
      const vulnList = Object.entries(vulns).map(([name, info]) => ({
        name,
        severity: info.severity,
        via: info.via?.map(v => typeof v === 'string' ? v : v.title).join(', '),
      }));

      const hasCritical = vulnList.some(v => ['critical', 'high'].includes(v.severity));

      if (vulnList.length === 0) {
        logger.verbose(`[dryinstall:audit] ✓ No known vulnerabilities in ${displayName}`);
      } else {
        vulnList.forEach(v => {
          if (v.severity === 'critical' || v.severity === 'high') {
            logger.block(`[dryinstall:audit] ${v.severity.toUpperCase()}: ${v.name} — ${v.via}`);
          } else {
            logger.warn(`[dryinstall:audit] ${v.severity.toUpperCase()}: ${v.name} — ${v.via}`);
          }
        });
      }

      const result = { safe: !hasCritical, vulnerabilities: vulnList };
      this.results.push({ pkg: pkgName, ...result });
      return result;

    } catch (err) {
      logger.verbose(`[dryinstall:audit] Could not audit ${pkgName}: ${err.message}`);
      return { safe: true, vulnerabilities: [] };
    }
  }

  report() {
    if (this.results.length === 0) return;
    logger.verbose('[dryinstall:audit] Audit Summary:');
    this.results.forEach(r => {
      const status = r.safe ? '✓ SAFE' : '✗ VULNERABLE';
      logger.verbose(`  ${r.pkg}: ${status} (${r.vulnerabilities.length} issues)`);
    });
  }
}

module.exports = new Auditor();
