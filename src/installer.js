'use strict';

const path  = require('path');
const fs    = require('fs');
const https = require('https');

const sandbox          = require('./sandbox');
const DryStorage       = require('./storage');
const auditor          = require('./auditor');
const profiler         = require('./profiler');
const advisor          = require('./advisor');
const networkAnalyzer  = require('./network-analyzer');
const executionTracker = require('./execution-tracker');
const ex               = require('./exception-handler');

const { detectTyposquatting }       = require('./typo-detector');
const { detectConfusion }           = require('./confusion-detector');
const { verifyHash }                = require('./hash-verifier');
const { analyzeVersionDiff }        = require('./version-diff-analyzer');
const { detectStealth }             = require('./stealth-detector');
const { checkMaintainerChange }     = require('./maintainer-monitor');
const { downloadAndExtract, cleanup } = require('./downloader');
const { printBlockCard, printSecurityReport, log } = require('./reporter');

/**
 * Lifecycle 차단 대상
 */
const DANGEROUS_HOOKS = [
  'preinstall', 'install', 'postinstall',
  'prepare', 'prepublish', 'prepack', 'postpack',
  'preuninstall', 'uninstall', 'postuninstall',
];

/**
 * 패키지명@버전 파싱
 * @param {string} raw  "express" | "express@4.18.2" | "@scope/pkg@1.0.0"
 */
function parsePkgName(raw) {
  if (raw.startsWith('@')) {
    const parts = raw.split('@');
    return { pkgName: '@' + parts[1], version: parts[2] || null };
  }
  const idx = raw.indexOf('@');
  if (idx > 0) {
    return { pkgName: raw.slice(0, idx), version: raw.slice(idx + 1) };
  }
  return { pkgName: raw, version: null };
}

/**
 * npm registry 메타 조회
 */
function fetchMeta(pkgName) {
  const encodedName = pkgName.replace('/', '%2F');
  const url = `https://registry.npmjs.org/${encodedName}`;
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
      if (res.statusCode === 404) {
        reject(new Error(`Package not found: ${pkgName}`));
        res.resume();
        return;
      }
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Failed to parse registry: ${e.message}`)); }
      });
    }).on('error', (err) => {
      ex.handleNetworkError(pkgName, null, err);
      reject(err);
    });
  });
}

/**
 * Installer
 * cli.js에서 install() + _checkDependencyLifecycles() + _printSecurityReport() 분리
 */
class Installer {
  constructor(cwd = process.cwd()) {
    this.cwd     = cwd;
    this.storage = new DryStorage(cwd);
  }

  /**
   * 패키지 설치 — 8-Layer 파이프라인
   * @param {string} rawPkgName
   * @returns {object|null}
   */
  async install(rawPkgName) {
    const { pkgName, version: requestedVersion } = parsePkgName(rawPkgName);
    const startTime = Date.now();

    log(`Installing: ${rawPkgName}`);
    log(`8-layer pipeline: checks → lifecycle block → sandbox`);

    const report = {
      pkg: pkgName, version: null,
      scanned: 1, blocked: [], passed: [],
      duration: 0,
    };

    try {
      // ① CVE Audit
      const auditResult = auditor.audit(pkgName, requestedVersion);
      if (!auditResult.safe) {
        printBlockCard(pkgName, 'cve', { version: requestedVersion });
        return null;
      }
      report.passed.push('CVE audit — no critical vulnerabilities');

      // ② Dependency Confusion
      const confusion = await detectConfusion(pkgName);
      if (confusion.risk === 'HIGH') {
        printBlockCard(pkgName, 'confusion');
        return null;
      }
      report.passed.push('Dependency Confusion — no attack detected');

      // ③ Registry 메타 조회
      let meta;
      try {
        meta = await fetchMeta(pkgName);
      } catch {
        log(`Package not found: ${pkgName}`, 'error');
        const suggestions = detectTyposquatting(pkgName);
        if (suggestions.length > 0) {
          log(`Did you mean: ${suggestions[0].name}?`, 'warn');
        }
        return null;
      }

      if (!meta?.['dist-tags']?.latest) {
        log(`Invalid package metadata: ${pkgName}`, 'error');
        return null;
      }

      const version = requestedVersion && meta.versions[requestedVersion]
        ? requestedVersion
        : meta['dist-tags'].latest;

      if (requestedVersion && !meta.versions[requestedVersion]) {
        log(`Version ${requestedVersion} not found, using latest: ${version}`, 'warn');
      }

      report.version = version;
      const versionMeta   = meta.versions[version];
      const tarballUrl    = versionMeta.dist.tarball;
      const integrity     = versionMeta.dist.integrity || null;

      // ④ Version Diff
      const diff = await analyzeVersionDiff(pkgName, version);
      if (!diff.skipped && !diff.clean) {
        const criticals = diff.findings.filter(f => f.severity === 'CRITICAL');
        if (criticals.length > 0) {
          printBlockCard(pkgName, 'version_diff', {
            version,
            pattern: criticals[0]?.pattern,
            extra: `${criticals.length} critical pattern(s) added since last version`,
          });
          return null;
        }
      }
      report.passed.push('Version diff — no new dangerous patterns');

      // ⑤ Hash Verification
      const hash = await verifyHash(pkgName, version, tarballUrl, integrity);
      if (hash.verified === false) {
        printBlockCard(pkgName, 'hash', { version });
        return null;
      }
      report.passed.push('Hash verification — integrity confirmed');

      // ⑥ Stealth Backdoor
      const stealth = await detectStealth(pkgName, tarballUrl);
      if (!stealth.skipped && !stealth.clean) {
        const criticals = stealth.findings.filter(f => f.severity === 'CRITICAL');
        if (criticals.length > 0) {
          printBlockCard(pkgName, 'stealth', {
            version,
            pattern: criticals[0]?.pattern,
          });
          return null;
        }
      }
      report.passed.push('Stealth backdoor scan — clean');

      // ⑦ Maintainer Monitor
      const maintainer = await checkMaintainerChange(pkgName, version);
      if (maintainer?.risk === 'CRITICAL') {
        printBlockCard(pkgName, 'maintainer', { version });
        return null;
      }
      report.passed.push('Maintainer check — no suspicious changes');

      // ⑧ Lifecycle Block
      const scripts     = versionMeta.scripts || {};
      const blockedHooks = Object.keys(scripts).filter(h => DANGEROUS_HOOKS.includes(h));

      blockedHooks.forEach(hook => {
        sandbox.blockLifecycleScript(pkgName, `${hook}: ${scripts[hook]}`);
        report.blocked.push({
          pkg: pkgName, reason: 'lifecycle',
          hook, cmd: scripts[hook], severity: 'WARN',
        });
      });

      if (blockedHooks.length > 0) {
        executionTracker.recordBlocked(pkgName, blockedHooks);
      }

      // ⑧-b 의존성 recursive lifecycle 검사
      await this._checkDeps(pkgName, versionMeta, 0, new Set([pkgName]), report);

      // 다운로드 + 추출
      networkAnalyzer.start(pkgName);
      const extractPath = await downloadAndExtract(pkgName, version, tarballUrl);

      // dry_modules 저장
      const pkgExtractPath = path.join(extractPath, 'package');
      this.storage.store(pkgName, pkgExtractPath);
      cleanup(extractPath);

      networkAnalyzer.stop();
      networkAnalyzer.report();

      // 프로파일 기록
      profiler.recordInstall(pkgName, version);
      advisor.printAdaptiveSummary(pkgName, version);

      report.duration = Date.now() - startTime;
      printSecurityReport(report);

      return { name: pkgName, version };

    } catch (err) {
      log(`Install failed: ${err.message}`, 'error');
      throw err;
    }
  }

  /**
   * 의존성 recursive lifecycle 검사 (depth 최대 3)
   */
  async _checkDeps(parentName, versionMeta, depth, visited, report) {
    if (depth > 3) return;

    const allDeps = {
      ...versionMeta.dependencies,
      ...versionMeta.devDependencies,
      ...versionMeta.optionalDependencies,
    };

    const depNames = Object.keys(allDeps).filter(d => !visited.has(d));
    if (depNames.length === 0) return;

    if (depth === 0) {
      log(`Scanning dependency tree of ${parentName}...`);
    }

    for (const dep of depNames) {
      visited.add(dep);
      report.scanned++;

      try {
        const depMeta = await fetchMeta(dep);
        if (!depMeta?.['dist-tags']?.latest) continue;

        const depVersion     = depMeta['dist-tags'].latest;
        const depVersionMeta = depMeta.versions[depVersion];
        const depScripts     = depVersionMeta?.scripts || {};
        const blocked        = Object.keys(depScripts).filter(h => DANGEROUS_HOOKS.includes(h));

        blocked.forEach(hook => {
          sandbox.blockLifecycleScript(dep, `${hook}: ${depScripts[hook]}`);
          report.blocked.push({
            pkg: dep, reason: 'lifecycle',
            hook, cmd: depScripts[hook], severity: 'WARN',
          });
        });

        if (depth < 3) {
          await this._checkDeps(dep, depVersionMeta, depth + 1, visited, report);
        }
      } catch {
        // 개별 의존성 실패는 무시
      }
    }
  }
}

module.exports = Installer;
