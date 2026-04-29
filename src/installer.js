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
const trustCache = require('./trust-cache');  // ← 증거 기반 신뢰 캐시
const traceRecorder    = require('./trace-recorder');

const { detectTyposquatting }         = require('./typo-detector');
const { detectConfusion }             = require('./confusion-detector');
const { verifyHash }                  = require('./hash-verifier');
const { analyzeVersionDiff }          = require('./version-diff-analyzer');
const { detectStealth }               = require('./stealth-detector');
const { checkMaintainerChange }       = require('./maintainer-monitor');
const { downloadAndExtract, cleanup } = require('./downloader');
const { printBlockCard, printSecurityReport, log } = require('./reporter');

// ─────────────────────────────────────────────────────────────
// 구조화된 출력 헬퍼
// ─────────────────────────────────────────────────────────────
const W     = 56;
const LINE  = '─'.repeat(W);
const DLINE = '═'.repeat(W);

function stepStart(num, label) {
  process.stdout.write(`\n${LINE}\n`);
  process.stdout.write(`  ${num}  ${label.padEnd(36)} ...\n`);
  process.stdout.write(`${LINE}\n`);
}

function stepDone(result, detail) {
  const R = '\x1b[0m';
  const c = result === 'ok'   ? '\x1b[32m' :
            result === 'warn' ? '\x1b[33m' :
            result === 'fail' ? '\x1b[31m' : '\x1b[37m';
  const i = result === 'ok' ? '✓' : result === 'warn' ? '⚠' : '✗';
  process.stdout.write(`  ${c}${i}${R}  ${detail}\n`);
}

function banner(pkg, version, level) {
  const label = {
    3: 'Paranoid  — full scan, block all scripts',
    2: 'Balanced  — fast install, high-risk blocks',
    1: 'Relaxed   — install first, scan after',
    0: 'Observer  — logs only, nothing blocked',
  }[level] ?? `Level ${level}`;
  console.log(`\n${DLINE}`);
  console.log(`  dryinstall  →  ${pkg}${version ? `@${version}` : ''}`);
  console.log(`  Level ${level}  ${label}`);
  console.log(`${DLINE}\n`);
}

function finalSummary(blocked, scanned) {
  console.log(`\n${DLINE}`);
  if (blocked === 0) {
    console.log(`  \x1b[32m✓\x1b[0m  All ${scanned} checks passed`);
  } else {
    console.log(`  \x1b[33m⚠\x1b[0m  ${blocked} script(s) blocked  /  ${scanned} packages scanned`);
  }
  console.log(`${DLINE}\n`);
}

function printConciseSuccess(pkg, version, duration) {
  const elapsed = duration ? ` (${(duration / 1000).toFixed(1)}s)` : '';
  console.log(`\x1b[32m✓\x1b[0m ${pkg}@${version} installed with dryinstall protection${elapsed}`);
}

// ─────────────────────────────────────────────────────────────
// 하드코딩 Whitelist (알려진 안전 빌드 도구)
// ─────────────────────────────────────────────────────────────
const FAST_WHITELIST = new Set([
  'webpack', 'vite', 'esbuild', 'rollup', 'parcel', 'swc',
  'typescript', 'ts-node', 'tsx', 'tshy',
  'eslint', 'prettier', 'oxlint',
  'jest', 'vitest', 'mocha', 'chai', 'tap',
  'babel', '@babel/core',
  'rimraf', 'glob', 'mkdirp', 'cross-env', 'shx',
  'nodemon', 'concurrently', 'npm-run-all', 'wireit',
  'postcss', 'tailwindcss', 'autoprefixer',
  'react-scripts', 'next', 'nuxt',
  'prisma', 'drizzle-kit',
  'puppeteer', 'playwright', 'sharp', 'canvas',
  'node-gyp', 'node-pre-gyp', 'prebuild', 'node-addon-api',
  'husky', 'lint-staged', 'is-ci', 'not-in-publish',
  'npmignore', 'safe-publish-latest', 'np',
  'log4js', 'socket.io', 'resolve', 'minimist', 'minimatch',
  'yargs', 'mime', 'assert', 'defined', 'hasown',
  'shell-quote', 'browser-pack', 'xo',
]);

const SAFE_CMD_PATTERNS = [
  /^tsc\b/, /^tshy\b/, /^wireit\b/, /^husky\b/,
  /^npmignore\b/, /^is-ci\b/, /^not-in-publish\b/,
  /^safe-publish-latest\b/, /^npm run build$/, /^npm run compile$/,
  /^node install\.(mjs|js|cjs)$/, /^bash scripts\/build\.sh$/,
];

/**
 * fast-pass 판단
 * 하드코딩 whitelist + 안전 커맨드 패턴만 — trust cache는 별도 흐름
 */
function isFastPass(pkgName, cmd, level) {
  if (level >= 3) return false;
  if (FAST_WHITELIST.has(pkgName)) return true;
  if (SAFE_CMD_PATTERNS.some(p => p.test(cmd.trim()))) return true;
  return false;
}

function getFastPassSource(pkgName) {
  if (FAST_WHITELIST.has(pkgName)) return 'known safe';
  return 'pattern match';
}

function formatRisk(assessment) {
  const reasons = assessment.risk.reasons.slice(0, 2).join(', ') || 'low risk';
  return `risk ${assessment.risk.score}/100: ${reasons}`;
}

function shouldRunDeepChecks(level) {
  return level >= 3;
}

function shouldShowDetailedOutput(level, report) {
  return level >= 3 || report.blocked.length > 0 || report.warnings.length > 0;
}

function recordInstallTrace(report, level, decision, reason, extra = {}) {
  const trace = traceRecorder.record({
    type: 'install',
    package: report.pkg,
    version: report.version,
    level,
    decision,
    reason,
    scanned: report.scanned,
    blocked: report.blocked,
    warnings: report.warnings,
    passed: report.passed,
    durationMs: report.duration,
    ...extra,
  });
  traceRecorder.printHint(trace);
  return trace;
}

// ─────────────────────────────────────────────────────────────
const DANGEROUS_HOOKS = [
  'preinstall', 'install', 'postinstall',
  'prepare', 'prepublish', 'prepack', 'postpack',
  'preuninstall', 'uninstall', 'postuninstall',
];

function parsePkgName(raw) {
  if (raw.startsWith('@')) {
    const parts = raw.split('@');
    return { pkgName: '@' + parts[1], version: parts[2] || null };
  }
  const idx = raw.indexOf('@');
  if (idx > 0) return { pkgName: raw.slice(0, idx), version: raw.slice(idx + 1) };
  return { pkgName: raw, version: null };
}

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

// ─────────────────────────────────────────────────────────────
class Installer {
  constructor(cwd = process.cwd()) {
    this.cwd     = cwd;
    this.storage = new DryStorage(cwd);
    this.level   = parseInt(process.env.DRYINSTALL_LEVEL ?? '2', 10);
  }

  async install(rawPkgName) {
    const { pkgName, version: requestedVersion } = parsePkgName(rawPkgName);
    const startTime = Date.now();
    const level = this.level;

    const report = {
      pkg: pkgName, version: null,
      scanned: 1, blocked: [], warnings: [], passed: [],
      duration: 0,
    };

    try {
      const detailedOutput = shouldRunDeepChecks(level);
      if (detailedOutput) banner(pkgName, requestedVersion, level);
      // 버전 바뀌면 trust cache 무효화
      if (requestedVersion) trustCache.invalidate(pkgName, requestedVersion);

      // ── 빠른 사전 보호 ─────────────────────────────
      if (detailedOutput) {
        stepStart('①', 'Fast preflight');
      }

      // ① CVE Audit
      const auditResult = auditor.audit(pkgName, requestedVersion);
      if (!auditResult.safe) {
        if (level >= 2) stepDone('fail', 'CVE — known vulnerability found');
        else { stepStart('①', 'CVE Audit'); stepDone('fail', 'Known vulnerability found'); }
        printBlockCard(pkgName, 'cve', { version: requestedVersion });
        report.version = requestedVersion || 'latest';
        report.blocked.push({ pkg: pkgName, reason: 'cve', severity: 'CRITICAL' });
        recordInstallTrace(report, level, 'BLOCK', 'Known CVE vulnerability');
        return null;
      }
      if (level < 2) { stepStart('①', 'CVE Audit'); stepDone('ok', 'No known vulnerabilities'); }
      report.passed.push('CVE audit');

      // ② Dependency Confusion
      const confusion = await detectConfusion(pkgName);
      if (confusion.risk === 'HIGH') {
        if (level >= 2) stepDone('fail', 'Dependency Confusion — attack detected');
        else { stepStart('②', 'Dependency Confusion'); stepDone('fail', 'Attack detected'); }
        printBlockCard(pkgName, 'confusion');
        report.version = requestedVersion || 'latest';
        report.blocked.push({ pkg: pkgName, reason: 'confusion', severity: 'CRITICAL' });
        recordInstallTrace(report, level, 'BLOCK', 'Dependency confusion risk');
        return null;
      }
      if (level < 2) { stepStart('②', 'Dependency Confusion'); stepDone('ok', 'No confusion attack'); }
      report.passed.push('Confusion check');

      // ③ Registry 메타
      let meta;
      try { meta = await fetchMeta(pkgName); }
      catch {
        if (level >= 2) stepDone('fail', `Package not found: ${pkgName}`);
        else { stepStart('③', 'Registry'); stepDone('fail', `Not found: ${pkgName}`); }
        const suggestions = detectTyposquatting(pkgName);
        if (suggestions.length > 0) log(`Did you mean: ${suggestions[0].name}?`, 'warn');
        report.version = requestedVersion || 'latest';
        const suggestionList = Array.isArray(suggestions) ? suggestions : [];
        recordInstallTrace(report, level, 'FAIL', 'Package metadata unavailable', {
          suggestions: suggestionList.slice(0, 3),
        });
        return null;
      }

      if (!meta?.['dist-tags']?.latest) {
        stepDone('fail', 'Invalid package metadata');
        report.version = requestedVersion || 'latest';
        recordInstallTrace(report, level, 'FAIL', 'Invalid package metadata');
        return null;
      }

      const version = requestedVersion && meta.versions[requestedVersion]
        ? requestedVersion : meta['dist-tags'].latest;
      if (requestedVersion && !meta.versions[requestedVersion])
        log(`Version ${requestedVersion} not found, using latest: ${version}`, 'warn');

      report.version = version;
      const versionMeta  = meta.versions[version];
      const tarballUrl   = versionMeta.dist.tarball;
      const integrity    = versionMeta.dist.integrity || null;
      // npm 배포 시각 — trust-cache TTL + 24h 재검증에 사용
      const publishedAt  = meta.time?.[version] ?? null;

      if (shouldRunDeepChecks(level)) {
        // ④ Version Diff
        const diff = await analyzeVersionDiff(pkgName, version);
        if (!diff.skipped && !diff.clean) {
          const criticals = diff.findings.filter(f => f.severity === 'CRITICAL');
          if (criticals.length > 0) {
            stepDone('fail', 'Version Diff — dangerous pattern added');
            printBlockCard(pkgName, 'version_diff', {
              version, pattern: criticals[0]?.pattern,
              extra: `${criticals.length} critical pattern(s) added`,
            });
            report.blocked.push({ pkg: pkgName, reason: 'version_diff', severity: 'CRITICAL', pattern: criticals[0]?.pattern });
            recordInstallTrace(report, level, 'BLOCK', 'Dangerous version diff', {
              findings: criticals.slice(0, 5),
            });
            return null;
          }
        }
        report.passed.push('Version diff');

        // ⑤ Hash Verification
        const hash = await verifyHash(pkgName, version, tarballUrl, integrity);
        if (hash.verified === false) {
          stepDone('fail', 'Hash — integrity check failed');
          printBlockCard(pkgName, 'hash', { version });
          report.blocked.push({ pkg: pkgName, reason: 'hash', severity: 'CRITICAL' });
          recordInstallTrace(report, level, 'BLOCK', 'Integrity mismatch');
          return null;
        }
        report.passed.push('Hash verification');

        // ⑥ Stealth Backdoor
        const stealth = await detectStealth(pkgName, tarballUrl);
        if (!stealth.skipped && !stealth.clean) {
          const criticals = stealth.findings.filter(f => f.severity === 'CRITICAL');
          if (criticals.length > 0) {
            stepDone('fail', 'Stealth — backdoor pattern detected');
            printBlockCard(pkgName, 'stealth', { version, pattern: criticals[0]?.pattern });
            report.blocked.push({ pkg: pkgName, reason: 'stealth', severity: 'CRITICAL', pattern: criticals[0]?.pattern });
            recordInstallTrace(report, level, 'BLOCK', 'Stealth backdoor pattern', {
              findings: criticals.slice(0, 5),
            });
            return null;
          }
        }
        report.passed.push('Stealth scan');

        // ⑦ Maintainer Monitor
        const maintainer = await checkMaintainerChange(pkgName, version);
        if (maintainer?.risk === 'CRITICAL') {
          stepDone('fail', 'Maintainer — suspicious change detected');
          printBlockCard(pkgName, 'maintainer', { version });
          report.blocked.push({ pkg: pkgName, reason: 'maintainer', severity: 'CRITICAL' });
          recordInstallTrace(report, level, 'BLOCK', 'Maintainer takeover risk', { maintainer });
          return null;
        }
        report.passed.push('Maintainer check');
        stepDone('ok', 'Full security checks passed');
      } else {
        report.passed.push('Fast preflight');
        if (detailedOutput) stepDone('ok', 'Fast preflight passed');
      }

      // ── ② Lifecycle protection ─────────────────────
      const scripts      = versionMeta.scripts || {};
      const blockedHooks = Object.keys(scripts).filter(h => DANGEROUS_HOOKS.includes(h));
      let   blockedCount = 0;

      if (detailedOutput && blockedHooks.length > 0) {
        stepStart('②', 'Lifecycle protection');
      }

      for (const hook of blockedHooks) {
        const cmd = scripts[hook];

        // 1. 하드코딩 whitelist fast-pass
        // 1. fast-pass (하드코딩 whitelist)
        if (isFastPass(pkgName, cmd, level)) {
          if (detailedOutput) stepDone('ok', `${pkgName} — ${hook}: fast-pass  [${getFastPassSource(pkgName)}]`);
          continue;
        }

        const assessment = trustCache.assessScript(cmd, hook, level);
        const cached = trustCache.lookup(pkgName, version, hook, cmd, this.cwd, { quiet: level < 3 });

        if (assessment.action === 'block') {
          stepDone('fail', `${pkgName} — ${hook}: BLOCKED  [${formatRisk(assessment)}]`);
          sandbox.blockLifecycleScript(pkgName, `${hook}: ${cmd}`);
          report.blocked.push({
            pkg: pkgName,
            reason: 'lifecycle',
            hook,
            cmd,
            severity: 'WARN',
            risk: assessment.risk.score,
            signals: assessment.risk.reasons,
          });
          trustCache.record(pkgName, version, hook, cmd, 'user_blocked', this.cwd, publishedAt);
          blockedCount++;
          continue;
        }

        if (cached.found && cached.autoBlock) {
          // 이전에 차단 결정 → 즉시 차단
          stepDone('fail', `${pkgName} — ${hook}: BLOCKED  [trust cache]`);
          sandbox.blockLifecycleScript(pkgName, `${hook}: ${cmd}`);
          report.blocked.push({ pkg: pkgName, reason: 'lifecycle', hook, cmd, severity: 'WARN' });
          blockedCount++;
          continue;
        }

        if (assessment.action === 'warn') {
          stepDone('warn', `${pkgName} — ${hook}: allowed with warning  [${formatRisk(assessment)}]`);
          report.warnings.push({
            pkg: pkgName,
            hook,
            cmd,
            risk: assessment.risk.score,
            signals: assessment.risk.reasons,
          });
          trustCache.record(pkgName, version, hook, cmd, 'risk_warned', this.cwd, publishedAt);
          continue;
        }

        if (cached.found && cached.shouldAsk) {
          // 이전 기록 있음 → 사용자에게 제안 (자동 허용 절대 없음, Enter = No)
          const decision = await trustCache.askUser(pkgName, version, hook, cmd, this.cwd);
          if (decision === 'block') {
            sandbox.blockLifecycleScript(pkgName, `${hook}: ${cmd}`);
            report.blocked.push({ pkg: pkgName, reason: 'lifecycle', hook, cmd, severity: 'WARN' });
            blockedCount++;
          }
          continue;
        }

        // Low-risk first-seen scripts pass in developer-friendly levels.
        if (detailedOutput) stepDone('ok', `${pkgName} — ${hook}: allowed  [${formatRisk(assessment)}]`);
        trustCache.record(pkgName, version, hook, cmd, 'risk_allowed', this.cwd, publishedAt);
      }

      if (blockedHooks.length > 0) executionTracker.recordBlocked(pkgName, blockedHooks);

      if (shouldRunDeepChecks(level)) {
        await this._checkDeps(pkgName, versionMeta, 0, new Set([pkgName]), report, level);
      }

      // ── 다운로드 + 저장 ────────────────────────────
      networkAnalyzer.start(pkgName);
      const extractPath    = await downloadAndExtract(pkgName, version, tarballUrl);
      const pkgExtractPath = path.join(extractPath, 'package');
      this.storage.store(pkgName, pkgExtractPath);
      cleanup(extractPath);
      networkAnalyzer.stop();
      networkAnalyzer.report();

      profiler.recordInstall(pkgName, version);
      advisor.printAdaptiveSummary(pkgName, version);

      report.duration = Date.now() - startTime;
      if (shouldShowDetailedOutput(level, report)) {
        const decision = report.blocked.length > 0 ? 'BLOCK' : 'WARN';
        const reason = report.blocked.length > 0
          ? 'Install completed with blocked behavior'
          : 'Install completed with warnings';
        recordInstallTrace(report, level, decision, reason);
        finalSummary(report.blocked.length, report.scanned);
        printSecurityReport(report);
      } else {
        printConciseSuccess(pkgName, version, report.duration);
      }

      return { name: pkgName, version };

    } catch (err) {
      log(`Install failed: ${err.message}`, 'error');
      report.duration = Date.now() - startTime;
      recordInstallTrace(report, level, 'FAIL', err.message, {
        error: {
          name: err.name,
          message: err.message,
          stack: err.stack,
        },
      });
      throw err;
    }
  }

  async _checkDeps(parentName, versionMeta, depth, visited, report, level) {
    if (depth > 3) return;

    const allDeps = {
      ...versionMeta.dependencies,
      ...versionMeta.devDependencies,
      ...versionMeta.optionalDependencies,
    };

    const depNames = Object.keys(allDeps).filter(d => !visited.has(d));
    if (depNames.length === 0) return;

    if (depth === 0) log(`Scanning dependency tree of ${parentName}...`);

    for (const dep of depNames) {
      visited.add(dep);
      report.scanned++;

      // 하드코딩 whitelist → 재귀 스캔 skip
      if (level < 3 && FAST_WHITELIST.has(dep)) {
        stepDone('ok', `${dep} — fast-pass  [known safe]`);
        continue;
      }

      try {
        const depMeta        = await fetchMeta(dep);
        if (!depMeta?.['dist-tags']?.latest) continue;

        const depVersion     = depMeta['dist-tags'].latest;
        const depVersionMeta = depMeta.versions[depVersion];
        const depScripts     = depVersionMeta?.scripts || {};
        const depPublishedAt = depMeta.time?.[depVersion] ?? null;
        const hooks = Object.keys(depScripts).filter(h => DANGEROUS_HOOKS.includes(h));

        for (const hook of hooks) {
          const cmd = depScripts[hook];

          if (isFastPass(dep, cmd, level)) {
            stepDone('ok', `${dep} — ${hook}: fast-pass  [${getFastPassSource(dep)}]`);
            continue;
          }

          const assessment2 = trustCache.assessScript(cmd, hook, level);
          const cached2 = trustCache.lookup(dep, depVersion, hook, cmd, this.cwd, { quiet: level < 3 });

          if (assessment2.action === 'block') {
            sandbox.blockLifecycleScript(dep, `${hook}: ${cmd}`);
            stepDone('fail', `${dep} — ${hook}: BLOCKED  [${formatRisk(assessment2)}]`);
            report.blocked.push({
              pkg: dep,
              reason: 'lifecycle',
              hook,
              cmd,
              severity: 'WARN',
              risk: assessment2.risk.score,
              signals: assessment2.risk.reasons,
            });
            trustCache.record(dep, depVersion, hook, cmd, 'user_blocked', this.cwd, depPublishedAt);
          } else if (cached2.found && cached2.autoBlock) {
            sandbox.blockLifecycleScript(dep, `${hook}: ${cmd}`);
            stepDone('fail', `${dep} — ${hook}: BLOCKED  [trust cache]`);
            report.blocked.push({ pkg: dep, reason: 'lifecycle', hook, cmd, severity: 'WARN' });
          } else if (assessment2.action === 'warn') {
            stepDone('warn', `${dep} — ${hook}: allowed with warning  [${formatRisk(assessment2)}]`);
            report.warnings.push({
              pkg: dep,
              hook,
              cmd,
              risk: assessment2.risk.score,
              signals: assessment2.risk.reasons,
            });
            trustCache.record(dep, depVersion, hook, cmd, 'risk_warned', this.cwd, depPublishedAt);
          } else {
            if (cached2.found && cached2.shouldAsk) {
              stepDone('warn', `${dep} — ${hook}: seen before — allow? (run interactively)`);
            } else {
              stepDone('ok', `${dep} — ${hook}: allowed  [${formatRisk(assessment2)}]`);
              trustCache.record(dep, depVersion, hook, cmd, 'risk_allowed', this.cwd, depPublishedAt);
            }
          }
        }

        if (depth < 3) {
          await this._checkDeps(dep, depVersionMeta, depth + 1, visited, report, level);
        }
      } catch {
        // 개별 의존성 실패 무시
      }
    }
  }
}

module.exports = Installer;
