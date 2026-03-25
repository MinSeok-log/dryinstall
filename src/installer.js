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
    2: 'Balanced  — malicious only, whitelist fast-pass',
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
    this.level   = parseInt(process.env.DRYINSTALL_LEVEL ?? '3', 10);
  }

  async install(rawPkgName) {
    const { pkgName, version: requestedVersion } = parsePkgName(rawPkgName);
    const startTime = Date.now();
    const level = this.level;

    const report = {
      pkg: pkgName, version: null,
      scanned: 1, blocked: [], passed: [],
      duration: 0,
    };

    try {
      banner(pkgName, requestedVersion, level);
      // 버전 바뀌면 trust cache 무효화
      if (requestedVersion) trustCache.invalidate(pkgName, requestedVersion);

      // ── ①~⑦ 보안 스캔 ─────────────────────────────
      if (level >= 2) {
        stepStart('①~⑦', 'Running security checks in parallel');
      }

      // ① CVE Audit
      const auditResult = auditor.audit(pkgName, requestedVersion);
      if (!auditResult.safe) {
        if (level >= 2) stepDone('fail', 'CVE — known vulnerability found');
        else { stepStart('①', 'CVE Audit'); stepDone('fail', 'Known vulnerability found'); }
        printBlockCard(pkgName, 'cve', { version: requestedVersion });
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
        return null;
      }

      if (!meta?.['dist-tags']?.latest) {
        stepDone('fail', 'Invalid package metadata');
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

      // ④ Version Diff
      const diff = await analyzeVersionDiff(pkgName, version);
      if (!diff.skipped && !diff.clean) {
        const criticals = diff.findings.filter(f => f.severity === 'CRITICAL');
        if (criticals.length > 0) {
          if (level >= 2) stepDone('fail', 'Version Diff — dangerous pattern added');
          else { stepStart('④', 'Version Diff'); stepDone('fail', 'Dangerous pattern added'); }
          printBlockCard(pkgName, 'version_diff', {
            version, pattern: criticals[0]?.pattern,
            extra: `${criticals.length} critical pattern(s) added`,
          });
          return null;
        }
      }
      if (level < 2) { stepStart('④', 'Version Diff'); stepDone('ok', 'No new dangerous patterns'); }
      report.passed.push('Version diff');

      // ⑤ Hash Verification
      const hash = await verifyHash(pkgName, version, tarballUrl, integrity);
      if (hash.verified === false) {
        if (level >= 2) stepDone('fail', 'Hash — integrity check failed');
        else { stepStart('⑤', 'Hash Verification'); stepDone('fail', 'Integrity check failed'); }
        printBlockCard(pkgName, 'hash', { version });
        return null;
      }
      if (level < 2) { stepStart('⑤', 'Hash Verification'); stepDone('ok', 'Integrity verified'); }
      report.passed.push('Hash verification');

      // ⑥ Stealth Backdoor
      const stealth = await detectStealth(pkgName, tarballUrl);
      if (!stealth.skipped && !stealth.clean) {
        const criticals = stealth.findings.filter(f => f.severity === 'CRITICAL');
        if (criticals.length > 0) {
          if (level >= 2) stepDone('fail', 'Stealth — backdoor pattern detected');
          else { stepStart('⑥', 'Stealth Detection'); stepDone('fail', 'Backdoor detected'); }
          printBlockCard(pkgName, 'stealth', { version, pattern: criticals[0]?.pattern });
          return null;
        }
      }
      if (level < 2) { stepStart('⑥', 'Stealth Detection'); stepDone('ok', 'Clean'); }
      report.passed.push('Stealth scan');

      // ⑦ Maintainer Monitor
      const maintainer = await checkMaintainerChange(pkgName, version);
      if (maintainer?.risk === 'CRITICAL') {
        if (level >= 2) stepDone('fail', 'Maintainer — suspicious change detected');
        else { stepStart('⑦', 'Maintainer Monitor'); stepDone('fail', 'Suspicious change'); }
        printBlockCard(pkgName, 'maintainer', { version });
        return null;
      }
      if (level < 2) { stepStart('⑦', 'Maintainer Monitor'); stepDone('ok', 'No suspicious changes'); }
      report.passed.push('Maintainer check');

      if (level >= 2) stepDone('ok', 'All 7 checks passed');

      // ── ⑧ Lifecycle Block ──────────────────────────
      stepStart('⑧', 'Lifecycle Script Analysis');

      const scripts      = versionMeta.scripts || {};
      const blockedHooks = Object.keys(scripts).filter(h => DANGEROUS_HOOKS.includes(h));
      let   blockedCount = 0;

      for (const hook of blockedHooks) {
        const cmd = scripts[hook];

        // 1. 하드코딩 whitelist fast-pass
        // 1. fast-pass (하드코딩 whitelist)
        if (isFastPass(pkgName, cmd, level)) {
          stepDone('ok', `${pkgName} — ${hook}: fast-pass  [${getFastPassSource(pkgName)}]`);
          continue;
        }

        // 2. behavior fingerprint — 즉시 차단 대상
        const fp = trustCache.analyzeFingerprint(cmd);
        const cls = trustCache.classifyScript(cmd, fp);

        if (cls === trustCache.CLASSIFICATION.SUSPICIOUS) {
          stepDone('fail', `${pkgName} — ${hook}: BLOCKED  [suspicious pattern]`);
          sandbox.blockLifecycleScript(pkgName, `${hook}: ${cmd}`);
          report.blocked.push({ pkg: pkgName, reason: 'lifecycle', hook, cmd, severity: 'WARN' });
          trustCache.record(pkgName, version, hook, cmd, 'user_blocked', this.cwd, publishedAt);
          blockedCount++;
          continue;
        }

        // 3. trust cache 조회 (version + scriptHash + refFileHash + context 완전 일치)
        const cached = trustCache.lookup(pkgName, version, hook, cmd, this.cwd);

        if (cached.found && cached.autoBlock) {
          // 이전에 차단 결정 → 즉시 차단
          stepDone('fail', `${pkgName} — ${hook}: BLOCKED  [trust cache]`);
          sandbox.blockLifecycleScript(pkgName, `${hook}: ${cmd}`);
          report.blocked.push({ pkg: pkgName, reason: 'lifecycle', hook, cmd, severity: 'WARN' });
          blockedCount++;
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

        // 4. 처음 보는 스크립트 → 차단 + cache 기록
        stepDone('fail', `${pkgName} — ${hook}: BLOCKED  →  ${cmd.slice(0, 40)}`);
        sandbox.blockLifecycleScript(pkgName, `${hook}: ${cmd}`);
        report.blocked.push({ pkg: pkgName, reason: 'lifecycle', hook, cmd, severity: 'WARN' });
        trustCache.record(pkgName, version, hook, cmd, 'user_blocked', this.cwd, publishedAt);
        blockedCount++;
      }

      if (blockedHooks.length > 0) executionTracker.recordBlocked(pkgName, blockedHooks);

      await this._checkDeps(pkgName, versionMeta, 0, new Set([pkgName]), report, level);

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
      finalSummary(report.blocked.length, report.scanned);
      printSecurityReport(report);

      return { name: pkgName, version };

    } catch (err) {
      log(`Install failed: ${err.message}`, 'error');
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

          // behavior fingerprint
          const fp2 = trustCache.analyzeFingerprint(cmd);
          const cls2 = trustCache.classifyScript(cmd, fp2);

          if (cls2 === trustCache.CLASSIFICATION.SUSPICIOUS) {
            sandbox.blockLifecycleScript(dep, `${hook}: ${cmd}`);
            stepDone('fail', `${dep} — ${hook}: BLOCKED  [suspicious]`);
            report.blocked.push({ pkg: dep, reason: 'lifecycle', hook, cmd, severity: 'WARN' });
            trustCache.record(dep, depVersion, hook, cmd, 'user_blocked', this.cwd, depPublishedAt);
          } else if (level >= 3) {
            sandbox.blockLifecycleScript(dep, `${hook}: ${cmd}`);
            stepDone('warn', `${dep} — ${hook}: blocked (level 3)`);
            report.blocked.push({ pkg: dep, reason: 'lifecycle', hook, cmd, severity: 'WARN' });
          } else {
            const cached2 = trustCache.lookup(dep, depVersion, hook, cmd, this.cwd);
            if (cached2.found && cached2.shouldAsk) {
              stepDone('warn', `${dep} — ${hook}: seen before — allow? (run interactively)`);
            } else {
              sandbox.blockLifecycleScript(dep, `${hook}: ${cmd}`);
              stepDone('warn', `${dep} — ${hook}: blocked`);
              report.blocked.push({ pkg: dep, reason: 'lifecycle', hook, cmd, severity: 'WARN' });
              trustCache.record(dep, depVersion, hook, cmd, 'user_blocked', this.cwd, depPublishedAt);
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