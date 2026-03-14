'use strict';

const https = require('https');
const { detectConfusion }        = require('./confusion-detector');
const { verifyHash }             = require('./hash-verifier');
const { analyzeVersionDiff }     = require('./version-diff-analyzer');
const { detectStealth }          = require('./stealth-detector');
const { checkMaintainerChange }  = require('./maintainer-monitor');
const auditor                    = require('./auditor');
const logger = require('./logger');

/**
 * Checker
 * 설치 없이 패키지 위험도만 분석 (dryinstall check <pkg>)
 * CI/CD 파이프라인에서 --json 옵션과 함께 사용
 */

function fetchMeta(pkgName) {
  return new Promise((resolve, reject) => {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName).replace('%40', '@')}`;
    https.get(url, { headers: { 'User-Agent': 'dryinstall-checker' } }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Failed to parse registry response')); }
      });
    }).on('error', reject);
  });
}

/**
 * 단일 패키지 전체 분석 (설치 없음)
 * @param {string} rawPkg  - "express" or "express@4.18.2"
 * @param {object} opts    - { json: bool, silent: bool }
 * @returns {object}       - 분석 결과
 */
async function check(rawPkg, opts = {}) {
  const { json = false, silent = false } = opts;

  // pkg@version 파싱
  let pkgName, version;
  if (rawPkg.startsWith('@')) {
    const parts = rawPkg.split('@');
    pkgName = '@' + parts[1];
    version = parts[2] || null;
  } else {
    const idx = rawPkg.indexOf('@');
    pkgName = idx > 0 ? rawPkg.slice(0, idx) : rawPkg;
    version = idx > 0 ? rawPkg.slice(idx + 1) : null;
  }

  const result = {
    package:   pkgName,
    version:   version || 'latest',
    timestamp: new Date().toISOString(),
    checks:    {},
    summary:   { passed: 0, warned: 0, failed: 0 },
    verdict:   'SAFE',   // SAFE | WARN | BLOCK
    blockReasons: [],
  };

  const log = (...a) => { if (!silent && !json) logger.always(a.join(' ')); };
  const C = {
    RESET: '\x1b[0m', RED: '\x1b[31m', GREEN: '\x1b[32m',
    YELLOW: '\x1b[33m', CYAN: '\x1b[36m', BOLD: '\x1b[1m',
  };

  if (!json) {
    log(`\n${C.CYAN}${C.BOLD}[dryinstall:check] Analyzing ${rawPkg}${C.RESET}`);
    log(`${C.CYAN}${'─'.repeat(52)}${C.RESET}`);
  }

  // ── 1. Registry 메타 조회 ──────────────────────────
  let meta;
  try {
    meta = await fetchMeta(pkgName);
    result.checks.registry = { status: 'ok', exists: true };
    log(`${C.GREEN}  ✓  Registry    package found${C.RESET}`);
    result.summary.passed++;
  } catch (e) {
    result.checks.registry = { status: 'error', message: e.message };
    result.verdict = 'WARN';
    result.summary.warned++;
    log(`${C.YELLOW}  ⚠  Registry    could not reach registry${C.RESET}`);
  }

  // ── 2. CVE Audit ──────────────────────────────────
  try {
    const audit = auditor.audit(pkgName, version);
    const hasCritical = audit.vulnerabilities.some(v =>
      ['critical', 'high'].includes(v.severity)
    );
    result.checks.cve = {
      status: hasCritical ? 'fail' : 'ok',
      vulnerabilities: audit.vulnerabilities,
    };
    if (hasCritical) {
      result.verdict = 'BLOCK';
      result.blockReasons.push('Known critical/high CVE vulnerabilities');
      result.summary.failed++;
      log(`${C.RED}  ✗  CVE Audit   critical vulnerabilities found${C.RESET}`);
    } else {
      result.summary.passed++;
      log(`${C.GREEN}  ✓  CVE Audit   no known critical vulnerabilities${C.RESET}`);
    }
  } catch (e) {
    result.checks.cve = { status: 'error', message: e.message };
    result.summary.warned++;
    log(`${C.YELLOW}  ⚠  CVE Audit   could not complete audit${C.RESET}`);
  }

  // ── 3. Lifecycle Scripts ──────────────────────────
  try {
    const latest = version
      ? meta?.versions?.[version]
      : meta?.versions?.[meta?.['dist-tags']?.latest];

    const scripts = latest?.scripts || {};
    const HOOKS = ['preinstall','install','postinstall','prepare','prepublish','prepack'];
    const foundHooks = HOOKS.filter(h => scripts[h]);

    result.checks.lifecycle = {
      status: foundHooks.length > 0 ? 'warn' : 'ok',
      hooks: foundHooks,
      scripts: Object.fromEntries(foundHooks.map(h => [h, scripts[h]])),
    };

    if (foundHooks.length > 0) {
      result.verdict = result.verdict === 'SAFE' ? 'WARN' : result.verdict;
      result.summary.warned++;
      log(`${C.YELLOW}  ⚠  Lifecycle   ${foundHooks.join(', ')} detected${C.RESET}`);
      foundHooks.forEach(h => log(`       ${h}: ${scripts[h]}`));
    } else {
      result.summary.passed++;
      log(`${C.GREEN}  ✓  Lifecycle   no install-time scripts${C.RESET}`);
    }
  } catch (e) {
    result.checks.lifecycle = { status: 'error', message: e.message };
    result.summary.warned++;
  }

  // ── 4. Dependency Confusion ───────────────────────
  try {
    const confusion = await detectConfusion(pkgName);
    result.checks.confusion = { status: confusion.risk === 'HIGH' ? 'fail' : 'ok', ...confusion };
    if (confusion.risk === 'HIGH') {
      result.verdict = 'BLOCK';
      result.blockReasons.push('Dependency Confusion attack detected');
      result.summary.failed++;
      log(`${C.RED}  ✗  Confusion   dependency confusion attack detected${C.RESET}`);
    } else {
      result.summary.passed++;
      log(`${C.GREEN}  ✓  Confusion   no confusion attack detected${C.RESET}`);
    }
  } catch (e) {
    result.checks.confusion = { status: 'error', message: e.message };
    result.summary.warned++;
  }

  // ── 5. Maintainer Monitor ─────────────────────────
  try {
    const maintainer = await checkMaintainerChange(pkgName);
    const isCritical = maintainer?.risk === 'CRITICAL';
    result.checks.maintainer = { status: isCritical ? 'fail' : 'ok', ...maintainer };
    if (isCritical) {
      result.verdict = 'BLOCK';
      result.blockReasons.push('Maintainer takeover detected');
      result.summary.failed++;
      log(`${C.RED}  ✗  Maintainer  full maintainer replacement detected${C.RESET}`);
    } else {
      result.summary.passed++;
      log(`${C.GREEN}  ✓  Maintainer  no suspicious maintainer changes${C.RESET}`);
    }
  } catch (e) {
    result.checks.maintainer = { status: 'error', message: e.message };
    result.summary.warned++;
  }

  // ── 결과 출력 ─────────────────────────────────────
  result.ciExitCode = result.verdict === 'BLOCK' ? 1 : 0;

  if (json) {
    _restoreConsole();
    if (!silent) process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    const color = result.verdict === 'SAFE'
      ? C.GREEN
      : result.verdict === 'WARN'
        ? C.YELLOW
        : C.RED;

    log(`\n${C.CYAN}${'─'.repeat(52)}${C.RESET}`);
    log(`${C.BOLD}  Verdict: ${color}${result.verdict}${C.RESET}`);
    log(`  Passed:  ${result.summary.passed}`);
    log(`  Warned:  ${result.summary.warned}`);
    log(`  Failed:  ${result.summary.failed}`);

    if (result.blockReasons.length > 0) {
      log(`\n${C.RED}  Block reasons:${C.RESET}`);
      result.blockReasons.forEach(r => log(`    - ${r}`));
    }

    if (result.checks.lifecycle?.hooks?.length > 0) {
      log(`\n${C.YELLOW}  To install anyway:${C.RESET}`);
      log(`    dryinstall install ${pkgName} --interactive`);
    }
    log('');
  }

  _restoreConsole();
  return result;
}

/**
 * 여러 패키지 동시 분석
 * @param {string[]} pkgs
 * @param {object}   opts
 */
async function checkMultiple(pkgs, opts = {}) {
  const results = [];
  for (const pkg of pkgs) {
    const r = await check(pkg, { ...opts, silent: opts.json });
    results.push(r);
  }

  if (opts.json) {
    // CI용 JSON 출력
    const output = {
      timestamp: new Date().toISOString(),
      packages: results,
      summary: {
        total:   results.length,
        safe:    results.filter(r => r.verdict === 'SAFE').length,
        warn:    results.filter(r => r.verdict === 'WARN').length,
        blocked: results.filter(r => r.verdict === 'BLOCK').length,
      },
      ciExitCode: results.some(r => r.verdict === 'BLOCK') ? 1 : 0,
    };
    process.stdout.write(JSON.stringify(output, null, 2) + '\n');
    return output;
  }

  return results;
}

module.exports = { check, checkMultiple };