'use strict';

const profiler = require('./profiler');
const rcGenerator = require('./rc-generator');

/**
 * Adaptive Advisor — 개발자 행동 기반 적응형 추천
 */

const THRESHOLDS = {
  autoAllowAfter: 3,
  ignoreRateHigh: 0.7,
  ignoreRateLow: 0.1,
  familiarPackage: 3,
};

function advise(pkgName, version, warningType) {
  const advice = {
    suppressWarning: false,
    autoAllow: false,
    message: null,
    highlight: false,
  };

  const pkgProfile = profiler.getPackageProfile(pkgName);
  const ignoreRate = profiler.getWarningIgnoreRate(warningType);

  if (pkgProfile && pkgProfile.installCount >= THRESHOLDS.familiarPackage) {
    if (pkgProfile.warningsIgnored.includes(warningType)) {
      advice.autoAllow = pkgProfile.installCount >= THRESHOLDS.autoAllowAfter;
      advice.message = `Familiar package (installed ${pkgProfile.installCount}x). You've always allowed this.`;
    }
  }

  if (ignoreRate >= THRESHOLDS.ignoreRateHigh) {
    advice.suppressWarning = true;
    advice.message = advice.message ||
      `You've ignored this warning type ${Math.round(ignoreRate * 100)}% of the time. Reducing noise.`;
  }

  if (ignoreRate <= THRESHOLDS.ignoreRateLow && ignoreRate > 0) {
    advice.highlight = true;
  }

  if (!pkgProfile && ['stealth', 'confusion', 'hash'].includes(warningType)) {
    advice.highlight = true;
    advice.message = advice.message || `First time installing ${pkgName}. Pay attention to this warning.`;
  }

  return advice;
}

/**
 * 설치 후 요약 출력 + 자동 힌트
 */
function printAdaptiveSummary(pkgName, version) {
  const profile = require('fs').existsSync(
    require('path').join(require('os').homedir(), '.dryinstall-profile.json')
  ) ? JSON.parse(require('fs').readFileSync(
    require('path').join(require('os').homedir(), '.dryinstall-profile.json'), 'utf-8'
  )) : null;

  if (!profile || (profile.stats?.totalInstalls || 0) < 3) return;

  const pkgData = profile.packages?.[pkgName];
  const lines = [];

  if (pkgData && pkgData.installCount > 1) {
    lines.push(`  ${pkgName} — installed ${pkgData.installCount}x  (last: ${pkgData.lastInstalled})`);
  }

  if (lines.length > 0) {
    console.log('\n\x1b[36m── Adaptive Profile ──────────────────────────────────\x1b[0m');
    lines.forEach(l => console.log(`\x1b[90m${l}\x1b[0m`));
    // 자동 힌트 — 추천이 있으면 조용히 알림
    rcGenerator.quickHint(profile);
    console.log('\x1b[36m──────────────────────────────────────────────────────\x1b[0m');
  } else {
    // 라인 없어도 힌트는 출력
    rcGenerator.quickHint(profile);
  }
}

/**
 * dryinstall profile 명령어
 */
function printProfileReport() {
  const summary = profiler.getSummary();

  if (summary.totalInstalls === 0) {
    console.log('\n\x1b[33m  No profile data yet. Install some packages first.\x1b[0m\n');
    return;
  }

  const since = summary.since
    ? new Date(summary.since).toISOString().slice(0, 10)
    : 'unknown';

  console.log('\n\x1b[36m══════════════════════════════════════════════════\x1b[0m');
  console.log('\x1b[36m  dryinstall Developer Profile\x1b[0m');
  console.log('\x1b[36m══════════════════════════════════════════════════\x1b[0m');
  console.log(`\x1b[90m  Tracking since : ${since}\x1b[0m`);
  console.log(`\x1b[90m  Total installs : ${summary.totalInstalls}\x1b[0m`);
  console.log(`\x1b[90m  Project type   : ${summary.topProjectType}\x1b[0m`);
  console.log(`\x1b[90m  Version pref   : ${summary.prefersLatest ? 'Latest' : 'Stable'}\x1b[0m`);

  if (summary.topPackages.length > 0) {
    console.log('\n\x1b[36m  Most used packages:\x1b[0m');
    summary.topPackages.forEach(p => {
      console.log(`\x1b[90m    ${p.name.padEnd(30)} ${p.count}x\x1b[0m`);
    });
  }

  if (summary.ignoreRates.length > 0) {
    console.log('\n\x1b[36m  Warning behavior:\x1b[0m');
    summary.ignoreRates.forEach(r => {
      const bar = '█'.repeat(Math.round(r.rate * 10)) + '░'.repeat(10 - Math.round(r.rate * 10));
      const pct = Math.round(r.rate * 100);
      const color = pct >= 70 ? '\x1b[33m' : pct <= 10 ? '\x1b[32m' : '\x1b[90m';
      console.log(`${color}    ${r.type.padEnd(15)} ${bar} ${pct}% ignored\x1b[0m`);
    });
  }

  console.log('\n\x1b[90m  Run "dryinstall config suggest" to auto-tune .dryinstallrc\x1b[0m');
  console.log('\x1b[36m══════════════════════════════════════════════════\x1b[0m\n');
}

/**
 * dryinstall config suggest 명령어
 */
async function runSuggest() {
  const os = require('os');
  const path = require('path');
  const fs = require('fs');
  const profilePath = path.join(os.homedir(), '.dryinstall-profile.json');

  if (!fs.existsSync(profilePath)) {
    console.log('\n\x1b[33m  No profile data yet. Install some packages first.\x1b[0m\n');
    return;
  }

  const profile = JSON.parse(fs.readFileSync(profilePath, 'utf-8'));
  await rcGenerator.suggestAndApply(profile);
}

module.exports = { advise, printAdaptiveSummary, printProfileReport, runSuggest };

