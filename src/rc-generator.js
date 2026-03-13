'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const readline = require('readline');

const RC_PATH = path.join(os.homedir(), '.dryinstallrc');
const THRESHOLDS = {
  alwaysAllowAfter: 3,      // N번 이상 설치 + 경고 무시 → alwaysAllow 후보
  ignoreRateHigh: 0.7,      // 70% 이상 무시 → 경고 유형 축소 후보
  minInstalls: 5,           // 프로파일 최소 데이터 기준
};

// ── RC 파일 로드 ──────────────────────────────────────
function loadRC() {
  try {
    if (fs.existsSync(RC_PATH)) {
      return JSON.parse(fs.readFileSync(RC_PATH, 'utf-8'));
    }
  } catch {}
  return { alwaysAllow: [], alwaysBlock: [] };
}

// ── RC 파일 저장 ──────────────────────────────────────
function saveRC(rc) {
  fs.writeFileSync(RC_PATH, JSON.stringify(rc, null, 2));
}

// ── 추천 분석 ─────────────────────────────────────────

/**
 * profiler 데이터 기반으로 .dryinstallrc 추천 생성
 */
function generateSuggestions(profile) {
  const suggestions = {
    alwaysAllow: [],    // lifecycle 허용 추천 패키지
    suppressTypes: [],  // 경고 축소 추천 유형
    highlights: [],     // 주목할 것
  };

  const existing = loadRC();

  // ① 자주 설치 + 경고 무시한 패키지 → alwaysAllow 추천
  for (const [pkgName, data] of Object.entries(profile.packages || {})) {
    if (existing.alwaysAllow?.includes(pkgName)) continue;
    if (existing.alwaysBlock?.includes(pkgName)) continue;

    if (
      data.installCount >= THRESHOLDS.alwaysAllowAfter &&
      data.warningsIgnored.includes('lifecycle')
    ) {
      suggestions.alwaysAllow.push({
        pkg: pkgName,
        count: data.installCount,
        reason: `installed ${data.installCount}x, lifecycle always allowed`,
      });
    }
  }

  // 설치 횟수 내림차순 정렬
  suggestions.alwaysAllow.sort((a, b) => b.count - a.count);

  // ② 경고 유형별 무시율 → suppressTypes 추천
  for (const [type, data] of Object.entries(profile.warningBehavior || {})) {
    if (data.shown === 0) continue;
    const rate = data.ignored / data.shown;
    if (rate >= THRESHOLDS.ignoreRateHigh) {
      suggestions.suppressTypes.push({
        type,
        rate: Math.round(rate * 100),
        reason: `ignored ${data.ignored}/${data.shown} times`,
      });
    }
  }

  // ③ 한 번도 허용 안 한 패키지 (alwaysBlock 후보 강조)
  for (const [pkgName, data] of Object.entries(profile.packages || {})) {
    if (existing.alwaysBlock?.includes(pkgName)) continue;
    if (data.installCount >= 2 && profile.stats?.totalBlocked > 0) {
      // recentEvents에서 이 패키지가 차단된 이력 확인
      const blocked = (profile.recentEvents || [])
        .filter(e => e.type === 'blocked' && e.pkg === pkgName);
      if (blocked.length >= 2) {
        suggestions.highlights.push({
          pkg: pkgName,
          message: `Blocked ${blocked.length}x — consider adding to alwaysBlock`,
        });
      }
    }
  }

  return suggestions;
}

/**
 * 추천 출력 + 대화형 적용
 * dryinstall config suggest 명령어에서 호출
 */
async function suggestAndApply(profile) {
  const stats = profile.stats || {};

  if ((stats.totalInstalls || 0) < THRESHOLDS.minInstalls) {
    console.log('\n\x1b[33m  Not enough data yet.\x1b[0m');
    console.log(`\x1b[90m  Install at least ${THRESHOLDS.minInstalls} packages to get recommendations.\x1b[0m`);
    console.log(`\x1b[90m  Current: ${stats.totalInstalls || 0} installs\x1b[0m\n`);
    return;
  }

  const suggestions = generateSuggestions(profile);
  const existing = loadRC();

  if (suggestions.alwaysAllow.length === 0 && suggestions.suppressTypes.length === 0) {
    console.log('\n\x1b[32m  ✓ Your .dryinstallrc looks well-tuned. No suggestions.\x1b[0m\n');
    return;
  }

  console.log('\n\x1b[36m══════════════════════════════════════════════════════\x1b[0m');
  console.log('\x1b[36m  dryinstall — Adaptive .dryinstallrc Suggestions\x1b[0m');
  console.log('\x1b[36m══════════════════════════════════════════════════════\x1b[0m');
  console.log(`\x1b[90m  Based on ${stats.totalInstalls} installs since profile creation\x1b[0m\n`);

  // ── alwaysAllow 추천 출력 ──────────────────────────
  if (suggestions.alwaysAllow.length > 0) {
    console.log('\x1b[33m  Packages to add to alwaysAllow:\x1b[0m');
    console.log('\x1b[90m  (You always allow these — skip the prompt next time)\x1b[0m\n');
    suggestions.alwaysAllow.forEach((s, i) => {
      console.log(`\x1b[0m  [${i + 1}] \x1b[1m${s.pkg}\x1b[0m`);
      console.log(`\x1b[90m       ${s.reason}\x1b[0m`);
    });
  }

  // ── suppressTypes 추천 출력 ───────────────────────
  if (suggestions.suppressTypes.length > 0) {
    console.log('\n\x1b[33m  Warning types that are mostly noise for you:\x1b[0m\n');
    suggestions.suppressTypes.forEach(s => {
      const bar = '█'.repeat(Math.round(s.rate / 10)) + '░'.repeat(10 - Math.round(s.rate / 10));
      console.log(`\x1b[33m  ${s.type.padEnd(15)} ${bar} ${s.rate}% ignored\x1b[0m`);
      console.log(`\x1b[90m  → ${s.reason}\x1b[0m`);
    });
  }

  // ── highlights 출력 ───────────────────────────────
  if (suggestions.highlights.length > 0) {
    console.log('\n\x1b[31m  Packages you consistently block:\x1b[0m\n');
    suggestions.highlights.forEach(h => {
      console.log(`\x1b[31m  ${h.pkg}\x1b[0m`);
      console.log(`\x1b[90m  → ${h.message}\x1b[0m`);
    });
  }

  console.log('\n\x1b[36m══════════════════════════════════════════════════════\x1b[0m\n');

  // ── 대화형 적용 ───────────────────────────────────
  if (suggestions.alwaysAllow.length === 0) return;

  const answer = await prompt(
    '\x1b[1mApply these suggestions to ~/.dryinstallrc? [Y/n/select] \x1b[0m'
  );

  if (answer.toLowerCase() === 'n') {
    console.log('\x1b[90m  Skipped. Run "dryinstall config suggest" anytime.\x1b[0m\n');
    return;
  }

  let toAdd = suggestions.alwaysAllow.map(s => s.pkg);

  // 'select' 입력 시 개별 선택
  if (answer.toLowerCase() === 'select' || answer.toLowerCase() === 's') {
    toAdd = [];
    for (const s of suggestions.alwaysAllow) {
      const a = await prompt(`  Add \x1b[1m${s.pkg}\x1b[0m to alwaysAllow? [Y/n] `);
      if (a.toLowerCase() !== 'n') toAdd.push(s.pkg);
    }
  }

  if (toAdd.length === 0) {
    console.log('\x1b[90m  Nothing added.\x1b[0m\n');
    return;
  }

  // RC 업데이트
  if (!existing.alwaysAllow) existing.alwaysAllow = [];
  if (!existing.alwaysBlock) existing.alwaysBlock = [];

  const added = [];
  for (const pkg of toAdd) {
    if (!existing.alwaysAllow.includes(pkg)) {
      existing.alwaysAllow.push(pkg);
      added.push(pkg);
    }
  }

  saveRC(existing);

  console.log(`\n\x1b[32m  ✓ Updated ~/.dryinstallrc\x1b[0m`);
  added.forEach(p => console.log(`\x1b[32m    + alwaysAllow: ${p}\x1b[0m`));
  console.log('\n\x1b[90m  These packages will skip lifecycle prompts from now on.\x1b[0m\n');
}

/**
 * 설치 후 자동 힌트 출력 (조용하게 — 데이터 충분할 때만)
 * cli.js의 printAdaptiveSummary에서 호출
 */
function quickHint(profile) {
  if ((profile.stats?.totalInstalls || 0) < THRESHOLDS.minInstalls) return;

  const suggestions = generateSuggestions(profile);
  if (suggestions.alwaysAllow.length === 0 && suggestions.suppressTypes.length === 0) return;

  const total = suggestions.alwaysAllow.length + suggestions.suppressTypes.length;
  console.log(`\x1b[90m  💡 ${total} new suggestion(s) available → run "dryinstall config suggest"\x1b[0m`);
}

// ── 유틸 ──────────────────────────────────────────────
function prompt(question) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim() || 'y');
    });
  });
}

module.exports = { generateSuggestions, suggestAndApply, quickHint, loadRC };
