'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Developer Profiler — 개발자 행동 누적 학습
 *
 * 수집하는 것:
 *   - 설치한 패키지 / 버전 / 날짜
 *   - 경고를 무시하고 설치한 패키지
 *   - 차단을 허용으로 바꾼 패키지
 *   - 프로젝트 유형 (frontend / backend / cli / library)
 *   - 선호하는 패키지 조합
 *   - 업데이트 주기 (안정성 중시 vs 최신 중시)
 *
 * 저장 위치: ~/.dryinstall-profile.json
 * 형식: 누적 이벤트 로그 + 집계 통계
 */

const PROFILE_PATH = path.join(os.homedir(), '.dryinstall-profile.json');

const DEFAULT_PROFILE = {
  version: 1,
  createdAt: null,
  updatedAt: null,

  // 누적 통계
  stats: {
    totalInstalls: 0,
    totalWarningsIgnored: 0,
    totalBlocked: 0,
    totalAllowed: 0,
  },

  // 패키지별 이력
  packages: {
    // "express": {
    //   installCount: 3,
    //   lastInstalled: "2026-03-11",
    //   warningsIgnored: ["stealth", "lifecycle"],
    //   alwaysAllowed: true,
    //   versions: ["4.18.2", "5.2.1"],
    // }
  },

  // 경고 유형별 무시 횟수
  warningBehavior: {
    lifecycle:    { shown: 0, ignored: 0 },
    stealth:      { shown: 0, ignored: 0 },
    confusion:    { shown: 0, ignored: 0 },
    maintainer:   { shown: 0, ignored: 0 },
    versionDiff:  { shown: 0, ignored: 0 },
    hash:         { shown: 0, ignored: 0 },
    typo:         { shown: 0, ignored: 0 },
  },

  // 프로젝트 유형 감지
  projectTypes: {
    // "backend": 12, "frontend": 3, "cli": 1
  },

  // 선호 패키지 조합 (자주 함께 설치되는 패키지)
  coinstallPatterns: {
    // "express+mongoose": 4
  },

  // 업데이트 성향
  updateBehavior: {
    prefersLatest: 0,    // 최신 버전 설치 횟수
    prefersStable: 0,    // 고정 버전 설치 횟수
    averageVersionAge: 0 // 설치한 버전의 평균 나이 (일)
  },

  // 최근 이벤트 로그 (최대 500개)
  recentEvents: [],
};

// ── 프로파일 로드 ──────────────────────────────────────
function load() {
  try {
    if (fs.existsSync(PROFILE_PATH)) {
      const raw = JSON.parse(fs.readFileSync(PROFILE_PATH, 'utf-8'));
      // 새 필드 병합 (버전 업그레이드 대응)
      return deepMerge(DEFAULT_PROFILE, raw);
    }
  } catch {}
  const profile = JSON.parse(JSON.stringify(DEFAULT_PROFILE));
  profile.createdAt = new Date().toISOString();
  return profile;
}

// ── 프로파일 저장 ─────────────────────────────────────
function save(profile) {
  try {
    profile.updatedAt = new Date().toISOString();
    // 이벤트 로그 최대 500개 유지
    if (profile.recentEvents.length > 500) {
      profile.recentEvents = profile.recentEvents.slice(-500);
    }
    fs.writeFileSync(PROFILE_PATH, JSON.stringify(profile, null, 2));
  } catch {}
}

// ── 이벤트 기록 ───────────────────────────────────────

/**
 * 패키지 설치 완료 이벤트
 */
function recordInstall(pkgName, version, warnings = []) {
  const profile = load();

  profile.stats.totalInstalls++;

  // 패키지 이력 업데이트
  if (!profile.packages[pkgName]) {
    profile.packages[pkgName] = {
      installCount: 0,
      lastInstalled: null,
      warningsIgnored: [],
      versions: [],
    };
  }
  const pkg = profile.packages[pkgName];
  pkg.installCount++;
  pkg.lastInstalled = new Date().toISOString().slice(0, 10);
  if (!pkg.versions.includes(version)) pkg.versions.push(version);

  // 경고 무시 기록
  warnings.forEach(w => {
    if (!pkg.warningsIgnored.includes(w)) pkg.warningsIgnored.push(w);
    if (profile.warningBehavior[w]) {
      profile.warningBehavior[w].ignored++;
    }
  });

  // 버전 선호 성향 분석
  if (version && !version.includes('-')) {
    profile.updateBehavior.prefersStable++;
  } else {
    profile.updateBehavior.prefersLatest++;
  }

  // 이벤트 로그
  profile.recentEvents.push({
    type: 'install',
    pkg: pkgName,
    version,
    warnings,
    at: new Date().toISOString(),
  });

  // 프로젝트 유형 감지
  const projectType = detectProjectType();
  if (projectType) {
    profile.projectTypes[projectType] = (profile.projectTypes[projectType] || 0) + 1;
  }

  save(profile);
}

/**
 * 경고 표시 이벤트
 */
function recordWarningShown(pkgName, warningType) {
  const profile = load();
  if (profile.warningBehavior[warningType]) {
    profile.warningBehavior[warningType].shown++;
  }
  save(profile);
}

/**
 * 경고 무시 (사용자가 Y 선택) 이벤트
 */
function recordWarningIgnored(pkgName, warningType) {
  const profile = load();

  profile.stats.totalWarningsIgnored++;
  if (profile.warningBehavior[warningType]) {
    profile.warningBehavior[warningType].ignored++;
  }

  if (!profile.packages[pkgName]) {
    profile.packages[pkgName] = { installCount: 0, lastInstalled: null, warningsIgnored: [], versions: [] };
  }
  if (!profile.packages[pkgName].warningsIgnored.includes(warningType)) {
    profile.packages[pkgName].warningsIgnored.push(warningType);
  }

  profile.recentEvents.push({
    type: 'warning_ignored',
    pkg: pkgName,
    warningType,
    at: new Date().toISOString(),
  });

  save(profile);
}

/**
 * 차단 이벤트
 */
function recordBlocked(pkgName, reason) {
  const profile = load();
  profile.stats.totalBlocked++;
  profile.recentEvents.push({
    type: 'blocked',
    pkg: pkgName,
    reason,
    at: new Date().toISOString(),
  });
  save(profile);
}

/**
 * 함께 설치된 패키지 조합 기록
 */
function recordCoinstall(pkgNames) {
  if (pkgNames.length < 2) return;
  const profile = load();
  const key = pkgNames.slice().sort().join('+');
  profile.coinstallPatterns[key] = (profile.coinstallPatterns[key] || 0) + 1;
  save(profile);
}

// ── 분석 함수 ─────────────────────────────────────────

/**
 * 특정 패키지에 대한 프로파일 조회
 */
function getPackageProfile(pkgName) {
  const profile = load();
  return profile.packages[pkgName] || null;
}

/**
 * 경고 무시율 계산
 */
function getWarningIgnoreRate(warningType) {
  const profile = load();
  const w = profile.warningBehavior[warningType];
  if (!w || w.shown === 0) return 0;
  return w.ignored / w.shown;
}

/**
 * 개발자 성향 요약
 */
function getSummary() {
  const profile = load();
  const stats = profile.stats;

  const topPackages = Object.entries(profile.packages)
    .sort((a, b) => b[1].installCount - a[1].installCount)
    .slice(0, 5)
    .map(([name, data]) => ({ name, count: data.installCount }));

  const topProjectType = Object.entries(profile.projectTypes)
    .sort((a, b) => b[1] - a[1])[0]?.[0] || 'unknown';

  const prefersLatest = profile.updateBehavior.prefersLatest >
    profile.updateBehavior.prefersStable;

  const ignoreRates = Object.entries(profile.warningBehavior)
    .filter(([, w]) => w.shown > 0)
    .map(([type, w]) => ({ type, rate: (w.ignored / w.shown) }))
    .sort((a, b) => b.rate - a.rate);

  return {
    totalInstalls: stats.totalInstalls,
    topPackages,
    topProjectType,
    prefersLatest,
    ignoreRates,
    since: profile.createdAt,
  };
}

// ── 유틸 ──────────────────────────────────────────────

function detectProjectType() {
  try {
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf-8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    if (deps.some(d => ['react', 'vue', 'svelte', 'next', 'nuxt'].includes(d))) return 'frontend';
    if (deps.some(d => ['express', 'fastify', 'koa', 'hapi', 'nestjs'].includes(d))) return 'backend';
    if (deps.some(d => ['commander', 'yargs', 'meow', 'chalk'].includes(d))) return 'cli';
    if (pkg.main && !pkg.scripts?.start) return 'library';
  } catch {}
  return null;
}

function deepMerge(base, override) {
  const result = { ...base };
  for (const key of Object.keys(override)) {
    if (override[key] && typeof override[key] === 'object' && !Array.isArray(override[key])) {
      result[key] = deepMerge(base[key] || {}, override[key]);
    } else {
      result[key] = override[key];
    }
  }
  return result;
}

module.exports = {
  recordInstall,
  recordWarningShown,
  recordWarningIgnored,
  recordBlocked,
  recordCoinstall,
  getPackageProfile,
  getWarningIgnoreRate,
  getSummary,
};
