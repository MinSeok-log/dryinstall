'use strict';

/**
 * Logger — 중앙 로그 레벨 관리
 *
 * 레벨:
 *   0  QUIET   — 차단/오류만
 *   1  NORMAL  — 기본 (default)
 *   2  VERBOSE — 전체 로그
 *
 * 사용:
 *   dryinstall scan              → NORMAL
 *   dryinstall scan --quiet      → QUIET  (CI, 장기 프로젝트)
 *   dryinstall scan --verbose    → VERBOSE (디버깅)
 */

const LEVELS = { QUIET: 0, NORMAL: 1, VERBOSE: 2 };

let _level   = LEVELS.NORMAL;
let _jsonMode = false;

// ANSI 색상
const C = {
  RED:    '\x1b[31m',
  YELLOW: '\x1b[33m',
  GREEN:  '\x1b[32m',
  CYAN:   '\x1b[36m',
  GRAY:   '\x1b[90m',
  BOLD:   '\x1b[1m',
  RESET:  '\x1b[0m',
};

function setLevel(level) {
  if (typeof level === 'string') {
    _level = LEVELS[level.toUpperCase()] ?? LEVELS.NORMAL;
  } else {
    _level = level;
  }
}

function setJson(enabled) {
  _jsonMode = enabled;
  // json 모드에서는 stdout 보호 — 모든 로그를 stderr로
  if (enabled) {
    _level = LEVELS.QUIET; // json 모드에서는 stdout 오염 방지
  }
}

function getLevel() { return _level; }

// ── 출력 함수 ──────────────────────────────────────────

/** 차단/공격 탐지 — 항상 출력 */
function block(msg) {
  const out = `${C.RED}[dryinstall] ✗ ${msg}${C.RESET}`;
  _jsonMode ? process.stderr.write(out + '\n') : console.error(out);
}

/** 경고 — NORMAL 이상 */
function warn(msg) {
  if (_level < LEVELS.NORMAL) return;
  const out = `${C.YELLOW}[dryinstall] ⚠  ${msg}${C.RESET}`;
  _jsonMode ? process.stderr.write(out + '\n') : console.warn(out);
}

/** 정보 — NORMAL 이상 */
function info(msg) {
  if (_level < LEVELS.NORMAL) return;
  const out = `${C.CYAN}[dryinstall] ${msg}${C.RESET}`;
  _jsonMode ? process.stderr.write(out + '\n') : console.log(out);
}

/** 성공 — NORMAL 이상 */
function ok(msg) {
  if (_level < LEVELS.NORMAL) return;
  const out = `${C.GREEN}[dryinstall] ✓ ${msg}${C.RESET}`;
  _jsonMode ? process.stderr.write(out + '\n') : console.log(out);
}

/** 상세 — VERBOSE만 */
function verbose(msg) {
  if (_level < LEVELS.VERBOSE) return;
  const out = `${C.GRAY}[dryinstall:verbose] ${msg}${C.RESET}`;
  _jsonMode ? process.stderr.write(out + '\n') : console.log(out);
}

/** 항상 출력 (요약 리포트 등) */
function always(msg) {
  _jsonMode ? process.stderr.write(msg + '\n') : console.log(msg);
}

/** json stdout 전용 출력 */
function json(obj) {
  process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
}

module.exports = {
  LEVELS,
  setLevel,
  setJson,
  getLevel,
  block,
  warn,
  info,
  ok,
  verbose,
  always,
  json,
  C,
};