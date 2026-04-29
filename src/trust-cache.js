'use strict';

/**
 * trust-cache.js
 *
 * "trust-cache는 기억장치지, 신뢰장치가 아닙니다."
 *
 * 원칙:
 *   - 자동 허용 절대 없음
 *   - Enter 기본값 항상 No
 *   - trust-cache는 판단 보조 (기억) 역할만
 *   - 실제 판단은 Confidence Score → advisor → 사용자
 *
 * 보완된 항목:
 *   1. autoDefault 완전 제거  → Enter = 항상 No
 *   2. TTL + npm publish time  → 배포 후 24h 내 무조건 재검증
 *   3. depsHash → lock 기반  → resolved URL + integrity 포함
 *   4. Confidence Score 모델  → 판단 근거 수치화
 *
 * 저장: ~/.dryinstall/trust-cache.json
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

const STORE_PATH      = path.join(os.homedir(), '.dryinstall', 'trust-cache.json');
const TRUST_TTL_MS    = 7 * 24 * 60 * 60 * 1000;   // 7일
const NEW_PUBLISH_TTL = 24 * 60 * 60 * 1000;         // 배포 후 24h → 재검증

const CLASSIFICATION = {
  SAFE_BUILD:   'SAFE_BUILD',
  SAFE_INSTALL: 'SAFE_INSTALL',
  UNKNOWN:      'UNKNOWN',
  SUSPICIOUS:   'SUSPICIOUS',
};

// ─────────────────────────────────────────────────────────────
// 해시 유틸
// ─────────────────────────────────────────────────────────────

function _hash(str) {
  return crypto.createHash('sha256').update(str).digest('hex').slice(0, 16);
}

function _hashFile(filePath) {
  try {
    return crypto.createHash('sha256')
      .update(fs.readFileSync(filePath))
      .digest('hex').slice(0, 16);
  } catch { return null; }
}

/** node build.js 같이 참조하는 파일 해시 */
function _referencedFileHash(cmd, cwd = process.cwd()) {
  const matches = cmd.match(/node\s+([\w./\\-]+\.(?:js|mjs|cjs))/g);
  if (!matches) return null;
  const hashes = matches
    .map(m => {
      const file = m.replace(/^node\s+/, '').trim();
      const abs  = path.isAbsolute(file) ? file : path.join(cwd, file);
      return _hashFile(abs);
    })
    .filter(Boolean);
  return hashes.length > 0 ? _hash(hashes.join(':')) : null;
}

/**
 * lock 기반 depsHash
 * package-lock.json의 resolved URL + integrity 포함
 * → package-lock.json 조작 공격 방어
 */
function _depsHash(cwd = process.cwd()) {
  try {
    // package-lock.json 우선 (더 정확)
    const lockPath = path.join(cwd, 'package-lock.json');
    if (fs.existsSync(lockPath)) {
      const lock = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));
      const deps = lock.packages || lock.dependencies || {};
      const entries = Object.entries(deps)
        .filter(([k]) => k !== '')
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([name, v]) => `${name}:${v.version ?? ''}:${v.resolved ?? ''}:${v.integrity ?? ''}`);
      return _hash(entries.join('|'));
    }
    // fallback: package.json
    const pkgPath = path.join(cwd, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg  = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      const sorted = Object.entries(deps).sort(([a], [b]) => a.localeCompare(b));
      return _hash(JSON.stringify(sorted));
    }
  } catch {}
  return null;
}

/** OS + CI 환경 구분 */
function _context() {
  const isCI = !!(
    process.env.CI || process.env.GITHUB_ACTIONS ||
    process.env.TRAVIS || process.env.CIRCLECI || process.env.GITLAB_CI
  );
  return `${process.platform}:${isCI ? 'ci' : 'local'}`;
}

// ─────────────────────────────────────────────────────────────
// Confidence Score 모델
// "판단 보조" — 자동 허용 트리거로 절대 사용 금지
// ─────────────────────────────────────────────────────────────

/**
 * @returns {number} 0~100
 * 90+  Low risk      (but still ask)
 * 60~89 Review recommended
 * <60  High risk
 */
function calcConfidence(entry, fp) {
  if (!entry) return 0;

  // SUSPICIOUS 스크립트는 점수 계산 자체 의미 없음 → 0 강제
  const cls = classifyScript(entry.cmd ?? '', fp);
  if (cls === CLASSIFICATION.SUSPICIOUS) return 0;

  let score = 0;
  if (entry.decision === 'user_allowed') score += 40;  // hash_match
  score += 20;                                          // script_same (lookup 통과 시 이미 일치)
  const currentDeps = _depsHash();
  if (currentDeps && entry.depsHash && currentDeps === entry.depsHash) score += 15; // deps_same
  if (!fp.hasNetwork)   score += 15;                   // no_network
  if (!fp.hasFileWrite) score += 10;                   // no_fs_write
  return Math.min(score, 100);
}

function confidenceLabel(score) {
  if (score >= 90) return { label: 'Low risk',             color: '\x1b[32m' };
  if (score >= 60) return { label: 'Review recommended',   color: '\x1b[33m' };
  return              { label: 'High risk',            color: '\x1b[31m' };
}

// ─────────────────────────────────────────────────────────────
// behavior fingerprint
// ─────────────────────────────────────────────────────────────

const NETWORK_PATTERNS   = [/https?:\/\//, /curl\b/, /wget\b/, /fetch\b/, /socket\.connect/, /\.request\(/];
const EXEC_PATTERNS      = [/child_process/, /exec\s*\(/, /spawn\s*\(/, /execSync/, /\/bin\/sh/, /\/bin\/bash/, /powershell/i];
const WRITE_PATTERNS     = [/fs\.write/, /fs\.unlink/, /fs\.rm/, /rm\s+-rf/, /writeFile/, /appendFile/];
const ENV_PATTERNS       = [/process\.env/, /\.env\b/, /NPM_TOKEN|AWS_SECRET|AWS_ACCESS_KEY|GITHUB_TOKEN|SECRET_KEY/i];
const SENSITIVE_ENV_PATTERNS = [/NPM_TOKEN|AWS_SECRET|AWS_ACCESS_KEY|GITHUB_TOKEN|SECRET_KEY/i];
const OBFUSCATION_PATTERNS = [/eval\s*\(/, /Buffer\.from.*base64/, /base64/, /atob\s*\(/, /new Function\s*\(/];
const DELETE_PATTERNS    = [/rm\s+-rf/, /rmdir\b/, /fs\.rm/, /fs\.unlink/];
const SHELL_DOWNLOAD_PATTERNS = [/(curl|wget)\b[^|&;]*(\||&&|;)\s*(sh|bash|node|powershell)/i];
const DANGEROUS_PATTERNS = [/process\.env.*JSON\.stringify/, /169\.254\.169\.254/, /metadata\.google/i, /sudo\b/, /chmod\s+[0-7]*7/];

function analyzeFingerprint(cmd) {
  return {
    hasNetwork:   NETWORK_PATTERNS.some(p => p.test(cmd)),
    hasExec:      EXEC_PATTERNS.some(p => p.test(cmd)),
    hasFileWrite: WRITE_PATTERNS.some(p => p.test(cmd)),
    hasEnvAccess: ENV_PATTERNS.some(p => p.test(cmd)),
    hasSensitiveEnv: SENSITIVE_ENV_PATTERNS.some(p => p.test(cmd)),
    hasObfuscation: OBFUSCATION_PATTERNS.some(p => p.test(cmd)),
    hasDeletion: DELETE_PATTERNS.some(p => p.test(cmd)),
    hasShellDownload: SHELL_DOWNLOAD_PATTERNS.some(p => p.test(cmd)),
    isDangerous:  DANGEROUS_PATTERNS.some(p => p.test(cmd)),
  };
}

function scoreScriptRisk(cmd, hook = '', fp = analyzeFingerprint(cmd)) {
  let score = 0;
  const reasons = [];
  const add = (points, reason) => {
    score += points;
    reasons.push(reason);
  };

  if (hook === 'preinstall') add(10, 'early lifecycle hook');
  else if (hook) add(5, 'lifecycle hook');

  if (fp.isDangerous) add(70, 'dangerous pattern');
  if (fp.hasShellDownload) add(75, 'download piped to shell');
  if (fp.hasObfuscation) add(35, 'obfuscation or dynamic code');
  if (fp.hasExec) add(30, 'exec or shell access');
  if (fp.hasNetwork) add(25, 'network access');
  if (fp.hasSensitiveEnv) add(40, 'sensitive environment access');
  else if (fp.hasEnvAccess) add(25, 'environment access');
  if (fp.hasDeletion) add(35, 'file deletion');
  else if (fp.hasFileWrite) add(10, 'file write');

  if (fp.hasNetwork && fp.hasExec) add(30, 'network plus exec');
  if (fp.hasNetwork && fp.hasEnvAccess) add(35, 'network plus environment access');
  if (fp.hasExec && fp.hasObfuscation) add(30, 'exec plus obfuscation');

  return {
    score: Math.min(score, 100),
    reasons,
  };
}

function classifyScript(cmd, fp, hook = '') {
  const risk = scoreScriptRisk(cmd, hook, fp);
  if (risk.score >= 70) return CLASSIFICATION.SUSPICIOUS;
  if (risk.score >= 35) return CLASSIFICATION.UNKNOWN;
  if (fp.hasFileWrite) return CLASSIFICATION.SAFE_INSTALL;
  return CLASSIFICATION.SAFE_BUILD;
}

function actionForLevel(risk, level) {
  const score = typeof risk === 'number' ? risk : risk.score;
  if (level <= 0) return 'allow';
  if (level === 1) return score >= 90 ? 'block' : score >= 35 ? 'warn' : 'allow';
  if (level === 2) return score >= 70 ? 'block' : score >= 35 ? 'warn' : 'allow';
  return score > 0 ? 'block' : 'warn';
}

function assessScript(cmd, hook = '', level = 2) {
  const fp = analyzeFingerprint(cmd);
  const risk = scoreScriptRisk(cmd, hook, fp);
  return {
    fingerprint: fp,
    risk,
    classification: classifyScript(cmd, fp, hook),
    action: actionForLevel(risk, level),
  };
}

// ─────────────────────────────────────────────────────────────
// 스토어
// ─────────────────────────────────────────────────────────────

function _load() {
  try {
    if (fs.existsSync(STORE_PATH))
      return JSON.parse(fs.readFileSync(STORE_PATH, 'utf-8'));
  } catch {}
  return { entries: {} };
}

function _save(store) {
  const dir = path.dirname(STORE_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
}

function _key(pkgName, version, hook, cmd, cwd) {
  const scriptHash = _hash(cmd.trim());
  const refHash    = _referencedFileHash(cmd, cwd) ?? 'noref';
  const ctx        = _context();
  return `${pkgName}@${version}:${hook}:${scriptHash}:${refHash}:${ctx}`;
}

// ─────────────────────────────────────────────────────────────
// TTL + publish time 체크
// ─────────────────────────────────────────────────────────────

function _isExpired(entry) {
  if (!entry?.lastSeen) return true;
  return (Date.now() - new Date(entry.lastSeen).getTime()) > TRUST_TTL_MS;
}

/**
 * npm 배포 후 24h 이내 → 무조건 재검증
 * publishedAt은 installer.js에서 registry meta에서 가져와 record 시 저장
 */
function _isNewlyPublished(entry) {
  if (!entry?.publishedAt) return false;
  return (Date.now() - new Date(entry.publishedAt).getTime()) < NEW_PUBLISH_TTL;
}

// ─────────────────────────────────────────────────────────────
// 공개 API
// ─────────────────────────────────────────────────────────────

/**
 * 캐시 조회
 */
function lookup(pkgName, version, hook, cmd, cwd = process.cwd(), opts = {}) {
  const store = _load();
  const key   = _key(pkgName, version, hook, cmd, cwd);
  const entry = store.entries[key];

  if (!entry) return { found: false };

  // TTL 만료
  if (_isExpired(entry)) {
    if (!opts.quiet) process.stdout.write(
      `\x1b[33m[dryinstall:trust] ${pkgName}@${version} — cache expired (>7d), re-evaluating\x1b[0m\n`
    );
    return { found: false, expired: true };
  }

  // 배포 후 24h 이내 → 재검증
  if (_isNewlyPublished(entry)) {
    if (!opts.quiet) process.stdout.write(
      `\x1b[33m[dryinstall:trust] ${pkgName}@${version} — newly published (<24h), re-evaluating\x1b[0m\n`
    );
    return { found: false, newlyPublished: true };
  }

  // 위험 or 사용자 차단
  if (entry.classification === CLASSIFICATION.SUSPICIOUS || entry.decision === 'user_blocked') {
    return { found: true, entry, shouldAsk: false, autoBlock: true };
  }

  const fp         = analyzeFingerprint(cmd);
  const confidence = calcConfidence(entry, fp);

  return {
    found:      true,
    entry,
    shouldAsk:  true,
    autoAllow:  false,    // 자동 허용 절대 없음
    autoDefault: false,   // Enter = 항상 No
    confidence,
    confidenceInfo: confidenceLabel(confidence),
  };
}

/**
 * 캐시 저장
 * @param {string|null} publishedAt  registry meta의 time[version]
 */
function record(pkgName, version, hook, cmd, decision, cwd = process.cwd(), publishedAt = null) {
  const store  = _load();
  const key    = _key(pkgName, version, hook, cmd, cwd);
  const fp     = analyzeFingerprint(cmd);
  const cls    = classifyScript(cmd, fp);

  store.entries[key] = {
    pkgName, version, hook,
    cmd:            cmd.slice(0, 100),
    scriptHash:     _hash(cmd.trim()),
    refFileHash:    _referencedFileHash(cmd, cwd),
    depsHash:       _depsHash(cwd),
    context:        _context(),
    classification: cls,
    fingerprint:    fp,
    decision,
    publishedAt,                                          // 배포 시각 저장
    seenCount:      (store.entries[key]?.seenCount ?? 0) + 1,
    firstSeen:      store.entries[key]?.firstSeen ?? new Date().toISOString(),
    lastSeen:       new Date().toISOString(),
  };

  _save(store);
}

/** 버전 변경 시 캐시 무효화 */
function invalidate(pkgName, newVersion) {
  const store   = _load();
  const oldKeys = Object.keys(store.entries).filter(k =>
    k.startsWith(`${pkgName}@`) && !k.startsWith(`${pkgName}@${newVersion}`)
  );
  if (!oldKeys.length) return;
  oldKeys.forEach(k => delete store.entries[k]);
  _save(store);
  process.stdout.write(
    `\x1b[33m[dryinstall:trust] ${pkgName}@${newVersion} — ${oldKeys.length} old entries invalidated\x1b[0m\n`
  );
}

/** 만료 항목 정리 */
function purgeExpired() {
  const store   = _load();
  const expired = Object.keys(store.entries).filter(k => _isExpired(store.entries[k]));
  if (!expired.length) return;
  expired.forEach(k => delete store.entries[k]);
  _save(store);
  process.stdout.write(`\x1b[90m[dryinstall:trust] Purged ${expired.length} expired entries\x1b[0m\n`);
}

/**
 * 인터랙티브 프롬프트
 * Enter = 항상 No (autoDefault 완전 제거)
 */
async function askUser(pkgName, version, hook, cmd, cwd = process.cwd()) {
  const fp          = analyzeFingerprint(cmd);
  const store       = _load();
  const key         = _key(pkgName, version, hook, cmd, cwd);
  const entry       = store.entries[key];
  const seen        = entry?.seenCount ?? 0;
  const confidence  = calcConfidence(entry, fp);
  const { label, color } = confidenceLabel(confidence);

  const R  = '\x1b[0m';
  const C  = '\x1b[36m';
  const Y  = '\x1b[33m';
  const G  = '\x1b[32m';
  const GR = '\x1b[90m';
  const RE = '\x1b[31m';
  const W  = 58;

  console.log(`\n${'─'.repeat(W)}`);
  console.log(`${C}  Lifecycle Script Detected${R}`);
  console.log(`${'─'.repeat(W)}`);
  console.log(`  Package    : ${pkgName}@${version}`);
  console.log(`  Script     : ${hook}`);
  console.log(`  Command    : ${cmd.slice(0, 55)}`);
  console.log(`  Context    : ${_context()}`);
  console.log(`\n  Risk analysis:`);
  console.log(`  ${fp.hasNetwork   ? Y+'⚠'+R : G+'✓'+R}  Network access   : ${fp.hasNetwork   ? 'YES ← suspicious' : 'none'}`);
  console.log(`  ${fp.hasExec      ? Y+'⚠'+R : G+'✓'+R}  Exec / shell     : ${fp.hasExec      ? 'YES ← suspicious' : 'none'}`);
  console.log(`  ${fp.hasFileWrite ? Y+'·'+R : G+'✓'+R}  File write       : ${fp.hasFileWrite  ? 'yes (build)' : 'none'}`);
  console.log(`  ${fp.isDangerous  ? RE+'✗'+R : G+'✓'+R}  Dangerous pattern: ${fp.isDangerous ? 'DETECTED' : 'none'}`);

  console.log(`\n  Confidence : ${color}${confidence}/100 — ${label}${R}`);

  if (seen > 0) {
    const daysAgo = Math.floor((Date.now() - new Date(entry.lastSeen).getTime()) / 86400000);
    console.log(`  History    : seen ${seen}x — ${daysAgo}d ago — ${entry.decision}`);
  } else {
    console.log(`  History    : ${GR}first time${R}`);
  }

  // 경고: Enter = No
  console.log(`\n  ${GR}[Y] Allow once   [A] Always allow (this version + script only)${R}`);
  console.log(`  ${GR}[N] Block        [B] Always block   ← Enter default${R}`);
  console.log(`${'─'.repeat(W)}`);

  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  return new Promise((resolve) => {
    rl.question(`  Allow? y/[N]/a/b  `, (answer) => {
      rl.close();
      const a = answer.trim().toLowerCase();

      if (a === 'a') {
        record(pkgName, version, hook, cmd, 'user_allowed', cwd);
        console.log(`  ${G}✓ Always allow (this version + script only)\x1b[0m`);
        resolve('allow');
      } else if (a === 'b') {
        record(pkgName, version, hook, cmd, 'user_blocked', cwd);
        console.log(`  ${RE}✗ Always block\x1b[0m`);
        resolve('block');
      } else if (a === 'y') {
        console.log(`  ${G}✓ Allowed (once)\x1b[0m`);
        resolve('allow_once');
      } else {
        // Enter 또는 N → 항상 Block
        record(pkgName, version, hook, cmd, 'user_blocked', cwd);
        console.log(`  ${RE}✗ Blocked\x1b[0m`);
        resolve('block');
      }
    });
  });
}

/** trust cache 현황 출력 */
function printStatus() {
  const store   = _load();
  const entries = Object.values(store.entries);
  const W       = 50;

  if (!entries.length) {
    console.log('\n\x1b[90m  [trust-cache] No entries yet.\x1b[0m\n');
    return;
  }

  const allowed = entries.filter(e => e.decision === 'user_allowed');
  const blocked = entries.filter(e => e.decision === 'user_blocked');
  const expired = entries.filter(e => _isExpired(e));
  const newPub  = entries.filter(e => _isNewlyPublished(e));

  console.log(`\n\x1b[36m${'═'.repeat(W)}\x1b[0m`);
  console.log('\x1b[36m  Trust Cache\x1b[0m');
  console.log(`\x1b[36m${'═'.repeat(W)}\x1b[0m`);

  if (allowed.length) {
    console.log(`\n  \x1b[32m✓ Allowed (${allowed.length})\x1b[0m`);
    allowed.forEach(e => {
      const fp   = analyzeFingerprint(e.cmd ?? '');
      const conf = calcConfidence(e, fp);
      const daysLeft = Math.floor(
        (TRUST_TTL_MS - (Date.now() - new Date(e.lastSeen).getTime())) / 86400000
      );
      console.log(
        `    ${(e.pkgName+'@'+e.version).padEnd(32)}` +
        `  ${e.hook}  conf:${conf}  seen:${e.seenCount}x  exp:${daysLeft}d`
      );
    });
  }

  if (blocked.length) {
    console.log(`\n  \x1b[31m✗ Blocked (${blocked.length})\x1b[0m`);
    blocked.forEach(e => {
      console.log(`    ${(e.pkgName+'@'+e.version).padEnd(32)}  ${e.hook}`);
    });
  }

  if (expired.length)
    console.log(`\n  \x1b[90m⏱ Expired (${expired.length}) — will re-ask on next install\x1b[0m`);

  if (newPub.length)
    console.log(`  \x1b[33m⚠ Newly published (${newPub.length}) — will re-verify (<24h)\x1b[0m`);

  console.log(`\x1b[36m${'═'.repeat(W)}\x1b[0m\n`);
}

module.exports = {
  lookup,
  record,
  invalidate,
  purgeExpired,
  askUser,
  calcConfidence,
  confidenceLabel,
  analyzeFingerprint,
  scoreScriptRisk,
  actionForLevel,
  assessScript,
  classifyScript,
  printStatus,
  CLASSIFICATION,
};
