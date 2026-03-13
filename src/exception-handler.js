'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Exception Handler
 * dryinstall 전체 예외 상황 처리
 *
 * ① npm install 직접 사용 감지
 * ② dry_modules 없거나 삭제됨
 * ③ .dryinstallrc 없거나 손상됨
 * ④ ~/.dryinstall-profile.json 손상됨
 * ⑤ 네트워크 없을 때
 * ⑥ Node.js 버전 낮을 때
 * ⑦ 권한 없을 때
 */

const RC_PATH      = path.join(os.homedir(), '.dryinstallrc');
const PROFILE_PATH = path.join(os.homedir(), '.dryinstall-profile.json');
const TRACKER_PATH = path.join(os.homedir(), '.dryinstall-exectrack.json');

// ── ① npm install 직접 사용 감지 ──────────────────────
/**
 * npm-wrapper.js에서 호출
 * npm install을 직접 쓰면 경고 출력
 */
function warnDirectNpmInstall(args = []) {
  const pkgs = args.filter(a => !a.startsWith('-'));

  console.log('\n\x1b[33m╔══════════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[33m║  ⚠  Direct npm install detected                  ║\x1b[0m');
  console.log('\x1b[33m╚══════════════════════════════════════════════════╝\x1b[0m');
  console.log('\x1b[90m  This package was not scanned by dryinstall.\x1b[0m');
  console.log('\x1b[90m  Supply chain attacks will not be detected.\x1b[0m\n');

  if (pkgs.length > 0) {
    console.log('\x1b[36m  Recommended:\x1b[0m');
    pkgs.forEach(p => {
      console.log(`\x1b[36m    dryinstall install ${p}\x1b[0m`);
    });
  } else {
    console.log('\x1b[36m  Recommended: dryinstall install <pkg>\x1b[0m');
  }

  console.log('\x1b[90m\n  Proceeding with npm install (unprotected)...\x1b[0m\n');
  // 강제 차단 없음 — 경고만 출력하고 통과
}

// ── ② dry_modules 없거나 삭제됨 ───────────────────────
/**
 * loader.js에서 require() 시 dry_modules 없으면 호출
 */
function handleMissingDryModules(pkgName, nodeModulesPath) {
  console.warn(`\x1b[33m[dryinstall:loader] ⚠ dry_modules/${pkgName} not found\x1b[0m`);
  console.warn('\x1b[90m  Falling back to node_modules (no sandbox protection)\x1b[0m');
  console.warn(`\x1b[90m  Run: dryinstall install ${pkgName}  to restore protection\x1b[0m`);

  // node_modules fallback
  if (nodeModulesPath && fs.existsSync(nodeModulesPath)) {
    return nodeModulesPath;
  }

  return null;
}

/**
 * dry_modules 디렉토리 자체가 없을 때
 */
function handleMissingDryModulesDir(cwd) {
  const dryDir = path.join(cwd, 'dry_modules');

  if (!fs.existsSync(dryDir)) {
    console.warn('\x1b[33m[dryinstall] ⚠ dry_modules/ not found\x1b[0m');
    console.warn('\x1b[90m  Running without sandbox protection.\x1b[0m');
    console.warn('\x1b[90m  Run: dryinstall scan  to restore protection\x1b[0m\n');
    return false;
  }
  return true;
}

// ── ③ .dryinstallrc 없거나 손상됨 ─────────────────────
/**
 * RC 파일 안전하게 로드 — 손상 시 기본값으로 초기화
 */
function loadRCSafe() {
  const DEFAULT_RC = { alwaysAllow: [], alwaysBlock: [] };

  if (!fs.existsSync(RC_PATH)) {
    return DEFAULT_RC;
  }

  try {
    const raw = fs.readFileSync(RC_PATH, 'utf-8');
    const parsed = JSON.parse(raw);

    // 구조 검증
    if (typeof parsed !== 'object' || parsed === null) throw new Error('invalid');
    if (!Array.isArray(parsed.alwaysAllow)) parsed.alwaysAllow = [];
    if (!Array.isArray(parsed.alwaysBlock)) parsed.alwaysBlock = [];

    return parsed;
  } catch (err) {
    console.warn('\x1b[33m[dryinstall] ⚠ ~/.dryinstallrc is corrupted — resetting to defaults\x1b[0m');
    // 손상된 파일 백업
    try {
      fs.copyFileSync(RC_PATH, RC_PATH + '.bak');
      console.warn('\x1b[90m  Backup saved to ~/.dryinstallrc.bak\x1b[0m');
    } catch {}
    // 기본값으로 초기화
    fs.writeFileSync(RC_PATH, JSON.stringify(DEFAULT_RC, null, 2));
    return DEFAULT_RC;
  }
}

// ── ④ profile.json 손상됨 ─────────────────────────────
/**
 * 프로파일 안전하게 로드 — 손상 시 초기화
 */
function loadProfileSafe() {
  const DEFAULT_PROFILE = {
    version: 1,
    createdAt: new Date().toISOString(),
    updatedAt: null,
    stats: { totalInstalls: 0, totalWarningsIgnored: 0, totalBlocked: 0, totalAllowed: 0 },
    packages: {},
    warningBehavior: {
      lifecycle: { shown: 0, ignored: 0 },
      stealth: { shown: 0, ignored: 0 },
      confusion: { shown: 0, ignored: 0 },
      maintainer: { shown: 0, ignored: 0 },
      versionDiff: { shown: 0, ignored: 0 },
      hash: { shown: 0, ignored: 0 },
      typo: { shown: 0, ignored: 0 },
    },
    projectTypes: {},
    coinstallPatterns: {},
    updateBehavior: { prefersLatest: 0, prefersStable: 0, averageVersionAge: 0 },
    recentEvents: [],
  };

  if (!fs.existsSync(PROFILE_PATH)) return DEFAULT_PROFILE;

  try {
    const raw = fs.readFileSync(PROFILE_PATH, 'utf-8');
    const parsed = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) throw new Error('invalid');
    return parsed;
  } catch {
    console.warn('\x1b[33m[dryinstall] ⚠ Developer profile corrupted — resetting\x1b[0m');
    try {
      fs.copyFileSync(PROFILE_PATH, PROFILE_PATH + '.bak');
      console.warn('\x1b[90m  Backup saved to ~/.dryinstall-profile.json.bak\x1b[0m');
    } catch {}
    fs.writeFileSync(PROFILE_PATH, JSON.stringify(DEFAULT_PROFILE, null, 2));
    return DEFAULT_PROFILE;
  }
}

// ── ⑤ 네트워크 없을 때 ────────────────────────────────
/**
 * registry 접근 실패 시 호출
 * 캐시된 버전 확인 후 안내
 */
function handleNetworkError(pkgName, cacheDir, err) {
  console.error(`\x1b[31m[dryinstall] ✗ Network error: cannot reach npm registry\x1b[0m`);
  console.error(`\x1b[90m  ${err.message}\x1b[0m`);

  // 캐시 확인
  const cachePath = cacheDir ? path.join(cacheDir, pkgName) : null;
  if (cachePath && fs.existsSync(cachePath)) {
    console.warn(`\x1b[33m[dryinstall] ⚠ Using cached version of ${pkgName}\x1b[0m`);
    console.warn('\x1b[90m  Cache may be outdated. Reconnect and reinstall when possible.\x1b[0m');
    return { usedCache: true, cachePath };
  }

  console.error('\x1b[90m  No cached version available.\x1b[0m');
  console.error('\x1b[90m  Check your internet connection and try again.\x1b[0m\n');
  return { usedCache: false, cachePath: null };
}

// ── ⑥ Node.js 버전 낮을 때 ───────────────────────────
/**
 * 실행 시작 시 Node.js 버전 체크
 * 낮은 버전이면 기능 제한하고 진행
 */
function checkNodeVersion() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  const result = { ok: true, level: 3, warnings: [] };

  if (major < 12) {
    result.ok = false;
    result.warnings.push('Node.js 12+ required. Please upgrade.');
    return result;
  }

  if (major < 14) {
    result.level = 1; // Worker Thread 불안정 → Level 1로 다운
    result.warnings.push(`Node.js ${process.versions.node} detected. Worker Thread isolation disabled. Upgrade to 14+ for full protection.`);
  } else if (major < 16) {
    result.level = 2; // 일부 vm 기능 제한
    result.warnings.push(`Node.js ${process.versions.node} detected. Some sandbox features limited. Upgrade to 16+ for full protection.`);
  }

  if (result.warnings.length > 0) {
    result.warnings.forEach(w => {
      console.warn(`\x1b[33m[dryinstall] ⚠ ${w}\x1b[0m`);
    });
    if (result.level < 3) {
      console.warn(`\x1b[33m[dryinstall] ⚠ Auto-downgraded to security level ${result.level}\x1b[0m\n`);
    }
  }

  return result;
}

// ── ⑦ 권한 없을 때 ────────────────────────────────────
/**
 * 파일/디렉토리 쓰기 실패 시 호출
 */
function handlePermissionError(targetPath, err) {
  console.error(`\x1b[31m[dryinstall] ✗ Permission denied: ${targetPath}\x1b[0m`);

  if (process.platform === 'win32') {
    console.error('\x1b[90m  Try running PowerShell as Administrator\x1b[0m');
    console.error('\x1b[90m  Or change folder permissions:\x1b[0m');
    console.error(`\x1b[90m    icacls "${path.dirname(targetPath)}" /grant %USERNAME%:F\x1b[0m`);
  } else {
    console.error('\x1b[90m  Try:\x1b[0m');
    console.error(`\x1b[90m    sudo chown -R $(whoami) ${path.dirname(targetPath)}\x1b[0m`);
    console.error(`\x1b[90m  Or run with sudo (not recommended for npm)\x1b[0m`);
  }
  console.error('\x1b[90m  Package stored in node_modules as fallback.\x1b[0m\n');
}

/**
 * 안전한 파일 쓰기 — 권한 오류 자동 처리
 */
function safeWriteFile(filePath, content) {
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, content);
    return true;
  } catch (err) {
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      handlePermissionError(filePath, err);
    } else {
      console.error(`\x1b[31m[dryinstall] ✗ Failed to write ${filePath}: ${err.message}\x1b[0m`);
    }
    return false;
  }
}

/**
 * 안전한 디렉토리 생성
 */
function safeMkdir(dirPath) {
  try {
    if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
    return true;
  } catch (err) {
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      handlePermissionError(dirPath, err);
    } else {
      console.error(`\x1b[31m[dryinstall] ✗ Failed to create ${dirPath}: ${err.message}\x1b[0m`);
    }
    return false;
  }
}

// ── 시작 시 전체 환경 검사 ─────────────────────────────
/**
 * dryinstall 실행 시작 시 한 번 호출
 * 문제 있으면 경고 출력 후 가능한 수준으로 진행
 */
function runStartupChecks() {
  const results = {
    nodeVersion: checkNodeVersion(),
    rcOk: true,
    profileOk: true,
  };

  // RC 파일 검증
  try {
    loadRCSafe();
  } catch {
    results.rcOk = false;
  }

  // 프로파일 검증
  try {
    loadProfileSafe();
  } catch {
    results.profileOk = false;
  }

  return results;
}

module.exports = {
  warnDirectNpmInstall,
  handleMissingDryModules,
  handleMissingDryModulesDir,
  loadRCSafe,
  loadProfileSafe,
  handleNetworkError,
  checkNodeVersion,
  handlePermissionError,
  safeWriteFile,
  safeMkdir,
  runStartupChecks,
};
