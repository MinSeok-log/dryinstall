'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawn } = require('child_process');

const TRACKER_PATH = path.join(os.homedir(), '.dryinstall-exectrack.json');
const RC_PATH = path.join(os.homedir(), '.dryinstallrc');

/**
 * Execution Tracker
 *
 * 흐름:
 *   1. dryinstall install <pkg> → 차단한 스크립트 기록
 *   2. npm start 실행
 *   3. 정상 기동 → "차단해도 안전" 학습
 *   4. 크래시   → "이 패키지 스크립트 필요" 학습 → alwaysAllow 자동 추가
 */

// ── 트래커 데이터 로드/저장 ───────────────────────────
function loadTracker() {
  try {
    if (fs.existsSync(TRACKER_PATH)) {
      return JSON.parse(fs.readFileSync(TRACKER_PATH, 'utf-8'));
    }
  } catch {}
  return {
    pendingVerification: [],  // 아직 실행 검증 안 된 차단 기록
    learned: {
      safeToBlock: [],        // 차단해도 앱 정상 → 계속 차단
      needsScript: [],        // 차단하면 앱 죽음 → alwaysAllow
    },
    history: [],
  };
}

function saveTracker(data) {
  try {
    fs.writeFileSync(TRACKER_PATH, JSON.stringify(data, null, 2));
  } catch {}
}

// ── RC 파일 로드/저장 ─────────────────────────────────
function loadRC() {
  try {
    if (fs.existsSync(RC_PATH)) return JSON.parse(fs.readFileSync(RC_PATH, 'utf-8'));
  } catch {}
  return { alwaysAllow: [], alwaysBlock: [] };
}

function saveRC(rc) {
  fs.writeFileSync(RC_PATH, JSON.stringify(rc, null, 2));
}

/**
 * 설치 시 차단한 스크립트 기록
 * cli.js에서 lifecycle 차단 시 호출
 */
function recordBlocked(pkgName, hooks) {
  if (!hooks || hooks.length === 0) return;

  const tracker = loadTracker();

  // 이미 learned 된 패키지는 기록 안 함
  if (tracker.learned.safeToBlock.includes(pkgName)) return;
  if (tracker.learned.needsScript.includes(pkgName)) return;

  // pendingVerification에 추가 (중복 제거)
  const existing = tracker.pendingVerification.find(p => p.pkg === pkgName);
  if (!existing) {
    tracker.pendingVerification.push({
      pkg: pkgName,
      hooks,
      blockedAt: new Date().toISOString(),
      verifyCount: 0,
    });
  }

  saveTracker(tracker);
}

/**
 * npm start / npm run dev 래핑 실행
 * 앱 기동 결과를 감지하고 학습
 *
 * dryinstall run <script> 명령어에서 호출
 */
async function runWithTracking(scriptName = 'start', cwd = process.cwd()) {
  const tracker = loadTracker();

  if (tracker.pendingVerification.length === 0) {
    // 검증할 게 없으면 그냥 실행
    _passthrough(scriptName, cwd);
    return;
  }

  const pending = tracker.pendingVerification.map(p => p.pkg);
  console.log('\n\x1b[36m[dryinstall:tracker] Execution verification active\x1b[0m');
  console.log(`\x1b[90m  Monitoring blocked packages: ${pending.join(', ')}\x1b[0m`);
  console.log('\x1b[90m  If app crashes, dryinstall will auto-learn which scripts are needed\x1b[0m\n');

  const startTime = Date.now();
  let crashed = false;
  let crashError = null;

  try {
    await _runAndMonitor(scriptName, cwd, (exitCode, stderr) => {
      // 빠른 크래시 감지 (5초 내 종료 = 크래시로 판단)
      const elapsed = Date.now() - startTime;
      if (exitCode !== 0 && elapsed < 8000) {
        crashed = true;
        crashError = stderr;
      }
    });
  } catch (err) {
    crashed = true;
    crashError = err.message;
  }

  // ── 결과 기반 학습 ────────────────────────────────
  if (crashed) {
    await _learnFromCrash(tracker, pending, crashError, cwd);
  } else {
    _learnFromSuccess(tracker, pending);
  }
}

/**
 * 크래시 발생 → 어떤 패키지가 원인인지 분석 후 학습
 */
async function _learnFromCrash(tracker, blockedPkgs, errorMsg, cwd) {
  console.log('\n\x1b[31m[dryinstall:tracker] App crashed after blocked scripts\x1b[0m');
  console.log('\x1b[90m  Analyzing which blocked script caused the crash...\x1b[0m');

  // 에러 메시지에서 패키지 이름 매칭
  const suspects = blockedPkgs.filter(pkg => {
    if (!errorMsg) return false;
    return errorMsg.includes(pkg) || errorMsg.toLowerCase().includes(pkg.toLowerCase());
  });

  const toAllow = suspects.length > 0 ? suspects : blockedPkgs;

  // learned.needsScript에 추가
  toAllow.forEach(pkg => {
    if (!tracker.learned.needsScript.includes(pkg)) {
      tracker.learned.needsScript.push(pkg);
    }
    // pendingVerification에서 제거
    tracker.pendingVerification = tracker.pendingVerification.filter(p => p.pkg !== pkg);
  });

  tracker.history.push({
    type: 'crash',
    pkgs: toAllow,
    at: new Date().toISOString(),
    error: errorMsg?.slice(0, 200),
  });

  saveTracker(tracker);

  // RC 파일 자동 업데이트
  const rc = loadRC();
  if (!rc.alwaysAllow) rc.alwaysAllow = [];

  const added = [];
  toAllow.forEach(pkg => {
    if (!rc.alwaysAllow.includes(pkg)) {
      rc.alwaysAllow.push(pkg);
      added.push(pkg);
    }
  });

  if (added.length > 0) {
    saveRC(rc);
    console.log('\n\x1b[33m[dryinstall:tracker] Auto-learned from crash:\x1b[0m');
    added.forEach(p => console.log(`\x1b[33m  + alwaysAllow: ${p} (script required for execution)\x1b[0m`));
    console.log('\x1b[90m  These packages will allow their scripts on next install\x1b[0m');
    console.log('\x1b[90m  Re-run: dryinstall install <pkg> && dryinstall run start\x1b[0m\n');
  }
}

/**
 * 정상 기동 → 차단이 안전했음을 학습
 */
function _learnFromSuccess(tracker, blockedPkgs) {
  console.log('\n\x1b[32m[dryinstall:tracker] ✓ App started successfully with blocked scripts\x1b[0m');

  blockedPkgs.forEach(pkg => {
    if (!tracker.learned.safeToBlock.includes(pkg)) {
      tracker.learned.safeToBlock.push(pkg);
      console.log(`\x1b[32m  ✓ ${pkg} — script not needed for execution\x1b[0m`);
    }
    tracker.pendingVerification = tracker.pendingVerification.filter(p => p.pkg !== pkg);
  });

  tracker.history.push({
    type: 'success',
    pkgs: blockedPkgs,
    at: new Date().toISOString(),
  });

  saveTracker(tracker);
  console.log('\x1b[90m  Learned. These scripts will be silently blocked from now on.\x1b[0m\n');
}

/**
 * 앱 실행 + 결과 모니터링
 */
function _runAndMonitor(scriptName, cwd, onExit) {
  return new Promise((resolve, reject) => {
    const child = spawn('npm', ['run', scriptName], {
      cwd,
      stdio: 'inherit',
      shell: true,
    });

    const timeout = setTimeout(() => {
      // 8초 이상 살아있으면 정상 기동으로 판단
      resolve({ success: true });
    }, 8000);

    child.on('exit', (code, signal) => {
      const elapsed = Date.now();
      clearTimeout(timeout);
      let stderr = '';
      try {
        // 마지막 에러 로그 읽기 시도
        const logDir = path.join(os.homedir(), 'AppData', 'Local', 'npm-cache', '_logs');
        if (fs.existsSync(logDir)) {
          const logs = fs.readdirSync(logDir).sort().slice(-1);
          if (logs.length > 0) {
            stderr = fs.readFileSync(path.join(logDir, logs[0]), 'utf-8').slice(-500);
          }
        }
      } catch {}

      onExit(code, stderr);

      if (code === 0 || code === null) {
        resolve({ success: true });
      } else {
        reject(new Error(`npm run ${scriptName} exited with code ${code}\n${stderr}`));
      }
    });

    child.on('error', reject);
  });
}

/**
 * 그냥 passthrough 실행 (학습 없이)
 */
function _passthrough(scriptName, cwd) {
  try {
    execSync(`npm run ${scriptName}`, { cwd, stdio: 'inherit' });
  } catch {}
}

/**
 * 학습 현황 출력
 * dryinstall track status 명령어
 */
function printStatus() {
  const tracker = loadTracker();

  console.log('\n\x1b[36m══════════════════════════════════════════════════\x1b[0m');
  console.log('\x1b[36m  dryinstall Execution Tracker\x1b[0m');
  console.log('\x1b[36m══════════════════════════════════════════════════\x1b[0m');

  if (tracker.pendingVerification.length > 0) {
    console.log('\n\x1b[33m  Pending verification (not yet run):\x1b[0m');
    tracker.pendingVerification.forEach(p => {
      console.log(`\x1b[90m    ${p.pkg.padEnd(30)} blocked: ${p.hooks.join(', ')}\x1b[0m`);
    });
    console.log('\x1b[90m\n  Run: dryinstall run start\x1b[0m');
  }

  if (tracker.learned.safeToBlock.length > 0) {
    console.log('\n\x1b[32m  Safe to block (confirmed):\x1b[0m');
    tracker.learned.safeToBlock.forEach(p => {
      console.log(`\x1b[32m    ✓ ${p}\x1b[0m`);
    });
  }

  if (tracker.learned.needsScript.length > 0) {
    console.log('\n\x1b[33m  Script required (auto-allowed):\x1b[0m');
    tracker.learned.needsScript.forEach(p => {
      console.log(`\x1b[33m    ! ${p}\x1b[0m`);
    });
  }

  if (tracker.learned.safeToBlock.length === 0 && tracker.learned.needsScript.length === 0) {
    console.log('\n\x1b[90m  No learning data yet.\x1b[0m');
    console.log('\x1b[90m  Install packages and run: dryinstall run start\x1b[0m');
  }

  console.log('\x1b[36m══════════════════════════════════════════════════\x1b[0m\n');
}

module.exports = { recordBlocked, runWithTracking, printStatus };
