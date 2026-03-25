'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawn } = require('child_process');

const trustCache = require('./trust-cache');  // ← 교체

const TRACKER_PATH = path.join(os.homedir(), '.dryinstall-exectrack.json');
const RC_PATH      = path.join(os.homedir(), '.dryinstallrc');

// ── 트래커 데이터 로드/저장 ───────────────────────────
function loadTracker() {
  try {
    if (fs.existsSync(TRACKER_PATH))
      return JSON.parse(fs.readFileSync(TRACKER_PATH, 'utf-8'));
  } catch {}
  return {
    pendingVerification: [],
    learned: { safeToBlock: [], needsScript: [] },
    history: [],
  };
}

function saveTracker(data) {
  try { fs.writeFileSync(TRACKER_PATH, JSON.stringify(data, null, 2)); } catch {}
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
 * installer.js에서 lifecycle 차단 시 호출
 */
function recordBlocked(pkgName, hooks) {
  if (!hooks || hooks.length === 0) return;

  const tracker = loadTracker();
  if (tracker.learned.safeToBlock.includes(pkgName)) return;
  if (tracker.learned.needsScript.includes(pkgName)) return;

  const existing = tracker.pendingVerification.find(p => p.pkg === pkgName);
  if (!existing) {
    tracker.pendingVerification.push({
      pkg: pkgName,
      hooks,
      blockedAt:    new Date().toISOString(),
      verifyCount:  0,
    });
  }

  saveTracker(tracker);
}

/**
 * npm start / npm run dev 래핑 실행
 * dryinstall run <script> 명령어에서 호출
 */
async function runWithTracking(scriptName = 'start', cwd = process.cwd()) {
  const tracker = loadTracker();

  if (tracker.pendingVerification.length === 0) {
    _passthrough(scriptName, cwd);
    return;
  }

  const pending = tracker.pendingVerification.map(p => p.pkg);
  console.log('\n\x1b[36m[dryinstall:tracker] Execution verification active\x1b[0m');
  console.log(`\x1b[90m  Monitoring: ${pending.join(', ')}\x1b[0m`);
  console.log('\x1b[90m  If app crashes, dryinstall will auto-learn which scripts are needed\x1b[0m\n');

  const startTime = Date.now();
  let crashed = false;
  let crashError = null;

  try {
    await _runAndMonitor(scriptName, cwd, (exitCode, stderr) => {
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

  if (crashed) {
    await _learnFromCrash(tracker, pending, crashError, cwd);
  } else {
    _learnFromSuccess(tracker, pending);
  }
}

/**
 * 크래시 발생 → 원인 분석 후 학습
 */
async function _learnFromCrash(tracker, blockedPkgs, errorMsg, cwd) {
  console.log('\n\x1b[31m[dryinstall:tracker] App crashed after blocked scripts\x1b[0m');
  console.log('\x1b[90m  Analyzing which blocked script caused the crash...\x1b[0m');

  const suspects = blockedPkgs.filter(pkg => {
    if (!errorMsg) return false;
    return errorMsg.includes(pkg) || errorMsg.toLowerCase().includes(pkg.toLowerCase());
  });

  const toAllow = suspects.length > 0 ? suspects : blockedPkgs;

  toAllow.forEach(pkg => {
    if (!tracker.learned.needsScript.includes(pkg))
      tracker.learned.needsScript.push(pkg);
    tracker.pendingVerification = tracker.pendingVerification.filter(p => p.pkg !== pkg);
    // trust cache에서도 해당 패키지 무효화
    toAllow.forEach(pkg => {
      // crash = 스크립트가 필요했다는 의미 → trust cache 갱신하지 않음 (RC로만 처리)
    });
  });

  tracker.history.push({
    type: 'crash', pkgs: toAllow,
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
    added.forEach(p =>
      console.log(`\x1b[33m  + alwaysAllow: ${p}  (script required)\x1b[0m`)
    );
    console.log('\x1b[90m  Re-run: dryinstall install <pkg> && dryinstall run start\x1b[0m\n');
  }
}

/**
 * 정상 기동 → 차단이 안전했음을 학습
 * trust-cache: 앱 생존 기록은 installer.js의 trust record로 처리
 */
function _learnFromSuccess(tracker, blockedPkgs) {
  console.log('\n\x1b[32m[dryinstall:tracker] ✓ App started successfully with blocked scripts\x1b[0m');

  blockedPkgs.forEach(pkg => {
    if (!tracker.learned.safeToBlock.includes(pkg)) {
      tracker.learned.safeToBlock.push(pkg);
      console.log(`\x1b[32m  ✓ ${pkg} — script not needed\x1b[0m`);
    }
    tracker.pendingVerification = tracker.pendingVerification.filter(p => p.pkg !== pkg);

    // trust cache: 앱 생존 = 해당 패키지 차단이 안전했음을 기록
    // (자동 허용 아님 — 다음 설치 시 제안으로만 활용)
  });

  tracker.history.push({
    type: 'success', pkgs: blockedPkgs,
    at: new Date().toISOString(),
  });
  saveTracker(tracker);
  console.log('\x1b[90m  Learned. These scripts will be silently fast-passed from now on.\x1b[0m\n');
}

function _runAndMonitor(scriptName, cwd, onExit) {
  return new Promise((resolve, reject) => {
    const child = spawn('npm', ['run', scriptName], {
      cwd, stdio: 'inherit', shell: true,
    });

    const timeout = setTimeout(() => resolve({ success: true }), 8000);

    child.on('exit', (code) => {
      clearTimeout(timeout);
      let stderr = '';
      try {
        const logDir = path.join(os.homedir(), 'AppData', 'Local', 'npm-cache', '_logs');
        if (fs.existsSync(logDir)) {
          const logs = fs.readdirSync(logDir).sort().slice(-1);
          if (logs.length > 0)
            stderr = fs.readFileSync(path.join(logDir, logs[0]), 'utf-8').slice(-500);
        }
      } catch {}

      onExit(code, stderr);

      if (code === 0 || code === null) resolve({ success: true });
      else reject(new Error(`npm run ${scriptName} exited with code ${code}\n${stderr}`));
    });

    child.on('error', reject);
  });
}

function _passthrough(scriptName, cwd) {
  try { execSync(`npm run ${scriptName}`, { cwd, stdio: 'inherit' }); } catch {}
}

/**
 * dryinstall track status
 */
function printStatus() {
  const tracker = loadTracker();
  const W = 50;
  const LINE = '═'.repeat(W);

  console.log(`\n\x1b[36m${LINE}\x1b[0m`);
  console.log('\x1b[36m  dryinstall Execution Tracker\x1b[0m');
  console.log(`\x1b[36m${LINE}\x1b[0m`);

  if (tracker.pendingVerification.length > 0) {
    console.log('\n\x1b[33m  Pending verification:\x1b[0m');
    tracker.pendingVerification.forEach(p => {
      console.log(`\x1b[90m    ${p.pkg.padEnd(30)} blocked: ${p.hooks.join(', ')}\x1b[0m`);
    });
    console.log('\x1b[90m\n  Run: dryinstall run start\x1b[0m');
  }

  if (tracker.learned.safeToBlock.length > 0) {
    console.log('\n\x1b[32m  Safe to block (confirmed):\x1b[0m');
    tracker.learned.safeToBlock.forEach(p =>
      console.log(`\x1b[32m    ✓ ${p}\x1b[0m`)
    );
  }

  if (tracker.learned.needsScript.length > 0) {
    console.log('\n\x1b[33m  Script required (auto-allowed):\x1b[0m');
    tracker.learned.needsScript.forEach(p =>
      console.log(`\x1b[33m    ! ${p}\x1b[0m`)
    );
  }

  if (!tracker.learned.safeToBlock.length && !tracker.learned.needsScript.length) {
    console.log('\n\x1b[90m  No learning data yet.\x1b[0m');
    console.log('\x1b[90m  Run: dryinstall run start\x1b[0m');
  }

  // Trust cache 현황 함께 출력
  trustCache.printStatus();
}

module.exports = { recordBlocked, runWithTracking, printStatus };