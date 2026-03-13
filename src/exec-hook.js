#!/usr/bin/env node
'use strict';

/**
 * exec-hook.js
 * npm start / npm run dev 앞에 자동으로 붙어서
 * execution-tracker를 활성화합니다.
 *
 * package.json에서:
 *   "start": "node ./node_modules/dryinstall/src/exec-hook.js start && react-scripts start"
 *
 * 역할:
 *   - pendingVerification 있는지 확인
 *   - 있으면 "tracking active" 표시
 *   - 프로세스 종료 시 결과 기록 (exit hook)
 */

const { recordBlocked } = require('./execution-tracker');
const fs = require('fs');
const path = require('path');
const os = require('os');

const TRACKER_PATH = path.join(os.homedir(), '.dryinstall-exectrack.json');

function loadTracker() {
  try {
    if (fs.existsSync(TRACKER_PATH)) {
      return JSON.parse(fs.readFileSync(TRACKER_PATH, 'utf-8'));
    }
  } catch {}
  return { pendingVerification: [], learned: { safeToBlock: [], needsScript: [] }, history: [] };
}

function saveTracker(data) {
  try { fs.writeFileSync(TRACKER_PATH, JSON.stringify(data, null, 2)); } catch {}
}

const tracker = loadTracker();
const pending = tracker.pendingVerification || [];

if (pending.length === 0) {
  // 검증할 게 없으면 조용히 종료 → 원본 명령 실행으로 넘어감
  process.exit(0);
}

const pkgs = pending.map(p => p.pkg);
console.log('\x1b[36m[dryinstall] Execution tracking active\x1b[0m');
console.log(`\x1b[90m  Monitoring: ${pkgs.join(', ')}\x1b[0m`);
console.log('\x1b[90m  If app crashes, run "dryinstall track status" to see results\x1b[0m\n');

// 시작 시각 기록
tracker._runStartedAt = new Date().toISOString();
saveTracker(tracker);

// exit hook — 부모 프로세스(npm run)가 종료될 때 감지
const startTime = Date.now();

process.on('exit', (code) => {
  const elapsed = Date.now() - startTime;
  const t = loadTracker();
  const stillPending = t.pendingVerification || [];

  if (stillPending.length === 0) return;

  // 5초 미만 종료 + exit code != 0 → 크래시
  if (code !== 0 && elapsed < 5000) {
    stillPending.forEach(p => {
      if (!t.learned.needsScript.includes(p.pkg)) {
        t.learned.needsScript.push(p.pkg);
      }
    });
    t.pendingVerification = [];
    t.history.push({
      type: 'crash_detected',
      pkgs: stillPending.map(p => p.pkg),
      at: new Date().toISOString(),
    });
    saveTracker(t);

    // RC 자동 업데이트
    const RC_PATH = path.join(os.homedir(), '.dryinstallrc');
    let rc = { alwaysAllow: [], alwaysBlock: [] };
    try { rc = JSON.parse(fs.readFileSync(RC_PATH, 'utf-8')); } catch {}
    if (!rc.alwaysAllow) rc.alwaysAllow = [];

    const added = [];
    stillPending.forEach(p => {
      if (!rc.alwaysAllow.includes(p.pkg)) {
        rc.alwaysAllow.push(p.pkg);
        added.push(p.pkg);
      }
    });

    if (added.length > 0) {
      fs.writeFileSync(RC_PATH, JSON.stringify(rc, null, 2));
      console.log('\n\x1b[33m[dryinstall] Auto-learned from crash:\x1b[0m');
      added.forEach(p => console.log(`\x1b[33m  + alwaysAllow: ${p}\x1b[0m`));
      console.log('\x1b[90m  Reinstall and restart to apply\x1b[0m\n');
    }
  } else if (elapsed >= 5000) {
    // 5초 이상 정상 동작 → 차단이 안전했음
    stillPending.forEach(p => {
      if (!t.learned.safeToBlock.includes(p.pkg)) {
        t.learned.safeToBlock.push(p.pkg);
      }
    });
    t.pendingVerification = [];
    t.history.push({
      type: 'success',
      pkgs: stillPending.map(p => p.pkg),
      at: new Date().toISOString(),
    });
    saveTracker(t);
  }
});

process.exit(0);

module.exports = {};