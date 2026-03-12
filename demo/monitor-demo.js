'use strict';

/**
 * monitor-demo.js
 * 백그라운드 프로세스 + 네트워크 감시 시연
 */

const monitor = require('../src/monitor');

function separator(title) {
  console.log('\n' + '═'.repeat(52));
  console.log(`  ${title}`);
  console.log('═'.repeat(52));
}

async function runMonitorDemo() {
  separator('Process Monitor 데모');
  console.log('설치 후 백그라운드 악성 프로세스 탐지 시연\n');

  // ── 기준선 스냅샷 ─────────────────────────────────
  separator('1. 기준선 스냅샷 (정상 프로세스 기록)');
  monitor.snapshot();

  // ── 모니터링 시작 ─────────────────────────────────
  separator('2. 모니터링 시작');
  monitor.start();

  // ── 시나리오 설명 ─────────────────────────────────
  separator('3. 공격 시나리오');
  console.log(`
  기존 npm 상황:
  → lodash 설치 (정상처럼 보임)
  → 앱 실행 후 setTimeout 5초 뒤
  → child_process로 curl attacker.com 실행
  → 백그라운드에서 데이터 유출 시작
  → 기존 도구는 탐지 불가

  dryinstall --watch:
  → 설치 전 프로세스 스냅샷
  → 앱 실행 중 2초마다 새 프로세스 체크
  → curl/wget/nc 등 의심 프로세스 즉시 감지
  → 즉시 kill + 알림
  `);

  // ── 네트워크 감시 설명 ────────────────────────────
  separator('4. 네트워크 아웃바운드 감시');
  console.log(`
  감시 대상 포트:
  → 4444  (Metasploit 기본 reverse shell)
  → 1337  (흔한 해커 포트)
  → 31337 (elite 포트)
  → 1024 이하 비표준 포트

  안전한 포트 (허용):
  → 443  (HTTPS)
  → 80   (HTTP)
  → 3000 (개발 서버)
  `);

  // ── 사용법 ───────────────────────────────────────
  separator('5. 사용법');
  console.log('  # 설치 시 프로세스 모니터링 활성화');
  console.log('  dryinstall install lodash --watch\n');
  console.log('  # npm start 시 자동으로 모니터 시작');
  console.log('  npm start  (npm-wrapper 통해 자동 적용)\n');

  // 3초 후 모니터 중지
  console.log('\x1b[36m[demo] 3초간 모니터링 후 종료...\x1b[0m');
  await new Promise(r => setTimeout(r, 3000));

  monitor.stop();
}

runMonitorDemo().catch(console.error);
