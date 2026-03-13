'use strict';

/**
 * worker-demo.js
 * vm.createContext() vs Worker Threads 격리 비교
 */

const path = require('path');
const fs = require('fs');
const { loadInWorker } = require('../src/sandbox');
const DryStorage = require('../src/storage');

const DEMO_DIR = path.join(__dirname, '..', 'worker-demo-workspace');
const storage = new DryStorage(DEMO_DIR);

function separator(title) {
  console.log('\n' + '═'.repeat(52));
  console.log(`  ${title}`);
  console.log('═'.repeat(52));
}

async function runWorkerDemo() {
  if (fs.existsSync(DEMO_DIR)) fs.rmSync(DEMO_DIR, { recursive: true });
  fs.mkdirSync(DEMO_DIR, { recursive: true });

  separator('Worker Threads 격리 데모');
  console.log('vm.createContext() 한계 → Worker Thread 이중 격리\n');

  // evil-pkg 저장
  storage.store('evil-pkg', path.join(__dirname, 'malicious-pkg'));
  storage.store('safe-pkg', path.join(__dirname, 'safe-pkg'));

  // ── vm.createContext() 한계 시연 ──────────────────────
  separator('vm.createContext() 한계');
  console.log('\n> Sandbox 탈출 가능한 코드:');
  console.log(`  const obj = {};`);
  console.log(`  obj.constructor.constructor('return process')()`);
  console.log('\x1b[31m[vm] → process 객체 접근 가능 → Sandbox 탈출\x1b[0m');
  console.log('\x1b[31m[vm] → 메인 프로세스와 같은 공간이라 근본적 한계 존재\x1b[0m');

  // ── Worker Thread 격리 ────────────────────────────────
  separator('Worker Thread — 이중 격리');
  console.log('\n> 악성 패키지를 Worker Thread에서 실행\n');

  const evilPath = path.join(DEMO_DIR, 'dry_modules', 'evil-pkg', 'index.js');
  await loadInWorker(evilPath, 'evil-pkg');

  // ── 정상 패키지 ───────────────────────────────────────
  separator('Worker Thread — 정상 패키지');
  const safePath = path.join(DEMO_DIR, 'dry_modules', 'safe-pkg', 'index.js');
  await loadInWorker(safePath, 'safe-pkg');

  // ── 비교 정리 ─────────────────────────────────────────
  separator('격리 레벨 비교');
  console.log(`
  기존 npm          실행 환경 없음    개발자 PC 직접 실행
  vm.createContext  소프트 격리       같은 프로세스, 탈출 가능
  Worker Thread     하드 격리         별도 스레드, 메인 영향 없음
  Docker            시스템 격리       컨테이너 단위
  `);

  console.log('\x1b[32m✓ dryinstall = vm 격리 + Worker Thread 이중 격리\x1b[0m\n');
}

runWorkerDemo().catch(console.error);
