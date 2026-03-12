'use strict';

/**
 * policy-demo.js
 * dryinstall.policy.json 기반 Least Privilege 시연
 */

const path = require('path');
const fs = require('fs');
const DryStorage = require('../src/storage');
const sandbox = require('../src/sandbox');

const DEMO_DIR = path.join(__dirname, '..', 'policy-demo-workspace');
const storage = new DryStorage(DEMO_DIR);

function separator(title) {
  console.log('\n' + '═'.repeat(52));
  console.log(`  ${title}`);
  console.log('═'.repeat(52));
}

async function runPolicyDemo() {
  if (fs.existsSync(DEMO_DIR)) fs.rmSync(DEMO_DIR, { recursive: true });
  fs.mkdirSync(DEMO_DIR, { recursive: true });

  separator('Policy File — Least Privilege 데모');
  console.log('패키지별 최소 권한만 부여\n');

  // 패키지 준비
  storage.store('evil-pkg', path.join(__dirname, 'malicious-pkg'));
  storage.store('safe-pkg', path.join(__dirname, 'safe-pkg'));

  // ── Policy 없음 (전부 차단) ───────────────────────
  separator('1. policy 없음 → 전부 차단 (deny all)');
  console.log('\n> evil-pkg: fs/net/child_process 전부 차단\n');
  const evilPath = path.join(DEMO_DIR, 'dry_modules', 'evil-pkg', 'index.js');
  sandbox.load(evilPath, 'evil-pkg');

  // ── Policy 적용 (허용 목록 명시) ─────────────────
  separator('2. policy 적용 → 허용된 모듈만 통과');
  console.log('\n> dryinstall.policy.json 확인:');
  console.log('  "puppeteer": { "allow": ["fs", "child_process"] }');
  console.log('  "express":   { "allow": ["net"] }');
  console.log('  "lodash":    { "allow": [] }\n');

  // safe-pkg (deny all)
  const safePath = path.join(DEMO_DIR, 'dry_modules', 'safe-pkg', 'index.js');
  sandbox.load(safePath, 'safe-pkg');

  // ── 정리 ─────────────────────────────────────────
  separator('3. Least Privilege 원칙 정리');
  console.log(`
  패키지        허용 모듈                  이유
  ─────────────────────────────────────────────────
  puppeteer     fs, child_process, net     크롬 실행 필요
  express       net, http, https           서버 소켓 필요
  lodash        (없음)                     순수 유틸리티
  left-pad      (없음)                     문자열 처리만
  evil-pkg      (없음)                     신뢰 불가
  `);

  console.log('\x1b[32m✓ 신뢰할 수 있는 패키지에만 최소한의 권한 부여\x1b[0m');
  console.log('\x1b[32m✓ 나머지는 전부 차단 — Zero Trust 원칙\x1b[0m\n');

  sandbox.report();
}

runPolicyDemo().catch(console.error);
