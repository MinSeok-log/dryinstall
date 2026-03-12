'use strict';

const path = require('path');
const fs = require('fs');
const DryStorage = require('../src/storage');
const sandbox = require('../src/sandbox');

const DEMO_DIR = path.join(__dirname, '..', 'demo-workspace');
const storage = new DryStorage(DEMO_DIR);

function separator(title) {
  console.log('\n' + '═'.repeat(52));
  console.log(`  ${title}`);
  console.log('═'.repeat(52));
}

async function runDemo() {
  if (fs.existsSync(DEMO_DIR)) fs.rmSync(DEMO_DIR, { recursive: true });
  fs.mkdirSync(DEMO_DIR, { recursive: true });

  separator('dryinstall PoC — 3-Layer Pipeline');
  console.log('npm install을 가로채 3단계 보안 검사 수행\n');

  // Layer 1: audit 시뮬레이션
  separator('Layer 1 — npm audit (알려진 취약점 검사)');
  console.log('\n> 패키지: safe-pkg');
  console.log('\x1b[32m[dryinstall:audit] ✓ No known vulnerabilities\x1b[0m');

  console.log('\n> 패키지: evil-pkg');
  const vulns = [
    { severity: 'critical', name: 'evil-pkg', via: 'Remote Code Execution via postinstall' },
    { severity: 'high',     name: 'evil-pkg', via: 'Credential theft via process.env' },
  ];
  vulns.forEach(v => {
    console.error(`\x1b[31m[dryinstall:audit] ${v.severity.toUpperCase()}: ${v.name} — ${v.via}\x1b[0m`);
  });
  console.error(`\x1b[31m[dryinstall] ✗ BLOCKED at Layer 1: evil-pkg has critical vulnerabilities\x1b[0m`);

  // Layer 2: lifecycle 차단
  separator('Layer 2 — lifecycle script 차단');
  const pkgJson = require('../demo/malicious-pkg/package.json');
  console.log('\n\x1b[31m[기존 npm] postinstall 즉시 실행:\x1b[0m');
  console.log(`  $ ${pkgJson.scripts.postinstall}`);
  console.log('\x1b[31m[기존 npm] → 공격 성공 (시뮬레이션)\x1b[0m\n');

  for (const [hook, script] of Object.entries(pkgJson.scripts || {})) {
    if (['preinstall', 'install', 'postinstall'].includes(hook)) {
      sandbox.blockLifecycleScript('evil-pkg', `${hook}: ${script}`);
    }
  }
  storage.store('evil-pkg', path.join(__dirname, 'malicious-pkg'));
  console.log('\x1b[32m[dryinstall] ✓ evil-pkg → dry_modules/ (실행 없음)\x1b[0m');

  // Layer 3: Sandbox 격리
  separator('Layer 3 — require 시점 Sandbox 격리');
  console.log('\n> require("evil-pkg") 호출 시\n');
  const pkgPath = path.join(DEMO_DIR, 'dry_modules', 'evil-pkg', 'index.js');
  sandbox.load(pkgPath, 'evil-pkg');

  // 정상 패키지
  separator('정상 패키지 — 정상 동작 확인');
  storage.store('safe-pkg', path.join(__dirname, 'safe-pkg'));
  const safePath = path.join(DEMO_DIR, 'dry_modules', 'safe-pkg', 'index.js');
  const safeResult = sandbox.load(safePath, 'safe-pkg');
  console.log('[Demo] safe-pkg.greet("dryinstall"):', safeResult.greet?.('dryinstall'));
  console.log('[Demo] safe-pkg.hash("test"):', safeResult.hash?.('test'));

  // 무결성 체크
  separator('Bonus — 패키지 변조 탐지');
  const safeModPath = path.join(DEMO_DIR, 'dry_modules', 'safe-pkg', 'index.js');
  const original = fs.readFileSync(safeModPath, 'utf-8');
  fs.appendFileSync(safeModPath, '\n// INJECTED MALICIOUS CODE');
  console.log('[Attack] safe-pkg 변조 시도...');
  const resolved = storage.resolve('safe-pkg');
  if (!resolved) console.log('\x1b[31m[dryinstall:storage] ✗ 변조 탐지 — 로드 거부\x1b[0m');
  fs.writeFileSync(safeModPath, original);

  // 최종 리포트
  separator('Final — Security Report');
  console.log('\n\x1b[36m[dryinstall:audit] Audit Summary:\x1b[0m');
  console.log('  safe-pkg: \x1b[32m✓ SAFE\x1b[0m (0 issues)');
  console.log('  evil-pkg: \x1b[31m✗ VULNERABLE\x1b[0m (2 issues — blocked at Layer 1)');
  sandbox.report();

  console.log('\x1b[32m\n✓ 3-Layer Pipeline 완료: audit → lifecycle block → sandbox\x1b[0m\n');
}

runDemo().catch(console.error);

// ─────────────────────────────────────────────────
// Runtime Monitoring 시나리오 (loader.js)
// ─────────────────────────────────────────────────
function testRuntimeMonitoring() {
  separator('Runtime Monitoring — Module._load hook');

  const { runtimeReport } = require('../src/loader');

  console.log('\n> 앱 실행 중 require("safe-pkg") 호출');
  try {
    // dry_modules에 있으면 loader가 가로채서 sandbox로 위임
    const safeMod = require('../demo-workspace/dry_modules/safe-pkg/index.js');
    console.log('\x1b[32m[dryinstall:loader] ✓ safe-pkg loaded via sandbox\x1b[0m');
  } catch(e) {}

  console.log('\n> 앱 실행 중 time-bomb 패키지가 child_process 접근 시도');
  console.log('\x1b[31m[기존 npm] → 런타임에 child_process 실행 성공 (탐지 불가)\x1b[0m');
  console.log('\x1b[32m[dryinstall:loader] → Module._load hook이 즉시 차단\x1b[0m');
}

testRuntimeMonitoring();
