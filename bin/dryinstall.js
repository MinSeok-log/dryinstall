#!/usr/bin/env node
'use strict';

const DryCLI  = require('../src/cli');
const Scanner = require('../src/scanner');
const sandbox = require('../src/sandbox');
const monitor = require('../src/monitor');
const advisor = require('../src/advisor');
const executionTracker = require('../src/execution-tracker');
const ex = require('../src/exception-handler');

// ── 시작 시 환경 검사 ─────────────────────────────────
const startupCheck = ex.runStartupChecks();
if (!startupCheck.nodeVersion.ok) {
  process.exit(1);
}
// Node 버전이 낮으면 보안 레벨 자동 조정
const defaultLevel = startupCheck.nodeVersion.level;

const args = process.argv.slice(2);
const command = args[0];

// ── 옵션 파싱 ─────────────────────────────────────────
const levelFlag       = args.find(a => a.startsWith('--level='));
const allowFlag       = args.find(a => a.startsWith('--allow='));
const allowPkgFlag    = args.find(a => a.startsWith('--allow-package='));
const interactive     = args.includes('--interactive') || args.includes('-i');
const watchFlag       = args.includes('--watch');

const level = levelFlag ? parseInt(levelFlag.split('=')[1]) : defaultLevel;
const extraAllowed    = allowFlag ? allowFlag.split('=')[1].split(',') : [];
const allowedPackages = allowPkgFlag ? allowPkgFlag.split('=')[1].split(',') : [];
const pkgName         = args.filter(a => !a.startsWith('--') && a !== command)[0];

// sandbox 옵션 적용
sandbox.setLevel(level);
sandbox.setInteractive(interactive);
sandbox.setExtraAllowed(extraAllowed);
sandbox.setAllowedPackages(allowedPackages);

const cli = new DryCLI(process.cwd());

(async () => {
  // --watch 옵션 시 프로세스 모니터 시작
  if (watchFlag) {
    monitor.snapshot();
    monitor.start();
  }

  if (command === 'install' && pkgName) {
    await cli.install(pkgName);
    sandbox.report();

  } else if (command === 'clean-install') {
    await cli.cleanInstall();
    sandbox.report();

  } else if (command === 'scan') {
    const scanner = new Scanner(process.cwd());
    await scanner.scan();

  } else if (command === 'list') {
    cli.list();

  } else if (command === 'setup-loader') {
    cli.setupLoader();

  } else if (command === 'remove-loader') {
    cli.removeLoader();

  } else if (command === 'profile') {
    advisor.printProfileReport();

  } else if (command === 'config' && args[1] === 'suggest') {
    await advisor.runSuggest();

  } else if (command === 'run') {
    // dryinstall run <script>
    // npm run <script>를 감싸서 실행 결과 학습
    const scriptName = args[1] || 'start';
    await executionTracker.runWithTracking(scriptName, process.cwd());

  } else if (command === 'track' && args[1] === 'status') {
    executionTracker.printStatus();

  } else {
    console.log('\nUsage:');
    console.log('  dryinstall install <pkg>                          Install a package through the security pipeline');
    console.log('  dryinstall install <pkg> --level=2                Set security level (0~3, default: 3)');
    console.log('  dryinstall install <pkg> --allow=fs,net           Allow specific Node.js modules in sandbox');
    console.log('  dryinstall install <pkg> --interactive            Prompt before each blocked lifecycle script');
    console.log('  dryinstall install <pkg> --watch                  Enable background process monitoring');
    console.log('  dryinstall install <pkg> --allow-package=a,b      Allow lifecycle scripts for specific packages');
    console.log('  dryinstall install <pkg> --allow-maintainer-change  Skip maintainer takeover block');
    console.log('  dryinstall clean-install                          Remove node_modules and reinstall');
    console.log('  dryinstall scan                                   Scan installed node_modules for risks');
    console.log('  dryinstall list                                   List packages stored in dry_modules');
    console.log('  dryinstall profile                                Show adaptive developer profile & recommendations');
    console.log('  dryinstall config suggest                         Auto-tune ~/.dryinstallrc from your usage data');
    console.log('  dryinstall run <script>                           Run npm script with execution tracking');
    console.log('  dryinstall track status                           Show execution learning status');
    console.log('  dryinstall setup-loader                           Register dryinstall loader in package.json start');
    console.log('  dryinstall remove-loader                          Remove loader registration');
    console.log('\nSecurity Levels:');
    console.log('  Level 3  Paranoid   Block all modules + Worker Thread isolation  (default)');
    console.log('  Level 2  Balanced   Block child_process only, allow fs/net');
    console.log('  Level 1  Relaxed    vm isolation only, no Worker Thread');
    console.log('  Level 0  Off        Observe only, no blocking');
    console.log('\nPipeline:');
    console.log('  ① Confusion Detection   Detects Dependency Confusion attacks on scoped packages');
    console.log('  ② Hash Verification     Validates tarball SHA512 against registry integrity field');
    console.log('  ③ Version Diff          Compares JS files between versions for new dangerous patterns');
    console.log('  ④ Stealth Detection     Detects CI backdoors, time bombs, base64 eval, env exfil');
    console.log('  ⑤ Maintainer Monitor    Tracks maintainer changes, detects account takeovers');
    console.log('  ⑥ CVE Audit             Checks for known vulnerabilities via npm audit');
    console.log('  ⑦ Lifecycle Block       Blocks ALL install-time scripts (preinstall, postinstall...)');
    console.log('  ⑧ Sandbox Isolation     vm + Worker Thread + fs/net/child_process API blocking\n');
  }

  // --watch 없으면 monitor 안 씀
  if (!watchFlag) process.exit(0);
})();
