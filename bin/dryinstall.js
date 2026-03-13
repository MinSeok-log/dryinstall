#!/usr/bin/env node
'use strict';

const DryCLI         = require('../src/cli');
const Scanner        = require('../src/scanner');
const sandbox        = require('../src/sandbox');
const monitor        = require('../src/monitor');
const advisor        = require('../src/advisor');
const executionTracker = require('../src/execution-tracker');
const ex             = require('../src/exception-handler');
const { check, checkMultiple } = require('../src/checker');

// ── 시작 시 환경 검사 ─────────────────────────────────
const startupCheck = ex.runStartupChecks();
if (!startupCheck.nodeVersion.ok) process.exit(1);
const defaultLevel = startupCheck.nodeVersion.level;

const args    = process.argv.slice(2);
const command = args[0];

// ── 옵션 파싱 ─────────────────────────────────────────
const levelFlag    = args.find(a => a.startsWith('--level='));
const allowFlag    = args.find(a => a.startsWith('--allow='));
const allowPkgFlag = args.find(a => a.startsWith('--allow-package='));
const interactive  = args.includes('--interactive') || args.includes('-i');
const watchFlag    = args.includes('--watch');
const jsonFlag     = args.includes('--json');
const dryRun       = args.includes('--dry-run');

const level          = levelFlag    ? parseInt(levelFlag.split('=')[1])        : defaultLevel;
const extraAllowed   = allowFlag    ? allowFlag.split('=')[1].split(',')       : [];
const allowedPackages = allowPkgFlag ? allowPkgFlag.split('=')[1].split(',')  : [];

// 패키지명 — 명령어/플래그 아닌 첫 번째 인수
const pkgName = args.filter(a =>
  !a.startsWith('--') && a !== command && a !== args[1]
)[0] || args.filter(a => !a.startsWith('--') && a !== command)[0];

// sandbox 옵션 적용
sandbox.setLevel(level);
sandbox.setInteractive(interactive);
sandbox.setExtraAllowed(extraAllowed);
sandbox.setAllowedPackages(allowedPackages);

const cli = new DryCLI(process.cwd());

(async () => {
  if (watchFlag) {
    monitor.snapshot();
    monitor.start();
  }

  // ── install ─────────────────────────────────────────
  if (command === 'install' && pkgName) {

    // --dry-run: 설치 없이 분석만
    if (dryRun) {
      const result = await check(pkgName, { json: jsonFlag });
      if (jsonFlag) process.exit(result.ciExitCode ?? 0);
      process.exit(result.verdict === 'BLOCK' ? 1 : 0);
    }

    await cli.install(pkgName);
    sandbox.report();

  // ── check ────────────────────────────────────────────
  } else if (command === 'check') {
    // dryinstall check <pkg> [<pkg2> ...] [--json]
    const targets = args
      .slice(1)
      .filter(a => !a.startsWith('--'));

    if (targets.length === 0) {
      console.error('Usage: dryinstall check <pkg> [<pkg2> ...] [--json]');
      process.exit(1);
    }

    if (targets.length === 1) {
      const result = await check(targets[0], { json: jsonFlag });
      if (jsonFlag) process.exit(result.ciExitCode ?? 0);
      process.exit(result.verdict === 'BLOCK' ? 1 : 0);
    } else {
      const results = await checkMultiple(targets, { json: jsonFlag });
      if (jsonFlag) {
        const hasBlock = Array.isArray(results)
          ? results.some(r => r.verdict === 'BLOCK')
          : results.ciExitCode === 1;
        process.exit(hasBlock ? 1 : 0);
      }
      const hasBlock = results.some(r => r.verdict === 'BLOCK');
      process.exit(hasBlock ? 1 : 0);
    }

  // ── clean-install ────────────────────────────────────
  } else if (command === 'clean-install') {
    await cli.cleanInstall();
    sandbox.report();

  // ── scan ─────────────────────────────────────────────
  } else if (command === 'scan') {
    const scanner = new Scanner(process.cwd());
    if (jsonFlag) {
      // --json: scanner 내부 console 억제, stdout에 JSON만
      const _l = console.log, _w = console.warn, _e = console.error;
      console.log = console.warn = console.error = (...a) => process.stderr.write(a.join(' ') + '\n');
      const result = await scanner.scan();
      console.log = _l; console.warn = _w; console.error = _e;
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      await scanner.scan();
    }

  // ── list ─────────────────────────────────────────────
  } else if (command === 'list') {
    cli.list();

  // ── setup-loader / remove-loader ─────────────────────
  } else if (command === 'setup-loader') {
    cli.setupLoader();

  } else if (command === 'remove-loader') {
    cli.removeLoader();

  // ── profile ──────────────────────────────────────────
  } else if (command === 'profile') {
    if (jsonFlag) {
      // printProfileReport가 출력하는 내용을 캡처해서 JSON으로 반환
      const lines = [];
      const _l = console.log;
      console.log = (...a) => lines.push(a.join(' '));
      advisor.printProfileReport();
      console.log = _l;
      process.stdout.write(JSON.stringify({ output: lines }, null, 2) + '\n');
    } else {
      advisor.printProfileReport();
    }

  // ── config suggest ───────────────────────────────────
  } else if (command === 'config' && args[1] === 'suggest') {
    await advisor.runSuggest();

  // ── run ──────────────────────────────────────────────
  } else if (command === 'run') {
    const scriptName = args[1] || 'start';
    await executionTracker.runWithTracking(scriptName, process.cwd());

  // ── track status ─────────────────────────────────────
  } else if (command === 'track' && args[1] === 'status') {
    if (jsonFlag) {
      const lines = [];
      const _l = console.log;
      console.log = (...a) => lines.push(a.join(' '));
      executionTracker.printStatus();
      console.log = _l;
      process.stdout.write(JSON.stringify({ output: lines }, null, 2) + '\n');
    } else {
      executionTracker.printStatus();
    }

  // ── help ─────────────────────────────────────────────
  } else {
    console.log(`
Usage:
  dryinstall install <pkg>                          Install through 8-layer security pipeline
  dryinstall install <pkg> --interactive            Prompt before each blocked lifecycle script
  dryinstall install <pkg> --level=0-3             Set security level (default: 3)
  dryinstall install <pkg> --allow=fs,net           Allow specific modules in sandbox
  dryinstall install <pkg> --allow-package=a,b      Allow lifecycle for specific packages
  dryinstall install <pkg> --allow-maintainer-change  Skip maintainer takeover block
  dryinstall install <pkg> --watch                  Enable background process monitoring
  dryinstall install <pkg> --dry-run                Analyze without installing
  dryinstall install <pkg> --json                   Output results as JSON

  dryinstall check <pkg> [<pkg2> ...]               Analyze packages without installing
  dryinstall check <pkg> --json                     CI-friendly JSON output (exit 1 if blocked)

  dryinstall clean-install                          Remove node_modules and reinstall
  dryinstall scan                                   Scan installed node_modules for risks
  dryinstall scan --json                            JSON output
  dryinstall list                                   List packages in dry_modules

  dryinstall profile                                Show adaptive developer profile
  dryinstall config suggest                         Auto-tune ~/.dryinstallrc

  dryinstall run <script>                           Run npm script with execution tracking
  dryinstall track status                           Show execution learning status

  dryinstall setup-loader                           Register runtime loader in package.json
  dryinstall remove-loader                          Remove loader registration

Security Levels:
  Level 3  Paranoid   Block all modules + Worker Thread isolation  (default)
  Level 2  Balanced   Block child_process only, allow fs/net
  Level 1  Relaxed    vm isolation only, no Worker Thread
  Level 0  Off        Observe only, no blocking

CI/CD Usage:
  dryinstall check express lodash --json
  dryinstall install react --dry-run --json
  → exit code 0: safe  |  exit code 1: blocked

Pipeline:
  ① Confusion Detection   Detects Dependency Confusion attacks
  ② Hash Verification     Validates tarball SHA512 integrity
  ③ Version Diff          Compares versions for new dangerous patterns
  ④ Stealth Detection     CI backdoors, time bombs, base64 eval
  ⑤ Maintainer Monitor    Tracks maintainer changes / account takeovers
  ⑥ CVE Audit             Known vulnerabilities via npm audit
  ⑦ Lifecycle Block       Blocks ALL install-time scripts
  ⑧ Sandbox Isolation     vm + Worker Thread isolation
`);
  }

  if (!watchFlag) process.exit(0);
})();