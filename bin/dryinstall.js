#!/usr/bin/env node
'use strict';

const DryCLI           = require('../src/cli');
const Scanner          = require('../src/scanner');
const sandbox          = require('../src/sandbox');
const monitor          = require('../src/monitor');
const advisor          = require('../src/advisor');
const executionTracker = require('../src/execution-tracker');
const trustCache = require('../src/trust-cache');
const ex               = require('../src/exception-handler');
const { check, checkMultiple } = require('../src/checker');
const logger           = require('../src/logger');
const { runInspect }   = require('../src/startup-inspector');
const { diagnose, printReport, fix: doctorFix } = require('../src/doctor');

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
const quietFlag    = args.includes('--quiet')   || args.includes('-q');
const verboseFlag  = args.includes('--verbose') || args.includes('-v');

if (jsonFlag)         logger.setJson(true);
else if (quietFlag)   logger.setLevel('QUIET');
else if (verboseFlag) logger.setLevel('VERBOSE');

const level           = levelFlag     ? parseInt(levelFlag.split('=')[1])       : defaultLevel;
const extraAllowed    = allowFlag     ? allowFlag.split('=')[1].split(',')       : [];
const allowedPackages = allowPkgFlag  ? allowPkgFlag.split('=')[1].split(',')   : [];

const pkgName = args.filter(a =>
  !a.startsWith('--') && a !== command && a !== args[1]
)[0] || args.filter(a => !a.startsWith('--') && a !== command)[0];

// ── DRYINSTALL_LEVEL 환경변수 주입 ← 핵심 추가
process.env.DRYINSTALL_LEVEL = String(level);

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
    if (dryRun) {
      const result = await check(pkgName, { json: jsonFlag });
      if (jsonFlag) process.exit(result.ciExitCode ?? 0);
      process.exit(result.verdict === 'BLOCK' ? 1 : 0);
    }
    await cli.install(pkgName);
    sandbox.report();

  // ── check ────────────────────────────────────────────
  } else if (command === 'check') {
    const targets = args.slice(1).filter(a => !a.startsWith('--'));
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
      process.exit(results.some(r => r.verdict === 'BLOCK') ? 1 : 0);
    }

  // ── clean-install ────────────────────────────────────
  } else if (command === 'clean-install') {
    await cli.cleanInstall();
    sandbox.report();

  // ── scan ─────────────────────────────────────────────
  } else if (command === 'scan') {
    const scanner = new Scanner(process.cwd());
    if (jsonFlag) {
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
      const lines = [];
      const _l = console.log;
      console.log = (...a) => lines.push(a.join(' '));
      advisor.printProfileReport();
      trustCache.printStatus();
      console.log = _l;
      process.stdout.write(JSON.stringify({ output: lines }, null, 2) + '\n');
    } else {
      advisor.printProfileReport();
      trustCache.printStatus();
    }

  // ── config suggest ───────────────────────────────────
  } else if (command === 'config' && args[1] === 'suggest') {
    await advisor.runSuggest();

  // ── allow <pkg> ──────────────────────────────────────
  // dryinstall allow <pkg>  — 수동으로 ECU whitelist 추가
  } else if (command === 'trust' && args[1] === 'status') {
    trustCache.printStatus();

  } else if (command === '_allow_disabled' && pkgName) {
    trustCache.record(pkgName, 'any', 'any', '', 'user_blocked');
    console.log(`\x1b[33m[dryinstall] ${pkgName} added to trust cache — will prompt on next install\x1b[0m`);

  // ── deny <pkg> ───────────────────────────────────────
  // dryinstall deny <pkg>  — ECU 학습에서 제거
  } else if (command === '_deny_disabled' && pkgName) {
    console.log(`\x1b[33m[dryinstall] Use dryinstall trust status to manage trust cache\x1b[0m`);

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

  // ── doctor ───────────────────────────────────────────
  } else if (command === 'doctor') {
    const results = await diagnose(process.cwd());
    printReport(results);

  // ── inspect ──────────────────────────────────────────
  } else if (command === 'inspect') {
    const verbose = args.includes('--verbose') || args.includes('-v');
    runInspect(process.cwd(), { verbose });

  // ── fix ───────────────────────────────────────────────
  } else if (command === 'fix') {
    const targetPkg = args[1] || null;
    await doctorFix(process.cwd(), targetPkg);

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
  dryinstall list                                   List packages in dry_modules

  dryinstall profile                                Show developer profile + ECU learned whitelist
  dryinstall config suggest                         Auto-tune .dryinstallrc + ECU suggestions

  dryinstall trust status                           Show trust cache entries + confidence scores

  dryinstall run <script>                           Run npm script with execution tracking
  dryinstall track status                           Show execution learning status

  dryinstall setup-loader                           Register runtime loader in package.json
  dryinstall remove-loader                          Remove loader registration

  dryinstall doctor                                 Diagnose dependencies
  dryinstall inspect [--verbose]                    Show dependency load status
  dryinstall fix [<pkg>]                            Restore sandboxed packages

Security Levels:
  Level 3  Paranoid   Full scan + block all scripts          (CI / security teams)
  Level 2  Balanced   Malicious only + whitelist fast-pass   (general developers)  ← default
  Level 1  Relaxed    Install first + scan after             (fast prototyping)
  Level 0  Observer   Logs only, nothing blocked             (monitoring)

Trust Cache:
  Evidence-based lifecycle decision memory
  Enter = No always — auto-allow never happens
  dryinstall trust status  to see trust cache entries
`);
  }

  if (!watchFlag) process.exit(0);
})();