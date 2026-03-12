#!/usr/bin/env node
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');
const ex = require('../src/exception-handler');

const args = process.argv.slice(2);
const command = args[0];

const isInstall = command === 'install' || command === 'i';
const isStart   = command === 'start';
const isScan    = command === 'scan';

if (isScan) {
  const Scanner = require('../src/scanner');
  const scanner = new Scanner(process.cwd());
  scanner.scan().catch(console.error);
  return;
}

if (isInstall) {
  const pkgArgs = args.slice(1).filter(a => !a.startsWith('-'));
  const flags   = args.slice(1).filter(a => a.startsWith('-'));

  if (pkgArgs.length === 0) {
    console.log('\x1b[33m[dryinstall] Bulk install detected — passing to npm\x1b[0m');
    const result = spawnSync('npm', args, { stdio: 'inherit' });
    process.exit(result.status || 0);
  }

  // 직접 npm install 경고
  ex.warnDirectNpmInstall(pkgArgs);

  const DryCLI  = require('../src/cli');
  const sandbox = require('../src/sandbox');
  const auditor = require('../src/auditor');
  const cli = new DryCLI(process.cwd());

  (async () => {
    for (const pkg of pkgArgs) {
      const auditResult = auditor.audit(pkg);
      if (!auditResult.safe) {
        console.error(`\x1b[31m[dryinstall] ✗ BLOCKED: ${pkg} has critical/high vulnerabilities\x1b[0m`);
        if (!flags.includes('--force')) continue;
      }
      try { await cli.install(pkg); } catch (err) {
        console.error(`\x1b[31m[dryinstall] Install failed: ${err.message}\x1b[0m`);
      }
    }
    sandbox.report();
  })();
  return;
}

// npm start는 그대로 통과 (setup-loader가 처리)
// 그 외 명령어는 원본 npm에 위임
const result = spawnSync('npm', args, { stdio: 'inherit' });
process.exit(result.status || 0);
