'use strict';

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const DepGraph = require('./dep-graph');
const logger   = require('./logger');

/**
 * Doctor
 * dryinstall doctor — 의존성 진단 + 원인 추적 + 자동 수정
 *
 * 출력:
 *   ① Summary     전체 상태 한 줄
 *   ② Table       패키지별 상태 표
 *   ③ Cause       missing/sandboxed 원인 — 누가 요구했는지
 *   ④ Fix         npm install / dryinstall fix 자동 실행
 */

const C = {
  RED:    '\x1b[31m', YELLOW: '\x1b[33m', GREEN:  '\x1b[32m',
  CYAN:   '\x1b[36m', GRAY:   '\x1b[90m', BOLD:   '\x1b[1m',
  RESET:  '\x1b[0m',
};

// ── 패키지 역할 설명 ────────────────────────────────────
const KNOWN_ROLES = {
  'react': 'UI core', 'react-dom': 'DOM renderer',
  'react-scripts': 'CRA build tool', 'react-router-dom': 'routing',
  'react-redux': 'state management', '@tanstack/react-query': 'server state',
  'webpack': 'bundler', 'vite': 'bundler', 'next': 'React framework',
  'core-js': 'ES polyfill', 'core-js-pure': 'ES polyfill (modular)',
  'regenerator-runtime': 'async polyfill',
  'axios': 'HTTP client', 'node-fetch': 'HTTP client',
  'jest': 'test runner', 'vitest': 'test runner',
  'axe-core': 'a11y testing', 'eslint': 'linter',
  'eslint-plugin-jsx-a11y': 'a11y lint rules',
  'prettier': 'formatter', 'typescript': 'type checker',
  'jiti': 'TS/ESM runtime loader', 'ts-node': 'TS runner',
  '@pmmmwh/react-refresh-webpack-plugin': 'HMR plugin',
  'lodash': 'utility', 'dayjs': 'date utility', 'zod': 'schema validation',
  'dryinstall': 'security layer',
};

// ── 상태 판별 ────────────────────────────────────────────
function getStatus(pkgName, cwd) {
  const nodeDir = path.join(cwd, 'node_modules', pkgName);
  const dryDir  = path.join(cwd, 'dry_modules',  pkgName);

  if (fs.existsSync(dryDir))  return 'sandboxed';
  if (fs.existsSync(nodeDir)) return 'ok';
  return 'missing';
}

function getInstalledVersion(pkgName, cwd) {
  for (const base of ['node_modules', 'dry_modules']) {
    const p = path.join(cwd, base, pkgName, 'package.json');
    if (fs.existsSync(p)) {
      try { return JSON.parse(fs.readFileSync(p, 'utf-8')).version || '?'; }
      catch {}
    }
  }
  return null;
}

// ── 진단 실행 ────────────────────────────────────────────
async function diagnose(cwd = process.cwd()) {
  const pkgJsonPath = path.join(cwd, 'package.json');
  if (!fs.existsSync(pkgJsonPath)) {
    logger.warn('doctor: package.json not found');
    return [];
  }

  let appPkg;
  try { appPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8')); }
  catch { logger.warn('doctor: failed to parse package.json'); return []; }

  const allDeps = {
    ...appPkg.dependencies    || {},
    ...appPkg.devDependencies || {},
  };

  // dep-graph로 역추적 준비
  const graph = new DepGraph(cwd);
  await graph.build();

  const results = [];

  for (const [name, versionRange] of Object.entries(allDeps)) {
    const status  = getStatus(name, cwd);
    const version = getInstalledVersion(name, cwd) || versionRange;
    const role    = KNOWN_ROLES[name] || '';

    // missing/sandboxed면 왜 필요한지 역추적
    let requiredBy = [];
    if (status !== 'ok') {
      const chains = graph.findChains(name);
      // 직접 의존성 제외하고 간접 의존성 체인만
      requiredBy = chains
        .filter(c => c.length > 1)
        .slice(0, 3)
        .map(c => c.slice(0, -1).join(' → '));
    }

    results.push({ name, status, version, role, requiredBy, versionRange });
  }

  return results;
}

// ── 출력 ────────────────────────────────────────────────

function printReport(results) {
  const missing   = results.filter(r => r.status === 'missing');
  const sandboxed = results.filter(r => r.status === 'sandboxed');
  const ok        = results.filter(r => r.status === 'ok');
  const problems  = [...missing, ...sandboxed];

  const col1 = Math.min(35, Math.max(12, ...results.map(r => r.name.length)) + 2);
  const col2 = 14;
  const col3 = 22;
  const col4 = 10;
  const W    = col1 + col2 + col3 + col4 + 4;
  const line = '─'.repeat(W);
  const dline = '═'.repeat(W);

  // ── ① Summary ──────────────────────────────────────────
  logger.always(`\n${C.CYAN}${dline}${C.RESET}`);
  logger.always(`${C.BOLD}${C.CYAN}  dryinstall — Dependency Doctor${C.RESET}`);
  logger.always(`${C.CYAN}${dline}${C.RESET}`);

  if (problems.length === 0) {
    logger.always(`  ${C.GREEN}${C.BOLD}✓ All dependencies are healthy${C.RESET}`);
    logger.always(`${C.CYAN}${dline}${C.RESET}\n`);
    return;
  }

  logger.always(
    `  ${C.GREEN}✓ ok: ${ok.length}${C.RESET}  ` +
    `${C.YELLOW}⚠ sandboxed: ${sandboxed.length}${C.RESET}  ` +
    `${C.RED}✗ missing: ${missing.length}${C.RESET}`
  );

  // ── ② Table — 문제 있는 것만 ───────────────────────────
  logger.always(`\n${C.CYAN}${line}${C.RESET}`);
  logger.always(
    `  ${C.BOLD}` +
    `${'Package'.padEnd(col1)}` +
    `${'Status'.padEnd(col2)}` +
    `${'Role'.padEnd(col3)}` +
    `${'Version'.padEnd(col4)}` +
    `${C.RESET}`
  );
  logger.always(`${C.CYAN}${line}${C.RESET}`);

  for (const r of problems) {
    const color = r.status === 'missing' ? C.RED : C.YELLOW;
    const icon  = r.status === 'missing' ? '✗ missing  ' : '⚠ sandboxed';
    logger.always(
      `  ${color}${r.name.slice(0, col1 - 1).padEnd(col1)}` +
      `${icon.padEnd(col2)}${C.RESET}` +
      `${C.GRAY}${(r.role || '—').slice(0, col3 - 1).padEnd(col3)}${C.RESET}` +
      `  ${r.version || '—'}`
    );
  }

  logger.always(`${C.CYAN}${line}${C.RESET}`);

  // ── ③ Cause — 누가 이 패키지를 요구했는지 ──────────────
  const withCause = problems.filter(r => r.requiredBy.length > 0);
  if (withCause.length > 0) {
    logger.always(`\n${C.BOLD}  Why these packages are needed:${C.RESET}`);
    for (const r of withCause) {
      const color = r.status === 'missing' ? C.RED : C.YELLOW;
      logger.always(`\n  ${color}${r.name}${C.RESET}  ${C.GRAY}(${r.status})${C.RESET}`);
      r.requiredBy.forEach(chain => {
        logger.always(`    ${C.GRAY}required by: ${chain}${C.RESET}`);
      });
    }
  }

  // ── ④ Fix 제안 ─────────────────────────────────────────
  logger.always(`\n${C.CYAN}${line}${C.RESET}`);
  logger.always(`${C.BOLD}  Suggested fixes:${C.RESET}`);

  if (missing.length > 0) {
    const pkgList = missing.map(r => r.name).join(' ');
    logger.always(`\n  ${C.GRAY}Missing packages:${C.RESET}`);
    logger.always(`  ${C.GREEN}npm install ${pkgList}${C.RESET}`);
  }
  if (sandboxed.length > 0) {
    logger.always(`\n  ${C.GRAY}Sandboxed packages (run app first to verify safety):${C.RESET}`);
    logger.always(`  ${C.YELLOW}dryinstall fix${C.RESET}  ${C.GRAY}— restore all to node_modules${C.RESET}`);
    sandboxed.forEach(r => {
      logger.always(`  ${C.YELLOW}dryinstall fix ${r.name}${C.RESET}  ${C.GRAY}— restore only ${r.name}${C.RESET}`);
    });
  }

  logger.always(`${C.CYAN}${dline}${C.RESET}\n`);
}

// ── 자동 수정 ────────────────────────────────────────────

async function fix(cwd = process.cwd(), targetPkg = null) {
  const results  = await diagnose(cwd);
  const missing  = results.filter(r => r.status === 'missing'   && (!targetPkg || r.name === targetPkg));
  const sandboxed = results.filter(r => r.status === 'sandboxed' && (!targetPkg || r.name === targetPkg));

  if (missing.length === 0 && sandboxed.length === 0) {
    logger.ok('doctor: nothing to fix');
    return;
  }

  const dline = '═'.repeat(48);
  logger.always(`\n${C.CYAN}${dline}${C.RESET}`);
  logger.always(`${C.BOLD}${C.CYAN}  dryinstall fix — Auto Repair${C.RESET}`);
  logger.always(`${C.CYAN}${dline}${C.RESET}\n`);

  // sandboxed → node_modules 복구
  if (sandboxed.length > 0) {
    logger.always(`${C.BOLD}  Restoring sandboxed packages...${C.RESET}`);
    const dryDir  = path.join(cwd, 'dry_modules');
    const nodeDir = path.join(cwd, 'node_modules');

    for (const r of sandboxed) {
      const src = path.join(dryDir, r.name);
      const dst = path.join(nodeDir, r.name);
      try {
        if (fs.existsSync(dst)) fs.rmSync(dst, { recursive: true, force: true });
        fs.renameSync(src, dst);
        logger.always(`  ${C.GREEN}✓ ${r.name}${C.RESET}  ${C.GRAY}restored${C.RESET}`);
      } catch (e) {
        logger.always(`  ${C.RED}✗ ${r.name}${C.RESET}  ${C.GRAY}failed: ${e.message}${C.RESET}`);
      }
    }

    // dry_modules 비면 삭제
    try {
      const remaining = fs.readdirSync(dryDir).filter(p => !p.startsWith('.'));
      if (remaining.length === 0) fs.rmdirSync(dryDir);
    } catch {}
  }

  // missing → npm install
  if (missing.length > 0) {
    logger.always(`\n${C.BOLD}  Installing missing packages...${C.RESET}`);
    const pkgList = missing.map(r => r.name).join(' ');
    try {
      logger.always(`  ${C.GRAY}> npm install ${pkgList}${C.RESET}`);
      execSync(`npm install ${pkgList}`, { cwd, stdio: 'pipe' });
      missing.forEach(r => {
        logger.always(`  ${C.GREEN}✓ ${r.name}${C.RESET}`);
      });
    } catch (e) {
      logger.always(`  ${C.RED}✗ npm install failed: ${e.message.slice(0, 80)}${C.RESET}`);
      logger.always(`  ${C.GRAY}Try manually: npm install ${pkgList}${C.RESET}`);
    }
  }

  const total = missing.length + sandboxed.length;
  logger.always(`\n${C.GREEN}${C.BOLD}  Done. ${total} issue(s) fixed. Restart your app.${C.RESET}`);
  logger.always(`${C.CYAN}${dline}${C.RESET}\n`);
}

module.exports = { diagnose, printReport, fix };
