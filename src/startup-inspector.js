'use strict';

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const logger = require('./logger');

/**
 * StartupInspector
 *
 * 역할:
 *   1. 앱 시작 전 — 의존성 로드 상태 표시
 *      react, axios, webpack 등이 제대로 설치됐는지 한눈에
 *
 *   2. 앱 실행 후 오류 발생 시 — 긴 로그 요약
 *      "Module not found: core-js-pure" 같은 오류를
 *      "core-js-pure 누락 → dry_modules에 격리됨 → dryinstall fix로 해결"
 *      한 줄로 요약
 *
 * 진입점:
 *   exec-hook.js (npm start 시 자동 실행)
 *   dryinstall inspect (수동)
 */

const C = {
  RED:    '\x1b[31m', YELLOW: '\x1b[33m', GREEN:  '\x1b[32m',
  CYAN:   '\x1b[36m', GRAY:   '\x1b[90m', BOLD:   '\x1b[1m',
  RESET:  '\x1b[0m',
};

// ── 알려진 패키지 역할 설명 ──────────────────────────────
const KNOWN_ROLES = {
  // React 생태계
  'react':                    'UI core',
  'react-dom':                'DOM renderer',
  'react-scripts':            'CRA build tool',
  'react-router-dom':         'routing',
  'react-redux':              'state management',
  'react-query':              'server state',
  '@tanstack/react-query':    'server state',

  // 번들러
  'webpack':                  'bundler',
  'vite':                     'bundler',
  'next':                     'React framework',
  'parcel':                   'bundler',

  // 폴리필 / 런타임
  'core-js':                  'polyfill (ES compat)',
  'core-js-pure':             'polyfill (modular)',
  'regenerator-runtime':      'async/generator polyfill',

  // HTTP
  'axios':                    'HTTP client',
  'node-fetch':               'HTTP client',
  'got':                      'HTTP client',

  // 스타일
  'styled-components':        'CSS-in-JS',
  'tailwindcss':              'utility CSS',
  '@emotion/react':           'CSS-in-JS',

  // 테스트
  'jest':                     'test runner',
  'vitest':                   'test runner',
  'axe-core':                 'a11y testing',
  '@testing-library/react':   'component testing',

  // 유틸
  'lodash':                   'utility',
  'date-fns':                 'date utility',
  'dayjs':                    'date utility',
  'zod':                      'schema validation',

  // 트랜스파일러
  'jiti':                     'TS/ESM runtime loader',
  'tsx':                      'TS runner',
  'ts-node':                  'TS runner',

  // 빌드 내부
  '@pmmmwh/react-refresh-webpack-plugin': 'HMR plugin',
  'babel-loader':             'JS transpiler',
  'css-loader':               'CSS bundling',

  // 보안
  'dryinstall':               'security layer (you)',
};

// ── 오류 패턴 → 원인 + 해결법 매핑 ─────────────────────
const ERROR_PATTERNS = [
  {
    pattern: /Module not found.*Can't resolve ['"]([^'"]+)['"]/i,
    type: 'missing_module',
    explain: (m) => `'${m[1]}' 모듈을 찾을 수 없음`,
    fix:     (m) => `dryinstall fix ${m[1].split('/')[0]}`,
  },
  {
    pattern: /Cannot find module ['"]([^'"]+)['"]/i,
    type: 'missing_module',
    explain: (m) => `'${m[1]}' 모듈 누락`,
    fix:     (m) => `dryinstall fix ${m[1].split('/')[0]}`,
  },
  {
    pattern: /Failed to load plugin ['"]([^'"]+)['"].*Cannot find module ['"]([^'"]+)['"]/i,
    type: 'missing_plugin_dep',
    explain: (m) => `ESLint 플러그인 '${m[1]}'의 의존성 '${m[2]}' 누락`,
    fix:     (m) => `dryinstall fix ${m[2].split('/')[0]}`,
  },
  {
    pattern: /webpack compiled with (\d+) error/i,
    type: 'webpack_error',
    explain: (m) => `webpack 컴파일 오류 ${m[1]}개`,
    fix:     () => 'dryinstall inspect --verbose 로 상세 확인',
  },
  {
    pattern: /SyntaxError.*([^\n]+)/i,
    type: 'syntax_error',
    explain: (m) => `문법 오류: ${m[1].slice(0, 60)}`,
    fix:     () => '소스 파일 확인 필요',
  },
  {
    pattern: /ENOENT.*no such file.*['"]([^'"]+)['"]/i,
    type: 'file_not_found',
    explain: (m) => `파일 없음: ${m[1]}`,
    fix:     () => 'npm install 또는 dryinstall fix',
  },
  {
    pattern: /dry_modules/i,
    type: 'isolated_package',
    explain: () => 'dry_modules에 격리된 패키지가 로드 실패',
    fix:     () => 'dryinstall fix (격리 해제)',
  },
];

// ── 의존성 로드 상태 확인 ────────────────────────────────

/**
 * package.json dependencies 읽어서 설치 상태 확인
 */
function inspectDependencies(cwd = process.cwd()) {
  const pkgJsonPath = path.join(cwd, 'package.json');
  if (!fs.existsSync(pkgJsonPath)) return [];

  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8')); }
  catch { return []; }

  const allDeps = {
    ...pkg.dependencies    || {},
    ...pkg.devDependencies || {},
  };

  const dryModulesDir = path.join(cwd, 'dry_modules');
  const nodeModulesDir = path.join(cwd, 'node_modules');

  return Object.entries(allDeps).map(([name, versionRange]) => {
    const inNodeModules = fs.existsSync(path.join(nodeModulesDir, name));
    const inDryModules  = fs.existsSync(path.join(dryModulesDir, name));

    let status, statusLabel, color;
    if (inDryModules) {
      status      = 'sandboxed';
      statusLabel = '⚠ sandboxed';
      color       = C.YELLOW;
    } else if (inNodeModules) {
      status      = 'ok';
      statusLabel = '✓ loaded';
      color       = C.GREEN;
    } else {
      status      = 'missing';
      statusLabel = '✗ missing';
      color       = C.RED;
    }

    // 실제 설치된 버전 읽기
    let version = versionRange;
    try {
      const installedPkg = JSON.parse(fs.readFileSync(
        path.join(inDryModules ? dryModulesDir : nodeModulesDir, name, 'package.json'), 'utf-8'
      ));
      version = installedPkg.version || versionRange;
    } catch {}

    return {
      name,
      status,
      statusLabel,
      color,
      role: KNOWN_ROLES[name] || '',
      version,
      sandboxed: inDryModules,
    };
  });
}

/**
 * 긴 로그 텍스트를 파싱해서 핵심 오류 추출
 */
function parseErrors(logText) {
  const issues = [];
  const seen   = new Set();

  for (const { pattern, type, explain, fix } of ERROR_PATTERNS) {
    const match = logText.match(pattern);
    if (!match) continue;

    const key = type + (match[1] || '');
    if (seen.has(key)) continue;
    seen.add(key);

    issues.push({
      type,
      message: explain(match),
      fix:     fix(match),
    });
  }

  return issues;
}

// ── 출력 ────────────────────────────────────────────────

function printTable(deps) {
  if (deps.length === 0) return;

  const col1 = Math.min(30, Math.max(12, ...deps.map(d => d.name.length)) + 2);
  const col2 = 14;
  const col3 = 20;
  const col4 = 10;
  const total = col1 + col2 + col3 + col4 + 5;

  const line  = '─'.repeat(total);
  const dline = '═'.repeat(total);

  logger.always(`\n${C.CYAN}${dline}${C.RESET}`);
  logger.always(`${C.BOLD}${C.CYAN}  dryinstall — Startup Dependency Report${C.RESET}`);
  logger.always(`${C.CYAN}${dline}${C.RESET}`);
  logger.always(
    `  ${C.BOLD}${'Package'.padEnd(col1)}${'Status'.padEnd(col2)}${'Role'.padEnd(col3)}${'Version'.padEnd(col4)}${C.RESET}`
  );
  logger.always(`${C.CYAN}${line}${C.RESET}`);

  const missing    = [];
  const sandboxed  = [];

  for (const d of deps) {
    const name    = d.name.slice(0, col1 - 1).padEnd(col1);
    const status  = (d.statusLabel).padEnd(col2);
    const role    = (d.role || '—').slice(0, col3 - 1).padEnd(col3);
    const ver     = (d.version || '').slice(0, col4 - 1).padEnd(col4);

    logger.always(`  ${C.GRAY}${name}${C.RESET}${d.color}${status}${C.RESET}${C.GRAY}${role}${C.RESET}  ${ver}`);

    if (d.status === 'missing')   missing.push(d.name);
    if (d.status === 'sandboxed') sandboxed.push(d.name);
  }

  logger.always(`${C.CYAN}${dline}${C.RESET}`);

  // 요약
  const ok = deps.filter(d => d.status === 'ok').length;
  logger.always(`  ${C.GREEN}✓ loaded: ${ok}${C.RESET}  ${C.YELLOW}⚠ sandboxed: ${sandboxed.length}${C.RESET}  ${C.RED}✗ missing: ${missing.length}${C.RESET}`);

  if (sandboxed.length > 0) {
    logger.always(`\n${C.YELLOW}  Sandboxed packages may cause Module not found errors.${C.RESET}`);
    logger.always(`${C.YELLOW}  Run: dryinstall fix${C.RESET}  ${C.GRAY}(moves back to node_modules)${C.RESET}`);
  }
  if (missing.length > 0) {
    logger.always(`\n${C.RED}  Missing packages: ${missing.join(', ')}${C.RESET}`);
    logger.always(`${C.GRAY}  Run: npm install${C.RESET}`);
  }

  logger.always(`${C.CYAN}${dline}${C.RESET}\n`);
}

function printErrorSummary(issues) {
  if (issues.length === 0) return;

  const line = '─'.repeat(58);
  logger.always(`\n${C.RED}${line}${C.RESET}`);
  logger.always(`${C.BOLD}${C.RED}  dryinstall — Error Summary (${issues.length} issue${issues.length > 1 ? 's' : ''})${C.RESET}`);
  logger.always(`${C.RED}${line}${C.RESET}`);

  issues.forEach((issue, i) => {
    logger.always(`  ${C.RED}[${i + 1}]${C.RESET} ${issue.message}`);
    logger.always(`      ${C.GRAY}→ fix: ${issue.fix}${C.RESET}`);
  });

  logger.always(`${C.RED}${line}${C.RESET}\n`);
}

// ── 공개 API ────────────────────────────────────────────

/**
 * npm start 시 자동 실행
 * 의존성 로드 상태 표시
 */
function runStartupReport(cwd = process.cwd()) {
  const deps = inspectDependencies(cwd);
  if (deps.length > 0) printTable(deps);
}

/**
 * 오류 로그 텍스트 받아서 요약 출력
 * exec-hook.js에서 stderr 캡처 후 호출
 */
function summarizeErrors(logText) {
  const issues = parseErrors(logText);
  if (issues.length > 0) printErrorSummary(issues);
  return issues;
}

/**
 * dryinstall inspect 명령어 — 상세 모드
 */
function runInspect(cwd = process.cwd(), opts = {}) {
  const deps = inspectDependencies(cwd);

  if (opts.verbose) {
    printTable(deps);
  } else {
    // 문제 있는 것만
    const problems = deps.filter(d => d.status !== 'ok');
    if (problems.length === 0) {
      logger.ok('inspect: all dependencies loaded correctly');
    } else {
      printTable(problems);
    }
  }

  return deps;
}

module.exports = { runStartupReport, summarizeErrors, runInspect, inspectDependencies, parseErrors };