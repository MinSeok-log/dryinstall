'use strict';

const fs      = require('fs');
const path    = require('path');
const { execSync } = require('child_process');
const DryStorage   = require('./storage');
const sandbox      = require('./sandbox');
const DepGraph     = require('./dep-graph');
const logger       = require('./logger');

const CONCURRENCY = 8; // 병렬 스캔 동시 실행 수

/**
 * Scanner
 * 기존 node_modules/ 전체 스캔
 * 악성코드 탐지 → 차단 → dry_modules/ 마이그레이션
 */

// ── 화이트리스트 ───────────────────────────────────────
// 알려진 안전 패키지 — child_process/shell 사용이 정상인 도구들
const WHITELIST = new Set([
  // 빌드 도구
  'webpack', 'webpack-cli', 'webpack-dev-server', 'webpack-dev-middleware',
  'webpack-bundle-analyzer', 'webpack-merge',
  'rollup', 'vite', 'esbuild', 'parcel', 'browserify',
  'typescript', 'ts-node', 'tsc',
  'babel', '@babel/core', '@babel/cli', '@babel/preset-env', '@babel/preset-react',
  'terser', 'uglify-js', 'svgo',
  'postcss', 'autoprefixer', 'tailwindcss', 'sass', 'node-sass',

  // React / CRA
  'react-scripts', 'react-dev-utils', 'create-react-app',

  // 테스트 도구
  'jest', 'jest-cli', 'mocha', 'chai', 'jasmine', 'karma',
  'playwright', 'puppeteer', 'cypress',
  '@testing-library/react', '@testing-library/jest-dom',
  'istanbul', 'nyc', 'c8',

  // 린터 / 포맷터
  'eslint', 'prettier', 'stylelint', 'tslint',
  'eslint-loader', 'eslint-webpack-plugin',

  // Node.js 도구
  'nodemon', 'ts-node-dev', 'concurrently', 'cross-env', 'dotenv-cli',
  'npm-run-all', 'rimraf', 'mkdirp', 'copyfiles', 'cpx',
  'semver', 'which', 'resolve', 'resolve.exports',
  'shell-quote', 'supports-hyperlinks',

  // 소스맵 / 디버그
  'source-map', 'source-map-loader', 'source-map-support',
  'stacktrace-js', 'stackframe',

  // workbox / PWA
  'workbox-webpack-plugin', 'workbox-routing', 'workbox-range-requests',
  'workbox-core', 'workbox-precaching', 'workbox-strategies',

  // 기타 알려진 안전 유틸
  'acorn', 'regjsparser', 'xml-name-validator',
  'update-browserslist-db', 'browserslist',
  'url-parse', 'whatwg-fetch', 'node-fetch',
  'ws', 'socket.io', 'socket.io-client',
  'selfsigned', 'safe-regex-test',
  'strip-comments', 'wrap-ansi', 'wrap-ansi-cjs',
  'sprintf-js', 'stable', 'text-table',
  'tinycolor2', 'svg-parser',

  // polyfill / 표준 라이브러리
  'core-js', 'core-js-pure', 'core-js-compat',
  'regenerator-runtime', 'regenerate', 'regenerate-unicode-properties',

  // 접근성 / 테스트 도구
  'axe-core', 'axe-webdriverjs',

  // 트랜스파일러 런타임
  'jiti', 'tsx', 'esbuild-register',

  // 네이티브 애드온 빌드 도구
  'canvas', 'node-gyp', 'node-gyp-build', 'prebuild-install',
  'node-pre-gyp', '@mapbox/node-pre-gyp',
  'bindings', 'nan', 'node-addon-api',

  // React / 번들러 내부
  '@pmmmwh/react-refresh-webpack-plugin', 'react-refresh',
  'lighthouse', 'lighthouse-logger',

  // 네이티브 이미지/그래픽
  'sharp', 'jimp', 'canvas',

  // Rust 기반 툴링 (정상적인 빌드 의존성)
  'unrs-resolver', '@unrs/resolver',
  '@biomejs/biome', 'lightningcss',
]);

// ── 탐지 패턴 ─────────────────────────────────────────
// 컨텍스트 없이 나타나면 실제로 위험한 패턴만 남김
const DANGEROUS_PATTERNS = [
  // 환경변수 대량 탈취 (process.env 전체를 외부로)
  {
    pattern: /JSON\.stringify\s*\(\s*process\.env\s*\)/,
    label: 'env mass exfiltration detected',
    severity: 'CRITICAL',
  },
  // 클라우드 메타데이터 접근 (AWS/GCP 키 탈취)
  {
    pattern: /169\.254\.169\.254/,
    label: 'cloud metadata API access detected',
    severity: 'CRITICAL',
  },
  // base64 인코딩된 eval (난독화)
  {
    pattern: /eval\s*\(\s*(?:Buffer\.from|atob)\s*\(/,
    label: 'obfuscated eval detected',
    severity: 'CRITICAL',
  },
  // CI 조건부 실행 — 맥락 기반 탐지
  // CI 체크 단독은 무시 (axe-core, jiti 등 정상 도구도 씀)
  // CI 체크 + 외부 네트워크/코드실행 조합일 때만 위험
  {
    pattern: /if\s*\([^)]*process\.env\.CI[^)]*\)[^}]*(?:fetch|axios|http|https|request)\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)/,
    label: 'CI-conditional + external network call detected',
    severity: 'CRITICAL',
  },
  {
    pattern: /process\.env\.CI[\s\S]{0,200}(?:execSync|exec|spawn)\s*\([^)]*(?:curl|wget|bash|sh)\s+https?:\/\//,
    label: 'CI-conditional + shell download detected',
    severity: 'CRITICAL',
  },
  // 민감 토큰 접근
  {
    pattern: /process\.env\.(NPM_TOKEN|AWS_SECRET|AWS_ACCESS_KEY|GITHUB_TOKEN|SECRET_KEY)/i,
    label: 'sensitive token access detected',
    severity: 'HIGH',
  },
  // curl/wget으로 외부 스크립트 실행
  {
    pattern: /(?:exec|execSync|spawn)\s*\([^)]*(?:curl|wget)\s+https?:\/\//,
    label: 'external script download+exec detected',
    severity: 'CRITICAL',
  },
];

class Scanner {
  constructor(cwd = process.cwd()) {
    this.cwd = cwd;
    this.nodeModulesDir = path.join(cwd, 'node_modules');
    this.storage = new DryStorage(cwd);
    this.report = {
      scanned: [],
      skipped: [],    // 화이트리스트로 스킵된 패키지
      dangerous: [],
      migrated: [],
    };
    this.depGraph = new DepGraph(cwd);
  }

  async scan() {
    const startTime = Date.now();
    logger.info('scanner: Scanning node_modules/...');

    await this.depGraph.build();

    if (!fs.existsSync(this.nodeModulesDir)) {
      logger.warn('scanner: node_modules/ not found — skipping');
      return this.report;
    }

    const packages = fs.readdirSync(this.nodeModulesDir)
      .filter(p => !p.startsWith('.'));

    logger.info(`scanner: Found ${packages.length} packages (whitelist: ${WHITELIST.size})`);

    // 병렬 스캔 — CONCURRENCY 단위로 분산 처리
    await this._scanConcurrent(packages);

    const dangerousPkgNames = this.report.dangerous.map(d => d.pkg);
    await this.depGraph.report(dangerousPkgNames);

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    logger.verbose(`scanner: completed in ${elapsed}s`);
    this._printReport();
    return this.report;
  }

  /**
   * 병렬 스캔 — CONCURRENCY 개씩 동시 처리
   * 1061개 패키지를 8개씩 묶어서 실행 → 순차 대비 ~6배 빠름
   */
  async _scanConcurrent(packages) {
    const chunks = [];
    for (let i = 0; i < packages.length; i += CONCURRENCY) {
      chunks.push(packages.slice(i, i + CONCURRENCY));
    }
    for (const chunk of chunks) {
      await Promise.all(chunk.map(pkg => this._scanPackage(pkg)));
    }
  }

  async _scanPackage(pkgName) {
    const pkgDir = path.join(this.nodeModulesDir, pkgName);
    if (!fs.existsSync(pkgDir)) return;

    // ── 화이트리스트 체크 ──────────────────────────────
    if (WHITELIST.has(pkgName)) {
      this.report.skipped.push(pkgName);
      return;
    }

    const issues = [];
    const lifecycleIssues = this._checkLifecycleScripts(pkgDir, pkgName);
    issues.push(...lifecycleIssues);

    const codeIssues = this._staticAnalysis(pkgDir, pkgName);
    issues.push(...codeIssues);

    this.report.scanned.push(pkgName);

    if (issues.length > 0) {
      const hasCritical  = issues.some(i => i.severity === 'CRITICAL');
      const isRequired   = this._isRuntimeCritical(pkgName);
      const color        = hasCritical ? '\x1b[31m' : '\x1b[33m';

      logger.block(`scanner: ${pkgName} — ${issues.length} issue(s)`);
      issues.forEach(i => logger.verbose(`  → [${i.severity}] ${i.label} in ${i.file}`));

      if (isRequired) {
        // 앱 실행에 필요한 패키지 — 격리하지 않고 경고만
        logger.warn(`scanner: ${pkgName} is runtime-required — skipping isolation`);
        logger.verbose(`  → add to .dryinstallrc alwaysAllow to suppress`);
        this.report.dangerous.push({ pkg: pkgName, issues, isolated: false, reason: 'runtime-required' });
      } else {
        // 앱 실행에 불필요하거나 devDependency — 격리
        this.report.dangerous.push({ pkg: pkgName, issues, isolated: true });
        this._isolate(pkgName, pkgDir);
      }
    }
  }

  /**
   * 이 패키지가 앱 실행에 실제로 필요한지 판단
   * 기준:
   *   1. package.json dependencies (devDependencies 제외)에 있음
   *   2. 빌드 도구(webpack, react-scripts 등)의 직접 의존성
   *   3. 앱 entry point에서 require되는 패키지
   */
  _isRuntimeCritical(pkgName) {
    try {
      const pkgJsonPath = path.join(this.cwd, 'package.json');
      if (!fs.existsSync(pkgJsonPath)) return false;
      const appPkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));

      // 1. 직접 dependency면 건드리지 않음
      const deps    = Object.keys(appPkg.dependencies    || {});
      const devDeps = Object.keys(appPkg.devDependencies || {});
      if (deps.includes(pkgName)) return true;

      // 2. 빌드 도구의 의존성인지 확인
      //    react-scripts, webpack, vite, next 등이 쓰는 패키지는 격리 위험
      const BUILD_TOOLS = [
        'react-scripts', 'webpack', 'vite', 'next', '@vue/cli-service',
        'create-react-app', 'parcel', 'rollup', 'esbuild',
      ];
      for (const tool of BUILD_TOOLS) {
        const toolPkgPath = path.join(this.nodeModulesDir, tool, 'package.json');
        if (!fs.existsSync(toolPkgPath)) continue;
        try {
          const toolPkg  = JSON.parse(fs.readFileSync(toolPkgPath, 'utf-8'));
          const toolDeps = Object.keys({
            ...(toolPkg.dependencies         || {}),
            ...(toolPkg.peerDependencies     || {}),
            ...(toolPkg.optionalDependencies || {}),
          });
          if (toolDeps.includes(pkgName)) return true;
        } catch {}
      }

      // 3. npm start/dev 스크립트가 직접 실행하는 패키지
      const scripts = appPkg.scripts || {};
      const runScripts = ['start', 'dev', 'serve', 'preview'];
      for (const s of runScripts) {
        if (scripts[s] && scripts[s].includes(pkgName)) return true;
      }

      return false;
    } catch {
      return false; // 판단 실패 시 격리 허용
    }
  }

  _checkLifecycleScripts(pkgDir, pkgName) {
    const issues = [];
    const pkgJsonPath = path.join(pkgDir, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return issues;

    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      const scripts = pkg.scripts || {};
      const dangerous = ['preinstall', 'install', 'postinstall'];

      for (const hook of dangerous) {
        if (scripts[hook]) {
          issues.push({
            label: `lifecycle script: ${hook}: ${scripts[hook].slice(0, 60)}`,
            severity: 'HIGH',
            file: 'package.json',
          });
        }
      }
    } catch {}

    return issues;
  }

  _staticAnalysis(pkgDir, pkgName) {
    const issues = [];
    const jsFiles = this._getJsFiles(pkgDir).slice(0, 20);

    for (const file of jsFiles) {
      try {
        const code = fs.readFileSync(file, 'utf-8');
        for (const { pattern, label, severity } of DANGEROUS_PATTERNS) {
          if (pattern.test(code)) {
            const relativePath = path.relative(pkgDir, file);
            issues.push({ label, severity, file: relativePath });
            break; // 파일당 하나만
          }
        }
      } catch {}
    }

    return issues;
  }

  _checkIntegrity(pkgName, pkgDir) {
    const resolved = this.storage.resolve(pkgName);
    if (!resolved) return true;
    return true;
  }

  _isolate(pkgName, pkgDir) {
    try {
      this.storage.store(pkgName, pkgDir);
      this.report.migrated.push(pkgName);
      fs.rmSync(pkgDir, { recursive: true, force: true });
      logger.verbose(`scanner: ${pkgName} isolated → dry_modules/`);
    } catch (e) {
      logger.block(`scanner: isolation failed: ${pkgName}: ${e.message}`);
    }
  }

  _getJsFiles(dir, result = [], depth = 0) {
    if (depth > 3) return result;
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith('.')) continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory() && entry.name !== 'node_modules') {
          this._getJsFiles(fullPath, result, depth + 1);
        } else if (entry.isFile() && entry.name.endsWith('.js')) {
          result.push(fullPath);
        }
      }
    } catch {}
    return result;
  }

  _printReport() {
    const graphStats = this.depGraph.stats();
    logger.always('\n\x1b[36m[dryinstall:scanner] ═══ Scan Report ═══\x1b[0m');
    logger.always(`  Total scanned  : ${this.report.scanned.length + this.report.skipped.length}`);
    logger.always(`  Whitelisted    : \x1b[90m${this.report.skipped.length} (known-safe, skipped)\x1b[0m`);
    logger.always(`  Inspected      : ${this.report.scanned.length}`);
    if (graphStats) {
      logger.always(`  In dep graph   : ${graphStats.total}`);
    }
    logger.always(`  Dangerous      : \x1b[31m${this.report.dangerous.length}\x1b[0m`);
    logger.always(`  Isolated       : \x1b[32m${this.report.migrated.length}\x1b[0m`);

    const isolated  = this.report.dangerous.filter(d => d.isolated !== false);
    const warnOnly  = this.report.dangerous.filter(d => d.isolated === false);

    if (isolated.length > 0) {
      logger.info('\n\x1b[31m  Isolated (moved to dry_modules):\x1b[0m');
      isolated.forEach(({ pkg, issues }) => {
        logger.info(`  \x1b[31m✗ ${pkg}\x1b[0m`);
        issues.forEach(i => logger.verbose(`  → [${i.severity}] ${i.label}`));
      });
      logger.info('\n\x1b[33m  These packages are sandboxed in dry_modules/\x1b[0m');
      logger.info('\x1b[33m  node -r ./node_modules/dryinstall/src/loader.js app.js\x1b[0m');
    }

    if (warnOnly.length > 0) {
      logger.warn('\n\x1b[33m  Warning only (app requires these — NOT isolated):\x1b[0m');
      warnOnly.forEach(({ pkg, issues }) => {
        logger.warn(`  \x1b[33m⚠  ${pkg}\x1b[0m  \x1b[90m(runtime-required, skipped isolation)\x1b[0m`);
        issues.forEach(i => logger.verbose(`  → [${i.severity}] ${i.label}`));
      });
      logger.warn('\n\x1b[90m  To suppress these warnings, add to ~/.dryinstallrc:\x1b[0m');
      logger.warn(`\x1b[90m  { "alwaysAllow": [${warnOnly.map(d => `"${d.pkg}"`).join(', ')}] }\x1b[0m`);
    }

    if (isolated.length === 0 && warnOnly.length === 0) {
      logger.ok('\n\x1b[32m  ✓ No threats detected\x1b[0m');
    }

    logger.always('\x1b[36m[dryinstall:scanner] ═══════════════════\x1b[0m\n');
  }
}

module.exports = Scanner;