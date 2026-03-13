'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const DryStorage = require('./storage');
const sandbox = require('./sandbox');
const DepGraph = require('./dep-graph');

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
  // CI 조건부 실행 (스텔스 백도어)
  {
    pattern: /process\.env\.CI\s*[=!]{1,3}.*require|if\s*\(.*CI.*\)\s*\{[^}]*require/,
    label: 'CI-conditional execution detected',
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
    console.log('\n\x1b[36m[dryinstall:scanner] Scanning node_modules/...\x1b[0m');

    await this.depGraph.build();

    if (!fs.existsSync(this.nodeModulesDir)) {
      console.log('\x1b[33m[dryinstall:scanner] node_modules/ not found — skipping\x1b[0m');
      return this.report;
    }

    const packages = fs.readdirSync(this.nodeModulesDir).filter(p => !p.startsWith('.'));
    console.log(`\x1b[36m[dryinstall:scanner] Found ${packages.length} packages\x1b[0m`);
    console.log(`\x1b[90m[dryinstall:scanner] Whitelist: ${WHITELIST.size} known-safe packages\x1b[0m\n`);

    for (const pkg of packages) {
      await this._scanPackage(pkg);
    }

    const dangerousPkgNames = this.report.dangerous.map(d => d.pkg);
    await this.depGraph.report(dangerousPkgNames);

    this._printReport();
    return this.report;
  }

  async _scanPackage(pkgName) {
    const pkgDir = path.join(this.nodeModulesDir, pkgName);
    if (!fs.existsSync(pkgDir)) return;

    // ── 화이트리스트 체크 ──────────────────────────────
    if (WHITELIST.has(pkgName)) {
      this.report.skipped.push(pkgName);
      return; // 출력 없이 조용히 스킵
    }

    const issues = [];

    const lifecycleIssues = this._checkLifecycleScripts(pkgDir, pkgName);
    issues.push(...lifecycleIssues);

    const codeIssues = this._staticAnalysis(pkgDir, pkgName);
    issues.push(...codeIssues);

    this.report.scanned.push(pkgName);

    if (issues.length > 0) {
      const hasCritical = issues.some(i => i.severity === 'CRITICAL');
      const color = hasCritical ? '\x1b[31m' : '\x1b[33m';
      console.error(`${color}[dryinstall:scanner] ✗ ${pkgName} — ${issues.length} issue(s)\x1b[0m`);
      issues.forEach(i => console.error(`  \x1b[31m→ [${i.severity}] ${i.label} in ${i.file}\x1b[0m`));
      this.report.dangerous.push({ pkg: pkgName, issues });
      this._isolate(pkgName, pkgDir);
    }
    // 안전한 패키지는 조용히 통과 (출력 없음)
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
    } catch (e) {
      console.error(`\x1b[31m[dryinstall:scanner] Isolation failed: ${pkgName}: ${e.message}\x1b[0m`);
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
    console.log('\n\x1b[36m[dryinstall:scanner] ═══ Scan Report ═══\x1b[0m');
    console.log(`  Total scanned  : ${this.report.scanned.length + this.report.skipped.length}`);
    console.log(`  Whitelisted    : \x1b[90m${this.report.skipped.length} (known-safe, skipped)\x1b[0m`);
    console.log(`  Inspected      : ${this.report.scanned.length}`);
    if (graphStats) {
      console.log(`  In dep graph   : ${graphStats.total}`);
    }
    console.log(`  Dangerous      : \x1b[31m${this.report.dangerous.length}\x1b[0m`);
    console.log(`  Isolated       : \x1b[32m${this.report.migrated.length}\x1b[0m`);

    if (this.report.dangerous.length > 0) {
      console.log('\n\x1b[31m  Packages requiring attention:\x1b[0m');
      this.report.dangerous.forEach(({ pkg, issues }) => {
        console.log(`  \x1b[31m✗ ${pkg}\x1b[0m`);
        issues.forEach(i => console.log(`    \x1b[90m→ [${i.severity}] ${i.label}\x1b[0m`));
      });
      console.log('\n\x1b[33m  These packages are moved to dry_modules/\x1b[0m');
      console.log('\x1b[33m  Run your app with loader to sandbox them:\x1b[0m');
      console.log('\x1b[33m  node -r ./node_modules/dryinstall/src/loader.js app.js\x1b[0m');
    } else {
      console.log('\n\x1b[32m  ✓ No threats detected\x1b[0m');
    }

    console.log('\x1b[36m[dryinstall:scanner] ═══════════════════\x1b[0m\n');
  }
}