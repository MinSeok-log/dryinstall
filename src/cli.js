'use strict';

const path = require('path');
const fs = require('fs');
const https = require('https');
const zlib = require('zlib');
const sandbox = require('./sandbox');
const DryStorage = require('./storage');
const auditor = require('./auditor');
const { detectTyposquatting } = require('./typo-detector');
const { detectConfusion, reportConfusion } = require('./confusion-detector');
const { verifyHash, reportHashMismatch } = require('./hash-verifier');
const { analyzeVersionDiff, reportDiff } = require('./version-diff-analyzer');
const { detectStealth, reportStealth } = require('./stealth-detector');
const { checkMaintainerChange, reportMaintainerChange } = require('./maintainer-monitor');
const profiler = require('./profiler');
const advisor = require('./advisor');
const networkAnalyzer = require('./network-analyzer');
const executionTracker = require('./execution-tracker');
const ex = require('./exception-handler');

// ── Lifecycle 차단 대상 전체 목록 ─────────────────────
const DANGEROUS_HOOKS = [
  'preinstall', 'install', 'postinstall',
  'prepare', 'prepublish', 'prepack', 'postpack',
  'preuninstall', 'uninstall', 'postuninstall',
];

// ── 인기 패키지 목록 (typosquatting 탐지용) ──────────
const POPULAR_PACKAGES = [
  'react', 'lodash', 'express', 'axios', 'webpack', 'babel',
  'typescript', 'eslint', 'prettier', 'jest', 'mocha', 'chai',
  'mongoose', 'sequelize', 'knex', 'redis', 'socket.io',
  'puppeteer', 'playwright', 'cheerio', 'request', 'got',
  'chalk', 'commander', 'yargs', 'dotenv', 'nodemon',
  'moment', 'dayjs', 'uuid', 'cors', 'helmet',
  'multer', 'passport', 'jsonwebtoken', 'bcrypt',
  'vue', 'angular', 'svelte', 'next', 'nuxt',
  'tailwindcss', 'sass', 'postcss', 'vite', 'rollup',
];

/**
 * Levenshtein Distance 계산
 */
/**
 * Typosquatting 탐지
 * 입력한 패키지명과 유사한 인기 패키지가 있으면 경고
 */
/**
 * DryCLI
 * Layer 1: audit → Layer 2: lifecycle 차단 → Layer 3: Sandbox 저장
 */
class DryCLI {
  constructor(cwd = process.cwd()) {
    this.cwd = cwd;
    this.storage = new DryStorage(cwd);
    this.registryUrl = 'https://registry.npmjs.org';
  }

  async install(rawPkgName) {
    // ── pkg@version 파싱 ─────────────────────────────────
    // scoped 패키지 처리: @scope/name@version
    let pkgName, requestedVersion;
    if (rawPkgName.startsWith('@')) {
      // @scope/name 또는 @scope/name@version
      const parts = rawPkgName.split('@');
      // parts = ['', 'scope/name'] 또는 ['', 'scope/name', 'version']
      pkgName = '@' + parts[1];
      requestedVersion = parts[2] || null;
    } else {
      const atIdx = rawPkgName.indexOf('@');
      if (atIdx > 0) {
        pkgName = rawPkgName.slice(0, atIdx);
        requestedVersion = rawPkgName.slice(atIdx + 1);
      } else {
        pkgName = rawPkgName;
        requestedVersion = null;
      }
    }

    console.log(`\n\x1b[36m[dryinstall] Installing: ${rawPkgName}\x1b[0m`);
    console.log(`\x1b[36m[dryinstall] 3-Layer pipeline: audit → lifecycle block → sandbox\x1b[0m\n`);

    try {
      // ── Layer 1: npm audit ──────────────────────────────
      const auditResult = auditor.audit(pkgName, requestedVersion);
      if (!auditResult.safe) {
        console.error(`\x1b[31m[dryinstall] ✗ BLOCKED: ${pkgName} has critical/high vulnerabilities\x1b[0m`);
        return null;
      }

      // ── Dependency Confusion 탐지 ────────────────────────
      const confusionResult = await detectConfusion(pkgName);
      reportConfusion(pkgName, confusionResult);
      if (confusionResult.risk === 'HIGH') {
        console.error(`\x1b[31m[dryinstall] ✗ BLOCKED: Dependency Confusion Attack detected for ${pkgName}\x1b[0m`);
        console.error(`\x1b[31m[dryinstall]   Use --allow-confusion to override\x1b[0m`);
        return null;
      }

      // ── npm registry 메타데이터 조회 ─────────────────────
      let meta;
      try {
        meta = await this._fetchMeta(pkgName);
      } catch (err) {
        // 패키지를 찾지 못한 경우 → typosquatting 탐지
        console.error(`\x1b[31m[dryinstall] ✗ Package not found: ${pkgName}\x1b[0m`);
        const suggestions = detectTyposquatting(pkgName);
        if (suggestions.length > 0) {
          console.error(`\x1b[33m[dryinstall:typo] Did you mean: \x1b[1m${suggestions[0].name}\x1b[0m\x1b[33m ?\x1b[0m`);
          if (suggestions.length > 1) {
            console.error(`\x1b[33m[dryinstall:typo] Other suggestions: ${suggestions.slice(1).map(s => s.name).join(', ')}\x1b[0m`);
          }
        }
        return null;
      }

      // dist-tags 없을 경우 방어
      if (!meta || !meta['dist-tags'] || !meta['dist-tags'].latest) {
        console.error(`\x1b[31m[dryinstall] ✗ Invalid package metadata: ${pkgName}\x1b[0m`);
        return null;
      }

      const version = requestedVersion
        ? (meta.versions[requestedVersion] ? requestedVersion : meta['dist-tags'].latest)
        : meta['dist-tags'].latest;

      if (requestedVersion && !meta.versions[requestedVersion]) {
        console.warn(`\x1b[33m[dryinstall] ⚠ Version ${requestedVersion} not found, using latest: ${version}\x1b[0m`);
      }
      const versionMeta = meta.versions[version];
      const tarballUrl = versionMeta.dist.tarball;
      const registryIntegrity = versionMeta.dist.integrity || null;

      // ── Version Diff 분석 ────────────────────────────────
      const diffResult = await analyzeVersionDiff(pkgName, version);
      reportDiff(pkgName, diffResult);
      if (!diffResult.skipped && !diffResult.clean) {
        const criticals = diffResult.findings.filter(f => f.severity === 'CRITICAL');
        if (criticals.length > 0) {
          console.error(`\x1b[31m[dryinstall] ✗ BLOCKED: Critical patterns added in v${version} — possible Version Poisoning\x1b[0m`);
          return null;
        }
      }

      console.log(`[dryinstall] Package: ${pkgName}@${version}`);


      // ── Hash 무결성 검증 ─────────────────────────────────
      const hashResult = await verifyHash(pkgName, version, tarballUrl, registryIntegrity);
      reportHashMismatch(pkgName, version, hashResult);
      if (hashResult.verified === false) {
        console.error(`\x1b[31m[dryinstall] ✗ BLOCKED: Integrity mismatch — possible tampered package\x1b[0m`);
        return null;
      }

      // ── Stealth Backdoor 탐지 ─────────────────────────────
      const stealthResult = await detectStealth(pkgName, tarballUrl);
      reportStealth(pkgName, stealthResult);
      if (!stealthResult.skipped && !stealthResult.clean) {
        const criticals = stealthResult.findings.filter(f => f.severity === 'CRITICAL');
        if (criticals.length > 0) {
          console.error(`\x1b[31m[dryinstall] ✗ BLOCKED: Stealth backdoor pattern detected in ${pkgName}\x1b[0m`);
          return null;
        }
      }

      // ── Maintainer 변경 감지 ─────────────────────────────
      const maintainerResult = await checkMaintainerChange(pkgName, version);
      reportMaintainerChange(pkgName, maintainerResult);
      if (maintainerResult.risk === 'CRITICAL') {
        console.error(`\x1b[31m[dryinstall] ✗ BLOCKED: Full maintainer takeover detected in ${pkgName}\x1b[0m`);
        console.error(`\x1b[31m[dryinstall]   Use --allow-maintainer-change to override\x1b[0m`);
        return null;
      }

      // ── Layer 2: lifecycle scripts 차단 (전체) ────────────
      const report = {
        pkg: pkgName, version,
        scanned: 1,
        blockedScripts: [],
        riskyPkgs: [],
      };

      const scripts = versionMeta.scripts || {};
      const blockedHooks = Object.keys(scripts).filter(s => DANGEROUS_HOOKS.includes(s));
      if (blockedHooks.length > 0) {
        blockedHooks.forEach(hook => {
          sandbox.blockLifecycleScript(pkgName, `${hook}: ${scripts[hook]}`);
          report.blockedScripts.push({ pkg: pkgName, hook });
          if (!report.riskyPkgs.find(r => r.pkg === pkgName))
            report.riskyPkgs.push({ pkg: pkgName, hooks: [] });
          report.riskyPkgs.find(r => r.pkg === pkgName).hooks.push(hook);
        });
        // ── Execution Tracker 기록 ─────────────────────────
        executionTracker.recordBlocked(pkgName, blockedHooks);
      }

      // ── Layer 2: 의존성 recursive lifecycle 검사 ─────────
      await this._checkDependencyLifecycles(pkgName, versionMeta, 0, new Set([pkgName]), report);

      // ── Network Analyzer 시작 ─────────────────────────────
      networkAnalyzer.start(pkgName);

      // ── 타볼 다운로드 ────────────────────────────────────
      const os = require('os');
      const tarballPath = require('path').join(os.tmpdir(), `${pkgName.replace(/[@/]/g, '_')}-${version}.tgz`);
      await this._download(tarballUrl, tarballPath);

      // ── 압축 해제 ────────────────────────────────────────
      const extractPath = require('path').join(os.tmpdir(), `dryinstall-extract-${pkgName.replace(/[@/]/g, '_')}`);
      await this._extract(tarballPath, extractPath);

      // ── Layer 3: dry_modules에 저장 (실행 없음) ──────────
      const pkgExtractPath = path.join(extractPath, 'package');
      this.storage.store(pkgName, pkgExtractPath);

      // ── 정리 ────────────────────────────────────────────
      fs.rmSync(tarballPath, { force: true });
      fs.rmSync(extractPath, { recursive: true, force: true });

      // ── Network Analyzer 중지 ─────────────────────────────
      networkAnalyzer.stop();
      const netReport = networkAnalyzer.report();

      console.log(`\n\x1b[32m[dryinstall] ✓ ${pkgName}@${version} → dry_modules/\x1b[0m`);
      console.log(`\x1b[32m[dryinstall] ✓ No code executed during install\x1b[0m`);

      // ── 프로파일 기록 ─────────────────────────────────────
      profiler.recordInstall(pkgName, version);

      // ── Security Report 출력 ────────────────────────────
      this._printSecurityReport(report);

      // ── Adaptive Profile 요약 ────────────────────────────
      advisor.printAdaptiveSummary(pkgName, version);

      return { name: pkgName, version };

    } catch (err) {
      console.error(`\x1b[31m[dryinstall] Install failed: ${err.message}\x1b[0m`);
      throw err;
    }
  }

  /**
   * 의존성 트리 recursive lifecycle 검사
   * dependencies / devDependencies / optionalDependencies 전부
   * report 객체에 결과 누적
   */
  async _checkDependencyLifecycles(parentName, versionMeta, depth = 0, visited = new Set(), report = null) {
    if (depth > 3) return;

    const allDeps = {
      ...versionMeta.dependencies,
      ...versionMeta.devDependencies,
      ...versionMeta.optionalDependencies,
    };

    const depNames = Object.keys(allDeps).filter(d => !visited.has(d));
    if (depNames.length === 0) return;

    if (depth === 0) {
      console.log(`\x1b[36m[dryinstall:deps] Scanning dependency tree of ${parentName}...\x1b[0m`);
    }

    for (const dep of depNames) {
      visited.add(dep);
      if (report) report.scanned++;

      try {
        const depMeta = await this._fetchMeta(dep);
        if (!depMeta?.['dist-tags']?.latest) continue;

        const depVersion = depMeta['dist-tags'].latest;
        const depVersionMeta = depMeta.versions[depVersion];
        const depScripts = depVersionMeta?.scripts || {};
        const blocked = Object.keys(depScripts).filter(s => DANGEROUS_HOOKS.includes(s));

        if (blocked.length > 0) {
          blocked.forEach(hook => {
            sandbox.blockLifecycleScript(dep, `${hook}: ${depScripts[hook]}`);
            if (report) {
              report.blockedScripts.push({ pkg: dep, hook });
              if (!report.riskyPkgs.find(r => r.pkg === dep))
                report.riskyPkgs.push({ pkg: dep, hooks: [] });
              report.riskyPkgs.find(r => r.pkg === dep).hooks.push(hook);
            }
          });
        }

        if (depth < 3) {
          await this._checkDependencyLifecycles(dep, depVersionMeta, depth + 1, visited, report);
        }
      } catch {
        // 개별 의존성 실패는 무시
      }
    }
  }

  /**
   * Security Report 요약 출력
   */
  _printSecurityReport(report) {
    const line = '═'.repeat(50);
    console.log(`\n\x1b[36m${line}\x1b[0m`);
    console.log(`\x1b[1m\x1b[36m  dryinstall Security Report\x1b[0m`);
    console.log(`\x1b[36m${line}\x1b[0m`);
    console.log(`  Package          : ${report.pkg}@${report.version}`);
    console.log(`  Packages scanned : ${report.scanned}`);
    console.log(`  Scripts blocked  : \x1b[31m${report.blockedScripts.length}\x1b[0m`);
    console.log(`  Risky packages   : \x1b[33m${report.riskyPkgs.length}\x1b[0m`);

    if (report.riskyPkgs.length > 0) {
      console.log(`\n  Top blocked packages:`);
      report.riskyPkgs.slice(0, 5).forEach(r => {
        console.log(`  \x1b[33m  - ${r.pkg}\x1b[0m (${r.hooks.join(', ')})`);
      });
      if (report.riskyPkgs.length > 5) {
        console.log(`  \x1b[33m  ... and ${report.riskyPkgs.length - 5} more\x1b[0m`);
      }
    }

    console.log(`\n  \x1b[32m✓ All lifecycle scripts blocked\x1b[0m`);
    console.log(`  \x1b[32m✓ Zero code executed during install\x1b[0m`);
    console.log(`\x1b[36m${line}\x1b[0m\n`);
  }

  _fetchMeta(pkgName) {
    const encodedName = pkgName.replace('/', '%2F');
    const url = `${this.registryUrl}/${encodedName}`;
    return new Promise((resolve, reject) => {
      https.get(url, { headers: { 'Accept': 'application/json' } }, (res) => {
        if (res.statusCode === 404) {
          reject(new Error(`Package not found: ${pkgName}`));
          res.resume();
          return;
        }
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(new Error(`Failed to parse registry response: ${e.message}`)); }
        });
      }).on('error', (err) => {
        // 네트워크 에러 예외처리
        ex.handleNetworkError(pkgName, null, err);
        reject(err);
      });
    });
  }

  _download(url, destPath) {
    return new Promise((resolve, reject) => {
      const file = fs.createWriteStream(destPath);
      const request = (u) => {
        https.get(u, (res) => {
          if (res.statusCode === 301 || res.statusCode === 302) return request(res.headers.location);
          res.pipe(file);
          file.on('finish', () => file.close(resolve));
        }).on('error', (err) => { fs.unlink(destPath, () => {}); reject(err); });
      };
      request(url);
    });
  }

  _extract(tarballPath, destPath) {
    return new Promise((resolve, reject) => {
      if (!fs.existsSync(destPath)) fs.mkdirSync(destPath, { recursive: true });
      const input = fs.createReadStream(tarballPath);
      const gunzip = zlib.createGunzip();
      let buffer = Buffer.alloc(0);
      gunzip.on('data', (chunk) => { buffer = Buffer.concat([buffer, chunk]); });
      gunzip.on('end', () => {
        try { this._parseTar(buffer, destPath); resolve(); }
        catch (e) { reject(e); }
      });
      gunzip.on('error', reject);
      input.pipe(gunzip);
    });
  }

  _parseTar(buffer, destPath) {
    let offset = 0;
    while (offset + 512 <= buffer.length) {
      const header = buffer.slice(offset, offset + 512);
      if (header.every(b => b === 0)) break;
      const name = header.slice(0, 100).toString('utf-8').replace(/\0/g, '');
      const sizeOctal = header.slice(124, 136).toString('utf-8').replace(/\0/g, '').trim();
      const typeFlag = header.slice(156, 157).toString('utf-8');
      const size = parseInt(sizeOctal, 8) || 0;
      offset += 512;
      if (name && typeFlag !== '5') {
        const fullPath = path.join(destPath, name);
        const dir = path.dirname(fullPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        if (size > 0) fs.writeFileSync(fullPath, buffer.slice(offset, offset + size));
      } else if (typeFlag === '5' && name) {
        const dirPath = path.join(destPath, name);
        if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
      }
      offset += Math.ceil(size / 512) * 512;
    }
  }

  /**
   * clean-install
   * node_modules/ 삭제 → package.json dependencies → 3-Layer 재설치
   */
  async cleanInstall() {
    console.log('\n\x1b[36m[dryinstall] clean-install 시작\x1b[0m');

    const pkgJsonPath = path.join(this.cwd, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) {
      console.error('\x1b[31m[dryinstall] package.json not found\x1b[0m');
      return;
    }
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });

    if (deps.length === 0) {
      console.log('\x1b[33m[dryinstall] No dependencies found\x1b[0m');
      return;
    }

    console.log(`\x1b[36m[dryinstall] Found ${deps.length} dependencies\x1b[0m`);

    const nodeModulesPath = path.join(this.cwd, 'node_modules');
    if (fs.existsSync(nodeModulesPath)) {
      console.log('\x1b[36m[dryinstall] Removing node_modules/...\x1b[0m');
      fs.rmSync(nodeModulesPath, { recursive: true, force: true });
      console.log('\x1b[32m[dryinstall] ✓ node_modules/ removed\x1b[0m');
    }

    console.log('\x1b[36m[dryinstall] Reinstalling via 3-Layer pipeline...\x1b[0m\n');
    const results = { success: [], failed: [], blocked: [] };

    for (const dep of deps) {
      try {
        const result = await this.install(dep);
        if (result) results.success.push(dep);
        else results.blocked.push(dep);
      } catch { results.failed.push(dep); }
    }

    console.log('\n\x1b[36m[dryinstall] clean-install 완료\x1b[0m');
    console.log(`  ✓ Success : \x1b[32m${results.success.length}\x1b[0m`);
    console.log(`  ✗ Blocked : \x1b[31m${results.blocked.length}\x1b[0m`);
    console.log(`  ! Failed  : \x1b[33m${results.failed.length}\x1b[0m`);
  }

  list() {
    const pkgs = this.storage.list();
    if (pkgs.length === 0) { console.log('[dryinstall] No packages installed'); return; }
    console.log('\n[dryinstall] Installed packages:');
    pkgs.forEach(p => console.log(`  - ${p}`));
    console.log();
  }

  /**
   * package.json start 스크립트에 loader 자동 등록
   * "start": "node -r dryinstall/src/loader.js index.js"
   */
  setupLoader() {
    const pkgJsonPath = path.join(this.cwd, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) {
      console.error('\x1b[31m[dryinstall] package.json not found\x1b[0m');
      return;
    }

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    if (!pkg.scripts) pkg.scripts = {};

    const loaderFlag = '-r ./node_modules/dryinstall/src/loader.js';
    const trackerCmd = 'node ./node_modules/dryinstall/src/exec-hook.js';

    // ── 감쌀 스크립트 목록 ───────────────────────────────
    // start, dev 계열만 — build/test/lint는 건드리지 않음
    const TARGET_SCRIPTS = ['start', 'dev', 'serve', 'preview'];

    let modified = false;

    for (const scriptName of TARGET_SCRIPTS) {
      const original = pkg.scripts[scriptName];
      if (!original) continue;

      // 이미 등록된 경우 스킵
      if (original.includes('dryinstall') || original.includes('loader.js')) continue;

      // 원본 백업
      pkg.scripts[`_${scriptName}_original`] = original;

      // node 계열 명령어에는 loader 삽입
      // react-scripts / vite / next 등 런처는 tracker로 감쌈
      if (original.startsWith('node ')) {
        pkg.scripts[scriptName] = original.replace(/^node /, `node ${loaderFlag} `);
      } else {
        // react-scripts start, vite, next dev 등
        // exec-hook.js가 앞에서 tracker 활성화 후 원본 명령 실행
        pkg.scripts[scriptName] = `${trackerCmd} ${scriptName} && ${original}`;
      }

      console.log(`\x1b[32m[dryinstall] ✓ ${scriptName}\x1b[0m`);
      console.log(`\x1b[90m    before: ${original}\x1b[0m`);
      console.log(`\x1b[90m    after : ${pkg.scripts[scriptName]}\x1b[0m`);
      modified = true;
    }

    if (!modified) {
      console.log('\x1b[33m[dryinstall] loader already registered — nothing to change\x1b[0m');
      return;
    }

    fs.writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2));
    console.log('\n\x1b[36m[dryinstall] ✓ setup complete\x1b[0m');
    console.log('\x1b[90m  npm start / npm run dev — now tracked by dryinstall\x1b[0m');
    console.log('\x1b[90m  dryinstall track status — check learning progress\x1b[0m\n');
  }

  /**
   * loader 등록 해제 (원본 복원)
   */
  removeLoader() {
    const pkgJsonPath = path.join(this.cwd, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return;

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    if (!pkg.scripts) return;

    const TARGET_SCRIPTS = ['start', 'dev', 'serve', 'preview'];
    let restored = false;

    for (const scriptName of TARGET_SCRIPTS) {
      const backupKey = `_${scriptName}_original`;
      if (pkg.scripts[backupKey]) {
        pkg.scripts[scriptName] = pkg.scripts[backupKey];
        delete pkg.scripts[backupKey];
        console.log(`\x1b[32m[dryinstall] ✓ ${scriptName} restored\x1b[0m`);
        restored = true;
      }
    }

    if (restored) {
      fs.writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2));
    } else {
      console.log('\x1b[33m[dryinstall] No backup found — nothing to restore\x1b[0m');
    }
  }
}

module.exports = DryCLI;
