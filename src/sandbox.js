'use strict';

const vm   = require('vm');
const fs   = require('fs');
const path = require('path');

const { SECURITY_LEVELS, getAllowedModules, buildInteractiveCache } = require('./sandbox-policy');
const { askLifecycle } = require('./sandbox-interactive');

/**
 * SandboxRuntime (리팩토링됨)
 *
 * 변경사항:
 *   RC/Policy/Level 정의  → sandbox-policy.js
 *   interactive 프롬프트  → sandbox-interactive.js
 *   여기는 vm 격리 컨텍스트 + lifecycle 차단만 담당
 */
class SandboxRuntime {
  constructor() {
    this.blocked          = [];
    this.allowed          = [];
    this.level            = 3;
    this.interactive      = false;
    this.extraAllowed     = [];
    this.allowedPackages  = [];
    this.skipAll          = false;
    this._cache           = buildInteractiveCache();
  }

  // ── 옵션 세터 ──────────────────────────────────────
  setLevel(level) {
    this.level = parseInt(level) || 3;
    const info = SECURITY_LEVELS[this.level];
    console.log(`\x1b[36m[dryinstall:security] Level ${this.level} — ${info.name}\x1b[0m`);
  }

  setInteractive(enabled) {
    this.interactive = enabled;
    if (enabled) console.log('\x1b[36m[dryinstall:security] Interactive mode enabled\x1b[0m');
  }

  setExtraAllowed(modules) {
    this.extraAllowed = modules;
    if (modules.length > 0) {
      console.log(`\x1b[33m[dryinstall:security] Extra allowed: [${modules.join(', ')}]\x1b[0m`);
    }
  }

  setAllowedPackages(pkgs) {
    this.allowedPackages = pkgs;
    if (pkgs.length > 0) {
      console.log(`\x1b[33m[dryinstall:security] Allowed packages: [${pkgs.join(', ')}]\x1b[0m`);
    }
  }

  // ── vm 컨텍스트 생성 ────────────────────────────────
  _createSafeContext(pkgName) {
    const levelConfig    = SECURITY_LEVELS[this.level];
    const policyAllowed  = getAllowedModules(pkgName);
    const { blocked, allowed, extraAllowed } = this;

    const DANGEROUS = ['fs','net','child_process','os','cluster','dgram','dns','tls','http','https'];

    const safeRequire = (mod) => {
      if (!DANGEROUS.includes(mod)) {
        // 안전한 빌트인 또는 상대경로
        allowed.push({ pkg: pkgName, module: mod });
        return require(mod);
      }

      // Level 0 — 감시만
      if (this.level === 0) {
        console.log(`\x1b[33m[dryinstall:monitor] "${pkgName}" → "${mod}" (pass-through)\x1b[0m`);
        allowed.push({ pkg: pkgName, module: mod, source: 'level-0' });
        return require(mod);
      }

      // policy / --allow / level 허용
      if (policyAllowed.includes(mod)) {
        allowed.push({ pkg: pkgName, module: mod, source: 'policy' });
        return require(mod);
      }
      if (extraAllowed.includes(mod)) {
        allowed.push({ pkg: pkgName, module: mod, source: '--allow' });
        return require(mod);
      }
      if (!levelConfig.blockedModules.includes(mod)) {
        allowed.push({ pkg: pkgName, module: mod, source: `level-${this.level}` });
        return require(mod);
      }

      // 차단
      const msg = `"${pkgName}" tried to access "${mod}" — blocked (Level ${this.level})`;
      console.error(`\x1b[31m[dryinstall:sandbox] ✗ ${msg}\x1b[0m`);
      blocked.push({ pkg: pkgName, module: mod, time: new Date().toISOString() });
      throw new Error(`dryinstall: access to "${mod}" is not allowed`);
    };

    // prototype 탈출 차단 Proxy
    const escapeProxy = new Proxy({}, {
      get() {
        blocked.push({ pkg: pkgName, type: 'prototype_escape', time: new Date().toISOString() });
        throw new Error('dryinstall: prototype escape blocked');
      },
    });

    return vm.createContext({
      require:     safeRequire,
      module:      { exports: {} },
      exports:     {},
      Buffer,
      setTimeout,  clearTimeout,
      setInterval, clearInterval,
      console: {
        log:   (...a) => console.log(`  [sandbox:${pkgName}]`, ...a),
        warn:  (...a) => console.warn(`  [sandbox:${pkgName}]`, ...a),
        error: (...a) => console.error(`  [sandbox:${pkgName}]`, ...a),
      },
      process: {
        version:  process.version,
        platform: process.platform,
        arch:     process.arch,
        argv:     [],
        env:      {},   // 환경변수 완전 차단
        cwd:      () => process.cwd(),
        exit:     ()  => { throw new Error('dryinstall: process.exit() blocked'); },
      },
      Function: escapeProxy,
      eval:     () => { throw new Error('dryinstall: eval() blocked'); },
      __filename: `[dryinstall-sandbox:${pkgName}]`,
      __dirname:  '/sandbox',
    });
  }

  // ── 파일 로드 (vm 격리) ─────────────────────────────
  load(filePath, pkgName = 'unknown') {
    const levelConfig = SECURITY_LEVELS[this.level];
    console.log(`\x1b[36m[dryinstall:sandbox] Loading: ${pkgName} [Level ${this.level} — ${levelConfig.name}]\x1b[0m`);

    if (!fs.existsSync(filePath)) {
      throw new Error(`dryinstall: file not found: ${filePath}`);
    }

    const code    = fs.readFileSync(filePath, 'utf-8');
    const context = this._createSafeContext(pkgName);

    try {
      vm.runInContext(code, context, { filename: filePath, timeout: 5000 });
      console.log(`\x1b[32m[dryinstall:sandbox] ✓ ${pkgName} loaded safely\x1b[0m`);
      return context.module.exports;
    } catch (err) {
      if (err.message.startsWith('dryinstall:')) {
        console.error(`\x1b[31m[dryinstall:sandbox] Attack blocked in "${pkgName}": ${err.message}\x1b[0m`);
        return {};
      }
      throw err;
    }
  }

  // ── Lifecycle 차단 ──────────────────────────────────
  async blockLifecycleScript(pkgName, script) {
    const levelConfig = SECURITY_LEVELS[this.level];
    if (!levelConfig.blockLifecycle) return;

    // --allow-package 허용
    if (this.allowedPackages.includes(pkgName)) {
      console.log(`\x1b[32m[dryinstall] ALLOWED by --allow-package: "${pkgName}"\x1b[0m`);
      this.allowed.push({ pkg: pkgName, type: 'lifecycle', script, source: '--allow-package' });
      return;
    }

    // interactive 모드
    if (this.interactive) {
      const decision = await askLifecycle(pkgName, script, this._cache, this);
      if (decision === 'allow') {
        this.allowed.push({ pkg: pkgName, type: 'lifecycle', script, source: 'interactive' });
        return;
      }
    }

    console.warn(`\x1b[33m[dryinstall] Lifecycle blocked: "${pkgName}" — ${script.slice(0, 80)}\x1b[0m`);
    this.blocked.push({ pkg: pkgName, type: 'lifecycle', script, time: new Date().toISOString() });
  }

  // ── 리포트 ──────────────────────────────────────────
  report() {
    if (this.blocked.length === 0) {
      console.log('\x1b[32m[dryinstall:sandbox] No threats detected\x1b[0m');
      return;
    }
    const line = '═'.repeat(48);
    console.log(`\n\x1b[31m${line}\x1b[0m`);
    console.log(`\x1b[31m  Sandbox Report — ${this.blocked.length} blocked attempt(s)\x1b[0m`);
    console.log(`\x1b[31m${line}\x1b[0m`);
    this.blocked.forEach((b, i) => {
      if (b.type === 'lifecycle') {
        console.log(`  [${i+1}] LIFECYCLE  pkg: ${b.pkg}`);
      } else if (b.type === 'prototype_escape') {
        console.log(`  [${i+1}] ESCAPE     pkg: ${b.pkg} — prototype escape attempt`);
      } else {
        console.log(`  [${i+1}] MODULE     pkg: ${b.pkg} → tried: ${b.module}`);
      }
    });
    console.log(`\x1b[31m${line}\x1b[0m\n`);
  }
}

// 싱글턴
const instance = new SandboxRuntime();

// Worker Thread loadInWorker 유지 (하위 호환)
const { Worker } = require('worker_threads');
const WORKER_RUNNER = path.join(__dirname, 'worker-runner.js');

function loadInWorker(filePath, pkgName = 'unknown') {
  return new Promise((resolve) => {
    console.log(`\x1b[36m[dryinstall:worker] Loading in Worker Thread: ${pkgName}\x1b[0m`);
    const worker = new Worker(WORKER_RUNNER, { workerData: { filePath, pkgName } });

    worker.on('message', (msg) => {
      if (msg.type === 'blocked') {
        console.error(`\x1b[31m[dryinstall:worker] BLOCKED: "${msg.pkg}" → require("${msg.module}")\x1b[0m`);
      } else if (msg.type === 'done') {
        const n = msg.blocked?.length ?? 0;
        console.log(`\x1b[32m[dryinstall:worker] ✓ ${pkgName} — ${n} attempt(s) blocked\x1b[0m`);
        resolve(msg.exports ?? {});
      }
    });

    worker.on('error', (err) => {
      console.error(`\x1b[31m[dryinstall:worker] Error: ${err.message}\x1b[0m`);
      resolve({});
    });

    worker.on('exit', (code) => { if (code !== 0) resolve({}); });
  });
}

instance.loadInWorker = loadInWorker;
module.exports = instance;
