'use strict';

const vm   = require('vm');
const fs   = require('fs');
const path = require('path');

const { SECURITY_LEVELS, getAllowedModules, buildInteractiveCache } = require('./sandbox-policy');
const { askLifecycle } = require('./sandbox-interactive');
const logger = require('./logger');

class SandboxRuntime {
  constructor() {
    this.blocked          = [];
    this.allowed          = [];
    this.level            = 2;
    this.interactive      = false;
    this.extraAllowed     = [];
    this.allowedPackages  = [];
    this.skipAll          = false;
    this._cache           = buildInteractiveCache();
  }

  setLevel(level) {
    const parsed = Number.parseInt(level, 10);
    this.level = Number.isNaN(parsed) ? 2 : parsed;
    const info = SECURITY_LEVELS[this.level];
    logger.verbose(`[dryinstall:security] Level ${this.level} — ${info.name}`);
  }

  setInteractive(enabled) {
    this.interactive = enabled;
    if (enabled) logger.verbose('security: Interactive mode enabled');
  }

  setExtraAllowed(modules) {
    this.extraAllowed = modules;
    if (modules.length > 0) logger.verbose(`[dryinstall:security] Extra allowed: [${modules.join(', ')}]`);
  }

  setAllowedPackages(pkgs) {
    this.allowedPackages = pkgs;
    if (pkgs.length > 0) logger.verbose(`[dryinstall:security] Allowed packages: [${pkgs.join(', ')}]`);
  }

  _createSafeContext(pkgName) {
    const levelConfig   = SECURITY_LEVELS[this.level];
    const policyAllowed = getAllowedModules(pkgName);
    const { blocked, allowed, extraAllowed } = this;

    const DANGEROUS = ['fs','net','child_process','os','cluster','dgram','dns','tls','http','https'];

    const safeRequire = (mod) => {
      if (!DANGEROUS.includes(mod)) {
        allowed.push({ pkg: pkgName, module: mod });
        return require(mod);
      }

      if (this.level === 0) {
        logger.verbose(`[dryinstall:monitor] "${pkgName}" → "${mod}" (pass-through)`);
        allowed.push({ pkg: pkgName, module: mod, source: 'level-0' });
        return require(mod);
      }

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

      const msg = `"${pkgName}" tried to access "${mod}" — blocked (Level ${this.level})`;
      logger.warn(`[dryinstall:sandbox] ✗ ${msg}`);
      blocked.push({ pkg: pkgName, module: mod, time: new Date().toISOString() });
      throw new Error(`dryinstall: access to "${mod}" is not allowed`);
    };

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
        log:   (...a) => logger.verbose(`sandbox:${pkgName} ` + a.join(' ')),
        warn:  (...a) => logger.verbose(`sandbox:${pkgName} ` + a.join(' ')),
        error: (...a) => logger.verbose(`sandbox:${pkgName} ` + a.join(' ')),
      },
      process: {
        version:  process.version,
        platform: process.platform,
        arch:     process.arch,
        argv:     [],
        env:      {},
        cwd:      () => process.cwd(),
        exit:     ()  => { throw new Error('dryinstall: process.exit() blocked'); },
      },
      Function: escapeProxy,
      eval:     () => { throw new Error('dryinstall: eval() blocked'); },
      __filename: `[dryinstall-sandbox:${pkgName}]`,
      __dirname:  '/sandbox',
    });
  }

  load(filePath, pkgName = 'unknown') {
    const levelConfig = SECURITY_LEVELS[this.level];
    logger.verbose(`[dryinstall:sandbox] Loading: ${pkgName} [Level ${this.level} — ${levelConfig.name}]`);

    if (!fs.existsSync(filePath)) throw new Error(`dryinstall: file not found: ${filePath}`);

    const code    = fs.readFileSync(filePath, 'utf-8');
    const context = this._createSafeContext(pkgName);

    try {
      vm.runInContext(code, context, { filename: filePath, timeout: 5000 });
      logger.verbose(`[dryinstall:sandbox] ✓ ${pkgName} loaded safely`);
      return context.module.exports;
    } catch (err) {
      if (err.message.startsWith('dryinstall:')) {
        logger.block(`[dryinstall:sandbox] Attack blocked in "${pkgName}": ${err.message}`);
        return {};
      }
      throw err;
    }
  }

  async blockLifecycleScript(pkgName, script) {
    const levelConfig = SECURITY_LEVELS[this.level];
    if (!levelConfig.blockLifecycle) return;

    if (this.allowedPackages.includes(pkgName)) {
      logger.verbose(`[dryinstall] ALLOWED by --allow-package: "${pkgName}"`);
      this.allowed.push({ pkg: pkgName, type: 'lifecycle', script, source: '--allow-package' });
      return;
    }

    if (this.interactive) {
      const decision = await askLifecycle(pkgName, script, this._cache, this);
      if (decision === 'allow') {
        this.allowed.push({ pkg: pkgName, type: 'lifecycle', script, source: 'interactive' });
        return;
      }
    }

    logger.verbose(`[dryinstall] Lifecycle blocked: "${pkgName}" — ${script.slice(0, 80)}`);
    this.blocked.push({ pkg: pkgName, type: 'lifecycle', script, time: new Date().toISOString() });
  }

  report() {
    if (this.blocked.length === 0) {
      logger.verbose('[dryinstall:sandbox] No threats detected');
      return;
    }
    logger.block(`[dryinstall:sandbox] ${this.blocked.length} blocked attempt(s)`);
    this.blocked.forEach((b, i) => {
      if (b.type === 'lifecycle')         logger.block(`  [${i+1}] LIFECYCLE  pkg: ${b.pkg}`);
      else if (b.type === 'prototype_escape') logger.block(`  [${i+1}] ESCAPE  pkg: ${b.pkg}`);
      else                                logger.block(`  [${i+1}] MODULE  pkg: ${b.pkg} → tried: ${b.module}`);
    });
  }
}

const instance = new SandboxRuntime();

const { Worker } = require('worker_threads');
const WORKER_RUNNER = path.join(__dirname, 'worker-runner.js');

function loadInWorker(filePath, pkgName = 'unknown') {
  return new Promise((resolve) => {
    logger.verbose(`[dryinstall:worker] Loading in Worker Thread: ${pkgName}`);
    const worker = new Worker(WORKER_RUNNER, { workerData: { filePath, pkgName } });

    worker.on('message', (msg) => {
      if (msg.type === 'blocked') {
        logger.block(`[dryinstall:worker] BLOCKED: "${msg.pkg}" → require("${msg.module}")`);
      } else if (msg.type === 'done') {
        logger.verbose(`[dryinstall:worker] ✓ ${pkgName} — ${msg.blocked?.length ?? 0} attempt(s) blocked`);
        resolve(msg.exports ?? {});
      }
    });

    worker.on('error', (err) => { logger.warn(`[dryinstall:worker] Error: ${err.message}`); resolve({}); });
    worker.on('exit', (code) => { if (code !== 0) resolve({}); });
  });
}

instance.loadInWorker = loadInWorker;
module.exports = instance;
