'use strict';

const vm = require('vm');
const path = require('path');
const fs = require('fs');
const readline = require('readline');
const os = require('os');

// ── .dryinstallrc 경로 (홈 디렉토리) ─────────────────
const RC_PATH = require('path').join(os.homedir(), '.dryinstallrc');

/**
 * .dryinstallrc 로드
 */
function loadRC() {
  try {
    if (require('fs').existsSync(RC_PATH)) {
      return JSON.parse(require('fs').readFileSync(RC_PATH, 'utf-8'));
    }
  } catch {}
  return { alwaysAllow: [], alwaysBlock: [] };
}

/**
 * .dryinstallrc 저장
 */
function saveRC(rc) {
  try {
    require('fs').writeFileSync(RC_PATH, JSON.stringify(rc, null, 2));
  } catch {}
}

/**
 * 위험도 분석 — 명령어에서 위험 패턴 탐지
 */
function analyzeRisk(cmd) {
  const HIGH_RISK = [
    { pattern: /&&|;|\|/, label: 'chained commands' },
    { pattern: /https?:\/\//, label: 'HTTP request' },
    { pattern: /sudo|su\s/, label: 'privilege escalation' },
    { pattern: /curl|wget|fetch/, label: 'network download' },
    { pattern: /rm\s+-rf|rmdir/, label: 'file deletion' },
    { pattern: /eval|exec\s*\(/, label: 'code execution' },
    { pattern: /base64|atob|btoa/, label: 'encoding/obfuscation' },
    { pattern: /process\.env|\.env/, label: 'env access' },
    { pattern: /\.node/, label: 'native addon' },
  ];
  const found = HIGH_RISK.filter(r => r.pattern.test(cmd));
  return found;
}

/**
 * 스크립트 파일 실제 내용 읽기
 * "node scripts/build.js" → scripts/build.js 내용 반환
 */
function readScriptFile(hookCmd, pkgDir) {
  try {
    // "node ./foo.js", "bash ./foo.sh" 등에서 파일 경로 추출
    const match = hookCmd.match(/(?:node|bash|sh|ts-node)\s+([\w.\/\-]+\.(js|mjs|cjs|sh|ts))/);
    if (!match) return null;
    const relPath = match[1];
    const absPath = require('path').join(pkgDir, relPath);
    if (!require('fs').existsSync(absPath)) return null;
    const content = require('fs').readFileSync(absPath, 'utf-8');
    return { path: absPath, content };
  } catch {
    return null;
  }
}

// ── Policy 로드 ───────────────────────────────────────
const POLICY_PATH = path.join(process.cwd(), 'dryinstall.policy.json');
let POLICY = {};
try {
  POLICY = JSON.parse(fs.readFileSync(POLICY_PATH, 'utf-8'));
  console.log('\x1b[36m[dryinstall:policy] Policy file loaded\x1b[0m');
} catch {}

// ── .dryinstallrc에서 초기 whitelist/blacklist 로드 ──
const _rc = loadRC();
const interactiveCache = {};
_rc.alwaysAllow.forEach(p => { interactiveCache[`lifecycle:${p}`] = 'always'; });
_rc.alwaysBlock.forEach(p => { interactiveCache[`lifecycle:${p}`] = 'never'; });

// ── 보안 레벨 정의 ────────────────────────────────────
const SECURITY_LEVELS = {
  3: {
    name: 'Paranoid (Default)',
    blockedModules: ['fs', 'net', 'child_process', 'os', 'cluster', 'dgram', 'dns', 'tls', 'http', 'https'],
    blockLifecycle: true,
    useWorker: true,
  },
  2: {
    name: 'Balanced',
    blockedModules: ['child_process', 'cluster', 'dgram'],
    blockLifecycle: true,
    useWorker: false,
  },
  1: {
    name: 'Relaxed',
    blockedModules: [],
    blockLifecycle: false,
    useWorker: false,
  },
  0: {
    name: 'Off (Pass-through)',
    blockedModules: [],
    blockLifecycle: false,
    useWorker: false,
  },
};

function getAllowedModules(pkgName) {
  const pkg = POLICY[pkgName] || POLICY['_default'] || { allow: [] };
  return pkg.allow || [];
}

/**
 * Interactive Override — 차단 시 사용자에게 실시간 질문
 */

async function askUser(pkgName, mod) {
  // 이미 always 선택한 경우
  if (interactiveCache[`${pkgName}:${mod}`] === 'always') return true;
  if (interactiveCache[`${pkgName}:${mod}`] === 'never') return false;

  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(
      `\x1b[33m[dryinstall:alert] "${pkgName}"가 "${mod}" 모듈에 접근하려고 합니다. 허용하시겠습니까? (y/n/always/never): \x1b[0m`,
      (answer) => {
        rl.close();
        const a = answer.trim().toLowerCase();
        if (a === 'always') { interactiveCache[`${pkgName}:${mod}`] = 'always'; resolve(true); }
        else if (a === 'never') { interactiveCache[`${pkgName}:${mod}`] = 'never'; resolve(false); }
        else resolve(a === 'y');
      }
    );
  });
}

/**
 * Sandbox Runtime
 * Level 기반 보안 정책 + Policy File + Interactive Override
 */
class SandboxRuntime {
  constructor(options = {}) {
    this.options = options;
    this.blocked = [];
    this.allowed = [];
    this.level = 3; // 기본값: Paranoid
    this.interactive = false;
    this.extraAllowed = []; // --allow fs,net 등
    this.skipAll = false; // [s] Skip all remaining
  }

  setLevel(level) {
    this.level = parseInt(level) || 3;
    const levelInfo = SECURITY_LEVELS[this.level];
    console.log(`\x1b[36m[dryinstall:security] Level ${this.level} — ${levelInfo.name}\x1b[0m`);
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

  _createSafeContext(pkgName) {
    const blocked = this.blocked;
    const allowed = this.allowed;
    const levelConfig = SECURITY_LEVELS[this.level];
    const policyAllowed = getAllowedModules(pkgName);
    const extraAllowed = this.extraAllowed;
    const interactive = this.interactive;
    const dangerousModules = ['fs', 'net', 'child_process', 'os', 'cluster', 'dgram', 'dns', 'tls', 'http', 'https'];

    const safeRequire = (mod) => {
      if (dangerousModules.includes(mod)) {

        // Level 0 → 전부 허용 (감시만)
        if (this.level === 0) {
          console.log(`\x1b[33m[dryinstall:monitor] "${pkgName}" accessed "${mod}" (Level 0 — pass-through)\x1b[0m`);
          allowed.push({ pkg: pkgName, module: mod, source: 'level-0' });
          return require(mod);
        }

        // policy 허용
        if (policyAllowed.includes(mod)) {
          console.log(`\x1b[33m[dryinstall:policy] ALLOWED by policy: "${pkgName}" → "${mod}"\x1b[0m`);
          allowed.push({ pkg: pkgName, module: mod, source: 'policy' });
          return require(mod);
        }

        // --allow 옵션 허용
        if (extraAllowed.includes(mod)) {
          console.log(`\x1b[33m[dryinstall:security] ALLOWED by --allow: "${pkgName}" → "${mod}"\x1b[0m`);
          allowed.push({ pkg: pkgName, module: mod, source: '--allow' });
          return require(mod);
        }

        // 레벨별 허용
        if (!levelConfig.blockedModules.includes(mod)) {
          console.log(`\x1b[33m[dryinstall:security] ALLOWED by Level ${this.level}: "${pkgName}" → "${mod}"\x1b[0m`);
          allowed.push({ pkg: pkgName, module: mod, source: `level-${this.level}` });
          return require(mod);
        }

        // 차단
        const msg = `[dryinstall] BLOCKED: "${pkgName}" tried to access "${mod}" — DENIED`;
        console.error('\x1b[31m' + msg + '\x1b[0m');
        blocked.push({ pkg: pkgName, module: mod, time: new Date().toISOString() });
        throw new Error(`dryinstall: access to "${mod}" is not allowed`);
      }

      const safeBuiltins = ['path', 'util', 'events', 'stream', 'buffer', 'url', 'querystring', 'crypto', 'zlib'];
      if (safeBuiltins.includes(mod)) {
        allowed.push({ pkg: pkgName, module: mod });
        return require(mod);
      }

      if (mod.startsWith('./') || mod.startsWith('../')) {
        allowed.push({ pkg: pkgName, module: mod });
        return require(mod);
      }

      const msg = `[dryinstall] BLOCKED: "${pkgName}" tried to require external "${mod}"`;
      console.error('\x1b[33m' + msg + '\x1b[0m');
      blocked.push({ pkg: pkgName, module: mod, time: new Date().toISOString() });
      throw new Error(`dryinstall: external require "${mod}" must go through Mirror Loader`);
    };

    // ── Anomaly Detection ────────────────────────────
    // 패키지 종류별 예상 접근 패턴 정의
    const EXPECTED_ACCESS = {
      eslint: ['path', 'fs', 'util'],
      prettier: ['path', 'fs'],
      lodash: [],
      axios: ['http', 'https', 'url'],
      express: ['http', 'https', 'net', 'path'],
    };

    const anomalyWrap = (mod) => {
      const expected = EXPECTED_ACCESS[pkgName];
      if (expected && !expected.includes(mod) &&
          ['fs','net','http','https','child_process','dns'].includes(mod)) {
        console.warn(`[35m[dryinstall:anomaly] UNEXPECTED: "${pkgName}" accessing "${mod}" — unusual for this package type[0m`);
        blocked.push({ pkg: pkgName, module: mod, type: 'anomaly', time: new Date().toISOString() });
      }
      return safeRequire(mod);
    };

    const safeProcess = {
      version: process.version,
      platform: process.platform,
      arch: process.arch,
      argv: [],
      env: {},
      exit: () => { throw new Error('dryinstall: process.exit() is not allowed'); },
      cwd: () => process.cwd(),
    };

    // ── prototype escape 차단 ─────────────────────────
    const blocked_ = blocked;
    const blockedEscape = new Proxy({}, {
      get() {
        const msg = `[dryinstall] BLOCKED: "${pkgName}" tried prototype escape`;
        console.error('[31m' + msg + '[0m');
        blocked_.push({ pkg: pkgName, type: 'prototype_escape', time: new Date().toISOString() });
        throw new Error('dryinstall: prototype escape blocked');
      }
    });

    return vm.createContext({
      console: {
        log: (...args) => console.log(`  [sandbox:${pkgName}]`, ...args),
        error: (...args) => console.error(`  [sandbox:${pkgName}]`, ...args),
        warn: (...args) => console.warn(`  [sandbox:${pkgName}]`, ...args),
      },
      require: anomalyWrap,
      process: safeProcess,
      Buffer,
      setTimeout, clearTimeout,
      setInterval, clearInterval,
      module: { exports: {} },
      exports: {},
      // prototype escape 차단 — Function/eval 비활성화
      Function: blockedEscape,
      eval: () => { throw new Error('dryinstall: eval() is not allowed in sandbox'); },
    });
  }

  load(filePath, pkgName = 'unknown') {
    const levelConfig = SECURITY_LEVELS[this.level];
    const policyAllowed = getAllowedModules(pkgName);

    console.log(`\x1b[36m[dryinstall:sandbox] Loading: ${pkgName} [Level ${this.level} — ${levelConfig.name}]\x1b[0m`);

    if (policyAllowed.length > 0) {
      console.log(`\x1b[33m[dryinstall:policy] "${pkgName}" policy: allow [${policyAllowed.join(', ')}]\x1b[0m`);
    }

    if (!fs.existsSync(filePath)) {
      throw new Error(`dryinstall: file not found: ${filePath}`);
    }

    const code = fs.readFileSync(filePath, 'utf-8');
    const context = this._createSafeContext(pkgName);

    try {
      vm.runInContext(code, context, { filename: filePath, timeout: 5000 });
      console.log(`\x1b[32m[dryinstall:sandbox] OK: ${pkgName} loaded safely\x1b[0m`);
      return context.module.exports;
    } catch (err) {
      if (err.message.startsWith('dryinstall:')) {
        console.error(`\x1b[31m[dryinstall:sandbox] ATTACK BLOCKED in "${pkgName}": ${err.message}\x1b[0m`);
        return {};
      }
      throw err;
    }
  }

  setAllowedPackages(pkgs) {
    this.allowedPackages = pkgs; // --allow-package glob,rimraf
    if (pkgs.length > 0) {
      console.log(`\x1b[33m[dryinstall:security] Allowed packages: [${pkgs.join(', ')}]\x1b[0m`);
    }
  }

  async blockLifecycleScript(pkgName, script) {
    const levelConfig = SECURITY_LEVELS[this.level];
    if (!levelConfig.blockLifecycle) {
      console.log(`\x1b[33m[dryinstall] Level ${this.level}: lifecycle allowed: ${pkgName}\x1b[0m`);
      return;
    }

    // --allow-package 옵션으로 명시적 허용된 패키지
    if (this.allowedPackages && this.allowedPackages.includes(pkgName)) {
      console.log(`\x1b[32m[dryinstall] ALLOWED by --allow-package: "${pkgName}": ${script}\x1b[0m`);
      this.allowed.push({ pkg: pkgName, type: 'lifecycle', script, source: '--allow-package' });
      return;
    }

    // interactive 모드 — 사용자에게 물어봄
    if (this.interactive) {
      // [s] Skip all 선택됐으면 바로 차단
      if (this.skipAll) {
        this.blocked.push({ pkg: pkgName, type: 'lifecycle', script, time: new Date().toISOString() });
        return;
      }
      const decision = await this._askLifecycle(pkgName, script);
      if (decision === 'allow') {
        console.log(`\x1b[32m[dryinstall:interactive] ALLOWED: "${pkgName}": ${script}\x1b[0m`);
        this.allowed.push({ pkg: pkgName, type: 'lifecycle', script, source: 'interactive' });
        return;
      }
    }

    // 차단
    console.warn(`\x1b[33m[dryinstall] BLOCKED lifecycle in "${pkgName}": ${script.slice(0, 80)}\x1b[0m`);
    this.blocked.push({ pkg: pkgName, type: 'lifecycle', script, time: new Date().toISOString() });
  }

  async _askLifecycle(pkgName, script, pkgDir = null) {
    const cacheKey = `lifecycle:${pkgName}`;
    if (interactiveCache[cacheKey] === 'always') return 'allow';
    if (interactiveCache[cacheKey] === 'never')  return 'block';

    const colonIdx = script.indexOf(':');
    const hookName = colonIdx >= 0 ? script.slice(0, colonIdx).trim() : script;
    const hookCmd  = colonIdx >= 0 ? script.slice(colonIdx + 1).trim() : script;

    // ── 위험도 분석 ──────────────────────────────────
    const risks = analyzeRisk(hookCmd);
    const riskLevel = risks.length >= 2 ? 'HIGH' : risks.length === 1 ? 'MED' : 'LOW';
    const riskColor = riskLevel === 'HIGH' ? '\x1b[31m' : riskLevel === 'MED' ? '\x1b[33m' : '\x1b[32m';
    const riskLabel = riskLevel === 'HIGH' ? ' ⚠ HIGH RISK!' : riskLevel === 'MED' ? ' ⚠ Medium Risk' : '';

    console.log('');
    console.log(`\x1b[33m┌──────────────────────────────────────────────────────────┐\x1b[0m`);
    console.log(`\x1b[33m│     [dryinstall:interactive] Lifecycle Script Detected    │\x1b[0m`);
    console.log(`\x1b[33m├──────────────────────────────────────────────────────────┤\x1b[0m`);
    console.log(`\x1b[33m│  Package : \x1b[1m${pkgName.padEnd(48)}\x1b[0m\x1b[33m│\x1b[0m`);
    console.log(`\x1b[33m│  Hook    : \x1b[1m${hookName.padEnd(48)}\x1b[0m\x1b[33m│\x1b[0m`);
    console.log(`\x1b[33m│  Command : \x1b[0m${hookCmd.slice(0, 48).padEnd(48)}\x1b[33m│\x1b[0m`);
    console.log(`\x1b[33m│  Risk    : ${riskColor}\x1b[1m${(riskLevel + riskLabel).padEnd(48)}\x1b[0m\x1b[33m│\x1b[0m`);
    if (risks.length > 0) {
      const riskStr = risks.map(r => r.label).join(', ').slice(0, 48).padEnd(48);
      console.log(`\x1b[33m│  Reason  : \x1b[0m${riskStr}\x1b[33m│\x1b[0m`);
    }
    console.log(`\x1b[33m└──────────────────────────────────────────────────────────┘\x1b[0m`);
    console.log(`\x1b[36m  [a] Allow once        [A] Always allow  (saved to .dryinstallrc)\x1b[0m`);
    console.log(`${riskColor}  [b] Block${riskLabel}  [B] Always block  (saved to .dryinstallrc)\x1b[0m`);
    console.log(`\x1b[36m  [v] View source file\x1b[0m`);
    console.log(`\x1b[90m  [s] Block all remaining\x1b[0m`);
    console.log('');

    const TIMEOUT_SEC = 15;
    const self = this;

    return new Promise((resolve) => {
      let settled = false;

      const settle = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(result);
      };

      // ── 자동 타임아웃 ──────────────────────────────
      const timer = setTimeout(() => {
        if (settled) return;
        console.log(`\n\x1b[90m  [auto-block] No input for ${TIMEOUT_SEC}s → blocked\x1b[0m`);
        settle('block');
      }, TIMEOUT_SEC * 1000);

      const askOnce = () => {
        if (settled) return;
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.question(`\x1b[1m  Your choice (a/A/b/B/v/s) [auto-block in ${TIMEOUT_SEC}s]: \x1b[0m`, (answer) => {
          rl.close();
          if (settled) return;
          const a = answer.trim();
          const aLower = a.toLowerCase();

          if (aLower === 'v') {
            const fileInfo = pkgDir ? readScriptFile(hookCmd, pkgDir) : null;
            if (fileInfo) {
              console.log(`\n\x1b[36m  ── Source: ${fileInfo.path} ──\x1b[0m`);
              const lines = fileInfo.content.split('\n').slice(0, 40);
              lines.forEach((line, i) => {
                console.log(`  \x1b[90m${String(i+1).padStart(3)}\x1b[0m  ${line}`);
              });
              if (fileInfo.content.split('\n').length > 40) {
                console.log(`  \x1b[90m  ... (${fileInfo.content.split('\n').length} lines total)\x1b[0m`);
              }
            } else {
              console.log(`\n\x1b[36m  Full command: \x1b[0m${hookCmd}\n`);
              console.log(`  \x1b[90m(Source file not accessible)\x1b[0m`);
            }
            console.log('');
            askOnce();
            return;
          }

          // s: Skip all remaining → 나머지 전부 자동 차단
          if (aLower === 's') {
            self.skipAll = true;
            console.log('\x1b[31m  [dryinstall:interactive] Skip all — remaining scripts will be auto-blocked\x1b[0m');
            settle('block');
          // A: Always allow → .dryinstallrc 저장
          } else if (a === 'A') {
            interactiveCache[cacheKey] = 'always';
            const rc = loadRC();
            if (!rc.alwaysAllow.includes(pkgName)) rc.alwaysAllow.push(pkgName);
            saveRC(rc);
            console.log(`\x1b[32m  Saved to ~/.dryinstallrc: always allow "${pkgName}"\x1b[0m`);
            settle('allow');
          // B: Always block → .dryinstallrc 저장
          } else if (a === 'B') {
            interactiveCache[cacheKey] = 'never';
            const rc = loadRC();
            if (!rc.alwaysBlock.includes(pkgName)) rc.alwaysBlock.push(pkgName);
            saveRC(rc);
            console.log(`\x1b[31m  Saved to ~/.dryinstallrc: always block "${pkgName}"\x1b[0m`);
            settle('block');
          } else if (aLower === 'a') {
            settle('allow');
          } else {
            settle('block');
          }
        });
      };
      askOnce();
    });
  }

  report() {
    if (this.blocked.length === 0) {
      console.log('\x1b[32m[dryinstall] Report: No threats detected\x1b[0m');
      return;
    }
    console.log('\n\x1b[31m========== dryinstall Security Report ==========\x1b[0m');
    console.log(`\x1b[31mTotal blocked attempts: ${this.blocked.length}\x1b[0m`);
    this.blocked.forEach((b, i) => {
      if (b.type === 'lifecycle') {
        console.log(`  [${i + 1}] LIFECYCLE BLOCKED | pkg: ${b.pkg} | script: ${b.script}`);
      } else {
        console.log(`  [${i + 1}] MODULE BLOCKED    | pkg: ${b.pkg} | tried: ${b.module}`);
      }
    });
    console.log('\x1b[31m============================================\x1b[0m\n');
  }
}

module.exports = new SandboxRuntime();

// ── Worker Threads 격리 ──────────────────────────────
const { Worker } = require('worker_threads');
const WORKER_RUNNER = require('path').join(__dirname, 'worker-runner.js');

function loadInWorker(filePath, pkgName = 'unknown') {
  return new Promise((resolve) => {
    console.log(`\x1b[36m[dryinstall:worker] Loading in Worker Thread: ${pkgName}\x1b[0m`);
    const worker = new Worker(WORKER_RUNNER, { workerData: { filePath, pkgName } });

    worker.on('message', (msg) => {
      if (msg.type === 'blocked') {
        console.error(`\x1b[31m[dryinstall:worker] BLOCKED: "${msg.pkg}" tried require("${msg.module}")\x1b[0m`);
      } else if (msg.type === 'log') {
        console.log(`  [worker:${pkgName}]`, ...msg.args);
      } else if (msg.type === 'done') {
        if (msg.blocked.length === 0) {
          console.log(`\x1b[32m[dryinstall:worker] ✓ ${pkgName} — clean execution\x1b[0m`);
        } else {
          console.log(`\x1b[32m[dryinstall:worker] ✓ ${pkgName} — ${msg.blocked.length} attempt(s) blocked\x1b[0m`);
        }
        resolve(msg.exports);
      }
    });

    worker.on('error', (err) => {
      console.error(`\x1b[31m[dryinstall:worker] Worker error: ${err.message}\x1b[0m`);
      resolve({});
    });

    worker.on('exit', (code) => { if (code !== 0) resolve({}); });
  });
}

module.exports.loadInWorker = loadInWorker;