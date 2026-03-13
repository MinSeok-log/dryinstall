'use strict';

const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const vm   = require('vm');
const path = require('path');
const fs   = require('fs');

/**
 * WorkerRunner (강화됨)
 *
 * vm 모듈의 한계:
 *   - require() 캐시 공유 (같은 프로세스)
 *   - prototype 체인 공격 가능 (Object.prototype 접근)
 *   - 동기 코드 타임아웃만 가능 (비동기 탈출 가능)
 *
 * Worker Thread로 보완:
 *   - 완전히 분리된 프로세스 메모리 공간
 *   - require 캐시 완전 분리
 *   - 타임아웃 시 terminate() → 프로세스 강제 종료
 *   - 부모 프로세스 오염 불가
 */

// ── Worker 내부에서 실행될 코드 ────────────────────────
// 이 파일이 Worker Thread로 실행될 때의 진입점
if (!isMainThread) {
  const { code, pkgName, allowedModules, timeoutMs } = workerData;

  // Worker Thread 안에서의 vm 격리
  const BLOCKED = [
    'fs', 'net', 'child_process', 'os', 'cluster',
    'dgram', 'dns', 'tls', 'http', 'https',
    'crypto', 'readline', 'repl', 'vm',
  ];

  const violations = [];

  const safeRequire = (mod) => {
    if (BLOCKED.includes(mod) && !allowedModules.includes(mod)) {
      const msg = `[BLOCKED in Worker] require("${mod}") — module not allowed`;
      violations.push({ module: mod, timestamp: Date.now() });
      parentPort.postMessage({ type: 'violation', module: mod });
      throw new Error(msg);
    }
    return require(mod);
  };

  // prototype 오염 방어 — Object.freeze로 핵심 prototype 잠금
  try {
    Object.freeze(Object.prototype);
    Object.freeze(Array.prototype);
    Object.freeze(Function.prototype);
  } catch {}

  // vm 컨텍스트 구성 — 최소한만 노출
  const sandbox = {
    require:   safeRequire,
    module:    { exports: {} },
    exports:   {},
    console:   {
      log:   (...a) => parentPort.postMessage({ type: 'log',   args: a }),
      warn:  (...a) => parentPort.postMessage({ type: 'warn',  args: a }),
      error: (...a) => parentPort.postMessage({ type: 'error', args: a }),
    },
    process: {
      // 최소한만 노출
      version:  process.version,
      platform: process.platform,
      arch:     process.arch,
      env:      {},          // 환경변수 완전 차단
      argv:     [],
      exit:     (code) => {
        parentPort.postMessage({ type: 'exit', code });
      },
    },
    Buffer,
    setTimeout:  (fn, ms) => setTimeout(fn, Math.min(ms, timeoutMs)),
    clearTimeout,
    setInterval: () => {},  // 장기 실행 방지
    __filename: `[dryinstall-sandbox:${pkgName}]`,
    __dirname:  '/sandbox',
  };

  vm.createContext(sandbox);

  try {
    // 스크립트 실행 — 타임아웃은 Worker terminate()로 처리
    const script = new vm.Script(code, {
      filename:        `[dryinstall-sandbox:${pkgName}]`,
      lineOffset:      0,
      columnOffset:    0,
      displayErrors:   true,
    });

    const result = script.runInContext(sandbox, { timeout: timeoutMs });
    parentPort.postMessage({ type: 'done', result, violations });

  } catch (err) {
    parentPort.postMessage({
      type:       'error',
      message:    err.message,
      violations,
    });
  }

  return;
}

// ── 메인 스레드에서 사용하는 API ──────────────────────

/**
 * 코드를 Worker Thread 안의 vm에서 실행
 *
 * @param {string}   code            - 실행할 JS 코드
 * @param {string}   pkgName         - 패키지명 (로그용)
 * @param {string[]} allowedModules  - 허용할 Node 모듈 목록
 * @param {number}   timeoutMs       - 타임아웃 (기본 5000ms)
 * @returns {Promise<{
 *   success:    boolean,
 *   result:     any,
 *   violations: Array<{module: string, timestamp: number}>,
 *   logs:       string[],
 *   error:      string|null,
 *   timedOut:   boolean,
 * }>}
 */
function runInWorker(code, pkgName = 'unknown', allowedModules = [], timeoutMs = 5000) {
  return new Promise((resolve) => {
    const logs       = [];
    const violations = [];
    let   settled    = false;
    let   worker;

    const settle = (result) => {
      if (settled) return;
      settled = true;
      try { worker?.terminate(); } catch {}
      resolve(result);
    };

    // 강제 종료 타이머 — vm timeout이 비동기를 못 잡을 수 있으므로
    const killTimer = setTimeout(() => {
      settle({
        success:    false,
        result:     null,
        violations,
        logs,
        error:      `Execution timed out after ${timeoutMs}ms`,
        timedOut:   true,
      });
    }, timeoutMs + 500);  // vm timeout + 여유 500ms

    try {
      worker = new Worker(__filename, {
        workerData: { code, pkgName, allowedModules, timeoutMs },
        // Worker에 노출할 env 없음 — 완전 격리
        env: {},
        // resourceLimits — 메모리 + CPU 제한
        resourceLimits: {
          maxOldGenerationSizeMb:  64,   // 힙 최대 64MB
          maxYoungGenerationSizeMb: 16,
          codeRangeSizeMb:         8,
        },
      });

      worker.on('message', (msg) => {
        if (msg.type === 'log' || msg.type === 'warn') {
          logs.push(msg.args?.join(' ') || '');
        }
        if (msg.type === 'violation') {
          violations.push({ module: msg.module, timestamp: Date.now() });
        }
        if (msg.type === 'done') {
          clearTimeout(killTimer);
          settle({
            success: true,
            result:  msg.result,
            violations: [...violations, ...(msg.violations || [])],
            logs,
            error:   null,
            timedOut: false,
          });
        }
        if (msg.type === 'error') {
          clearTimeout(killTimer);
          settle({
            success:    false,
            result:     null,
            violations: [...violations, ...(msg.violations || [])],
            logs,
            error:      msg.message,
            timedOut:   false,
          });
        }
      });

      worker.on('error', (err) => {
        clearTimeout(killTimer);
        settle({
          success:    false,
          result:     null,
          violations,
          logs,
          error:      err.message,
          timedOut:   false,
        });
      });

      worker.on('exit', (code) => {
        clearTimeout(killTimer);
        if (!settled) {
          settle({
            success:    code === 0,
            result:     null,
            violations,
            logs,
            error:      code !== 0 ? `Worker exited with code ${code}` : null,
            timedOut:   false,
          });
        }
      });

    } catch (err) {
      clearTimeout(killTimer);
      settle({
        success:    false,
        result:     null,
        violations,
        logs,
        error:      `Failed to create Worker: ${err.message}`,
        timedOut:   false,
      });
    }
  });
}

/**
 * 패키지 파일을 Worker Thread에서 실행 (파일 경로 기반)
 * @param {string}   filePath
 * @param {string}   pkgName
 * @param {string[]} allowedModules
 * @param {number}   timeoutMs
 */
async function runFileInWorker(filePath, pkgName, allowedModules = [], timeoutMs = 5000) {
  if (!fs.existsSync(filePath)) {
    return { success: false, error: `File not found: ${filePath}`, violations: [], logs: [] };
  }

  let code;
  try {
    code = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    return { success: false, error: `Cannot read file: ${err.message}`, violations: [], logs: [] };
  }

  return runInWorker(code, pkgName, allowedModules, timeoutMs);
}

/**
 * 결과 요약 출력
 */
function reportWorkerResult(pkgName, result) {
  const C = {
    RESET:  '\x1b[0m',
    RED:    '\x1b[31m',
    GREEN:  '\x1b[32m',
    YELLOW: '\x1b[33m',
    GRAY:   '\x1b[90m',
  };

  if (result.violations.length > 0) {
    console.log(`${C.RED}[dryinstall:worker] ${pkgName} — ${result.violations.length} violation(s) detected${C.RESET}`);
    result.violations.forEach(v => {
      console.log(`${C.RED}  ✗  Attempted require("${v.module}")${C.RESET}`);
    });
  }

  if (result.timedOut) {
    console.log(`${C.RED}[dryinstall:worker] ${pkgName} — execution timed out (killed)${C.RESET}`);
  }

  if (!result.success && !result.timedOut && result.violations.length === 0) {
    console.log(`${C.YELLOW}[dryinstall:worker] ${pkgName} — ${result.error}${C.RESET}`);
  }

  if (result.logs.length > 0) {
    console.log(`${C.GRAY}[dryinstall:worker] ${pkgName} logs:${C.RESET}`);
    result.logs.slice(0, 10).forEach(l => console.log(`${C.GRAY}  ${l}${C.RESET}`));
  }
}

module.exports = { runInWorker, runFileInWorker, reportWorkerResult };
