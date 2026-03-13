'use strict';

/**
 * worker-runner.js
 * Worker Thread 안에서 패키지 실행
 * 메인 프로세스와 완전히 분리된 공간
 */

const { workerData, parentPort } = require('worker_threads');
const vm = require('vm');
const fs = require('fs');

const { filePath, pkgName } = workerData;

const blocked = [];

// Worker 안에서도 vm Sandbox 유지 (이중 격리)
const safeRequire = (mod) => {
  const blockedModules = ['fs', 'net', 'child_process', 'os', 'cluster', 'dgram', 'dns', 'tls'];
  if (blockedModules.includes(mod)) {
    const msg = `Worker blocked: "${pkgName}" tried require("${mod}")`;
    blocked.push({ pkg: pkgName, module: mod });
    parentPort.postMessage({ type: 'blocked', pkg: pkgName, module: mod });
    throw new Error(`dryinstall Worker: access to "${mod}" is blocked`);
  }
  return require(mod);
};

try {
  const code = fs.readFileSync(filePath, 'utf-8');
  const context = vm.createContext({
    console: {
      log: (...args) => parentPort.postMessage({ type: 'log', args }),
      error: (...args) => parentPort.postMessage({ type: 'error', args }),
    },
    require: safeRequire,
    process: { version: process.version, platform: process.platform, env: {} },
    Buffer,
    module: { exports: {} },
    exports: {},
  });

  vm.runInContext(code, context, { timeout: 5000 });

  // 실행 결과 메인으로 전송
  parentPort.postMessage({
    type: 'done',
    exports: JSON.stringify(context.module.exports),
    blocked,
  });

} catch (err) {
  parentPort.postMessage({
    type: 'error',
    message: err.message,
    blocked,
  });
}
