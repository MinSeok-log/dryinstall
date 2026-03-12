'use strict';

const Module = require('module');
const path = require('path');
const fs = require('fs');
const sandbox = require('./sandbox');
const ex = require('./exception-handler');

/**
 * Mirror Loader — Runtime Monitoring
 * Module._load를 가로채서 모든 require() 호출을 실시간 감시
 */

const originalLoad = Module._load;
const DRY_MODULES_DIR = path.join(process.cwd(), 'dry_modules');
const monitorLog = [];
const BUILTINS = new Set(Module.builtinModules);
const DANGEROUS_MODULES = new Set([
  'child_process', 'fs', 'net', 'dgram',
  'cluster', 'tls', 'http', 'https', 'dns',
]);

// dry_modules 존재 여부 시작 시 확인
const dryModulesExist = ex.handleMissingDryModulesDir(process.cwd());

// ── require 우회 벡터 패치 ───────────────────────────

// 1. process.mainModule.require 패치
if (process.mainModule) {
  const _origMainRequire = process.mainModule.require.bind(process.mainModule);
  process.mainModule.require = function(id) {
    const dryPath = _resolveDryPath(id);
    if (dryPath) {
      console.log(`[31m[dryinstall:loader] BYPASS BLOCKED: process.mainModule.require("${id}")[0m`);
      return sandbox.load(dryPath, id);
    }
    return _origMainRequire(id);
  };
}

// 2. Module.createRequire 패치
const _origCreateRequire = Module.createRequire.bind(Module);
Module.createRequire = function(filename) {
  const originalRequire = _origCreateRequire(filename);
  return new Proxy(originalRequire, {
    apply(target, thisArg, args) {
      const id = args[0];
      const dryPath = _resolveDryPath(id);
      if (dryPath) {
        console.log(`[31m[dryinstall:loader] BYPASS BLOCKED: Module.createRequire("${id}")[0m`);
        return sandbox.load(dryPath, id);
      }
      return target.apply(thisArg, args);
    }
  });
};

// 3. vm.runInThisContext 패치 — sandbox 탈출 차단
const vm = require('vm');
const _origRunInThisContext = vm.runInThisContext.bind(vm);
vm.runInThisContext = function(code, options) {
  // dry_modules 관련 코드에서만 감시
  if (typeof code === 'string' && (
    code.includes('process.mainModule') ||
    code.includes('Function(') ||
    code.includes('constructor.constructor')
  )) {
    console.error(`[31m[dryinstall:loader] BYPASS BLOCKED: vm.runInThisContext with suspicious code[0m`);
    throw new Error('dryinstall: suspicious vm.runInThisContext blocked');
  }
  return _origRunInThisContext(code, options);
};

// 4. dynamic import() 감시 — Node 18+
// import()는 완전 차단 불가 (언어 레벨)이므로 경고만
const _origSetTimeout = global.setTimeout;
global.__dryinstall_import_warned = false;

Module._load = function(request, parent, isMain) {
  const callerFile = parent?.filename || 'unknown';
  const isDryModule = callerFile.includes('dry_modules');
  const isOwnFile = callerFile.includes('dryinstall') || callerFile.includes('src/');

  // dryinstall 자체 파일은 패스
  if (isOwnFile && !isDryModule) {
    return originalLoad.call(this, request, parent, isMain);
  }

  // dry_modules에서 호출된 require → Sandbox 위임
  if (isDryModule) {
    const pkgName = _extractPkgName(callerFile);

    // 위험 모듈 접근 시도
    if (DANGEROUS_MODULES.has(request)) {
      const msg = `[dryinstall:loader] RUNTIME BLOCKED: "${pkgName}" tried require("${request}")`;
      console.error('\x1b[31m' + msg + '\x1b[0m');
      monitorLog.push({
        type: 'BLOCKED',
        pkg: pkgName,
        module: request,
        caller: callerFile,
        time: new Date().toISOString(),
      });
      throw new Error(`dryinstall: runtime access to "${request}" is blocked`);
    }

    // 허용된 모듈은 로그만 남기고 통과
    monitorLog.push({
      type: 'ALLOWED',
      pkg: pkgName,
      module: request,
      time: new Date().toISOString(),
    });

    return originalLoad.call(this, request, parent, isMain);
  }

  // 일반 require → dry_modules에 있으면 Sandbox로 로드
  const dryPath = _resolveDryPath(request);
  if (dryPath) {
    console.log(`\x1b[36m[dryinstall:loader] Intercepted: require("${request}") → dry_modules\x1b[0m`);
    monitorLog.push({ type: 'INTERCEPTED', pkg: request, time: new Date().toISOString() });
    return sandbox.load(dryPath, request);
  }

  // dry_modules에 없지만 dry_modules 자체가 있으면 → 경고 후 fallback
  if (dryModulesExist && !BUILTINS.has(request) && !request.startsWith('.')) {
    const nodeModulesFallback = path.join(process.cwd(), 'node_modules', request);
    if (fs.existsSync(nodeModulesFallback)) {
      ex.handleMissingDryModules(request, nodeModulesFallback);
    }
  }

  // 원본 require
  return originalLoad.call(this, request, parent, isMain);
};

/**
 * dry_modules에서 패키지 메인 파일 경로 찾기
 */
function _resolveDryPath(pkgName) {
  if (BUILTINS.has(pkgName)) return null;
  if (pkgName.startsWith('.') || pkgName.startsWith('/')) return null;

  const pkgDir = path.join(DRY_MODULES_DIR, pkgName);
  if (!fs.existsSync(pkgDir)) return null;

  // package.json main 필드 참조
  const pkgJsonPath = path.join(pkgDir, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      const main = pkg.main || 'index.js';
      const mainPath = path.join(pkgDir, main);
      if (fs.existsSync(mainPath)) return mainPath;
    } catch {}
  }

  // fallback: index.js
  const indexPath = path.join(pkgDir, 'index.js');
  if (fs.existsSync(indexPath)) return indexPath;

  return null;
}

/**
 * 파일 경로에서 패키지명 추출
 */
function _extractPkgName(filePath) {
  const match = filePath.match(/dry_modules[\\/]([^\\/]+)/);
  return match ? match[1] : 'unknown';
}

/**
 * 런타임 감시 리포트
 */
function runtimeReport() {
  const blocked = monitorLog.filter(l => l.type === 'BLOCKED');
  const intercepted = monitorLog.filter(l => l.type === 'INTERCEPTED');

  console.log('\n\x1b[36m[dryinstall:loader] Runtime Monitor Report\x1b[0m');
  console.log(`  Intercepted require() calls : ${intercepted.length}`);
  console.log(`  Runtime blocked attempts    : ${blocked.length}`);

  if (blocked.length > 0) {
    console.log('\n\x1b[31m  Blocked details:\x1b[0m');
    blocked.forEach((b, i) => {
      console.log(`  [${i + 1}] pkg: ${b.pkg} | tried: ${b.module} | ${b.time}`);
    });
  }
}

// 프로세스 종료 시 자동 리포트
process.on('exit', runtimeReport);

module.exports = { runtimeReport };
