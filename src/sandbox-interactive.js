'use strict';

const readline = require('readline');
const { loadRC, saveRC } = require('./sandbox-policy');

/**
 * SandboxInteractive
 * sandbox.js에서 분리 — interactive 모드 전담
 * 사용자에게 lifecycle script 허용/차단 질문
 */

// 위험 패턴 정의
const HIGH_RISK_PATTERNS = [
  { pattern: /&&|;|\|/,            label: 'chained commands'      },
  { pattern: /https?:\/\//,        label: 'HTTP request'          },
  { pattern: /sudo|su\s/,          label: 'privilege escalation'  },
  { pattern: /curl|wget|fetch/,    label: 'network download'      },
  { pattern: /rm\s+-rf|rmdir/,     label: 'file deletion'         },
  { pattern: /eval|exec\s*\(/,     label: 'code execution'        },
  { pattern: /base64|atob|btoa/,   label: 'encoding/obfuscation'  },
  { pattern: /process\.env|\.env/, label: 'env access'            },
  { pattern: /\.node\b/,           label: 'native addon'          },
];

/**
 * 명령어 위험도 분석
 */
function analyzeRisk(cmd) {
  return HIGH_RISK_PATTERNS.filter(r => r.pattern.test(cmd));
}

/**
 * 스크립트 파일 내용 읽기
 * "node scripts/build.js" → 파일 내용 반환
 */
function readScriptFile(hookCmd, pkgDir) {
  try {
    const match = hookCmd.match(/(?:node|bash|sh|ts-node)\s+([\w.\/\-]+\.(js|mjs|cjs|sh|ts))/);
    if (!match) return null;
    const absPath = require('path').join(pkgDir, match[1]);
    if (!require('fs').existsSync(absPath)) return null;
    return { path: absPath, content: require('fs').readFileSync(absPath, 'utf-8') };
  } catch {
    return null;
  }
}

/**
 * Interactive lifecycle 프롬프트
 * @param {string}  pkgName
 * @param {string}  script        "postinstall: node install.mjs"
 * @param {object}  cache         interactiveCache 참조
 * @param {object}  selfRef       skipAll 상태 참조용
 * @param {string}  pkgDir        소스파일 탐색용 (optional)
 * @returns {Promise<'allow'|'block'>}
 */
function askLifecycle(pkgName, script, cache, selfRef, pkgDir = null) {
  const cacheKey = `lifecycle:${pkgName}`;
  if (cache[cacheKey] === 'always') return Promise.resolve('allow');
  if (cache[cacheKey] === 'never')  return Promise.resolve('block');
  if (selfRef.skipAll)              return Promise.resolve('block');

  const colonIdx = script.indexOf(':');
  const hookName = colonIdx >= 0 ? script.slice(0, colonIdx).trim()      : script;
  const hookCmd  = colonIdx >= 0 ? script.slice(colonIdx + 1).trim()     : script;

  const risks     = analyzeRisk(hookCmd);
  const riskLevel = risks.length >= 2 ? 'HIGH' : risks.length === 1 ? 'MED' : 'LOW';
  const riskColor = riskLevel === 'HIGH' ? '\x1b[31m' : riskLevel === 'MED' ? '\x1b[33m' : '\x1b[32m';
  const riskLabel = riskLevel === 'HIGH' ? ' ⚠ HIGH RISK!' : riskLevel === 'MED' ? ' ⚠ Medium Risk' : '';

  const pad = (s, n) => String(s).slice(0, n).padEnd(n);
  console.log('');
  console.log('\x1b[33m┌──────────────────────────────────────────────────────────┐\x1b[0m');
  console.log('\x1b[33m│     [dryinstall:interactive] Lifecycle Script Detected    │\x1b[0m');
  console.log('\x1b[33m├──────────────────────────────────────────────────────────┤\x1b[0m');
  console.log(`\x1b[33m│  Package : \x1b[1m${pad(pkgName, 48)}\x1b[0m\x1b[33m│\x1b[0m`);
  console.log(`\x1b[33m│  Hook    : \x1b[1m${pad(hookName, 48)}\x1b[0m\x1b[33m│\x1b[0m`);
  console.log(`\x1b[33m│  Command : \x1b[0m${pad(hookCmd, 48)}\x1b[33m│\x1b[0m`);
  console.log(`\x1b[33m│  Risk    : ${riskColor}\x1b[1m${pad(riskLevel + riskLabel, 48)}\x1b[0m\x1b[33m│\x1b[0m`);
  if (risks.length > 0) {
    console.log(`\x1b[33m│  Reason  : \x1b[0m${pad(risks.map(r => r.label).join(', '), 48)}\x1b[33m│\x1b[0m`);
  }
  console.log('\x1b[33m└──────────────────────────────────────────────────────────┘\x1b[0m');
  console.log('\x1b[36m  [a] Allow once        [A] Always allow  (saved to .dryinstallrc)\x1b[0m');
  console.log(`${riskColor}  [b] Block (rec.)      [B] Always block  (saved to .dryinstallrc)\x1b[0m`);
  console.log('\x1b[36m  [v] View source file\x1b[0m');
  console.log('\x1b[90m  [s] Block all remaining\x1b[0m\n');

  const TIMEOUT_SEC = 15;

  return new Promise((resolve) => {
    let settled = false;
    const settle = (val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(val);
    };

    const timer = setTimeout(() => {
      console.log(`\n\x1b[90m  [auto-block] No input for ${TIMEOUT_SEC}s → blocked\x1b[0m`);
      settle('block');
    }, TIMEOUT_SEC * 1000);

    const ask = () => {
      if (settled) return;
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      rl.question(`\x1b[1m  Your choice (a/A/b/B/v/s) [auto-block in ${TIMEOUT_SEC}s]: \x1b[0m`, (ans) => {
        rl.close();
        if (settled) return;
        const a = ans.trim();

        if (a.toLowerCase() === 'v') {
          const fileInfo = pkgDir ? readScriptFile(hookCmd, pkgDir) : null;
          if (fileInfo) {
            console.log(`\n\x1b[36m  ── ${fileInfo.path} ──\x1b[0m`);
            fileInfo.content.split('\n').slice(0, 40).forEach((l, i) =>
              console.log(`  \x1b[90m${String(i+1).padStart(3)}\x1b[0m  ${l}`)
            );
          } else {
            console.log(`\n\x1b[36m  Full command:\x1b[0m ${hookCmd}\n`);
          }
          console.log('');
          ask();
          return;
        }

        if (a.toLowerCase() === 's') {
          selfRef.skipAll = true;
          console.log('\x1b[31m  [dryinstall] Skip all — remaining scripts auto-blocked\x1b[0m');
          settle('block');
        } else if (a === 'A') {
          cache[cacheKey] = 'always';
          const rc = loadRC();
          if (!rc.alwaysAllow.includes(pkgName)) rc.alwaysAllow.push(pkgName);
          saveRC(rc);
          console.log(`\x1b[32m  Saved: always allow "${pkgName}"\x1b[0m`);
          settle('allow');
        } else if (a === 'B') {
          cache[cacheKey] = 'never';
          const rc = loadRC();
          if (!rc.alwaysBlock.includes(pkgName)) rc.alwaysBlock.push(pkgName);
          saveRC(rc);
          console.log(`\x1b[31m  Saved: always block "${pkgName}"\x1b[0m`);
          settle('block');
        } else if (a.toLowerCase() === 'a') {
          settle('allow');
        } else {
          settle('block');
        }
      });
    };
    ask();
  });
}

module.exports = { analyzeRisk, askLifecycle };
