'use strict';

const path = require('path');
const fs   = require('fs');
const os   = require('os');

/**
 * SandboxPolicy
 * sandbox.js에서 분리 — RC 파일, 보안 레벨, Policy 전담
 */

const RC_PATH     = path.join(os.homedir(), '.dryinstallrc');
const POLICY_PATH = path.join(process.cwd(), 'dryinstall.policy.json');

// ── 보안 레벨 정의 ─────────────────────────────────────
const SECURITY_LEVELS = {
  3: {
    name:           'Paranoid (Default)',
    blockedModules: ['fs','net','child_process','os','cluster','dgram','dns','tls','http','https'],
    blockLifecycle: true,
    useWorker:      true,
  },
  2: {
    name:           'Balanced',
    blockedModules: ['child_process','cluster','dgram'],
    blockLifecycle: true,
    useWorker:      false,
  },
  1: {
    name:           'Relaxed',
    blockedModules: [],
    blockLifecycle: false,
    useWorker:      false,
  },
  0: {
    name:           'Off (Pass-through)',
    blockedModules: [],
    blockLifecycle: false,
    useWorker:      false,
  },
};

// ── RC 파일 ────────────────────────────────────────────
function loadRC() {
  try {
    if (fs.existsSync(RC_PATH)) {
      return JSON.parse(fs.readFileSync(RC_PATH, 'utf-8'));
    }
  } catch {}
  return { alwaysAllow: [], alwaysBlock: [] };
}

function saveRC(rc) {
  try {
    fs.writeFileSync(RC_PATH, JSON.stringify(rc, null, 2));
  } catch {}
}

// ── Policy 파일 ────────────────────────────────────────
let POLICY = {};
try {
  POLICY = JSON.parse(fs.readFileSync(POLICY_PATH, 'utf-8'));
  console.log('\x1b[36m[dryinstall:policy] Policy file loaded\x1b[0m');
} catch {}

function getAllowedModules(pkgName) {
  const entry = POLICY[pkgName] || POLICY['_default'] || { allow: [] };
  return entry.allow || [];
}

// ── Interactive キャッシュ初期化 ──────────────────────
function buildInteractiveCache() {
  const cache = {};
  const rc    = loadRC();
  rc.alwaysAllow.forEach(p => { cache[`lifecycle:${p}`] = 'always'; });
  rc.alwaysBlock.forEach(p => { cache[`lifecycle:${p}`] = 'never';  });
  return cache;
}

module.exports = {
  SECURITY_LEVELS,
  loadRC,
  saveRC,
  getAllowedModules,
  buildInteractiveCache,
  RC_PATH,
};
