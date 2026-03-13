'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');

// ── 캐시 경로 ─────────────────────────────────────────
const CACHE_PATH = path.join(__dirname, '..', '.popular-packages-cache.json');
const CACHE_TTL = 1000 * 60 * 60 * 24; // 24시간

// ── 기본 폴백 목록 (네트워크 없을 때) ─────────────────
const FALLBACK_PACKAGES = [
  'react', 'react-dom', 'lodash', 'express', 'axios', 'webpack',
  'babel', 'typescript', 'eslint', 'prettier', 'jest', 'mocha',
  'chai', 'mongoose', 'sequelize', 'redis', 'socket.io', 'puppeteer',
  'playwright', 'cheerio', 'chalk', 'commander', 'yargs', 'dotenv',
  'nodemon', 'moment', 'dayjs', 'uuid', 'cors', 'helmet', 'multer',
  'passport', 'jsonwebtoken', 'bcrypt', 'vue', 'angular', 'svelte',
  'next', 'nuxt', 'tailwindcss', 'sass', 'postcss', 'vite', 'rollup',
  'rxjs', 'ramda', 'underscore', 'async', 'bluebird', 'debug',
  'winston', 'morgan', 'body-parser', 'cookie-parser', 'compression',
  'cross-env', 'rimraf', 'glob', 'minimist', 'semver', 'inquirer',
  'ora', 'boxen', 'update-notifier', 'conf', 'cosmiconfig',
  'sharp', 'jimp', 'canvas', 'pdfkit', 'exceljs', 'csv-parse',
  'pg', 'mysql2', 'sqlite3', 'knex', 'typeorm', 'prisma',
  'graphql', 'apollo-server', 'fastify', 'koa', 'hapi',
  'electron', 'tauri', 'expo', 'react-native',
  'firebase', 'aws-sdk', 'googleapis', 'stripe',
  'cheerio', 'puppeteer-core', 'selenium-webdriver',
  'jest-cli', 'ts-jest', 'vitest', 'cypress', 'playwright',
  'husky', 'lint-staged', 'commitlint', 'standard',
  'webpack-cli', 'webpack-dev-server', 'babel-loader',
  'css-loader', 'style-loader', 'file-loader', 'url-loader',
];

/**
 * Levenshtein Distance
 */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/**
 * npm registry에서 상위 다운로드 패키지 목록 가져오기
 * https://registry.npmjs.org/-/v1/search?text=&popularity=1.0&size=250
 */
function fetchPopularPackages(page = 0) {
  return new Promise((resolve) => {
    const url = `https://registry.npmjs.org/-/v1/search?text=&popularity=1.0&size=250&from=${page * 250}`;
    https.get(url, { headers: { 'Accept': 'application/json' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const names = (json.objects || []).map(o => o.package.name);
          resolve(names);
        } catch {
          resolve([]);
        }
      });
    }).on('error', () => resolve([]));
  });
}

/**
 * 캐시에서 인기 패키지 목록 로드
 * 없거나 만료됐으면 npm에서 가져옴
 */
async function loadPopularPackages() {
  // 캐시 확인
  if (fs.existsSync(CACHE_PATH)) {
    try {
      const cache = JSON.parse(fs.readFileSync(CACHE_PATH, 'utf-8'));
      if (Date.now() - cache.timestamp < CACHE_TTL) {
        return cache.packages;
      }
    } catch {}
  }

  // npm registry에서 가져오기 (4페이지 = 1000개)
  console.log('\x1b[36m[dryinstall:typo] Updating popular packages list from npm...\x1b[0m');
  const results = await Promise.all([0, 1, 2, 3].map(fetchPopularPackages));
  const packages = [...new Set(results.flat())];

  if (packages.length > 0) {
    try {
      fs.writeFileSync(CACHE_PATH, JSON.stringify({ timestamp: Date.now(), packages }));
      console.log(`\x1b[36m[dryinstall:typo] Cached ${packages.length} popular packages\x1b[0m`);
    } catch {}
    return packages;
  }

  // 네트워크 실패 시 폴백
  console.log('\x1b[33m[dryinstall:typo] Using fallback package list\x1b[0m');
  return FALLBACK_PACKAGES;
}

/**
 * 로컬 패키지 목록 수집
 * node_modules/ + dry_modules/ + package.json dependencies
 */
function loadLocalPackages(cwd = process.cwd()) {
  const local = new Set();

  // node_modules/
  const nodeModules = path.join(cwd, 'node_modules');
  if (fs.existsSync(nodeModules)) {
    fs.readdirSync(nodeModules)
      .filter(p => !p.startsWith('.') && !p.startsWith('@'))
      .forEach(p => local.add(p));
    // scoped packages (@org/pkg)
    fs.readdirSync(nodeModules)
      .filter(p => p.startsWith('@'))
      .forEach(scope => {
        const scopeDir = path.join(nodeModules, scope);
        if (fs.statSync(scopeDir).isDirectory()) {
          fs.readdirSync(scopeDir).forEach(p => local.add(`${scope}/${p}`));
        }
      });
  }

  // dry_modules/
  const dryModules = path.join(cwd, 'dry_modules');
  if (fs.existsSync(dryModules)) {
    fs.readdirSync(dryModules)
      .filter(p => !p.startsWith('.'))
      .forEach(p => local.add(p));
  }

  // package.json
  const pkgJson = path.join(cwd, 'package.json');
  if (fs.existsSync(pkgJson)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJson, 'utf-8'));
      Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).forEach(p => local.add(p));
    } catch {}
  }

  return [...local];
}

/**
 * Typosquatting 탐지 메인 함수
 * popular + local 합쳐서 비교
 */
async function detectTyposquatting(pkgName, cwd = process.cwd()) {
  const [popular, local] = await Promise.all([
    loadPopularPackages(),
    Promise.resolve(loadLocalPackages(cwd)),
  ]);

  // 합쳐서 중복 제거
  const allKnown = [...new Set([...popular, ...local])];

  const suggestions = [];
  const nameLower = pkgName.toLowerCase();

  for (const known of allKnown) {
    if (known === pkgName) continue; // 정확히 일치하면 패스
    const dist = levenshtein(nameLower, known.toLowerCase());

    // 거리 1~2 : 강한 의심
    // 거리 3   : 긴 패키지명(8자 이상)에서만 포함
    if (dist <= 2) {
      suggestions.push({ name: known, distance: dist, source: popular.includes(known) ? 'popular' : 'local' });
    } else if (dist === 3 && pkgName.length >= 8) {
      suggestions.push({ name: known, distance: dist, source: popular.includes(known) ? 'popular' : 'local' });
    }
  }

  // 거리 순, 인기 패키지 우선 정렬
  suggestions.sort((a, b) =>
    a.distance !== b.distance ? a.distance - b.distance :
    a.source === 'popular' ? -1 : 1
  );

  return suggestions.slice(0, 5); // 상위 5개만
}

module.exports = { detectTyposquatting, levenshtein, loadPopularPackages };
