'use strict';

const https = require('https');
const zlib = require('zlib');
const tar = require('tar');
const path = require('path');
const fs = require('fs');
const os = require('os');
const logger = require('./logger');

const STEALTH_PATTERNS = [
  {
    id: 'ENV_CONDITIONAL_NETWORK',
    pattern: /if\s*\(\s*process\.env\.(CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS|TRAVIS|CIRCLECI)\s*\)[\s\S]{0,300}(?:fetch|axios|http\.get|https\.get|request)\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)/g,
    label: 'CI-conditional + external network call — possible stealth backdoor',
    severity: 'CRITICAL',
  },
  {
    id: 'ENV_CONDITIONAL_EXEC',
    pattern: /if\s*\(\s*process\.env\.(CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS|TRAVIS|CIRCLECI)\s*\)[\s\S]{0,300}(?:execSync|exec|spawn)\s*\([^)]*(?:curl|wget|bash|sh)\s+https?:\/\//g,
    label: 'CI-conditional + shell download — possible stealth backdoor',
    severity: 'CRITICAL',
  },
  {
    id: 'HOSTNAME_TARGET',
    pattern: /os\.hostname\(\)|require\('os'\)\.hostname|hostname\(\).*includes|hostname\(\).*startsWith/g,
    label: 'hostname-based targeting',
    severity: 'HIGH',
  },
  {
    id: 'IP_TARGET',
    pattern: /\b(172\.16|10\.\d+\.\d+|192\.168|169\.254)\b.*exec|networkInterfaces.*exec|getNetworkInterfaces/g,
    label: 'IP range targeting',
    severity: 'HIGH',
  },
  {
    id: 'TIME_BOMB',
    pattern: /Date\.now\(\)\s*[>]=\s*\d{10,13}|new Date\(\)\s*[>]=?\s*new Date\(['"][0-9\-]+['"]\)/g,
    label: 'time bomb — date-triggered execution',
    severity: 'CRITICAL',
  },
  {
    id: 'DELAYED_EXEC',
    pattern: /setTimeout\s*\([^,]+,\s*(\d{7,})\s*\)/g,
    label: 'long-delay execution (possible time bomb)',
    severity: 'HIGH',
  },
  {
    id: 'BASE64_EVAL',
    pattern: /eval\s*\(\s*(?:Buffer\.from|atob)\s*\([^)]+(?:base64|hex)[^)]*\)/g,
    label: 'base64/hex encoded eval (obfuscation)',
    severity: 'CRITICAL',
  },
  {
    id: 'DYNAMIC_FUNCTION',
    pattern: /new\s+Function\s*\(\s*['"`][^'"` ]{20,}/g,
    label: 'dynamic Function constructor with long string',
    severity: 'CRITICAL',
  },
  {
    id: 'ENV_EXFIL',
    pattern: /JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.keys\s*\(\s*process\.env\s*\)/g,
    label: 'environment variable mass collection',
    severity: 'CRITICAL',
  },
  {
    id: 'CLOUD_METADATA',
    pattern: /169\.254\.169\.254|metadata\.google\.internal|instance-data\.ec2\.internal/g,
    label: 'cloud metadata API access',
    severity: 'CRITICAL',
  },
  {
    id: 'PROTESTWARE',
    pattern: /while\s*\(\s*true\s*\)\s*\{[^}]{0,100}(console\.log|process\.stdout)/g,
    label: 'infinite loop with output (possible protestware)',
    severity: 'HIGH',
  },
];

function extractJsFiles(tarballUrl) {
  return new Promise((resolve, reject) => {
    const files = new Map();
    https.get(tarballUrl, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        return extractJsFiles(res.headers.location).then(resolve).catch(reject);
      }
      res.pipe(zlib.createGunzip())
        .pipe(tar.t({
          onentry: (entry) => {
            if (!/\.(js|mjs|cjs)$/.test(entry.path)) { entry.resume(); return; }
            if (entry.path.includes('node_modules') || entry.path.includes('.min.js')) { entry.resume(); return; }
            let content = '';
            entry.on('data', chunk => content += chunk.toString());
            entry.on('end', () => files.set(entry.path.replace(/^[^/]+\//, ''), content));
          }
        }))
        .on('finish', () => resolve(files))
        .on('error', reject);
    }).on('error', reject);
  });
}

function analyzeFile(filename, content) {
  const findings = [];
  for (const def of STEALTH_PATTERNS) {
    const matches = content.match(def.pattern);
    if (!matches || matches.length === 0) continue;
    const idx = content.search(def.pattern);
    const context = content.slice(Math.max(0, idx-40), idx+80).replace(/\n/g,' ').trim();
    findings.push({ id: def.id, label: def.label, severity: def.severity, filename, count: matches.length, context });
  }
  return findings;
}

async function detectStealth(pkgName, tarballUrl) {
  logger.verbose(`[dryinstall:stealth] Scanning for backdoor patterns: ${pkgName}`);

  let files;
  try { files = await extractJsFiles(tarballUrl); }
  catch (err) {
    logger.verbose(`[dryinstall:stealth] Could not extract files: ${err.message}`);
    return { skipped: true };
  }

  const allFindings = [];
  for (const [filename, content] of files) {
    allFindings.push(...analyzeFile(filename, content));
  }

  if (allFindings.length === 0) {
    logger.verbose(`[dryinstall:stealth] No stealth patterns detected`);
    return { clean: true };
  }

  return { clean: false, findings: allFindings };
}

function reportStealth(pkgName, result) {
  if (result.skipped || result.clean) return;
  const color = result.findings.some(f=>f.severity==='CRITICAL') ? '\x1b[31m' : '\x1b[33m';
  console.log(`${color}┌──────────────────────────────────────────────────────────┐\x1b[0m`);
  console.log(`${color}│        ⚠  STEALTH BACKDOOR PATTERN DETECTED              │\x1b[0m`);
  console.log(`${color}│  Package  : \x1b[1m${pkgName.padEnd(47)}\x1b[0m${color}│\x1b[0m`);
  console.log(`${color}└──────────────────────────────────────────────────────────┘\x1b[0m`);
  result.findings.forEach((f, i) => {
    const fc = f.severity==='CRITICAL'?'\x1b[31m':'\x1b[33m';
    console.log(`${fc}  [${i+1}] [${f.severity}] ${f.label}\x1b[0m`);
    console.log(`\x1b[90m       file: ${f.filename}  context: ...${f.context.slice(0,60)}...\x1b[0m`);
  });
}

module.exports = { detectStealth, reportStealth };