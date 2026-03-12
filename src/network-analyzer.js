'use strict';

const https = require('https');
const http = require('http');
const net = require('net');
const dns = require('dns');
const { execSync } = require('child_process');
const os = require('os');

/**
 * NetworkAnalyzer
 * 패키지 설치 중 네트워크 동작 분석
 * - DNS 조회 감시
 * - 외부 HTTP/HTTPS 요청 감시
 * - 비정상 아웃바운드 연결 탐지
 */
class NetworkAnalyzer {
  constructor() {
    this.enabled = false;
    this.requests = [];     // 모든 네트워크 요청 기록
    this.blocked = [];      // 차단된 요청
    this.allowed = [];      // 허용된 요청
    this.pkgName = null;

    // 허용된 npm 관련 도메인
    this.safeDomains = [
      'registry.npmjs.org',
      'registry.yarnpkg.com',
      'npmjs.org',
      'npmjs.com',
      'nodejs.org',
      'github.com',
      'raw.githubusercontent.com',
      'objects.githubusercontent.com',
      'cdn.npmjs.com',
      'codeload.github.com',
    ];

    // 위험 패턴
    this.dangerousPatterns = [
      /attacker/i,
      /steal/i,
      /exfil/i,
      /c2\./i,
      /\.onion/i,
      /ngrok\.io/i,
      /burpcollaborator/i,
      /interact\.sh/i,
      /requestbin/i,
      /webhook\.site/i,
      /pipedream\.net/i,
    ];
  }

  /**
   * 분석 시작 - http/https 모듈 monkey-patch
   */
  start(pkgName) {
    this.pkgName = pkgName;
    this.enabled = true;
    this.requests = [];
    this.blocked = [];
    this.allowed = [];

    console.log(`\x1b[36m[dryinstall:network] Monitoring network for: ${pkgName}\x1b[0m`);

    // ── https.request monkey-patch ──────────────────────
    this._originalHttpsRequest = https.request;
    this._originalHttpRequest = http.request;
    this._originalDnsLookup = dns.lookup;

    const self = this;

    https.request = function(options, callback) {
      const hostname = typeof options === 'string'
        ? new URL(options).hostname
        : (options.hostname || options.host || '');
      return self._interceptRequest('https', hostname, options, callback,
        self._originalHttpsRequest.bind(https));
    };

    http.request = function(options, callback) {
      const hostname = typeof options === 'string'
        ? new URL(options).hostname
        : (options.hostname || options.host || '');
      return self._interceptRequest('http', hostname, options, callback,
        self._originalHttpRequest.bind(http));
    };

    // dns.lookup 감시
    dns.lookup = function(hostname, options, callback) {
      const cb = typeof options === 'function' ? options : callback;
      const opts = typeof options === 'function' ? {} : options;
      self._recordDns(hostname);
      return self._originalDnsLookup.call(dns, hostname, opts, cb);
    };
  }

  /**
   * 분석 중지 - monkey-patch 복원
   */
  stop() {
    if (!this.enabled) return;
    this.enabled = false;

    if (this._originalHttpsRequest) https.request = this._originalHttpsRequest;
    if (this._originalHttpRequest) http.request = this._originalHttpRequest;
    if (this._originalDnsLookup) dns.lookup = this._originalDnsLookup;

    console.log(`\x1b[36m[dryinstall:network] Monitoring stopped: ${this.pkgName}\x1b[0m`);
  }

  /**
   * 요청 가로채기 및 판단
   */
  _interceptRequest(protocol, hostname, options, callback, original) {
    const record = {
      pkg: this.pkgName,
      protocol,
      hostname,
      time: new Date().toISOString(),
    };

    this.requests.push(record);

    // safe domain 여부
    const isSafe = this.safeDomains.some(d =>
      hostname === d || hostname.endsWith('.' + d)
    );

    // 위험 패턴 여부
    const isDangerous = this.dangerousPatterns.some(p => p.test(hostname));

    if (isDangerous) {
      console.error(`\x1b[31m[dryinstall:network] ✗ DANGEROUS: "${this.pkgName}" → ${protocol}://${hostname}\x1b[0m`);
      this.blocked.push({ ...record, reason: 'dangerous_pattern' });
      // 요청 자체를 차단 (빈 소켓 반환)
      return this._fakeRequest();
    }

    if (!isSafe) {
      console.warn(`\x1b[33m[dryinstall:network] ⚠ SUSPICIOUS: "${this.pkgName}" → ${protocol}://${hostname}\x1b[0m`);
      this.blocked.push({ ...record, reason: 'unknown_domain' });
      return this._fakeRequest();
    }

    // 안전한 도메인은 허용
    console.log(`\x1b[32m[dryinstall:network] ✓ ALLOWED: ${protocol}://${hostname}\x1b[0m`);
    this.allowed.push(record);
    return original(options, callback);
  }

  /**
   * DNS 기록
   */
  _recordDns(hostname) {
    const isSafe = this.safeDomains.some(d =>
      hostname === d || hostname.endsWith('.' + d)
    );
    if (!isSafe) {
      console.warn(`\x1b[33m[dryinstall:network] ⚠ DNS lookup: "${this.pkgName}" → ${hostname}\x1b[0m`);
    }
  }

  /**
   * 차단용 가짜 요청 반환
   */
  _fakeRequest() {
    const { Writable } = require('stream');
    const fake = new Writable({
      write(chunk, encoding, callback) { callback(); }
    });
    fake.end = () => fake;
    fake.on = (event, cb) => { if (event === 'error') {} return fake; };
    fake.setTimeout = () => fake;
    fake.destroy = () => fake;
    return fake;
  }

  /**
   * 현재 아웃바운드 연결 스냅샷 (netstat 기반)
   */
  snapshotConnections() {
    try {
      const platform = os.platform();
      let output = '';
      if (platform === 'win32') {
        output = execSync('netstat -ano', { timeout: 3000 }).toString();
      } else {
        output = execSync('netstat -tn 2>/dev/null || ss -tn', { timeout: 3000 }).toString();
      }
      return output.trim().split('\n')
        .filter(l => l.includes('ESTABLISHED'))
        .map(l => l.trim());
    } catch {
      return [];
    }
  }

  /**
   * 최종 리포트
   */
  report() {
    console.log('\n\x1b[36m[dryinstall:network] ═══ Network Analysis Report ═══\x1b[0m');
    console.log(`  Package        : ${this.pkgName}`);
    console.log(`  Total requests : ${this.requests.length}`);
    console.log(`  Allowed        : \x1b[32m${this.allowed.length}\x1b[0m`);
    console.log(`  Blocked        : \x1b[31m${this.blocked.length}\x1b[0m`);

    if (this.blocked.length > 0) {
      console.log('\n\x1b[31m  Blocked requests:\x1b[0m');
      this.blocked.forEach((b, i) => {
        console.log(`  [${i + 1}] ${b.protocol}://${b.hostname} — ${b.reason}`);
      });
    }

    if (this.allowed.length > 0) {
      console.log('\n\x1b[32m  Allowed requests:\x1b[0m');
      this.allowed.forEach((a, i) => {
        console.log(`  [${i + 1}] ${a.protocol}://${a.hostname}`);
      });
    }

    console.log('\x1b[36m[dryinstall:network] ═══════════════════════════════\x1b[0m\n');

    return {
      total: this.requests.length,
      allowed: this.allowed.length,
      blocked: this.blocked.length,
      isSuspicious: this.blocked.length > 0,
    };
  }
}

module.exports = new NetworkAnalyzer();
