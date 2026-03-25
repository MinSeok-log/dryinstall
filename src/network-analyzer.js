'use strict';

const https = require('https');
const http = require('http');
const net = require('net');
const dns = require('dns');
const { execSync } = require('child_process');
const os = require('os');
const logger = require('./logger');

class NetworkAnalyzer {
  constructor() {
    this.enabled = false;
    this.requests = [];
    this.blocked = [];
    this.allowed = [];
    this.pkgName = null;

    this.safeDomains = [
      'registry.npmjs.org', 'registry.yarnpkg.com', 'npmjs.org', 'npmjs.com',
      'nodejs.org', 'github.com', 'raw.githubusercontent.com',
      'objects.githubusercontent.com', 'cdn.npmjs.com', 'codeload.github.com',
    ];

    this.dangerousPatterns = [
      /attacker/i, /steal/i, /exfil/i, /c2\./i, /\.onion/i,
      /ngrok\.io/i, /burpcollaborator/i, /interact\.sh/i,
      /requestbin/i, /webhook\.site/i, /pipedream\.net/i,
    ];
  }

  start(pkgName) {
    this.pkgName = pkgName;
    this.enabled = true;
    this.requests = [];
    this.blocked = [];
    this.allowed = [];

    logger.verbose(`[dryinstall:network] Monitoring network for: ${pkgName}`);

    this._originalHttpsRequest = https.request;
    this._originalHttpRequest  = http.request;
    this._originalDnsLookup    = dns.lookup;

    const self = this;

    https.request = function(options, callback) {
      const hostname = typeof options === 'string' ? new URL(options).hostname : (options.hostname || options.host || '');
      return self._interceptRequest('https', hostname, options, callback, self._originalHttpsRequest.bind(https));
    };

    http.request = function(options, callback) {
      const hostname = typeof options === 'string' ? new URL(options).hostname : (options.hostname || options.host || '');
      return self._interceptRequest('http', hostname, options, callback, self._originalHttpRequest.bind(http));
    };

    dns.lookup = function(hostname, options, callback) {
      const cb   = typeof options === 'function' ? options : callback;
      const opts = typeof options === 'function' ? {} : options;
      self._recordDns(hostname);
      return self._originalDnsLookup.call(dns, hostname, opts, cb);
    };
  }

  stop() {
    if (!this.enabled) return;
    this.enabled = false;
    if (this._originalHttpsRequest) https.request = this._originalHttpsRequest;
    if (this._originalHttpRequest)  http.request  = this._originalHttpRequest;
    if (this._originalDnsLookup)    dns.lookup     = this._originalDnsLookup;
    logger.verbose(`[dryinstall:network] Monitoring stopped: ${this.pkgName}`);
  }

  _interceptRequest(protocol, hostname, options, callback, original) {
    const record = { pkg: this.pkgName, protocol, hostname, time: new Date().toISOString() };
    this.requests.push(record);

    const isSafe      = this.safeDomains.some(d => hostname === d || hostname.endsWith('.' + d));
    const isDangerous = this.dangerousPatterns.some(p => p.test(hostname));

    if (isDangerous) {
      logger.block(`[dryinstall:network] DANGEROUS: "${this.pkgName}" → ${protocol}://${hostname}`);
      this.blocked.push({ ...record, reason: 'dangerous_pattern' });
      return this._fakeRequest();
    }

    if (!isSafe) {
      logger.warn(`[dryinstall:network] SUSPICIOUS: "${this.pkgName}" → ${protocol}://${hostname}`);
      this.blocked.push({ ...record, reason: 'unknown_domain' });
      return this._fakeRequest();
    }

    logger.verbose(`[dryinstall:network] ALLOWED: ${protocol}://${hostname}`);
    this.allowed.push(record);
    return original(options, callback);
  }

  _recordDns(hostname) {
    const isSafe = this.safeDomains.some(d => hostname === d || hostname.endsWith('.' + d));
    if (!isSafe) logger.verbose(`[dryinstall:network] DNS lookup: "${this.pkgName}" → ${hostname}`);
  }

  _fakeRequest() {
    const { Writable } = require('stream');
    const fake = new Writable({ write(chunk, encoding, callback) { callback(); } });
    fake.end = () => fake;
    fake.on = (event, cb) => fake;
    fake.setTimeout = () => fake;
    fake.destroy = () => fake;
    return fake;
  }

  snapshot() {
    logger.verbose(`[dryinstall:monitor] Taking process snapshot...`);
  }

  report() {
    // 차단된 요청 있을 때만 출력 (항상 출력 제거)
    if (this.blocked.length > 0) {
      logger.block(`[dryinstall:network] ${this.blocked.length} request(s) blocked for: ${this.pkgName}`);
      this.blocked.forEach((b, i) => {
        logger.block(`  [${i+1}] ${b.protocol}://${b.hostname} — ${b.reason}`);
      });
    }
    logger.verbose(`[dryinstall:network] Network summary: total=${this.requests.length} allowed=${this.allowed.length} blocked=${this.blocked.length}`);

    return {
      total: this.requests.length,
      allowed: this.allowed.length,
      blocked: this.blocked.length,
      isSuspicious: this.blocked.length > 0,
    };
  }
}

module.exports = new NetworkAnalyzer();