'use strict';

const { execSync, spawn } = require('child_process');
const os = require('os');

/**
 * ProcessMonitor
 * 설치 후 백그라운드 프로세스 생성 및 네트워크 아웃바운드 감시
 * 비정상 프로세스 즉시 kill
 */
class ProcessMonitor {
  constructor() {
    this.watching = false;
    this.interval = null;
    this.baseline = new Set(); // 정상 프로세스 목록 (시작 전 스냅샷)
    this.blocked = [];
    this.alerts = [];
    this.monitorInterval = 2000; // 2초마다 체크
  }

  /**
   * 모니터링 시작 전 기준선 스냅샷
   */
  snapshot() {
    console.log('\x1b[36m[dryinstall:monitor] Taking process snapshot...\x1b[0m');
    const pids = this._getProcessList();
    pids.forEach(p => this.baseline.add(p.pid));
    console.log(`\x1b[36m[dryinstall:monitor] Baseline: ${this.baseline.size} processes\x1b[0m`);
  }

  /**
   * 모니터링 시작
   */
  start() {
    if (this.watching) return;
    this.watching = true;
    console.log('\x1b[36m[dryinstall:monitor] Process monitoring started\x1b[0m');

    this.interval = setInterval(() => {
      this._checkNewProcesses();
      this._checkNetworkConnections();
    }, this.monitorInterval);

    // 프로세스 종료 시 자동 정리
    process.on('exit', () => this.stop());
    process.on('SIGINT', () => { this.stop(); process.exit(0); });
  }

  /**
   * 모니터링 중지
   */
  stop() {
    if (!this.watching) return;
    this.watching = false;
    clearInterval(this.interval);
    console.log('\x1b[36m[dryinstall:monitor] Process monitoring stopped\x1b[0m');
    this.report();
  }

  /**
   * 새로 생성된 프로세스 감시
   */
  _checkNewProcesses() {
    const current = this._getProcessList();

    for (const proc of current) {
      if (!this.baseline.has(proc.pid)) {
        // 새 프로세스 발견
        const isSuspicious = this._isSuspicious(proc);

        if (isSuspicious) {
          console.error(`\x1b[31m[dryinstall:monitor] ⚠ SUSPICIOUS PROCESS: PID ${proc.pid} — ${proc.name} | ${proc.cmd}\x1b[0m`);
          this.alerts.push({
            type: 'process',
            pid: proc.pid,
            name: proc.name,
            cmd: proc.cmd,
            time: new Date().toISOString(),
          });

          // 즉시 kill
          this._killProcess(proc.pid, proc.name);
        } else {
          // 정상 프로세스는 baseline에 추가
          this.baseline.add(proc.pid);
        }
      }
    }
  }

  /**
   * 네트워크 아웃바운드 연결 감시
   */
  _checkNetworkConnections() {
    try {
      const connections = this._getNetworkConnections();
      const suspiciousConnections = connections.filter(c => this._isSuspiciousConnection(c));

      for (const conn of suspiciousConnections) {
        const alreadyAlerted = this.alerts.some(
          a => a.type === 'network' && a.remoteAddr === conn.remoteAddr
        );
        if (!alreadyAlerted) {
          console.error(`\x1b[31m[dryinstall:monitor] ⚠ SUSPICIOUS CONNECTION: ${conn.remoteAddr}:${conn.remotePort} (PID: ${conn.pid})\x1b[0m`);
          this.alerts.push({
            type: 'network',
            remoteAddr: conn.remoteAddr,
            remotePort: conn.remotePort,
            pid: conn.pid,
            time: new Date().toISOString(),
          });
        }
      }
    } catch {}
  }

  /**
   * 프로세스 목록 조회
   */
  _getProcessList() {
    try {
      const platform = os.platform();
      let output = '';

      if (platform === 'win32') {
        output = execSync('tasklist /fo csv /nh', { timeout: 3000 }).toString();
        return output.trim().split('\n').map(line => {
          const parts = line.split('","');
          return {
            name: parts[0]?.replace('"', '') || '',
            pid: parseInt(parts[1]) || 0,
            cmd: parts[0]?.replace('"', '') || '',
          };
        }).filter(p => p.pid > 0);
      } else {
        output = execSync('ps aux', { timeout: 3000 }).toString();
        return output.trim().split('\n').slice(1).map(line => {
          const parts = line.trim().split(/\s+/);
          return {
            name: parts[10] || '',
            pid: parseInt(parts[1]) || 0,
            cmd: parts.slice(10).join(' '),
          };
        }).filter(p => p.pid > 0);
      }
    } catch {
      return [];
    }
  }

  /**
   * 네트워크 연결 조회
   */
  _getNetworkConnections() {
    try {
      const platform = os.platform();
      let output = '';

      if (platform === 'win32') {
        output = execSync('netstat -ano', { timeout: 3000 }).toString();
      } else {
        output = execSync('netstat -tunp 2>/dev/null || ss -tunp', { timeout: 3000 }).toString();
      }

      return output.trim().split('\n')
        .filter(line => line.includes('ESTABLISHED') || line.includes('SYN_SENT'))
        .map(line => {
          const parts = line.trim().split(/\s+/);
          const remoteAddr = parts[2]?.split(':')[0] || '';
          const remotePort = parseInt(parts[2]?.split(':').pop()) || 0;
          const pid = parseInt(parts[parts.length - 1]) || 0;
          return { remoteAddr, remotePort, pid };
        })
        .filter(c => c.remoteAddr && c.remoteAddr !== '0.0.0.0' && c.remoteAddr !== '127.0.0.1');
    } catch {
      return [];
    }
  }

  /**
   * 의심스러운 프로세스 판단
   */
  _isSuspicious(proc) {
    const suspiciousKeywords = [
      'curl', 'wget', 'nc ', 'ncat', 'netcat',
      'python -c', 'bash -i', 'sh -i',
      'attack', 'steal', 'exfil', 'backdoor',
    ];
    const cmd = (proc.cmd || '').toLowerCase();
    return suspiciousKeywords.some(k => cmd.includes(k));
  }

  /**
   * 의심스러운 네트워크 연결 판단
   */
  _isSuspiciousConnection(conn) {
    // 알려진 안전한 포트 제외
    const safePorts = [443, 80, 53, 22, 3000, 8080, 8443];
    if (safePorts.includes(conn.remotePort)) return false;

    // 비표준 포트 (1024 이하 또는 고위험 포트)
    if (conn.remotePort < 1024 && conn.remotePort !== 80 && conn.remotePort !== 443) return true;
    if ([4444, 4445, 1337, 31337].includes(conn.remotePort)) return true; // 흔한 reverse shell 포트

    return false;
  }

  /**
   * 프로세스 강제 종료
   */
  _killProcess(pid, name) {
    try {
      const platform = os.platform();
      if (platform === 'win32') {
        execSync(`taskkill /PID ${pid} /F`, { timeout: 3000 });
      } else {
        execSync(`kill -9 ${pid}`, { timeout: 3000 });
      }
      console.error(`\x1b[31m[dryinstall:monitor] ✗ KILLED: PID ${pid} (${name})\x1b[0m`);
      this.blocked.push({ pid, name, time: new Date().toISOString() });
    } catch {
      console.error(`\x1b[31m[dryinstall:monitor] Failed to kill PID ${pid}\x1b[0m`);
    }
  }

  /**
   * 최종 리포트
   */
  report() {
    if (this.alerts.length === 0) {
      console.log('\x1b[32m[dryinstall:monitor] No suspicious activity detected\x1b[0m');
      return;
    }

    console.log('\n\x1b[31m========== Process Monitor Report ==========\x1b[0m');
    console.log(`\x1b[31mTotal alerts: ${this.alerts.length}\x1b[0m`);

    this.alerts.forEach((a, i) => {
      if (a.type === 'process') {
        console.log(`  [${i + 1}] PROCESS  | PID: ${a.pid} | ${a.name} | ${a.cmd}`);
      } else {
        console.log(`  [${i + 1}] NETWORK  | ${a.remoteAddr}:${a.remotePort} | PID: ${a.pid}`);
      }
    });

    if (this.blocked.length > 0) {
      console.log(`\n\x1b[31m  Killed processes: ${this.blocked.length}\x1b[0m`);
      this.blocked.forEach(b => console.log(`  ✗ PID ${b.pid} (${b.name})`));
    }

    console.log('\x1b[31m============================================\x1b[0m\n');
  }
}

module.exports = new ProcessMonitor();
