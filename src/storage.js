'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Mirror Storage
 * dry_modules/에 패키지를 저장하고 무결성 해시를 기록
 * 저장 단계에서 코드 실행 없음
 */
class DryStorage {
  constructor(baseDir = process.cwd()) {
    this.mirrorDir = path.join(baseDir, 'dry_modules');
    this.hashFile = path.join(this.mirrorDir, '.dryinstall-integrity.json');
    this._ensureDir();
  }

  _ensureDir() {
    try {
      if (!fs.existsSync(this.mirrorDir)) {
        fs.mkdirSync(this.mirrorDir, { recursive: true });
      }
    } catch (err) {
      if (err.code === 'EACCES' || err.code === 'EPERM') {
        require('./exception-handler').handlePermissionError(this.mirrorDir, err);
      } else {
        throw err;
      }
    }
  }

  /**
   * 패키지를 dry_modules에 저장
   * @param {string} pkgName
   * @param {string} sourcePath - 압축 해제된 소스 경로
   */
  store(pkgName, sourcePath) {
    const destPath = path.join(this.mirrorDir, pkgName);

    try {
      if (fs.existsSync(destPath)) {
        fs.rmSync(destPath, { recursive: true });
      }
      this._copyDir(sourcePath, destPath);
    } catch (err) {
      if (err.code === 'EACCES' || err.code === 'EPERM') {
        require('./exception-handler').handlePermissionError(destPath, err);
        return null;
      }
      throw err;
    }

    const hash = this._hashDir(destPath);
    this._recordHash(pkgName, hash);

    console.log(`\x1b[36m[dryinstall:storage] Stored: ${pkgName} (hash: ${hash.slice(0, 12)}...)\x1b[0m`);
    return destPath;
  }

  /**
   * 패키지 경로 반환
   */
  resolve(pkgName) {
    const pkgPath = path.join(this.mirrorDir, pkgName);
    if (!fs.existsSync(pkgPath)) return null;

    // 무결성 체크
    const currentHash = this._hashDir(pkgPath);
    const storedHash = this._getStoredHash(pkgName);

    if (storedHash && currentHash !== storedHash) {
      console.error(`\x1b[31m[dryinstall:storage] INTEGRITY VIOLATION: ${pkgName} has been tampered!\x1b[0m`);
      return null;
    }

    return pkgPath;
  }

  /**
   * package.json에서 lifecycle scripts 추출
   */
  getLifecycleScripts(pkgName) {
    const pkgJsonPath = path.join(this.mirrorDir, pkgName, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return {};

    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      return pkg.scripts || {};
    } catch {
      return {};
    }
  }

  /**
   * 디렉토리 재귀 복사
   */
  _copyDir(src, dest) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);
      if (entry.isDirectory()) {
        this._copyDir(srcPath, destPath);
      } else {
        fs.copyFileSync(srcPath, destPath);
      }
    }
  }

  /**
   * 디렉토리 전체 해시 계산
   */
  _hashDir(dirPath) {
    const hash = crypto.createHash('sha256');
    const files = this._getAllFiles(dirPath).sort();
    for (const file of files) {
      hash.update(file);
      hash.update(fs.readFileSync(file));
    }
    return hash.digest('hex');
  }

  _getAllFiles(dir, result = []) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        this._getAllFiles(fullPath, result);
      } else {
        result.push(fullPath);
      }
    }
    return result;
  }

  _recordHash(pkgName, hash) {
    let hashes = {};
    if (fs.existsSync(this.hashFile)) {
      try { hashes = JSON.parse(fs.readFileSync(this.hashFile, 'utf-8')); } catch {}
    }
    hashes[pkgName] = { hash, storedAt: new Date().toISOString() };
    fs.writeFileSync(this.hashFile, JSON.stringify(hashes, null, 2));
  }

  _getStoredHash(pkgName) {
    if (!fs.existsSync(this.hashFile)) return null;
    try {
      const hashes = JSON.parse(fs.readFileSync(this.hashFile, 'utf-8'));
      return hashes[pkgName]?.hash || null;
    } catch { return null; }
  }

  /**
   * 저장된 패키지 목록
   */
  list() {
    if (!fs.existsSync(this.mirrorDir)) return [];
    return fs.readdirSync(this.mirrorDir).filter(f => !f.startsWith('.'));
  }
}

module.exports = DryStorage;
