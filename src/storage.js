'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const logger = require('./logger');

class DryStorage {
  constructor(baseDir = process.cwd()) {
    this.mirrorDir = path.join(baseDir, 'dry_modules');
    this.hashFile  = path.join(this.mirrorDir, '.dryinstall-integrity.json');
    this._ensureDir();
  }

  _ensureDir() {
    try {
      if (!fs.existsSync(this.mirrorDir)) fs.mkdirSync(this.mirrorDir, { recursive: true });
    } catch (err) {
      if (err.code === 'EACCES' || err.code === 'EPERM') {
        require('./exception-handler').handlePermissionError(this.mirrorDir, err);
      } else throw err;
    }
  }

  store(pkgName, sourcePath) {
    const destPath = path.join(this.mirrorDir, pkgName);
    try {
      if (fs.existsSync(destPath)) fs.rmSync(destPath, { recursive: true });
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
    logger.verbose(`[dryinstall:storage] Stored: ${pkgName} (hash: ${hash.slice(0, 12)}...)`);
    return destPath;
  }

  resolve(pkgName) {
    const pkgPath = path.join(this.mirrorDir, pkgName);
    if (!fs.existsSync(pkgPath)) return null;

    const currentHash = this._hashDir(pkgPath);
    const storedHash  = this._getStoredHash(pkgName);

    if (storedHash && currentHash !== storedHash) {
      logger.block(`[dryinstall:storage] INTEGRITY VIOLATION: ${pkgName} has been tampered!`);
      return null;
    }
    return pkgPath;
  }

  getLifecycleScripts(pkgName) {
    const pkgJsonPath = path.join(this.mirrorDir, pkgName, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return {};
    try { return JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8')).scripts || {}; }
    catch { return {}; }
  }

  _copyDir(src, dest) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
      const srcPath  = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);
      if (entry.isDirectory()) this._copyDir(srcPath, destPath);
      else fs.copyFileSync(srcPath, destPath);
    }
  }

  _hashDir(dirPath) {
    const hash  = crypto.createHash('sha256');
    const files = this._getAllFiles(dirPath).sort();
    for (const file of files) { hash.update(file); hash.update(fs.readFileSync(file)); }
    return hash.digest('hex');
  }

  _getAllFiles(dir, result = []) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) this._getAllFiles(fullPath, result);
      else result.push(fullPath);
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
    try { return JSON.parse(fs.readFileSync(this.hashFile, 'utf-8'))[pkgName]?.hash || null; }
    catch { return null; }
  }

  list() {
    if (!fs.existsSync(this.mirrorDir)) return [];
    return fs.readdirSync(this.mirrorDir).filter(f => !f.startsWith('.'));
  }
}

module.exports = DryStorage;