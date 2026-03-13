'use strict';

const path      = require('path');
const fs        = require('fs');
const Installer = require('./installer');
const sandbox   = require('./sandbox');

/**
 * DryCLI (리팩토링됨)
 *
 * 변경사항:
 *   - install() → installer.js 위임
 *   - _download(), _extract(), _parseTar() → downloader.js 분리
 *   - _printSecurityReport() → reporter.js 분리
 *   - cli.js는 명령어 라우팅 + project 관련 기능만 담당
 */
class DryCLI {
  constructor(cwd = process.cwd()) {
    this.cwd       = cwd;
    this.installer = new Installer(cwd);
  }

  // install은 installer.js에 완전 위임
  async install(rawPkgName) {
    return this.installer.install(rawPkgName);
  }

  async cleanInstall() {
    const pkgJsonPath = path.join(this.cwd, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) {
      console.error('\x1b[31m[dryinstall] package.json not found\x1b[0m');
      return;
    }

    const pkg  = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });

    if (deps.length === 0) {
      console.log('\x1b[33m[dryinstall] No dependencies found\x1b[0m');
      return;
    }

    console.log(`\x1b[36m[dryinstall] clean-install — ${deps.length} packages\x1b[0m`);

    const nodeModulesPath = path.join(this.cwd, 'node_modules');
    if (fs.existsSync(nodeModulesPath)) {
      console.log('\x1b[36m[dryinstall] Removing node_modules/...\x1b[0m');
      fs.rmSync(nodeModulesPath, { recursive: true, force: true });
    }

    const results = { success: [], failed: [], blocked: [] };
    for (const dep of deps) {
      try {
        const result = await this.install(dep);
        if (result) results.success.push(dep);
        else        results.blocked.push(dep);
      } catch {
        results.failed.push(dep);
      }
    }

    console.log(`\n\x1b[36m[dryinstall] clean-install done\x1b[0m`);
    console.log(`  ✓ Success : \x1b[32m${results.success.length}\x1b[0m`);
    console.log(`  ✗ Blocked : \x1b[31m${results.blocked.length}\x1b[0m`);
    console.log(`  ! Failed  : \x1b[33m${results.failed.length}\x1b[0m`);
  }

  list() {
    const DryStorage = require('./storage');
    const storage = new DryStorage(this.cwd);
    const pkgs    = storage.list();
    if (pkgs.length === 0) { console.log('[dryinstall] No packages installed'); return; }
    console.log('\n[dryinstall] Installed packages:');
    pkgs.forEach(p => console.log(`  - ${p}`));
    console.log();
  }

  setupLoader() {
    const pkgJsonPath = path.join(this.cwd, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) {
      console.error('\x1b[31m[dryinstall] package.json not found\n  Run: npm init -y\x1b[0m');
      return;
    }

    const pkg    = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    if (!pkg.scripts) pkg.scripts = {};

    const loaderFlag  = '-r ./node_modules/dryinstall/src/loader.js';
    const trackerCmd  = 'node ./node_modules/dryinstall/src/exec-hook.js';
    const TARGET      = ['start', 'dev', 'serve', 'preview'];
    let   modified    = false;

    for (const name of TARGET) {
      const orig = pkg.scripts[name];
      if (!orig) continue;
      if (orig.includes('dryinstall') || orig.includes('loader.js')) continue;

      pkg.scripts[`_${name}_original`] = orig;
      pkg.scripts[name] = orig.startsWith('node ')
        ? orig.replace(/^node /, `node ${loaderFlag} `)
        : `${trackerCmd} ${name} && ${orig}`;

      console.log(`\x1b[32m[dryinstall] ✓ ${name}\x1b[0m`);
      console.log(`\x1b[90m    before: ${orig}\x1b[0m`);
      console.log(`\x1b[90m    after : ${pkg.scripts[name]}\x1b[0m`);
      modified = true;
    }

    if (!modified) {
      console.log('\x1b[33m[dryinstall] loader already registered\x1b[0m');
      return;
    }

    fs.writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2));
    console.log('\n\x1b[36m[dryinstall] ✓ setup complete\x1b[0m');
  }

  removeLoader() {
    const pkgJsonPath = path.join(this.cwd, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return;

    const pkg  = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    if (!pkg.scripts) return;

    const TARGET = ['start', 'dev', 'serve', 'preview'];
    let restored = false;

    for (const name of TARGET) {
      const backup = `_${name}_original`;
      if (pkg.scripts[backup]) {
        pkg.scripts[name] = pkg.scripts[backup];
        delete pkg.scripts[backup];
        console.log(`\x1b[32m[dryinstall] ✓ ${name} restored\x1b[0m`);
        restored = true;
      }
    }

    if (restored) fs.writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2));
    else          console.log('\x1b[33m[dryinstall] Nothing to restore\x1b[0m');
  }
}

module.exports = DryCLI;