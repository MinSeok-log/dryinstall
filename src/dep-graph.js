'use strict';

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * DepGraph
 * npm ls --json으로 dependency tree 분석
 * 위험 패키지가 어떤 체인을 통해 들어왔는지 추적
 */
class DepGraph {
  constructor(cwd = process.cwd()) {
    this.cwd = cwd;
    this.graph = null;
    this.dangerousPkgs = new Set();
  }

  /**
   * npm ls --json으로 전체 dependency tree 가져오기
   */
  async build() {
    console.log('\x1b[36m[dryinstall:depgraph] Building dependency graph...\x1b[0m');
    try {
      const output = execSync('npm ls --json --all 2>/dev/null', {
        cwd: this.cwd, timeout: 15000, encoding: 'utf-8'
      });
      this.graph = JSON.parse(output);
      console.log('\x1b[32m[dryinstall:depgraph] Graph built successfully\x1b[0m');
    } catch (e) {
      // npm ls 실패 시 package-lock.json fallback
      console.log('\x1b[33m[dryinstall:depgraph] npm ls failed, falling back to package-lock.json\x1b[0m');
      this.graph = this._buildFromLockfile();
    }
    return this.graph;
  }

  /**
   * package-lock.json에서 graph 구성 (fallback)
   */
  _buildFromLockfile() {
    const lockPath = path.join(this.cwd, 'package-lock.json');
    if (!fs.existsSync(lockPath)) return null;

    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));
      const packages = lock.packages || {};
      const graph = { name: lock.name, version: lock.version, dependencies: {} };

      for (const [pkgPath, info] of Object.entries(packages)) {
        if (!pkgPath) continue;
        const name = pkgPath.replace(/^node_modules\//, '').split('/node_modules/').pop();
        graph.dependencies[name] = {
          version: info.version,
          resolved: info.resolved,
          dependencies: info.dependencies || {},
        };
      }
      return graph;
    } catch {
      return null;
    }
  }

  /**
   * 위험 패키지 등록 (scanner에서 호출)
   */
  markDangerous(pkgName) {
    this.dangerousPkgs.add(pkgName);
  }

  /**
   * 위험 패키지로 가는 모든 체인 추적
   * 예: A → B → malicious-pkg
   */
  findChains(targetPkg) {
    if (!this.graph) return [];
    const chains = [];
    this._dfs(this.graph.dependencies || {}, targetPkg, [], chains);
    return chains;
  }

  _dfs(deps, target, currentChain, chains) {
    for (const [name, info] of Object.entries(deps || {})) {
      const chain = [...currentChain, name];
      if (name === target) {
        chains.push(chain);
        continue;
      }
      if (info?.dependencies) {
        this._dfs(info.dependencies, target, chain, chains);
      }
    }
  }

  /**
   * 전체 위험 패키지 체인 리포트 출력
   */
  async report(dangerousList = []) {
    if (!this.graph) await this.build();

    dangerousList.forEach(p => this.markDangerous(p));

    if (this.dangerousPkgs.size === 0) {
      console.log('\x1b[32m[dryinstall:depgraph] No dangerous packages in graph\x1b[0m');
      return;
    }

    const line = '═'.repeat(52);
    console.log(`\n\x1b[36m${line}\x1b[0m`);
    console.log(`\x1b[1m\x1b[36m  Dependency Graph — Risk Chain Analysis\x1b[0m`);
    console.log(`\x1b[36m${line}\x1b[0m`);

    for (const pkg of this.dangerousPkgs) {
      const chains = this.findChains(pkg);
      console.log(`\n\x1b[31m  ✗ ${pkg}\x1b[0m`);

      if (chains.length === 0) {
        console.log(`    → Direct dependency (in package.json)`);
      } else {
        console.log(`    Attack chains (${chains.length}):`);
        chains.slice(0, 5).forEach(chain => {
          console.log(`    \x1b[33m  ${chain.join(' → ')}\x1b[0m`);
        });
        if (chains.length > 5) {
          console.log(`    \x1b[33m  ... and ${chains.length - 5} more chains\x1b[0m`);
        }
      }
    }

    console.log(`\x1b[36m\n${line}\x1b[0m\n`);
  }

  /**
   * 전체 그래프 통계
   */
  stats() {
    if (!this.graph) return null;
    const allPkgs = new Set();
    const countPkgs = (deps) => {
      for (const [name, info] of Object.entries(deps || {})) {
        allPkgs.add(name);
        if (info?.dependencies) countPkgs(info.dependencies);
      }
    };
    countPkgs(this.graph.dependencies || {});
    return {
      total: allPkgs.size,
      dangerous: this.dangerousPkgs.size,
      safe: allPkgs.size - this.dangerousPkgs.size,
    };
  }
}

module.exports = DepGraph;
