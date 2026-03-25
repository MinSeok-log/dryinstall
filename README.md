# dryinstall

![version](https://img.shields.io/badge/version-0.8.0-blue)
![npm](https://img.shields.io/npm/v/dryinstall)
![license](https://img.shields.io/badge/license-MIT-green)
![node](https://img.shields.io/badge/node-%3E%3D16-brightgreen)
![rust](https://img.shields.io/badge/core-Rust-orange?logo=rust)
![security](https://img.shields.io/badge/sandbox-OS%20kernel%20level-red?logo=linux)

> **npm install trusts everyone. dryinstall trusts no one.**

You run `npm install`. Somewhere in that 1,500-package dependency tree, a postinstall script wakes up, calls home, and walks off with your AWS keys.

dryinstall makes sure that never happens.

```
npm install anything
  → package says "hey can I run this real quick?"
  → npm says "sure!"
  → ✗ your SSH keys are on a server in Belarus

dryinstall install anything
  → package says "hey can I run this real quick?"
  → dryinstall says "lol no"
  → ✓ zero code executed. you're fine.
```

**Keywords:** npm security · npm install security · block lifecycle scripts · safe npm install · supply chain attack prevention · npm runtime security · install-time RCE prevention

---

## The Uncomfortable Truth About `npm install`

Most developers think `npm install` just... downloads files.

It doesn't.

It **runs code**. On your machine. Right now. Without asking.

Every package in your dependency tree can include lifecycle scripts that execute automatically:

| Script | When it fires |
|---|---|
| `preinstall` | Before anything starts |
| `install` | Mid-install |
| `postinstall` | The moment install finishes |
| `prepare` | On `git install` |

You didn't consent to this. npm just does it.

**And attackers know this.**

| Package | Year | What happened |
|---|---|---|
| `event-stream` | 2018 | postinstall quietly stole Bitcoin wallet keys. 2M downloads/week. |
| `ua-parser-js` | 2021 | Maintainer account hijacked. Malware shipped overnight. 7M/week. |
| `coa` | 2021 | Same playbook. Different package. 9M/week. |
| `colors` + `faker` | 2022 | Developer rage-sabotaged his own packages. 20M+/week. |
| `xz-utils` | 2024 | Two years of social engineering. One backdoor. Core Linux infrastructure. |
| `cline-cli` | 2026 | postinstall silently dropped a backdoor CLI. Still active. |

---

## Why Your Current Tools Won't Save You

| Tool | What it does | The problem |
|---|---|---|
| `npm audit` / Snyk | Checks against known CVE database | Unknown threats walk right past |
| Socket.dev | Sends you a warning email | Cool email. Code already ran. |
| Docker | Isolates at the OS level | The malicious code still executes. Inside the container. |
| **dryinstall** | **Kills execution before it starts** | **No detection needed if nothing can run** |

The others are smoke detectors.  
dryinstall removes the matches.

---

## Quick Start

```bash
# Install once, protect forever
npm install -g dryinstall

# Drop-in replacement for npm install
dryinstall install <pkg>

# On an existing project
npm init -y
dryinstall setup-loader
```

> Works with any package — `lodash`, `puppeteer`, `express`, whatever.  
> If it's on npm, dryinstall can handle it.

---

## How It Works

Every package goes through 8 checkpoints before a single byte executes.

```
══════════════════════════════════════════════════════
  dryinstall  →  puppeteer@24.39.1
  Level 2  Balanced — malicious only, whitelist fast-pass
══════════════════════════════════════════════════════

──────────────────────────────────────────────────────
  ①~⑦  Running security checks in parallel  ...
──────────────────────────────────────────────────────
  ✓  All 7 checks passed

──────────────────────────────────────────────────────
  ⑧  Lifecycle Script Analysis  ...
──────────────────────────────────────────────────────
  ✓  puppeteer — postinstall: fast-pass  [known safe]
  ✓  glob — prepare: fast-pass  [known safe]
  ✗  evil-pkg — postinstall: BLOCKED  → curl http://...

══════════════════════════════════════════════════════
  ⚠  1 script(s) blocked  /  47 packages scanned
══════════════════════════════════════════════════════
```

**Checkpoint lineup:**

| # | Check | What it catches |
|---|---|---|
| ① | Confusion Detection | Dependency Confusion attacks |
| ② | Hash Verification | Tampered tarballs |
| ③ | Version Diff | Dangerous patterns added between versions |
| ④ | Stealth Detection | CI backdoors, time bombs, base64 eval |
| ⑤ | Maintainer Monitor | Account takeovers |
| ⑥ | CVE Audit | Known vulnerabilities |
| ⑦ | Lifecycle Block | All install-time script execution |
| ⑧ | Sandbox Isolation | vm + Worker Thread + Rust kernel-level |

---

## Features

### The Quarantine Zone (Sandbox)

When a package enters the sandbox, it loses its privileges. All of them.

```
Tries to access the filesystem?   → gone
Tries to open a network socket?   → gone  
Tries to spawn a child process?   → gone
Tries to read process.env?        → gone
Tries to escape the sandbox?      → Worker Thread says hi. also gone.
```

It's not that we're mean. We just don't know you yet.

---

### Trust Cache — Evidence-Based Trust System (new in v0.8.0)

> **"Trust cache is a memory device, not a trust device."**

When a lifecycle script is blocked, dryinstall remembers it. Next time the same package appears — same version, same script content, same environment — it shows you the full context and asks what to do.

```
──────────────────────────────────────────────────────────
  Lifecycle Script Detected
──────────────────────────────────────────────────────────
  Package    : eslint-plugin-n@16.6.0
  Script     : prepack
  Command    : tsc --emitDeclarationOnly
  Context    : linux:local

  Risk analysis:
  ✓  Network access   : none
  ✓  Exec / shell     : none
  ✓  File write       : yes (build artifacts)
  ✓  Dangerous pattern: none

  Confidence : 85/100 — Review recommended
  History    : seen 3x — 0d ago — user_allowed

  [Y/Enter] Allow once   [A] Always allow (this version + script only)
  [N]       Block        [B] Always block   ← Enter default
──────────────────────────────────────────────────────────
  Allow? y/[N]/a/b
```

**Key design decisions:**

| Rule | Why |
|---|---|
| Enter = **No** always | Habit-clicking past prompts is an attack vector |
| Auto-allow = **never** | "Seen 10x" doesn't mean safe — attackers can wait |
| version + script hash locked | New version or changed script → full re-evaluation |
| TTL: 7 days | Stale caches are dangerous |
| Re-verify if published < 24h | Newly published packages get extra scrutiny |
| CI vs local separated | Same script, different environments = different risk |
| Referenced file hashed | `node build.js` changes → `build.js` content hashed too |
| lock file integrity | `package-lock.json` resolved URL + integrity included |

**Confidence Score:**

```
score = hash_match(40) + script_same(20) + deps_same(15)
      + no_network(15) + no_fs_write(10)

90+    Low risk           (but still asks you)
60~89  Review recommended
<60    High risk

SUSPICIOUS scripts always score 0 — no exceptions.
```

Confidence is a hint for your decision. Never a trigger for auto-allow.

---

### Dependency Confusion Detection

Someone registered a public package with the same name as your private one, but with a higher version number. npm will happily install theirs instead of yours.

This is how Microsoft, Apple, and Tesla got hit.

```
┌──────────────────────────────────────────────────────────┐
│   ⚠  Hey. Something's wrong here.                        │
│                                                          │
│  Package : @yourcompany/internal-utils                   │
│  Public  : v9.9.9   ← this appeared out of nowhere      │
│  Yours   : v1.0.0                                        │
│                                                          │
│  npm would have installed the public one. We didn't.     │
└──────────────────────────────────────────────────────────┘
```

---

### Hash Verification

Same version number. Different contents. That's not an update. That's an attack.

```
[CRITICAL] This package has been modified.
  Package  : some-package@2.1.0
  Expected : sha512-abc123...
  Got      : sha512-xyz789...
  
  Same version. Different bytes. We're not installing this.
```

---

### Stealth Backdoor Detection

| What it looks like | What it actually is |
|---|---|
| `if(process.env.CI) { ... }` | Only runs on your build server |
| `setTimeout(evil, 86400000)` | Waits 24 hours before activating |
| `eval(Buffer.from("...", "base64"))` | The code is hidden in base64 |
| `JSON.stringify(process.env)` | Stealing every environment variable you have |
| `fetch("http://169.254.169.254/...")` | Grabbing your cloud credentials |

---

### Maintainer Change Detection

```
┌──────────────────────────────────────────────────────────┐
│  ⚠  This package has new owners.                         │
│                                                          │
│  New maintainer  : someone-you've-never-heard-of         │
│  Previous owners : all removed                           │
│                                                          │
│  This is exactly what happened to ua-parser-js in 2021. │
│  Your call.                                              │
└──────────────────────────────────────────────────────────┘
```

---

### Adaptive ECU — It Gets Smarter

```bash
dryinstall profile
```

```
══════════════════════════════════════════════
  dryinstall Developer Profile
══════════════════════════════════════════════
  Tracking since : 2026-03-11
  Total installs : 47
  Project type   : backend developer

  Most used packages:
    express    12x
    lodash      8x

  Warning behavior:
    lifecycle   ████████░░  80% — you always ignore these
    stealth     ██░░░░░░░░  20% — you actually read these

══════════════════════════════════════════════
  Trust Cache
══════════════════════════════════════════════
  ✓ Allowed (2)
    eslint-plugin-n@16.6.0   prepack  conf:85  seen:3x  exp:6d
    typescript@5.4.0          prepare  conf:90  seen:7x  exp:4d
══════════════════════════════════════════════
```

---

### Execution Tracker

```bash
dryinstall track status
```

```
  Confirmed safe to block:
    ✓ glob       (your app didn't care)
    ✓ rimraf     (your app didn't care)

  Actually needed:
    ! puppeteer  (your app crashed without it, so we allowed it)
```

---

### When Things Go Wrong — It Stays Calm

| What went wrong | What dryinstall does |
|---|---|
| You ran `npm install` directly | Warns you. Doesn't throw a fit. |
| `dry_modules/` got deleted somehow | Falls back to `node_modules`, tells you |
| Config file got corrupted | Resets to defaults, keeps a backup |
| No internet | Checks cache, explains the situation |
| Old Node.js version | Quietly adjusts what it can do |
| Permission error | Tells you exactly how to fix it |

---

## Security Levels

```bash
dryinstall install <pkg> --level=3   # Paranoid  — CI / security teams
dryinstall install <pkg> --level=2   # Balanced  — general developers (default)
dryinstall install <pkg> --level=1   # Relaxed   — fast prototyping
dryinstall install <pkg> --level=0   # Observer  — logs only
```

| Level | Who it's for | What it does |
|---|---|---|
| 3 | CI / security teams | Sequential scan + block all scripts |
| 2 | General developers | Parallel scan + whitelist fast-pass + malicious only |
| 1 | Fast prototyping | Install first, scan after, warn only |
| 0 | Monitoring | Logs everything. Blocks nothing. |

**What "fast-pass" means at Level 2:**  
Known safe build tools (webpack, tsc, puppeteer, rimraf, 54 packages total) skip the scan entirely. Your install doesn't grind to a halt because `glob` has a `prepare` script.

---

## CLI Reference

```bash
# Installing packages
dryinstall install <pkg>                          full 8-layer scan + install
dryinstall install <pkg> --interactive            ask before each blocked script
dryinstall install <pkg> --level=0-3             set security level (default: 2)
dryinstall install <pkg> --allow=fs,net           let it touch specific things
dryinstall install <pkg> --allow-package=name     whitelist a specific package
dryinstall install <pkg> --allow-maintainer-change  live dangerously
dryinstall install <pkg> --watch                  keep watching after install
dryinstall install <pkg> --dry-run                analyze without installing
dryinstall install <pkg> --json                   machine-readable JSON output

# Analysis (no install)
dryinstall check <pkg>                            analyze a package without installing
dryinstall check <pkg1> <pkg2> --json            CI-friendly batch check (exit 1 if blocked)

# Diagnosis & repair
dryinstall doctor                                 diagnose all dependencies
dryinstall fix                                    auto-repair: restore sandboxed + install missing
dryinstall fix <pkg>                             repair a specific package only
dryinstall inspect                                show problem dependencies only
dryinstall inspect --verbose                      show all dependencies

# Managing your project
dryinstall clean-install                          nuke node_modules, start fresh
dryinstall scan                                   scan what's already installed
dryinstall scan --quiet                           CI-friendly minimal output
dryinstall list                                   what's in dry_modules

# Trust Cache
dryinstall trust status                           show trust cache + confidence scores

# The smart stuff
dryinstall profile                                developer profile + trust cache status
dryinstall config suggest                         let it tune itself
dryinstall run <script>                           run with execution tracking
dryinstall track status                           what it's learned so far

# Runtime
dryinstall setup-loader                           hook into npm start/dev/serve
dryinstall remove-loader                          unhook

# Global flags
--quiet, -q       only show blocks and errors
--verbose, -v     show all internal logs
--json            machine-readable output, all logs go to stderr
```

---

## How It Stacks Up

| Tool | Blocks scripts | Pre-install checks | Runtime guard | Typo detect | Confusion | Hash | Stealth | Maintainer | Trust Cache |
|---|---|---|---|---|---|---|---|---|---|
| `npm audit` | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `socket.dev` | ✗ | ✗ | ✗ | △ | △ | ✗ | △ | ✗ | ✗ |
| `LavaMoat` | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| **dryinstall** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** |

---

## Glossary

| Word | What it actually means |
|---|---|
| **Lifecycle script** | Code baked into a package that runs automatically when you `npm install`. You didn't ask for it. It just runs. |
| **Supply chain attack** | Instead of hacking you directly, attackers compromise something you already trust. |
| **Dependency Confusion** | Publish a malicious package with the same name as your company's private one, but higher version. npm picks theirs. |
| **Sandbox** | A walled-off environment where dangerous APIs don't exist. The package thinks it can do things. It cannot. |
| **dry_modules** | Where dryinstall stores packages after install. Not `node_modules`. Nothing in here has ever run. |
| **Typosquatting** | `lodash` vs `lodas`. One character. Someone registered the wrong spelling and put malware in it. |
| **ECU** | Engine Control Unit — how dryinstall adapts to your behavior over time. |
| **Trust Cache** | Evidence-based memory of past lifecycle decisions. A hint for your judgment — not a shortcut around it. |
| **Confidence Score** | 0–100 score based on hash match, script content, deps, network/fs behavior. Never triggers auto-allow. |

---

## Honest Limitations

- **Native addons** (`.node` files): Can't sandbox these at the JS level. Use container isolation for those.
- **Dynamic `import()`**: ES module dynamic imports are hard to intercept fully.
- **False positives**: Some legitimate build tools get blocked too. The scanner knows about 54 of them already. Use `--allow-package` for the rest.
- **Trust Cache is memory, not authority**: A package seen 100 times is not automatically safe. dryinstall always asks. You always decide.
- **Linux only for kernel-level isolation**: seccomp + namespace require Linux. Windows/macOS get Node hook only.

This started as a research project. It works. But for production environments, pair it with container isolation.

---

## The Philosophy

> Detection can fail.  
> A zero-day can slip past any scanner.  
> But if lifecycle scripts can't execute at all — it doesn't matter what they contain.

That's the gap dryinstall fills.

---

## Changelog

| Version | What changed |
|---|---|
| **v0.8.0** | Trust Cache — evidence-based lifecycle decision memory. Confidence Score (0–100). version + script hash + lock file integrity locking. TTL 7d + 24h re-verify for newly published. CI/local context separation. Enter = No always. `dryinstall trust status`. Structured install output UI. Level 2 as default. |
| **v0.7.0** | Rust sandbox engine (`dryinstall-core`) — OS kernel-level isolation via seccomp + namespace. N-API bridge. CLI options `-n -f -e`. |
| **v0.6.0** | `dryinstall doctor`, `dryinstall fix`, `dryinstall inspect`, startup dependency report, logger system, parallel scan, `--quiet`/`--verbose` |
| v0.5.5 | Centralized logger (423 console.log → logger), `--quiet`/`--verbose` added |
| v0.5.2 | Context-aware CI detection (false positive fix) |
| v0.5.0 | `dryinstall check`, `--json`, `--dry-run`, GitHub Actions, sandbox refactor |
| v0.4.0 | Execution Tracker, Exception Handler (7 scenarios) |
| v0.3.0 | Adaptive ECU — profiler, advisor, rc-generator |
| v0.2.0 | scanner whitelist (52 packages), detection pattern tuning |
| v0.1.1 | confusion-detector, hash-verifier, stealth-detector, maintainer-monitor |
| v0.1.0 | Initial release — 3-Layer pipeline |

---

## dryinstall-core — Rust Engine

<div align="center">

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=orange)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Security](https://img.shields.io/badge/OS%20Kernel%20Level-Sandbox-red?style=for-the-badge)

</div>

The Node.js layer handles detection.  
The Rust engine handles **execution isolation**.

```
JavaScript sandbox (old)       Rust + OS kernel (new)
─────────────────────────      ──────────────────────────────
require('fs') blocked          openat() syscall → EPERM
require('net') blocked         connect() syscall → EPERM
child_process blocked          execve() syscall → EPERM
process.env filtered           namespace isolation
```

**Why Rust?**

Node.js sandboxes operate at the application layer — they can be bypassed by native addons, `process.binding()`, or crafted prototype chains.

Rust talks directly to the OS kernel via `seccomp` and Linux `namespaces`. There is no bypass. The kernel says no.

```
Attack attempt         JS sandbox         Rust seccomp
──────────────         ──────────         ────────────
network call           blocked*           EPERM (kernel)
read /etc/passwd       blocked*           namespace void
child_process          blocked*           EPERM (kernel)
native addon escape    possible ✗         impossible ✓

* = bypassable via internal Node.js APIs
```

**4-Layer Defense:**

| Layer | Technology | Blocks |
|-------|-----------|--------|
| 1 | Node hook | `child_process` module |
| 2 | seccomp (`-n`) | network syscalls |
| 3 | namespace (`-f`) | filesystem access |
| 4 | env_clear (`-e`) | environment variables |

**Source:** [`dryinstall-core/`](./dryinstall-core/) · [GitHub](https://github.com/MinSeok-log/dryinstall-core)

> Experiment log: [EXPERIMENT.md](https://github.com/MinSeok-log/dryinstall-core/blob/main/EXPERIMENT.md)

## Platform Support

| Platform | Node hook | seccomp | namespace | Status |
|----------|-----------|---------|-----------|--------|
| Linux    | ✓ | ✓ | ✓ | **Full support** |
| macOS    | ✓ | △ | △ | Partial |
| Windows  | ✓ | ✗ | ✗ | Node hook only |

---

## Research

[Cognitive Injection](https://github.com/MinSeok-log/cognitive-injection) — A new npm attack vector targeting AI agents via stdout. Bypasses all static security scanners.

---

## License

MIT