# dryinstall

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
dryinstall install <pkg>
         │
         ▼
┌─────────────────────────────────────────┐
│           Checkpoint Lineup             │
│                                         │
│  ① Confusion Check   Is this a fake?   │
│  ② Hash Check        Was it tampered?  │
│  ③ Version Diff      New sketchy code? │
│  ④ Stealth Scan      Hiding something? │
│  ⑤ Maintainer Check  Who owns this now?│
└──────────────────┬──────────────────────┘
                   │
                   ▼
          ┌────────────────┐
          │  CVE Audit     │  Known bad? Out.
          └───────┬────────┘
                  │
                  ▼
          ┌────────────────┐
          │ Lifecycle Block│  Wants to run code? Not today.
          └───────┬────────┘
                  │
                  ▼
          ┌────────────────┐
          │  Quarantine    │  Goes into the sandbox.
          │  Zone 🚫       │  Can't call home.
          │                │  Can't touch your files.
          │                │  Can't spawn a shell.
          │                │  Just... sits there.
          └───────┬────────┘
                  │
                  ▼
            dry_modules/
         (stored. not executed.)
                  │
                  ▼
          ┌────────────────┐
          │  Adaptive ECU  │  Learns your habits.
          │                │  Gets smarter over time.
          └────────────────┘
```

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

### Interactive Mode — You're In Control

Not sure about a package? Let dryinstall ask you.

```bash
dryinstall install <pkg> --interactive
```

```
┌──────────────────────────────────────────────────────────┐
│     [dryinstall] Hey, this package wants to run code.    │
├──────────────────────────────────────────────────────────┤
│  Package : puppeteer                                     │
│  Hook    : postinstall                                   │
│  Command : node install.mjs   ← wants to do this        │
│  Risk    : LOW                                           │
└──────────────────────────────────────────────────────────┘
  [a] Allow once        [A] Always allow  (remembered)
  [b] Block (default)   [B] Always block  (remembered)
  [v] What does it actually do?
  [s] Block everything, I'm paranoid today
```

Risk levels:
- `HIGH` — HTTP calls, `eval`, `sudo`, `rm -rf`. Hard no.
- `MED` — Something's off. Probably fine. Probably.
- `LOW` — Standard build stuff. `tsc`, `npm run build`. Usually fine.

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

Some malicious code is clever. It hides. It waits. It only activates in CI environments, or on specific machines, or after a certain date.

dryinstall knows the tricks.

| What it looks like | What it actually is |
|---|---|
| `if(process.env.CI) { ... }` | Only runs on your build server |
| `setTimeout(evil, 86400000)` | Waits 24 hours before activating |
| `eval(Buffer.from("...", "base64"))` | The code is hidden in base64 |
| `JSON.stringify(process.env)` | Stealing every environment variable you have |
| `fetch("http://169.254.169.254/...")` | Grabbing your cloud credentials |

---

### Maintainer Change Detection

The scariest supply chain attacks don't involve writing malicious code from scratch. They involve taking over an existing trusted package.

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

dryinstall watches how you work. Not in a creepy way. In a "stop bugging you about the same packages" way.

```bash
dryinstall profile
```

```
══════════════════════════════════════════════
  dryinstall knows you pretty well by now
══════════════════════════════════════════════
  Tracking since : 2026-03-11
  Total installs : 47
  You seem to be : a backend developer
  Version style  : you like stable releases

  Packages you install a lot:
    express    12x  (we get it, you like express)
    lodash      8x  (classic)

  Warning behavior:
    lifecycle   ████████░░  80% — you always ignore these
    stealth     ██░░░░░░░░  20% — you actually read these
══════════════════════════════════════════════
```

```bash
dryinstall config suggest
```

```
Based on what we've seen:
  → glob      you've allowed this 5 times. want to just always allow it?
  → rimraf    same deal.

Apply? [Y/n]
```

---

### Execution Tracker — The Antivirus Problem, Solved

Classic antivirus problem: tool blocks something → app breaks → user disables tool → point lost.

dryinstall learns what actually needs to run and what doesn't.

```bash
# Set it up once per project
npm init -y
dryinstall setup-loader

# Then just... use npm like normal
npm start
npm run dev
```

Behind the scenes:
```
npm start
  → dryinstall hooks in silently
  → your app runs normally

App runs fine for 5+ seconds?
  → "okay, that script wasn't needed"
  → blocked forever, no noise

App crashes immediately?
  → "okay, that one actually matters"
  → auto-added to allowlist
  → reinstall and it works
```

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

dryinstall won't crash your workflow. Even if you break things.

| What went wrong | What dryinstall does |
|---|---|
| You ran `npm install` directly | Warns you. Doesn't throw a fit. |
| `dry_modules/` got deleted somehow | Falls back to `node_modules`, tells you |
| Config file got corrupted | Resets to defaults, keeps a backup |
| No internet | Checks cache, explains the situation |
| Old Node.js version | Quietly adjusts what it can do |
| Permission error | Tells you exactly how to fix it |

```
You ran: npm install express

  ⚠  Heads up — this wasn't scanned by dryinstall.
     Consider using: dryinstall install express

  Continuing anyway (unprotected)...
```

No lectures. No force-blocking. Just a heads up.

---

## Security Levels

```bash
dryinstall install <pkg> --level=3   # default — full lockdown
dryinstall install <pkg> --level=2   # balanced — most teams use this  
dryinstall install <pkg> --level=1   # relaxed — vm only
dryinstall install <pkg> --level=0   # observer mode — logs, doesn't block
```

| Level | Vibe | What it does |
|---|---|---|
| 3 | Paranoid | Block everything dangerous + double isolation |
| 2 | Sensible | Block `child_process`. Allow `fs`/`net`. |
| 1 | Chill | vm sandbox only. No Worker Thread. |
| 0 | Just watching | Logs everything. Blocks nothing. |

---

## CLI Reference

```bash
# Installing packages
dryinstall install <pkg>                          full 8-layer scan + install
dryinstall install <pkg> --interactive            ask before each blocked script
dryinstall install <pkg> --level=0-3             set paranoia level
dryinstall install <pkg> --allow=fs,net           let it touch specific things
dryinstall install <pkg> --allow-package=name     whitelist a specific package
dryinstall install <pkg> --allow-maintainer-change  live dangerously
dryinstall install <pkg> --watch                  keep watching after install

# Managing your project
dryinstall clean-install                          nuke node_modules, start fresh
dryinstall scan                                   scan what's already installed
dryinstall list                                   what's in dry_modules

# The smart stuff
dryinstall profile                                see what dryinstall knows about you
dryinstall config suggest                         let it tune itself
dryinstall run <script>                           run with tracking
dryinstall track status                           what it's learned so far

# Runtime
dryinstall setup-loader                           hook into npm start/dev/serve
dryinstall remove-loader                          unhook
```

---

## How It Stacks Up

| Tool | Blocks scripts | Pre-install checks | Runtime guard | Typo detect | Confusion | Hash | Stealth | Maintainer | Learns |
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
| **ECU** | Engine Control Unit — the car analogy for how dryinstall adapts to your behavior over time. |

---

## Honest Limitations

- **Native addons** (`.node` files): Can't sandbox these at the JS level. Use container isolation for those.
- **Dynamic `import()`**: ES module dynamic imports are hard to intercept fully.
- **False positives**: Some legitimate build tools get blocked too. The scanner knows about 52 of them already (webpack, vite, typescript...). Use `--allow-package` for the rest.

This started as a research project. It works. But for production environments, pair it with container isolation.

---

## The Philosophy

> Detection can fail.  
> A zero-day can slip past any scanner.  
> But if lifecycle scripts can't execute at all — it doesn't matter what they contain.

That's the gap dryinstall fills.

---

## License

MIT
