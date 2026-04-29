'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const PRIMARY_TRACE_DIR = path.join(os.homedir(), '.dryinstall', 'events');
const FALLBACK_TRACE_DIR = path.join(process.cwd(), '.dryinstall', 'events');

function ensureDir() {
  for (const dir of [PRIMARY_TRACE_DIR, FALLBACK_TRACE_DIR]) {
    try {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      return dir;
    } catch {}
  }
  return null;
}

function safePart(value) {
  return String(value || 'unknown')
    .replace(/^@/, '')
    .replace(/[\/\\:@\s]+/g, '-')
    .replace(/[^a-zA-Z0-9._-]/g, '')
    .slice(0, 48) || 'unknown';
}

function timestampId() {
  return new Date().toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}Z$/, 'Z');
}

function record(event) {
  const dir = ensureDir();
  if (!dir) return { id: null, file: null, trace: null };
  const id = `${timestampId()}-${safePart(event.package || event.pkg)}`;
  const trace = {
    id,
    timestamp: new Date().toISOString(),
    cwd: process.cwd(),
    ...event,
  };
  const file = path.join(dir, `${id}.json`);
  try {
    fs.writeFileSync(file, JSON.stringify(trace, null, 2));
    return { id, file, trace };
  } catch {
    return { id: null, file: null, trace: null };
  }
}

function list(limit = 20) {
  const dirs = [PRIMARY_TRACE_DIR, FALLBACK_TRACE_DIR].filter(fs.existsSync);
  return dirs.flatMap(dir => fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .map(file => {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);
      return { id: file.replace(/\.json$/, ''), file: fullPath, mtimeMs: stat.mtimeMs };
    }))
    .sort((a, b) => b.mtimeMs - a.mtimeMs)
    .slice(0, limit);
}

function read(idOrLatest = 'latest') {
  const target = idOrLatest === 'latest'
    ? list(1)[0]
    : list(1000).find(t => t.id === idOrLatest || t.id.startsWith(idOrLatest));
  if (!target) return null;
  return JSON.parse(fs.readFileSync(target.file, 'utf-8'));
}

function print(trace) {
  if (!trace) {
    console.log('\n  No dryinstall trace found.\n');
    return;
  }

  console.log('');
  console.log('dryinstall trace');
  console.log('='.repeat(56));
  console.log(`id       : ${trace.id}`);
  console.log(`time     : ${trace.timestamp}`);
  console.log(`package  : ${trace.package || trace.pkg}@${trace.version || '?'}`);
  console.log(`level    : ${trace.level}`);
  console.log(`decision : ${trace.decision}`);
  if (trace.reason) console.log(`reason   : ${trace.reason}`);
  if (trace.hook) console.log(`hook     : ${trace.hook}`);
  if (trace.command) console.log(`command  : ${trace.command}`);
  if (trace.riskScore !== undefined) console.log(`risk     : ${trace.riskScore}/100`);
  if (Array.isArray(trace.reasons) && trace.reasons.length) {
    console.log('signals  :');
    trace.reasons.forEach(r => console.log(`  - ${r}`));
  }
  if (Array.isArray(trace.blocked) && trace.blocked.length) {
    console.log('blocked  :');
    trace.blocked.forEach(b => {
      console.log(`  - ${b.pkg}${b.hook ? ` ${b.hook}` : ''}${b.risk ? ` risk=${b.risk}` : ''}`);
      if (Array.isArray(b.signals)) b.signals.forEach(s => console.log(`    signal: ${s}`));
      if (b.cmd) console.log(`    cmd: ${b.cmd}`);
    });
  }
  if (Array.isArray(trace.warnings) && trace.warnings.length) {
    console.log('warnings :');
    trace.warnings.forEach(w => {
      console.log(`  - ${w.pkg}${w.hook ? ` ${w.hook}` : ''}${w.risk ? ` risk=${w.risk}` : ''}`);
      if (Array.isArray(w.signals)) w.signals.forEach(s => console.log(`    signal: ${s}`));
      if (w.cmd) console.log(`    cmd: ${w.cmd}`);
    });
  }
  console.log(`cwd      : ${trace.cwd}`);
  console.log('='.repeat(56));
  console.log('');
}

function printHint(trace) {
  if (trace?.id) console.log(`  trace: dryinstall trace ${trace.id}`);
}

module.exports = {
  TRACE_DIR: PRIMARY_TRACE_DIR,
  PRIMARY_TRACE_DIR,
  FALLBACK_TRACE_DIR,
  record,
  list,
  read,
  print,
  printHint,
};
