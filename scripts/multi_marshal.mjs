// scripts/multi_marshal.mjs
//
// Shared helper: discover CPython build toolchains on the host and pack
// per-minor marshal blobs into a multi-version PGMV container.
//
// Runtime (outer stub / stage1 / stage2) scans the container for its own
// sys.version_info and silently exits if no entry matches.
//
// Format:
//   b'PGMV' + <1-byte entry count> +
//       N × (major:1 + minor:1 + len:4LE + marshal_bytes)
//
// marshal_bytes is raw `marshal.dumps(compile(source, filename, 'exec'))`
// for that minor. No nested tag. Audit hooks still observe exactly one
// marshal.loads event per stage on the matching entry's bytes only.

import { existsSync, readdirSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BUILD_IR_PATH = path.join(ROOT, 'lib/v5/build_ir.py');

export const DEFAULT_MINORS = ['3.9', '3.10', '3.11', '3.12', '3.13', '3.14'];
const ENTRY_HEADER_LEN = 6;
const COMPILE_TIMEOUT_MS = Number(process.env.PYGUARD_COMPILE_TIMEOUT_MS || 300_000);
const SYNTAX_TIMEOUT_MS = Number(process.env.PYGUARD_SYNTAX_TIMEOUT_MS || 30_000);

function subprocessEnv(extra = {}) {
    const keep = [
        'PATH',
        'HOME',
        'USERPROFILE',
        'LOCALAPPDATA',
        'SYSTEMROOT',
        'SystemRoot',
        'WINDIR',
        'LANG',
        'LC_ALL',
        'LC_CTYPE',
    ];
    const env = {};
    for (const key of keep) {
        if (process.env[key]) env[key] = process.env[key];
    }
    if (!env.PATH) env.PATH = '';
    return { ...env, ...extra };
}

function probeBin(bin) {
    const r = spawnSync(bin, ['-c', 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'], {
        encoding: 'utf-8',
        env: subprocessEnv(),
        timeout: 5_000,
        killSignal: 'SIGKILL',
    });
    if (r.status !== 0) return null;
    const vs = (r.stdout || '').trim();
    const m = vs.match(/^(\d+)\.(\d+)$/);
    if (!m) return null;
    return { bin, major: parseInt(m[1], 10), minor: parseInt(m[2], 10) };
}

function splitPythonBinList(value) {
    if (!value) return [];
    return value
        .split(path.delimiter)
        .map((part) => part.trim())
        .filter(Boolean);
}

function pathCandidates() {
    const out = [];
    const pathValue = process.env.PATH || '';
    for (const dir of pathValue.split(path.delimiter).filter(Boolean)) {
        try {
            for (const name of readdirSync(dir)) {
                if (/^python(?:3(?:\.\d+)?)?(?:\.exe)?$/i.test(name)) {
                    out.push(path.join(dir, name));
                }
            }
        } catch {
            // Ignore unreadable PATH entries.
        }
    }
    return out;
}

function realKey(bin, info) {
    try {
        if (existsSync(bin)) return realpathSync(bin);
    } catch {
        // Fall back to the version key below.
    }
    return `${info.major}.${info.minor}`;
}

export function discoverPythons() {
    const envList = process.env.PYGUARD_PYTHON_BINS;
    const seen = new Map();
    const seenReal = new Set();
    const add = (bin) => {
        if (!bin) return;
        const info = probeBin(bin);
        if (!info) return;
        const key = `${info.major}.${info.minor}`;
        const rk = realKey(bin, info);
        if (seenReal.has(rk)) return;
        seenReal.add(rk);
        if (!seen.has(key)) seen.set(key, info);
    };
    if (envList) {
        for (const b of splitPythonBinList(envList)) add(b);
    } else {
        const candidates = [];
        for (const v of DEFAULT_MINORS) {
            candidates.push(
                `/opt/homebrew/opt/python@${v}/bin/python${v}`,
                `/opt/homebrew/bin/python${v}`,
                `/usr/local/opt/python@${v}/bin/python${v}`,
                `/usr/local/bin/python${v}`,
                `/usr/bin/python${v}`,
                `${process.env.HOME || ''}/.local/bin/python${v}`,
                `${process.env.HOME || ''}/.pyenv/shims/python${v}`,
                `${process.env.HOME || ''}/.asdf/shims/python${v}`,
                `python${v}`,
                `python${v}.exe`,
            );
        }
        candidates.push(
            process.env.PYTHON || '',
            process.env.PYTHON3 || '',
            'python3',
            'python',
            'python3.exe',
            'python.exe',
            ...pathCandidates(),
        );
        for (const c of candidates) add(c);
    }
    return Array.from(seen.values()).sort((a, b) => {
        if (a.major !== b.major) return a.major - b.major;
        return a.minor - b.minor;
    });
}

export function targetMinors() {
    const raw = process.env.PYGUARD_TARGET_MINORS;
    if (!raw) return DEFAULT_MINORS.slice();
    const out = [];
    const seen = new Set();
    const add = (major, minor) => {
        if (major !== 3 || minor < 0 || minor > 255) {
            throw new Error(`invalid PYGUARD_TARGET_MINORS entry: ${major}.${minor}`);
        }
        const key = `${major}.${minor}`;
        if (!seen.has(key)) {
            seen.add(key);
            out.push(key);
        }
    };
    for (const partRaw of raw.split(',')) {
        const part = partRaw.trim();
        if (!part) continue;
        const range = part.match(/^(\d+)\.(\d+)\s*-\s*(\d+)\.(\d+)$/);
        if (range) {
            const aMaj = Number(range[1]);
            const aMin = Number(range[2]);
            const bMaj = Number(range[3]);
            const bMin = Number(range[4]);
            if (aMaj !== bMaj || aMaj !== 3 || bMin < aMin) {
                throw new Error(`invalid PYGUARD_TARGET_MINORS range: ${part}`);
            }
            for (let minor = aMin; minor <= bMin; minor++) add(aMaj, minor);
            continue;
        }
        const one = part.match(/^(\d+)\.(\d+)$/);
        if (!one) {
            throw new Error(`invalid PYGUARD_TARGET_MINORS entry: ${part}`);
        }
        add(Number(one[1]), Number(one[2]));
    }
    if (out.length === 0) {
        throw new Error('PYGUARD_TARGET_MINORS did not name any target versions');
    }
    return out;
}

export function assertPythonTargetCoverage(pythons, targets = targetMinors()) {
    const found = new Set(
        (pythons || []).map((p) => `${p.major}.${p.minor}`),
    );
    const missing = targets.filter((v) => !found.has(v));
    if (missing.length > 0) {
        throw new Error(
            'missing target CPython toolchains: ' + missing.join(', ') +
            '. Install these versions, set PYGUARD_PYTHON_BINS, or narrow ' +
            'PYGUARD_TARGET_MINORS intentionally.',
        );
    }
}

export function selectTargetPythons(pythons, targets = targetMinors()) {
    assertPythonTargetCoverage(pythons, targets);
    const targetSet = new Set(targets);
    return (pythons || [])
        .filter((p) => targetSet.has(`${p.major}.${p.minor}`))
        .sort((a, b) => {
            if (a.major !== b.major) return a.major - b.major;
            return a.minor - b.minor;
        });
}

function lastMeaningfulStderrLine(stderr) {
    const lines = String(stderr || '')
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
    return lines[lines.length - 1] || 'syntax check failed';
}

export function assertSourceSyntaxCoverage(pythons, source, filename = '<pg>') {
    if (typeof source !== 'string') {
        throw new Error('source syntax coverage check requires a string source');
    }
    const snippet = [
        'import ast, sys',
        'ast.parse(sys.stdin.read(), filename=sys.argv[1], mode="exec")',
    ].join('\n');
    for (const py of pythons || []) {
        const r = spawnSync(py.bin, ['-c', snippet, filename], {
            input: source,
            encoding: 'utf-8',
            env: subprocessEnv(),
            timeout: SYNTAX_TIMEOUT_MS,
            killSignal: 'SIGKILL',
        });
        const label = `${py.major}.${py.minor}`;
        if (r.error && r.error.code === 'ETIMEDOUT') {
            throw new Error(`source syntax check timed out on CPython ${label}`);
        }
        if (r.status !== 0) {
            throw new Error(
                `source is not syntax-compatible with target CPython ${label}: ` +
                lastMeaningfulStderrLine(r.stderr),
            );
        }
    }
}

function compileWithModeOne(pythonBin, source, filename, mode, tagMagic) {
    const r = spawnSync(pythonBin, [BUILD_IR_PATH], {
        input: source,
        encoding: 'utf-8',
        env: subprocessEnv({
            PYGUARD_MODE: mode,
            PYGUARD_FILENAME: filename || '<pg>',
        }),
        maxBuffer: 64 * 1024 * 1024,
        timeout: COMPILE_TIMEOUT_MS,
        killSignal: 'SIGKILL',
    });
    if (r.error && r.error.code === 'ETIMEDOUT') {
        throw new Error(
            `compile_with_mode subprocess (${pythonBin}, ${mode}, ${filename || '<pg>'}) timed out after ${COMPILE_TIMEOUT_MS}ms`,
        );
    }
    if (r.status !== 0) {
        throw new Error('compile_with_mode subprocess (' + pythonBin + ') failed: ' + r.stderr);
    }
    const buf = Buffer.from(r.stdout.trim(), 'base64');
    const tag = Buffer.from(tagMagic, 'ascii');
    if (buf.length < 6 ||
        buf[0] !== tag[0] ||
        buf[1] !== tag[1] ||
        buf[2] !== tag[2] ||
        buf[3] !== tag[3]) {
        throw new Error('compile_with_mode: missing ' + tagMagic + ' tag from ' + pythonBin);
    }
    return { major: buf[4], minor: buf[5], bytes: Uint8Array.from(buf.subarray(6)) };
}

function compileAndMarshalOne(pythonBin, source, filename) {
    return compileWithModeOne(pythonBin, source, filename, 'marshal', 'PGM1');
}

function compileAndPackCodeOne(pythonBin, source, filename) {
    return compileWithModeOne(pythonBin, source, filename, 'codepack', 'PGC1');
}

function packVersioned(entries, magic) {
    if (entries.length === 0 || entries.length > 255) {
        throw new Error('packVersioned: invalid entry count ' + entries.length);
    }
    let total = 5;
    for (const e of entries) total += ENTRY_HEADER_LEN + e.bytes.length;
    const out = new Uint8Array(total);
    const tag = Buffer.from(magic, 'ascii');
    out[0] = tag[0];
    out[1] = tag[1];
    out[2] = tag[2];
    out[3] = tag[3];
    out[4] = entries.length;
    let off = 5;
    for (const e of entries) {
        out[off] = e.major & 0xff;
        out[off + 1] = e.minor & 0xff;
        const L = e.bytes.length;
        out[off + 2] = L & 0xff;
        out[off + 3] = (L >>> 8) & 0xff;
        out[off + 4] = (L >>> 16) & 0xff;
        out[off + 5] = (L >>> 24) & 0xff;
        off += 6;
        out.set(e.bytes, off);
        off += e.bytes.length;
    }
    return out;
}

export function packPGMV(entries) {
    return packVersioned(entries, 'PGMV');
}

export function packPGCV(entries) {
    return packVersioned(entries, 'PGCV');
}

// Build a closure that compiles `source` with every targeted Python
// and packs the outputs into PGMV. Reusing one closure across stage1 /
// stage2 / interpreter lets the caller probe Pythons just once.
export function createCompileAndMarshal(pythons) {
    const builds = pythons || selectTargetPythons(discoverPythons());
    if (builds.length === 0) {
        throw new Error('createCompileAndMarshal: no Python toolchains discovered');
    }
    const cache = new Map();
    return (source, filename) => {
        const cacheKey = `${filename || '<pg>'}\0${source}`;
        const cached = cache.get(cacheKey);
        if (cached) return cached;
        const entries = [];
        const seen = new Set();
        for (const b of builds) {
            const entry = compileAndMarshalOne(b.bin, source, filename);
            const key = entry.major + '.' + entry.minor;
            if (seen.has(key)) continue;
            seen.add(key);
            entries.push(entry);
        }
        const packed = packPGMV(entries);
        cache.set(cacheKey, packed);
        return packed;
    };
}

export function createCompileAndPackCode(pythons) {
    const builds = pythons || selectTargetPythons(discoverPythons());
    if (builds.length === 0) {
        throw new Error('createCompileAndPackCode: no Python toolchains discovered');
    }
    const cache = new Map();
    return (source, filename) => {
        const cacheKey = `${filename || '<pg>'}\0${source}`;
        const cached = cache.get(cacheKey);
        if (cached) return cached;
        const entries = [];
        const seen = new Set();
        for (const b of builds) {
            const entry = compileAndPackCodeOne(b.bin, source, filename);
            const key = entry.major + '.' + entry.minor;
            if (seen.has(key)) continue;
            seen.add(key);
            entries.push(entry);
        }
        const packed = packPGCV(entries);
        cache.set(cacheKey, packed);
        return packed;
    };
}
