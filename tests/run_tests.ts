// tests/run_tests.ts
//
// Compatibility test harness for the PyGuard obfuscator.
//
// For each .py file in tests/cases/:
//   1. Compile it to v5 IR via lib/v5/build_ir.py.
//   2. Obfuscate it through the v5 path.
//   3. Write the obfuscated source to tests/out_v5/<name>.py.
//   3. Execute the original with python3, capture stdout/stderr/exit.
//   4. Execute the obfuscated stub with python3, capture the same.
//   5. Compare. PASS if outputs and exit codes match exactly.
//
// Run with: ./node_modules/.bin/sucrase-node tests/run_tests.ts

import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";
import { execFileSync } from "child_process";
import { obfuscatePythonCode } from "../lib/obfuscate";
import { makeV5Schema } from "../lib/v5/schema";
import { INTERPRETER_SRC_B64 } from "../lib/v5/interpreter_src";
import type { V5IR } from "../lib/v5/assemble";
import { createCompileAndPackCode, discoverPythons } from "../scripts/multi_marshal.mjs";

const ROOT = path.resolve(__dirname, "..");
const CASES_DIR = path.join(ROOT, "tests", "cases");
const OUT_DIR = path.join(ROOT, "tests", "out_v5");

interface RunResult {
    stdout: string;
    stderr: string;
    code: number;
}

function runPython(pyBin: string, file: string, timeoutMs = 15000): RunResult {
    try {
        const stdout = execFileSync(pyBin, [file], {
            timeout: timeoutMs,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
        });
        return { stdout, stderr: "", code: 0 };
    } catch (err: any) {
        return {
            stdout: err.stdout?.toString() ?? "",
            stderr: err.stderr?.toString() ?? String(err.message ?? err),
            code: typeof err.status === "number" ? err.status : -1,
        };
    }
}

function buildV5IR(source: string, schema: object): V5IR {
    const out = execFileSync(BUILD_PYTHON, [path.join(ROOT, "lib", "v5", "build_ir.py")], {
        input: source,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
        maxBuffer: 32 * 1024 * 1024,
        env: { ...process.env, PYGUARD_V5_SCHEMA: JSON.stringify(schema) },
    }).trim();
    const parsed = JSON.parse(out);
    return {
        compressed: Uint8Array.from(Buffer.from(parsed.compressed, "base64")),
        manifest: Uint8Array.from(Buffer.from(parsed.manifest, "base64")),
        schema: schema as any,
    };
}

interface PyBuild { bin: string; major: number; minor: number; }

const PYTHONS = discoverPythons() as PyBuild[];
if (PYTHONS.length === 0) throw new Error("no Python build toolchains discovered");
const BUILD_PYTHON = PYTHONS[PYTHONS.length - 1].bin;

function lzmaCompress(bytes: Uint8Array): Uint8Array {
    const r = execFileSync(
        BUILD_PYTHON,
        ["-c", "import sys, lzma; sys.stdout.buffer.write(lzma.compress(sys.stdin.buffer.read(), preset=9|lzma.PRESET_EXTREME))"],
        { input: Buffer.from(bytes), maxBuffer: 256 * 1024 * 1024 },
    );
    return Uint8Array.from(r);
}

function prepareInterpreterSource(): string {
    const src = zlib.inflateRawSync(Buffer.from(INTERPRETER_SRC_B64, "base64"));
    return Buffer.from(src).toString("utf8");
}

function assertUnsupportedRuntimeMessage(interpreterSource: string): void {
    if (PYTHONS.length < 2) {
        console.log("SKIP  unsupported-runtime diagnostic (need at least 2 Python builds)");
        return;
    }
    const buildOnly = PYTHONS[0];
    const runWith = PYTHONS[PYTHONS.length - 1];
    if (buildOnly.major === runWith.major && buildOnly.minor === runWith.minor) {
        console.log("SKIP  unsupported-runtime diagnostic (only one Python minor)");
        return;
    }

    const source = "print('should not run')\n";
    const schema = makeV5Schema();
    const compileAndPackCode = createCompileAndPackCode([buildOnly]);
    const obf = obfuscatePythonCode(source, {
        v5IR: buildV5IR(source, schema),
        interpreterSource,
        compileAndPackCode,
        compress: lzmaCompress,
    });
    const outPath = path.join(OUT_DIR, "_unsupported_runtime.py");
    fs.writeFileSync(outPath, obf);
    const actual = runPython(runWith.bin, outPath);
    if (
        actual.code !== 1 ||
        actual.stdout !== "" ||
        !actual.stderr.includes(`unsupported CPython ${runWith.major}.${runWith.minor}`)
    ) {
        throw new Error(
            `unsupported-runtime diagnostic failed: code=${actual.code} stdout=${JSON.stringify(actual.stdout)} stderr=${JSON.stringify(actual.stderr)}`,
        );
    }
    console.log(`PASS  unsupported-runtime diagnostic  built py${buildOnly.major}.${buildOnly.minor} ran py${runWith.major}.${runWith.minor}`);
}

function main() {
    if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

    const interpreterSource = prepareInterpreterSource();
    const compileAndPackCode = createCompileAndPackCode(PYTHONS);

    const cases = fs
        .readdirSync(CASES_DIR)
        .filter((f) => f.endsWith(".py"))
        .sort();

    let pass = 0;
    let fail = 0;
    const failures: string[] = [];

    for (const name of cases) {
        const srcPath = path.join(CASES_DIR, name);
        const src = fs.readFileSync(srcPath, "utf8");
        const schema = makeV5Schema();

        const obf = obfuscatePythonCode(src, {
            v5IR: buildV5IR(src, schema),
            interpreterSource,
            compileAndPackCode,
            compress: lzmaCompress,
        });
        const outPath = path.join(OUT_DIR, name);
        fs.writeFileSync(outPath, obf);

        for (const py of PYTHONS) {
            const pyLabel = `${py.major}.${py.minor}`;
            const expected = runPython(py.bin, srcPath);
            const actual = runPython(py.bin, outPath);

            const ok =
                expected.stdout === actual.stdout &&
                expected.code === actual.code;

            if (ok) {
                pass++;
                console.log(`PASS  ${name}  py${pyLabel}`);
            } else {
                fail++;
                failures.push(`${name}@${pyLabel}`);
                console.log(`FAIL  ${name}  py${pyLabel}`);
                console.log(`  expected.code=${expected.code}  actual.code=${actual.code}`);
                console.log(`  expected.stdout=${JSON.stringify(expected.stdout)}`);
                console.log(`  actual.stdout=${JSON.stringify(actual.stdout)}`);
                if (actual.stderr.trim()) {
                    console.log(`  actual.stderr=${actual.stderr.trim().split("\n").slice(-10).join("\n  ")}`);
                }
            }
        }
    }

    console.log(`\n${pass} passed, ${fail} failed (of ${cases.length} cases × ${PYTHONS.length} Python builds)`);
    if (fail > 0) {
        console.log("failures:", failures.join(", "));
        process.exit(1);
    }

    assertUnsupportedRuntimeMessage(interpreterSource);
}

main();
