import { NextRequest, NextResponse } from "next/server";
import { spawnSync } from "node:child_process";
import zlib from "node:zlib";
import path from "node:path";
import { obfuscatePythonCode } from "@/lib/obfuscate";
import { makeV5Schema } from "@/lib/v5/schema";
import { INTERPRETER_SRC_B64 } from "@/lib/v5/interpreter_src";
import { createCompileAndPackCode, discoverPythons } from "@/scripts/multi_marshal.mjs";
import { createRateLimiter, clientIp } from "@/lib/rateLimit";

// ---------------------------------------------------------------------------
// Route config
// ---------------------------------------------------------------------------

export const runtime = "nodejs";
export const maxDuration = 180;

/** Refuse pathologically large inputs upfront (both to avoid DoS and because
 *  the obfuscator's own complexity becomes quadratic above this). */
const MAX_SOURCE_BYTES = 1_000_000;

/** Per-subprocess wall-clock caps. Route's maxDuration (60 s) bounds the whole
 *  handler; these bound individual spawns so a single hung Python doesn't
 *  consume the entire budget and starve the response path. */
const BUILD_IR_TIMEOUT_MS = 45_000;
const LZMA_TIMEOUT_MS = 20_000;

const BUILD_IR_PATH = path.join(process.cwd(), "lib/v5/build_ir.py");

const LZMA_COMPRESS_SNIPPET = [
    "import sys, lzma",
    "sys.stdout.buffer.write(",
    "    lzma.compress(sys.stdin.buffer.read(),",
    "                  preset=9 | lzma.PRESET_EXTREME))",
].join("\n");

/** Per-IP rate limit. One obfuscation is 1–30 s of CPU work, so this is
 *  primarily DoS defense, not abuse-pricing. Override via env without redeploy. */
const RATE_LIMIT_CAPACITY = Number(process.env.PYGUARD_RL_CAPACITY ?? 10);
const RATE_LIMIT_WINDOW_MS = Number(process.env.PYGUARD_RL_WINDOW_MS ?? 60_000);

const rateLimit = createRateLimiter({
    capacity: RATE_LIMIT_CAPACITY,
    windowMs: RATE_LIMIT_WINDOW_MS,
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type PyInfo = { bin: string; major: number; minor: number };
type ErrorKind = "syntax" | "python" | "internal" | "rate_limit";

function jsonError(
    status: number,
    message: string,
    kind: ErrorKind = "internal",
    extraHeaders?: Record<string, string>,
) {
    return NextResponse.json(
        { error: message, kind },
        { status, headers: extraHeaders },
    );
}

/** Minimal env for Python subprocesses: PATH to locate shared libs and
 *  the explicit PYGUARD_* knobs the build script reads. Anything else in
 *  the Node process env (secrets, deploy tokens, oauth client IDs) is not
 *  the subprocess's business. */
function subprocessEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
    // NODE_ENV is included so the declared NodeJS.ProcessEnv type is satisfied;
    // the Python subprocess does not read it.
    const base: Record<string, string> = {
        PATH: process.env.PATH ?? "",
        NODE_ENV: process.env.NODE_ENV ?? "production",
    };
    if (process.env.LANG) base.LANG = process.env.LANG;
    if (process.env.LC_ALL) base.LC_ALL = process.env.LC_ALL;
    return { ...base, ...extra } as NodeJS.ProcessEnv;
}

function makeLzmaCompressor(pyBin: string): (b: Uint8Array) => Uint8Array {
    return (bytes) => {
        const r = spawnSync(pyBin, ["-c", LZMA_COMPRESS_SNIPPET], {
            input: Buffer.from(bytes),
            maxBuffer: 256 * 1024 * 1024,
            env: subprocessEnv({}),
            timeout: LZMA_TIMEOUT_MS,
            killSignal: "SIGKILL",
        });
        if (r.error && (r.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
            throw new Error("lzma compress timed out");
        }
        if (r.status !== 0) {
            throw new Error(`lzma compress failed: ${r.stderr?.toString()}`);
        }
        return Uint8Array.from(r.stdout);
    };
}

/** Normalize Python's `SyntaxError: (...)` traceback to something the UI can
 *  render without the `<stdin>` / `<unknown>` noise. */
function formatPyError(stderr: string): { message: string; kind: ErrorKind } {
    const lines = stderr
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
    const last = lines[lines.length - 1] || "build_ir failed";
    const isSyntax = /^(SyntaxError|IndentationError|TabError)\b/.test(last);
    return {
        message: last.replace(/\(<(?:unknown|stdin)>,\s*/, "("),
        kind: isSyntax ? "syntax" : "python",
    };
}

function parseSource(body: unknown): string | NextResponse {
    if (typeof body !== "object" || body === null) {
        return jsonError(400, "invalid JSON body");
    }
    const source = (body as { source?: unknown }).source;
    if (typeof source !== "string" || !source.trim()) {
        return jsonError(400, "source required");
    }
    if (Buffer.byteLength(source, "utf-8") > MAX_SOURCE_BYTES) {
        return jsonError(413, `source exceeds ${MAX_SOURCE_BYTES} bytes`);
    }
    return source;
}

// ---------------------------------------------------------------------------
// Toolchain discovery (cached for the lifetime of the Node process)
// ---------------------------------------------------------------------------
//
// The cache is intentionally racy: two concurrent cold-start requests may
// both run discoverPythons(), but they will converge on the same result and
// the overwrite is a harmless last-write-wins. Adding a mutex buys nothing.

let cachedPythons: PyInfo[] | null = null;

function getPythons(): PyInfo[] {
    if (cachedPythons) return cachedPythons;
    const found = discoverPythons() as PyInfo[];
    if (found.length === 0) {
        throw new Error("no CPython toolchains discovered on server");
    }
    cachedPythons = found;
    return found;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
    // 0. Rate-limit before doing anything expensive.
    const ip = clientIp(req.headers, null);
    const rl = rateLimit(ip);
    const rlHeaders: Record<string, string> = {
        "X-RateLimit-Limit": String(RATE_LIMIT_CAPACITY),
        "X-RateLimit-Remaining": String(rl.remaining),
        "X-RateLimit-Reset": String(Math.ceil(rl.resetAt / 1000)),
    };
    if (!rl.allowed) {
        const retryAfter = Math.max(1, Math.ceil((rl.resetAt - Date.now()) / 1000));
        return jsonError(429, "rate limit exceeded", "rate_limit", {
            ...rlHeaders,
            "Retry-After": String(retryAfter),
        });
    }

    // 1. Validate input
    let body: unknown;
    try {
        body = await req.json();
    } catch {
        return jsonError(400, "invalid JSON body");
    }
    const maybeSource = parseSource(body);
    if (maybeSource instanceof NextResponse) return maybeSource;
    const source = maybeSource;

    // 2. Discover toolchains
    let pythons: PyInfo[];
    try {
        pythons = getPythons();
    } catch (e) {
        return jsonError(
            500,
            `server build toolchain missing: ${
                e instanceof Error ? e.message : String(e)
            }`,
        );
    }

    // 3. Lift user source → IR with the newest discovered Python. The emitted
    //    IR is marshal-independent JSON, but parsing with the newest toolchain
    //    accepts newer source syntax when the server has that Python installed.
    const buildPython = pythons[pythons.length - 1].bin;
    const schema = makeV5Schema();
    const ir = spawnSync(buildPython, [BUILD_IR_PATH], {
        input: source,
        encoding: "utf-8",
        env: subprocessEnv({ PYGUARD_V5_SCHEMA: JSON.stringify(schema) }),
        maxBuffer: 64 * 1024 * 1024,
        timeout: BUILD_IR_TIMEOUT_MS,
        killSignal: "SIGKILL",
    });
    if (ir.error && (ir.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
        return jsonError(504, "build_ir timed out", "internal");
    }
    if (ir.status !== 0) {
        const { message, kind } = formatPyError(ir.stderr || "");
        return jsonError(400, message, kind);
    }
    if (!ir.stdout || !ir.stdout.trim()) {
        return jsonError(500, "build_ir produced empty output");
    }

    let artifacts: { compressed: string; manifest: string };
    try {
        artifacts = JSON.parse(ir.stdout.trim());
    } catch (e) {
        return jsonError(
            500,
            `build_ir output invalid: ${
                e instanceof Error ? e.message : String(e)
            }`,
        );
    }

    // 4. Prepare the interpreter source and the code-pack compiler used
    //    by stage1 / stage2 / interpreter packaging.
    let interpreterSource = "";
    const compress = makeLzmaCompressor(buildPython);
    const compileAndPackCode = createCompileAndPackCode(pythons);
    try {
        const interpSrcBytes = zlib.inflateRawSync(
            Buffer.from(INTERPRETER_SRC_B64, "base64"),
        );
        interpreterSource = Buffer.from(interpSrcBytes).toString("utf8");
    } catch (e) {
        return jsonError(
            500,
            `interpreter prepare failed: ${
                e instanceof Error ? e.message : String(e)
            }`,
        );
    }

    // 5. Produce the stub
    let stub: string;
    try {
        stub = obfuscatePythonCode(source, {
            v5IR: {
                compressed: Uint8Array.from(
                    Buffer.from(artifacts.compressed, "base64"),
                ),
                manifest: Uint8Array.from(
                    Buffer.from(artifacts.manifest, "base64"),
                ),
                schema,
            },
            interpreterSource,
            compileAndPackCode,
            compress,
        });
    } catch (e) {
        return jsonError(500, e instanceof Error ? e.message : String(e));
    }

    return new NextResponse(stub, {
        status: 200,
        headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "X-PyGuard-Targets": pythons
                .map((p) => `${p.major}.${p.minor}`)
                .join(","),
            ...rlHeaders,
        },
    });
}
