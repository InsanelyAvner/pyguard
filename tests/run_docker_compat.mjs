#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const CASES_DIR = path.join(ROOT, "tests", "cases");
const OUT_DIR = path.join(ROOT, "tests", "out_v5");
const DOCKER_CONFIG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "pyguard-docker-"));
fs.writeFileSync(path.join(DOCKER_CONFIG_DIR, "config.json"), "{\"auths\":{}}\n");

function currentDockerHost() {
    if (process.env.DOCKER_HOST) return process.env.DOCKER_HOST;
    const r = spawnSync("docker", [
        "context",
        "inspect",
        "--format",
        '{{(index .Endpoints "docker").Host}}',
    ], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
        timeout: 10_000,
    });
    return r.status === 0 ? r.stdout.trim() : "";
}

const DOCKER_ENV = {
    ...process.env,
    DOCKER_CONFIG: process.env.DOCKER_CONFIG || DOCKER_CONFIG_DIR,
    ...(currentDockerHost() ? { DOCKER_HOST: currentDockerHost() } : {}),
};

const DEFAULT_IMAGES = [
    "python:3.9-slim",
    "python:3.10-slim",
    "python:3.11-slim",
    "python:3.12-slim",
    "python:3.13-slim",
    "python:3.14-slim",
];

function dockerImages() {
    const raw = process.env.PYGUARD_DOCKER_IMAGES;
    if (!raw) return DEFAULT_IMAGES;
    return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

function runDocker(image, file) {
    const args = [
        "run",
        "--rm",
        "-v",
        `${ROOT}:/work`,
        "-w",
        "/work",
        image,
        "python",
        file,
    ];
    const r = spawnSync("docker", args, {
        env: DOCKER_ENV,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 30_000,
        maxBuffer: 64 * 1024 * 1024,
    });
    return {
        stdout: r.stdout || "",
        stderr: r.stderr || (r.error ? String(r.error.message || r.error) : ""),
        code: typeof r.status === "number" ? r.status : -1,
    };
}

function ensureDocker() {
    execFileSync("docker", ["info"], {
        env: DOCKER_ENV,
        stdio: ["ignore", "ignore", "pipe"],
        timeout: 10_000,
    });
}

function main() {
    ensureDocker();
    const images = dockerImages();
    const cases = fs.readdirSync(CASES_DIR)
        .filter((f) => f.endsWith(".py"))
        .sort();

    let pass = 0;
    let fail = 0;
    const failures = [];

    for (const image of images) {
        execFileSync("docker", ["pull", image], {
            env: DOCKER_ENV,
            stdio: ["ignore", "inherit", "inherit"],
            timeout: 180_000,
        });
        for (const name of cases) {
            const original = path.posix.join("tests", "cases", name);
            const obfuscated = path.posix.join("tests", "out_v5", name);
            if (!fs.existsSync(path.join(OUT_DIR, name))) {
                throw new Error(`missing ${obfuscated}; run npx tsx tests/run_tests.ts first`);
            }
            const expected = runDocker(image, original);
            const actual = runDocker(image, obfuscated);
            const ok =
                expected.code === actual.code &&
                expected.stdout === actual.stdout;
            if (ok) {
                pass++;
                console.log(`PASS  ${image}  ${name}`);
            } else {
                fail++;
                failures.push(`${image}:${name}`);
                console.log(`FAIL  ${image}  ${name}`);
                console.log(`  expected.code=${expected.code} actual.code=${actual.code}`);
                console.log(`  expected.stdout=${JSON.stringify(expected.stdout)}`);
                console.log(`  actual.stdout=${JSON.stringify(actual.stdout)}`);
                if (actual.stderr.trim()) {
                    console.log(`  actual.stderr=${actual.stderr.trim().split(/\r?\n/).slice(-10).join("\n  ")}`);
                }
            }
        }
    }

    console.log(`\n${pass} passed, ${fail} failed (${cases.length} cases x ${images.length} Docker images)`);
    if (fail > 0) {
        console.log("failures:", failures.join(", "));
        process.exit(1);
    }
}

try {
    main();
} finally {
    fs.rmSync(DOCKER_CONFIG_DIR, { recursive: true, force: true });
}
