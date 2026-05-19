#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const DOCKER_CONFIG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "pyguard-docker-"));
fs.writeFileSync(path.join(DOCKER_CONFIG_DIR, "config.json"), "{\"auths\":{}}\n");

const SOURCE = `import sys

try:
    name = input("Name: ")
    count = int(input("Count: "))
except ValueError:
    print("bad-count")
else:
    print(f"hello {name}")
    print(sum(range(count + 1)))
    print(sys.executable.rsplit("/", 1)[-1])
`;

const DEFAULT_IMAGES = [
    "python:3.9-slim",
    "python:3.10-slim",
    "python:3.11-slim",
    "python:3.12-slim",
    "python:3.13.7-slim",
    "python:3.13-slim",
    "python:3.14-slim",
];

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

function dockerImages() {
    const raw = process.env.PYGUARD_REALWORLD_IMAGES;
    if (!raw) return DEFAULT_IMAGES;
    return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

function ensureDocker() {
    execFileSync("docker", ["info"], {
        env: DOCKER_ENV,
        stdio: ["ignore", "ignore", "pipe"],
        timeout: 10_000,
    });
}

function runDocker(image, command, file, cwd, input) {
    const args = [
        "run",
        "--rm",
        "-i",
        "-v",
        `${RUNTIME_DIR}:/rt`,
        "-w",
        cwd,
        image,
        command,
        file,
    ];
    const r = spawnSync("docker", args, {
        env: DOCKER_ENV,
        input,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
        timeout: 45_000,
        maxBuffer: 64 * 1024 * 1024,
    });
    return {
        stdout: r.stdout || "",
        stderr: r.stderr || (r.error ? String(r.error.message || r.error) : ""),
        code: typeof r.status === "number" ? r.status : -1,
    };
}

function buildStub(srcPath, outPath) {
    execFileSync("node", [
        "--import",
        "tsx",
        path.join(ROOT, "scripts", "gen-v5-stub.mjs"),
        srcPath,
        "-o",
        outPath,
    ], {
        cwd: ROOT,
        stdio: ["ignore", "ignore", "pipe"],
        timeout: 180_000,
        maxBuffer: 64 * 1024 * 1024,
    });
}

function assertSame(label, expected, actual) {
    const ok =
        expected.code === actual.code &&
        expected.stdout === actual.stdout &&
        actual.stderr === "";
    if (!ok) {
        throw new Error(
            `${label}\n` +
            `  expected.code=${expected.code} actual.code=${actual.code}\n` +
            `  expected.stdout=${JSON.stringify(expected.stdout)}\n` +
            `  actual.stdout=${JSON.stringify(actual.stdout)}\n` +
            `  actual.stderr=${JSON.stringify(actual.stderr)}`,
        );
    }
}

const RUNTIME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "pyguard-runtime-"));

function main() {
    ensureDocker();

    const srcPath = path.join(RUNTIME_DIR, "src.py");
    const stubPath = path.join(RUNTIME_DIR, "dist.py");
    const crlfStubPath = path.join(RUNTIME_DIR, "dist_crlf.py");
    fs.writeFileSync(srcPath, SOURCE, "utf8");
    buildStub(srcPath, stubPath);
    fs.writeFileSync(
        crlfStubPath,
        fs.readFileSync(stubPath, "utf8").replace(/\n/g, "\r\n"),
        "utf8",
    );

    const images = dockerImages();
    const input = "Avner\n5\n";
    let pass = 0;

    for (const image of images) {
        execFileSync("docker", ["pull", image], {
            env: DOCKER_ENV,
            stdio: ["ignore", "inherit", "inherit"],
            timeout: 180_000,
        });
        for (const command of ["python", "python3"]) {
            const expected = runDocker(image, command, "/rt/src.py", "/rt", input);
            for (const [file, cwd, variant] of [
                ["/rt/dist.py", "/rt", "abs-path"],
                ["/rt/dist.py", "/tmp", "foreign-cwd"],
                ["/rt/dist_crlf.py", "/rt", "crlf"],
            ]) {
                const actual = runDocker(image, command, file, cwd, input);
                assertSame(`${image} ${command} ${variant}`, expected, actual);
                pass++;
                console.log(`PASS  ${image}  ${command}  ${variant}`);
            }
        }
    }

    console.log(`\n${pass} real-world runtime checks passed`);
}

try {
    main();
} finally {
    fs.rmSync(RUNTIME_DIR, { recursive: true, force: true });
    fs.rmSync(DOCKER_CONFIG_DIR, { recursive: true, force: true });
}
