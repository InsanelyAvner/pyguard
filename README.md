# PyGuard

PyGuard is a Python source obfuscator that turns a Python program into a protected pure-Python stub.

PyGuard v5 is a friction system, not confidential execution. The goal is to make reverse-engineering and reusable automation meaningfully harder, especially after one clean run, while staying honest that an attacker-controlled Python process cannot offer strong secrecy guarantees.

Website: [pyguard.avkean.com](https://pyguard.avkean.com)

## What v5 Does

At a high level, v5:

1. rewrites source into a structurally alien form
2. lowers it into custom IR
3. randomizes the schema per build
4. packs the IR into a custom binary format
5. encrypts the payload in multiple stages
6. runs it through an embedded, LZMA-compressed interpreter source

It does not ship plaintext stage source, it does not rely on runtime `compile()` of decrypted user code, and it no longer exposes a `marshal.loads` execution boundary for stage0/stage1/stage2 or the interpreter itself — those are all compressed source blobs decrypted and exec'd at runtime. The user IR, once parsed, is a packed binary, not a recoverable Python code object; there is no single `marshal`/`compile` stop that discloses a usable representation of the original program.

## Current Hardening Strategy

The main failure mode for Python obfuscation is not just "source text recovered." It is "the decisive logic or decisive data still survives somewhere as one attacker-useful representation."

PyGuard's current v5 direction is therefore:

- keep the wrapper hard enough to avoid trivial one-run extraction
- permanently deform source before IR lowering
- move decisive secret-centric closures into per-build bespoke semantics where the payoff justifies the cost
- avoid single-stage choke points, so recovering one artefact or one runtime view is not enough to extract, force, or generalize

In practice, that means password checks, win gates, reward emission, and similar secret-bearing closures should not survive as obvious compare/jump/call structure inside generic IR when they can be lifted into semantic islands.

## Core v5 Pieces

- `lib/v5/transform_ast.py`
  Build-time AST transforms. This is where source deformation lives.

- `lib/v5/build_ir.py`
  Lowers transformed AST into v5 IR and tagged marshal payloads.

- `lib/v5/runtime_interp.py`
  The runtime interpreter for v5 IR and semantic-island payloads.

- `lib/v5/schema.ts`
  Per-build schema/tag/layout definitions used by the binary layer.

- `lib/obfuscate.ts`
  Packs, encrypts, and assembles the final stub.

- `scripts/gen-v5-stub.mjs`
  Main local entry point for generating a v5 stub.

## Permanent Source Transforms

These transforms survive full payload recovery because they change the program before IR packing:

- identifier renaming
- attribute mangling
- import concealment
- local slot lifting
- function body fusion
- opaque predicates
- control-flow flattening
- constant deformation
- semantic islands for secret-bearing regions

The newest important addition is semantic islands:

- transformed AST emits `__pyguard_semantic_island__(payload)`
- IR lowers this to `IIsland`
- runtime executes the payload through a bespoke, resumable per-island machine
- the current payload format is `PGSI2`, with per-island variation in opcode space, operand encoding, layout, stack/call convention, and dispatch shape
- string and bytes material can be fragmented in the payload and materialized late inside the island runtime
- per-island key material is derived locally at boot from a schema-bound build secret — it is not transported as a separate manifest aux entry
- island-owned name/slot state is sealed: an external write to a protected local is detected on the next read and aborts the island
- the resumable machine does not keep decoded decisive names/consts/handlers/island keys in live, callback-visible frame locals; host-call resume is transcript-bound and rejects tampered state instead of forcing reward
- a recovered island payload by itself is therefore not enough to read the decisive literals, and a local frame write at a host-call boundary can no longer flip the island cleanly to success

This targets the real root issue: preventing a protected secret check or reward path from collapsing into a tiny clean equivalent, and removing the single-stage choke points (one marshal dump, one frame walk, one local write) that make short-path attacks cheap.

## Boot-Packet Hardening

The stage2 → `_pg_boot` hand-off is the most attack-prone boundary in the stub: everything after it runs inside the interpreter, everything before it has the boot packet, boot key, and env available as plain Python state. The current path is hardened along four complementary axes:

- **Env-bound mask (v6.2).** The boot packet is XOR-masked with a SHAKE-128 keystream derived from `boot_key || env_hash`. `env_hash` includes witnesses for `sys.settrace` / `sys.setprofile` / `sys.gettrace` / `sys.getprofile` / `sys.monitoring` / `hashlib.shake_128` types; any runtime tampering flips the keystream and yields garbage before the cipher even runs. `_pg_boot` re-derives `env_hash` internally via `_pg_compute_env`, so a demasker must also execute inside an un-tampered interpreter.
- **Late-phase trace guard (v6.3).** `sys.gettrace()` / `sys.getprofile()` are re-checked immediately before the `_pg_boot(...)` call, and `sys.monitoring` tool slots 0–5 are scanned on 3.12+. This closes the window between stage2's entry check and the boot call during which an audit-hook-triggered late `settrace` could capture the boot args on the `call` event. `_pg_boot` itself repeats the check as defense-in-depth for paths where stage2 was bypassed.
- **Authority split (v6.4).** The boot key is not in the args tuple; `_pg_boot` receives only `(boot_blob, builtins_snapshot, import_lut)`. Stage2 deletes the decrypted plaintext and its components before the call.
- **Decoy-sharded key delivery (v6.5–v6.7).** The boot key is no longer retrievable from stage2's caller frame. Stage2 splits it into two shard sides (`key = shard_alpha XOR shard_beta`), wraps each side in a 4-tuple containing three per-run decoys plus the live shard, stashes one tuple in the interpreter module's globals and the other in `_pg_boot.__dict__`, then deletes the original key. `_pg_boot` selects the real slot from env/id witnesses, combines the selected pair from its own reflection surfaces — `sys._getframe(0).f_globals` and `f_globals[co_name].__dict__` — and never walks `f_back`. The live shard position and shard material use per-run entropy, so a capture cannot be replayed against a different execution of the same stub.

None of this makes the key "secret" in the cryptographic sense — an attacker who controls the process still recovers it eventually. It meaningfully raises the number of distinct reflection steps and the brittleness of each one, and removes the single-frame-walk path that used to disclose the key in one read.

## Host-Callback Boundary

Module-level `str` / `bytes` bindings are stored in an opaque `_PgB` representation inside the live module namespace. The wrapper keeps ciphertext plus a nonce, not an adjacent key; unwrapping uses runtime-private process state. Resolved `input` calls are routed through PyGuard's internal stdin/stdout implementation, including when `builtins.input` was monkeypatched before boot, so a hostile `input()` callback frame does not run inside the interpreter stack. The disclosure gate also checks passive frame walks, active `Scope.get(...)`, wrapper-slot XOR probes, and monkeypatched-input bypass.

## Release Gates

Use these in order:

```bash
npx tsx tests/run_disclosure_checks.ts
npm run test:compat
npm run test:compat:docker
npm run test:compat:realworld
bash tests/pentest/run_scoreboard.sh
```

What they mean:

- `run_disclosure_checks.ts`: primary release gate, including the real `tests/test_rev/dist.py` closure-lift assertion and a guard against plain decisive literals surviving in the lifted island payload
- `run_tests.ts`: host compatibility regression gate; it builds every case once
  and runs each generated stub on every discovered local CPython minor
- `run_docker_compat.mjs`: Linux runtime compatibility gate against official
  `python:3.9-slim` through `python:3.14-slim` images. Override with
  `PYGUARD_DOCKER_IMAGES=python:3.12-slim,python:3.13-slim` when narrowing CI.
- `run_realworld_compat.mjs`: final-artifact runtime gate that builds a stdin
  prompt program and runs the obfuscated output with both `python` and
  `python3`, absolute paths, foreign cwd, CRLF line endings, and exact patch
  images including `python:3.13.7-slim`. Override with
  `PYGUARD_REALWORLD_IMAGES=python:3.13.7-slim` when reproducing a reported
  environment.
- `run_scoreboard.sh`: attack dashboard

The scoreboard matters, but it is not the product definition. If the shortest one-run recovery path still works, the hardening round is not done even if many attacks say `HELD`.

## Honest Limits

PyGuard is deliberately honest about what it cannot guarantee:

- An attacker who can run the program controls the Python process.
- A sufficiently complete symbolic/static emulator can recover what the runtime recovers.
- Runtime values are not protected. If the program prints a secret, running the program reveals it.
- Import names still have unavoidable leakage through Python's import system.
- Artifacts are CPython-minor-specific. The service should build with every
  target CPython minor installed; otherwise the generated stub now exits with a
  clear unsupported-runtime message instead of silently producing no output.
- `match` (PEP 634) and `except*` (PEP 654) are not yet lowered by the v5 lifter; inputs that use them fail loud at build time with `NotImplementedError` rather than producing a broken stub.

If you need cryptographic secrecy, move the secret off the client.

## Local Use

Install:

```bash
npm install
```

Generate a stub:

```bash
node --import tsx scripts/gen-v5-stub.mjs input.py -o out.py
```

Regenerate embedded Python sources after editing `lib/v5/build_ir.py` or `lib/v5/runtime_interp.py`:

```bash
npm run gen:v5
```

## Red-Team Fixture

The main local semantic-hardening fixture is:

- clean source target: `tests/test_rev/dist.py`
- already-obfuscated sample: `tests/test_rev/sillybillysgame.py`

When validating semantic-island work, use `dist.py` as the source target. The important question is whether the clean secret-bearing logic still collapses into a short equivalent after protection.

For this fixture class, a green result means more than "the wrapper held" or "the island exists." A recovered `PGSI2` blob alone should not reveal the flag, the reward text, or enough decisive truth to stop at that layer.

## Running the Web Service

The `/api/obfuscate` Next.js route shells out to Python on untrusted input, so the deploy image is hardened along a few axes.

Container:

- `Dockerfile` runs the Node process as an unprivileged `pyguard` user (uid 10001), not root.
- The runtime stage ships CPython 3.9 – 3.14 side-by-side on `$PATH`; the route's `discoverPythons()` probes these on first request and then filters to the configured target range. This is the supported common-version range tested locally and in Docker.
- `HEALTHCHECK` fetches `/` and expects a 2xx so orchestrators can rotate unhealthy replicas.

Subprocess safety:

- Every `spawnSync` (build_ir, lzma compressor, version probe, code-pack compiler) has an explicit wall-clock `timeout` with `SIGKILL` on expiry. A hung Python subprocess will not starve the route's 180 s budget or block a worker indefinitely.
- Subprocesses get a minimal whitelisted env (`PATH`, `LANG`, `LC_ALL`, `PYGUARD_V5_SCHEMA`) — not the full Node `process.env`, so Node-side secrets do not leak into the Python build step.
- A 1 MB input cap is enforced before the AST is even parsed.

Rate limiting:

- A per-IP sliding-window limiter (default 10 requests per 60 s, see `lib/rateLimit.ts`) sits in front of the handler. Tune with `PYGUARD_RL_CAPACITY` and `PYGUARD_RL_WINDOW_MS`.
- Responses carry `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and a `Retry-After` header on 429.

Deploy-time env vars:

| Variable | Default | Purpose |
| -- | -- | -- |
| `TRUSTED_PROXY` | `0` | Set to `1` when running behind a reverse proxy; the rate limiter then keys on `x-forwarded-for` / `x-real-ip`. |
| `PYGUARD_PYTHON_BINS` | *(empty)* | Platform-delimited list of Python binaries to use instead of probing `$PATH` (`:` on Linux/macOS, `;` on Windows). |
| `PYGUARD_TARGET_MINORS` | `3.9,3.10,3.11,3.12,3.13,3.14` | CPython minor versions that must be present before generating stubs. Comma-separated versions and ranges such as `3.9-3.14` are accepted. Narrow this only when intentionally producing limited-target artifacts. |
| `PYGUARD_ALLOW_PARTIAL_PYTHONS` | *(unset)* | Local `gen-v5-stub.mjs` escape hatch that permits generating a stub with only discovered Python minors. Do not set in production. |
| `PYGUARD_COMPILE_TIMEOUT_MS` | `300000` | Timeout for per-minor code-pack compiler subprocesses. Raise this on slow CI/build hosts. |
| `PYGUARD_LZMA_TIMEOUT_MS` | `120000` local CLI/tests, `20000` API | Timeout for Python LZMA compressor subprocesses. |
| `PYGUARD_SYNTAX_TIMEOUT_MS` | `30000` | Timeout for per-target source syntax checks. The build refuses source that cannot be parsed by every configured target minor. |
| `PYGUARD_RL_CAPACITY` | `10` | Max requests per window per IP. |
| `PYGUARD_RL_WINDOW_MS` | `60000` | Rate-limit window length (ms). |
| `PYGUARD_ALLOW_UNOBFUSCATED_IR` | *(unset)* | Opt-in escape hatch for embedded/Pyodide contexts where `transform_ast` genuinely cannot be loaded. Any production deployment should leave this unset — otherwise a broken import silently ships un-deformed IR. |

Obfuscation-quality invariants enforced at build time:

- `randomBytes` in `lib/obfuscate.ts` throws if `crypto.getRandomValues` is missing rather than degrading to `Math.random()`.
- `compile_to_ir` raises when `transform_ast` fails to import (unless the opt-in env above is set), so a misconfigured deploy fails loud instead of shipping weaker stubs.

## License

Copyright 2026 avkean. Licensed under [GPL-3.0](LICENSE).
