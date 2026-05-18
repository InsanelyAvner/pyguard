// lib/v5/assemble.ts
//
// PyGuard stage2-source assembler (current generation: v12).
//
// ARCHITECTURE:
//
// Stage2 source is assembled here, marshaled at build time, and then
// packed with a binary boot bundle by lib/obfuscate.ts. At stub runtime
// the outer canonical region decrypts stage1, stage1 decrypts the stage2
// payload package, and stage2 decrypts the interpreter as a TAGGED
// marshal blob:
//   b'PGM1' + major + minor + marshal.dumps(code)
//
// The 6-byte header lets runtime fail closed before marshal.loads on
// interpreter-version mismatch, instead of reverting to compile() on stage
// source and handing audit hooks the whole launcher.
//
// v12 packaging change: stage2 no longer embeds encrypted interpreter /
// IR / schema / manifest blobs as Python source literals. Those payloads
// now travel once, in a binary boot bundle passed from stage1 to the
// marshaled stage2 launcher. This removes the largest fixed-size cost in
// every stub and avoids re-encoding the same payload structure as nested
// source text.

import type { V5Schema } from './schema';

// v5.2: the IR is built into a compressed byte blob by the Python side
// (build_ir.py for gen-v5-stub.mjs, Pyodide for the browser) and shipped
// to TS as opaque bytes. TS never sees a JSON dict in memory.
export interface V5IR {
    // zlib-deflated (raw, -15 wbits) JSON bytes. Obfuscate.ts encrypts
    // these as-is and the runtime stage2 decompresses after decryption.
    compressed: Uint8Array;
    // zlib-deflated (raw, -15 wbits) static import manifest bytes.
    manifest: Uint8Array;
    schema: V5Schema;
}

// Names the assembler needs from the outer obfuscator.
export interface AssembleNames {
    n_seed: string;     // stage1 injects real decrypted seed here
    n_kd: string;       // stage1 injects _kd function here
    n_dec: string;      // stage1 injects _dec function here
    n_tchk: string;     // stage1 injects traceback-based trace checker here
    // v6.9: `n_loadc` is intentionally absent — stage1 pre-loads the
    // interpreter code-pack and passes the resulting code object to
    // stage2 via `AssembleStage2.interpCodeVar`, so the PGCV decoder is
    // no longer reachable through stage2's __globals__.
}

// Runtime cipher primitives — must match encrypt() in lib/obfuscate.ts.
export interface V5BootBundle {
    // Per-build labels mixed into runtime key derivation.
    interpLabel: Uint8Array;
    irLabel: Uint8Array;
    schemaLabel: Uint8Array;
    manifestLabel: Uint8Array;
    // Encrypted runtime payloads. These are opaque until stage2 decrypts
    // them inside the proper runtime context.
    interpCiphertext: Uint8Array;
    irCiphertext: Uint8Array;
    schemaCiphertext: Uint8Array;
    manifestCiphertext: Uint8Array;
    // Randomized bytes-key under which the interpreter module registers
    // its renamed `_pg_boot`.
    bootKeyBytes: Uint8Array;
    // Inert-bytes versions of the crypto profile, handed to `_pg_boot`
    // instead of stage1's `_kd` / `_dec` closures.
    pepBytes: Uint8Array;       // 32-byte pepper (= obfuscate.ts `pep`)
    profileBytes: Uint8Array;   // 15-byte packed PolyProfile
}

export interface AssembleStage2 {
    bootBundleVar: string;
    bootFuncName: string;
    // v6.9: stage1 pre-loads the interpreter code object and injects it
    // into stage2's globals dict under this randomized name.
    interpCodeVar: string;
}

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const a of arrs) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}

function u32le(n: number): Uint8Array {
    return new Uint8Array([
        n & 0xff,
        (n >>> 8) & 0xff,
        (n >>> 16) & 0xff,
        (n >>> 24) & 0xff,
    ]);
}

const BOOT_BUNDLE_MAGIC = new Uint8Array([80, 71, 66, 49]);    // PGB1
// v6.9: the stage2 plaintext envelope intentionally has no leading
// magic. Removing the "PGS2" sentinel closed the cheapest single-byte
// tamper oracle on the stage2 ciphertext (magic-mismatch fail-fast vs
// proceed); residual oracles still exist via lzma / PGCV rejection but
// require the tamper to traverse more of the canonical chain per probe.

export function packV5BootBundle(bundle: V5BootBundle): Uint8Array {
    if (bundle.interpLabel.length !== 6 ||
        bundle.irLabel.length !== 6 ||
        bundle.schemaLabel.length !== 6 ||
        bundle.manifestLabel.length !== 6) {
        throw new Error('packV5BootBundle: expected 6-byte labels');
    }
    if (bundle.bootKeyBytes.length !== 12) {
        throw new Error('packV5BootBundle: expected 12-byte boot key');
    }
    if (bundle.pepBytes.length !== 32) {
        throw new Error('packV5BootBundle: expected 32-byte pepper');
    }
    if (bundle.profileBytes.length !== 15) {
        throw new Error('packV5BootBundle: expected 15-byte profile');
    }
    return concatBytes(
        BOOT_BUNDLE_MAGIC,
        u32le(bundle.interpCiphertext.length),
        u32le(bundle.manifestCiphertext.length),
        u32le(bundle.schemaCiphertext.length),
        u32le(bundle.irCiphertext.length),
        bundle.interpLabel,
        bundle.manifestLabel,
        bundle.schemaLabel,
        bundle.irLabel,
        bundle.bootKeyBytes,
        bundle.pepBytes,
        bundle.profileBytes,
        bundle.interpCiphertext,
        bundle.manifestCiphertext,
        bundle.schemaCiphertext,
        bundle.irCiphertext,
    );
}

export function packV5Stage2Payload(
    stage2Marshal: Uint8Array,
    bootBundle: Uint8Array,
): Uint8Array {
    // Layout: [pkg2_len: u32 LE][pkg2: pkg2_len][boot2: rest]. No
    // leading magic — the canonical region clamps pkg2_len and lets
    // garbage fall through to the uniform lzma/loadc except clause.
    return concatBytes(
        u32le(stage2Marshal.length),
        stage2Marshal,
        bootBundle,
    );
}

// Build the stage2 source — the Python source string that the obfuscator
// will compile into a versioned code-pack at build time, then encrypt +
// wrap inside stage1.
//
// When executed (via FunctionType(code_object, isolated_ns)), this code:
//   1. Trace/profile nullification + env-integrity hash
//   2. Unpack the binary boot bundle supplied by stage1
//   3. Decrypt the encrypted manifest blob and resolve it into opaque
//      `(id, value)` pairs before the interpreter code is loaded
//   4. Decrypt the compressed interpreter code-pack bytes
//   5. Pre-seed the boot argument tuple into `interp_ns[bootKey]`
//   6. load-code() + FunctionType(code, interp_ns)()
//
// The schema is NEVER written to any globals dict outside the boot frame.
// `run_blob` is NEVER assigned to a globals name. Profile-hooking stage2's
// frame yields only encrypted ciphertexts and hash material.
export function buildV5Stage2Source(
    names: AssembleNames,
    stage2: AssembleStage2,
): string {
    const { n_seed, n_kd, n_dec, n_tchk } = names;
    const { bootBundleVar, bootFuncName, interpCodeVar } = stage2;
    const bootFuncNameExpr = JSON.stringify(bootFuncName);

    // Stage2 source (compiled+packed at build time):
    //   - stage2 reads one binary boot bundle from its globals dict, then
    //     deletes that slot before touching the interpreter
    //   - the schema is decrypted inside the interpreter's own boot frame,
    //     never in stage2 globals
    //   - FunctionType is recovered via (lambda: 0).__class__
    return `import sys
import hashlib
import zlib
import lzma
import marshal
try:
    sys.settrace(None)
except Exception:
    pass
try:
    sys.setprofile(None)
except Exception:
    pass
if ${n_tchk}():
    raise SystemExit(0)
_pg_ft = (lambda: 0).__class__
def _pg_frame_probe():
    try:
        raise RuntimeError
    except RuntimeError as _pg_probe_exc:
        _pg_tb = _pg_probe_exc.__traceback__
    _pg_depth = 0
    while _pg_tb is not None:
        _pg_depth += 1
        _pg_tb = _pg_tb.tb_next
    return _pg_depth
_pg_env = hashlib.sha256(bytes([124]).decode().join([str(_pg_frame_probe()), type(zlib.decompress).__name__, type(print).__name__, type(getattr).__name__, type(sys.settrace).__name__, type(sys.setprofile).__name__, type(sys.gettrace).__name__, type(sys.getprofile).__name__, type(exec).__name__, type(marshal.loads).__name__, type(hashlib.scrypt).__name__, type(hashlib.shake_128).__name__, str(type(sys.settrace) is type(zlib.decompress)), str(type(sys.setprofile) is type(zlib.decompress)), str(type(sys.gettrace) is type(zlib.decompress)), str(type(sys.getprofile) is type(zlib.decompress)), str(type(exec) is type(zlib.decompress)), str(type(marshal.loads) is type(zlib.decompress)), str(type(hashlib.scrypt) is type(zlib.decompress)), str(type(hashlib.shake_128) is type(zlib.decompress)), _pg_ft.__name__, str(_pg_ft is (lambda: None).__class__), _pg_ft.__class__.__name__, _pg_ft.__module__]).encode()).digest()
_pg_pkg = ${bootBundleVar}
del ${bootBundleVar}
if len(_pg_pkg) < 103 or _pg_pkg[:4] != bytes([80, 71, 66, 49]):
    raise SystemExit(0)
_pg_o = 4
_pg_interp_len = int.from_bytes(_pg_pkg[_pg_o:_pg_o + 4], 'little'); _pg_o += 4
_pg_manifest_len = int.from_bytes(_pg_pkg[_pg_o:_pg_o + 4], 'little'); _pg_o += 4
_pg_schema_len = int.from_bytes(_pg_pkg[_pg_o:_pg_o + 4], 'little'); _pg_o += 4
_pg_ir_len = int.from_bytes(_pg_pkg[_pg_o:_pg_o + 4], 'little'); _pg_o += 4
# v6.9: skip the interp_label slot — stage1 read its own copy from the
# boot bundle when it pre-loaded the interpreter code-pack, so stage2
# does not need to materialize the label at all.
_pg_o += 6
_pg_manifest_label = _pg_pkg[_pg_o:_pg_o + 6]; _pg_o += 6
_pg_schema_label = _pg_pkg[_pg_o:_pg_o + 6]; _pg_o += 6
_pg_ir_label = _pg_pkg[_pg_o:_pg_o + 6]; _pg_o += 6
_pg_boot_key = _pg_pkg[_pg_o:_pg_o + 12]; _pg_o += 12
_pg_pep = _pg_pkg[_pg_o:_pg_o + 32]; _pg_o += 32
_pg_profile = _pg_pkg[_pg_o:_pg_o + 15]; _pg_o += 15
if _pg_o + _pg_interp_len + _pg_manifest_len + _pg_schema_len + _pg_ir_len != len(_pg_pkg):
    raise SystemExit(0)
_pg_interp_ct = _pg_pkg[_pg_o:_pg_o + _pg_interp_len]; _pg_o += _pg_interp_len
_pg_manifest_ct = _pg_pkg[_pg_o:_pg_o + _pg_manifest_len]; _pg_o += _pg_manifest_len
_pg_schema_ct = _pg_pkg[_pg_o:_pg_o + _pg_schema_len]; _pg_o += _pg_schema_len
_pg_ir_ct = _pg_pkg[_pg_o:_pg_o + _pg_ir_len]
_pg_interp_hash = hashlib.sha256(_pg_interp_ct).digest()
# v6.9: stage1 already produced the interpreter code object and stashed
# it under a randomized globals name. Pop+clear the slot so neither the
# decoder nor the loaded code stays reachable through stage2 globals.
_pg_interp_code = globals().pop(${JSON.stringify(interpCodeVar)})
_pg_interp_ns = {bytes([95, 95, 98, 117, 105, 108, 116, 105, 110, 115, 95, 95]).decode(): __builtins__, bytes([95, 95, 110, 97, 109, 101, 95, 95]).decode(): bytes([60, 112, 103, 95, 105, 62]).decode(), bytes([95, 80, 71, 95, 70, 73, 76, 69]).decode(): globals().get(bytes([95, 95, 102, 105, 108, 101, 95, 95]).decode(), bytes().decode())}
_pg_interp_fn = _pg_ft(_pg_interp_code, _pg_interp_ns)
del _pg_interp_ns, _pg_interp_code
try:
    if sys.gettrace() is not None or sys.getprofile() is not None:
        raise SystemExit(0)
except Exception:
    pass
_pg_interp_fn()
_pg_manifest_seed = bytes(a ^ b ^ c for a, b, c in zip(hashlib.sha256(${n_seed} + _pg_manifest_label).digest(), _pg_interp_hash, _pg_env))
_pg_manifest_p = ${n_kd}(_pg_manifest_seed)
_pg_manifest_blob = zlib.decompress(${n_dec}(_pg_manifest_ct, _pg_manifest_p[0], _pg_manifest_p[1], _pg_manifest_p[2]), -15)
_pg_manifest_pairs = []
_pg_manifest_mods = {}
_pg_bi_snap = dict(__builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__)
_pg_mod_type = type(sys)
_pg_mod_dict = _pg_mod_type.__dict__.get(bytes([95, 95, 100, 105, 99, 116, 95, 95]).decode())
_pg_manifest_off = 0
_pg_manifest_cnt = int.from_bytes(_pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + 4], bytes([108, 105, 116, 116, 108, 101]).decode())
_pg_manifest_off += 4
for _ in range(_pg_manifest_cnt):
    _pg_mid = int.from_bytes(_pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + 4], bytes([108, 105, 116, 116, 108, 101]).decode())
    _pg_manifest_off += 4
    _pg_ml = int.from_bytes(_pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + 2], bytes([108, 105, 116, 116, 108, 101]).decode())
    _pg_manifest_off += 2
    _pg_mod_name = _pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + _pg_ml].decode(bytes([117, 116, 102, 45, 56]).decode())
    _pg_manifest_off += _pg_ml
    _pg_al = int.from_bytes(_pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + 2], bytes([108, 105, 116, 116, 108, 101]).decode())
    _pg_manifest_off += 2
    _pg_attr_name = None if _pg_al == 65535 else _pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + _pg_al].decode(bytes([117, 116, 102, 45, 56]).decode())
    if _pg_al != 65535:
        _pg_manifest_off += _pg_al
    try:
        _pg_mod = _pg_manifest_mods.get(_pg_mod_name)
        if _pg_mod is None:
            _pg_mod = sys.modules.get(_pg_mod_name)
            if type(_pg_mod) is not _pg_mod_type:
                # sys.modules entry is not a real ModuleType — an audit
                # hook (c18-class attack) has planted a proxy object to
                # log __getattribute__ calls. Pop and re-__import__; if
                # the hook re-wraps during import, retry a bounded number
                # of times. If we cannot obtain a real ModuleType, fail
                # closed rather than falling through to getattr and
                # leaking the attr name through the proxy.
                _pg_retry = 0
                while _pg_retry < 3:
                    sys.modules.pop(_pg_mod_name, None)
                    _pg_mod = _pg_bi_snap[bytes([95, 95, 105, 109, 112, 111, 114, 116, 95, 95]).decode()](_pg_mod_name, None, None, (bytes([95]).decode(),), 0)
                    if type(_pg_mod) is _pg_mod_type:
                        break
                    _pg_live_mod = sys.modules.get(_pg_mod_name)
                    if type(_pg_live_mod) is _pg_mod_type:
                        _pg_mod = _pg_live_mod
                        break
                    _pg_retry += 1
                if type(_pg_mod) is not _pg_mod_type:
                    raise SystemExit(0)
            _pg_manifest_mods[_pg_mod_name] = _pg_mod
        if _pg_attr_name is None:
            _pg_val = _pg_mod
        else:
            # Attribute resolution MUST go through the ModuleType.__dict__
            # slot descriptor — never through getattr / __getattribute__,
            # which would fire any proxy __getattribute__ planted on a
            # non-ModuleType sys.modules entry and disclose the attr
            # name. The cached _pg_mod is already validated as
            # ModuleType above, so the descriptor call is safe.
            if _pg_mod_dict is None:
                raise SystemExit(0)
            try:
                _pg_dict = _pg_mod_dict.__get__(_pg_mod)
            except Exception:
                raise SystemExit(0)
            if not isinstance(_pg_dict, dict):
                raise SystemExit(0)
            _pg_val = _pg_dict.get(_pg_attr_name, _pg_manifest_mods)
            if _pg_val is _pg_manifest_mods:
                # Attr not in module.__dict__ directly — could be a
                # lazy-loaded submodule or descriptor defined on the
                # module's type. Permit getattr only when _pg_mod is a
                # plain ModuleType (no proxy) — already enforced above.
                _pg_val = getattr(_pg_mod, _pg_attr_name)
        _pg_manifest_pairs.append((_pg_mid, _pg_val))
    except SystemExit:
        raise
    except BaseException as _pg_exc:
        _pg_manifest_pairs.append((_pg_mid, _pg_exc))
_pg_manifest_pairs = tuple(_pg_manifest_pairs)
for _pg_mod_name, _pg_mod in _pg_manifest_mods.items():
    try:
        sys.modules[_pg_mod_name] = _pg_mod
    except Exception:
        pass
_pg_boot_fn = _pg_interp_fn.__globals__[${bootFuncNameExpr}]
_pg_mod_name = bytes([95, 95, 109, 97, 105, 110, 95, 95]).decode()
_pg_mod_name_b = _pg_mod_name.encode(bytes([117, 116, 102, 45, 56]).decode())
_pg_boot_plain = bytes().join((len(_pg_schema_ct).to_bytes(4, bytes([108, 105, 116, 116, 108, 101]).decode()), len(_pg_ir_ct).to_bytes(4, bytes([108, 105, 116, 116, 108, 101]).decode()), len(_pg_mod_name_b).to_bytes(4, bytes([108, 105, 116, 116, 108, 101]).decode()), _pg_schema_label, _pg_ir_label, ${n_seed}, _pg_interp_hash, _pg_pep, _pg_profile, _pg_mod_name_b, _pg_schema_ct, _pg_ir_ct))
_pg_boot_mask = hashlib.shake_128(bytes(_pg_boot_key) + _pg_env).digest(len(_pg_boot_plain))
_pg_boot_blob = bytes(a ^ b for a, b in zip(_pg_boot_plain, _pg_boot_mask))
# v6.4 Cut A/B: demask authority material is purged from stage2 scope
# BEFORE the _pg_boot call so that a frame-local capture at the call
# site no longer yields either the unmasked packet (was _pg_boot_plain,
# direct plaintext of every decisive field) or the individual
# reconstruction components (_pg_schema_ct / _pg_ir_ct / labels /
# hashes / seed / pep / profile / mod_name_b — any subset reassembles
# the plaintext without the key). Only the masked blob remains live.
del _pg_boot_mask, _pg_boot_plain, _pg_schema_ct, _pg_ir_ct, _pg_schema_label, _pg_ir_label, _pg_interp_hash, _pg_pep, _pg_profile, _pg_mod_name_b, _pg_mod_name, _pg_pkg, _pg_interp_ct, _pg_manifest_ct, _pg_manifest_blob, _pg_manifest_mods
# v6.5 shard split: instead of leaving _pg_boot_key in stage2's caller
# frame for _pg_boot to retrieve via f_back, split the key into two
# shards (alpha XOR beta = key) and stash each in a distinct reflection
# scope that _pg_boot can reach WITHOUT touching the caller frame:
#   - shard_alpha → _pg_interp_fn.__globals__[<name_a>] (interp module
#     dict; reachable from _pg_boot via sys._getframe(0).f_globals)
#   - shard_beta  → _pg_boot_fn.__dict__[<name_b>] (function object's
#     own attribute dict; reachable from _pg_boot via its self-ref)
# After stashing, _pg_boot_key is deleted from stage2 locals, so a
# caller-frame dump at the _pg_boot call site yields no key material.
# A single reflection step at EITHER shard location is still a 12-byte
# bytes value that is useless on its own — the attacker must locate
# BOTH shards and know the XOR combination before any demask attempt.
# shard_alpha uses fresh per-run entropy via id()+env hash so that a
# shard capture from one execution cannot be replayed against another
# execution of the same stub.
# v6.3: late-phase trace guard. The gettrace check at the top of stage2
# is a snapshot — an attacker with an addaudithook listening for
# 'import' events can install sys.settrace DURING the manifest load
# (which fires 'import' audit events for each stdlib module resolved).
# By the time _pg_boot_fn is called here, that trace would fire on the
# 'call' event and capture (boot_blob, boot_key) from frame.f_locals.
# Env_hash is deterministic on a clean interpreter, so the attacker can
# reproduce the mask keystream offline and fully demask the packet.
# Re-verify now, so the window between the top-of-stage2 check and this
# call is closed. Also scan sys.monitoring tool-ids on 3.12+, which can
# install a CALL-event callback via a separate API.
#
# v6.6: these checks run BEFORE the shard stash, not after. Previously
# trace/monitoring detection ran after _PG_KSA/_PG_KSB were already on
# reflection-reachable surfaces, so a smart attacker whose hook walked
# gc.get_objects() on every audit event could capture both shards even
# while we were about to abort. Moving the check up means instrumented
# runs never materialize shard state in the first place.
if sys.gettrace() is not None or sys.getprofile() is not None:
    raise SystemExit(0)
_pg_mon_sv = getattr(sys, bytes([109, 111, 110, 105, 116, 111, 114, 105, 110, 103]).decode(), None)
if _pg_mon_sv is not None:
    for _pg_mon_i in range(6):
        try:
            if _pg_mon_sv.get_events(_pg_mon_i) != 0:
                raise SystemExit(0)
        except ValueError:
            pass
del _pg_mon_sv
# v6.6: audit-hook presence detection via timing probe. gettrace /
# getprofile / sys.monitoring do NOT cover sys.addaudithook, and audit
# hooks are the natural vehicle for the shard-recovery attack against
# v6.5: install a hook that does gc.get_objects() on every audit event,
# then let stage2 run — between the shard stash below and _pg_boot's
# internal pop, some audit event (e.g. 'import' inside _pg_boot's
# payload decompress path) fires, the hook sweeps the heap, and both
# shards fall out as 12-byte bytes objects in dicts / function __dict__.
# Audit hooks cannot be removed once installed, but the heavy-handler
# pattern this attack requires makes sys.audit() measurably slow. Fire
# a tight burst and abort if the loop is many orders of magnitude
# slower than the no-hook baseline. Baseline on a clean interpreter is
# typically 20-100us for 1000 audits (~50ns per call); a handler that
# walks gc.get_objects() pushes per-call cost into the tens of
# microseconds, so the burst takes tens of milliseconds. The 5ms
# threshold sits comfortably above baseline and well below the heavy-
# handler regime, giving clean discrimination with a wide safety band.
import time as _pg_t_ah
_pg_probe_ev = bytes([112, 103, 95, 112, 114, 111, 98, 101]).decode()
_pg_t_ah0 = _pg_t_ah.perf_counter_ns()
for _pg_ah_i in range(8):
    sys.audit(_pg_probe_ev)
    if _pg_t_ah.perf_counter_ns() - _pg_t_ah0 > 500_000:
        raise SystemExit(0)
del _pg_t_ah, _pg_t_ah0, _pg_probe_ev, _pg_ah_i
_pg_ks_a = hashlib.sha256(id(_pg_boot_blob).to_bytes(8, bytes([108, 105, 116, 116, 108, 101]).decode()) + id(_pg_env).to_bytes(8, bytes([108, 105, 116, 116, 108, 101]).decode()) + id(_pg_interp_fn).to_bytes(8, bytes([108, 105, 116, 116, 108, 101]).decode()) + _pg_env).digest()[:12]
_pg_ks_b = bytes(a ^ b for a, b in zip(bytes(_pg_boot_key), _pg_ks_a))
# v6.7 decoy wrap: a surgical attacker (audit hook filtering by event
# name to dodge the v6.6 timing trip) can still walk gc.get_objects()
# during the narrow shard-live window and pattern-match any 12-byte
# bytes value reachable from a dict or FunctionType __dict__. Instead
# of storing the raw shard under a flat dict entry, wrap each shard in
# a fixed-shape tuple whose other slots are per-run random 12-byte
# decoys of the same length. A naive attacker iterating dict values and
# filtering by isinstance(v, (bytes, bytearray)) and len(v) == 12 sees
# nothing and gives up; an attacker iterating tuples too now faces
# N**2 XOR combinations per (a, b) pair and must recompute shake_128
# keystream per candidate, which is costly enough that even recovery
# is a work-factor win. _pg_boot derives the real slot index from the
# same env/id witnesses it already consumes.
import os as _pg_os_t
_pg_decoy_pool_a = [_pg_os_t.urandom(12) for _pg_decoy_i in range(4)]
_pg_decoy_pool_b = [_pg_os_t.urandom(12) for _pg_decoy_i in range(4)]
_pg_ks_idx = hashlib.sha256(b'ksidx' + id(_pg_boot_blob).to_bytes(8, 'little') + _pg_env).digest()[0] & 3
_pg_decoy_pool_a[_pg_ks_idx] = _pg_ks_a
_pg_decoy_pool_b[_pg_ks_idx] = _pg_ks_b
_pg_interp_fn.__globals__[bytes([95, 80, 71, 95, 75, 83, 65]).decode()] = tuple(_pg_decoy_pool_a)
_pg_boot_fn.__dict__[bytes([95, 80, 71, 95, 75, 83, 66]).decode()] = tuple(_pg_decoy_pool_b)
del _pg_boot_key, _pg_ks_a, _pg_ks_b, _pg_decoy_pool_a, _pg_decoy_pool_b, _pg_ks_idx, _pg_os_t
# v6.5: the boot key is NOT passed through the args tuple AND is NOT in
# stage2's caller-frame locals. Two shards live in _pg_boot's own scope
# (interp globals + boot-fn attribute dict); _pg_boot combines them
# internally without ever walking f_back to this frame. A caller-frame
# dump at this call-site therefore yields zero key material.
_pg_boot_fn(_pg_boot_blob, _pg_bi_snap, _pg_manifest_pairs)
try:
    del _pg_interp_fn.__globals__[${bootFuncNameExpr}]
except Exception:
    pass
del _pg_boot_fn, _pg_boot_blob, _pg_interp_fn, _pg_env, _pg_bi_snap, _pg_manifest_pairs
`;
}

// Serialize a V5IR for encrypt() input.
// In v5.2 the IR is pre-compressed by the Python side, so we just return
// the raw compressed bytes — the encryption layer treats them as opaque.
export function serializeIR(ir: V5IR): Uint8Array {
    return ir.compressed;
}
