"""PyGuard v5 runtime AST-walking interpreter.

Embedded into v5 obfuscated stubs. Takes a v5 IR dict (tree + strings + consts)
and executes the program WITHOUT ever calling compile() or exec() on user code.

This is the only architecture that defends against PEP 578 audit-hook attacks
on a pure-Python self-decoding obfuscator: there is never a moment at which
user source materializes as a code object or a string fed to compile().

Stdlib-only. Compatible with Python 3.8+.
"""

import builtins
import struct as _pg_struct
import sys
import hashlib as _pg_hashlib
import os as _pg_os


# v6.5 / C17 — capture real built-in type objects via C-slot __class__ reads
# on empty literals, at interpreter-module load time. These are unreachable
# through Python-level hooks on `builtins.bytes` / `builtins.str` / `type()`:
# `(b'').__class__` goes through the `tp_descr_get` slot of `object.__class__`
# (a C-level getset descriptor on the immutable type `object`) which reads the
# literal's `ob_type` pointer directly. A sitecustomize-planted
# `builtins.bytes = _SpyBytes` subclass does not affect the ob_type of `b''`.
# All interpreter-internal construction uses these captures instead of the
# module-global names, so that a `builtins.bytes` / `builtins.str` spy never
# sees the decoded string-pool / consts / IR-leaf bytes that the interpreter
# materializes while running user code.
_PGBT = (b'').__class__       # real bytes type
_PGST = ('').__class__        # real str type


# v6.5 / C18 — custom tagged binary codec for IR consts. Replaces
# marshal.dumps/loads in `_build_accessor`. The accessor used to route
# every const lookup through `marshal.loads(pt)`, which fires the
# `marshal.loads` PEP 578 audit event with the plaintext bytes as the
# first arg. A `sys.addaudithook()` installed from sitecustomize (before
# stage0 runs) observed the stream and recovered user consts — including
# the adjacent (byte^key, key) int pairs emitted by `_StringObfuscator`,
# which XOR-pair trivially to plaintext user source literals.
# The custom codec here is unobservable to audit hooks: the decode is
# pure byte arithmetic, no stdlib audited call in the hot path.
def _pg_pack_const(v):
    t = type(v)
    if v is None:     return b'\x00'
    if v is True:     return b'\x01'
    if v is False:    return b'\x02'
    if v is Ellipsis: return b'\x0A'
    if t is int:
        n = (v.bit_length() // 8) + 1
        b = v.to_bytes(n, 'little', signed=True)
        return b'\x03' + len(b).to_bytes(4, 'little') + b
    if t is float:
        return b'\x04' + _pg_struct.pack('<d', v)
    if t is complex:
        return b'\x05' + _pg_struct.pack('<dd', v.real, v.imag)
    if t is bytes:
        return b'\x06' + len(v).to_bytes(4, 'little') + v
    if t is str:
        eb = v.encode('utf-8')
        return b'\x07' + len(eb).to_bytes(4, 'little') + eb
    if t is tuple:
        parts = [_pg_pack_const(x) for x in v]
        return b'\x08' + len(v).to_bytes(4, 'little') + b''.join(parts)
    if t is frozenset:
        vals = list(v)
        parts = [_pg_pack_const(x) for x in vals]
        return b'\x09' + len(vals).to_bytes(4, 'little') + b''.join(parts)
    raise TypeError('unpackable const: ' + t.__name__)


def _pg_unpack_const(buf, ofs=0):
    tag = buf[ofs]
    ofs += 1
    if tag == 0x00: return None, ofs
    if tag == 0x01: return True, ofs
    if tag == 0x02: return False, ofs
    if tag == 0x0A: return Ellipsis, ofs
    if tag == 0x03:
        n = int.from_bytes(buf[ofs:ofs+4], 'little'); ofs += 4
        v = int.from_bytes(buf[ofs:ofs+n], 'little', signed=True); ofs += n
        return v, ofs
    if tag == 0x04:
        v = _pg_struct.unpack('<d', buf[ofs:ofs+8])[0]; ofs += 8
        return v, ofs
    if tag == 0x05:
        r, i = _pg_struct.unpack('<dd', buf[ofs:ofs+16]); ofs += 16
        return complex(r, i), ofs
    if tag == 0x06:
        n = int.from_bytes(buf[ofs:ofs+4], 'little'); ofs += 4
        v = _PGBT(buf[ofs:ofs+n]); ofs += n
        return v, ofs
    if tag == 0x07:
        n = int.from_bytes(buf[ofs:ofs+4], 'little'); ofs += 4
        v = buf[ofs:ofs+n].decode('utf-8'); ofs += n
        return v, ofs
    if tag == 0x08:
        n = int.from_bytes(buf[ofs:ofs+4], 'little'); ofs += 4
        vals = []
        for _ in range(n):
            x, ofs = _pg_unpack_const(buf, ofs)
            vals.append(x)
        return tuple(vals), ofs
    if tag == 0x09:
        n = int.from_bytes(buf[ofs:ofs+4], 'little'); ofs += 4
        vals = []
        for _ in range(n):
            x, ofs = _pg_unpack_const(buf, ofs)
            vals.append(x)
        return frozenset(vals), ofs
    raise ValueError('bad const tag')


_PGSI_STR = object()
_PGSI_BYTES = object()
_PGSI_GSTR = object()
_PGSI_GBYTES = object()


def _pg_si_unpack_fragments(buf, ofs, with_salt=False):
    salt = None
    if with_salt:
        salt = _PGBT(buf[ofs:ofs+8])
        ofs += 8
    frag_count = buf[ofs]
    ofs += 1
    frags = []
    for _ in range(frag_count):
        key = buf[ofs]
        ofs += 1
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        frag = _PGBT(buf[ofs:ofs+n])
        ofs += n
        frags.append((key, frag))
    if with_salt:
        return salt, tuple(frags), ofs
    return tuple(frags), ofs


def _pg_si_unpack_const_v1(buf, ofs=0):
    tag = buf[ofs]
    ofs += 1
    if tag == 0x00:
        return None, ofs
    if tag == 0x01:
        return True, ofs
    if tag == 0x02:
        return False, ofs
    if tag == 0x03:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        v = int.from_bytes(buf[ofs:ofs+n], 'little', signed=True)
        ofs += n
        return v, ofs
    if tag == 0x04:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        v = float(buf[ofs:ofs+n].decode('utf-8'))
        ofs += n
        return v, ofs
    if tag == 0x05:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        v = buf[ofs:ofs+n].decode('utf-8')
        ofs += n
        return v, ofs
    if tag == 0x06:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        v = _PGBT(buf[ofs:ofs+n])
        ofs += n
        return v, ofs
    if tag == 0x07:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        vals = []
        for _ in range(n):
            x, ofs = _pg_si_unpack_const(buf, ofs)
            vals.append(x)
        return tuple(vals), ofs
    if tag == 0x08:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        vals = []
        for _ in range(n):
            x, ofs = _pg_si_unpack_const_v1(buf, ofs)
            vals.append(x)
        return vals, ofs
    raise ValueError('bad island const tag')


def _pg_si_unpack_const(buf, ofs=0):
    tag = buf[ofs]
    ofs += 1
    if tag == 0x00:
        return None, ofs
    if tag == 0x01:
        return True, ofs
    if tag == 0x02:
        return False, ofs
    if tag == 0x03:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        v = int.from_bytes(buf[ofs:ofs+n], 'little', signed=True)
        ofs += n
        return v, ofs
    if tag == 0x04:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        v = float(buf[ofs:ofs+n].decode('utf-8'))
        ofs += n
        return v, ofs
    if tag == 0x05:
        frags, ofs = _pg_si_unpack_fragments(buf, ofs)
        return (_PGSI_STR, tuple(frags)), ofs
    if tag == 0x06:
        frags, ofs = _pg_si_unpack_fragments(buf, ofs)
        return (_PGSI_BYTES, tuple(frags)), ofs
    if tag == 0x07:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        vals = []
        for _ in range(n):
            x, ofs = _pg_si_unpack_const(buf, ofs)
            vals.append(x)
        return tuple(vals), ofs
    if tag == 0x08:
        n = int.from_bytes(buf[ofs:ofs+2], 'little')
        ofs += 2
        vals = []
        for _ in range(n):
            x, ofs = _pg_si_unpack_const(buf, ofs)
            vals.append(x)
        return vals, ofs
    if tag == 0x09:
        salt, frags, ofs = _pg_si_unpack_fragments(buf, ofs, with_salt=True)
        return (_PGSI_GSTR, salt, tuple(frags)), ofs
    if tag == 0x0A:
        salt, frags, ofs = _pg_si_unpack_fragments(buf, ofs, with_salt=True)
        return (_PGSI_GBYTES, salt, tuple(frags)), ofs
    raise ValueError('bad island const tag')


def _pg_si_mask_stream(seed, n):
    out = bytearray(n)
    state = seed & 0xFFFFFFFF
    for i in range(n):
        state = ((1103515245 * state) + 12345) & 0xFFFFFFFF
        out[i] = (state >> 16) & 0xFF
    return _PGBT(out)


def _pg_si_guard_stream(key, salt, n):
    if not key:
        raise ValueError('missing island guard key')
    out = bytearray(n)
    state = 0x9E3779B9
    seed = _PGBT(key) + _PGBT(salt)
    for idx, b in enumerate(seed):
        state ^= (b + ((idx + 1) * 0x45D9F3B)) & 0xFFFFFFFF
        state = ((state << 7) | (state >> 25)) & 0xFFFFFFFF
        state = (state * 0x85EBCA6B + 0xC2B2AE35) & 0xFFFFFFFF
    sl = len(salt)
    kl = len(key)
    for i in range(n):
        state ^= (key[i % kl] << 8) ^ salt[i % sl] ^ ((i + 1) * 0x27D4EB2D)
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        out[i] = ((state >> 16) ^ key[(i * 5 + 3) % kl] ^ salt[(i * 7 + 1) % sl]) & 0xFF
    return _PGBT(out)


def _pg_si_decode_fragments(frags):
    buf = bytearray()
    for key, frag in frags:
        for b in frag:
            buf.append(b ^ key)
    return _PGBT(buf)


def _pg_si_unary(opid, value):
    if opid == 1:
        return not value
    if opid == 2:
        return +value
    if opid == 3:
        return -value
    if opid == 4:
        return ~value
    raise ValueError('bad island unary op')


def _pg_si_binary(opid, left, right):
    if opid == 1:
        return left + right
    if opid == 2:
        return left - right
    if opid == 3:
        return left * right
    if opid == 4:
        return left / right
    if opid == 5:
        return left // right
    if opid == 6:
        return left % right
    if opid == 7:
        return left ** right
    if opid == 8:
        return left | right
    if opid == 9:
        return left ^ right
    if opid == 10:
        return left & right
    if opid == 11:
        return left << right
    if opid == 12:
        return left >> right
    if opid == 13:
        return left @ right
    raise ValueError('bad island binary op')


def _pg_si_compare(opid, left, right):
    if opid == 1:
        return left == right
    if opid == 2:
        return left != right
    if opid == 3:
        return left < right
    if opid == 4:
        return left <= right
    if opid == 5:
        return left > right
    if opid == 6:
        return left >= right
    if opid == 7:
        return left is right
    if opid == 8:
        return left is not right
    if opid == 9:
        return left in right
    if opid == 10:
        return left not in right
    raise ValueError('bad island compare op')


def _pg_si_materialize(value, island_key=None):
    if isinstance(value, tuple):
        if len(value) == 2 and value[0] is _PGSI_STR:
            return _pg_si_decode_fragments(value[1]).decode('utf-8')
        if len(value) == 2 and value[0] is _PGSI_BYTES:
            return _pg_si_decode_fragments(value[1])
        if len(value) == 3 and value[0] is _PGSI_GSTR:
            if island_key is None:
                raise ValueError('missing island key for guarded string')
            buf = _pg_si_decode_fragments(value[2])
            stream = _pg_si_guard_stream(island_key, value[1], len(buf))
            return _PGBT(buf[i] ^ stream[i] for i in range(len(buf))).decode('utf-8')
        if len(value) == 3 and value[0] is _PGSI_GBYTES:
            if island_key is None:
                raise ValueError('missing island key for guarded bytes')
            buf = _pg_si_decode_fragments(value[2])
            stream = _pg_si_guard_stream(island_key, value[1], len(buf))
            return _PGBT(buf[i] ^ stream[i] for i in range(len(buf)))
        return tuple(_pg_si_materialize(x, island_key) for x in value)
    if isinstance(value, list):
        return [_pg_si_materialize(x, island_key) for x in value]
    return value


# --- sentinel exceptions used for control flow ---------------------------

class _Return(BaseException):
    __slots__ = ('value',)
    def __init__(self, value=None):
        self.value = value


class _Break(BaseException):
    pass


class _Continue(BaseException):
    pass


_MISSING = object()

# Internal schema storage — populated by run_blob(), not accessible as
# _PG_* globals (those are wiped after copying to prevent frame-walk extraction).
# These are ALSO scrubbed from module globals once interp.run() returns
# (v6.5 / C13), so an atexit-registered gc walk finds nothing.
_S_K = {}   # keys mapping
_S_RT = {}  # reverse tags
_S_M = b''  # XOR mask
_S_L = {}   # field layouts
_S_IS = b''  # schema-derived semantic-island build secret

# v6.5 / C19 — pinned builtins snapshot. Populated by `_pg_boot` from
# the stage2 packet call (`boot_blob, builtins_snapshot, import_lut`).
# Stage2 captures `dict(__builtins__)` after envCheck and before the
# first post-envCheck audit-event opportunity an attacker can use to
# swap `builtins.print`. `Scope.get` consults `_PG_BI` before falling
# back to `getattr(builtins, name)`, so a post-boot swap is invisible to
# user name resolution.
_PG_BI = {}
# Static import lookup table resolved inside `_pg_boot` from the encrypted
# manifest blob. Maps manifest ids -> resolved module objects, imported
# attributes, or deferred exceptions for re-raise at use time.
_PG_IMP = {}


def _pg_key(key):
    return _S_K.get(key, key)


def _pg_tag(tag):
    return _S_RT.get(tag, tag)


def _pg_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        mask = _S_M
        if not mask:
            return ''.join(chr(x) for x in value)
        buf = bytearray(len(value))
        for i, b in enumerate(value):
            buf[i] = b ^ mask[i % len(mask)]
        return _PGBT(buf).decode('utf-8')
    return value


def _pg_schema_island_secret(mask, key_map, reverse_tags, layouts):
    h = _pg_hashlib.sha256()
    h.update(b'PGSI-BUILD-SECRET\0')
    mask_b = _PGBT(mask or b'')
    h.update(len(mask_b).to_bytes(2, 'little'))
    h.update(mask_b)
    return h.digest()


def _pg_si_island_key(island_id):
    if not _S_IS:
        raise ValueError('missing semantic-island build secret')
    return _pg_hashlib.sha256(
        _PGBT(_S_IS) + b'|pgsi-key|' + (int(island_id) & 0xFFFFFFFF).to_bytes(4, 'little') + b'|'
    ).digest()


def _pg_si_state_fingerprint(value, depth=0):
    if depth >= 3:
        return b'R' + (id(value) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
    if value is None:
        return b'N'
    if value is True:
        return b'T'
    if value is False:
        return b'F'
    t = type(value)
    if t is int:
        n = (value.bit_length() // 8) + 1
        return b'I' + value.to_bytes(n, 'little', signed=True)
    if t is float:
        return b'G' + _pg_struct.pack('<d', value)
    if t is str:
        return b'S' + value.encode('utf-8')
    if t is bytes:
        return b'B' + _PGBT(value)
    if t is tuple:
        out = bytearray(b'U')
        for item in value[:8]:
            fp = _pg_si_state_fingerprint(item, depth + 1)
            out.extend(len(fp).to_bytes(2, 'little'))
            out.extend(fp)
        return _PGBT(out)
    if t is list:
        return b'L' + (id(value) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
    if t is dict:
        return b'D' + (id(value) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
    return b'O' + (id(value) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')


def _pg_si_state_seal(island_key, label, value):
    fp = _pg_si_state_fingerprint(value)
    salt = (int(label) & 0xFFFFFFFF).to_bytes(4, 'little')
    acc = bytearray(_pg_si_guard_stream(island_key, salt + b'PG', 16))
    for idx, b in enumerate(fp):
        pos = idx % 16
        acc[pos] ^= (b + ((idx + 1) * 17)) & 0xFF
        acc[pos] = ((acc[pos] << 1) | (acc[pos] >> 7)) & 0xFF
    return _PGBT(acc)


def _pg_env_w():
    """v6.5 / C12 — live environment witness byte.

    Measured at boot-time inside `_build_accessor` and re-measured on every
    accessor call. If any witnessed identity diverges post-boot (attacker
    wraps sys.stdout / sys.stderr / sys.excepthook after the stage0 seed
    gate has already accepted a clean env), the XOR delta folds into the
    per-access decrypt key and the accessor returns garbage — preventing
    post-decryption heap walks triggered via stdio hooks from recovering
    plaintext strings and consts out of closure cells.

    Stage0's envCheck already gates PRE-boot hook installation into the
    seed; this function is the defense-in-depth that catches POST-boot
    hook installation against the already-booted interpreter.
    """
    try:
        w = 0
        if sys.stdout is not sys.__stdout__: w |= 0x01
        if sys.stderr is not sys.__stderr__: w |= 0x02
        if sys.displayhook is not sys.__displayhook__: w |= 0x04
        if sys.breakpointhook is not sys.__breakpointhook__: w |= 0x08
        if type(sys.stdout) is not type(sys.__stdout__): w |= 0x10
        if type(sys.stderr) is not type(sys.__stderr__): w |= 0x20
        if sys.stdin is not sys.__stdin__: w |= 0x40
        if sys.excepthook is not sys.__excepthook__: w |= 0x80
        return w
    except Exception:
        return 0

_NODE_POS = {
    'Code': {'instrs': 1},
    'IExpr': {'value': 1},
    'IIsland': {'payload': 1},
    'IAssign': {'targets': 1, 'value': 2},
    'IAugAssign': {'target': 1, 'op2': 2, 'value': 3},
    'IAnnAssign': {'target': 1, 'annotation': 2, 'value': 3, 'simple': 4},
    'IReturn': {'value': 1},
    'IRaise': {'exc': 1, 'cause': 2},
    'IPass': {},
    'IBreak': {},
    'IContinue': {},
    'IDelete': {'targets': 1},
    'IGlobal': {'names': 1},
    'INonlocal': {'names': 1},
    'IIf': {'test': 1, 'body': 2, 'orelse': 3},
    'IWhile': {'test': 1, 'body': 2, 'orelse': 3},
    'IFor': {'target': 1, 'iter': 2, 'body': 3, 'orelse': 4},
    'IAsyncFor': {'target': 1, 'iter': 2, 'body': 3, 'orelse': 4},
    'IWith': {'items': 1, 'body': 2},
    'IAsyncWith': {'items': 1, 'body': 2},
    'ITry': {'body': 1, 'handlers': 2, 'orelse': 3, 'finalbody': 4},
    'IHandler': {'type': 1, 'name': 2, 'body': 3},
    'IImportLookup': {'binds': 1, 'ids': 2},
    'IImport': {'names': 1},
    'IImportFrom': {'module': 1, 'names': 2, 'level': 3},
    'IFunctionDef': {'name': 1, 'args': 2, 'body': 3, 'decorator_list': 4, 'returns': 5, 'is_async': 6, 'is_gen': 7},
    'IClassDef': {'name': 1, 'bases': 2, 'keywords': 3, 'body': 4, 'decorator_list': 5},
    'Module': {'body': 1},
    'Expr': {'value': 1},
    'Assign': {'targets': 1, 'value': 2},
    'AugAssign': {'target': 1, 'op2': 2, 'value': 3},
    'AnnAssign': {'target': 1, 'annotation': 2, 'value': 3, 'simple': 4},
    'Return': {'value': 1},
    'Raise': {'exc': 1, 'cause': 2},
    'Pass': {},
    'Break': {},
    'Continue': {},
    'Delete': {'targets': 1},
    'Global': {'names': 1},
    'Nonlocal': {'names': 1},
    'If': {'test': 1, 'body': 2, 'orelse': 3},
    'While': {'test': 1, 'body': 2, 'orelse': 3},
    'For': {'target': 1, 'iter': 2, 'body': 3, 'orelse': 4},
    'AsyncFor': {'target': 1, 'iter': 2, 'body': 3, 'orelse': 4},
    'With': {'items': 1, 'body': 2},
    'AsyncWith': {'items': 1, 'body': 2},
    'withitem': {'context_expr': 1, 'optional_vars': 2},
    'Try': {'body': 1, 'handlers': 2, 'orelse': 3, 'finalbody': 4},
    'ExceptHandler': {'type': 1, 'name': 2, 'body': 3},
    'ImportLookup': {'binds': 1, 'ids': 2},
    'Import': {'names': 1},
    'ImportFrom': {'module': 1, 'names': 2, 'level': 3},
    'alias': {'name': 1, 'asname': 2},
    'FunctionDef': {'name': 1, 'args': 2, 'body': 3, 'decorator_list': 4, 'returns': 5},
    'AsyncFunctionDef': {'name': 1, 'args': 2, 'body': 3, 'decorator_list': 4, 'returns': 5},
    'ClassDef': {'name': 1, 'bases': 2, 'keywords': 3, 'body': 4, 'decorator_list': 5},
    'Lambda': {'args': 1, 'body': 2},
    'arguments': {'posonlyargs': 1, 'args': 2, 'vararg': 3, 'kwonlyargs': 4, 'kw_defaults': 5, 'kwarg': 6, 'defaults': 7},
    'arg': {'arg': 1, 'annotation': 2},
    'keyword': {'arg': 1, 'value': 2},
    'Name': {'id': 1, 'ctx': 2},
    'Constant': {'idx': 1},
    'BinOp': {'left': 1, 'op2': 2, 'right': 3},
    'UnaryOp': {'op2': 1, 'operand': 2},
    'BoolOp': {'op2': 1, 'values': 2},
    'Compare': {'left': 1, 'ops': 2, 'comparators': 3},
    'IfExp': {'test': 1, 'body': 2, 'orelse': 3},
    'Call': {'func': 1, 'args': 2, 'keywords': 3},
    'Attribute': {'value': 1, 'attr': 2, 'ctx': 3},
    'Subscript': {'value': 1, 'slice': 2, 'ctx': 3},
    'Slice': {'lower': 1, 'upper': 2, 'step': 3},
    'Starred': {'value': 1, 'ctx': 2},
    'List': {'elts': 1, 'ctx': 2},
    'Tuple': {'elts': 1, 'ctx': 2},
    'Set': {'elts': 1},
    'Dict': {'keys': 1, 'values': 2},
    'ListComp': {'elt': 1, 'generators': 2},
    'SetComp': {'elt': 1, 'generators': 2},
    'DictComp': {'key': 1, 'value': 2, 'generators': 3},
    'GeneratorExp': {'elt': 1, 'generators': 2},
    'comprehension': {'target': 1, 'iter': 2, 'ifs': 3, 'is_async': 4},
    'JoinedStr': {'values': 1},
    'FormattedValue': {'value': 1, 'conversion': 2, 'format_spec': 3},
    'Yield': {'value': 1},
    'YieldFrom': {'value': 1},
    'Await': {'value': 1},
    'NamedExpr': {'target': 1, 'value': 2},
}


def _nf(node, field, default=_MISSING):
    if not isinstance(node, tuple) or not node:
        if default is not _MISSING:
            return default
        raise KeyError(field)
    canon_op = _pg_tag(node[0])
    pos = _S_L.get(canon_op, {}).get(field, _MISSING)
    if pos is _MISSING:
        pos = _NODE_POS.get(canon_op, {}).get(field, _MISSING)
    if pos is _MISSING:
        if default is not _MISSING:
            return default
        raise KeyError(field)
    if pos >= len(node):
        if default is not _MISSING:
            return default
        raise KeyError(field)
    return node[pos]


# No _PGMap wrapper class: a class with __slots__ == ('_k', '_v') would
# be a single unique fingerprint an attacker could locate and patch to
# dump every materialized map (schema, layouts, IR map-nodes, const
# wrappers, …). Call sites construct dict(items) inline; the const wire
# format is positional (t, v) tuples (see _decode_const), so the only
# dict that exists at parse time is the transient schema map, and even
# that is replaced in step D by a positional binary schema parser inside
# _pg_boot's frame (no dict ever materializes).


# --- operator dispatch ---------------------------------------------------
#
# Op dispatch is inlined at each call site. Module-level dicts would
# centralize a hook point (`runtime_interp._CMP_OPS['Eq'] = sniff` would
# intercept every compare in one line); with the tables gone, each of the
# five call sites performs its own if/elif chain on the op tag. No single
# observable symbol intercepts every compare or every binary op.


# --- scope ---------------------------------------------------------------
#
# v6.8 / C19 — opaque module-level str/bytes binding.
#
# Pre-v6.8 hole: at a hostile `input()` callback, a frame walker could
# deep-walk `Scope.globals` (the module's backing dict) and find any
# module-level decisive literal — e.g., `FLAG = "EC3{REDACTED}"` landed
# as a plaintext `str` under that key, visible via
#   sys._getframe(2).f_locals['<scope_local>'].globals['<flag_name>']
# which the disclosure-check deep-frame scanner confirmed as an OPEN
# leak against the v5/v6 fixture.
#
# `_PgB` is an opaque XOR-encoded wrapper holding `(enc_bytes, nonce, t)`
# in `__slots__` only — no adjacent key slot, no `__dict__`, no
# content-revealing `__repr__`, and no instance-level unwrap helper that
# a hostile walker could call directly off the stored object. `_PgGlobals`
# stores every non-dunder module-scope str/bytes binding in this opaque
# form; keyed lookup unwraps via runtime-private helpers so user
# semantics stay intact.
# The plaintext never materializes inside the raw `scope.globals`
# storage or its `dict.items()` walk — it only exists transiently on the
# interpreter's value stack during a specific keyed read.

_PG_WRAP_SEED = _pg_hashlib.shake_128(_pg_os.urandom(32))
_PG_INPUT_FREEZE_DEPTH = 0


def _pg_wrap_key(nonce, length):
    if _PG_INPUT_FREEZE_DEPTH:
        raise RuntimeError("input boundary")
    h = _PG_WRAP_SEED.copy()
    h.update(nonce)
    return h.digest(length)


class _PgB:
    """Opaque wrapper for module-level str/bytes bindings.

    Stores the value XOR-encoded with a per-instance nonce in `__slots__`.
    The stream key is derived from process-local runtime state, not stored on
    the wrapper next to the ciphertext. Default `__repr__` yields only
    `<_PgB object at 0x...>`, never the plaintext.
    """

    __slots__ = ('_e', '_n', '_t')

    def __init__(self, value):
        import os as _os
        if isinstance(value, bytes):
            raw = bytes(value)
            self._t = 1
        else:
            raw = value.encode('utf-8')
            self._t = 0
        nonce = _pg_os.urandom(16)
        key = _pg_wrap_key(nonce, len(raw)) if raw else b''
        self._e = bytes(a ^ b for a, b in zip(raw, key))
        self._n = nonce

def _pg_maybe_wrap(value):
    if isinstance(value, (str, bytes)):
        return _PgB(value)
    return value


def _pg_unwrap(value):
    if isinstance(value, _PgB):
        raw = bytes(a ^ b for a, b in zip(value._e, _pg_wrap_key(value._n, len(value._e))))
        if value._t == 0:
            return raw.decode('utf-8')
        return raw
    return value


def _pg_should_wrap_name(name, value):
    if not isinstance(value, (str, bytes)):
        return False
    if isinstance(name, str) and name[:2] == '__' and name[-2:] == '__':
        return False
    return True


class _PgGlobals(dict):
    """Live module namespace with opaque storage and unwrapped lookup.

    The underlying dict storage keeps module-scope str/bytes bindings as
    `_PgB` wrappers so deep frame walkers that recurse through raw dict
    items do not see plaintext. Normal keyed lookup (`globals()['x']`,
    `globals().get('x')`) unwraps transparently, and Python-level writes
    (`globals()['x'] = ...`) write through to the real backing dict.

    C-level writes performed by `types.FunctionType(..., globals())()`
    bypass `__setitem__` and land raw in the dict storage. `__getitem__`
    seals those values on first keyed read so later storage snapshots
    return to the opaque form.
    """

    __slots__ = ()

    def __init__(self, initial=None):
        dict.__init__(self)
        if initial:
            self.update(initial)

    def _seal_if_needed(self, key):
        v = dict.__getitem__(self, key)
        if _pg_should_wrap_name(key, v) and not isinstance(v, _PgB):
            v = _pg_maybe_wrap(v)
            dict.__setitem__(self, key, v)
        return v

    def __getitem__(self, key):
        if _PG_INPUT_FREEZE_DEPTH and _pg_should_wrap_name(key, dict.get(self, key)):
            raise KeyError(key)
        return _pg_unwrap(self._seal_if_needed(key))

    def __setitem__(self, key, value):
        if _pg_should_wrap_name(key, value):
            value = _pg_maybe_wrap(value)
        dict.__setitem__(self, key, value)

    def get(self, key, default=None):
        if dict.__contains__(self, key):
            return self[key]
        return default

    def setdefault(self, key, default=None):
        if dict.__contains__(self, key):
            return self[key]
        self[key] = default
        return self[key]

    def update(self, *args, **kwargs):
        for k, v in dict(*args, **kwargs).items():
            self[k] = v


def _pg_call_host(scope, fn, args, kwargs=None):
    if fn is builtins.input or fn is _PG_BI.get('input'):
        return _pg_call_input_with_depth(args, kwargs)
    if kwargs is None:
        return fn(*args)
    return fn(*args, **kwargs)


def _pg_safe_input(args, kwargs=None):
    if kwargs:
        raise TypeError("input() takes no keyword arguments")
    if len(args) > 1:
        raise TypeError("input expected at most 1 argument, got " + str(len(args)))
    prompt = args[0] if args else ''
    if prompt:
        sys.__stdout__.write(str(prompt))
        sys.__stdout__.flush()
    line = sys.__stdin__.readline()
    if line == '':
        raise EOFError
    if line.endswith('\n'):
        line = line[:-1]
        if line.endswith('\r'):
            line = line[:-1]
    return line


def _pg_call_input_with_depth(args, kwargs=None):
    global _PG_INPUT_FREEZE_DEPTH
    _PG_INPUT_FREEZE_DEPTH += 1
    try:
        return _pg_safe_input(args, kwargs)
    finally:
        _PG_INPUT_FREEZE_DEPTH -= 1


class Scope:
    """Lexical scope. Chains via parent. Module scope has vars==globals."""

    __slots__ = ('vars', 'parent', 'globals', 'global_names',
                 'nonlocal_names', 'is_module', '_gate')

    def __init__(self, parent=None, globals_=None, is_module=False):
        self.parent = parent
        if parent is not None:
            self._gate = parent._gate
        else:
            self._gate = {'live': True}
        if globals_ is not None:
            if is_module and not isinstance(globals_, _PgGlobals):
                self.globals = _PgGlobals(globals_)
            else:
                self.globals = globals_
        elif parent is not None:
            self.globals = parent.globals
        else:
            self.globals = _PgGlobals() if is_module else {}
        if is_module:
            self.vars = self.globals
        else:
            self.vars = {}
        self.global_names = set()
        self.nonlocal_names = set()
        self.is_module = is_module

    def _check_live(self, name):
        if _PG_INPUT_FREEZE_DEPTH or not self._gate.get('live', True):
            raise NameError(name)

    def get(self, name):
        self._check_live(name)
        if name in self.global_names:
            if name in self.globals:
                return _pg_unwrap(self.globals[name])
            if name in _PG_BI:
                return _PG_BI[name]
            try:
                return getattr(builtins, name)
            except AttributeError:
                raise NameError(name)
        if name in self.nonlocal_names:
            p = self.parent
            while p is not None:
                if not p.is_module and name in p.vars:
                    return _pg_unwrap(p.vars[name])
                p = p.parent
            raise NameError(name)
        if name in self.vars:
            return _pg_unwrap(self.vars[name])
        p = self.parent
        while p is not None:
            if name in p.vars:
                return _pg_unwrap(p.vars[name])
            p = p.parent
        if name in self.globals:
            return _pg_unwrap(self.globals[name])
        if name in _PG_BI:
            return _PG_BI[name]
        try:
            return getattr(builtins, name)
        except AttributeError:
            raise NameError(name)

    def set(self, name, value):
        self._check_live(name)
        if name in self.global_names:
            self.globals[name] = value
            return
        if name in self.nonlocal_names:
            p = self.parent
            while p is not None:
                if not p.is_module and name in p.vars:
                    p.vars[name] = value
                    return
                p = p.parent
            raise NameError(name)
        self.vars[name] = value

    def delete(self, name):
        self._check_live(name)
        if name in self.global_names:
            del self.globals[name]
            return
        if name in self.vars:
            del self.vars[name]
            return
        raise NameError(name)


def _pg_freeze_scope(scope):
    try:
        if scope is not None:
            scope._gate['live'] = False
    except Exception:
        pass


# --- user function -------------------------------------------------------

def _pg_ufunc_slot(item):
    if item == '__name__':
        return '_name'
    if item == '__qualname__':
        return '_qualname'
    if item == '__module__':
        return '_module_name'
    if item == '__doc__':
        return '_doc'
    if item == '__annotations__':
        return '_ann'
    return None


def _pg_make_ufunc_blob(args_def, body, is_gen, is_async, defaults, kw_defaults):
    kw_mask = tuple(kd is _MISSING for kd in kw_defaults)
    kw_vals = tuple(None if kd is _MISSING else kd for kd in kw_defaults)
    return _pg_pack_const((
        args_def,
        body,
        bool(is_gen),
        bool(is_async),
        tuple(defaults),
        kw_mask,
        kw_vals,
    ))


def _pg_read_ufunc_blob(blob):
    args_def, body, is_gen, is_async, defaults, kw_mask, kw_vals = _pg_unpack_const(blob)[0]
    kw_defaults = tuple(
        _MISSING if kw_mask[idx] else kw_vals[idx]
        for idx in range(len(kw_vals))
    )
    return args_def, body, is_gen, is_async, tuple(defaults), kw_defaults


class _UFunction:
    """A user-defined function. Acts as a regular Python callable."""

    __slots__ = (
        '_interp', '_scope', '_blob', '_name', '_qualname',
        '_module_name', '_doc', '_ann', 'defining_class',
    )

    def __init__(self, interp, name, defining_scope, blob):
        self._interp = interp
        self._scope = defining_scope
        self._blob = blob
        self._name = name
        self._qualname = name
        self._module_name = '__main__'
        self._doc = None
        self._ann = {}
        self.defining_class = None  # patched after class build for super()

    def __getattribute__(self, item):
        slot = _pg_ufunc_slot(item)
        if slot is not None:
            return object.__getattribute__(self, slot)
        return object.__getattribute__(self, item)

    def __setattr__(self, item, value):
        slot = _pg_ufunc_slot(item)
        if slot is not None:
            object.__setattr__(self, slot, value)
            return
        object.__setattr__(self, item, value)

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return _BoundMethod(self, instance)

    def __call__(self, *args, **kwargs):
        return self._interp.call_user_function(self, args, kwargs)

    def __repr__(self):
        return "<function {} at 0x{:x}>".format(self.__name__, id(self))


class _BoundMethod:
    __slots__ = ('__func__', '__self__')

    def __init__(self, func, instance):
        self.__func__ = func
        self.__self__ = instance

    def __call__(self, *args, **kwargs):
        return self.__func__(self.__self__, *args, **kwargs)

    def __getattr__(self, item):
        return getattr(self.__func__, item)

    def __repr__(self):
        return "<bound method {} of {!r}>".format(
            self.__func__.__name__, self.__self__)


_PGSI_NOARG = object()


class _IslandMachine:
    __slots__ = (
        '_scope', '_iid', '_flags', '_layout', '_slot_layout',
        '_ops', '_unary', '_binary', '_compare',
        '_u8', '_u16', '_seed', '_enc', '_code_len',
        '_state', '_name_seals', '_slot_seals', '_tr', '_hold',
    )

    def __init__(self, payload, scope):
        pos = 5
        island_id = int.from_bytes(payload[pos:pos+4], 'little')
        pos += 4
        flags = payload[pos]
        pos += 1

        pc_i = payload[pos]
        stack_i = payload[pos + 1]
        slot_i = payload[pos + 2]
        scratch_i = payload[pos + 3]
        pos += 4

        slot_flag = payload[pos]
        pos += 1
        if slot_flag:
            slot_name_enc, pos = _pg_si_unpack_const(payload, pos)
        else:
            slot_name_enc = None

        slot_count = int.from_bytes(payload[pos:pos+2], 'little')
        pos += 2
        slot_layout = []
        for _ in range(slot_count):
            slot_layout.append(int.from_bytes(payload[pos:pos+2], 'little'))
            pos += 2

        ops = _PGBT(payload[pos:pos + 20])
        pos += 20
        unary = _PGBT(payload[pos:pos + 4])
        pos += 4
        binary = _PGBT(payload[pos:pos + 13])
        pos += 13
        compare = _PGBT(payload[pos:pos + 10])
        pos += 10

        u8 = []
        for _ in range(4):
            u8.append((payload[pos], payload[pos + 1]))
            pos += 2
        u16 = []
        for _ in range(2):
            add = int.from_bytes(payload[pos:pos+2], 'little')
            xor = int.from_bytes(payload[pos+2:pos+4], 'little')
            pos += 4
            u16.append((add, xor))

        seed = int.from_bytes(payload[pos:pos+4], 'little')
        pos += 4
        code_len = int.from_bytes(payload[pos:pos+2], 'little')
        pos += 2
        enc = _PGBT(payload[pos:pos+code_len])

        state = [None, None, None, None]
        state[pc_i] = 0
        state[stack_i] = []
        state[slot_i] = None
        state[scratch_i] = 0

        if slot_name_enc is not None:
            slot_name = _pg_si_materialize(slot_name_enc, _pg_si_island_key(island_id))
            state[slot_i] = scope.get(slot_name)

        self._scope = scope
        self._iid = island_id
        self._flags = flags
        self._layout = (pc_i, stack_i, slot_i, scratch_i)
        self._slot_layout = tuple(slot_layout)
        self._ops = ops
        self._unary = unary
        self._binary = binary
        self._compare = compare
        self._u8 = tuple(u8)
        self._u16 = tuple(u16)
        self._seed = seed
        self._enc = enc
        self._code_len = code_len
        self._state = state
        self._name_seals = {}
        self._slot_seals = [None] * slot_count
        self._tr = _pg_hashlib.sha256(
            _pg_si_island_key(island_id) + b'|pgsi-transcript|' +
            (island_id & 0xFFFFFFFF).to_bytes(4, 'little')
        ).digest()
        self._hold = None

    def _reverse_stack(self):
        return bool(self._flags & 1)

    def _relative_jumps(self):
        return bool(self._flags & 2)

    def _callee_last(self):
        return bool(self._flags & 4)

    def _pc(self):
        return self._state[self._layout[0]]

    def _set_pc(self, value):
        self._state[self._layout[0]] = value

    def _stack(self):
        return self._state[self._layout[1]]

    def _push(self, value):
        if self._reverse_stack():
            self._stack().insert(0, value)
        else:
            self._stack().append(value)

    def _pop(self):
        if self._reverse_stack():
            return self._stack().pop(0)
        return self._stack().pop()

    def _tick(self, tag, value=b''):
        h = _pg_hashlib.sha256()
        h.update(self._tr)
        h.update(bytes([tag & 0xFF]))
        h.update(_PGBT(value))
        self._tr = h.digest()

    def _key(self):
        return _pg_si_island_key(self._iid)

    def _host_seal(self):
        snap = (
            self._pc(),
            self._state[self._layout[3]],
            tuple(self._stack()),
            tuple(sorted(self._name_seals.items())),
            tuple(self._slot_seals),
        )
        return _pg_hashlib.sha256(
            self._key() + b'|pgsi-host|' + self._tr +
            _pg_si_state_fingerprint(snap)
        ).digest()

    def _resume_host(self, value, raised):
        if self._hold is None:
            if raised is not None:
                raise raised
            return
        if self._hold != self._host_seal():
            raise ValueError('semantic-island machine tampered')
        self._hold = None
        if raised is not None:
            self._tick(0xE2, _pg_si_state_fingerprint(raised))
            raise raised
        self._tick(0xE1, _pg_si_state_fingerprint(value))
        self._push(value)

    def _code_byte(self, idx):
        state = self._seed & 0xFFFFFFFF
        i = 0
        while i <= idx:
            state = ((1103515245 * state) + 12345) & 0xFFFFFFFF
            i += 1
        return self._enc[idx] ^ ((state >> 16) & 0xFF)

    def _u8_raw(self):
        pc = self._pc()
        value = self._code_byte(pc)
        self._set_pc(pc + 1)
        return value

    def _u16_raw(self):
        pc = self._pc()
        value = self._code_byte(pc) | (self._code_byte(pc + 1) << 8)
        self._set_pc(pc + 2)
        return value

    def _dec_u8(self, raw, kind):
        add, xor = self._u8[kind]
        return ((raw ^ xor) - add) & 0xFF

    def _dec_u16(self, raw, kind):
        add, xor = self._u16[kind]
        return ((raw ^ xor) - add) & 0xFFFF

    def _jump_target(self):
        raw = self._dec_u16(self._u16_raw(), 1)
        if self._relative_jumps():
            if raw >= 0x8000:
                raw -= 0x10000
            return self._pc() + raw
        return raw

    def _logical(self, raw):
        for idx, code in enumerate(self._ops):
            if code == raw:
                return idx
        return -1

    def _inline_stream(self, kind, site, n):
        seed = _pg_hashlib.sha256(
            self._key() + b'|pgsi-inline|' +
            bytes([kind & 0xFF]) + site.to_bytes(2, 'little')
        ).digest()
        out = bytearray()
        ctr = 0
        while len(out) < n:
            out.extend(
                _pg_hashlib.sha256(
                    seed + ctr.to_bytes(2, 'little')
                ).digest()
            )
            ctr += 1
        return _PGBT(out[:n])

    def _inline_len_mask(self, kind, site):
        return int.from_bytes(
            _pg_hashlib.sha256(
                self._key() + b'|pgsi-inline-len|' +
                bytes([kind & 0xFF]) + site.to_bytes(2, 'little')
            ).digest()[:2],
            'little',
        )

    def _inline_blob(self, kind, site):
        enc_len = self._u16_raw()
        raw_len = enc_len ^ self._inline_len_mask(kind, site)
        stream = self._inline_stream(kind, site, raw_len)
        out = bytearray(raw_len)
        for i in range(raw_len):
            out[i] = self._u8_raw() ^ stream[i]
        return _PGBT(out)

    def _inline_name(self, site):
        value, _pos = _pg_si_unpack_const(self._inline_blob(1, site), 0)
        return _pg_si_materialize(value, self._key())

    def _inline_const(self, site):
        value, _pos = _pg_si_unpack_const(self._inline_blob(2, site), 0)
        return _pg_si_materialize(value, self._key())

    def _slot_ref(self, idx):
        slot_ref = self._state[self._layout[2]]
        slot_idx = self._slot_layout[idx]
        value = slot_ref[slot_idx]
        seal = self._slot_seals[idx]
        key = self._key()
        if seal is None:
            self._slot_seals[idx] = _pg_si_state_seal(key, slot_idx, value)
        elif seal != _pg_si_state_seal(key, slot_idx, value):
            raise ValueError('semantic-island slot state tampered')
        return value

    def _slot_store(self, idx, value):
        slot_ref = self._state[self._layout[2]]
        slot_idx = self._slot_layout[idx]
        slot_ref[slot_idx] = value
        self._slot_seals[idx] = _pg_si_state_seal(self._key(), slot_idx, value)

    def _load_name_value(self, site):
        name = self._inline_name(site)
        value = self._scope.get(name)
        seal = self._name_seals.get(name)
        key = self._key()
        tag = _pg_si_state_seal(key, 0x80000000, value)
        if seal is None:
            self._name_seals[name] = tag
        elif seal != tag:
            raise ValueError('semantic-island name state tampered')
        return value

    def _store_name_value(self, site, value):
        name = self._inline_name(site)
        self._scope.set(name, value)
        self._name_seals[name] = _pg_si_state_seal(
            self._key(), 0x80000000, value)

    def _scrub(self):
        try:
            if isinstance(self._state, list):
                for idx in range(len(self._state)):
                    self._state[idx] = None
        except Exception:
            pass
        self._scope = None
        self._slot_layout = ()
        self._ops = b''
        self._unary = b''
        self._binary = b''
        self._compare = b''
        self._u8 = ()
        self._u16 = ()
        self._enc = b''
        self._code_len = 0
        self._name_seals = {}
        self._slot_seals = []
        self._tr = b''
        self._hold = None

    def run(self, value=_PGSI_NOARG, raised=None):
        self._resume_host(value, raised)
        while self._pc() < self._code_len:
            pc = self._pc()
            raw = self._code_byte(pc)
            self._state[self._layout[3]] = raw
            self._set_pc(pc + 1)
            self._tick(0xA0, bytes([raw, pc & 0xFF, (pc >> 8) & 0xFF]))
            op = self._logical(raw)
            if op == 0:
                self._push(self._inline_const(pc))
                continue
            if op == 1:
                self._push(self._load_name_value(pc))
                continue
            if op == 2:
                idx = self._dec_u16(self._u16_raw(), 0)
                self._push(self._slot_ref(idx))
                continue
            if op == 3:
                self._store_name_value(pc, self._pop())
                continue
            if op == 4:
                idx = self._dec_u16(self._u16_raw(), 0)
                self._slot_store(idx, self._pop())
                continue
            if op == 5:
                key = self._pop()
                obj = self._pop()
                self._push(obj[key])
                continue
            if op == 6:
                n = self._dec_u8(self._u8_raw(), 0)
                vals = [self._pop() for _ in range(n)]
                vals.reverse()
                self._push(vals)
                continue
            if op == 7:
                n = self._dec_u8(self._u8_raw(), 0)
                vals = [self._pop() for _ in range(n)]
                vals.reverse()
                self._push(tuple(vals))
                continue
            if op == 8:
                self._pop()
                continue
            if op == 9:
                argc = self._dec_u8(self._u8_raw(), 0)
                if self._callee_last():
                    fn = self._pop()
                    args = [self._pop() for _ in range(argc)]
                    args.reverse()
                else:
                    args = [self._pop() for _ in range(argc)]
                    args.reverse()
                    fn = self._pop()
                self._tick(0xC1, _pg_si_state_fingerprint((fn, tuple(args))))
                self._hold = self._host_seal()
                return fn, tuple(args)
            if op == 10:
                raw_id = self._dec_u8(self._u8_raw(), 1)
                opid = self._unary.find(bytes([raw_id])) + 1
                self._push(_pg_si_unary(opid, self._pop()))
                continue
            if op == 11:
                raw_id = self._dec_u8(self._u8_raw(), 2)
                opid = self._binary.find(bytes([raw_id])) + 1
                right = self._pop()
                left = self._pop()
                self._push(_pg_si_binary(opid, left, right))
                continue
            if op == 12:
                raw_id = self._dec_u8(self._u8_raw(), 3)
                opid = self._compare.find(bytes([raw_id])) + 1
                right = self._pop()
                left = self._pop()
                self._push(_pg_si_compare(opid, left, right))
                continue
            if op == 13:
                self._set_pc(self._jump_target())
                continue
            if op == 14:
                target = self._jump_target()
                if not self._pop():
                    self._set_pc(target)
                continue
            if op == 15:
                target = self._jump_target()
                if self._pop():
                    self._set_pc(target)
                continue
            if op == 16:
                raise _Return(self._pop() if self._stack() else None)
            if op == 17:
                raise _Break()
            if op == 18:
                raise _Continue()
            if op == 19:
                raise self._pop()
            raise ValueError('bad island opcode')
        return None


# --- driver helpers ------------------------------------------------------

def _drive_sync(gen):
    """Drive a step-generator that should not yield events (sync context)."""
    try:
        evt = next(gen)
    except StopIteration as si:
        return si.value
    raise RuntimeError("yield/await outside generator/coroutine: " + repr(evt))


# --- interpreter ---------------------------------------------------------

class Interp:
    """Holds an opaque accessor closure instead of plain strings/consts
    tuples. Callers build `(_a)` where `_a(kind, idx)` is a closure holding
    ENCRYPTED byte buffers (v6.5 / C17); the only handle on them is the
    returned closure, which has no stable name across builds.

    v6.5 / C14 — `__slots__` prevents `__dict__` creation on instances.
    A gc.get_objects() walk that filters by `hasattr(o, '__dict__')` and
    reads `o.__dict__['_a']` (the c12 pivot) finds nothing: slotted
    instances have no __dict__, so the attack misses Interp entirely and
    falls back to scanning for bare closures — which, thanks to C17,
    hold ciphertext.

    Also: the leaky `_str_cache` was dropped. Each access re-decrypts the
    requested entry via the accessor; no plaintext accumulates anywhere
    in Python-reachable memory across the lifetime of the interpreter.
    """

    __slots__ = ('_a',)

    def __init__(self, *_args):
        # Vararg signature: `co_argcount == 1` (self), indistinguishable
        # from dozens of other methods. A fixed-arity signature like
        # `__init__(self, _a, _decoy_a=None, _decoy_b=None, _decoy_c=None)`
        # gives `co_argcount == 5` — a structural fingerprint that locates
        # the Interp class regardless of name obfuscation.
        #
        # `_args[0]` MUST be the accessor closure `_a`. Remaining entries
        # are decoys (ignored).
        if not _args:
            raise TypeError("Interp: missing accessor")
        # `_a(0, idx)` returns raw (possibly mask-encoded) strings table entry.
        # `_a(1, idx)` returns the decoded const table entry.
        self._a = _args[0]

    def s(self, idx):
        if idx is None or idx < 0:
            return None
        return _pg_text(self._a(0, idx))

    def k(self, idx):
        return self._a(1, idx)

    # ---- entry point ----

    def run(self, tree, module_name='__main__'):
        # Each user call goes through several Python frames in our step
        # generators, so the host limit must be raised proportionally.
        try:
            cur = sys.getrecursionlimit()
            if cur < 50000:
                sys.setrecursionlimit(50000)
        except Exception:
            pass
        try:
            runtime_file = globals().get('_PG_FILE')
        except Exception:
            runtime_file = None
        glob = {
            '__name__': module_name,
            '__builtins__': builtins,
            '__doc__': None,
            '__annotations__': {},
            '__package__': None,
            '__loader__': None,
            '__spec__': None,
        }
        if isinstance(runtime_file, str) and runtime_file:
            glob['__file__'] = runtime_file
        scope = Scope(globals_=glob, is_module=True)
        try:
            if isinstance(tree, tuple) and tree and _pg_tag(tree[0]) == 'Code':
                _drive_sync(self.exec_code(tree, scope))
            else:
                _drive_sync(self.step_block(_nf(tree, 'body'), scope))
        except _Return:
            pass
        except BaseException:
            _pg_freeze_scope(scope)
            raise

    # ---- statement stepper (generator-of-events) ----

    def step_block(self, body, scope):
        if False:
            yield  # mark as generator
        for stmt in body:
            yield from self.step_stmt(stmt, scope)

    def exec_code(self, code, scope):
        if False:
            yield
        if isinstance(code, tuple) and code and _pg_tag(code[0]) == 'Code':
            for inst in _nf(code, 'instrs'):
                yield from self.step_inst(inst, scope)
            return
        yield from self.step_block(code, scope)

    def _exec_body(self, body, scope):
        if False:
            yield
        if isinstance(body, tuple) and body and _pg_tag(body[0]) == 'Code':
            yield from self.exec_code(body, scope)
            return
        yield from self.step_block(body, scope)

    def _bind_import_lookup(self, node, scope):
        if False:
            yield
        for bind_idx, import_id in zip(_nf(node, 'binds'), _nf(node, 'ids')):
            value = _PG_IMP[import_id]
            if isinstance(value, BaseException):
                raise value
            scope.set(self.s(bind_idx), value)

    def _bind_import(self, aliases, scope):
        if False:
            yield
        for alias in aliases:
            name = self.s(_nf(alias, 'name'))
            asname = self.s(_nf(alias, 'asname'))
            mod = __import__(name, scope.globals, None, (), 0)
            if asname is not None:
                target = mod
                for p in name.split('.')[1:]:
                    target = getattr(target, p)
                scope.set(asname, target)
            else:
                scope.set(name.split('.')[0], mod)

    def _bind_import_from(self, node, scope):
        if False:
            yield
        module = self.s(_nf(node, 'module')) or ''
        level = _nf(node, 'level')
        fromlist = tuple(self.s(_nf(a, 'name')) for a in _nf(node, 'names'))
        mod = __import__(module, scope.globals, None, fromlist, level)
        for alias in _nf(node, 'names'):
            name = self.s(_nf(alias, 'name'))
            asname = self.s(_nf(alias, 'asname'))
            bind = asname if asname is not None else name
            if name == '*':
                if hasattr(mod, '__all__'):
                    for k in mod.__all__:
                        scope.set(k, getattr(mod, k))
                else:
                    for k in dir(mod):
                        if not k.startswith('_'):
                            scope.set(k, getattr(mod, k))
            else:
                scope.set(bind, getattr(mod, name))

    def _run_island(self, payload, scope):
        if isinstance(payload, list):
            payload = _PGBT(payload)
        elif not isinstance(payload, (bytes, bytearray)):
            payload = _PGBT(payload)
        payload = _PGBT(payload)
        if payload[:5] == b'PGSI1':
            pos = 5
            slot_len = int.from_bytes(payload[pos:pos+2], 'little')
            pos += 2
            if slot_len == 0xFFFF:
                slot_name = None
            else:
                slot_name = payload[pos:pos+slot_len].decode('utf-8')
                pos += slot_len
            name_count = int.from_bytes(payload[pos:pos+2], 'little')
            pos += 2
            names = []
            for _ in range(name_count):
                n = int.from_bytes(payload[pos:pos+2], 'little')
                pos += 2
                names.append(payload[pos:pos+n].decode('utf-8'))
                pos += n
            const_count = int.from_bytes(payload[pos:pos+2], 'little')
            pos += 2
            consts = []
            for _ in range(const_count):
                value, pos = _pg_si_unpack_const_v1(payload, pos)
                consts.append(value)
            logical = (
                'LOAD_CONST', 'LOAD_NAME', 'LOAD_SLOT',
                'STORE_NAME', 'STORE_SLOT',
                'LOAD_SUBSCR',
                'BUILD_LIST', 'BUILD_TUPLE',
                'POP', 'CALL',
                'UNARY', 'BINARY', 'COMPARE',
                'JUMP', 'JUMP_IF_FALSE', 'JUMP_IF_TRUE',
                'RETURN', 'BREAK', 'CONTINUE', 'RAISE',
            )
            opmap = {}
            for name in logical:
                opmap[payload[pos]] = name
                pos += 1
            seed = int.from_bytes(payload[pos:pos+4], 'little')
            pos += 4
            code_len = int.from_bytes(payload[pos:pos+2], 'little')
            pos += 2
            enc = payload[pos:pos+code_len]
            mask = _pg_si_mask_stream(seed, code_len)
            code = _PGBT(enc[i] ^ mask[i] for i in range(code_len))
            stack = []
            pc = 0
            slot_ref = scope.get(slot_name) if slot_name is not None else None

            def _u8():
                nonlocal pc
                v = code[pc]
                pc += 1
                return v

            def _u16():
                nonlocal pc
                v = code[pc] | (code[pc + 1] << 8)
                pc += 2
                return v

            while pc < code_len:
                op = opmap.get(code[pc])
                pc += 1
                if op == 'LOAD_CONST':
                    stack.append(consts[_u16()])
                    continue
                if op == 'LOAD_NAME':
                    stack.append(scope.get(names[_u16()]))
                    continue
                if op == 'LOAD_SLOT':
                    stack.append(slot_ref[_u16()])
                    continue
                if op == 'STORE_NAME':
                    scope.set(names[_u16()], stack.pop())
                    continue
                if op == 'STORE_SLOT':
                    slot_ref[_u16()] = stack.pop()
                    continue
                if op == 'LOAD_SUBSCR':
                    key = stack.pop()
                    obj = stack.pop()
                    stack.append(obj[key])
                    continue
                if op == 'BUILD_LIST':
                    n = _u8()
                    vals = [stack.pop() for _ in range(n)]
                    vals.reverse()
                    stack.append(vals)
                    continue
                if op == 'BUILD_TUPLE':
                    n = _u8()
                    vals = [stack.pop() for _ in range(n)]
                    vals.reverse()
                    stack.append(tuple(vals))
                    continue
                if op == 'POP':
                    stack.pop()
                    continue
                if op == 'CALL':
                    argc = _u8()
                    args = [stack.pop() for _ in range(argc)]
                    args.reverse()
                    fn = stack.pop()
                    stack.append(_pg_call_host(scope, fn, tuple(args)))
                    continue
                if op == 'UNARY':
                    stack.append(_pg_si_unary(_u8(), stack.pop()))
                    continue
                if op == 'BINARY':
                    right = stack.pop()
                    left = stack.pop()
                    stack.append(_pg_si_binary(_u8(), left, right))
                    continue
                if op == 'COMPARE':
                    right = stack.pop()
                    left = stack.pop()
                    stack.append(_pg_si_compare(_u8(), left, right))
                    continue
                if op == 'JUMP':
                    pc = _u16()
                    continue
                if op == 'JUMP_IF_FALSE':
                    target = _u16()
                    if not stack.pop():
                        pc = target
                    continue
                if op == 'JUMP_IF_TRUE':
                    target = _u16()
                    if stack.pop():
                        pc = target
                    continue
                if op == 'RETURN':
                    raise _Return(stack.pop() if stack else None)
                if op == 'BREAK':
                    raise _Break()
                if op == 'CONTINUE':
                    raise _Continue()
                if op == 'RAISE':
                    raise stack.pop()
                raise ValueError('bad island opcode')
            return

        if payload[:5] != b'PGSI2':
            raise ValueError('bad island payload')

        machine = _IslandMachine(payload, scope)
        value = _PGSI_NOARG
        raised = None
        try:
            while True:
                request = machine.run(value, raised)
                value = _PGSI_NOARG
                raised = None
                if request is None:
                    return
                fn, args = request
                try:
                    value = _pg_call_host(scope, fn, args)
                except BaseException as exc:
                    raised = exc
        except BaseException as exc:
            try:
                machine._scrub()
            except Exception:
                pass
            raise exc.with_traceback(None)
        finally:
            try:
                machine._scrub()
            except Exception:
                pass

    def step_inst(self, node, scope):
        if False:
            yield
        op = _pg_tag(node[0])

        if op == 'IPass':
            return

        if op == 'IExpr':
            yield from self.step_expr(_nf(node, 'value'), scope)
            return

        if op == 'IIsland':
            self._run_island(_nf(node, 'payload'), scope)
            return

        if op == 'IReturn':
            v = None
            value = _nf(node, 'value')
            if value is not None:
                v = yield from self.step_expr(value, scope)
            raise _Return(v)

        if op == 'IRaise':
            exc = None
            cause = None
            exc_node = _nf(node, 'exc')
            cause_node = _nf(node, 'cause')
            if exc_node is not None:
                exc = yield from self.step_expr(exc_node, scope)
            if cause_node is not None:
                cause = yield from self.step_expr(cause_node, scope)
            if exc is None:
                raise
            if cause is not None:
                raise exc from cause
            raise exc

        if op == 'IBreak':
            raise _Break()

        if op == 'IContinue':
            raise _Continue()

        if op == 'IDelete':
            for tgt in _nf(node, 'targets'):
                yield from self._delete(tgt, scope)
            return

        if op == 'IGlobal':
            for n in _nf(node, 'names'):
                scope.global_names.add(self.s(n))
            return

        if op == 'INonlocal':
            for n in _nf(node, 'names'):
                scope.nonlocal_names.add(self.s(n))
            return

        if op == 'IAssign':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            for tgt in _nf(node, 'targets'):
                yield from self._assign(tgt, v, scope)
            return

        if op == 'IAugAssign':
            tgt = _nf(node, 'target')
            cur = yield from self._load_target(tgt, scope)
            inc = yield from self.step_expr(_nf(node, 'value'), scope)
            _ot = _pg_tag(_nf(node, 'op2'))
            if   _ot == 'Add':      new_v = cur + inc
            elif _ot == 'Sub':      new_v = cur - inc
            elif _ot == 'Mult':     new_v = cur * inc
            elif _ot == 'FloorDiv': new_v = cur // inc
            elif _ot == 'Div':      new_v = cur / inc
            elif _ot == 'Mod':      new_v = cur % inc
            elif _ot == 'Pow':      new_v = cur ** inc
            elif _ot == 'BitOr':    new_v = cur | inc
            elif _ot == 'BitXor':   new_v = cur ^ inc
            elif _ot == 'BitAnd':   new_v = cur & inc
            elif _ot == 'LShift':   new_v = cur << inc
            elif _ot == 'RShift':   new_v = cur >> inc
            elif _ot == 'MatMult':  new_v = cur @ inc
            else: raise ValueError(_ot)
            yield from self._assign(tgt, new_v, scope)
            return

        if op == 'IAnnAssign':
            ann_v = yield from self.step_expr(_nf(node, 'annotation'), scope)
            value = _nf(node, 'value')
            target = _nf(node, 'target')
            if value is not None:
                v = yield from self.step_expr(value, scope)
                yield from self._assign(target, v, scope)
            if _nf(node, 'simple', False) and _pg_tag(target[0]) == 'Name':
                name = self.s(_nf(target, 'id'))
                if '__annotations__' in scope.vars:
                    scope.vars['__annotations__'][name] = ann_v
            return

        if op == 'IIf':
            test = yield from self.step_expr(_nf(node, 'test'), scope)
            yield from self._exec_body(
                _nf(node, 'body') if test else _nf(node, 'orelse'), scope)
            return

        if op == 'IWhile':
            broke = False
            while True:
                test = yield from self.step_expr(_nf(node, 'test'), scope)
                if not test:
                    break
                try:
                    yield from self._exec_body(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self._exec_body(_nf(node, 'orelse'), scope)
            return

        if op == 'IFor':
            iter_val = yield from self.step_expr(_nf(node, 'iter'), scope)
            broke = False
            for item in iter_val:
                yield from self._assign(_nf(node, 'target'), item, scope)
                try:
                    yield from self._exec_body(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self._exec_body(_nf(node, 'orelse'), scope)
            return

        if op == 'IAsyncFor':
            ait_val = yield from self.step_expr(_nf(node, 'iter'), scope)
            ait = ait_val.__aiter__()
            broke = False
            while True:
                try:
                    item = yield ('await', ait.__anext__())
                except StopAsyncIteration:
                    break
                yield from self._assign(_nf(node, 'target'), item, scope)
                try:
                    yield from self._exec_body(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self._exec_body(_nf(node, 'orelse'), scope)
            return

        if op == 'IWith':
            yield from self._do_with(_nf(node, 'items'), 0, _nf(node, 'body'), scope, False)
            return

        if op == 'IAsyncWith':
            yield from self._do_with(_nf(node, 'items'), 0, _nf(node, 'body'), scope, True)
            return

        if op == 'ITry':
            yield from self._do_try(node, scope)
            return

        if op == 'IImportLookup':
            yield from self._bind_import_lookup(node, scope)
            return

        if op == 'IImport':
            yield from self._bind_import(_nf(node, 'names'), scope)
            return

        if op == 'IImportFrom':
            yield from self._bind_import_from(node, scope)
            return

        if op == 'IFunctionDef':
            yield from self._define_function(node, scope, _nf(node, 'is_async', False))
            return

        if op == 'IClassDef':
            yield from self._define_class(node, scope)
            return

        yield from self.step_stmt(node, scope)

    def step_stmt(self, node, scope):
        if False:
            yield
        op = _pg_tag(node[0])

        if op == 'Pass':
            return

        if op == 'Expr':
            yield from self.step_expr(_nf(node, 'value'), scope)
            return

        if op == 'Return':
            v = None
            value = _nf(node, 'value')
            if value is not None:
                v = yield from self.step_expr(value, scope)
            raise _Return(v)

        if op == 'Raise':
            exc = None
            cause = None
            exc_node = _nf(node, 'exc')
            cause_node = _nf(node, 'cause')
            if exc_node is not None:
                exc = yield from self.step_expr(exc_node, scope)
            if cause_node is not None:
                cause = yield from self.step_expr(cause_node, scope)
            if exc is None:
                raise
            if cause is not None:
                raise exc from cause
            raise exc

        if op == 'Break':
            raise _Break()

        if op == 'Continue':
            raise _Continue()

        if op == 'Delete':
            for tgt in _nf(node, 'targets'):
                yield from self._delete(tgt, scope)
            return

        if op == 'Global':
            for n in _nf(node, 'names'):
                scope.global_names.add(self.s(n))
            return

        if op == 'Nonlocal':
            for n in _nf(node, 'names'):
                scope.nonlocal_names.add(self.s(n))
            return

        if op == 'Assign':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            for tgt in _nf(node, 'targets'):
                yield from self._assign(tgt, v, scope)
            return

        if op == 'AugAssign':
            tgt = _nf(node, 'target')
            cur = yield from self._load_target(tgt, scope)
            inc = yield from self.step_expr(_nf(node, 'value'), scope)
            _ot = _pg_tag(_nf(node, 'op2'))
            if   _ot == 'Add':      new_v = cur + inc
            elif _ot == 'Sub':      new_v = cur - inc
            elif _ot == 'Mult':     new_v = cur * inc
            elif _ot == 'FloorDiv': new_v = cur // inc
            elif _ot == 'Div':      new_v = cur / inc
            elif _ot == 'Mod':      new_v = cur % inc
            elif _ot == 'Pow':      new_v = cur ** inc
            elif _ot == 'BitOr':    new_v = cur | inc
            elif _ot == 'BitXor':   new_v = cur ^ inc
            elif _ot == 'BitAnd':   new_v = cur & inc
            elif _ot == 'LShift':   new_v = cur << inc
            elif _ot == 'RShift':   new_v = cur >> inc
            elif _ot == 'MatMult':  new_v = cur @ inc
            else: raise ValueError(_ot)
            yield from self._assign(tgt, new_v, scope)
            return

        if op == 'AnnAssign':
            ann_v = yield from self.step_expr(_nf(node, 'annotation'), scope)
            value = _nf(node, 'value')
            target = _nf(node, 'target')
            if value is not None:
                v = yield from self.step_expr(value, scope)
                yield from self._assign(target, v, scope)
            if _nf(node, 'simple', False) and _pg_tag(target[0]) == 'Name':
                name = self.s(_nf(target, 'id'))
                if '__annotations__' in scope.vars:
                    scope.vars['__annotations__'][name] = ann_v
            return

        if op == 'If':
            test = yield from self.step_expr(_nf(node, 'test'), scope)
            yield from self.step_block(
                _nf(node, 'body') if test else _nf(node, 'orelse'), scope)
            return

        if op == 'While':
            broke = False
            while True:
                test = yield from self.step_expr(_nf(node, 'test'), scope)
                if not test:
                    break
                try:
                    yield from self.step_block(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self.step_block(_nf(node, 'orelse'), scope)
            return

        if op == 'For':
            iter_val = yield from self.step_expr(_nf(node, 'iter'), scope)
            broke = False
            for item in iter_val:
                yield from self._assign(_nf(node, 'target'), item, scope)
                try:
                    yield from self.step_block(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self.step_block(_nf(node, 'orelse'), scope)
            return

        if op == 'AsyncFor':
            ait_val = yield from self.step_expr(_nf(node, 'iter'), scope)
            ait = ait_val.__aiter__()
            broke = False
            while True:
                try:
                    item = yield ('await', ait.__anext__())
                except StopAsyncIteration:
                    break
                yield from self._assign(_nf(node, 'target'), item, scope)
                try:
                    yield from self.step_block(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self.step_block(_nf(node, 'orelse'), scope)
            return

        if op == 'With':
            yield from self._do_with(_nf(node, 'items'), 0, _nf(node, 'body'), scope, False)
            return

        if op == 'AsyncWith':
            yield from self._do_with(_nf(node, 'items'), 0, _nf(node, 'body'), scope, True)
            return

        if op == 'Try':
            yield from self._do_try(node, scope)
            return

        if op == 'ImportLookup':
            yield from self._bind_import_lookup(node, scope)
            return

        if op == 'Import':
            yield from self._bind_import(_nf(node, 'names'), scope)
            return

        if op == 'ImportFrom':
            yield from self._bind_import_from(node, scope)
            return

        if op == 'FunctionDef' or op == 'AsyncFunctionDef':
            yield from self._define_function(node, scope, op == 'AsyncFunctionDef')
            return

        if op == 'ClassDef':
            yield from self._define_class(node, scope)
            return

        raise NotImplementedError("step_stmt: " + op)

    # ---- expression stepper ----

    def step_expr(self, node, scope):
        if False:
            yield
        op = _pg_tag(node[0])

        if op == 'Constant':
            return self.k(_nf(node, 'idx'))

        if op == 'Name':
            return scope.get(self.s(_nf(node, 'id')))

        if op == 'BinOp':
            l = yield from self.step_expr(_nf(node, 'left'), scope)
            r = yield from self.step_expr(_nf(node, 'right'), scope)
            _ot = _pg_tag(_nf(node, 'op2'))
            if   _ot == 'Add':      return l + r
            elif _ot == 'Sub':      return l - r
            elif _ot == 'Mult':     return l * r
            elif _ot == 'FloorDiv': return l // r
            elif _ot == 'Div':      return l / r
            elif _ot == 'Mod':      return l % r
            elif _ot == 'Pow':      return l ** r
            elif _ot == 'BitOr':    return l | r
            elif _ot == 'BitXor':   return l ^ r
            elif _ot == 'BitAnd':   return l & r
            elif _ot == 'LShift':   return l << r
            elif _ot == 'RShift':   return l >> r
            elif _ot == 'MatMult':  return l @ r
            raise ValueError(_ot)

        if op == 'UnaryOp':
            v = yield from self.step_expr(_nf(node, 'operand'), scope)
            _ot = _pg_tag(_nf(node, 'op2'))
            if   _ot == 'USub':   return -v
            elif _ot == 'UAdd':   return +v
            elif _ot == 'Not':    return not v
            elif _ot == 'Invert': return ~v
            raise ValueError(_ot)

        if op == 'BoolOp':
            if _pg_tag(_nf(node, 'op2')) == 'And':
                last = True
                for vn in _nf(node, 'values'):
                    last = yield from self.step_expr(vn, scope)
                    if not last:
                        return last
                return last
            else:
                last = False
                for vn in _nf(node, 'values'):
                    last = yield from self.step_expr(vn, scope)
                    if last:
                        return last
                return last

        if op == 'Compare':
            left = yield from self.step_expr(_nf(node, 'left'), scope)
            for cmp_op, cn in zip(_nf(node, 'ops'), _nf(node, 'comparators')):
                right = yield from self.step_expr(cn, scope)
                _ot = _pg_tag(cmp_op)
                if   _ot == 'Eq':    ok = left == right
                elif _ot == 'NotEq': ok = left != right
                elif _ot == 'Lt':    ok = left < right
                elif _ot == 'LtE':   ok = left <= right
                elif _ot == 'Gt':    ok = left > right
                elif _ot == 'GtE':   ok = left >= right
                elif _ot == 'In':    ok = left in right
                elif _ot == 'NotIn': ok = left not in right
                elif _ot == 'Is':    ok = left is right
                elif _ot == 'IsNot': ok = left is not right
                else: raise ValueError(_ot)
                if not ok:
                    return False
                left = right
            return True

        if op == 'IfExp':
            test = yield from self.step_expr(_nf(node, 'test'), scope)
            if test:
                v = yield from self.step_expr(_nf(node, 'body'), scope)
            else:
                v = yield from self.step_expr(_nf(node, 'orelse'), scope)
            return v

        if op == 'Call':
            func = yield from self.step_expr(_nf(node, 'func'), scope)
            # Intercept zero-arg super() so it works without the magic cell.
            if (func is builtins.super
                    and not _nf(node, 'args') and not _nf(node, 'keywords')):
                cls_v = self._lookup_magic(scope, '__pyguard_class__')
                self_v = self._lookup_magic(scope, '__pyguard_self__')
                if cls_v is not None and self_v is not None:
                    return builtins.super(cls_v, self_v)
                return builtins.super()
            # Intercept builtins.globals() / builtins.locals() so they
            # return the user's simulated module namespace object, not the
            # interpreter module's native Python globals. `_PgGlobals` keeps
            # the backing storage live for write-through compatibility while
            # storing module-scope str/bytes opaquely at rest.
            if (func is builtins.globals
                    and not _nf(node, 'args') and not _nf(node, 'keywords')):
                return scope.globals
            if (func is builtins.locals
                    and not _nf(node, 'args') and not _nf(node, 'keywords')):
                if scope.vars is scope.globals:
                    return scope.vars
                return scope.vars
            args = []
            for a in _nf(node, 'args'):
                if _pg_tag(a[0]) == 'Starred':
                    sv = yield from self.step_expr(_nf(a, 'value'), scope)
                    args.extend(sv)
                else:
                    av = yield from self.step_expr(a, scope)
                    args.append(av)
            kwargs = {}
            for kw in _nf(node, 'keywords'):
                arg_idx = _nf(kw, 'arg')
                if arg_idx is None or arg_idx < 0:
                    kv = yield from self.step_expr(_nf(kw, 'value'), scope)
                    kwargs.update(kv)
                else:
                    kv = yield from self.step_expr(_nf(kw, 'value'), scope)
                    kwargs[self.s(arg_idx)] = kv
            return _pg_call_host(scope, func, tuple(args), kwargs)

        if op == 'Attribute':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            return getattr(v, self.s(_nf(node, 'attr')))

        if op == 'Subscript':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            sl = yield from self._eval_slice(_nf(node, 'slice'), scope)
            return v[sl]

        if op == 'Slice':
            return (yield from self._eval_slice(node, scope))

        if op == 'List':
            elts = []
            for e in _nf(node, 'elts'):
                if _pg_tag(e[0]) == 'Starred':
                    sv = yield from self.step_expr(_nf(e, 'value'), scope)
                    elts.extend(sv)
                else:
                    ev = yield from self.step_expr(e, scope)
                    elts.append(ev)
            return elts

        if op == 'Tuple':
            elts = []
            for e in _nf(node, 'elts'):
                if _pg_tag(e[0]) == 'Starred':
                    sv = yield from self.step_expr(_nf(e, 'value'), scope)
                    elts.extend(sv)
                else:
                    ev = yield from self.step_expr(e, scope)
                    elts.append(ev)
            return tuple(elts)

        if op == 'Set':
            out = set()
            for e in _nf(node, 'elts'):
                if _pg_tag(e[0]) == 'Starred':
                    sv = yield from self.step_expr(_nf(e, 'value'), scope)
                    out.update(sv)
                else:
                    ev = yield from self.step_expr(e, scope)
                    out.add(ev)
            return out

        if op == 'Dict':
            d = {}
            for kn, vn in zip(_nf(node, 'keys'), _nf(node, 'values')):
                if kn is None:
                    vv = yield from self.step_expr(vn, scope)
                    d.update(vv)
                else:
                    kv = yield from self.step_expr(kn, scope)
                    vv = yield from self.step_expr(vn, scope)
                    d[kv] = vv
            return d

        if op == 'Lambda':
            # Pre-evaluate defaults
            args_def = _nf(node, 'args')
            defaults = []
            for d in _nf(args_def, 'defaults'):
                dv = yield from self.step_expr(d, scope)
                defaults.append(dv)
            kw_defaults = []
            for kd in _nf(args_def, 'kw_defaults'):
                if kd is None:
                    kw_defaults.append(_MISSING)
                else:
                    kdv = yield from self.step_expr(kd, scope)
                    kw_defaults.append(kdv)
            # Wrap body as Return statement so the function path works
            wrapped = (('Return', _nf(node, 'body')),)
            blob = _pg_make_ufunc_blob(
                args_def, wrapped, False, False, defaults, kw_defaults)
            return _UFunction(self, '<lambda>', scope, blob)

        if op == 'ListComp':
            return (yield from self._eval_comp('list', node, scope))
        if op == 'SetComp':
            return (yield from self._eval_comp('set', node, scope))
        if op == 'DictComp':
            return (yield from self._eval_comp('dict', node, scope))
        if op == 'GeneratorExp':
            return (yield from self._eval_genexp(node, scope))

        if op == 'JoinedStr':
            parts = []
            for vn in _nf(node, 'values'):
                v = yield from self.step_expr(vn, scope)
                parts.append(v if isinstance(v, str) else str(v))
            return ''.join(parts)

        if op == 'FormattedValue':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            conv = _nf(node, 'conversion')
            if conv == 115:
                v = str(v)
            elif conv == 114:
                v = repr(v)
            elif conv == 97:
                v = ascii(v)
            spec = ''
            if _nf(node, 'format_spec') is not None:
                spec = yield from self.step_expr(_nf(node, 'format_spec'), scope)
            return format(v, spec)

        if op == 'Yield':
            v = None
            if _nf(node, 'value') is not None:
                v = yield from self.step_expr(_nf(node, 'value'), scope)
            sent = yield ('yield', v)
            return sent

        if op == 'YieldFrom':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            it = iter(v)
            result = None
            while True:
                try:
                    item = next(it)
                except StopIteration as si:
                    result = si.value
                    break
                yield ('yield', item)
            return result

        if op == 'Await':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            r = yield ('await', v)
            return r

        if op == 'NamedExpr':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            yield from self._assign(_nf(node, 'target'), v, scope)
            return v

        if op == 'Starred':
            return (yield from self.step_expr(_nf(node, 'value'), scope))

        raise NotImplementedError("step_expr: " + op)

    # ---- assignment / lvalue helpers ----

    def _assign(self, target, value, scope):
        if False:
            yield
        op = _pg_tag(target[0])
        if op == 'Name':
            scope.set(self.s(_nf(target, 'id')), value)
            return
        if op == 'Tuple' or op == 'List':
            elts = _nf(target, 'elts')
            star_idx = None
            for i, e in enumerate(elts):
                if _pg_tag(e[0]) == 'Starred':
                    star_idx = i
                    break
            if star_idx is None:
                vlist = list(value)
                if len(vlist) != len(elts):
                    raise ValueError(
                        "expected {} values, got {}".format(
                            len(elts), len(vlist)))
                for e, v in zip(elts, vlist):
                    yield from self._assign(e, v, scope)
            else:
                vlist = list(value)
                n_before = star_idx
                n_after = len(elts) - star_idx - 1
                if len(vlist) < n_before + n_after:
                    raise ValueError("not enough values to unpack")
                for i in range(n_before):
                    yield from self._assign(elts[i], vlist[i], scope)
                star_count = len(vlist) - n_before - n_after
                yield from self._assign(
                    _nf(elts[star_idx], 'value'),
                    vlist[n_before:n_before + star_count],
                    scope)
                for j in range(n_after):
                    yield from self._assign(
                        elts[star_idx + 1 + j],
                        vlist[n_before + star_count + j],
                        scope)
            return
        if op == 'Attribute':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            setattr(obj, self.s(_nf(target, 'attr')), value)
            return
        if op == 'Subscript':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            sl = yield from self._eval_slice(_nf(target, 'slice'), scope)
            obj[sl] = value
            return
        if op == 'Starred':
            yield from self._assign(_nf(target, 'value'), value, scope)
            return
        raise NotImplementedError("_assign: " + op)

    def _delete(self, target, scope):
        if False:
            yield
        op = _pg_tag(target[0])
        if op == 'Name':
            scope.delete(self.s(_nf(target, 'id')))
            return
        if op == 'Attribute':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            delattr(obj, self.s(_nf(target, 'attr')))
            return
        if op == 'Subscript':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            sl = yield from self._eval_slice(_nf(target, 'slice'), scope)
            del obj[sl]
            return
        if op == 'Tuple' or op == 'List':
            for e in _nf(target, 'elts'):
                yield from self._delete(e, scope)
            return
        raise NotImplementedError("_delete: " + op)

    def _load_target(self, target, scope):
        if False:
            yield
        op = _pg_tag(target[0])
        if op == 'Name':
            return scope.get(self.s(_nf(target, 'id')))
        if op == 'Attribute':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            return getattr(obj, self.s(_nf(target, 'attr')))
        if op == 'Subscript':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            sl = yield from self._eval_slice(_nf(target, 'slice'), scope)
            return obj[sl]
        raise NotImplementedError("_load_target: " + op)

    def _eval_slice(self, node, scope):
        if False:
            yield
        if _pg_tag(node[0]) == 'Slice':
            l = None
            u = None
            s = None
            if _nf(node, 'lower') is not None:
                l = yield from self.step_expr(_nf(node, 'lower'), scope)
            if _nf(node, 'upper') is not None:
                u = yield from self.step_expr(_nf(node, 'upper'), scope)
            if _nf(node, 'step') is not None:
                s = yield from self.step_expr(_nf(node, 'step'), scope)
            return slice(l, u, s)
        if _pg_tag(node[0]) == 'Tuple':
            elts = []
            for e in _nf(node, 'elts'):
                if _pg_tag(e[0]) == 'Slice':
                    elts.append((yield from self._eval_slice(e, scope)))
                else:
                    elts.append((yield from self.step_expr(e, scope)))
            return tuple(elts)
        return (yield from self.step_expr(node, scope))

    # ---- function / class definition ----

    def _define_function(self, node, scope, is_async):
        if False:
            yield
        if is_async is None:
            is_async = _nf(node, 'is_async', False)
        is_gen = _nf(node, 'is_gen', None)
        if is_gen is None:
            is_gen = self._contains_yield(_nf(node, 'body'))
        # Async generators (PEP 525) are not supported in this version.
        if is_async:
            is_gen = False  # treat any yield in async def as syntax-irrelevant
        args_def = _nf(node, 'args')
        defaults = []
        for d in _nf(args_def, 'defaults'):
            dv = yield from self.step_expr(d, scope)
            defaults.append(dv)
        kw_defaults = []
        for kd in _nf(args_def, 'kw_defaults'):
            if kd is None:
                kw_defaults.append(_MISSING)
            else:
                kdv = yield from self.step_expr(kd, scope)
                kw_defaults.append(kdv)
        func_name = self.s(_nf(node, 'name'))
        blob = _pg_make_ufunc_blob(
            args_def, _nf(node, 'body'), is_gen, is_async, defaults, kw_defaults)
        func = _UFunction(self, func_name, scope, blob)
        # Evaluate annotations
        ann = {}
        for a in (_nf(args_def, 'posonlyargs') + _nf(args_def, 'args')
                  + _nf(args_def, 'kwonlyargs')):
            if _nf(a, 'annotation') is not None:
                ann[self.s(_nf(a, 'arg'))] = (
                    yield from self.step_expr(_nf(a, 'annotation'), scope))
        vararg = _nf(args_def, 'vararg')
        if vararg is not None and _nf(vararg, 'annotation') is not None:
            ann[self.s(_nf(vararg, 'arg'))] = (
                yield from self.step_expr(_nf(vararg, 'annotation'), scope))
        kwarg = _nf(args_def, 'kwarg')
        if kwarg is not None and _nf(kwarg, 'annotation') is not None:
            ann[self.s(_nf(kwarg, 'arg'))] = (
                yield from self.step_expr(_nf(kwarg, 'annotation'), scope))
        if _nf(node, 'returns') is not None:
            ann['return'] = yield from self.step_expr(_nf(node, 'returns'), scope)
        func.__annotations__ = ann
        # Decorators
        decos = []
        for d in _nf(node, 'decorator_list'):
            dv = yield from self.step_expr(d, scope)
            decos.append(dv)
        decorated = func
        for d in reversed(decos):
            decorated = d(decorated)
        scope.set(self.s(_nf(node, 'name')), decorated)

    def _define_class(self, node, scope):
        if False:
            yield
        name = self.s(_nf(node, 'name'))
        bases = []
        for b in _nf(node, 'bases'):
            bv = yield from self.step_expr(b, scope)
            bases.append(bv)
        kw = {}
        for k in _nf(node, 'keywords'):
            kv = yield from self.step_expr(_nf(k, 'value'), scope)
            arg_idx = _nf(k, 'arg')
            if arg_idx is None or arg_idx < 0:
                kw.update(kv)
            else:
                kw[self.s(arg_idx)] = kv
        metaclass = kw.pop('metaclass', None)
        if metaclass is None:
            metaclass = type(bases[0]) if bases else type
        # Class body in its own scope
        cls_scope = Scope(parent=scope)
        cls_scope.vars['__annotations__'] = {}
        cls_scope.vars['__name__'] = name
        cls_scope.vars['__qualname__'] = name
        cls_scope.vars['__module__'] = scope.globals.get('__name__', '__main__')
        yield from self._exec_body(_nf(node, 'body'), cls_scope)
        ns = dict(cls_scope.vars)
        cls = metaclass(name, tuple(bases), ns, **kw)
        # Patch defining_class onto user functions for super()
        for v in ns.values():
            if isinstance(v, _UFunction):
                v.defining_class = cls
            elif isinstance(v, (staticmethod, classmethod)):
                inner = v.__func__
                if isinstance(inner, _UFunction):
                    inner.defining_class = cls
        # Decorators
        decos = []
        for d in _nf(node, 'decorator_list'):
            dv = yield from self.step_expr(d, scope)
            decos.append(dv)
        for d in reversed(decos):
            cls = d(cls)
        scope.set(name, cls)

    # ---- function call binding ----

    def call_user_function(self, func, args, kwargs):
        args_def, body, is_gen, is_async, defaults, kw_defaults = (
            _pg_read_ufunc_blob(func._blob))
        local = Scope(parent=func._scope)
        self._bind_args(func, args_def, defaults, kw_defaults, args, kwargs, local)
        if func.defining_class is not None:
            local.vars['__pyguard_class__'] = func.defining_class
            if args:
                local.vars['__pyguard_self__'] = args[0]
        if is_gen:
            return self._make_host_generator(func, local)
        if is_async:
            return self._make_host_coroutine(func, local)
        try:
            _drive_sync(self._exec_body(body, local))
        except _Return as r:
            return r.value
        return None

    def _bind_args(self, func, a, defaults, kw_defaults, args, kwargs, local):
        posonly = _nf(a, 'posonlyargs')
        pos = _nf(a, 'args')
        kwonly = _nf(a, 'kwonlyargs')
        vararg = _nf(a, 'vararg')
        kwarg = _nf(a, 'kwarg')

        all_pos = posonly + pos
        n_pos = len(all_pos)
        n_defaults = len(defaults)

        bound = {}
        kwargs = dict(kwargs)
        n_args = len(args)

        # 1. positional → posonly+pos
        for i in range(min(n_args, n_pos)):
            bound[self.s(_nf(all_pos[i], 'arg'))] = args[i]

        # 2. extra positional → vararg (or error)
        if n_args > n_pos:
            if vararg is not None:
                bound[self.s(_nf(vararg, 'arg'))] = tuple(args[n_pos:])
            else:
                raise TypeError(
                    "{}() takes {} positional arguments but {} were given".format(
                        func.__name__, n_pos, n_args))
        elif vararg is not None:
            bound[self.s(_nf(vararg, 'arg'))] = ()

        # 3. keyword → pos (excluding posonly) and kwonly
        pos_names = {self.s(_nf(p, 'arg')) for p in pos}
        kwonly_names = [self.s(_nf(p, 'arg')) for p in kwonly]
        for k in list(kwargs):
            if k in pos_names:
                if k in bound:
                    raise TypeError(
                        "{}() got multiple values for argument {!r}".format(
                            func.__name__, k))
                bound[k] = kwargs.pop(k)
            elif k in kwonly_names:
                bound[k] = kwargs.pop(k)

        # 4. defaults for unfilled positional
        for i, p in enumerate(all_pos):
            name = self.s(_nf(p, 'arg'))
            if name in bound:
                continue
            di = i - (n_pos - n_defaults)
            if di >= 0:
                bound[name] = defaults[di]
            else:
                raise TypeError(
                    "{}() missing required argument: {!r}".format(
                        func.__name__, name))

        # 5. defaults for unfilled kwonly
        for i, name in enumerate(kwonly_names):
            if name in bound:
                continue
            kd = kw_defaults[i]
            if kd is not _MISSING:
                bound[name] = kd
            else:
                raise TypeError(
                    "{}() missing required keyword argument: {!r}".format(
                        func.__name__, name))

        # 6. leftover keyword → **kwarg
        if kwarg is not None:
            bound[self.s(_nf(kwarg, 'arg'))] = dict(kwargs)
        elif kwargs:
            raise TypeError(
                "{}() got unexpected keyword arguments: {}".format(
                    func.__name__, list(kwargs)))

        local.vars.update(bound)

    # ---- generator / coroutine host wrappers ----

    def _make_host_generator(self, func, local):
        body = _pg_read_ufunc_blob(func._blob)[1]
        inner = self._exec_body(body, local)
        def host():
            sent = None
            try:
                while True:
                    try:
                        if sent is None:
                            evt = next(inner)
                        else:
                            evt = inner.send(sent)
                            sent = None
                    except StopIteration:
                        return
                    if evt[0] == 'yield':
                        sent = (yield evt[1])
                    else:
                        raise RuntimeError(
                            "await event in non-async generator")
            except _Return:
                return
        return host()

    def _make_host_coroutine(self, func, local):
        body = _pg_read_ufunc_blob(func._blob)[1]
        inner = self._exec_body(body, local)
        async def host():
            sent = None
            try:
                while True:
                    try:
                        if sent is None:
                            evt = next(inner)
                        else:
                            evt = inner.send(sent)
                            sent = None
                    except StopIteration:
                        return None
                    if evt[0] == 'await':
                        sent = await evt[1]
                    else:
                        raise RuntimeError(
                            "yield event in coroutine")
            except _Return as r:
                return r.value
        return host()

    # ---- with-statement ----

    def _do_with(self, items, idx, body, scope, is_async):
        if False:
            yield
        if idx >= len(items):
            yield from self._exec_body(body, scope)
            return
        item = items[idx]
        ctx = yield from self.step_expr(_nf(item, 'context_expr'), scope)
        if is_async:
            entered = yield ('await', ctx.__aenter__())
            if _nf(item, 'optional_vars') is not None:
                yield from self._assign(_nf(item, 'optional_vars'), entered, scope)
            try:
                yield from self._do_with(items, idx + 1, body, scope, is_async)
            except BaseException:
                exc_info = sys.exc_info()
                suppress = yield ('await',
                                  ctx.__aexit__(exc_info[0], exc_info[1], exc_info[2]))
                if not suppress:
                    raise
            else:
                yield ('await', ctx.__aexit__(None, None, None))
        else:
            entered = ctx.__enter__()
            if _nf(item, 'optional_vars') is not None:
                yield from self._assign(_nf(item, 'optional_vars'), entered, scope)
            try:
                yield from self._do_with(items, idx + 1, body, scope, is_async)
            except BaseException:
                exc_info = sys.exc_info()
                suppress = ctx.__exit__(exc_info[0], exc_info[1], exc_info[2])
                if not suppress:
                    raise
            else:
                ctx.__exit__(None, None, None)

    # ---- try/except/finally ----

    def _do_try(self, node, scope):
        if False:
            yield
        pending_exc = None
        pending_ctrl = None
        try:
            try:
                yield from self._exec_body(_nf(node, 'body'), scope)
            except (_Return, _Break, _Continue) as ctrl:
                pending_ctrl = ctrl
            except BaseException as e:
                handled = False
                for handler in _nf(node, 'handlers'):
                    htype = None
                    if _nf(handler, 'type') is not None:
                        htype = yield from self.step_expr(
                            _nf(handler, 'type'), scope)
                    if htype is None or isinstance(e, htype):
                        handled = True
                        name_idx = _nf(handler, 'name')
                        name = self.s(name_idx) if name_idx is not None and name_idx >= 0 else None
                        if name is not None:
                            scope.set(name, e)
                        try:
                            try:
                                yield from self._exec_body(
                                    _nf(handler, 'body'), scope)
                            except (_Return, _Break, _Continue) as ctrl:
                                pending_ctrl = ctrl
                            except BaseException as e2:
                                pending_exc = e2
                        finally:
                            if name is not None and name in scope.vars:
                                del scope.vars[name]
                        break
                if not handled:
                    pending_exc = e
            else:
                try:
                    yield from self._exec_body(_nf(node, 'orelse'), scope)
                except (_Return, _Break, _Continue) as ctrl:
                    pending_ctrl = ctrl
                except BaseException as e:
                    pending_exc = e
        finally:
            try:
                yield from self._exec_body(_nf(node, 'finalbody'), scope)
            except (_Return, _Break, _Continue) as ctrl:
                pending_ctrl = ctrl
                pending_exc = None
            except BaseException as e:
                pending_exc = e
                pending_ctrl = None
        if pending_exc is not None:
            raise pending_exc
        if pending_ctrl is not None:
            raise pending_ctrl

    # ---- comprehensions ----

    def _eval_comp(self, kind, node, scope):
        if False:
            yield
        if kind == 'list':
            result = []
        elif kind == 'set':
            result = set()
        else:
            result = {}
        first_iter = yield from self.step_expr(
            _nf(_nf(node, 'generators')[0], 'iter'), scope)
        comp_scope = Scope(parent=scope)
        yield from self._comp_loop(node, 0, comp_scope, kind, result, first_iter)
        return result

    def _comp_loop(self, node, gi, comp_scope, kind, result, first_iter):
        if False:
            yield
        generators = _nf(node, 'generators')
        gen = generators[gi]
        if gi == 0:
            iter_val = first_iter
        else:
            iter_val = yield from self.step_expr(_nf(gen, 'iter'), comp_scope)
        for item in iter_val:
            yield from self._assign(_nf(gen, 'target'), item, comp_scope)
            skip = False
            for cond in _nf(gen, 'ifs'):
                cv = yield from self.step_expr(cond, comp_scope)
                if not cv:
                    skip = True
                    break
            if skip:
                continue
            if gi + 1 < len(generators):
                yield from self._comp_loop(
                    node, gi + 1, comp_scope, kind, result, None)
            else:
                if kind == 'list':
                    v = yield from self.step_expr(_nf(node, 'elt'), comp_scope)
                    result.append(v)
                elif kind == 'set':
                    v = yield from self.step_expr(_nf(node, 'elt'), comp_scope)
                    result.add(v)
                else:
                    kv = yield from self.step_expr(_nf(node, 'key'), comp_scope)
                    vv = yield from self.step_expr(_nf(node, 'value'), comp_scope)
                    result[kv] = vv

    def _eval_genexp(self, node, scope):
        if False:
            yield
        # Eager (build a list, return iter). Adequate for our test surface.
        result = []
        first_iter = yield from self.step_expr(
            _nf(_nf(node, 'generators')[0], 'iter'), scope)
        comp_scope = Scope(parent=scope)
        yield from self._comp_loop(node, 0, comp_scope, 'list', result, first_iter)
        return iter(result)

    # ---- helpers ----

    def _lookup_magic(self, scope, name):
        s = scope
        while s is not None:
            if name in s.vars:
                return s.vars[name]
            s = s.parent
        return None

    def _contains_yield(self, body):
        return self._walk_for_yield(body)

    def _walk_for_yield(self, node):
        if isinstance(node, tuple) and node and _pg_tag(node[0]) in _NODE_POS:
            op = _pg_tag(node[0])
            if op in ('FunctionDef', 'AsyncFunctionDef', 'Lambda', 'ClassDef', 'IFunctionDef', 'IClassDef'):
                return False
            if op in ('Yield', 'YieldFrom'):
                return True
            for v in node[1:]:
                if self._walk_for_yield(v):
                    return True
            return False
        if isinstance(node, (list, tuple)):
            for x in node:
                if self._walk_for_yield(x):
                    return True
            return False
        if not isinstance(node, dict):
            return False
        for _, v in node.items():
            if self._walk_for_yield(v):
                return True
        return False


# --- entry points --------------------------------------------------------

def _decode_const(c):
    """Decode a positional const wrapper produced by build_ir.compile_to_json.

    v8: const wire format is a positional list/tuple `(tag, *values)`. The
    previous `{'t': tag, 'v': value, ...}` dict shape was a unique structural
    fingerprint by which an attacker could find every const wrapper materialized
    during parse — replaced here with positional access so const wrappers
    look indistinguishable from any other tuple in the IR stream.
    """
    t = _pg_tag(c[0])
    if t == 'none':     return None
    if t == 'true':     return True
    if t == 'false':    return False
    if t == 'int':      return int(c[1])
    if t == 'float':    return float(c[1])
    if t == 'str':      return _pg_text(c[1])
    if t == 'bytes':    return _PGBT(c[1])
    if t == 'complex':  return complex(float(c[1]), float(c[2]))
    if t == 'ellipsis': return Ellipsis
    if t == 'tuple':    return tuple(_decode_const(x) for x in c[1])
    if t == 'frozenset': return frozenset(_decode_const(x) for x in c[1])
    raise ValueError("unknown const tag: " + t)


def _build_accessor(strings, consts):
    """v6.5 / C12+C17 — construct the opaque (kind, idx) accessor.

    SECURITY MODEL (post-decryption leak defense):

    The legacy implementation captured raw `strings` and `consts` tuples
    in the closure cells of a trivial `_a(kind, idx)` lookup. A
    gc.get_objects() walk (triggered from a sitecustomize-installed
    sys.stdout proxy on first user print, since stage0 didn't witness
    stdio identity pre-v6.5) could directly read cell_contents and exfil
    the entire decoded string pool and const pool plus the interpreter
    module's _S_M / _S_K / _S_RT / _S_L globals.

    This version keeps ONLY encrypted byte buffers + plaintext offset
    tables in the closure. Each accessor call:
      1. Measures the live environment witness byte (`_pg_env_w()`).
      2. XORs it against the boot-time witness byte to get a delta.
      3. Decrypts the requested slice with `static_key ^ delta`.
    In a clean env, delta == 0 and decryption uses the static key
    unchanged. If an attacker hooks any witnessed stdio identity after
    boot (to pivot into a gc walk), the delta is non-zero and the
    accessor returns garbage — interpreter processing of a corrupted
    string table aborts before the first user print can fire any
    attacker-installed write() hook.

    The pre-boot pivot (attacker wraps stdout via sitecustomize before
    stage0 runs) is caught upstream by stage0's `n_io` witness folding
    into the master seed — decryption of stage1 fails silently and the
    accessor is never constructed in that scenario.
    """
    import os as _os
    _xk = _os.urandom(32)
    _xkl = len(_xk)
    # Pack + encrypt strings. Tag byte distinguishes:
    #   \x00 — plain UTF-8 str
    #   \x01 — list-of-int (mask-encoded; _pg_text decodes via _S_M)
    #   \x02 — any other object, custom-codec dumped (C18: no marshal)
    _s_offs = []
    _s_plain = bytearray()
    for e in strings:
        if isinstance(e, str):
            b = b'\x00' + e.encode('utf-8')
        elif isinstance(e, (list, tuple)):
            b = b'\x01' + _PGBT(e)
        else:
            b = b'\x02' + _pg_pack_const(e)
        _s_offs.append((len(_s_plain), len(b)))
        _s_plain.extend(b)
    _c_offs = []
    _c_plain = bytearray()
    for c in consts:
        b = _pg_pack_const(c)
        _c_offs.append((len(_c_plain), len(b)))
        _c_plain.extend(b)
    _s_ct = _PGBT(b ^ _xk[i % _xkl] for i, b in enumerate(_s_plain))
    _c_ct = _PGBT(b ^ _xk[i % _xkl] for i, b in enumerate(_c_plain))
    _s_offs_t = tuple(_s_offs)
    _c_offs_t = tuple(_c_offs)
    _bw = _pg_env_w()
    # Scrub plaintext locals before closure is built.
    del _s_plain, _c_plain, _s_offs, _c_offs, strings, consts

    def _a(kind, idx):
        delta = _bw ^ _pg_env_w()
        if kind == 0:
            start, length = _s_offs_t[idx]
            pt = _PGBT(_s_ct[start + i] ^ _xk[(start + i) % _xkl] ^ delta
                       for i in range(length))
            tag = pt[:1]
            if tag == b'\x00':
                return pt[1:].decode('utf-8')
            if tag == b'\x01':
                return list(pt[1:])
            return _pg_unpack_const(pt, 1)[0]
        if kind == 1:
            start, length = _c_offs_t[idx]
            pt = _PGBT(_c_ct[start + i] ^ _xk[(start + i) % _xkl] ^ delta
                       for i in range(length))
            return _pg_unpack_const(pt, 0)[0]
        raise LookupError(kind)
    return _a


def run_blob(blob, module_name='__main__'):
    """Parse packed binary IR and execute it.

    Strips noise bytes and reverses rolling XOR before parsing. The
    seed and noise schedule are injected as globals by stage2.
    """
    global _S_K, _S_RT, _S_M, _S_L, _S_IS
    g = globals()
    # Internalize schema from _PG_* globals → private module vars, then wipe.
    # This prevents frame-walk attacks from extracting schema by known names.
    _S_K = dict(g.pop('_PG_KEYS', {}))
    _S_RT = dict(g.pop('_PG_RTAGS', {}))
    _S_M = _PGBT(g.pop('_PG_MASK', ()))
    _S_L = dict(g.pop('_PG_LAYOUTS', {}))
    _S_IS = _pg_schema_island_secret(_S_M, _S_K, _S_RT, _S_L)
    g.pop('_PG_TAGS', None)
    # --- undo noise injection + rolling XOR ---
    _ns = g.pop('_PG_NOISE_SCHEDULE', None)
    if _ns:
        blob = _strip_noise(blob, _ns)
    _bk = g.pop('_PG_BIN_KEY', None)
    if _bk is not None:
        blob = _rolling_xor(blob, _bk)
    del _ns, _bk
    # ------------------------------------------------
    loaded = _pg_parse_bin(blob)
    consts = tuple(_decode_const(c) for c in loaded[1])
    _acc = _build_accessor(loaded[0], consts)
    interp = Interp(_acc)
    tree = loaded[2]
    del loaded, blob, consts
    try:
        interp.run(tree, module_name)
    finally:
        _pg_scrub_post_run(_acc, interp)
        del _acc, interp, tree


def _pg_scrub_post_run(_acc, _interp):
    """v6.5 / C15 — post-run cleanup.

    After the user program finishes (or raises), drop every Python-level
    reference to decrypted interpreter state:
      1. Scrub the accessor closure's cell contents — the encrypted byte
         buffers and key material held inside `_build_accessor`'s closure.
         Cell contents are writable on CPython 3.7+; assigning `None`
         breaks the reference graph that an atexit-registered
         gc.get_objects() walk would otherwise find.
      2. Drop `_S_K / _S_RT / _S_M / _S_L` from the interpreter module's
         globals. These are the per-build polymorphic schema dicts; the
         legacy c12_attack exfiltrated them via `_a.__globals__`. After
         scrub, the interpreter module dict contains none of them, so an
         attacker's atexit hook walking sys.modules finds nothing.
      3. Force a gc cycle so any reference cycles (Interp → accessor →
         closure) release their memory before the main process's atexit
         hooks fire.
    """
    try:
        cl = getattr(_acc, '__closure__', None) or ()
        for _cell in cl:
            try:
                _cell.cell_contents = None
            except Exception:
                pass
    except Exception:
        pass
    try:
        setattr(_interp, '_a', None)
    except Exception:
        pass
    _g = globals()
    for _n in ('_S_K', '_S_RT', '_S_M', '_S_L', '_S_IS'):
        _g.pop(_n, None)
    try:
        _PG_IMP.clear()
    except Exception:
        pass
    try:
        _PG_BI.clear()
    except Exception:
        pass
    try:
        import gc as _gc
        _gc.collect()
    except Exception:
        pass


def _pg_compute_env():
    """Recompute the stage2 env-integrity hash inside the interpreter.

    Recipe must match `_pg_env` in lib/v5/assemble.ts buildV5Stage2Source
    AND `envCheckExpected` in lib/obfuscate.ts. The mask keystream and
    crypto-key derivations both bind to this hash, so any drift between
    stage2's and the interpreter's computation silently corrupts the
    SHAKE-128 keystream used to unmask the boot packet AND the downstream
    schema/IR keys — double-fail-closed on trace/profile/type tampering.
    """
    import hashlib as _h3
    import sys as _sys3
    import zlib as _z3
    import marshal as _m3
    _ft = (lambda: 0).__class__
    _parts = [
        str(len(_sys3._current_frames())),
        type(_z3.decompress).__name__,
        type(print).__name__,
        type(getattr).__name__,
        type(_sys3.settrace).__name__,
        type(_sys3.setprofile).__name__,
        type(_sys3.gettrace).__name__,
        type(_sys3.getprofile).__name__,
        type(exec).__name__,
        type(_m3.loads).__name__,
        type(_h3.scrypt).__name__,
        # v6.2 closure: shake_128 is the mask keystream provider; a
        # Python-level replacement would leak (boot_key, env_hash) and
        # reconstruct the mask. Bind its type into env so such a swap
        # flips env_hash, breaks the mask, and garbles the packet.
        type(_h3.shake_128).__name__,
        str(type(_sys3.settrace) is type(_z3.decompress)),
        str(type(_sys3.setprofile) is type(_z3.decompress)),
        str(type(_sys3.gettrace) is type(_z3.decompress)),
        str(type(_sys3.getprofile) is type(_z3.decompress)),
        str(type(exec) is type(_z3.decompress)),
        str(type(_m3.loads) is type(_z3.decompress)),
        str(type(_h3.scrypt) is type(_z3.decompress)),
        str(type(_h3.shake_128) is type(_z3.decompress)),
        _ft.__name__,
        str(_ft is (lambda: None).__class__),
        _ft.__class__.__name__,
        _ft.__module__,
    ]
    return _h3.sha256('|'.join(_parts).encode()).digest()


def _pg_boot(*_a):
    """PyGuard interpreter entry point.

    Signature:
      - packet path: boot_blob, builtins_snapshot, import_pairs

    All stage2-supplied "config" is inert bytes: a 32-byte `pep` pepper,
    and a 15-byte `profile` struct (rounds, rot_mod, sbx_nudge,
    rk_label[4], rot_label[4], sbx_label[4]). The cipher algorithm is
    implemented inline here via the _k_derive / _c_dec helpers above.
    An attacker hooking `types.FunctionType` finds only inert bytes in
    the boot-args tuple — no callable to replace with a logging wrapper.

    `co_argcount == 0` (vararg-only) defeats any structural fingerprint
    keyed on argument count.

    Packet-path masking (v6.2): the boot packet is XOR-masked with a
    SHAKE-128 keystream derived from (boot_key || env_hash), where
    env_hash is re-derived locally via `_pg_compute_env`. Stage2 applies
    the same mask using its own env_hash computation. Generic cross-build
    demasking via a fixed formula no longer works — the demasker must
    also run inside an un-tampered env, because a tampered env produces
    a different keystream and garbage plaintext, before crypto keys are
    even consulted.
    """
    _bi_snap = None
    _imp_lut = None
    _boot_slice = None
    _schema_ct_len = None
    _ir_ct_len = None
    _mod_name_len = None
    _schema_label_off = None
    _ir_label_off = None
    _seed_off = None
    _interp_hash_off = None
    _pep_off = None
    _profile_off = None
    _mod_name_off = None
    _schema_ct_off = None
    _ir_ct_off = None
    _boot_buf = None
    _boot_key_buf = None
    _boot_key_len = None
    _boot_total = None
    _env_local = None
    _mask_ks = None
    if len(_a) == 3 and isinstance(_a[0], (bytes, bytearray)):
        # v6.3: late-phase trace guard mirroring stage2's pre-call check.
        # If an attacker's audit-hook-triggered trace captured our args
        # BEFORE we reached this point, it's already too late for the
        # blob — but we fail here so at least the remainder of boot
        # never runs, and repeat-runs under the same hook still trip the
        # stage2-side guard. Primary defense is the stage2 check; this
        # is defense-in-depth for paths where stage2 was bypassed and
        # _pg_boot was called directly via imported globals.
        import sys as _sys_tg
        if _sys_tg.gettrace() is not None or _sys_tg.getprofile() is not None:
            raise SystemExit(0)
        _mon_tg = getattr(_sys_tg, 'monitoring', None)
        if _mon_tg is not None:
            for _i_tg in range(6):
                try:
                    if _mon_tg.get_events(_i_tg) != 0:
                        raise SystemExit(0)
                except ValueError:
                    pass
        (_boot_blob, _bi_snap, _imp_lut) = _a
        # v6.5 shard-combine: the boot key is NOT in the caller frame
        # and NOT in the args tuple. Stage2 split it across two shards
        # stashed in this function's OWN reflective surfaces:
        #   - shard_alpha: sys._getframe(0).f_globals['_PG_KSA']
        #                  (i.e. this interpreter module's dict)
        #   - shard_beta:  self_fn.__dict__['_PG_KSB']
        #                  (this function object's attribute dict,
        #                   located via f_globals[co_name])
        # Neither shard is the key on its own; the key is
        # shard_alpha XOR shard_beta. stage2 uses fresh per-run entropy
        # (id() + env hash) to derive shard_alpha, so shard captures
        # from a prior run cannot be replayed.
        _own_frame = _sys_tg._getframe(0)
        _own_ns = _own_frame.f_globals
        _self_fn = _own_ns.get(_own_frame.f_code.co_name)
        if _self_fn is None:
            raise SystemExit(0)
        # v6.7: stash is now a 4-tuple of 12-byte blobs (3 per-run decoys
        # + 1 real shard) per side. Real slot index is derived from the
        # same env/id witnesses stage2 used; stage2 and here must agree.
        _ks_tup_a = _own_ns.pop('_PG_KSA', None)
        _ks_tup_b = _self_fn.__dict__.pop('_PG_KSB', None)
        if (not isinstance(_ks_tup_a, tuple) or not isinstance(_ks_tup_b, tuple)
                or len(_ks_tup_a) != 4 or len(_ks_tup_b) != 4):
            raise SystemExit(0)
        import hashlib as _h_ks
        _boot_blob_ref = _boot_blob
        _env_ks = _pg_compute_env()
        _ks_idx = _h_ks.sha256(b'ksidx' + id(_boot_blob_ref).to_bytes(8, 'little') + _env_ks).digest()[0] & 3
        _ks_a = _ks_tup_a[_ks_idx]
        _ks_b = _ks_tup_b[_ks_idx]
        if (not isinstance(_ks_a, (bytes, bytearray))
                or not isinstance(_ks_b, (bytes, bytearray))
                or len(_ks_a) != 12 or len(_ks_b) != 12):
            raise SystemExit(0)
        _boot_key = bytes(a ^ b for a, b in zip(_ks_a, _ks_b))
        del _own_frame, _own_ns, _self_fn, _ks_a, _ks_b, _sys_tg, _mon_tg
        del _ks_tup_a, _ks_tup_b, _ks_idx, _h_ks, _boot_blob_ref, _env_ks
        _boot_buf = memoryview(_boot_blob)
        _boot_key_buf = memoryview(_boot_key)
        _boot_key_len = len(_boot_key_buf)
        _boot_total = len(_boot_buf)
        del _boot_blob
        del _boot_key
        # v6.2: env-bound SHAKE-128 mask keystream. Stage2 computed the
        # same hash from its own env witnesses and produced the matching
        # keystream. Any trace/profile/type-name tampering flips env,
        # keystream, and the packet is garbage before cipher runs.
        _env_local = _pg_compute_env()
        import hashlib as _h_pkt
        _mask_ks = _h_pkt.shake_128(
            bytes(_boot_key_buf) + _env_local
        ).digest(_boot_total)
        def _boot_slice(_off, _ln):
            return _PGBT(
                _boot_buf[_off + _i] ^ _mask_ks[_off + _i]
                for _i in range(_ln)
            )
        _o = 0
        _schema_ct_len = int.from_bytes(_boot_slice(_o, 4), 'little'); _o += 4
        _ir_ct_len = int.from_bytes(_boot_slice(_o, 4), 'little'); _o += 4
        _mod_name_len = int.from_bytes(_boot_slice(_o, 4), 'little'); _o += 4
        _schema_label_off = _o; _o += 6
        _ir_label_off = _o; _o += 6
        _seed_off = _o; _o += 32
        _interp_hash_off = _o; _o += 32
        _pep_off = _o; _o += 32
        _profile_off = _o; _o += 15
        _mod_name_off = _o; _o += _mod_name_len
        _schema_ct_off = _o; _o += _schema_ct_len
        _ir_ct_off = _o; _o += _ir_ct_len
        if _o != _boot_total:
            raise TypeError("_pg_boot: bad packet")
        module_name = '__main__'
    else:
        raise TypeError("_pg_boot: expected packet args, got " + str(len(_a)))
    del _a
    global _PG_BI, _PG_IMP
    if isinstance(_bi_snap, dict):
        _PG_BI = _bi_snap
    if isinstance(_imp_lut, dict):
        _PG_IMP = _imp_lut
    elif isinstance(_imp_lut, (tuple, list)):
        try:
            _PG_IMP = {k: v for k, v in _imp_lut}
        except Exception:
            _PG_IMP = {}
    del _bi_snap
    del _imp_lut

    # Unpack the 15-byte profile struct (layout must match TS emission
    # in lib/obfuscate.ts / lib/v5/assemble.ts).
    if _boot_slice is not None:
        profile = _boot_slice(_profile_off, 15)
    _rounds = profile[0]
    _rot_mod = profile[1]
    _sbx_nudge = profile[2]
    _rk_label = _PGBT(profile[3:7])
    _rot_label = _PGBT(profile[7:11])
    _sbx_label = _PGBT(profile[11:15])

    global _S_K, _S_RT, _S_M, _S_L, _S_IS
    import hashlib as _h
    import zlib as _z

    # --- decrypt schema (v8: positional binary, not JSON) ---
    if _boot_slice is not None:
        _schema_seed_pre = _h.sha256(
            _boot_slice(_seed_off, 32) +
            _boot_slice(_schema_label_off, 6)
        ).digest()
        seed = _boot_slice(_seed_off, 32)
        interp_hash = _boot_slice(_interp_hash_off, 32)
        # v6.2: env_hash no longer travels in the packet. It is live-
        # computed and also gates the SHAKE mask keystream, so a tampered
        # env hits both the mask and the cipher-key paths.
        env_hash = _env_local
        pep = _boot_slice(_pep_off, 32)
        profile = _boot_slice(_profile_off, 15)
        schema_label = _boot_slice(_schema_label_off, 6)
        schema_ct = _boot_slice(_schema_ct_off, _schema_ct_len)
        ir_label = _boot_slice(_ir_label_off, 6)
        ir_ct = _boot_slice(_ir_ct_off, _ir_ct_len)
        module_name = _boot_slice(_mod_name_off, _mod_name_len).decode('utf-8')
        del _boot_slice
        del _boot_buf
        del _boot_key_buf
        del _boot_key_len
        del _boot_total
        del _env_local
        del _mask_ks
    _schema_seed = _PGBT(a ^ b ^ c for a, b, c in zip(
        _schema_seed_pre, interp_hash, env_hash))
    _schema_p = _k_derive(_schema_seed, pep, _rounds, _rk_label,
                          _rot_label, _sbx_label, _rot_mod, _sbx_nudge)
    _sb = _c_dec(schema_ct, _schema_p[0], _schema_p[1], _schema_p[2])
    del _schema_seed, _schema_seed_pre, _schema_p

    _o = 0
    # mask
    _ml = _sb[_o]; _o += 1
    _S_M = _PGBT(_sb[_o:_o + _ml]); _o += _ml
    # bin_key
    _bk_lo = _sb[_o] | (_sb[_o+1] << 8) | (_sb[_o+2] << 16) | (_sb[_o+3] << 24); _o += 4
    _bk_hi = _sb[_o] | (_sb[_o+1] << 8) | (_sb[_o+2] << 16) | (_sb[_o+3] << 24); _o += 4
    _bin_key = _bk_lo | (_bk_hi << 32)
    # noise schedule
    _nc = _sb[_o]; _o += 1
    _noise = []
    for _ in range(_nc):
        _pos = _sb[_o] | (_sb[_o+1] << 8); _o += 2
        _ln = _sb[_o]; _o += 1
        _noise.append((_pos, _ln))
    # keys
    _kc = _sb[_o] | (_sb[_o+1] << 8); _o += 2
    _S_K = {}
    for _ in range(_kc):
        _kl = _sb[_o]; _o += 1
        _k = _sb[_o:_o + _kl].decode('utf-8'); _o += _kl
        _vl = _sb[_o]; _o += 1
        _v = _sb[_o:_o + _vl].decode('utf-8'); _o += _vl
        _S_K[_k] = _v
    # tags (read straight into reverse-tag map; forward map never exists)
    _tc = _sb[_o] | (_sb[_o+1] << 8); _o += 2
    _S_RT = {}
    for _ in range(_tc):
        _kl = _sb[_o]; _o += 1
        _k = _sb[_o:_o + _kl].decode('utf-8'); _o += _kl
        _vl = _sb[_o]; _o += 1
        _v = _sb[_o:_o + _vl].decode('utf-8'); _o += _vl
        _S_RT[_v] = _k
    # layouts (name → {field: index+1})
    _lc = _sb[_o] | (_sb[_o+1] << 8); _o += 2
    _S_L = {}
    for _ in range(_lc):
        _tl = _sb[_o]; _o += 1
        _tag = _sb[_o:_o + _tl].decode('utf-8'); _o += _tl
        _fc = _sb[_o]; _o += 1
        _fmap = {}
        for _j in range(_fc):
            _fl = _sb[_o]; _o += 1
            _fn = _sb[_o:_o + _fl].decode('utf-8'); _o += _fl
            _fmap[_fn] = _j + 1
        _S_L[_tag] = _fmap
    _S_IS = _pg_schema_island_secret(_S_M, _S_K, _S_RT, _S_L)
    del _sb, _o, _ml, _bk_lo, _bk_hi, _nc
    try:
        del _pos, _ln, _kc, _kl, _k, _vl, _v, _tc, _lc, _tl, _tag, _fc, _fmap, _fl, _fn, _j
    except NameError:
        pass

    # --- decrypt IR bytes ---
    _ir_seed_pre = _h.sha256(seed + ir_label).digest()
    _ir_seed = _PGBT(a ^ b ^ c for a, b, c in zip(
        _ir_seed_pre, interp_hash, env_hash))
    _ir_p = _k_derive(_ir_seed, pep, _rounds, _rk_label,
                      _rot_label, _sbx_label, _rot_mod, _sbx_nudge)
    blob = _z.decompress(_c_dec(ir_ct, _ir_p[0], _ir_p[1], _ir_p[2]), -15)
    del _ir_seed, _ir_seed_pre, _ir_p, schema_ct, ir_ct, seed, pep, profile
    del _rounds, _rot_mod, _sbx_nudge, _rk_label, _rot_label, _sbx_label

    # --- strip noise + rolling XOR ---
    if _noise:
        blob = _strip_noise(blob, _noise)
    if _bin_key is not None:
        blob = _rolling_xor(blob, _bin_key)
    del _noise, _bin_key

    # --- parse + run ---
    loaded = _pg_parse_bin(blob)
    _consts = tuple(_decode_const(c) for c in loaded[1])
    # v6.5 / C17: _build_accessor packs and XOR-encrypts the strings +
    # consts at this point. The closure cells of `_a` hold only
    # ciphertext + offset tables; plaintext tuples never reach closure.
    _acc = _build_accessor(loaded[0], _consts)
    interp = Interp(_acc)
    tree = loaded[2]
    del loaded, blob, _consts
    try:
        interp.run(tree, module_name)
    finally:
        # v6.5 / C15: post-run scrub. Nulls accessor closure cells, pops
        # _S_K / _S_RT / _S_M / _S_L from module globals, and forces a gc
        # cycle. An attacker's atexit hook walks gc.get_objects() after
        # this and finds no decrypted state reachable.
        _pg_scrub_post_run(_acc, interp)
        del _acc, interp, tree


def _k_derive(input_seed, pep, rounds, rk_label, rot_label, sbx_label, rot_mod, sbx_nudge):
    """Inline key-derivation — mirror of stage1's _kd.

    Derivation runs INSIDE the interpreter. Profile parameters (rounds,
    labels, rot_mod, sbx_nudge) travel as inert bytes in the boot-args
    tuple; there is no Python callable to wrap. An attacker who captures
    the args has only raw bytes and must reimplement this derivation
    offline to make use of them.

    Algorithm must match lib/obfuscate.ts `kdf()` exactly — the stage1
    encryption side used the same math and any drift breaks compat.
    """
    import hashlib as _h2
    peppered = _PGBT(a ^ b for a, b in zip(input_seed, pep))
    rks = []
    h = peppered
    for _ in range(rounds):
        h = _h2.sha256(h + rk_label).digest()
        rks.append(h)
    rot_seed = _h2.sha256(peppered + rot_label).digest()
    rotk = [(rot_seed[i] % rot_mod) + 1 for i in range(rounds)]
    sbx_seed = _h2.sha256(peppered + sbx_label).digest()
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + sbx_seed[i % 32] + sbx_nudge) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    inv = [0] * 256
    for i in range(256):
        inv[sbox[i]] = i
    return rks, rotk, inv


def _c_dec(ct, rks, rotk, inv):
    L = len(ct)
    N = len(rks)
    buf = bytes(ct)
    r = N - 1
    while r >= 0:
        k = rotk[r]
        tbl = bytes(inv[((b >> k) | (b << (8 - k))) & 255] for b in range(256))
        buf = buf.translate(tbl)
        rk = rks[r]
        if L > 0:
            kb = (rk * ((L + 31) // 32))[:L]
            ib = int.from_bytes(buf, 'big')
            ik = int.from_bytes(kb, 'big')
            buf = (ib ^ ik).to_bytes(L, 'big')
        r -= 1
    out = bytearray(L)
    prev = 0
    i = 0
    while i < L:
        out[i] = buf[i] ^ prev
        prev = ct[i]
        i += 1
    return _PGBT(out)


def _rolling_xor(data, seed):
    """Apply rolling XOR using an LCG-derived byte stream. Self-inverse."""
    _MULT = 6364136223846793005
    _INC = 1442695040888963407
    _MASK64 = (1 << 64) - 1
    out = bytearray(len(data))
    key = seed & _MASK64
    for i in range(len(data)):
        key = (key * _MULT + _INC) & _MASK64
        out[i] = data[i] ^ ((key >> 32) & 0xFF)
    return _PGBT(out)


def _strip_noise(data, noise_schedule):
    """Remove noise bytes previously injected by _inject_noise.

    Reverses the schedule in reverse order so that position accounting
    is consistent with the forward injection pass.
    """
    buf = bytearray(data)
    # Replay in reverse to undo the cumulative offset correctly
    for pos, length in reversed(noise_schedule):
        # During injection, actual = pos % (len(buf_at_that_time) + 1).
        # We need to reconstruct the same actual position.  When stripping
        # in reverse, buf is at the same length it was *after* that particular
        # injection, so actual = pos % (len(buf) - length + 1) ... but the
        # injection used len(buf_before)+1 = len(buf)-length+1.  Since we
        # are undoing the *last* injection first, the current buf is exactly
        # the state right after that injection.
        before_len = len(buf) - length
        actual = pos % (before_len + 1)
        del buf[actual:actual + length]
    return _PGBT(buf)


def _pg_parse_bin(blob):
    idx = [0]
    n = len(blob)

    def _u32():
        i = idx[0]
        if i + 4 > n:
            raise ValueError("short u32")
        idx[0] = i + 4
        return blob[i] | (blob[i + 1] << 8) | (blob[i + 2] << 16) | (blob[i + 3] << 24)

    def _take(m):
        i = idx[0]
        if i + m > n:
            raise ValueError("short read")
        idx[0] = i + m
        return blob[i:i + m]

    def _parse():
        tag = _take(1)
        if tag == b'n':
            return None
        if tag == b't':
            return True
        if tag == b'f':
            return False
        if tag == b'i':
            return int(_take(_u32()).decode('utf-8'))
        if tag == b'r':
            return float(_take(_u32()).decode('utf-8'))
        if tag == b's':
            return _take(_u32()).decode('utf-8')
        if tag == b'l':
            out = []
            for _ in range(_u32()):
                out.append(_parse())
            return tuple(out)
        if tag == b'm':
            # v8: legacy `m` (map) tag retained only so old packed blobs
            # parse — current build_ir.py emits const wrappers as positional
            # tuples (`l` tag) per step B, so the only `m` payloads in v8
            # streams are absent. Returning a plain dict keeps backward-compat
            # without re-introducing a unique-class fingerprint.
            items = []
            for _ in range(_u32()):
                k = _take(_u32()).decode('utf-8')
                items.append((k, _parse()))
            return dict(items)
        raise ValueError("bad tag: " + repr(tag))

    out = _parse()
    if idx[0] != n:
        raise ValueError("trailing packed data")
    return out


# --- self-test entry point ----------------------------------------------
if __name__ == '__main__':
    import json
    import os

    # Smoke test: read source from argv[1], compile via the real packed
    # binary path (compile_to_compressed_bytes + run_blob) so this exercises
    # the same code that production stubs use.
    import zlib

    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import build_ir as _bi  # noqa

    if len(sys.argv) < 2:
        print("usage: runtime_interp.py <source.py>")
        sys.exit(2)
    with open(sys.argv[1]) as f:
        src = f.read()
    schema_json = os.environ.get('PYGUARD_V5_SCHEMA')
    compressed = _bi.compile_to_compressed_bytes(src, schema_json)
    blob = zlib.decompress(compressed, -15)
    if schema_json:
        schema = json.loads(schema_json)
        globals()['_PG_KEYS'] = dict(schema.get('keys', {}).items())
        tags = dict(schema.get('tags', {}).items())
        globals()['_PG_TAGS'] = tags
        globals()['_PG_RTAGS'] = {v: k for k, v in tags.items()}
        globals()['_PG_MASK'] = _PGBT(schema.get('mask', []))
        globals()['_PG_LAYOUTS'] = {
            k: {name: i + 1 for i, name in enumerate(v)}
            for k, v in dict(schema.get('layouts', {}).items()).items()
        }
        # rolling XOR + noise injection globals
        bin_key_pair = schema.get('binKey')
        if bin_key_pair is not None:
            lo, hi = bin_key_pair
            globals()['_PG_BIN_KEY'] = (lo & 0xFFFFFFFF) | ((hi & 0xFFFFFFFF) << 32)
        globals()['_PG_NOISE_SCHEDULE'] = schema.get('noiseSchedule', [])
    run_blob(blob)
