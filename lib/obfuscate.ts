// lib/obfuscate.ts

/**
 * Advanced Python Obfuscator with:
 * 1) Layered encryption (Custom multi-step cipher)
 * 2) Polymorphic code generation with heavily obfuscated identifiers
 * 3) Advanced anti-debugging and anti-analysis measures with runtime verification
 * 4) String literal encryption for payload AND parts of the deobfuscation stub
 * 5) Dead code injection and control flow obfuscation via block shuffling
 * 6) Obfuscated key derivation (keys are not stored directly)
 * 7) Import-compatible secure execution context
 * 8) NO COMMENTS in generated Python code.
 * 9) More compact formatting (reduced newlines).
 * 10) Fixed to run in all Python environments while maintaining security
 */

// Secure random number generator (simulated)
const secureRandom = (min: number, max: number): number => {
    const range = max - min + 1;
    const byteCount = Math.ceil(Math.log2(range) / 8);
    if (byteCount <= 0) return min;
    const maxValidValue = Math.floor(256 ** byteCount / range) * range - 1;

    let value;
    do {
        const bytes = Array.from({ length: byteCount }, () => Math.floor(Math.random() * 256));
        value = bytes.reduce((acc, byte, i) => acc + byte * (256 ** i), 0);
    } while (value > maxValidValue);

    return min + (value % range);
};

// Utility to generate random identifiers
const randomIdent = (len = 8): string => {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    return Array.from({ length: len }, () => alphabet[secureRandom(0, alphabet.length - 1)]).join('');
};

// Utility to shuffle an array
const shuffle = <T>(array: T[]): T[] => {
    const result = [...array];
    for (let i = result.length - 1; i > 0; i--) {
        const j = secureRandom(0, i);
        [result[i], result[j]] = [result[j], result[i]];
    }
    return result;
};

// AES-like byte operations
const bitwiseRotateLeft = (value: number, shift: number): number => {
    return ((value << shift) | (value >> (8 - shift))) & 0xFF;
};

// Multi-layer encryption for the payload
const encryptBytes = (data: string, keys: any): number[] => {
    const bytes = Array.from(data).map(c => c.charCodeAt(0));
    const output = new Array(bytes.length);
    const { primaryKey, secondaryKey, rotationKey, substitutionKey, ivValue } = keys;
    let previousByte = ivValue % 256;

    for (let i = 0; i < bytes.length; i++) {
        let b = bytes[i] ^ primaryKey[i % primaryKey.length];
        b = substitutionKey[b];
        b = bitwiseRotateLeft(b, rotationKey[i % rotationKey.length]);
        b = b ^ previousByte;
        b = b ^ secondaryKey[i % secondaryKey.length];
        output[i] = b;
        previousByte = b;
    }
    return output;
};

// Base64 encode with custom alphabet (URL-safe variant)
const customBase64Encode = (bytes: number[]): string => {
    const standard = btoa(String.fromCharCode(...bytes));
    return standard.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

// Generates dynamic variable names for the Python stub
const generateVarNames = () => {
    const prefixes = ['q_', 'z_', 'x_', 'w_', 'v_', 'k_', 'p_', 'm_', 'g_', 'd_'];
    const suffixes = ['_var', '_val', '_dat', '_buf', '_ctx', '_env', '_cfg', '_sys', '_app', '_lib', '_util', '_sec', '_core'];
    const getRandomName = (baseLen = 7) => {
        let name = prefixes[secureRandom(0, prefixes.length - 1)] + randomIdent(secureRandom(baseLen -2, baseLen + 2));
        if (Math.random() > 0.5) {
            name += suffixes[secureRandom(0, suffixes.length-1)];
        }
        return name;
    }
    return {
        KEY_DERIVE_FACTOR1: getRandomName(), KEY_DERIVE_FACTOR2: getRandomName(),
        KEY_DERIVE_SALT: getRandomName(), SBOX_HALF_LEN: getRandomName(),
        GET_PKEY: getRandomName(), GET_SKEY: getRandomName(), GET_RKEY: getRandomName(),
        GET_SBOX: getRandomName(), GET_IV: getRandomName(), CHUNKS: getRandomName(),
        DECRYPT_FUNC: getRandomName(), ROTATE_FUNC: getRandomName(),
        DEOBFUSCATE_FUNC: getRandomName(), EXEC_FUNC: getRandomName(),
        ENV_INSPECT: getRandomName(), ASSEMBLE_FUNC: getRandomName(),
        OBFUSCATED_DATA: getRandomName(), INTEGRITY_CHECK: getRandomName(),
        TIME_SEED: getRandomName(), MAIN_FUNC: getRandomName(),
        STR_UTF8: getRandomName(), STR_REPLACE: getRandomName(),
        STR_B64DECODE_TARGET: getRandomName(), STR_PLUS: getRandomName(),
        STR_SLASH: getRandomName(), STR_EQUALS: getRandomName(),
        STR_BYTES_DECODE_TARGET: getRandomName(), STR_STRIP_TARGET: getRandomName(),
        STR_GETATTR_TARGET: getRandomName(), STR_BUILTINS_TARGET: getRandomName(),
        STR_BASE64_MODULE_TARGET: getRandomName(), STR_LT_OBFUSCATED_GT: getRandomName(),
        STR_EXEC_TARGET: getRandomName(), STR_SYS_TARGET: getRandomName(),
        STR_TIME_TARGET: getRandomName(), STR_INSPECT_TARGET: getRandomName(),
        STR_MAIN_GUARD: getRandomName(), METH_GETTRACE: getRandomName(),
        METH_TIME: getRandomName(), METH_SLEEP: getRandomName(), METH_STACK: getRandomName(),
        METH_FIND_MODULE: getRandomName(), METH_DECODE: getRandomName(),
        METH_REPLACE: getRandomName(), METH_STRIP: getRandomName(), METH_B64DEC: getRandomName(),
        METH_EXEC: getRandomName(), METH_COMPILE: getRandomName(), MOD_BUILTINS: getRandomName(),
        MOD_BASE64: getRandomName(),
    };
};

// Generates functions that derive keys at runtime (comment-free)
const generateKeyDerivationFunctions = (keys: any, ids: any, factor1: number, factor2: number, salt: number) => {
    const funcs: string[] = [];
    funcs.push(`def ${ids.GET_PKEY}():
    k_data = [${keys.primaryKey.map((val: number) => (val ^ factor1) + factor2 - salt).join(", ")}]
    return [(x + ${salt} - ${factor2}) ^ ${factor1} for x in k_data]`);

    const s_key_intermediate_add = factor1 + factor2 + salt;
    funcs.push(`def ${ids.GET_SKEY}():
    s_data = [${keys.secondaryKey.map((val: number) => val + s_key_intermediate_add).join(", ")}]
    return [x - ${s_key_intermediate_add} for x in s_data]`);

    funcs.push(`def ${ids.GET_RKEY}():
    r_const = [${keys.rotationKey.map((val: number) => val + salt).join(", ")}]
    return [val - ${salt} for val in r_const]`);

    const sboxHalfLen = Math.floor(keys.substitutionKey.length / 2);
    funcs.push(`def ${ids.GET_SBOX}():
    p1 = [${keys.substitutionKey.slice(0, sboxHalfLen).map((v:number)=> v ^ salt).join(", ")}]
    p2 = [${keys.substitutionKey.slice(sboxHalfLen).map((v:number)=> v ^ factor1).join(", ")}]
    return [(v ^ ${salt}) for v in p1] + [(v ^ ${factor1}) for v in p2]`);

    const iv_base_val = keys.ivValue - factor1 * factor2 - salt;
    funcs.push(`def ${ids.GET_IV}():
    return ${iv_base_val} + (${factor1} * ${factor2}) + ${salt}`);
    return funcs;
};

// Generates decoy functions (comment-free)
const generateDecoyFunctions = (count: number, ids: ReturnType<typeof generateVarNames>) => {
    const decoys: string[] = [];
    const decoyTemplates = [
        (name: string) => `def ${name}(a, b, c=${secureRandom(1,100)}): return [(x * c ^ b) % 256 for x in a[:${secureRandom(10,20)}]] if hasattr(a, '__len__') else [b,c]`,
        (name: string) => `def ${name}(data, key=None): return bytes(reversed(data)) if isinstance(data, bytes) else str(data)[::-1]`,
        (name: string) => `def ${name}(n, m=${secureRandom(0,5)}): return (n << m) | (n >> (8-m if n < 256 else 32-m))`,
        (name: string) => `def ${name}(s): return ''.join(chr(ord(c) + ${secureRandom(1,3)}) for c in str(s) if ord(c) < 125)`,
        (name: string) => `def ${name}(arr): return sum(x*${secureRandom(1,5)}+${secureRandom(0,10)} for i,x in enumerate(arr) if i%2==${secureRandom(0,1)}) % ${secureRandom(1000,2000)}`,
    ];
    for (let i = 0; i < count; i++) {
        const templateIdx = secureRandom(0, decoyTemplates.length - 1);
        decoys.push(decoyTemplates[templateIdx](randomIdent(secureRandom(10, 18))));
    }
    return decoys;
};


export function obfuscatePythonCode(input: string): string {
    const keys = (() => {
        const keySize = secureRandom(32, 64);
        return {
            primaryKey: Array.from({ length: keySize }, () => secureRandom(0, 255)),
            secondaryKey: Array.from({ length: keySize }, () => secureRandom(0, 255)),
            rotationKey: Array.from({ length: secureRandom(8, 16) }, () => secureRandom(1, 7)),
            substitutionKey: shuffle([...Array(256).keys()]),
            ivValue: secureRandom(1000000, 99999999),
        };
    })();

    const encryptedBytes = encryptBytes(input, keys);
    const encodedData = customBase64Encode(encryptedBytes);
    const chunks: string[] = [];
    let pos = 0;
    while (pos < encodedData.length) {
        chunks.push(encodedData.slice(pos, pos + secureRandom(30, 70)));
        pos += chunks[chunks.length-1].length;
    }

    const ids = generateVarNames();
    const py_keyDeriveFactor1 = secureRandom(10, 100);
    const py_keyDeriveFactor2 = secureRandom(101, 200);
    const py_keyDeriveSalt = secureRandom(201, 300);

    const headerBlockLines = [
        "# Protected by PyGuard v3.0.1 (pyguard.akean.dev)",
        "#!/usr/bin/env python3",
        "import sys, time, base64, inspect, struct",
        "from functools import reduce",
        "from random import randint",
    ];

    const initialSetupBlockLines = [
        `${ids.TIME_SEED} = time.time()`,
        `${ids.KEY_DERIVE_FACTOR1} = ${py_keyDeriveFactor1}`,
        `${ids.KEY_DERIVE_FACTOR2} = ${py_keyDeriveFactor2}`,
        `${ids.KEY_DERIVE_SALT} = ${py_keyDeriveSalt}`,
        `${ids.SBOX_HALF_LEN} = ${Math.floor(keys.substitutionKey.length / 2)}`,
    ];
    
    const strObfuscationBlockLines = [
        `${ids.MOD_BUILTINS} = __import__(bytes([98, 117, 105, 108, 116, 105, 110, 115]).decode())`,
        `${ids.STR_GETATTR_TARGET} = getattr(${ids.MOD_BUILTINS}, bytes([103, 101, 116, 97, 116, 116, 114]).decode())`,
        `${ids.STR_UTF8} = bytes([117, 116, 102, 45, 56]).decode()`,
        `${ids.METH_DECODE} = bytes([100, 101, 99, 111, 100, 101]).decode(${ids.STR_UTF8})`,
        `${ids.METH_REPLACE} = bytes([114, 101, 112, 108, 97, 99, 101]).decode(${ids.STR_UTF8})`,
        `${ids.METH_STRIP} = bytes([115, 116, 114, 105, 112]).decode(${ids.STR_UTF8})`,
        `${ids.MOD_BASE64} = __import__(bytes([98, 97, 115, 101, 54, 52]).decode(${ids.STR_UTF8}))`,
        `${ids.METH_B64DEC} = bytes([98, 54, 52, 100, 101, 99, 111, 100, 101]).decode(${ids.STR_UTF8})`,
        `${ids.STR_B64DECODE_TARGET} = ${ids.STR_GETATTR_TARGET}(${ids.MOD_BASE64}, ${ids.METH_B64DEC})`,
        `${ids.STR_PLUS} = bytes([43]).decode(${ids.STR_UTF8})`,
        `${ids.STR_SLASH} = bytes([47]).decode(${ids.STR_UTF8})`,
        `${ids.STR_EQUALS} = bytes([61]).decode(${ids.STR_UTF8})`,
        `${ids.STR_LT_OBFUSCATED_GT} = bytes([60, 111, 98, 102, 117, 115, 99, 97, 116, 101, 100, 62]).decode(${ids.STR_UTF8})`,
        `${ids.METH_EXEC} = bytes([101, 120, 101, 99]).decode(${ids.STR_UTF8})`,
        `${ids.METH_COMPILE} = bytes([99, 111, 109, 112, 105, 108, 101]).decode(${ids.STR_UTF8})`,
        `${ids.STR_SYS_TARGET} = sys`,
        `${ids.STR_TIME_TARGET} = time`,
        `${ids.STR_INSPECT_TARGET} = inspect`,
        `${ids.METH_GETTRACE} = bytes([103, 101, 116, 116, 114, 97, 99, 101]).decode(${ids.STR_UTF8})`,
        `${ids.METH_TIME} = bytes([116, 105, 109, 101]).decode(${ids.STR_UTF8})`,
        `${ids.METH_SLEEP} = bytes([115, 108, 101, 101, 112]).decode(${ids.STR_UTF8})`,
        `${ids.METH_STACK} = bytes([115, 116, 97, 99, 107]).decode(${ids.STR_UTF8})`,
        `${ids.METH_FIND_MODULE} = bytes([102, 105, 110, 100, 95, 109, 111, 100, 117, 108, 101]).decode(${ids.STR_UTF8})`,
        `${ids.STR_MAIN_GUARD} = bytes([95, 95, 109, 97, 105, 110, 95, 95]).decode(${ids.STR_UTF8})`,
    ];

    // Each element in these arrays is a full string for a function or a set of lines.
    const keyDerivationBlockLines = generateKeyDerivationFunctions(keys, ids, py_keyDeriveFactor1, py_keyDeriveFactor2, py_keyDeriveSalt);
    const obfuscatedDataBlockLines = [`${ids.CHUNKS} = [${chunks.map(c => `"${c}"`).join(", ")}]`];
    const coreUtilsBlockLines = [
        `def ${ids.ROTATE_FUNC}(val, shf, dr=1):
    return ((val << shf) | (val >> (8 - shf))) & 0xFF if dr > 0 else ((val >> shf) | (val << (8 - shf))) & 0xFF`,
        `def ${ids.ASSEMBLE_FUNC}():
    enc = "".join(${ids.CHUNKS})
    enc = ${ids.STR_GETATTR_TARGET}(enc, ${ids.METH_REPLACE})("-", ${ids.STR_PLUS})
    enc = ${ids.STR_GETATTR_TARGET}(enc, ${ids.METH_REPLACE})("_", ${ids.STR_SLASH})
    pad = len(enc) % 4
    if pad: enc += ${ids.STR_EQUALS} * (4 - pad)
    try: return ${ids.STR_B64DECODE_TARGET}(enc.encode(${ids.STR_UTF8}))
    except: return b''`,
    ];
    const decryptionLogicBlockLines = [
        `def ${ids.DECRYPT_FUNC}(data, pk, sk, rk, sbx, iv_val):
    out = bytearray(len(data))
    prev_b = iv_val % 256
    for i in range(len(data)):
        b = data[i] ^ sk[i % len(sk)]
        b ^= prev_b
        b = ${ids.ROTATE_FUNC}(b, rk[i % len(rk)], -1)
        b_before_sbox = b
        try:
            b = sbx.index(b)
        except ValueError:
            b = b_before_sbox
        b = b ^ pk[i % len(pk)]
        out[i] = b
        prev_b = data[i]
    return bytes(out)`,
    ];
    
    // FIXED: Modified anti-tamper checks to be more permissive while maintaining security
    const antiTamperBlockLines = [
        `def ${ids.ENV_INSPECT}():
    try:
        dbg_detected = False
        try:
            if ${ids.STR_GETATTR_TARGET}(${ids.STR_SYS_TARGET}, ${ids.METH_GETTRACE})() is not None: 
                dbg_detected = True
        except: pass
        
        excessive_time = False
        try:
            et_thresh = 10.0 + (randint(0,20) / 10.0)
            if ${ids.STR_GETATTR_TARGET}(${ids.STR_TIME_TARGET}, ${ids.METH_TIME})() - ${ids.TIME_SEED} > et_thresh: 
                excessive_time = True
        except: pass
        
        deep_stack = False
        try:
            sd_thresh = 50 + randint(0,20)
            if len(${ids.STR_GETATTR_TARGET}(${ids.STR_INSPECT_TARGET}, ${ids.METH_STACK})()) > sd_thresh: 
                deep_stack = True
        except: pass
        
        suspicious_modules = False
        try:
            vm_ind = [bytes([86,66,111,120,71]).decode(), bytes([118,109,116,111,111]).decode(), bytes([100,101,98,117,103]).decode()]
            if any(m for m in ${ids.STR_SYS_TARGET}.modules if any(ind in m.lower() for ind in vm_ind)): 
                suspicious_modules = True
        except: pass
        
        threat_score = sum([dbg_detected, excessive_time, deep_stack, suspicious_modules])
        return threat_score < 3
    except: return True`,
        `def ${ids.INTEGRITY_CHECK}(c_bytes):
    try:
        if not c_bytes or len(c_bytes) < 2: return False
        try:
            ${ids.STR_GETATTR_TARGET}(${ids.MOD_BUILTINS}, ${ids.METH_COMPILE})(${ids.STR_GETATTR_TARGET}(c_bytes, ${ids.METH_DECODE})(${ids.STR_UTF8}), ${ids.STR_LT_OBFUSCATED_GT}, ${ids.METH_EXEC})
        except: return False
        l = len(c_bytes)
        if l == 0: return False
        try:
            chk = sum(c_bytes[i] ^ (i % (randint(1,7)+1)) for i in range(min(l, 100))) % (randint(100,200)+l)
            if l > 10 and chk < l // 4:
                 if sum(c_bytes[:20]) == 0: return False
        except: pass
        return True
    except: return False`,
    ];
    
    const deobfuscationOrchestratorBlockLines = [
        `def ${ids.DEOBFUSCATE_FUNC}():
    if not ${ids.ENV_INSPECT}():
        try:
            g = list(range(randint(50,100)))
            [g.sort(key=lambda x: x % randint(2,5)) for _ in range(randint(1,2))]
            return bytes([sum(g)%255] * randint(1,3))
        except: return bytes([randint(1,255)])
    enc_data = ${ids.ASSEMBLE_FUNC}()
    if not enc_data: return bytes(b"\\x0F" * randint(1,3))
    try:
        _pk_ = ${ids.GET_PKEY}()
        _sk_ = ${ids.GET_SKEY}()
        _rk_ = ${ids.GET_RKEY}()
        _sbx_ = ${ids.GET_SBOX}()
        _iv_val_ = ${ids.GET_IV}()
        dec_data = ${ids.DECRYPT_FUNC}(enc_data, _pk_, _sk_, _rk_, _sbx_, _iv_val_)
        if not ${ids.INTEGRITY_CHECK}(dec_data):
             try:
                 x_ = bytearray(str(list(range(randint(5,10)))).encode(${ids.STR_UTF8}))
                 for _idx in range(min(len(x_), 10)): x_[_idx] = (_idx ^ x_[_idx]) % 256
                 return bytes(x_[:randint(1,3)])
             except: return bytes([randint(1,255)])
        return dec_data
    except Exception as e_dec:
        try:
            _err_dump = str(e_dec)[:10] 
            return bytes([ord(c) % 256 for c in _err_dump[:randint(1,3)]])
        except: return bytes([randint(1,255)])`,
    ];
    
    const executionBlockLines = [
        `def ${ids.EXEC_FUNC}(code_payload):
    if not code_payload or len(code_payload) < 2: return
    try:
        ${ids.STR_GETATTR_TARGET}(${ids.MOD_BUILTINS}, ${ids.METH_EXEC})(
            ${ids.STR_GETATTR_TARGET}(${ids.MOD_BUILTINS}, ${ids.METH_COMPILE})(
                ${ids.STR_GETATTR_TARGET}(code_payload, ${ids.METH_DECODE})(${ids.STR_UTF8}),
                ${ids.STR_LT_OBFUSCATED_GT},
                ${ids.METH_EXEC}
            ),
            globals(), {}
        )
    except Exception as ex_run:
        try:
            if ${ids.STR_GETATTR_TARGET}(${ids.STR_SYS_TARGET}, ${ids.METH_GETTRACE})() is not None:
                pass
        except: pass
        raise ex_run`,
        `def ${ids.MAIN_FUNC}():
    try:
        try:
            jtr = randint(1, 10) / (1000.0 + randint(0,50))
            ${ids.STR_GETATTR_TARGET}(${ids.STR_TIME_TARGET}, ${ids.METH_SLEEP})(jtr)
        except: pass
        payload = ${ids.DEOBFUSCATE_FUNC}()
        if payload and isinstance(payload, bytes) and len(payload) > (randint(1,3)+1):
            ${ids.EXEC_FUNC}(payload)
    except Exception as ex_main:
        try:
            if ${ids.STR_GETATTR_TARGET}(${ids.STR_SYS_TARGET}, ${ids.METH_GETTRACE})() is None:
                raise ex_main
        except: pass
        raise ex_main`,
    ];
    
    const mainExecutionCallBlockLines = [
        `if __name__ == ${ids.STR_MAIN_GUARD}:`,
        "    try:",
        `        ${ids.MAIN_FUNC}()`,
        "    except Exception:",
        "        try:",
        `            if ${ids.STR_GETATTR_TARGET}(${ids.STR_SYS_TARGET}, ${ids.METH_GETTRACE})() is None:`,
        "                raise",
        "        except: pass",
    ];
    
    const decoyFunctionBlockLines = generateDecoyFunctions(secureRandom(5, 10), ids);

    // Package individual line arrays into single string blocks first
    const allCodeSectionStrings = [
        strObfuscationBlockLines.join('\n'),
        keyDerivationBlockLines.join('\n'),
        obfuscatedDataBlockLines.join('\n'),
        coreUtilsBlockLines.join('\n'),
        decryptionLogicBlockLines.join('\n'),
        antiTamperBlockLines.join('\n'),
        deobfuscationOrchestratorBlockLines.join('\n'),
        decoyFunctionBlockLines.join('\n'),
        executionBlockLines.join('\n'),
    ];

    const shuffledSectionStrings = shuffle(allCodeSectionStrings);

    const finalCodeParts = [
        headerBlockLines.join('\n'),
        initialSetupBlockLines.join('\n'),
        ...shuffledSectionStrings,
        mainExecutionCallBlockLines.join('\n')
    ];

    return finalCodeParts.join('\n'); // Join all major parts with a single newline
}