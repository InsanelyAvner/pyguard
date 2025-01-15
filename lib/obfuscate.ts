// lib/obfuscate.ts

/**
 * 1) XOR encryption
 * 2) Base64 encoding
 * 3) Reverse string
 * 4) Random chunking
 * 5) Frequent troll line injection
 * 6) Merged lines
 * 7) Overwriting built-ins / hidden exec
 *
 * This function returns the final obfuscated Python code as a string.
 */
export function obfuscateCode(input: string): string {
    // TROLLS
    const TROLLS = [
      `"Look closely, but not too closely."`,
      `"Some doors are better left unopened."`,
      `"Unlocking secrets? Try harder."`,
      `"This is the one line you'll regret skipping."`,
      `"Counting bugs before they hatch."`,
      `"Code so elegant, it's practically an heirloom."`,
      `"The answer lies in another repo."`,
      `"One does not simply debug this."`,
      `"Breadcrumbs for the brave."`,
      `"Debugging? More like treasure hunting."`,
      `"Careful, you're almost overthinking this."`,
      `"Every line a riddle, every comment a trap."`,
      `"Hidden layers await the persistent."`,
      `"Obfuscation is an art form."`,
      `"Fortune favors the bold coder."`,
      `"Intricate webs of logic."`,
      `"Patience is key, adventurer."`,
      `"Embrace the complexity."`,
      `"Silent guardians of the code."`,
      `"The maze deepens."`,
    ];
  
    // Utility
    const randInt = (min: number, max: number) =>
      Math.floor(Math.random() * (max - min + 1)) + min;
    const randomTroll = () => TROLLS[randInt(0, TROLLS.length - 1)];
    const randomIdent = (len = 8) =>
      Array.from({ length: len }, () =>
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[
          randInt(0, 51)
        ]
      ).join("");
  
    // XOR
    const generateKey = (keySize: number) =>
      Array.from({ length: keySize }, () => randInt(0, 255));
    const xorEncrypt = (plaintext: string, key: number[]) =>
      Array.from(plaintext, (c, i) => c.charCodeAt(0) ^ key[i % key.length]);
    const bytesToBase64 = (byteArr: number[]) =>
      btoa(String.fromCharCode(...byteArr));
  
    // 1) XOR
    const keySize = randInt(20, 40);
    const keyArr = generateKey(keySize);
    const xoredBytes = xorEncrypt(input, keyArr);
  
    // 2) Base64
    const encoded = bytesToBase64(xoredBytes);
  
    // 3) Reverse
    const reversed = encoded.split("").reverse().join("");
  
    // 4) Random chunking
    const chunkList: string[] = [];
    {
      let i = 0;
      while (i < reversed.length) {
        const chunkSize = randInt(25, 60);
        chunkList.push(reversed.slice(i, i + chunkSize));
        i += chunkSize;
      }
    }
  
    // 5) Random Identifiers
    const KEY_VAR = randomIdent(10),
      CHUNK_VAR = randomIdent(10),
      XOR_FUNC = randomIdent(12),
      REV_FUNC = randomIdent(12),
      DEC_VAR = randomIdent(10),
      CODE_VAR = randomIdent(10),
      BUILTINS_VAR = randomIdent(10),
      RUN_FUNC = randomIdent(12),
      SNEAKY_LAMBDA = randomIdent(12);
  
    // 6) Build lines
    const lines: string[] = [
      "# Protected by PyGuard (pyguard.akean.dev)",
      "#!/usr/bin/env python3",
      randomTroll(),
      "import sys, base64",
      randomTroll(),
      "sys.setrecursionlimit(10**7)",
      randomTroll(),
      `${KEY_VAR}=[${keyArr.join(", ")}]`,
      `${CHUNK_VAR}=[]`,
      ...chunkList.flatMap((c) => [
        `${CHUNK_VAR}.append("${c}")`,
        randInt(0, 1) ? randomTroll() : "",
      ]),
      `def ${XOR_FUNC}(barr,key):return bytes([b^key[i%len(key)] for i,b in enumerate(barr)])`,
      `def ${REV_FUNC}(s):return s[::-1]`,
      randomTroll(),
      `${DEC_VAR}="".join(${CHUNK_VAR})`,
      `${DEC_VAR}=${REV_FUNC}(${DEC_VAR})`,
      `${DEC_VAR}=base64.b64decode(${DEC_VAR})`,
      `${CODE_VAR}=${XOR_FUNC}(${DEC_VAR},${KEY_VAR})`,
      `${BUILTINS_VAR}=__import__("builtins").__dict__.copy()`,
      `for _k in ["print","exec","compile","eval"]:__import__("builtins").__dict__[_k]=lambda *a,**kw:None`,
      `def ${RUN_FUNC}(code_bytes):import types;bdict=__import__("builtins").__dict__;bdict.update(${BUILTINS_VAR});cobj=compile(code_bytes.decode("utf-8"),"<obfuscated>","exec");eval(cobj,{"__builtins__":bdict},{})`,
      `${SNEAKY_LAMBDA}=(lambda f,d:f(d))`,
      `${SNEAKY_LAMBDA}(${RUN_FUNC},${CODE_VAR})`,
    ];
  
    // Insert more trolls after every 3 lines
    const enhanced: string[] = [];
    const insertionInterval = 3;
    lines.forEach((line, index) => {
      enhanced.push(line);
      if ((index + 1) % insertionInterval === 0) {
        enhanced.push(randomTroll());
      }
    });
  
    // Final
    return enhanced.join("\n");
  }
  