<p align="center">
  <img src="https://github.com/drvova/pi-mcp-deferred/raw/master/pi-logo-animated.svg" alt="pi" width="120" />
</p>

<h1 align="center">pi-reverse</h1>

<p align="center">Static binary reverse-engineering MCP server for the <a href="https://github.com/earendil-works/pi">pi agent</a>.</p>

---

## Capabilities

### Format detection and parsing

| Format | Magic | Sections | Imports | Exports | Disassembly | Pseudocode | Source reconstruction |
|---|---|---|---|---|---|---|---|
| ELF 32-bit | `\x7fELF` (class 1) | yes | `.so` references | — | x86 pseudo-disasm | C-like | C stub |
| ELF 64-bit | `\x7fELF` (class 2) | yes | `.so` references | — | x86 pseudo-disasm | C-like | C stub |
| PE 32-bit | `MZ` + `PE\0\0` (machine 0x14c) | yes | IAT (DLL + functions) | — | x86 pseudo-disasm | C-like | C stub |
| PE 64-bit | `MZ` + `PE\0\0` (machine 0x8664) | yes | IAT (DLL + functions) | — | x86 pseudo-disasm | C-like | C stub |
| Mach-O | `\xFE\xED\xFA` / `\xCE\xFA\xED` | detected | — | — | — | — | — |
| Java .class | `\xCA\xFE\xBA\xBE` | yes | class refs | — | JVM bytecode (200+ opcodes) | Java-like | .java |
| JAR / J2ME | `PK\x03\0x04` + `.jar` | entries | manifest + refs | — | JVM bytecode (200+ opcodes) | Java-like | .java |
| JAD | `.jad` extension | — | metadata | — | — | — | — |
| Raw / unknown | fallback | — | — | — | x86 pseudo-disasm | C-like | C stub |

### Architecture detection

| Architecture | ELF | PE |
|---|---|---|
| x86 | 0x03 | 0x014c |
| x86_64 | 0x3e | 0x8664 |
| ARM | 0x28 | 0x01c0 |
| AArch64 | 0xb7 | 0xaa64 |
| MIPS | 0x08 | — |
| RISC-V | 0xf3 | — |

### Section parsing

- Section names, virtual addresses, file offsets, sizes, flags (W/A/X)
- Per-section entropy calculation
- Writable+executable section detection (loader, unpacker, JIT, shellcode staging)
- High-entropy section detection (> 7.2 = packed/compressed/firmware blob)
- Executable code region identification
- Section bytes extraction via virtual address and file offset

### Import extraction

- ELF: shared library references (`.so` strings from `.dynstr`)
- PE: import address table (DLL name + function names from IAT)
- Java: class references from constant pool
- JAR: manifest metadata + all class references

### String extraction

- ASCII strings (4+ printable characters)
- UTF-16LE strings (4+ printable characters)
- Configurable maximum count (`max_strings` parameter)

### Entropy analysis

- Sliding window entropy (256-byte window, Shannon entropy)
- Per-section entropy
- Packed/encrypted detection threshold (> 7.4 = likely packed/encrypted)
- Entropy window map for visualizing entropy distribution

### Disassembly

**x86/x86_64 pseudo-disassembler** (34 opcodes):
- Arithmetic: `add`, `sub`, `xor`, `and`, `or`, `inc`, `dec`, `neg`, `mul`, `div`, `imul`
- Stack: `push`, `pop`, `mov`, `lea`
- Control flow: `jmp`, `je`, `jne`, `jl`, `jle`, `jg`, `jge`, `jb`, `jbe`, `ja`, `jae`, `call`, `ret`, `nop`
- Memory: `int3`, `int 0x80`, `syscall`, `leave`
- Register and immediate operand decoding
- Address annotation

**JVM bytecode disassembler** (200+ opcodes):
- Constants: nop, aconst_null, iconst_*, lconst_*, fconst_*, dconst_*, bipush, sipush, ldc, ldc_w, ldc2_w
- Loads: iload*, lload*, fload*, dload*, aload*, iaload, laload, faload, daload, aaload, baload, caload, saload
- Stores: istore*, lstore*, fstore*, dstore*, astore*, iastore, lastore, fastore, dastore, aastore, bastore, castore, sastore
- Stack: pop, pop2, dup, dup_x1, dup_x2, dup2, dup2_x1, dup2_x2, swap
- Arithmetic: iadd, ladd, fadd, dadd, isub, lsub, fsub, dsub, imul, lmul, fmul, dmul, idiv, ldiv, fdiv, ddiv, irem, lrem, frem, drem, ineg, lneg, fneg, dneg, ishl, lshl, ishr, lshr, iushr, lushr, iand, land, ior, lor, ixor, lxor, iinc
- Conversion: i2l, i2f, i2d, l2i, l2f, l2d, f2i, f2l, f2d, d2i, d2l, d2f, i2b, i2c, i2s
- Comparison: lcmp, fcmpl, fcmpg, dcmpl, dcmpg
- Branching: ifeq, ifne, iflt, ifge, ifgt, ifle, if_icmpeq, if_icmpne, if_icmplt, if_icmpge, if_icmpgt, if_icmple, if_acmpeq, if_acmpne, goto, jsr, ret, tableswitch, lookupswitch, ifnull, ifnonnull
- Method invocation: invokevirtual, invokespecial, invokestatic, invokeinterface, invokedynamic
- Object: new, newarray, anewarray, arraylength, athrow, checkcast, instanceof, monitorenter, monitorexit
- Wide, multianewarray, ifnull, ifnonnull
- Field access: getstatic, putstatic, getfield, putfield
- Type resolution and branch target annotation

### Pseudocode generation

- **C-like** from native x86 disassembly: register assignments, arithmetic operations, function calls, conditional branches, loops (backward jump detection)
- **Java-like** from JVM bytecode: method signatures, field access, method invocation, type casting, array operations, control flow

### Source reconstruction

- **Java `.java` files** from bytecode: class declaration, fields, constructors, methods with proper Java types, return statements, method invocations, field accesses, type casts
- **C `.c` files** from native analysis: function stubs from disassembly, string references, import declarations

### Algorithm fingerprinting

| Category | Patterns |
|---|---|
| AES | `AES`, `aes`, `rijndael`, `sbox` |
| RSA | `RSA`, `rsa`, `modexp`, `publickey` |
| Hashing | `sha1`, `sha256`, `md5` |
| CRC/Checksum | `crc32`, `checksum`, `adler` |
| Compression | `inflate`, `deflate`, `gzip`, `zlib`, `lzma` |
| Networking | `socket`, `datagram` |
| J2ME UI | `javax.microedition.lcdui`, `midlet`, `canvas`, `displayable` |
| GPU/Register | `mmio`, `register`, `reg_`, `opcode`, `microcode`, `firmware`, `shader` |
| Control flow | backward branch detection (`goto`, `jmp`, `if` with target < address) |
| Register/opcode strings | `0x`, `reg`, `mmio` candidates from string table |
| High-entropy sections | packed/compressed/firmware blob candidates (entropy > 7.2) |
| Executable regions | code section identification with file offset and size |

### IOC extraction

| IOC type | Regex pattern |
|---|---|
| URLs | `https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}` |
| IPv4 addresses | `\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b` |
| Domains | `\b(?:[A-Za-z0-9-]{2,63}\.)+(?:com|net|org|io|ru|cn|biz|info|top|xyz|online|site|dev|nl)\b` |
| Registry paths | `\bHK(?:LM|CU|CR|U|CC)\\[A-Za-z0-9_\\ .{}-]{4,}` (case-insensitive) |
| File paths | `\b[A-Z]:\\[A-Za-z0-9_ .\\/\-]{4,}` (case-insensitive) |

Maximum 256 IOC candidates extracted per analysis.

### Capability detection

| Capability | Indicators |
|---|---|
| Persistence | `currentversion\run`, `runonce`, `startup`, `createservice`, `schtasks`, `systemd`, `launchdaemon`, `midlet-push` |
| Process injection / memory tampering | `virtualalloc`, `virtualallocex`, `writeprocessmemory`, `createremotethread`, `ntmapviewofsection`, `setwindowshookex`, `ptrace`, `process hollow` |
| Network / C2 | `internetopen`, `winhttp`, `wsastartup`, `connect`, `socket`, `recv`, `send`, `javax.microedition.io.connector`, `socket://`, `http://`, `https://` |
| Credential or browser data access | `lsass`, `dpapi`, `cryptunprotectdata`, `login data`, `cookies`, `keychain`, `wallet`, `password` |
| Anti-analysis / sandbox awareness | `isdebuggerpresent`, `checkremotedebuggerpresent`, `ntqueryinformationprocess`, `vmware`, `virtualbox`, `qemu`, `sandbox`, `debugger`, `frida` |
| Crypto / ransomware primitive | `cryptencrypt`, `bcrypt`, `aes`, `rsa`, `chacha`, `salsa20`, `curve25519`, `ransom`, `.locked` |
| Java reflection / dynamic loading | `class.forname`, `getdeclaredmethod`, `invoke(`, `classloader`, `defineclass`, `reflection` |
| J2ME sensitive capability | `midlet-permissions`, `javax.microedition.io.file.fileconnection`, `javax.wireless.messaging`, `pushregistry`, `recordstore` |
| Driver / firmware reverse target | `ioctl`, `deviceiocontrol`, `mmio`, `pci`, `bar0`, `register`, `opcode`, `microcode`, `firmware`, `shader` |
| Writable+executable section | Detected from section flags (W+X = loader, unpacker, JIT, shellcode staging) |

Maximum 8 indicator hits per capability category.

### YARA seed strings

Extracts strings (6-96 chars) matching: `.dll`, `http`, `reg`, `mutex`, `cmd`, `powershell`, `midlet`, `opcode`, `microcode`. Maximum 12 seed strings.

### NanoPython scripting

| Function | Description |
|---|---|
| `summary()` | Format, architecture, file size, SHA-256 hash |
| `sections()` | Section table (name, vaddr, offset, size, flags, entropy) |
| `imports()` | Import list |
| `algorithms()` | Algorithm fingerprint results |
| `iocs()` | IOC candidates (URLs, IPs, domains, registry, paths) |
| `capabilities()` | Malware capability indicators |
| `find_strings('needle')` | Filter extracted strings by substring |
| `grep('needle')` | Search across disassembly + pseudocode + strings |
| `print('text')` | Echo literal text |

### Analysis modes

| Mode | Output |
|---|---|
| `overview` | Format, architecture, sections, imports, entropy, algorithm/IOC/capability summary |
| `strings` | All extracted ASCII and UTF-16LE strings |
| `disasm` | Disassembly + pseudocode |
| `all` | Everything: overview + strings + disasm + algorithms + IOCs + capabilities + YARA seeds |
| `source` | Reconstructed source code (.java or .c) |
| `reconstruct` | Reconstructed source with full report |

### SHA-256 hashing

Every analyzed binary gets a SHA-256 hash computed via `node:crypto`.

## Installation

Add to `~/.pi/agent/settings.json`:

```json
{
  "packages": [
    "git:github.com/drvova/pi-reverse"
  ]
}
```

Then add to `~/.pi/agent/mcp.json`:

```json
{
  "mcpServers": {
    "pi-reverse": {
      "command": "bun",
      "args": ["~/.pi/agent/git/github.com/drvova/pi-reverse/src/index.ts"]
    }
  }
}
```

Restart your pi session. The `reverse_analyze` tool will be available.

### Standalone

```bash
git clone https://github.com/drvova/pi-reverse.git
cd pi-reverse
bun src/index.ts --cli /bin/ls --mode overview
```

## Usage

### MCP tool: `reverse_analyze`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `path` | string | (required) | Path to the binary file to analyze |
| `mode` | string | `overview` | `overview`, `strings`, `disasm`, `all`, `source`, `reconstruct` |
| `max_strings` | number | 160 | Maximum number of strings to extract |
| `max_disassembly` | number | 256 | Maximum disassembly lines |
| `max_bytes` | number | 67108864 | Maximum bytes to read (0 = unlimited) |
| `script` | string | — | NanoPython script to run against the report |
| `generate_source` | boolean | false | Generate reconstructed source code |

### CLI

```bash
bun src/index.ts --cli /bin/ls --mode overview
bun src/index.ts --cli /bin/ls --mode all --generate-source
bun src/index.ts --cli ./app.class --mode all --max-disasm 50
bun src/index.ts --cli ./malware.exe --script "iocs()
capabilities()"
```

### Self-test

```bash
bun src/index.ts --self-test
```

Verifies: entropy calculation, string extraction, x86 disassembly, SHA-256 hashing.

## Architecture

```
src/
  index.ts    MCP server (stdio JSON-RPC) + CLI + analyzeBinary orchestrator + formatReport
  parsers.ts  ELF, PE, Java class, JAR/ZIP, JAD parsers (44 functions)
  utils.ts    sha256, entropy, string extraction, x86 disasm, algorithm/IOC/capability extraction, source reconstruction, nanopython (13 functions)
  types.ts    ReverseReport, BinarySection, EntropyWindow, ReconstructedSource, AnalyzeOptions interfaces
```

No npm dependencies. Uses only `node:crypto`, `node:fs`, `node:path`, `node:readline`, and Bun's `inflateSync` for DEFLATE decompression in JAR parsing.

## License

MIT
