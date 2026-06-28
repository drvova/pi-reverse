# pi-reverse

Static binary reverse-engineering MCP server for the pi agent.

Direct TypeScript port of `ixlinx-agent-core/src/reverse.rs` (2345 lines of Rust).
Zero external dependencies beyond Node/Bun builtins.

## What it does

Analyzes binary files and returns:

- **Format detection**: ELF (32/64-bit), PE (32/64-bit), Mach-O (detected), Java .class, JAR/J2ME archives, JAD descriptors, raw/unknown
- **Section table parsing**: names, virtual addresses, file offsets, sizes, flags (W/A/X), per-section entropy
- **Import extraction**: ELF shared library references, PE import address table (DLL + function names), Java class references
- **String extraction**: ASCII (4+ chars) and UTF-16LE
- **Entropy analysis**: sliding window entropy with packed/encrypted detection (> 7.4)
- **Disassembly**: x86/x86_64 pseudo-disassembler (common opcodes), JVM bytecode disassembler (200+ opcodes)
- **Pseudocode generation**: C-like pseudocode from disassembly, Java method pseudocode from bytecode
- **Algorithm fingerprinting**: AES, RSA, SHA, CRC, compression, networking, filesystem, J2ME UI, GPU/register work
- **Malware lab indicators**: IOC extraction (URLs, IPs, domains, registry paths, file paths), capability detection (persistence, process injection, C2, credential access, anti-analysis, crypto/ransomware, reflection, J2ME capabilities, driver/firmware), YARA seed strings
- **Source reconstruction**: Java .java files from bytecode, C files from native analysis
- **NanoPython scripting**: summary(), sections(), imports(), algorithms(), iocs(), capabilities(), find_strings('needle'), grep('needle')

## Usage

### As MCP server (pi agent)

Registered in `~/.pi/agent/mcp.json`:

```json
{
  "pi-reverse": {
    "command": "bun",
    "args": ["/home/drvova/kot/pi-reverse/src/index.ts"]
  }
}
```

The agent can then call `reverse_analyze` with:
- `path` (required): path to binary
- `mode`: overview | strings | disasm | all | source | reconstruct
- `max_strings`: default 160
- `max_disassembly`: default 256
- `max_bytes`: default 64MB (0 = unlimited)
- `script`: NanoPython script
- `generate_source`: boolean

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

## Architecture

```
src/
  index.ts    — MCP server (stdio JSON-RPC) + CLI + analyzeBinary orchestrator + formatReport
  parsers.ts  — ELF, PE, Java class, JAR/ZIP, JAD parsers
  utils.ts    — sha256, entropy, string extraction, x86 disasm, algorithm/IOC/capability extraction, source reconstruction, nanopython
  types.ts    — ReverseReport, BinarySection, AnalyzeOptions interfaces
```

No npm dependencies. Uses only `node:crypto`, `node:fs`, `node:path`, `node:readline`, and Bun's `inflateSync` for DEFLATE decompression in JAR parsing.
