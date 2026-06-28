# pi-reverse

Static binary reverse-engineering MCP server for the [pi agent](https://github.com/earendil-works/pi).

Direct TypeScript port of `ixlinx-agent-core/src/reverse.rs` (2345 lines of Rust).
Zero npm dependencies — uses only Node/Bun builtins.

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

## Installation

### As a pi package (recommended)

Add to `~/.pi/agent/settings.json`:

```json
{
  "packages": [
    "git:github.com/drvova/pi-reverse"
  ]
}
```

Pi will clone this repo into `~/.pi/agent/git/github.com/drvova/pi-reverse/` automatically.

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

The agent calls `reverse_analyze` with these arguments:

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

### NanoPython scripting

Pass a `script` string to query the report programmatically:

```
summary()                    # format, arch, size, sha256
sections()                   # section table
imports()                    # import list
algorithms()                 # algorithm fingerprints
iocs()                       # IOC candidates
capabilities()               # malware capability indicators
find_strings('needle')       # filter strings by substring
grep('needle')               # search disassembly + pseudocode + strings
print('text')                # echo literal text
```

## Supported formats

| Format | Detection | Sections | Imports | Disassembly | Source reconstruction |
|---|---|---|---|---|---|
| ELF 32/64 | `\x7fELF` magic | yes | `.so` references | x86 pseudo-disasm | C stub |
| PE 32/64 | `MZ` + `PE\0\0` | yes | IAT (DLL + functions) | x86 pseudo-disasm | C stub |
| Mach-O | `\xFE\xED\xFA` / `\xCE\xFA\xED` | detected | — | — | — |
| Java .class | `\xCA\xFE\xBA\xBE` | yes | class refs | JVM bytecode | .java |
| JAR / J2ME | `PK\x03\x04` + `.jar` | entries | manifest + refs | JVM bytecode | .java |
| JAD | `.jad` extension | — | metadata | — | — |
| Raw / unknown | fallback | — | — | x86 pseudo-disasm | C stub |

## Architecture

```
src/
  index.ts    MCP server (stdio JSON-RPC) + CLI + analyzeBinary orchestrator + formatReport
  parsers.ts  ELF, PE, Java class, JAR/ZIP, JAD parsers
  utils.ts    sha256, entropy, string extraction, x86 disasm, algorithm/IOC/capability extraction, source reconstruction, nanopython
  types.ts    ReverseReport, BinarySection, AnalyzeOptions interfaces
```

No npm dependencies. Uses only `node:crypto`, `node:fs`, `node:path`, `node:readline`, and Bun's `inflateSync` for DEFLATE decompression in JAR parsing.

## License

MIT
