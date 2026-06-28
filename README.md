<p align="center">
  <img src="https://github.com/drvova/pi-mcp-deferred/raw/master/pi-logo-animated.svg" alt="pi" width="120" />
</p>

<h1 align="center">pi-reverse</h1>

<p align="center">Static binary reverse-engineering MCP server for the <a href="https://github.com/earendil-works/pi">pi agent</a>.</p>

---

## Capabilities

| Capability | Details |
|---|---|
| Formats | ELF 32/64, PE 32/64, Mach-O, Java .class, JAR/J2ME, JAD, raw/unknown |
| Section parsing | Names, virtual addresses, file offsets, sizes, flags (W/A/X), per-section entropy |
| Import extraction | ELF shared library refs, PE import address table (DLL + functions), Java class refs |
| String extraction | ASCII (4+ chars) and UTF-16LE |
| Entropy | Sliding window with packed/encrypted detection (> 7.4) |
| Disassembly | x86 pseudo-disassembler + JVM bytecode disassembler (200+ opcodes) |
| Pseudocode | C-like from native disassembly, Java-like from bytecode |
| Source reconstruction | .java from bytecode, .c from native analysis |
| Algorithm fingerprinting | AES, RSA, SHA, CRC, compression, networking, filesystem, J2ME UI, GPU/register |
| IOC extraction | URLs, IPs, domains, registry paths, file paths |
| Capability detection | Persistence, process injection, C2, credential access, anti-analysis, crypto/ransomware, reflection, J2ME, driver/firmware |
| YARA seeds | String candidates for YARA rules |
| NanoPython | summary(), sections(), imports(), algorithms(), iocs(), capabilities(), find_strings(), grep() |

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

### NanoPython scripting

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
