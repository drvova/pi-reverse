import { createHash } from "node:crypto";
import type { EntropyWindow } from "./types.js";

export function sha256(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function entropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const b of bytes) counts[b]++;
  const len = bytes.length;
  let sum = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / len;
      sum -= p * Math.log2(p);
    }
  }
  return sum;
}

export function entropyWindows(bytes: Uint8Array, window: number, max: number): EntropyWindow[] {
  if (bytes.length === 0) return [];
  const out: EntropyWindow[] = [];
  const step = Math.max(window, 256);
  let offset = 0;
  while (offset < bytes.length && out.length < max) {
    const end = Math.min(offset + step, bytes.length);
    out.push({ offset, size: end - offset, entropy: entropy(bytes.subarray(offset, end)) });
    offset += step;
  }
  return out;
}

export function extractStrings(bytes: Uint8Array, max: number): string[] {
  const out: string[] = [];
  let cur: number[] = [];
  function flush() {
    if (cur.length >= 4 && out.length < max) {
      try { out.push(new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(cur))); } catch {}
    }
    cur = [];
  }
  for (const b of bytes) {
    if ((b >= 0x21 && b <= 0x7e) || b === 0x20) cur.push(b);
    else { flush(); if (out.length >= max) return out; }
  }
  flush();
  if (out.length < max) extractUtf16leStrings(bytes, max, out);
  return out;
}

function extractUtf16leStrings(bytes: Uint8Array, max: number, out: string[]): void {
  let cur: number[] = [];
  function flush() {
    if (cur.length >= 4 && out.length < max) {
      try { out.push(new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(cur))); } catch {}
    }
    cur = [];
  }
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const code = bytes[i] | (bytes[i + 1] << 8);
    if (code >= 0x20 && code <= 0x7e) cur.push(code & 0xff);
    else { flush(); if (out.length >= max) return; }
  }
  flush();
}

// ── x86 pseudo-disassembly ───────────────────────────────────────────────────

export function pseudoDisassemble(bytes: Uint8Array, maxLines: number): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < bytes.length && out.length < maxLines) {
    const op = bytes[i];
    let mnemonic = "";
    let size = 1;
    if (op === 0x55) { mnemonic = "push rbp"; size = 1; }
    else if (op === 0x53) { mnemonic = "push rbx"; size = 1; }
    else if (op === 0x57) { mnemonic = "push rdi"; size = 1; }
    else if (op === 0x56) { mnemonic = "push rsi"; size = 1; }
    else if (op === 0x5d) { mnemonic = "pop rbp"; size = 1; }
    else if (op === 0xc3) { mnemonic = "ret"; size = 1; }
    else if (op === 0xcc) { mnemonic = "int3"; size = 1; }
    else if (op === 0x90) { mnemonic = "nop"; size = 1; }
    else if (op === 0xe8 && i + 4 < bytes.length) {
      const rel = bytes[i + 1] | (bytes[i + 2] << 8) | (bytes[i + 3] << 16) | (bytes[i + 4] << 24);
      const signed = rel > 0x7fffffff ? rel - 0x100000000 : rel;
      mnemonic = `call 0x${Math.max(0, i + 5 + signed).toString(16)}`; size = 5;
    }
    else if (op === 0xe9 && i + 4 < bytes.length) {
      const rel = bytes[i + 1] | (bytes[i + 2] << 8) | (bytes[i + 3] << 16) | (bytes[i + 4] << 24);
      const signed = rel > 0x7fffffff ? rel - 0x100000000 : rel;
      mnemonic = `jmp 0x${Math.max(0, i + 5 + signed).toString(16)}`; size = 5;
    }
    else if (op === 0xeb && i + 1 < bytes.length) {
      const rel = bytes[i + 1] > 0x7f ? bytes[i + 1] - 0x100 : bytes[i + 1];
      mnemonic = `jmp.short 0x${Math.max(0, i + 2 + rel).toString(16)}`; size = 2;
    }
    else if (op === 0x74 && i + 1 < bytes.length) {
      const rel = bytes[i + 1] > 0x7f ? bytes[i + 1] - 0x100 : bytes[i + 1];
      mnemonic = `jz 0x${Math.max(0, i + 2 + rel).toString(16)}`; size = 2;
    }
    else if (op === 0x75 && i + 1 < bytes.length) {
      const rel = bytes[i + 1] > 0x7f ? bytes[i + 1] - 0x100 : bytes[i + 1];
      mnemonic = `jnz 0x${Math.max(0, i + 2 + rel).toString(16)}`; size = 2;
    }
    else if (op === 0x48 && i + 2 < bytes.length && bytes[i + 1] === 0x89 && bytes[i + 2] === 0xe5) {
      mnemonic = "mov rbp,rsp"; size = 3;
    }
    else if (op === 0x48 && i + 3 < bytes.length && bytes[i + 1] === 0x83 && bytes[i + 2] === 0xec) {
      mnemonic = `sub rsp,0x${bytes[i + 3].toString(16).padStart(2, "0")}`; size = 4;
    }
    else if (op === 0x48 && i + 3 < bytes.length && bytes[i + 1] === 0x83 && bytes[i + 2] === 0xc4) {
      mnemonic = `add rsp,0x${bytes[i + 3].toString(16).padStart(2, "0")}`; size = 4;
    }
    else if (op >= 0x40 && op <= 0x4f) { mnemonic = `rex 0x${op.toString(16).padStart(2, "0")}`; size = 1; }
    else { mnemonic = `db 0x${op.toString(16).padStart(2, "0")}`; size = 1; }

    const rawEnd = Math.min(i + size, bytes.length);
    const raw = Array.from(bytes.subarray(i, rawEnd)).map(b => b.toString(16).padStart(2, "0")).join(" ");
    out.push(`0x${i.toString(16).padStart(8, "0")}: ${raw.padEnd(16)} ${mnemonic}`);
    i += Math.max(size, 1);
  }
  return out;
}

// ── Pseudocode generation ────────────────────────────────────────────────────

import type { ReverseReport } from "./types.js";

export function generatePseudocode(report: ReverseReport): string[] {
  const out: string[] = ["int recovered_entry(void) {"];
  for (const line of report.disassembly.slice(0, 180)) {
    const instr = line.split(/\s+/).slice(2).join(" ");
    if (instr.startsWith("call ")) out.push(`    call_target(${instr.replace("call ", "")});`);
    else if (instr.startsWith("jmp ") || instr.startsWith("jmp.short ")) out.push(`    goto label_${instr.split(" ").pop() ?? "unknown"};`);
    else if (instr.startsWith("jz ") || instr.startsWith("jnz ")) out.push(`    if (condition) goto label_${instr.split(" ").pop() ?? "unknown"};`);
    else if (instr === "ret") out.push("    return 0;");
    else if (instr.startsWith("mov ")) out.push(`    ${instr.replace("mov ", "assign ")}; `);
    else if (instr.startsWith("sub rsp")) out.push("    allocate_stack_frame();");
    else if (instr.startsWith("add rsp")) out.push("    release_stack_frame();");
  }
  out.push("}");
  return out;
}

// ── Algorithm / IOC / capability extraction ──────────────────────────────────

function collectRegex(input: string, pattern: RegExp, label: string, out: string[]): void {
  for (const m of input.matchAll(pattern)) {
    const value = m[0].replace(/["'\)\];]/g, "").trim();
    if (value) out.push(`${label}=${value}`);
  }
}

export function extractAlgorithms(report: ReverseReport): string[] {
  const out: string[] = [];
  const lowerStrings = report.strings.map(s => s.toLowerCase());
  const joined = lowerStrings.join("\n");
  const markers: [string, string[]][] = [
    ["AES", ["aes", "rijndael", "sbox"]],
    ["RSA", ["rsa", "modexp", "publickey"]],
    ["SHA/Hashing", ["sha1", "sha-1", "sha256", "sha-256", "md5"]],
    ["CRC/checksum", ["crc32", "checksum", "adler"]],
    ["Compression", ["inflate", "deflate", "gzip", "zlib", "lzma"]],
    ["Networking", ["http://", "https://", "socket", "datagram", "javax.microedition.io"]],
    ["Filesystem/RMS", ["recordstore", "fileconnection", "javax.microedition.rms"]],
    ["J2ME UI", ["javax.microedition.lcdui", "midlet", "canvas", "displayable"]],
    ["GPU/register work", ["mmio", "register", "reg_", "opcode", "microcode", "firmware", "shader"]],
  ];
  for (const [label, needles] of markers) {
    if (needles.some(n => joined.includes(n))) out.push(`${label} indicators found in strings/imports`);
  }
  for (const s of report.strings) {
    const lower = s.toLowerCase();
    if (lower.includes("0x") || lower.includes("reg") || lower.includes("mmio"))
      out.push(`register/opcode candidate string: ${s}`);
  }
  for (const section of report.sections) {
    if (section.entropy > 7.2)
      out.push(`packed/compressed or firmware-like blob candidate: section ${section.name} entropy ${section.entropy.toFixed(2)}`);
    if (section.flags.includes("X") && section.size > 0)
      out.push(`executable code region: ${section.name} file_off=0x${section.file_offset.toString(16)} size=0x${section.size.toString(16)}`);
  }
  const backwardJumps = report.disassembly.filter(line => {
    const colonIdx = line.indexOf(":");
    if (colonIdx < 0) return false;
    const addr = parseInt(line.slice(0, colonIdx).trim().replace("0x", ""), 16) || 0;
    if (!/goto|jmp|if/.test(line)) return false;
    const hexMatch = line.match(/0x([0-9a-f]+)\s*$/);
    const target = hexMatch ? parseInt(hexMatch[1], 16) : addr;
    return target < addr;
  }).length;
  if (backwardJumps > 0) out.push(`loop/control-flow indicators: ${backwardJumps} backward branches`);
  if (out.length === 0) out.push("no strong algorithm fingerprint; inspect strings, imports, entropy, and pseudocode manually");
  out.sort();
  return [...new Set(out)];
}

export function extractLabIndicators(report: ReverseReport): string[] {
  const corpus = [...report.strings, ...report.imports, ...report.pseudocode];
  const joined = corpus.join("\n");
  const lower = joined.toLowerCase();
  const out: string[] = [];
  const iocs: string[] = [];
  collectRegex(joined, /https?:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}/g, "url", iocs);
  collectRegex(joined, /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, "ipv4", iocs);
  collectRegex(joined, /\b(?:[A-Za-z0-9-]{2,63}\.)+(?:com|net|org|io|ru|cn|biz|info|top|xyz|online|site|dev|nl)\b/g, "domain", iocs);
  collectRegex(joined, /\bHK(?:LM|CU|CR|U|CC)\\[A-Za-z0-9_\\ .{}-]{4,}/gi, "registry", iocs);
  collectRegex(joined, /\b[A-Z]:\\[A-Za-z0-9_ .\\/\-]{4,}/gi, "path", iocs);
  out.push(...iocs.slice(0, 256).map(item => `IOC candidate: ${item}`));

  const capabilities: [string, string[]][] = [
    ["persistence", ["currentversion\\run", "runonce", "startup", "createservice", "schtasks", "systemd", "launchdaemon", "midlet-push"]],
    ["process injection / memory tampering", ["virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection", "setwindowshookex", "ptrace", "process hollow"]],
    ["network / C2", ["internetopen", "winhttp", "wsastartup", "connect", "socket", "recv", "send", "javax.microedition.io.connector", "socket://", "http://", "https://"]],
    ["credential or browser data access", ["lsass", "dpapi", "cryptunprotectdata", "login data", "cookies", "keychain", "wallet", "password"]],
    ["anti-analysis / sandbox awareness", ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "vmware", "virtualbox", "qemu", "sandbox", "debugger", "frida"]],
    ["crypto / ransomware primitive", ["cryptencrypt", "bcrypt", "aes", "rsa", "chacha", "salsa20", "curve25519", "ransom", ".locked"]],
    ["Java reflection / dynamic loading", ["class.forname", "getdeclaredmethod", "invoke(", "classloader", "defineclass", "reflection"]],
    ["J2ME sensitive capability", ["midlet-permissions", "javax.microedition.io.file.fileconnection", "javax.wireless.messaging", "pushregistry", "recordstore"]],
    ["driver / firmware reverse target", ["ioctl", "deviceiocontrol", "mmio", "pci", "bar0", "register", "opcode", "microcode", "firmware", "shader"]],
  ];
  for (const [name, needles] of capabilities) {
    const hits = needles.filter(n => lower.includes(n)).slice(0, 8);
    if (hits.length > 0) out.push(`capability: ${name} indicators [${hits.join(", ")}]`);
  }
  if (report.sections.some(s => s.flags.includes("W") && s.flags.includes("X")))
    out.push("capability: writable+executable section; loader, unpacker, JIT, or shellcode staging candidate");

  const yaraStrings = report.strings
    .filter(s => {
      const lower = s.toLowerCase();
      return s.length >= 6 && s.length <= 96 &&
        (lower.includes(".dll") || lower.includes("http") || lower.includes("reg") ||
         lower.includes("mutex") || lower.includes("cmd") || lower.includes("powershell") ||
         lower.includes("midlet") || lower.includes("opcode") || lower.includes("microcode"));
    })
    .slice(0, 12);
  if (yaraStrings.length > 0)
    out.push(`YARA seed strings: ${yaraStrings.map(s => JSON.stringify(s)).join(", ")}`);

  out.sort();
  return [...new Set(out)];
}

// ── Source reconstruction ────────────────────────────────────────────────────

function cEscape(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r");
}

export function reconstructSources(report: ReverseReport): import("./types.js").ReconstructedSource[] {
  if (report.reconstructed_sources.length > 0) return report.reconstructed_sources;
  let c = "#include <stdint.h>\n#include <stddef.h>\n\n";
  c += "typedef struct recovered_blob { const char *name; const char *value; } recovered_blob;\n\n";
  c += "static const recovered_blob recovered_strings[] = {\n";
  for (const s of report.strings.slice(0, 64)) c += `    {"string", "${cEscape(s)}"},\n`;
  c += "};\n\n";
  c += "int recovered_entry(void) {\n";
  for (const line of report.pseudocode.slice(0, 80)) c += `    /* ${cEscape(line)} */\n`;
  c += "    return (int)(sizeof(recovered_strings) / sizeof(recovered_strings[0]));\n}\n";
  return [{ path: "recovered/recovered.c", language: "c", content: c }];
}

// ── NanoPython script runner ─────────────────────────────────────────────────

export function runNanopython(script: string, report: ReverseReport): string[] {
  const out: string[] = [];
  for (const raw of script.split("\n").slice(0, 256)) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    if (line === "summary()" || line === "print(summary())") {
      out.push(`${report.format} ${report.architecture} size=${report.size} sha256=${report.sha256}`);
    } else if (line === "sections()" || line === "print(sections())") {
      out.push(...report.sections.map(s => `${s.name} off=0x${s.file_offset.toString(16)} size=0x${s.size.toString(16)} flags=${s.flags}`));
    } else if (line === "imports()" || line === "print(imports())") {
      out.push(...report.imports.slice(0, 200));
    } else if (line === "algorithms()" || line === "print(algorithms())") {
      out.push(...report.algorithms);
    } else if (line === "iocs()" || line === "print(iocs())") {
      out.push(...report.algorithms.filter(l => l.startsWith("IOC candidate:")));
    } else if (line === "capabilities()" || line === "print(capabilities())") {
      out.push(...report.algorithms.filter(l => l.startsWith("capability:")));
    } else {
      const findMatch = line.match(/^(?:find_strings|grep)\((['"])(.*?)\1\)$/);
      if (findMatch) {
        const needle = findMatch[2].toLowerCase();
        out.push(...[...report.disassembly, ...report.pseudocode, ...report.strings]
          .filter(s => s.toLowerCase().includes(needle)).slice(0, 200));
      } else {
        const printMatch = line.match(/^print\((['"])(.*?)\1\)$/);
        if (printMatch) out.push(printMatch[2]);
        else throw new Error(`unsupported nanopython statement: ${line}`);
      }
    }
  }
  return out;
}
