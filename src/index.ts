#!/usr/bin/env bun
/**
 * pi-reverse — MCP server for static binary reverse engineering.
 *
 * Exposes one tool: `reverse_analyze`
 * Analyzes PE/ELF/Mach-O/raw/Java class/JAR/JAD files.
 * Returns sections, imports, strings, entropy, disassembly, pseudocode,
 * algorithm/IOC/capability detection, source reconstruction, and nanopython scripting.
 */

import { readFileSync } from "node:fs";
import { resolve, isAbsolute, relative, join, dirname } from "node:path";
import { argv, exit } from "node:process";

import type { ReverseReport, AnalyzeOptions } from "./types.js";
import { DEFAULT_OPTIONS } from "./types.js";
import { sha256, entropy, extractStrings, entropyWindows, pseudoDisassemble, generatePseudocode, extractAlgorithms, extractLabIndicators, reconstructSources, runNanopython } from "./utils.js";
import { parseElf, parsePe, parseJavaClass, parseJavaArchive, parseJad } from "./parsers.js";

// ── Core analyzer ────────────────────────────────────────────────────────────

export function analyzeBinary(workspaceRoot: string, relPath: string, opts: AnalyzeOptions = {}): ReverseReport {
  const mode = opts.mode ?? DEFAULT_OPTIONS.mode;
  const maxStrings = opts.max_strings ?? DEFAULT_OPTIONS.max_strings;
  const maxDisassembly = opts.max_disassembly ?? DEFAULT_OPTIONS.max_disassembly;
  const maxBytes = opts.max_bytes ?? DEFAULT_OPTIONS.max_bytes;
  const script = opts.script ?? null;
  const generateSource = opts.generate_source ?? DEFAULT_OPTIONS.generate_source;

  const absPath = isAbsolute(relPath) ? relPath : resolve(workspaceRoot, relPath);
  const bytes = readFileSync(absPath);
  const cap = maxBytes === 0 ? bytes.length : Math.min(maxBytes, bytes.length);
  const sample = bytes.subarray(0, cap);
  const lowerRel = relPath.toLowerCase();

  let report: ReverseReport;
  if (sample[0] === 0xca && sample[1] === 0xfe && sample[2] === 0xba && sample[3] === 0xbe) {
    report = parseJavaClass(sample);
  } else if (sample[0] === 0x50 && sample[1] === 0x4b && sample[2] === 0x03 && sample[3] === 0x04 &&
    (lowerRel.endsWith(".jar") || lowerRel.endsWith(".zip"))) {
    report = parseJavaArchive(sample, Math.max(maxDisassembly, 1));
  } else if (lowerRel.endsWith(".jad")) {
    report = parseJad(sample);
  } else if (sample[0] === 0x7f && sample[1] === 0x45 && sample[2] === 0x4c && sample[3] === 0x46) {
    report = parseElf(sample);
  } else if (sample[0] === 0x4d && sample[1] === 0x5a) {
    report = parsePe(sample);
  } else if ((sample[0] === 0xfe && sample[1] === 0xed && sample[2] === 0xfa) ||
    (sample[0] === 0xce && sample[1] === 0xfa && sample[2] === 0xed) ||
    (sample[0] === 0xca && sample[1] === 0xfe && sample[2] === 0xba && sample[3] === 0xbe)) {
    report = {
      path: relPath, size: bytes.length, sha256: sha256(bytes),
      format: "mach-o/fat-mach-o", architecture: "mach-o header detected",
      sections: [], imports: [], strings: [], entropy: [],
      disassembly: [], pseudocode: [], algorithms: [],
      reconstructed_sources: [], script_output: [],
      notes: ["Mach-O deep section parsing is not enabled in this build"],
    };
  } else {
    report = {
      path: relPath, size: bytes.length, sha256: sha256(bytes),
      format: "raw/unknown", architecture: "unknown",
      sections: [], imports: [], strings: [], entropy: [],
      disassembly: [], pseudocode: [], algorithms: [],
      reconstructed_sources: [], script_output: [], notes: [],
    };
  }

  report.path = relPath;
  report.size = bytes.length;
  report.sha256 = sha256(bytes);

  const wantsStrings = mode === "all" || mode === "strings" || mode === "overview" || mode === "";
  const wantsDisasm = mode === "all" || mode === "disasm" || mode === "disassembly";
  if (wantsStrings) report.strings = extractStrings(sample, Math.max(maxStrings, 1));
  report.entropy = entropyWindows(sample, 4096, 32);
  if (wantsDisasm) report.disassembly = pseudoDisassemble(sample, Math.max(maxDisassembly, 1));
  if (report.pseudocode.length === 0) report.pseudocode = generatePseudocode(report);
  report.algorithms = extractAlgorithms(report);
  report.algorithms.push(...extractLabIndicators(report));
  report.algorithms.sort();
  report.algorithms = [...new Set(report.algorithms)];
  if (generateSource || mode === "all" || mode === "source" || mode === "reconstruct")
    report.reconstructed_sources = reconstructSources(report);
  if (script && script.trim().length > 0) report.script_output = runNanopython(script, report);
  if (sample.length < bytes.length)
    report.notes.push(`analysis capped at ${sample.length} of ${bytes.length} bytes; set max_bytes=0 for full scan`);
  if (report.entropy.some(w => w.entropy > 7.4 && w.size >= 1024))
    report.notes.push("high-entropy regions detected; packed/encrypted/compressed data is likely");

  return report;
}

export function formatReport(report: ReverseReport): string {
  let out = "";
  out += `reverse_analyze ${report.path}\nformat=${report.format} arch=${report.architecture} size=${report.size} sha256=${report.sha256}\n`;
  if (report.sections.length > 0) {
    out += "\nsections:\n";
    for (const s of report.sections) {
      out += `- ${s.name} va=0x${s.virtual_address.toString(16)} off=0x${s.file_offset.toString(16)} size=0x${s.size.toString(16)} flags=${s.flags} entropy=${s.entropy.toFixed(2)}\n`;
    }
  }
  if (report.imports.length > 0) {
    out += "\nimports:\n";
    for (const item of report.imports.slice(0, 200)) out += `- ${item}\n`;
  }
  if (report.strings.length > 0) {
    out += "\nstrings:\n";
    for (const item of report.strings.slice(0, 200)) out += `- ${item}\n`;
  }
  if (report.entropy.length > 0) {
    out += "\nentropy windows:\n";
    for (const item of report.entropy.slice(0, 32)) {
      out += `- off=0x${item.offset.toString(16)} size=${item.size} entropy=${item.entropy.toFixed(2)}\n`;
    }
  }
  if (report.disassembly.length > 0) {
    out += "\ndisassembly:\n";
    for (const line of report.disassembly) out += line + "\n";
  }
  if (report.pseudocode.length > 0) {
    out += "\npseudocode:\n";
    for (const line of report.pseudocode.slice(0, 240)) out += line + "\n";
  }
  if (report.algorithms.length > 0) {
    out += "\nalgorithm and nuance extraction:\n";
    for (const line of report.algorithms.slice(0, 200)) out += `- ${line}\n`;
  }
  if (report.reconstructed_sources.length > 0) {
    out += "\nreconstructed sources:\n";
    for (const src of report.reconstructed_sources.slice(0, 8)) {
      out += `### ${src.path} (${src.language})\n\`\`\`${src.language}\n${src.content}\n\`\`\`\n`;
    }
  }
  if (report.script_output.length > 0) {
    out += "\nnanopython output:\n";
    for (const line of report.script_output) out += line + "\n";
  }
  if (report.notes.length > 0) {
    out += "\nnotes:\n";
    for (const note of report.notes) out += `- ${note}\n`;
  }
  return out;
}

// ── MCP server (stdio) ───────────────────────────────────────────────────────

const TOOL_DEFINITION = {
  name: "reverse_analyze",
  description: "Mini-IDA style defensive static reverse-engineering tool. Detects PE/ELF/Mach-O/raw plus Java .class, JAR and J2ME MIDlet/JAD. Returns sections/classes, imports/refs, strings, entropy, JVM/native assembly, pseudocode, algorithm/register/opcode indicators, malware-lab triage signals, IOC/capability candidates, optional source reconstruction, and optional NanoPython script output. Modes: overview, strings, disasm, all, source.",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string", description: "Path to the binary file to analyze (absolute or relative to cwd)" },
      mode: { type: "string", description: "Analysis mode: overview (default), strings, disasm, all, source, reconstruct", enum: ["overview", "strings", "disasm", "disassembly", "all", "source", "reconstruct"] },
      max_strings: { type: "number", description: "Maximum number of strings to extract (default 160)" },
      max_disassembly: { type: "number", description: "Maximum disassembly lines (default 256)" },
      max_bytes: { type: "number", description: "Maximum bytes to read from file (default 64MB, 0 for unlimited)" },
      script: { type: "string", description: "NanoPython script to run against the report. Supported: summary(), sections(), imports(), algorithms(), iocs(), capabilities(), find_strings('needle'), grep('needle'), print('text')" },
      generate_source: { type: "boolean", description: "Generate reconstructed source code (default false)" },
    },
    required: ["path"],
  },
};

function readMessage(): any | null {
  const input = readFileSync(0, "utf-8");
  if (input.trim().length === 0) return null;
  try { return JSON.parse(input); } catch { return null; }
}

function sendMessage(msg: any): void {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function handleRequest(msg: any): any {
  const { id, method, params } = msg;
  switch (method) {
    case "initialize":
      return {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "pi-reverse", version: "1.0.0" },
      };
    case "tools/list":
      return { tools: [TOOL_DEFINITION] };
    case "tools/call": {
      const toolName = params?.name;
      const args = params?.arguments ?? {};
      if (toolName !== "reverse_analyze") {
        return {
          content: [{ type: "text", text: `Unknown tool: ${toolName}` }],
          isError: true,
        };
      }
      try {
        const cwd = process.cwd();
        const report = analyzeBinary(cwd, args.path, {
          mode: args.mode,
          max_strings: args.max_strings,
          max_disassembly: args.max_disassembly,
          max_bytes: args.max_bytes,
          script: args.script,
          generate_source: args.generate_source,
        });
        const text = formatReport(report);
        return { content: [{ type: "text", text }] };
      } catch (err: any) {
        return {
          content: [{ type: "text", text: `reverse_analyze error: ${err.message}` }],
          isError: true,
        };
      }
    }
    default:
      throw new Error(`Unknown method: ${method}`);
  }
}

function main(): void {
  // Read line-delimited JSON-RPC over stdio
  const { createInterface } = require("node:readline");
  const rl = createInterface({ input: process.stdin, terminal: false });
  rl.on("line", (line: string) => {
    if (line.trim().length === 0) return;
    let msg: any;
    try { msg = JSON.parse(line); } catch { return; }
    try {
      const result = handleRequest(msg);
      if (result !== undefined && msg.id !== undefined) {
        sendMessage({ jsonrpc: "2.0", id: msg.id, result });
      }
    } catch (err: any) {
      if (msg.id !== undefined) {
        sendMessage({ jsonrpc: "2.0", id: msg.id, error: { code: -32603, message: err.message } });
      }
    }
  });
  rl.on("close", () => exit(0));
}

// ── CLI mode ─────────────────────────────────────────────────────────────────

function cliMain(): void {
  const args = argv.slice(2);
  if (args.length === 0) {
    console.error("Usage: pi-reverse <file> [--mode overview|strings|disasm|all|source] [--max-strings N] [--max-disasm N] [--max-bytes N] [--script '...'] [--generate-source]");
    exit(1);
  }
  const filePath = args[0];
  const opts: AnalyzeOptions = {};
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--mode") opts.mode = args[++i];
    else if (args[i] === "--max-strings") opts.max_strings = parseInt(args[++i], 10);
    else if (args[i] === "--max-disasm") opts.max_disassembly = parseInt(args[++i], 10);
    else if (args[i] === "--max-bytes") opts.max_bytes = parseInt(args[++i], 10);
    else if (args[i] === "--script") opts.script = (args[++i] ?? "").replace(/\\n/g, "\n");
    else if (args[i] === "--generate-source") opts.generate_source = true;
  }
  try {
    const report = analyzeBinary(process.cwd(), filePath, opts);
    console.log(formatReport(report));
  } catch (err: any) {
    console.error(`Error: ${err.message}`);
    exit(1);
  }
}

// ── Self-test ────────────────────────────────────────────────────────────────

export function selfTest(): void {
  // Test entropy
  const zeroEntropy = entropy(new Uint8Array(1024));
  if (zeroEntropy > 0.1) throw new Error(`entropy test failed: ${zeroEntropy} > 0.1`);

  // Test string extraction
  const strings = extractStrings(new Uint8Array([0, ...new TextEncoder().encode("hello-world"), 0]), 8);
  if (!strings.includes("hello-world")) throw new Error("string extraction test failed");

  // Test x86 pseudo-disasm
  const disasm = pseudoDisassemble(new Uint8Array([0x55, 0x48, 0x89, 0xe5, 0xc3]), 8);
  if (!disasm.some(l => l.includes("push rbp"))) throw new Error("disasm push rbp test failed");
  if (!disasm.some(l => l.includes("mov rbp,rsp"))) throw new Error("disasm mov test failed");
  if (!disasm.some(l => l.includes("ret"))) throw new Error("disasm ret test failed");

  // Test sha256
  const hash = sha256(new TextEncoder().encode("test"));
  if (hash !== "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    throw new Error(`sha256 test failed: ${hash}`);

  console.log("pi-reverse self-test passed");
}

if (import.meta.main) {
  const args = argv.slice(2);
  if (args[0] === "--self-test") { selfTest(); exit(0); }
  if (args[0] === "--cli") { argv.splice(2, 1); cliMain(); }
  else if (args.length > 0 && !args[0].startsWith("--") && process.stdin.isTTY) { cliMain(); }
  else { main(); }
}
