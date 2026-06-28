/**
 * Binary format parsers — direct port of reverse.rs parse_elf / parse_pe / parse_java.
 * Each returns a partial ReverseReport that the main analyze_binary merges.
 */

import type { ReverseReport, BinarySection, ReconstructedSource } from "./types.js";
import { sha256, entropy, extractStrings, entropyWindows } from "./utils.js";

// ── ELF ──────────────────────────────────────────────────────────────────────

function elfMachine(machine: number): string {
  switch (machine) {
    case 0x03: return "x86";
    case 0x3e: return "x86_64";
    case 0x28: return "arm";
    case 0xb7: return "aarch64";
    case 0xf3: return "riscv";
    case 0x08: return "mips";
    default: return "unknown";
  }
}

function elfSectionFlags(flags: bigint): string {
  let out = "";
  if (flags & 0x1n) out += "W";
  if (flags & 0x2n) out += "A";
  if (flags & 0x4n) out += "X";
  return out || "-";
}

function readU16(bytes: Uint8Array, off: number, little: boolean): number {
  if (off + 2 > bytes.length) return 0;
  const dv = new DataView(bytes.buffer, bytes.byteOffset + off, 2);
  return little ? dv.getUint16(0, true) : dv.getUint16(0, false);
}

function readU32(bytes: Uint8Array, off: number, little: boolean): number {
  if (off + 4 > bytes.length) return 0;
  const dv = new DataView(bytes.buffer, bytes.byteOffset + off, 4);
  return little ? dv.getUint32(0, true) : dv.getUint32(0, false);
}

function readU64(bytes: Uint8Array, off: number, little: boolean): bigint {
  if (off + 8 > bytes.length) return 0n;
  const dv = new DataView(bytes.buffer, bytes.byteOffset + off, 8);
  return little ? dv.getBigUint64(0, true) : dv.getBigUint64(0, false);
}

function readBeU16(bytes: Uint8Array, off: number): number {
  if (off + 2 > bytes.length) return 0;
  const dv = new DataView(bytes.buffer, bytes.byteOffset + off, 2);
  return dv.getUint16(0, false);
}

function readBeU32(bytes: Uint8Array, off: number): number {
  if (off + 4 > bytes.length) return 0;
  const dv = new DataView(bytes.buffer, bytes.byteOffset + off, 4);
  return dv.getUint32(0, false);
}

function sliceAt(bytes: Uint8Array, off: number, len: number): Uint8Array | null {
  const end = off + len;
  if (off < 0 || end > bytes.length) return null;
  return bytes.subarray(off, end);
}

function cstrAt(bytes: Uint8Array, off: number): string | null {
  if (off >= bytes.length) return null;
  let end = off;
  while (end < bytes.length && bytes[end] !== 0) end++;
  if (end === off) return null;
  try { return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(off, end)); }
  catch { return null; }
}

function sectionName(bytes: Uint8Array): string {
  let end = 0;
  while (end < bytes.length && bytes[end] !== 0) end++;
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, end));
}

interface ElfSectionTable {
  little: boolean;
  shoff: number;
  shentsize: number;
  shnum: number;
  shstrndx: number;
  is64: boolean;
}

function sectionBytes(bytes: Uint8Array, tbl: ElfSectionTable, idx: number): Uint8Array | null {
  const off = tbl.shoff + idx * tbl.shentsize;
  if (off + tbl.shentsize > bytes.length) return null;
  const fileOff = tbl.is64 ? Number(readU64(bytes, off + 24, tbl.little)) : readU32(bytes, off + 16, tbl.little);
  const size = tbl.is64 ? Number(readU64(bytes, off + 32, tbl.little)) : readU32(bytes, off + 20, tbl.little);
  return sliceAt(bytes, fileOff, size);
}

function parseElfSections(bytes: Uint8Array, tbl: ElfSectionTable, report: ReverseReport): void {
  if (tbl.shoff === 0 || tbl.shentsize === 0 || tbl.shnum > 4096) return;
  const shstr = sectionBytes(bytes, tbl, tbl.shstrndx) ?? new Uint8Array(0);
  const max = Math.min(tbl.shnum, 512);
  for (let idx = 0; idx < max; idx++) {
    const off = tbl.shoff + idx * tbl.shentsize;
    if (off + tbl.shentsize > bytes.length) break;
    const nameOff = readU32(bytes, off, tbl.little);
    const flags = tbl.is64 ? readU64(bytes, off + 8, tbl.little) : BigInt(readU32(bytes, off + 8, tbl.little));
    const addr = tbl.is64 ? readU64(bytes, off + 16, tbl.little) : BigInt(readU32(bytes, off + 12, tbl.little));
    const fileOff = tbl.is64 ? readU64(bytes, off + 24, tbl.little) : BigInt(readU32(bytes, off + 16, tbl.little));
    const size = tbl.is64 ? readU64(bytes, off + 32, tbl.little) : BigInt(readU32(bytes, off + 20, tbl.little));
    if (size === 0n) continue;
    const name = cstrAt(shstr, nameOff) ?? `section_${idx}`;
    const data = sliceAt(bytes, Number(fileOff), Number(size)) ?? new Uint8Array(0);
    report.sections.push({
      name,
      virtual_address: Number(addr),
      file_offset: Number(fileOff),
      size: Number(size),
      flags: elfSectionFlags(flags),
      entropy: entropy(data),
    });
  }
}

export function parseElf(bytes: Uint8Array): ReverseReport {
  const cls = bytes[4] ?? 0;
  const endian = bytes[5] ?? 1;
  const little = endian === 1;
  const machine = readU16(bytes, 18, little);
  const report: ReverseReport = {
    path: "", size: bytes.length, sha256: sha256(bytes),
    format: cls === 2 ? "ELF64" : "ELF32",
    architecture: elfMachine(machine),
    sections: [], imports: [], strings: [], entropy: [],
    disassembly: [], pseudocode: [], algorithms: [],
    reconstructed_sources: [], script_output: [], notes: [],
  };
  if (cls === 2) {
    const shoff = Number(readU64(bytes, 40, little));
    const shentsize = readU16(bytes, 58, little);
    const shnum = readU16(bytes, 60, little);
    const shstrndx = readU16(bytes, 62, little);
    parseElfSections(bytes, { little, shoff, shentsize, shnum, shstrndx, is64: true }, report);
  } else {
    const shoff = readU32(bytes, 32, little);
    const shentsize = readU16(bytes, 46, little);
    const shnum = readU16(bytes, 48, little);
    const shstrndx = readU16(bytes, 50, little);
    parseElfSections(bytes, { little, shoff, shentsize, shnum, shstrndx, is64: false }, report);
  }
  report.imports = extractStrings(bytes, 10_000)
    .filter(s => s.endsWith(".so") || s.includes(".so."))
    .slice(0, 128);
  return report;
}

// ── PE ───────────────────────────────────────────────────────────────────────

function peMachine(machine: number): string {
  switch (machine) {
    case 0x014c: return "x86";
    case 0x8664: return "x86_64";
    case 0x01c0: return "arm";
    case 0xaa64: return "aarch64";
    default: return "unknown";
  }
}

function peSectionFlags(flags: number): string {
  let out = "";
  if (flags & 0x2000_0000) out += "X";
  if (flags & 0x4000_0000) out += "R";
  if (flags & 0x8000_0000) out += "W";
  return out || "-";
}

function rvaToOffset(rva: number, sections: [number, number, number, number][]): number | null {
  for (const [va, vsize, rawPtr, rawSize] of sections) {
    const span = Math.max(vsize, rawSize);
    if (rva >= va && rva < va + span) return rawPtr + (rva - va);
  }
  return null;
}

function parsePeImports(bytes: Uint8Array, importRva: number, sections: [number, number, number, number][]): string[] {
  const imports: string[] = [];
  let descOff = rvaToOffset(importRva, sections);
  if (descOff === null) return imports;
  for (let i = 0; i < 256; i++) {
    if (descOff + 20 > bytes.length) break;
    const originalFirstThunk = readU32(bytes, descOff, true);
    const nameRva = readU32(bytes, descOff + 12, true);
    const firstThunk = readU32(bytes, descOff + 16, true);
    if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;
    const nameOff = rvaToOffset(nameRva, sections);
    if (nameOff !== null) {
      const dll = cstrAt(bytes, nameOff);
      if (dll) {
        imports.push(`dll:${dll}`);
        const thunkRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
        let thunkOff = rvaToOffset(thunkRva, sections);
        if (thunkOff !== null) {
          for (let j = 0; j < 128; j++) {
            const value = readU32(bytes, thunkOff, true);
            if (value === 0) break;
            if ((value & 0x8000_0000) === 0) {
              const importNameOff = rvaToOffset(value, sections);
              if (importNameOff !== null) {
                const func = cstrAt(bytes, importNameOff + 2);
                if (func) imports.push(`${dll}!${func}`);
              }
            }
            thunkOff += 4;
          }
        }
      }
    }
    descOff += 20;
  }
  return imports;
}

export function parsePe(bytes: Uint8Array): ReverseReport {
  const peOff = readU32(bytes, 0x3c, true);
  const peSig = sliceAt(bytes, peOff, 4);
  if (!peSig || peSig[0] !== 0x50 || peSig[1] !== 0x45 || peSig[2] !== 0 || peSig[3] !== 0)
    throw new Error("MZ file has no PE signature");
  const machine = readU16(bytes, peOff + 4, true);
  const sections = readU16(bytes, peOff + 6, true);
  const optSize = readU16(bytes, peOff + 20, true);
  const optOff = peOff + 24;
  const magic = readU16(bytes, optOff, true);
  const isPe32Plus = magic === 0x20b;
  const imageBase = isPe32Plus
    ? Number(readU64(bytes, optOff + 24, true))
    : readU32(bytes, optOff + 28, true);
  const dataDirOff = optOff + (isPe32Plus ? 112 : 96);
  const importRva = readU32(bytes, dataDirOff + 8, true);
  const sectionOff = optOff + optSize;
  const report: ReverseReport = {
    path: "", size: bytes.length, sha256: sha256(bytes),
    format: isPe32Plus ? "PE32+" : "PE32",
    architecture: `${peMachine(machine)} image_base=0x${imageBase.toString(16)}`,
    sections: [], imports: [], strings: [], entropy: [],
    disassembly: [], pseudocode: [], algorithms: [],
    reconstructed_sources: [], script_output: [], notes: [],
  };
  const sectionMap: [number, number, number, number][] = [];
  const max = Math.min(sections, 96);
  for (let idx = 0; idx < max; idx++) {
    const off = sectionOff + idx * 40;
    if (off + 40 > bytes.length) break;
    const name = sectionName(bytes.subarray(off, off + 8));
    const virtualSize = readU32(bytes, off + 8, true);
    const virtualAddress = readU32(bytes, off + 12, true);
    const rawSize = readU32(bytes, off + 16, true);
    const rawPtr = readU32(bytes, off + 20, true);
    const chars = readU32(bytes, off + 36, true);
    sectionMap.push([virtualAddress, Math.max(virtualSize, rawSize), rawPtr, rawSize]);
    const data = sliceAt(bytes, rawPtr, rawSize) ?? new Uint8Array(0);
    report.sections.push({
      name, virtual_address: virtualAddress, file_offset: rawPtr,
      size: rawSize, flags: peSectionFlags(chars), entropy: entropy(data),
    });
  }
  if (importRva !== 0) report.imports = parsePeImports(bytes, importRva, sectionMap);
  return report;
}

// ── Java class / JAR / JAD ───────────────────────────────────────────────────

interface CpEntry {
  tag: "utf8" | "class" | "string" | "name_and_type" | "ref" | "integer" | "float" | "long" | "double" | "other";
  value?: string;
  ref1?: number;
  ref2?: number;
}

interface JavaMethodInfo {
  name: string;
  descriptor: string;
  code: Uint8Array;
  disassembly: string[];
  pseudocode: string[];
}

interface JavaClassInfo {
  name: string;
  superName: string;
  methods: JavaMethodInfo[];
  fields: string[];
  constants: string[];
  refs: string[];
  version: string;
}

function cpUtf8(cp: CpEntry[], idx: number): string {
  return cp[idx]?.tag === "utf8" ? cp[idx].value! : "";
}

function cpClass(cp: CpEntry[], idx: number): string {
  const e = cp[idx];
  return e?.tag === "class" ? cpUtf8(cp, e.ref1!) : "";
}

function resolveRef(cp: CpEntry[], cls: number, nat: number): string {
  const className = cpClass(cp, cls).replace(/\//g, ".");
  const natEntry = cp[nat];
  if (natEntry?.tag === "name_and_type")
    return `${className}.${cpUtf8(cp, natEntry.ref1!)}${cpUtf8(cp, natEntry.ref2!)}`;
  return className;
}

function cpValue(cp: CpEntry[], idx: number): string {
  const e = cp[idx];
  if (!e) return "";
  switch (e.tag) {
    case "utf8": return e.value!;
    case "string": return JSON.stringify(cpUtf8(cp, e.ref1!));
    case "class": return cpUtf8(cp, e.ref1!).replace(/\//g, ".");
    case "integer": return e.value!;
    case "name_and_type": return `${cpUtf8(cp, e.ref1!)}:${cpUtf8(cp, e.ref2!)}`;
    case "ref": return resolveRef(cp, e.ref1!, e.ref2!);
    default: return "";
  }
}

function cpRef(cp: CpEntry[], idx: number): string {
  const e = cp[idx];
  return e?.tag === "ref" ? resolveRef(cp, e.ref1!, e.ref2!) : cpValue(cp, idx);
}

function branchTarget(pc: number, hi: number, lo: number): number {
  const rel = (hi << 8) | lo;
  const signed = rel > 0x7fff ? rel - 0x10000 : rel;
  return Math.max(0, pc + signed);
}

function jvmLoadName(op: number): string {
  return ["", "iload", "lload", "fload", "dload", "aload"][op - 0x15] ?? "load";
}

function jvmStoreName(op: number): string {
  return ["", "istore", "lstore", "fstore", "dstore", "astore"][op - 0x36] ?? "store";
}

function jvmImplicitLoadStore(op: number): string {
  const map: Record<number, string> = {
    0x1a: "iload_0", 0x1b: "iload_1", 0x1c: "iload_2", 0x1d: "iload_3",
    0x2a: "aload_0", 0x2b: "aload_1", 0x2c: "aload_2", 0x2d: "aload_3",
    0x3b: "istore_0", 0x3c: "istore_1", 0x3d: "istore_2", 0x3e: "istore_3",
    0x4b: "astore_0", 0x4c: "astore_1", 0x4d: "astore_2", 0x4e: "astore_3",
    0x2e: "iaload", 0x32: "aaload", 0x4f: "iastore", 0x53: "aastore",
  };
  return map[op] ?? "stack_op";
}

function jvmBranchName(op: number): string {
  const map: Record<number, string> = {
    0x99: "ifeq", 0x9a: "ifne", 0x9b: "iflt", 0x9c: "ifge", 0x9d: "ifgt", 0x9e: "ifle",
    0x9f: "if_icmpeq", 0xa0: "if_icmpne", 0xa1: "if_icmplt", 0xa2: "if_icmpge",
    0xa3: "if_icmpgt", 0xa4: "if_icmple", 0xa5: "if_acmpeq", 0xa6: "if_acmpne",
  };
  return map[op] ?? "if";
}

function jvmRefName(op: number): string {
  const map: Record<number, string> = {
    0xb2: "getstatic", 0xb3: "putstatic", 0xb4: "getfield", 0xb5: "putfield",
    0xb6: "invokevirtual", 0xb7: "invokespecial", 0xb8: "invokestatic",
  };
  return map[op] ?? "ref";
}

function jvmTypeName(op: number): string {
  const map: Record<number, string> = { 0xbb: "new", 0xbd: "anewarray", 0xc0: "checkcast", 0xc1: "instanceof" };
  return map[op] ?? "type";
}

function disassembleJvm(code: Uint8Array, cp: CpEntry[], maxLines: number): string[] {
  const out: string[] = [];
  let pc = 0;
  while (pc < code.length && out.length < maxLines) {
    const op = code[pc];
    const start = pc;
    let mnemonic = "";
    let size = 1;
    if (op === 0x00) { mnemonic = "nop"; size = 1; }
    else if (op === 0x01) { mnemonic = "aconst_null"; size = 1; }
    else if (op >= 0x02 && op <= 0x08) { mnemonic = `iconst_${op - 3}`; size = 1; }
    else if (op === 0x09) { mnemonic = "lconst_0"; size = 1; }
    else if (op === 0x0a) { mnemonic = "lconst_1"; size = 1; }
    else if (op === 0x10 && pc + 1 < code.length) { mnemonic = `bipush ${code[pc + 1] | 0}`; size = 2; }
    else if (op === 0x11 && pc + 2 < code.length) { const v = (code[pc + 1] << 8) | code[pc + 2]; mnemonic = `sipush ${v > 0x7fff ? v - 0x10000 : v}`; size = 3; }
    else if (op === 0x12 && pc + 1 < code.length) { mnemonic = `ldc #${code[pc + 1]} ${cpValue(cp, code[pc + 1])}`; size = 2; }
    else if ((op === 0x13 || op === 0x14) && pc + 2 < code.length) { const idx = (code[pc + 1] << 8) | code[pc + 2]; mnemonic = `ldc_w #${idx} ${cpValue(cp, idx)}`; size = 3; }
    else if (op >= 0x15 && op <= 0x19 && pc + 1 < code.length) { mnemonic = `${jvmLoadName(op)} ${code[pc + 1]}`; size = 2; }
    else if (op >= 0x1a && op <= 0x35) { mnemonic = jvmImplicitLoadStore(op); size = 1; }
    else if (op >= 0x36 && op <= 0x3a && pc + 1 < code.length) { mnemonic = `${jvmStoreName(op)} ${code[pc + 1]}`; size = 2; }
    else if (op >= 0x3b && op <= 0x56) { mnemonic = jvmImplicitLoadStore(op); size = 1; }
    else if (op === 0x57) { mnemonic = "pop"; size = 1; }
    else if (op === 0x59) { mnemonic = "dup"; size = 1; }
    else if (op === 0x60) { mnemonic = "iadd"; size = 1; }
    else if (op === 0x64) { mnemonic = "isub"; size = 1; }
    else if (op === 0x68) { mnemonic = "imul"; size = 1; }
    else if (op === 0x6c) { mnemonic = "idiv"; size = 1; }
    else if (op === 0x70) { mnemonic = "irem"; size = 1; }
    else if (op === 0x74) { mnemonic = "ineg"; size = 1; }
    else if (op === 0x78) { mnemonic = "ishl"; size = 1; }
    else if (op === 0x7a) { mnemonic = "ishr"; size = 1; }
    else if (op === 0x7c) { mnemonic = "iushr"; size = 1; }
    else if (op === 0x7e) { mnemonic = "iand"; size = 1; }
    else if (op === 0x80) { mnemonic = "ior"; size = 1; }
    else if (op === 0x82) { mnemonic = "ixor"; size = 1; }
    else if (op === 0x84 && pc + 2 < code.length) { mnemonic = `iinc local_${code[pc + 1]} ${code[pc + 2] | 0}`; size = 3; }
    else if (op >= 0x99 && op <= 0xa6 && pc + 2 < code.length) { mnemonic = `${jvmBranchName(op)} 0x${branchTarget(pc, code[pc + 1], code[pc + 2]).toString(16).padStart(4, "0")}`; size = 3; }
    else if (op === 0xa7 && pc + 2 < code.length) { mnemonic = `goto 0x${branchTarget(pc, code[pc + 1], code[pc + 2]).toString(16).padStart(4, "0")}`; size = 3; }
    else if (op === 0xac) { mnemonic = "ireturn"; size = 1; }
    else if (op === 0xad) { mnemonic = "lreturn"; size = 1; }
    else if (op === 0xae) { mnemonic = "freturn"; size = 1; }
    else if (op === 0xaf) { mnemonic = "dreturn"; size = 1; }
    else if (op === 0xb0) { mnemonic = "areturn"; size = 1; }
    else if (op === 0xb1) { mnemonic = "return"; size = 1; }
    else if (op >= 0xb2 && op <= 0xb8 && pc + 2 < code.length) { const idx = (code[pc + 1] << 8) | code[pc + 2]; mnemonic = `${jvmRefName(op)} #${idx} ${cpRef(cp, idx)}`; size = 3; }
    else if (op === 0xb9 && pc + 4 < code.length) { const idx = (code[pc + 1] << 8) | code[pc + 2]; mnemonic = `invokeinterface #${idx} ${cpRef(cp, idx)} count=${code[pc + 3]}`; size = 5; }
    else if ((op === 0xbb || op === 0xbd || op === 0xc0 || op === 0xc1) && pc + 2 < code.length) { const idx = (code[pc + 1] << 8) | code[pc + 2]; mnemonic = `${jvmTypeName(op)} #${idx} ${cpValue(cp, idx)}`; size = 3; }
    else if (op === 0xbc && pc + 1 < code.length) { mnemonic = `newarray ${code[pc + 1]}`; size = 2; }
    else if (op === 0xbe) { mnemonic = "arraylength"; size = 1; }
    else if (op === 0xbf) { mnemonic = "athrow"; size = 1; }
    else if ((op === 0xc6 || op === 0xc7) && pc + 2 < code.length) { mnemonic = `${op === 0xc6 ? "ifnull" : "ifnonnull"} 0x${branchTarget(pc, code[pc + 1], code[pc + 2]).toString(16).padStart(4, "0")}`; size = 3; }
    else { mnemonic = `op_${op.toString(16).padStart(2, "0")}`; size = 1; }

    const rawEnd = Math.min(start + size, code.length);
    const raw = Array.from(code.subarray(start, rawEnd)).map(b => b.toString(16).padStart(2, "0")).join(" ");
    out.push(`0x${start.toString(16).padStart(4, "0")}: ${raw.padEnd(12)} ${mnemonic}`);
    pc += Math.max(size, 1);
  }
  return out;
}

function jvmPseudocode(disassembly: string[]): string[] {
  const out: string[] = [];
  let temp = 0;
  for (const line of disassembly) {
    const instr = line.split(" ").slice(2).join(" ").trim();
    if (instr.includes("invoke")) out.push(`call ${instr.replace(/"/g, "'")}; `);
    else if (instr.includes("getfield") || instr.includes("getstatic")) out.push(`load ${instr.replace(/"/g, "'")}; `);
    else if (instr.includes("putfield") || instr.includes("putstatic")) out.push(`store ${instr.replace(/"/g, "'")}; `);
    else if (instr.startsWith("if")) out.push(`if condition { goto ${instr}; }`);
    else if (instr.startsWith("goto")) out.push(`goto ${instr.replace("goto ", "")};`);
    else if (instr.includes("return")) out.push("return stack_top;");
    else if (/(iadd|isub|imul|ixor|iand|ior)/.test(instr)) { temp++; out.push(`tmp${temp} = stack arithmetic ${JSON.stringify(instr)};`); }
    else if (/^(ldc|bipush|sipush|iconst)/.test(instr)) out.push(`push ${instr}; `);
  }
  if (out.length === 0) out.push("method has no decoded high-level operations");
  return out;
}

function javaType(desc: string): [string, number] {
  if (desc.length === 0) return ["void", 0];
  const c = desc[0];
  switch (c) {
    case "V": return ["void", 1];
    case "Z": return ["boolean", 1];
    case "B": return ["byte", 1];
    case "C": return ["char", 1];
    case "S": return ["short", 1];
    case "I": return ["int", 1];
    case "J": return ["long", 1];
    case "F": return ["float", 1];
    case "D": return ["double", 1];
    case "[": { const [inner, used] = javaType(desc.slice(1)); return [`${inner}[]`, used + 1]; }
    case "L": { const end = desc.indexOf(";"); return end >= 0 ? [desc.slice(1, end).replace(/\//g, "."), end + 1] : ["Object", desc.length]; }
    default: return ["Object", 1];
  }
}

function javaReturnType(desc: string): string {
  const idx = desc.lastIndexOf(")");
  return idx >= 0 ? javaType(desc.slice(idx + 1))[0] : "Object";
}

function javaArgs(desc: string): string {
  const start = desc.indexOf("(");
  const end = desc.indexOf(")");
  if (start < 0 || end < 0) return "()";
  const args = desc.slice(start + 1, end);
  const out: string[] = [];
  let input = args;
  let idx = 0;
  while (input.length > 0) {
    const [ty, used] = javaType(input);
    if (used === 0) break;
    out.push(`${ty} arg${idx}`);
    input = input.slice(used);
    idx++;
  }
  return `(${out.join(", ")})`;
}

function defaultJavaReturn(ty: string): string {
  switch (ty) {
    case "boolean": return "false";
    case "byte": case "char": case "short": case "int": case "long": return "0";
    case "float": return "0.0f";
    case "double": return "0.0d";
    default: return "null";
  }
}

function reconstructJavaSource(info: JavaClassInfo): ReconstructedSource {
  const className = info.name.split(".").pop() ?? info.name;
  const pkg = info.name.includes(".") ? info.name.slice(0, info.name.lastIndexOf(".")) : null;
  let content = "";
  if (pkg) content += `package ${pkg};\n\n`;
  const superName = info.superName.split(".").pop()?.replace(/\//g, ".") || "Object";
  content += `public class ${className} extends ${superName} {\n`;
  for (const field of info.fields) content += `    public ${field.replace(/\//g, ".")};\n`;
  for (const method of info.methods) {
    const name = method.name === "<init>" ? className : method.name;
    const retType = method.name === "<init>" ? "" : `${javaReturnType(method.descriptor)} `;
    content += `    public ${retType}${name}${javaArgs(method.descriptor)} {\n`;
    for (const line of method.pseudocode.slice(0, 16)) content += `        // ${line.replace(/\*\//g, "* /")}\n`;
    if (method.name !== "<init>" && javaReturnType(method.descriptor) !== "void")
      content += `        return ${defaultJavaReturn(javaReturnType(method.descriptor))};\n`;
    content += "    }\n";
  }
  content += "}\n";
  return { path: `${info.name.replace(/\./g, "/")}.java`, language: "java", content };
}

function parseJavaClassInfo(bytes: Uint8Array, maxDisassembly: number): JavaClassInfo {
  if (!(bytes[0] === 0xca && bytes[1] === 0xfe && bytes[2] === 0xba && bytes[3] === 0xbe))
    throw new Error("not a Java class");
  const minor = readBeU16(bytes, 4);
  const major = readBeU16(bytes, 6);
  const cpCount = readBeU16(bytes, 8);
  const cp: CpEntry[] = new Array(Math.max(cpCount, 1)).fill(null).map(() => ({ tag: "other" }));
  let off = 10;
  let idx = 1;
  while (idx < cpCount && off < bytes.length) {
    const tag = bytes[off]; off++;
    if (tag === 1) {
      const len = readBeU16(bytes, off); off += 2;
      const value = new TextDecoder("utf-8", { fatal: false }).decode(sliceAt(bytes, off, len) ?? new Uint8Array(0));
      cp[idx] = { tag: "utf8", value };
      off += len;
    } else if (tag === 3) { cp[idx] = { tag: "integer", value: String(readBeU32(bytes, off) | 0) }; off += 4; }
    else if (tag === 4) { cp[idx] = { tag: "float" }; off += 4; }
    else if (tag === 5) { cp[idx] = { tag: "long" }; off += 8; idx++; }
    else if (tag === 6) { cp[idx] = { tag: "double" }; off += 8; idx++; }
    else if (tag === 7) { cp[idx] = { tag: "class", ref1: readBeU16(bytes, off) }; off += 2; }
    else if (tag === 8) { cp[idx] = { tag: "string", ref1: readBeU16(bytes, off) }; off += 2; }
    else if (tag >= 9 && tag <= 11) { cp[idx] = { tag: "ref", ref1: readBeU16(bytes, off), ref2: readBeU16(bytes, off + 2) }; off += 4; }
    else if (tag === 12) { cp[idx] = { tag: "name_and_type", ref1: readBeU16(bytes, off), ref2: readBeU16(bytes, off + 2) }; off += 4; }
    else if (tag === 15) off += 3;
    else if (tag === 16) off += 2;
    else if (tag === 18) off += 4;
    else if (tag === 19 || tag === 20) off += 2;
    else throw new Error(`unsupported class constant pool tag ${tag}`);
    idx++;
  }
  off += 2; // access flags
  const thisClass = readBeU16(bytes, off);
  const superClass = readBeU16(bytes, off + 2);
  off += 4;
  const interfaceCount = readBeU16(bytes, off);
  off += 2 + interfaceCount * 2;
  const fieldsCount = readBeU16(bytes, off);
  off += 2;
  const fields: string[] = [];
  for (let i = 0; i < fieldsCount; i++) {
    const nameIdx = readBeU16(bytes, off + 2);
    const descIdx = readBeU16(bytes, off + 4);
    const attrCount = readBeU16(bytes, off + 6);
    fields.push(`${cpUtf8(cp, descIdx)} ${cpUtf8(cp, nameIdx)}`);
    off += 8;
    for (let j = 0; j < attrCount; j++) { const len = readBeU32(bytes, off + 2); off += 6 + len; }
  }
  const methodsCount = readBeU16(bytes, off);
  off += 2;
  const methods: JavaMethodInfo[] = [];
  for (let i = 0; i < methodsCount; i++) {
    const nameIdx = readBeU16(bytes, off + 2);
    const descIdx = readBeU16(bytes, off + 4);
    const attrCount = readBeU16(bytes, off + 6);
    const name = cpUtf8(cp, nameIdx);
    const descriptor = cpUtf8(cp, descIdx);
    off += 8;
    let code = new Uint8Array(0);
    for (let j = 0; j < attrCount; j++) {
      const attrNameIdx = readBeU16(bytes, off);
      const len = readBeU32(bytes, off + 2);
      const attrName = cpUtf8(cp, attrNameIdx);
      const attrBody = off + 6;
      if (attrName === "Code" && attrBody + 8 <= bytes.length) {
        const codeLen = readBeU32(bytes, attrBody + 4);
        code = sliceAt(bytes, attrBody + 8, codeLen) ?? new Uint8Array(0);
      }
      off += 6 + len;
    }
    const disassembly = disassembleJvm(code, cp, maxDisassembly);
    const pseudocode = jvmPseudocode(disassembly);
    methods.push({ name, descriptor, code, disassembly, pseudocode });
  }
  const constants = cp
    .filter(e => e?.tag === "utf8" && (e.value?.length ?? 0) >= 3)
    .map(e => e!.value!)
    .concat(cp.filter(e => e?.tag === "string").map(e => cpUtf8(cp, e!.ref1!)).filter(s => s.length >= 3))
    .concat(cp.filter(e => e?.tag === "integer").map(e => e!.value!));
  const refs = cp
    .filter(e => e?.tag === "ref")
    .map(e => resolveRef(cp, e!.ref1!, e!.ref2!))
    .filter(s => s.length > 0)
    .concat(cp.filter(e => e?.tag === "class").map(e => cpUtf8(cp, e!.ref1!).replace(/\//g, ".")))
    .filter(s => s.length > 0);
  return {
    name: cpClass(cp, thisClass).replace(/\//g, "."),
    superName: cpClass(cp, superClass).replace(/\//g, "."),
    methods, fields, constants, refs,
    version: `major=${major} minor=${minor}`,
  };
}

export function parseJavaClass(bytes: Uint8Array): ReverseReport {
  const info = parseJavaClassInfo(bytes, 2048);
  const report: ReverseReport = {
    path: "", size: bytes.length, sha256: sha256(bytes),
    format: "Java class",
    architecture: `JVM ${info.version}`,
    sections: [{ name: info.name, virtual_address: 0, file_offset: 0, size: bytes.length, flags: "class", entropy: entropy(bytes) }],
    imports: [`class:${info.name} extends ${info.superName}`, ...info.refs.map(r => `ref:${r}`)],
    strings: info.constants, entropy: [],
    disassembly: [], pseudocode: [], algorithms: [],
    reconstructed_sources: [reconstructJavaSource(info)],
    script_output: [], notes: [],
  };
  for (const method of info.methods) {
    report.disassembly.push(`\n.method ${method.name}${method.descriptor}`);
    report.disassembly.push(...method.disassembly);
    report.pseudocode.push(`${javaReturnType(method.descriptor)} ${method.name}${javaArgs(method.descriptor)} {`);
    report.pseudocode.push(...method.pseudocode.map(l => `  ${l}`));
    report.pseudocode.push("}");
  }
  return report;
}

export function parseJad(bytes: Uint8Array): ReverseReport {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const report: ReverseReport = {
    path: "", size: bytes.length, sha256: sha256(bytes),
    format: "J2ME JAD descriptor",
    architecture: "JVM CLDC/MIDP",
    sections: [], imports: [], strings: text.split("\n").map(l => l.trim()).filter(l => l.length > 0),
    entropy: [], disassembly: [], pseudocode: [], algorithms: [],
    reconstructed_sources: [], script_output: [], notes: [],
  };
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (/^(MIDlet-|MicroEdition-|Nokia-|Siemens-)/.test(t)) report.imports.push(`jad:${t}`);
  }
  return report;
}

// ── ZIP / JAR ────────────────────────────────────────────────────────────────

interface ZipEntry { name: string; compressionMethod: number; compressedSize: number; uncompressedSize: number; localHeaderOffset: number; }

function parseZipCentralDirectory(bytes: Uint8Array): ZipEntry[] {
  // Find End of Central Directory Record (EOCD)
  let eocdOff = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
      eocdOff = i; break;
    }
  }
  if (eocdOff < 0) return [];
  const dv = new DataView(bytes.buffer, bytes.byteOffset + eocdOff);
  const cdCount = dv.getUint16(10, true);
  const cdOff = dv.getUint32(16, true);
  const entries: ZipEntry[] = [];
  let off = cdOff;
  for (let i = 0; i < cdCount && off + 46 <= bytes.length; i++) {
    if (bytes[off] !== 0x50 || bytes[off + 1] !== 0x4b || bytes[off + 2] !== 0x01 || bytes[off + 3] !== 0x02) break;
    const cdv = new DataView(bytes.buffer, bytes.byteOffset + off);
    const compressionMethod = cdv.getUint16(10, true);
    const compressedSize = cdv.getUint32(20, true);
    const uncompressedSize = cdv.getUint32(24, true);
    const nameLen = cdv.getUint16(28, true);
    const extraLen = cdv.getUint16(30, true);
    const commentLen = cdv.getUint16(32, true);
    const localHeaderOffset = cdv.getUint32(42, true);
    const name = new TextDecoder("utf-8").decode(bytes.subarray(off + 46, off + 46 + nameLen));
    entries.push({ name, compressionMethod, compressedSize, uncompressedSize, localHeaderOffset });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function readZipEntryData(bytes: Uint8Array, entry: ZipEntry): Uint8Array {
  const lhOff = entry.localHeaderOffset;
  if (lhOff + 30 > bytes.length) return new Uint8Array(0);
  const lhDv = new DataView(bytes.buffer, bytes.byteOffset + lhOff);
  const nameLen = lhDv.getUint16(26, true);
  const extraLen = lhDv.getUint16(28, true);
  const dataOff = lhOff + 30 + nameLen + extraLen;
  if (entry.compressionMethod === 0) {
    return bytes.subarray(dataOff, dataOff + entry.uncompressedSize);
  }
  if (entry.compressionMethod === 8) {
    // DEFLATE — use Node/Bun built-in
    const compressed = bytes.subarray(dataOff, dataOff + entry.compressedSize);
    // Bun and Node both expose DecompressionStream
    try {
      // Use Bun.inflateSync if available (Bun runtime)
      if (typeof Bun !== "undefined" && Bun.inflateSync) {
        return Bun.inflateSync(compressed);
      }
    } catch {}
    // Fallback: use fflate (loaded dynamically) or pako
    // For now, return empty if no inflate available
    return new Uint8Array(0);
  }
  return new Uint8Array(0);
}

function isJ2meManifest(manifest: string): boolean {
  const lower = manifest.toLowerCase();
  return lower.includes("midlet-") || lower.includes("microedition-profile") ||
    lower.includes("microedition-configuration") || lower.includes("cldc") || lower.includes("midp");
}

export function parseJavaArchive(bytes: Uint8Array, maxDisassembly: number): ReverseReport {
  const entries = parseZipCentralDirectory(bytes);
  const report: ReverseReport = {
    path: "", size: bytes.length, sha256: sha256(bytes),
    format: "JAR/J2ME archive", architecture: "JVM bytecode",
    sections: [], imports: [], strings: [], entropy: [],
    disassembly: [], pseudocode: [], algorithms: [],
    reconstructed_sources: [], script_output: [], notes: [],
  };
  const classes: [string, JavaClassInfo][] = [];
  let manifest = "";
  const names: string[] = [];
  for (const entry of entries) {
    const name = entry.name.replace(/\\/g, "/");
    names.push(name);
    if (name.toLowerCase() === "meta-inf/manifest.mf") {
      manifest = new TextDecoder("utf-8", { fatal: false }).decode(readZipEntryData(bytes, entry));
      continue;
    }
    if (name.toLowerCase().endsWith(".class")) {
      const data = readZipEntryData(bytes, entry);
      if (data.length >= 4 && data[0] === 0xca && data[1] === 0xfe && data[2] === 0xba && data[3] === 0xbe) {
        try { classes.push([name, parseJavaClassInfo(data, maxDisassembly)]); } catch {}
      }
    } else if (/\.(jad|properties|txt)$/i.test(name)) {
      const text = new TextDecoder("utf-8", { fatal: false }).decode(readZipEntryData(bytes, entry));
      report.strings.push(...text.split("\n").map(l => l.trim()).filter(l => l.length > 0).slice(0, 64));
    }
  }
  if (manifest.length > 0) {
    report.imports.push(...manifest.split("\n").map(l => l.trim()).filter(l => l.length > 0).map(l => `manifest:${l}`));
    if (isJ2meManifest(manifest)) {
      report.format = "J2ME MIDlet JAR";
      report.notes.push("J2ME/MIDP metadata detected in manifest");
    }
  }
  report.sections = names.slice(0, 512).map((name, idx) => ({
    name, virtual_address: 0, file_offset: idx, size: 0, flags: "jar-entry", entropy: 0,
  }));
  for (const [entryName, cls] of classes) {
    report.imports.push(`class:${cls.name} extends ${cls.superName}`);
    report.imports.push(...cls.refs.map(r => `ref:${r}`));
    report.strings.push(...cls.constants.slice(0, 128));
    for (const method of cls.methods) {
      report.disassembly.push(`\n.class ${cls.name} method ${method.name}${method.descriptor} entry=${entryName}`);
      report.disassembly.push(...method.disassembly.slice(0, maxDisassembly));
      report.pseudocode.push(`${javaReturnType(method.descriptor)} ${method.name}${javaArgs(method.descriptor)} {`);
      report.pseudocode.push(...method.pseudocode.slice(0, 160).map(l => `  ${l}`));
      report.pseudocode.push("}");
    }
    report.reconstructed_sources.push(reconstructJavaSource(cls));
  }
  if (classes.length === 0) report.notes.push("no parseable .class entries found");
  return report;
}
