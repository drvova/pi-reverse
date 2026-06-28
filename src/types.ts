export interface BinarySection {
  name: string;
  virtual_address: number;
  file_offset: number;
  size: number;
  flags: string;
  entropy: number;
}

export interface EntropyWindow {
  offset: number;
  size: number;
  entropy: number;
}

export interface ReconstructedSource {
  path: string;
  language: string;
  content: string;
}

export interface ReverseReport {
  path: string;
  size: number;
  sha256: string;
  format: string;
  architecture: string;
  sections: BinarySection[];
  imports: string[];
  strings: string[];
  entropy: EntropyWindow[];
  disassembly: string[];
  pseudocode: string[];
  algorithms: string[];
  reconstructed_sources: ReconstructedSource[];
  script_output: string[];
  notes: string[];
}

export interface AnalyzeOptions {
  mode?: string;
  max_strings?: number;
  max_disassembly?: number;
  max_bytes?: number;
  script?: string;
  generate_source?: boolean;
}

export const DEFAULT_OPTIONS: Required<Omit<AnalyzeOptions, "script" | "mode">> & { script: string | null; mode: string } = {
  mode: "overview",
  max_strings: 160,
  max_disassembly: 256,
  max_bytes: 64 * 1024 * 1024,
  script: null,
  generate_source: false,
};
