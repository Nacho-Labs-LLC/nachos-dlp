export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Finding {
  patternId: string
  patternName: string
  severity: Severity
  match: string
  redacted: string
  start: number
  end: number
  line?: number
  column?: number
  context?: string
  confidence: number
}

export interface PatternMatch {
  pattern: PatternDefinition
  match: RegExpExecArray
  confidence: number
}

export interface ScannerConfig {
  patterns?: string[]
  exclude?: string[]
  customPatterns?: PatternDefinition[]
  customPatternFiles?: string[] // YAML files to load patterns from
  minConfidence?: number
  includeContext?: boolean
  contextLines?: number
  allowlist?: Array<string | RegExp>
  denylist?: Array<string | RegExp>
}

export interface ScanOptions {
  signal?: AbortSignal
  timeoutMs?: number
  allowlist?: Array<string | RegExp>
  denylist?: Array<string | RegExp>
  chunkSize?: number
  overlap?: number
}

export interface PatternDefinition {
  id: string
  name: string
  description?: string
  severity: Severity
  pattern: RegExp | string
  keywords?: string[]
  validators?: Validator[]
  falsePositives?: RegExp[]
  examples?: {
    positive: string[]
    negative: string[]
  }
}

export type Validator =
  | { type: 'entropy'; min: number }
  | { type: 'luhn' }
  | { type: 'checksum'; algorithm: string }
  | { type: 'length'; min?: number; max?: number }
  | { type: 'custom'; fn: (match: string) => boolean }
