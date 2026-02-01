import type { ScannerConfig, Finding, PatternDefinition } from './types.js'
import { patterns as defaultPatterns } from './patterns/index.js'

export class Scanner {
  private patterns: PatternDefinition[]
  private config: ScannerConfig

  constructor(config: ScannerConfig = {}) {
    this.config = config
    this.patterns = this.loadPatterns()
  }

  private loadPatterns(): PatternDefinition[] {
    // TODO: Implement pattern loading with include/exclude
    return defaultPatterns
  }

  scan(text: string): Finding[] {
    const findings: Finding[] = []
    // TODO: Implement scanning logic
    return findings
  }

  scanAsync(text: string): Promise<Finding[]> {
    // TODO: Implement async scanning with validators
    return Promise.resolve(this.scan(text))
  }

  addPattern(pattern: PatternDefinition): void {
    this.patterns.push(pattern)
  }

  getPatterns(): PatternDefinition[] {
    return [...this.patterns]
  }
}
