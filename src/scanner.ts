import type { ScannerConfig, Finding, PatternDefinition, PatternMatch } from './types.js'
import { patterns as defaultPatterns, patternCategories } from './patterns/index.js'
import { runValidators, calculateConfidence } from './validators/index.js'
import { redactMatch } from './utils/redact.js'

export interface ScanResult {
  findings: Finding[]
  scannedLength: number
  patternsChecked: number
  scanTimeMs: number
}

export class Scanner {
  private patterns: PatternDefinition[]
  private config: Required<
    Pick<ScannerConfig, 'minConfidence' | 'includeContext' | 'contextLines'>
  > &
    ScannerConfig

  constructor(config: ScannerConfig = {}) {
    this.config = {
      minConfidence: 0.5,
      includeContext: true,
      contextLines: 2,
      ...config,
    }
    this.patterns = this.loadPatterns()
  }

  private loadPatterns(): PatternDefinition[] {
    let patterns: PatternDefinition[] = []

    // Start with default patterns or filtered set
    if (this.config.patterns && this.config.patterns.length > 0) {
      // Check if patterns are category names or pattern IDs
      for (const p of this.config.patterns) {
        if (p in patternCategories) {
          const categoryPatterns = defaultPatterns.filter((dp) =>
            patternCategories[p as keyof typeof patternCategories].includes(dp.id)
          )
          patterns.push(...categoryPatterns)
        } else {
          const pattern = defaultPatterns.find((dp) => dp.id === p)
          if (pattern) {
            patterns.push(pattern)
          }
        }
      }
    } else {
      patterns = [...defaultPatterns]
    }

    // Apply exclusions
    if (this.config.exclude && this.config.exclude.length > 0) {
      const excludeSet = new Set(this.config.exclude)
      patterns = patterns.filter((p) => !excludeSet.has(p.id))
    }

    // Add custom patterns
    if (this.config.customPatterns && this.config.customPatterns.length > 0) {
      patterns.push(...this.config.customPatterns)
    }

    // Deduplicate by ID
    const seen = new Set<string>()
    return patterns.filter((p) => {
      if (seen.has(p.id)) return false
      seen.add(p.id)
      return true
    })
  }

  /**
   * Synchronous scan - validates patterns inline
   */
  scan(text: string): Finding[] {
    const findings: Finding[] = []
    const lines = text.split('\n')

    for (const pattern of this.patterns) {
      const matches = this.findMatches(text, pattern, lines)

      for (const match of matches) {
        if (match.confidence >= this.config.minConfidence) {
          findings.push(this.createFinding(match, text, lines))
        }
      }
    }

    // Sort by line number, then by column
    return findings.sort((a, b) => {
      if (a.line !== b.line) return (a.line ?? 0) - (b.line ?? 0)
      return (a.column ?? 0) - (b.column ?? 0)
    })
  }

  /**
   * Full scan with metadata
   */
  scanWithMetadata(text: string): ScanResult {
    const startTime = performance.now()
    const findings = this.scan(text)
    const endTime = performance.now()

    return {
      findings,
      scannedLength: text.length,
      patternsChecked: this.patterns.length,
      scanTimeMs: endTime - startTime,
    }
  }

  /**
   * Async scan - useful for large texts or expensive validators
   */
  async scanAsync(text: string): Promise<Finding[]> {
    // For now, just wrap sync scan
    // In future, could chunk large texts or run validators in parallel
    return new Promise((resolve) => {
      setImmediate(() => {
        resolve(this.scan(text))
      })
    })
  }

  private findMatches(
    text: string,
    pattern: PatternDefinition,
    lines: string[]
  ): PatternMatch[] {
    const matches: PatternMatch[] = []
    const regex =
      pattern.pattern instanceof RegExp
        ? new RegExp(pattern.pattern.source, pattern.pattern.flags)
        : new RegExp(pattern.pattern, 'g')

    let match: RegExpExecArray | null
    while ((match = regex.exec(text)) !== null) {
      // Check for false positives
      if (this.isFalsePositive(match[0], pattern)) {
        continue
      }

      // Get context for confidence calculation
      const lineInfo = this.getLineInfo(text, match.index)
      const context = this.config.includeContext
        ? this.getContext(lines, lineInfo.line, this.config.contextLines)
        : undefined

      // Calculate confidence
      const confidence = calculateConfidence(
        match[0],
        pattern.validators ?? [],
        pattern.keywords,
        context
      )

      // Run validators
      if (pattern.validators && pattern.validators.length > 0) {
        if (!runValidators(pattern.validators, match[0])) {
          continue
        }
      }

      matches.push({
        pattern,
        match,
        confidence,
      })

      // Prevent infinite loops with zero-width matches
      if (match[0].length === 0) {
        regex.lastIndex++
      }
    }

    return matches
  }

  private isFalsePositive(matchStr: string, pattern: PatternDefinition): boolean {
    if (!pattern.falsePositives) return false

    for (const fp of pattern.falsePositives) {
      if (fp.test(matchStr)) {
        return true
      }
    }
    return false
  }

  private getLineInfo(
    text: string,
    index: number
  ): { line: number; column: number } {
    const beforeMatch = text.substring(0, index)
    const lines = beforeMatch.split('\n')
    const line = lines.length
    const column = lines[lines.length - 1].length + 1
    return { line, column }
  }

  private getContext(lines: string[], lineNum: number, contextLines: number): string {
    const startLine = Math.max(0, lineNum - contextLines - 1)
    const endLine = Math.min(lines.length, lineNum + contextLines)
    return lines.slice(startLine, endLine).join('\n')
  }

  private createFinding(match: PatternMatch, text: string, lines: string[]): Finding {
    const lineInfo = this.getLineInfo(text, match.match.index!)

    return {
      patternId: match.pattern.id,
      patternName: match.pattern.name,
      severity: match.pattern.severity,
      match: match.match[0],
      redacted: redactMatch(match.match[0]),
      line: lineInfo.line,
      column: lineInfo.column,
      context: this.config.includeContext
        ? this.getContext(lines, lineInfo.line, this.config.contextLines)
        : undefined,
      confidence: Math.round(match.confidence * 100) / 100,
    }
  }

  /**
   * Add a custom pattern to the scanner
   */
  addPattern(pattern: PatternDefinition): void {
    // Remove existing pattern with same ID if exists
    this.patterns = this.patterns.filter((p) => p.id !== pattern.id)
    this.patterns.push(pattern)
  }

  /**
   * Remove a pattern by ID
   */
  removePattern(id: string): boolean {
    const initialLength = this.patterns.length
    this.patterns = this.patterns.filter((p) => p.id !== id)
    return this.patterns.length < initialLength
  }

  /**
   * Get all loaded patterns
   */
  getPatterns(): PatternDefinition[] {
    return [...this.patterns]
  }

  /**
   * Get pattern by ID
   */
  getPattern(id: string): PatternDefinition | undefined {
    return this.patterns.find((p) => p.id === id)
  }

  /**
   * Update scanner configuration
   */
  updateConfig(config: Partial<ScannerConfig>): void {
    this.config = { ...this.config, ...config }
    if (config.patterns || config.exclude || config.customPatterns) {
      this.patterns = this.loadPatterns()
    }
  }

  /**
   * Check if a single string matches any pattern
   */
  quickCheck(text: string): boolean {
    for (const pattern of this.patterns) {
      const regex =
        pattern.pattern instanceof RegExp
          ? new RegExp(pattern.pattern.source, pattern.pattern.flags)
          : new RegExp(pattern.pattern, 'g')

      if (regex.test(text)) {
        return true
      }
    }
    return false
  }
}
