import type {
  ScannerConfig,
  Finding,
  PatternDefinition,
  PatternMatch,
  ScanOptions,
} from './types.js'
import { patterns as defaultPatterns, patternCategories } from './patterns/index.js'
import { runValidators, calculateConfidence } from './validators/index.js'
import { redactMatch } from './utils/redact.js'
import { loadPatternsFromYAML } from './utils/yaml-loader.js'

export interface ScanResult {
  findings: Finding[]
  scannedLength: number
  patternsChecked: number
  scanTimeMs: number
}

export class ScanAbortedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ScanAbortedError'
  }
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
      allowlist: [],
      denylist: [],
      ...config,
    }
    this.patterns = this.loadPatterns()
  }

  private createScanState(options: ScanOptions = {}) {
    const startTimeMs = Date.now()
    const timeoutMs = options.timeoutMs
    const deadlineMs = typeof timeoutMs === 'number' ? startTimeMs + timeoutMs : undefined

    return {
      startTimeMs,
      deadlineMs,
      signal: options.signal,
      allowlist: options.allowlist ?? this.config.allowlist ?? [],
      denylist: options.denylist ?? this.config.denylist ?? [],
    }
  }

  private checkAbort(state: ReturnType<Scanner['createScanState']>): void {
    if (state.signal?.aborted) {
      throw new ScanAbortedError('Scan aborted')
    }
    if (typeof state.deadlineMs === 'number' && Date.now() > state.deadlineMs) {
      throw new ScanAbortedError('Scan timed out')
    }
  }

  private matchesList(value: string, list: Array<string | RegExp>): boolean {
    for (const entry of list) {
      if (typeof entry === 'string') {
        if (entry === value) return true
      } else if (entry.test(value)) {
        return true
      }
    }
    return false
  }

  private loadPatterns(): PatternDefinition[] {
    let patterns: PatternDefinition[] = []

    // Start with default patterns or filtered set
    if (this.config.patterns && this.config.patterns.length > 0) {
      // Check if patterns are category names or pattern IDs
      for (const p of this.config.patterns) {
        if (p in patternCategories) {
          const categoryPatterns = defaultPatterns.filter((dp) =>
            patternCategories[p as keyof typeof patternCategories].includes(dp.id),
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

    // Load patterns from YAML files
    if (this.config.customPatternFiles && this.config.customPatternFiles.length > 0) {
      for (const file of this.config.customPatternFiles) {
        try {
          const yamlPatterns = loadPatternsFromYAML(file)
          patterns.push(...yamlPatterns)
        } catch (error) {
          console.error(`Failed to load patterns from ${file}:`, error)
          // Continue loading other files
        }
      }
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
  scan(text: string, options: ScanOptions = {}): Finding[] {
    const state = this.createScanState(options)
    return this.scanInternal(text, state)
  }

  /**
   * Full scan with metadata
   */
  scanWithMetadata(text: string, options: ScanOptions = {}): ScanResult {
    const startTime = Date.now()
    const findings = this.scan(text, options)
    const endTime = Date.now()

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
  async scanAsync(text: string, options: ScanOptions = {}): Promise<Finding[]> {
    // For now, just wrap sync scan
    // In future, could chunk large texts or run validators in parallel
    return new Promise((resolve) => {
      const schedule =
        typeof (globalThis as { setImmediate?: (cb: () => void) => void }).setImmediate ===
        'function'
          ? (globalThis as { setImmediate: (cb: () => void) => void }).setImmediate
          : (cb: () => void) => setTimeout(cb, 0)

      schedule(() => {
        resolve(this.scan(text, options))
      })
    })
  }

  /**
   * Chunked scan - useful for very large texts
   */
  scanChunks(text: string, options: ScanOptions = {}): Finding[] {
    const chunkSize = options.chunkSize ?? 200_000
    const overlap = options.overlap ?? 200
    const state = this.createScanState(options)

    if (chunkSize <= 0) {
      throw new Error('chunkSize must be greater than 0')
    }
    if (overlap < 0) {
      throw new Error('overlap must be >= 0')
    }

    const findings: Finding[] = []
    const seen = new Set<string>()

    for (let start = 0; start < text.length; start += chunkSize - overlap) {
      this.checkAbort(state)
      const end = Math.min(text.length, start + chunkSize)
      const chunkText = text.slice(start, end)
      const baseLineInfo = this.getLineInfo(text, start)
      const chunkFindings = this.scanInternal(chunkText, state)

      for (const finding of chunkFindings) {
        const adjusted = this.adjustFindingOffsets(
          finding,
          start,
          baseLineInfo.line,
          baseLineInfo.column,
        )
        const key = `${adjusted.patternId}:${adjusted.start}:${adjusted.end}`
        if (seen.has(key)) continue
        seen.add(key)
        findings.push(adjusted)
      }

      if (end === text.length) break
    }

    return findings.sort((a, b) => {
      if (a.line !== b.line) return (a.line ?? 0) - (b.line ?? 0)
      return (a.column ?? 0) - (b.column ?? 0)
    })
  }

  private scanInternal(text: string, state: ReturnType<Scanner['createScanState']>): Finding[] {
    const findings: Finding[] = []
    const lines = text.split('\n')

    for (const pattern of this.patterns) {
      this.checkAbort(state)
      const matches = this.findMatches(text, pattern, lines, state)

      for (const match of matches) {
        this.checkAbort(state)
        if (match.confidence >= this.config.minConfidence) {
          findings.push(this.createFinding(match, text, lines))
        }
      }
    }

    return findings.sort((a, b) => {
      if (a.line !== b.line) return (a.line ?? 0) - (b.line ?? 0)
      return (a.column ?? 0) - (b.column ?? 0)
    })
  }

  private findMatches(
    text: string,
    pattern: PatternDefinition,
    lines: string[],
    state: ReturnType<Scanner['createScanState']>,
  ): PatternMatch[] {
    const matches: PatternMatch[] = []
    const regex =
      pattern.pattern instanceof RegExp
        ? new RegExp(pattern.pattern.source, pattern.pattern.flags)
        : new RegExp(pattern.pattern, 'g')

    let match: RegExpExecArray | null
    while ((match = regex.exec(text)) !== null) {
      this.checkAbort(state)
      // Check for false positives
      if (this.isFalsePositive(match[0], pattern)) {
        continue
      }

      if (this.matchesList(match[0], state.allowlist)) {
        continue
      }

      const forcedInclude = this.matchesList(match[0], state.denylist)

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
        context,
      )

      // Run validators
      if (!forcedInclude && pattern.validators && pattern.validators.length > 0) {
        if (!runValidators(pattern.validators, match[0])) {
          continue
        }
      }

      matches.push({
        pattern,
        match,
        confidence: forcedInclude ? Math.max(confidence, this.config.minConfidence) : confidence,
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

  private getLineInfo(text: string, index: number): { line: number; column: number } {
    const beforeMatch = text.substring(0, index)
    const lines = beforeMatch.split('\n')
    const line = lines.length
    const lastLine = lines[lines.length - 1] ?? ''
    const column = lastLine.length + 1
    return { line, column }
  }

  private getContext(lines: string[], lineNum: number, contextLines: number): string {
    const startLine = Math.max(0, lineNum - contextLines - 1)
    const endLine = Math.min(lines.length, lineNum + contextLines)
    return lines.slice(startLine, endLine).join('\n')
  }

  private createFinding(match: PatternMatch, text: string, lines: string[]): Finding {
    const lineInfo = this.getLineInfo(text, match.match.index!)
    const start = match.match.index!
    const end = start + match.match[0].length

    const finding: Finding = {
      patternId: match.pattern.id,
      patternName: match.pattern.name,
      severity: match.pattern.severity,
      match: match.match[0],
      redacted: redactMatch(match.match[0]),
      start,
      end,
      line: lineInfo.line,
      column: lineInfo.column,
      confidence: Math.round(match.confidence * 100) / 100,
    }

    if (this.config.includeContext) {
      finding.context = this.getContext(lines, lineInfo.line, this.config.contextLines)
    }

    return finding
  }

  private adjustFindingOffsets(
    finding: Finding,
    offset: number,
    baseLine: number,
    baseColumn: number,
  ): Finding {
    const adjusted: Finding = {
      ...finding,
      start: finding.start + offset,
      end: finding.end + offset,
    }

    if (finding.line !== undefined) {
      adjusted.line = baseLine + finding.line - 1
      if (finding.line === 1 && finding.column !== undefined) {
        adjusted.column = baseColumn + finding.column - 1
      }
    }

    return adjusted
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
