import type { Finding } from '../types.js'

export interface RedactOptions {
  /** Replacement string for redacted content */
  replacement?: string
  /** Number of characters to show at the start */
  showPrefix?: number
  /** Number of characters to show at the end */
  showSuffix?: number
  /** Use partial masking (show prefix/suffix) */
  partial?: boolean
  /** Custom mask character */
  maskChar?: string
  /** Mask format: 'fixed' uses replacement, 'length' preserves length with maskChar */
  maskFormat?: 'fixed' | 'length'
}

const DEFAULT_OPTIONS: Required<RedactOptions> = {
  replacement: '[REDACTED]',
  showPrefix: 4,
  showSuffix: 4,
  partial: false,
  maskChar: '*',
  maskFormat: 'fixed',
}

/**
 * Redact a single match value
 */
export function redactMatch(value: string, options: RedactOptions = {}): string {
  const opts = { ...DEFAULT_OPTIONS, ...options }

  if (opts.partial && value.length > opts.showPrefix + opts.showSuffix + 4) {
    const prefix = value.substring(0, opts.showPrefix)
    const suffix = value.substring(value.length - opts.showSuffix)
    const middleLength = value.length - opts.showPrefix - opts.showSuffix

    if (opts.maskFormat === 'length') {
      return prefix + opts.maskChar.repeat(middleLength) + suffix
    }
    return `${prefix}...${suffix}`
  }

  if (opts.maskFormat === 'length') {
    return opts.maskChar.repeat(value.length)
  }

  return opts.replacement
}

/**
 * Redact all findings in a text
 * Replaces all matched sensitive data with redacted versions
 */
export function redact(
  text: string,
  findings: Finding[],
  options: RedactOptions = {}
): string {
  if (findings.length === 0) return text

  const opts = { ...DEFAULT_OPTIONS, ...options }

  // Sort findings by position (descending) to replace from end to start
  // This preserves indices as we make replacements
  const sortedFindings = [...findings].sort((a, b) => {
    const posA = getMatchPosition(text, a.match)
    const posB = getMatchPosition(text, b.match)
    return posB - posA
  })

  let result = text

  for (const finding of sortedFindings) {
    const pos = getMatchPosition(result, finding.match)
    if (pos === -1) continue

    const redactedValue = redactMatch(finding.match, opts)
    result = result.substring(0, pos) + redactedValue + result.substring(pos + finding.match.length)
  }

  return result
}

/**
 * Redact text using a scanner (convenience function)
 */
export function redactWithPatterns(
  text: string,
  findings: Finding[],
  options: RedactOptions = {}
): {
  redacted: string
  findings: Finding[]
  replacements: Array<{ original: string; redacted: string; position: number }>
} {
  const opts = { ...DEFAULT_OPTIONS, ...options }
  const replacements: Array<{ original: string; redacted: string; position: number }> = []

  if (findings.length === 0) {
    return { redacted: text, findings: [], replacements: [] }
  }

  // Build replacement list
  const sortedFindings = [...findings].sort((a, b) => {
    const posA = getMatchPosition(text, a.match)
    const posB = getMatchPosition(text, b.match)
    return posA - posB
  })

  let result = text
  let offset = 0

  for (const finding of sortedFindings) {
    const originalPos = getMatchPosition(text, finding.match)
    if (originalPos === -1) continue

    const adjustedPos = originalPos + offset
    const redactedValue = redactMatch(finding.match, opts)

    replacements.push({
      original: finding.match,
      redacted: redactedValue,
      position: originalPos,
    })

    result =
      result.substring(0, adjustedPos) +
      redactedValue +
      result.substring(adjustedPos + finding.match.length)

    offset += redactedValue.length - finding.match.length
  }

  return { redacted: result, findings, replacements }
}

/**
 * Get position of a match in text
 */
function getMatchPosition(text: string, match: string): number {
  return text.indexOf(match)
}

/**
 * Create a redacted summary of findings
 */
export function summarizeFindings(findings: Finding[]): string {
  if (findings.length === 0) {
    return 'No sensitive data found.'
  }

  const bySeverity = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1
      return acc
    },
    {} as Record<string, number>
  )

  const byPattern = findings.reduce(
    (acc, f) => {
      acc[f.patternName] = (acc[f.patternName] || 0) + 1
      return acc
    },
    {} as Record<string, number>
  )

  const lines = [
    `Found ${findings.length} sensitive item(s):`,
    '',
    'By severity:',
    ...Object.entries(bySeverity).map(([sev, count]) => `  ${sev}: ${count}`),
    '',
    'By type:',
    ...Object.entries(byPattern).map(([name, count]) => `  ${name}: ${count}`),
  ]

  return lines.join('\n')
}

/**
 * Format findings as a report
 */
export function formatReport(
  findings: Finding[],
  options: { showContext?: boolean; showRedacted?: boolean } = {}
): string {
  const { showContext = false, showRedacted = true } = options

  if (findings.length === 0) {
    return 'No sensitive data found.'
  }

  const lines: string[] = []

  for (const finding of findings) {
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.patternName}`)
    lines.push(`  Pattern: ${finding.patternId}`)
    lines.push(`  Location: line ${finding.line}, column ${finding.column}`)
    lines.push(`  Confidence: ${Math.round(finding.confidence * 100)}%`)

    if (showRedacted) {
      lines.push(`  Value: ${finding.redacted}`)
    }

    if (showContext && finding.context) {
      lines.push('  Context:')
      finding.context.split('\n').forEach((l) => lines.push(`    ${l}`))
    }

    lines.push('')
  }

  return lines.join('\n')
}
