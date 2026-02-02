import { describe, it, expect } from 'vitest'
import {
  redact,
  redactMatch,
  redactWithPatterns,
  summarizeFindings,
  formatReport,
} from '../src/utils/redact.js'
import { Scanner } from '../src/scanner.js'
import type { Finding } from '../src/types.js'

describe('redactMatch', () => {
  it('should redact with default replacement', () => {
    expect(redactMatch('secret123')).toBe('[REDACTED]')
  })

  it('should redact with custom replacement', () => {
    expect(redactMatch('secret123', { replacement: '***' })).toBe('***')
  })

  it('should show partial match when enabled', () => {
    const result = redactMatch('ghp_1234567890abcdefghijklmnopqrstuvwxyz', {
      partial: true,
      showPrefix: 4,
      showSuffix: 4,
    })
    expect(result).toBe('ghp_...wxyz')
  })

  it('should use mask character when format is length', () => {
    const result = redactMatch('secret', { maskFormat: 'length', maskChar: '*' })
    expect(result).toBe('******')
  })

  it('should use partial mask with length format', () => {
    const result = redactMatch('ghp_1234567890abcdefghijklmnopqrstuvwxyz', {
      partial: true,
      showPrefix: 4,
      showSuffix: 4,
      maskFormat: 'length',
      maskChar: 'X',
    })
    expect(result.startsWith('ghp_')).toBe(true)
    expect(result.endsWith('wxyz')).toBe(true)
    expect(result.includes('X')).toBe(true)
  })

  it('should not use partial for short strings', () => {
    const result = redactMatch('short', {
      partial: true,
      showPrefix: 4,
      showSuffix: 4,
    })
    expect(result).toBe('[REDACTED]')
  })
})

describe('redact', () => {
  it('should redact all findings in text', () => {
    const text =
      'Key1: ghp_1234567890abcdefghijklmnopqrstuvwxyz and Key2: ghp_abcdefghijklmnopqrstuvwxyz123456'
    const findings: Finding[] = [
      {
        patternId: 'github-pat',
        patternName: 'GitHub PAT',
        severity: 'critical',
        match: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
        redacted: '[REDACTED]',
        start: 6,
        end: 46,
        confidence: 0.9,
      },
      {
        patternId: 'github-pat',
        patternName: 'GitHub PAT',
        severity: 'critical',
        match: 'ghp_abcdefghijklmnopqrstuvwxyz123456',
        redacted: '[REDACTED]',
        start: 57,
        end: 93,
        confidence: 0.9,
      },
    ]

    const result = redact(text, findings)
    expect(result).toBe('Key1: [REDACTED] and Key2: [REDACTED]')
  })

  it('should return original text if no findings', () => {
    const text = 'Normal text without secrets'
    const result = redact(text, [])
    expect(result).toBe(text)
  })

  it('should handle overlapping findings', () => {
    const text = 'secret: AKIAIOSFODNN7EXAMPLE'
    const findings: Finding[] = [
      {
        patternId: 'aws-access-key-id',
        patternName: 'AWS Access Key',
        severity: 'critical',
        match: 'AKIAIOSFODNN7EXAMPLE',
        redacted: '[REDACTED]',
        start: 8,
        end: 28,
        confidence: 0.9,
      },
    ]

    const result = redact(text, findings)
    expect(result).toBe('secret: [REDACTED]')
  })

  it('should use custom redaction options', () => {
    const text = 'Key: ghp_1234567890abcdefghijklmnopqrstuvwxyz'
    const findings: Finding[] = [
      {
        patternId: 'github-pat',
        patternName: 'GitHub PAT',
        severity: 'critical',
        match: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
        redacted: '[REDACTED]',
        start: 5,
        end: 45,
        confidence: 0.9,
      },
    ]

    const result = redact(text, findings, { partial: true, showPrefix: 4, showSuffix: 4 })
    expect(result).toBe('Key: ghp_...wxyz')
  })
})

describe('redactWithPatterns', () => {
  it('should return redacted text and replacements', () => {
    const text = 'Key: ghp_1234567890abcdefghijklmnopqrstuvwxyz'
    const findings: Finding[] = [
      {
        patternId: 'github-pat',
        patternName: 'GitHub PAT',
        severity: 'critical',
        match: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
        redacted: '[REDACTED]',
        start: 5,
        end: 45,
        confidence: 0.9,
      },
    ]

    const result = redactWithPatterns(text, findings)

    expect(result.redacted).toBe('Key: [REDACTED]')
    expect(result.replacements.length).toBe(1)
    expect(result.replacements[0].original).toBe('ghp_1234567890abcdefghijklmnopqrstuvwxyz')
    expect(result.replacements[0].redacted).toBe('[REDACTED]')
    expect(result.replacements[0].position).toBe(5)
  })

  it('should handle multiple findings', () => {
    const text = 'First: secret1 Second: secret2'
    const findings: Finding[] = [
      {
        patternId: 'test',
        patternName: 'Test',
        severity: 'high',
        match: 'secret1',
        redacted: '[REDACTED]',
        start: 7,
        end: 14,
        confidence: 0.8,
      },
      {
        patternId: 'test',
        patternName: 'Test',
        severity: 'high',
        match: 'secret2',
        redacted: '[REDACTED]',
        start: 23,
        end: 30,
        confidence: 0.8,
      },
    ]

    const result = redactWithPatterns(text, findings)
    expect(result.redacted).toBe('First: [REDACTED] Second: [REDACTED]')
    expect(result.replacements.length).toBe(2)
  })
})

describe('summarizeFindings', () => {
  it('should return message for no findings', () => {
    expect(summarizeFindings([])).toBe('No sensitive data found.')
  })

  it('should summarize findings by severity and type', () => {
    const findings: Finding[] = [
      {
        patternId: 'aws-key',
        patternName: 'AWS Access Key',
        severity: 'critical',
        match: 'test',
        redacted: '[REDACTED]',
        start: 0,
        end: 4,
        confidence: 0.9,
      },
      {
        patternId: 'github-pat',
        patternName: 'GitHub PAT',
        severity: 'critical',
        match: 'test',
        redacted: '[REDACTED]',
        start: 0,
        end: 4,
        confidence: 0.9,
      },
      {
        patternId: 'email',
        patternName: 'Email Address',
        severity: 'low',
        match: 'test',
        redacted: '[REDACTED]',
        start: 0,
        end: 4,
        confidence: 0.7,
      },
    ]

    const summary = summarizeFindings(findings)
    expect(summary).toContain('Found 3 sensitive item(s)')
    expect(summary).toContain('critical: 2')
    expect(summary).toContain('low: 1')
    expect(summary).toContain('AWS Access Key: 1')
    expect(summary).toContain('GitHub PAT: 1')
    expect(summary).toContain('Email Address: 1')
  })
})

describe('formatReport', () => {
  it('should return message for no findings', () => {
    expect(formatReport([])).toBe('No sensitive data found.')
  })

  it('should format findings as report', () => {
    const findings: Finding[] = [
      {
        patternId: 'github-pat',
        patternName: 'GitHub PAT',
        severity: 'critical',
        match: 'ghp_test',
        redacted: '[REDACTED]',
        start: 0,
        end: 8,
        line: 10,
        column: 5,
        confidence: 0.95,
      },
    ]

    const report = formatReport(findings)
    expect(report).toContain('[CRITICAL] GitHub PAT')
    expect(report).toContain('Pattern: github-pat')
    expect(report).toContain('Location: line 10, column 5')
    expect(report).toContain('Confidence: 95%')
    expect(report).toContain('Value: [REDACTED]')
  })

  it('should include context when enabled', () => {
    const findings: Finding[] = [
      {
        patternId: 'github-pat',
        patternName: 'GitHub PAT',
        severity: 'critical',
        match: 'ghp_test',
        redacted: '[REDACTED]',
        start: 0,
        end: 8,
        line: 2,
        column: 1,
        context: 'line before\ntoken: ghp_test\nline after',
        confidence: 0.9,
      },
    ]

    const report = formatReport(findings, { showContext: true })
    expect(report).toContain('Context:')
    expect(report).toContain('line before')
    expect(report).toContain('line after')
  })

  it('should hide redacted value when disabled', () => {
    const findings: Finding[] = [
      {
        patternId: 'github-pat',
        patternName: 'GitHub PAT',
        severity: 'critical',
        match: 'ghp_test',
        redacted: '[REDACTED]',
        start: 0,
        end: 8,
        line: 1,
        column: 1,
        confidence: 0.9,
      },
    ]

    const report = formatReport(findings, { showRedacted: false })
    expect(report).not.toContain('Value:')
  })
})

describe('Integration: Scanner + Redact', () => {
  it('should scan and redact text', () => {
    const scanner = new Scanner({ patterns: ['github-pat'] })
    const text = 'My token is ghp_1234567890abcdefghijklmnopqrstuvwxyz'

    const findings = scanner.scan(text)
    const redacted = redact(text, findings)

    expect(findings.length).toBeGreaterThan(0)
    expect(redacted).not.toContain('ghp_1234567890abcdefghijklmnopqrstuvwxyz')
    expect(redacted).toContain('[REDACTED]')
  })
})
