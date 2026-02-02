import { describe, it, expect } from 'vitest'
import { Scanner } from '../src/scanner.js'
import type { PatternDefinition } from '../src/types.js'

describe('Scanner', () => {
  describe('constructor', () => {
    it('should create scanner with default config', () => {
      const scanner = new Scanner()
      expect(scanner.getPatterns().length).toBeGreaterThan(0)
    })

    it('should accept custom config', () => {
      const scanner = new Scanner({
        minConfidence: 0.8,
        includeContext: false,
      })
      expect(scanner).toBeDefined()
    })
  })

  describe('scan', () => {
    it('should detect AWS access key', () => {
      const scanner = new Scanner({ patterns: ['aws-access-key-id'] })
      const text = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
      const findings = scanner.scan(text)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].patternId).toBe('aws-access-key-id')
    })

    it('should detect GitHub PAT', () => {
      const scanner = new Scanner({ patterns: ['github-pat'] })
      const text = 'token: ghp_1234567890abcdefghijklmnopqrstuvwxyz'
      const findings = scanner.scan(text)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].patternId).toBe('github-pat')
    })

    it('should detect private keys', () => {
      const scanner = new Scanner({ patterns: ['rsa-private-key'] })
      const text = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
-----END RSA PRIVATE KEY-----`
      const findings = scanner.scan(text)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].patternId).toBe('rsa-private-key')
    })

    it('should detect credit cards with Luhn validation', () => {
      const scanner = new Scanner({ patterns: ['credit-card'] })
      // Valid Visa test number
      const findings = scanner.scan('Card: 4111111111111111')
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].patternId).toBe('credit-card')
    })

    it('should return empty array for clean text', () => {
      const scanner = new Scanner()
      const findings = scanner.scan('Hello, this is a normal text without secrets.')
      // May have some false positives, but should be low confidence
      const highConfidenceFindings = findings.filter((f) => f.confidence > 0.7)
      expect(highConfidenceFindings.length).toBe(0)
    })

    it('should include line and column information', () => {
      const scanner = new Scanner({ patterns: ['github-pat'] })
      const text = `line 1
line 2
token: ghp_1234567890abcdefghijklmnopqrstuvwxyz
line 4`
      const findings = scanner.scan(text)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].line).toBe(3)
      expect(findings[0].column).toBeGreaterThan(0)
    })

    it('should include context when enabled', () => {
      const scanner = new Scanner({
        patterns: ['github-pat'],
        includeContext: true,
        contextLines: 1,
      })
      const text = `before
token: ghp_1234567890abcdefghijklmnopqrstuvwxyz
after`
      const findings = scanner.scan(text)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].context).toContain('before')
      expect(findings[0].context).toContain('after')
    })

    it('should exclude context when disabled', () => {
      const scanner = new Scanner({
        patterns: ['github-pat'],
        includeContext: false,
      })
      const text = 'token: ghp_1234567890abcdefghijklmnopqrstuvwxyz'
      const findings = scanner.scan(text)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].context).toBeUndefined()
    })
  })

  describe('scanWithMetadata', () => {
    it('should return metadata with findings', () => {
      const scanner = new Scanner({ patterns: ['github-pat'] })
      const text = 'token: ghp_1234567890abcdefghijklmnopqrstuvwxyz'
      const result = scanner.scanWithMetadata(text)

      expect(result.findings.length).toBeGreaterThan(0)
      expect(result.scannedLength).toBe(text.length)
      expect(result.patternsChecked).toBe(1)
      expect(result.scanTimeMs).toBeGreaterThanOrEqual(0)
    })
  })

  describe('pattern filtering', () => {
    it('should filter patterns by ID', () => {
      const scanner = new Scanner({ patterns: ['github-pat', 'stripe-secret-key'] })
      expect(scanner.getPatterns().length).toBe(2)
    })

    it('should filter patterns by category', () => {
      const scanner = new Scanner({ patterns: ['aws'] })
      const patterns = scanner.getPatterns()
      expect(patterns.every((p) => p.id.startsWith('aws') || p.id.includes('gcp') || p.id.includes('azure'))).toBe(true)
    })

    it('should exclude patterns', () => {
      const scanner = new Scanner({
        patterns: ['api-keys'],
        exclude: ['github-pat'],
      })
      const patterns = scanner.getPatterns()
      expect(patterns.find((p) => p.id === 'github-pat')).toBeUndefined()
    })
  })

  describe('custom patterns', () => {
    it('should add custom pattern via config', () => {
      const customPattern: PatternDefinition = {
        id: 'custom-test',
        name: 'Custom Test Pattern',
        severity: 'high',
        pattern: /CUSTOM_SECRET_[A-Z0-9]{10}/g,
        keywords: ['custom', 'secret'],
      }

      const scanner = new Scanner({
        customPatterns: [customPattern],
      })

      const findings = scanner.scan('My secret: CUSTOM_SECRET_ABCDEFGH12')
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].patternId).toBe('custom-test')
    })

    it('should add custom pattern via addPattern method', () => {
      const scanner = new Scanner({ patterns: [] })

      scanner.addPattern({
        id: 'runtime-pattern',
        name: 'Runtime Pattern',
        severity: 'medium',
        pattern: /RUNTIME_[0-9]+/g,
      })

      const findings = scanner.scan('Code: RUNTIME_12345')
      expect(findings.length).toBeGreaterThan(0)
    })
  })

  describe('removePattern', () => {
    it('should remove pattern by ID', () => {
      const scanner = new Scanner({ patterns: ['github-pat', 'stripe-secret-key'] })
      expect(scanner.getPatterns().length).toBe(2)

      const removed = scanner.removePattern('github-pat')
      expect(removed).toBe(true)
      expect(scanner.getPatterns().length).toBe(1)
    })

    it('should return false if pattern not found', () => {
      const scanner = new Scanner({ patterns: ['github-pat'] })
      const removed = scanner.removePattern('non-existent')
      expect(removed).toBe(false)
    })
  })

  describe('getPattern', () => {
    it('should return pattern by ID', () => {
      const scanner = new Scanner({ patterns: ['github-pat'] })
      const pattern = scanner.getPattern('github-pat')
      expect(pattern).toBeDefined()
      expect(pattern?.id).toBe('github-pat')
    })

    it('should return undefined for unknown pattern', () => {
      const scanner = new Scanner({ patterns: ['github-pat'] })
      const pattern = scanner.getPattern('unknown')
      expect(pattern).toBeUndefined()
    })
  })

  describe('quickCheck', () => {
    it('should return true if any pattern matches', () => {
      const scanner = new Scanner({ patterns: ['github-pat'] })
      expect(scanner.quickCheck('ghp_1234567890abcdefghijklmnopqrstuvwxyz')).toBe(true)
    })

    it('should return false if no pattern matches', () => {
      const scanner = new Scanner({ patterns: ['github-pat'] })
      expect(scanner.quickCheck('normal text')).toBe(false)
    })
  })

  describe('minConfidence filtering', () => {
    it('should filter out low confidence matches', () => {
      const scanner = new Scanner({
        minConfidence: 0.9,
      })
      // Low entropy string that might match some pattern
      const findings = scanner.scan('test123456789')
      // High confidence threshold should filter most matches
      expect(findings.every((f) => f.confidence >= 0.9)).toBe(true)
    })
  })
})
