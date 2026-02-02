import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import {
  loadPatternsFromYAML,
  loadPatternsFromYAMLString,
  exportPatternsToYAML,
} from '../src/utils/yaml-loader.js'
import type { PatternDefinition } from '../src/types.js'

const TEST_DIR = join(process.cwd(), 'tests', 'fixtures', 'yaml-test')

describe('YAML Pattern Loader', () => {
  beforeEach(() => {
    // Create test directory
    mkdirSync(TEST_DIR, { recursive: true })
  })

  afterEach(() => {
    // Clean up test directory
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  describe('loadPatternsFromYAMLString', () => {
    it('should load patterns from valid YAML string', () => {
      const yaml = `
patterns:
  - id: test-pattern
    name: Test Pattern
    description: A test pattern
    severity: high
    pattern: "test-\\\\d+"
    flags: gi
    keywords:
      - test
      - pattern
    validators:
      - type: entropy
        min: 3.0
`
      const patterns = loadPatternsFromYAMLString(yaml)
      expect(patterns).toHaveLength(1)
      expect(patterns[0].id).toBe('test-pattern')
      expect(patterns[0].name).toBe('Test Pattern')
      expect(patterns[0].severity).toBe('high')
      expect(patterns[0].keywords).toEqual(['test', 'pattern'])
      expect(patterns[0].validators).toHaveLength(1)
      expect(patterns[0].validators![0]).toEqual({ type: 'entropy', min: 3.0 })
    })

    it('should load multiple patterns', () => {
      const yaml = `
patterns:
  - id: pattern-1
    name: Pattern One
    severity: critical
    pattern: "pat1"
    flags: g
  - id: pattern-2
    name: Pattern Two
    severity: medium
    pattern: "pat2"
    flags: g
`
      const patterns = loadPatternsFromYAMLString(yaml)
      expect(patterns).toHaveLength(2)
      expect(patterns[0].id).toBe('pattern-1')
      expect(patterns[1].id).toBe('pattern-2')
    })

    it('should handle patterns without optional fields', () => {
      const yaml = `
patterns:
  - id: minimal-pattern
    name: Minimal
    severity: low
    pattern: "test"
    flags: g
`
      const patterns = loadPatternsFromYAMLString(yaml)
      expect(patterns).toHaveLength(1)
      expect(patterns[0].keywords).toEqual([])
      expect(patterns[0].validators).toEqual([])
    })

    it('should throw error for invalid YAML', () => {
      const yaml = `
invalid: yaml: structure
`
      expect(() => loadPatternsFromYAMLString(yaml)).toThrow()
    })

    it('should throw error for missing patterns array', () => {
      const yaml = `
notpatterns:
  - id: test
`
      expect(() => loadPatternsFromYAMLString(yaml)).toThrow('must contain a "patterns" array')
    })

    it('should throw error for pattern without id', () => {
      const yaml = `
patterns:
  - name: No ID Pattern
    severity: high
    pattern: "test"
`
      expect(() => loadPatternsFromYAMLString(yaml)).toThrow('must have a string "id" field')
    })

    it('should throw error for pattern without name', () => {
      const yaml = `
patterns:
  - id: no-name
    severity: high
    pattern: "test"
`
      expect(() => loadPatternsFromYAMLString(yaml)).toThrow('must have a string "name" field')
    })

    it('should throw error for invalid severity', () => {
      const yaml = `
patterns:
  - id: bad-severity
    name: Bad Severity
    severity: invalid
    pattern: "test"
`
      expect(() => loadPatternsFromYAMLString(yaml)).toThrow('must have a severity')
    })

    it('should throw error for invalid regex pattern', () => {
      const yaml = `
patterns:
  - id: bad-regex
    name: Bad Regex
    severity: high
    pattern: "[invalid(regex"
`
      expect(() => loadPatternsFromYAMLString(yaml)).toThrow('invalid regex')
    })

    it('should skip custom validators with warning', () => {
      const yaml = `
patterns:
  - id: custom-validator-pattern
    name: Custom Validator
    severity: high
    pattern: "test"
    validators:
      - type: custom
        fn: "() => true"
      - type: entropy
        min: 4.0
`
      const patterns = loadPatternsFromYAMLString(yaml)
      expect(patterns[0].validators).toHaveLength(1)
      expect(patterns[0].validators![0]).toEqual({ type: 'entropy', min: 4.0 })
    })

    it('should support all validator types', () => {
      const yaml = `
patterns:
  - id: multi-validator
    name: Multi Validator
    severity: high
    pattern: "test"
    validators:
      - type: entropy
        min: 3.5
      - type: luhn
      - type: length
        min: 10
        max: 50
      - type: checksum
        algorithm: luhn
`
      const patterns = loadPatternsFromYAMLString(yaml)
      expect(patterns[0].validators).toHaveLength(4)
      expect(patterns[0].validators![0]).toEqual({ type: 'entropy', min: 3.5 })
      expect(patterns[0].validators![1]).toEqual({ type: 'luhn' })
      expect(patterns[0].validators![2]).toEqual({ type: 'length', min: 10, max: 50 })
      expect(patterns[0].validators![3]).toEqual({ type: 'checksum', algorithm: 'luhn' })
    })
  })

  describe('loadPatternsFromYAML', () => {
    it('should load patterns from YAML file', () => {
      const yaml = `
patterns:
  - id: file-pattern
    name: File Pattern
    severity: critical
    pattern: "file-\\\\d+"
    flags: g
`
      const filePath = join(TEST_DIR, 'patterns.yaml')
      writeFileSync(filePath, yaml, 'utf-8')

      const patterns = loadPatternsFromYAML(filePath)
      expect(patterns).toHaveLength(1)
      expect(patterns[0].id).toBe('file-pattern')
    })

    it('should throw error for non-existent file', () => {
      const filePath = join(TEST_DIR, 'non-existent.yaml')
      expect(() => loadPatternsFromYAML(filePath)).toThrow()
    })
  })

  describe('exportPatternsToYAML', () => {
    it('should export patterns to YAML string', () => {
      const patterns: PatternDefinition[] = [
        {
          id: 'export-test',
          name: 'Export Test',
          description: 'Test export',
          severity: 'high',
          pattern: /test-\d+/g,
          keywords: ['test', 'export'],
          validators: [{ type: 'entropy', min: 3.5 }],
          examples: { positive: [], negative: [] },
        },
      ]

      const yaml = exportPatternsToYAML(patterns)
      expect(yaml).toContain('id: export-test')
      expect(yaml).toContain('name: Export Test')
      expect(yaml).toContain('severity: high')
      expect(yaml).toContain('pattern: "test-')
      expect(yaml).toContain('flags: g')

      // Verify it can be re-imported
      const reimported = loadPatternsFromYAMLString(yaml)
      expect(reimported).toHaveLength(1)
      expect(reimported[0].id).toBe('export-test')
    })

    it('should export multiple patterns', () => {
      const patterns: PatternDefinition[] = [
        {
          id: 'pattern-1',
          name: 'Pattern 1',
          severity: 'critical',
          pattern: /p1/g,
          validators: [],
          examples: { positive: [], negative: [] },
        },
        {
          id: 'pattern-2',
          name: 'Pattern 2',
          severity: 'medium',
          pattern: /p2/gi,
          validators: [],
          examples: { positive: [], negative: [] },
        },
      ]

      const yaml = exportPatternsToYAML(patterns)
      expect(yaml).toContain('id: pattern-1')
      expect(yaml).toContain('id: pattern-2')
    })

    it('should handle string patterns', () => {
      const patterns: PatternDefinition[] = [
        {
          id: 'string-pattern',
          name: 'String Pattern',
          severity: 'low',
          pattern: 'test-string',
          validators: [],
          examples: { positive: [], negative: [] },
        },
      ]

      const yaml = exportPatternsToYAML(patterns)
      expect(yaml).toContain('id: string-pattern')
      expect(yaml).toContain('pattern: "test-string"')
    })
  })

  describe('Scanner integration with YAML', () => {
    it('should load and use patterns from YAML file in Scanner', async () => {
      const yaml = `
patterns:
  - id: custom-api-key
    name: Custom API Key
    severity: critical
    pattern: "CUSTOM-[A-Z0-9]{32}"
    flags: g
    keywords:
      - custom
      - api
    validators:
      - type: entropy
        min: 3.0
`
      const filePath = join(TEST_DIR, 'custom-patterns.yaml')
      writeFileSync(filePath, yaml, 'utf-8')

      const { Scanner } = await import('../src/scanner.js')
      const scanner = new Scanner({
        patterns: [], // No default patterns
        customPatternFiles: [filePath],
      })

      const findings = scanner.scan('My custom key is CUSTOM-ABCD1234EFGH5678IJKL9012MNOP3456')
      const customFindings = findings.filter((f) => f.patternId === 'custom-api-key')
      expect(customFindings).toHaveLength(1)
      expect(customFindings[0].severity).toBe('critical')
    })
  })
})
