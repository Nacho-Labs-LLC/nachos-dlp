import { readFileSync } from 'node:fs'
import { parse } from 'yaml'
import type { PatternDefinition, Validator } from '../types.js'

/**
 * Schema for YAML pattern definitions
 */
interface YAMLPattern {
  id: string
  name: string
  description?: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  pattern: string
  flags?: string
  keywords?: string[]
  validators?: Array<{
    type: 'entropy' | 'luhn' | 'checksum' | 'length' | 'custom'
    min?: number
    max?: number
    algorithm?: string
    fn?: string
  }>
  examples?: {
    positive?: string[]
    negative?: string[]
  }
}

interface YAMLPatternFile {
  patterns: YAMLPattern[]
}

/**
 * Load patterns from a YAML file
 * @param filePath - Path to YAML file containing pattern definitions
 * @returns Array of PatternDefinition objects
 * @throws Error if file cannot be read or parsed
 */
export function loadPatternsFromYAML(filePath: string): PatternDefinition[] {
  try {
    const fileContent = readFileSync(filePath, 'utf-8')
    const data = parse(fileContent) as YAMLPatternFile

    if (!data || !Array.isArray(data.patterns)) {
      throw new Error('YAML file must contain a "patterns" array')
    }

    return data.patterns.map((p) => convertYAMLPattern(p))
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to load patterns from ${filePath}: ${error.message}`)
    }
    throw error
  }
}

/**
 * Load patterns from a YAML string
 * @param yamlString - YAML string containing pattern definitions
 * @returns Array of PatternDefinition objects
 * @throws Error if YAML cannot be parsed
 */
export function loadPatternsFromYAMLString(yamlString: string): PatternDefinition[] {
  try {
    const data = parse(yamlString) as YAMLPatternFile

    if (!data || !Array.isArray(data.patterns)) {
      throw new Error('YAML must contain a "patterns" array')
    }

    return data.patterns.map((p) => convertYAMLPattern(p))
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to parse YAML patterns: ${error.message}`)
    }
    throw error
  }
}

/**
 * Convert YAML pattern to PatternDefinition
 */
function convertYAMLPattern(yamlPattern: YAMLPattern): PatternDefinition {
  // Validate required fields
  if (!yamlPattern.id || typeof yamlPattern.id !== 'string') {
    throw new Error('Pattern must have a string "id" field')
  }
  if (!yamlPattern.name || typeof yamlPattern.name !== 'string') {
    throw new Error(`Pattern ${yamlPattern.id} must have a string "name" field`)
  }
  if (!yamlPattern.severity || !['critical', 'high', 'medium', 'low'].includes(yamlPattern.severity)) {
    throw new Error(
      `Pattern ${yamlPattern.id} must have a severity of "critical", "high", "medium", or "low"`
    )
  }
  if (!yamlPattern.pattern || typeof yamlPattern.pattern !== 'string') {
    throw new Error(`Pattern ${yamlPattern.id} must have a string "pattern" field`)
  }

  // Create RegExp from pattern string
  let regex: RegExp
  try {
    const flags = yamlPattern.flags || 'g'
    regex = new RegExp(yamlPattern.pattern, flags)
  } catch (error) {
    throw new Error(
      `Pattern ${yamlPattern.id} has invalid regex: ${error instanceof Error ? error.message : 'unknown error'}`
    )
  }

  // Convert validators (skip custom validators from YAML for security)
  const validators: Validator[] = []
  if (yamlPattern.validators) {
    for (const v of yamlPattern.validators) {
      if (v.type === 'custom') {
        console.warn(
          `Skipping custom validator for pattern ${yamlPattern.id}: custom validators cannot be loaded from YAML for security reasons`
        )
        continue
      }

      validators.push({
        type: v.type,
        min: v.min,
        max: v.max,
        algorithm: v.algorithm,
      } as Validator)
    }
  }

  return {
    id: yamlPattern.id,
    name: yamlPattern.name,
    description: yamlPattern.description || '',
    severity: yamlPattern.severity,
    pattern: regex,
    keywords: yamlPattern.keywords || [],
    validators,
    examples: yamlPattern.examples ? {
      positive: yamlPattern.examples.positive || [],
      negative: yamlPattern.examples.negative || []
    } : { positive: [], negative: [] },
  }
}

/**
 * Export patterns to YAML string
 * @param patterns - Array of PatternDefinition objects to export
 * @returns YAML string representation
 */
export function exportPatternsToYAML(patterns: PatternDefinition[]): string {
  const yamlPatterns = patterns.map((p) => {
    const pattern = typeof p.pattern === 'string' ? p.pattern : p.pattern.source
    const flags = typeof p.pattern === 'string' ? 'g' : p.pattern.flags

    return {
      id: p.id,
      name: p.name,
      description: p.description,
      severity: p.severity as 'critical' | 'high' | 'medium' | 'low',
      pattern,
      flags,
      keywords: p.keywords,
      validators: p.validators?.map((v) => {
        const base: any = { type: v.type }
        if ('min' in v && v.min !== undefined) base.min = v.min
        if ('max' in v && v.max !== undefined) base.max = v.max
        if ('algorithm' in v && v.algorithm !== undefined) base.algorithm = v.algorithm
        return base
      }),
      examples: p.examples,
    }
  })

  const data = { patterns: yamlPatterns }
  
  // Use yaml.stringify for clean output
  return `# DLP Pattern Definitions
# Generated: ${new Date().toISOString()}
patterns:
${yamlPatterns.map((p) => `  - id: ${p.id}
    name: ${p.name}
    description: ${p.description || ''}
    severity: ${p.severity}
    pattern: ${JSON.stringify(p.pattern)}
    flags: ${p.flags}${p.keywords && p.keywords.length > 0 ? `\n    keywords: [${p.keywords.join(', ')}]` : ''}${p.validators && p.validators.length > 0 ? `\n    validators:${p.validators.map((v: any) => `\n      - type: ${v.type}${v.min !== undefined ? `\n        min: ${v.min}` : ''}${v.max !== undefined ? `\n        max: ${v.max}` : ''}${v.algorithm ? `\n        algorithm: ${v.algorithm}` : ''}`).join('')}` : ''}`).join('\n\n')}`
}
