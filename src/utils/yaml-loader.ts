import { readFileSync } from 'node:fs'
import { parse } from 'yaml'
import safeRegex from 'safe-regex2'
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
    const data = parse(fileContent, { maxAliasCount: 0 }) as YAMLPatternFile

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
    const data = parse(yamlString, { maxAliasCount: 0 }) as YAMLPatternFile

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
  if (
    !yamlPattern.severity ||
    !['critical', 'high', 'medium', 'low'].includes(yamlPattern.severity)
  ) {
    throw new Error(
      `Pattern ${yamlPattern.id} must have a severity of "critical", "high", "medium", or "low"`,
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
      `Pattern ${yamlPattern.id} has invalid regex: ${error instanceof Error ? error.message : 'unknown error'}`,
    )
  }

  if (!safeRegex(regex)) {
    throw new Error(`Pattern ${yamlPattern.id} has an unsafe regex (possible ReDoS risk)`)
  }

  // Convert validators (skip custom validators from YAML for security)
  const validators: Validator[] = []
  if (yamlPattern.validators) {
    for (const v of yamlPattern.validators) {
      if (v.type === 'custom') {
        console.warn(
          `Skipping custom validator for pattern ${yamlPattern.id}: custom validators cannot be loaded from YAML for security reasons`,
        )
        continue
      }

      if (v.type === 'entropy') {
        if (typeof v.min !== 'number') {
          throw new Error(`Entropy validator for pattern ${yamlPattern.id} must include "min"`)
        }
        validators.push({ type: 'entropy', min: v.min })
        continue
      }

      if (v.type === 'length') {
        const lengthValidator: { type: 'length'; min?: number; max?: number } = {
          type: 'length',
        }
        if (typeof v.min === 'number') lengthValidator.min = v.min
        if (typeof v.max === 'number') lengthValidator.max = v.max
        validators.push(lengthValidator)
        continue
      }

      if (v.type === 'checksum') {
        if (!v.algorithm || typeof v.algorithm !== 'string') {
          throw new Error(
            `Checksum validator for pattern ${yamlPattern.id} must include "algorithm"`,
          )
        }
        validators.push({ type: 'checksum', algorithm: v.algorithm })
        continue
      }

      if (v.type === 'luhn') {
        validators.push({ type: 'luhn' })
        continue
      }
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
    examples: yamlPattern.examples
      ? {
          positive: yamlPattern.examples.positive || [],
          negative: yamlPattern.examples.negative || [],
        }
      : { positive: [], negative: [] },
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
        const base: { type: string; min?: number; max?: number; algorithm?: string } = {
          type: v.type,
        }
        if ('min' in v && v.min !== undefined) base.min = v.min
        if ('max' in v && v.max !== undefined) base.max = v.max
        if ('algorithm' in v && v.algorithm !== undefined) base.algorithm = v.algorithm
        return base
      }),
      examples: p.examples,
    }
  })

  const formatValidator = (validator: {
    type: string
    min?: number
    max?: number
    algorithm?: string
  }): string => {
    return [
      `      - type: ${validator.type}`,
      validator.min !== undefined ? `        min: ${validator.min}` : null,
      validator.max !== undefined ? `        max: ${validator.max}` : null,
      validator.algorithm ? `        algorithm: ${validator.algorithm}` : null,
    ]
      .filter((line): line is string => Boolean(line))
      .join('\n')
  }

  type YamlPatternExport = (typeof yamlPatterns)[number]

  const formatPattern = (p: YamlPatternExport): string => {
    const keywordsLine =
      p.keywords && p.keywords.length > 0 ? `\n    keywords: [${p.keywords.join(', ')}]` : ''
    const validatorsBlock =
      p.validators && p.validators.length > 0
        ? `\n    validators:\n${p.validators.map(formatValidator).join('\n')}`
        : ''

    return `  - id: ${p.id}
    name: ${p.name}
    description: ${p.description || ''}
    severity: ${p.severity}
    pattern: ${JSON.stringify(p.pattern)}
    flags: ${p.flags}${keywordsLine}${validatorsBlock}`
  }

  // Use yaml.stringify for clean output
  return `# DLP Pattern Definitions
# Generated: ${new Date().toISOString()}
patterns:
${yamlPatterns.map(formatPattern).join('\n\n')}`
}
