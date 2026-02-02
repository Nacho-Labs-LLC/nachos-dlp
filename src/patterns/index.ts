import type { PatternDefinition } from '../types.js'
import { awsPatterns } from './aws.js'
import { apiKeyPatterns } from './api-keys.js'
import { privateKeyPatterns } from './private-keys.js'
import { piiPatterns } from './pii.js'

// Re-export individual pattern collections
export { awsPatterns } from './aws.js'
export { apiKeyPatterns } from './api-keys.js'
export { privateKeyPatterns } from './private-keys.js'
export { piiPatterns } from './pii.js'

// Combined default patterns
export const patterns: PatternDefinition[] = [
  ...awsPatterns,
  ...apiKeyPatterns,
  ...privateKeyPatterns,
  ...piiPatterns,
]

// Pattern categories for filtering
export const patternCategories = {
  aws: awsPatterns.map((p) => p.id),
  cloud: [...awsPatterns.map((p) => p.id)],
  'api-keys': apiKeyPatterns.map((p) => p.id),
  'private-keys': privateKeyPatterns.map((p) => p.id),
  pii: piiPatterns.map((p) => p.id),
  secrets: [
    ...awsPatterns.map((p) => p.id),
    ...apiKeyPatterns.map((p) => p.id),
    ...privateKeyPatterns.map((p) => p.id),
  ],
  all: patterns.map((p) => p.id),
} as const

export type PatternCategory = keyof typeof patternCategories

// Get pattern by ID
export function getPatternById(id: string): PatternDefinition | undefined {
  return patterns.find((p) => p.id === id)
}

// Get patterns by category
export function getPatternsByCategory(category: PatternCategory): PatternDefinition[] {
  const ids = patternCategories[category]
  return patterns.filter((p) => ids.includes(p.id))
}

// Get patterns by severity
export function getPatternsBySeverity(
  severity: PatternDefinition['severity'],
): PatternDefinition[] {
  return patterns.filter((p) => p.severity === severity)
}
