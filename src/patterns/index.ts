import type { PatternDefinition } from '../types.js'

// Pattern collections - to be implemented
export const awsPatterns: PatternDefinition[] = []
export const apiKeyPatterns: PatternDefinition[] = []
export const privateKeyPatterns: PatternDefinition[] = []
export const piiPatterns: PatternDefinition[] = []

export const patterns: PatternDefinition[] = [
  ...awsPatterns,
  ...apiKeyPatterns,
  ...privateKeyPatterns,
  ...piiPatterns,
]
