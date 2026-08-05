// Core scanner
export { Scanner, ScanAbortedError, type ScanResult } from './scanner.js'

// Types
export type {
  ScannerConfig,
  ScanOptions,
  Finding,
  Severity,
  PatternMatch,
  PatternDefinition,
  Validator,
} from './types.js'

// Pattern collections
export {
  patterns,
  awsPatterns,
  apiKeyPatterns,
  privateKeyPatterns,
  piiPatterns,
  patternCategories,
  getPatternById,
  getPatternsByCategory,
  getPatternsBySeverity,
  type PatternCategory,
} from './patterns/index.js'

// Redaction utilities
export {
  redact,
  redactMatch,
  redactWithPatterns,
  summarizeFindings,
  formatReport,
  type RedactOptions,
} from './utils/redact.js'

// Portable YAML utilities (no Node.js fs dependency)
export { loadPatternsFromYAMLString, exportPatternsToYAML } from './utils/yaml-shared.js'

// Validators
export {
  calculateEntropy,
  validateLuhn,
  validateLength,
  validateChecksum,
  runValidator,
  runValidators,
  calculateConfidence,
} from './validators/index.js'
