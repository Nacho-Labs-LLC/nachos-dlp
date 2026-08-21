import { readFileSync } from 'node:fs'
import type { PatternDefinition } from '../types.js'
import { loadPatternsFromYAMLString } from './yaml-shared.js'

/**
 * Load patterns from a YAML file
 * @param filePath - Path to YAML file containing pattern definitions
 * @returns Array of PatternDefinition objects
 * @throws Error if file cannot be read or parsed
 */
export function loadPatternsFromYAML(filePath: string): PatternDefinition[] {
  try {
    return loadPatternsFromYAMLString(readFileSync(filePath, 'utf-8'))
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to load patterns from ${filePath}: ${error.message}`, {
        cause: error,
      })
    }
    throw error
  }
}

export { loadPatternsFromYAMLString, exportPatternsToYAML } from './yaml-shared.js'
