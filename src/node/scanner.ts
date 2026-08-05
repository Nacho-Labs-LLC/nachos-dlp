import { Scanner } from '../scanner.js'
import type { PatternDefinition, ScannerConfig } from '../types.js'
import { loadPatternsFromYAML } from '../utils/yaml-loader.js'

export interface NodeScannerConfig extends ScannerConfig {
  customPatternFiles?: string[]
}

export class NodeScanner extends Scanner {
  private customPatternFiles: string[] | undefined

  constructor(config: NodeScannerConfig = {}) {
    const { customPatternFiles, ...scannerConfig } = config
    super(scannerConfig)
    this.customPatternFiles = customPatternFiles
    this.reloadPatterns()
  }

  protected override getAdditionalPatterns(): PatternDefinition[] {
    const patterns: PatternDefinition[] = []

    for (const file of this.customPatternFiles ?? []) {
      try {
        patterns.push(...loadPatternsFromYAML(file))
      } catch (error) {
        console.error(`Failed to load patterns from ${file}:`, error)
      }
    }

    return patterns
  }

  override updateConfig(config: Partial<ScannerConfig> & { customPatternFiles?: string[] }): void {
    const { customPatternFiles, ...scannerConfig } = config

    super.updateConfig(scannerConfig)

    if (customPatternFiles) {
      this.customPatternFiles = customPatternFiles
    }

    if (
      customPatternFiles ||
      scannerConfig.patterns ||
      scannerConfig.exclude ||
      scannerConfig.customPatterns
    ) {
      this.reloadPatterns()
    }
  }
}
