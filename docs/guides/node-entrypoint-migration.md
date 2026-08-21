# Migrate to the Node Entrypoint

This package now splits its public API into:

- `@nacho-labs/nachos-dlp` for the portable scanner and in-memory helpers
- `@nacho-labs/nachos-dlp/node` for file-backed YAML loading and `NodeScanner`

## What Changed

- Root `ScannerConfig` no longer includes `customPatternFiles`.
- Root exports no longer include `loadPatternsFromYAML()`.
- Node consumers should import `NodeScanner` and file-backed YAML helpers from `@nacho-labs/nachos-dlp/node`.

## Before and After

### File-backed YAML from the root entrypoint

Before:

```ts
import { Scanner, loadPatternsFromYAML } from '@nacho-labs/nachos-dlp'

const scanner = new Scanner({
  customPatternFiles: ['./patterns.internal.yaml'],
})

const patterns = loadPatternsFromYAML('./patterns.internal.yaml')
```

After:

```ts
import { NodeScanner, loadPatternsFromYAML } from '@nacho-labs/nachos-dlp/node'

const scanner = new NodeScanner({
  customPatternFiles: ['./patterns.internal.yaml'],
})

const patterns = loadPatternsFromYAML('./patterns.internal.yaml')
```

### YAML already loaded into memory

If another part of your app already fetched or bundled the YAML text, stay on the portable root entrypoint:

```ts
import { Scanner, loadPatternsFromYAMLString } from '@nacho-labs/nachos-dlp'

const customPatterns = loadPatternsFromYAMLString(yamlText)
const scanner = new Scanner({ customPatterns })
```

### Updating long-lived scanners

Before:

```ts
scanner.updateConfig({ customPatternFiles: ['./next-rules.yaml'] })
```

After:

```ts
nodeScanner.updateConfig({ customPatternFiles: ['./next-rules.yaml'] })
```

## Choosing the Right Entrypoint

Use `@nacho-labs/nachos-dlp` when:

- you are scanning text with built-in patterns
- you define `customPatterns` in code
- you already have YAML content in memory and want `loadPatternsFromYAMLString()`

Use `@nacho-labs/nachos-dlp/node` when:

- you need to read YAML pattern files from disk
- you want `NodeScanner`
- you want `loadPatternsFromYAML(filePath)`

## Release Note Copy

Breaking change: file-backed YAML loading moved off the portable root entrypoint. `ScannerConfig` on `@nacho-labs/nachos-dlp` no longer accepts `customPatternFiles`, and `loadPatternsFromYAML()` now lives under `@nacho-labs/nachos-dlp/node` alongside `NodeScanner`. In-memory usage of `Scanner` and `loadPatternsFromYAMLString()` stays on the root entrypoint.
