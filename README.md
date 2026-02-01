# @nachos/dlp

TypeScript DLP (Data Loss Prevention) scanning library for detecting secrets, API keys, and sensitive data in text.

## Features

- **Fast**: Pure TypeScript regex-based scanning
- **Accurate**: Patterns sourced from detect-secrets and gitleaks
- **Extensible**: Add custom patterns via YAML or code
- **Framework-agnostic**: Works in Node.js, browsers, and edge runtimes

## Installation

```bash
npm install @nachos/dlp
# or
pnpm add @nachos/dlp
```

## Quick Start

```typescript
import { Scanner } from '@nachos/dlp'

const scanner = new Scanner()
const findings = scanner.scan(text)

if (findings.length > 0) {
  console.log('Secrets detected:', findings)
}
```

## Supported Patterns

- AWS credentials (Access Key ID, Secret Access Key)
- GCP/Azure credentials
- API keys (OpenAI, Anthropic, GitHub, Slack, Stripe, etc.)
- Private keys (RSA, SSH, PGP)
- PII (SSN, credit cards)
- Generic high-entropy secrets

## Custom Patterns

```typescript
scanner.addPattern({
  id: 'my-api-key',
  name: 'My API Key',
  severity: 'critical',
  pattern: /myapp_[a-z0-9]{32}/,
  keywords: ['myapp_']
})
```

Or via YAML:

```yaml
patterns:
  - id: my-api-key
    name: My API Key
    severity: critical
    pattern: "myapp_[a-z0-9]{32}"
    keywords: ["myapp_"]
```

## API

### Scanner

```typescript
const scanner = new Scanner(config?)
scanner.scan(text): Finding[]
scanner.addPattern(pattern): void
```

### Finding

```typescript
interface Finding {
  patternId: string
  patternName: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  match: string
  redacted: string
  line?: number
  column?: number
  confidence: number
}
```

## License

MIT
