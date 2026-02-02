# @nachos/dlp

TypeScript DLP (Data Loss Prevention) scanning library for detecting secrets, API keys, and sensitive data in text.

## Features

- **Fast** - Pure TypeScript regex-based scanning
- **Accurate** - Validators (entropy, Luhn, checksums) reduce false positives
- **Comprehensive** - 50+ patterns for secrets, API keys, and PII
- **Extensible** - Add custom patterns via code
- **Framework-agnostic** - Works in Node.js and edge runtimes

## Installation

```bash
npm install @nachos/dlp
# or
pnpm add @nachos/dlp
```

## Development

### Building
```bash
npm run build        # Build the project
npm run dev          # Watch mode for development
```

### Testing
```bash
npm test             # Run tests
npm run test:watch   # Watch mode
npm run test:coverage # Coverage report
```

### Linting & Formatting
```bash
npm run lint         # Lint the code
npm run format       # Format the code
```

### Publishing

#### Version Bumping
```bash
npm run version:patch  # Bump patch version (0.0.1 -> 0.0.2)
npm run version:minor  # Bump minor version (0.0.1 -> 0.1.0)
npm run version:major  # Bump major version (0.0.1 -> 1.0.0)
```

#### Publishing to NPM
```bash
npm run publish:npm    # Publish to NPM (requires npm login)
```

#### Release (Version + Publish)
```bash
npm run release:patch  # Bump patch and publish
npm run release:minor  # Bump minor and publish
npm run release:major  # Bump major and publish
```

**Note:** Make sure you're logged in to npm (`npm login`) before publishing.

## Quick Start

```typescript
import { Scanner, redact } from '@nachos/dlp'

const scanner = new Scanner()
const text = `
  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
  GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
`

const findings = scanner.scan(text)

if (findings.length > 0) {
  console.log('Secrets detected:', findings)

  // Redact sensitive data
  const safeText = redact(text, findings)
  console.log(safeText)
}
```

## Supported Patterns

### Cloud Provider Credentials
- AWS Access Key ID, Secret Access Key, Session Token, MWS Key
- GCP API Key, Service Account, OAuth Token
- Azure Storage Key, Connection String, SAS Token, Client Secret

### API Keys & Tokens
- GitHub (PAT, OAuth, App, Refresh tokens)
- Stripe (Secret, Publishable, Restricted keys)
- Slack (Bot, User tokens, Webhooks)
- Twilio, SendGrid, Mailchimp
- Discord (Bot tokens, Webhooks)
- NPM, PyPI tokens
- Generic JWT, Bearer tokens, Basic Auth

### Private Keys & Certificates
- RSA, EC, DSA private keys
- OpenSSH, PuTTY private keys
- PGP private key blocks
- X.509 certificates
- PKCS#12 references

### PII (Personally Identifiable Information)
- US Social Security Numbers
- Credit card numbers (with Luhn validation)
- Email addresses, Phone numbers
- IP addresses
- IBAN, Bank routing numbers
- Passport numbers, Driver's license patterns

## Configuration

```typescript
import { Scanner } from '@nachos/dlp'

const scanner = new Scanner({
  // Include only specific patterns or categories
  patterns: ['aws', 'api-keys'],  // Categories: 'aws', 'cloud', 'api-keys', 'private-keys', 'pii', 'secrets', 'all'

  // Exclude specific pattern IDs
  exclude: ['email-address', 'ipv4-address'],

  // Minimum confidence threshold (0-1)
  minConfidence: 0.6,

  // Include context lines around findings
  includeContext: true,
  contextLines: 2,

  // Add custom patterns
  customPatterns: [{
    id: 'my-api-key',
    name: 'My API Key',
    severity: 'critical',
    pattern: /myapp_[a-z0-9]{32}/g,
    keywords: ['myapp'],
    validators: [
      { type: 'entropy', min: 4.0 },
      { type: 'length', min: 38, max: 38 }
    ]
  }]
})
```

## API Reference

### Scanner

```typescript
// Create scanner
const scanner = new Scanner(config?)

// Scan text for secrets
const findings = scanner.scan(text)

// Scan with metadata (timing, pattern count)
const result = scanner.scanWithMetadata(text)

// Async scan for large texts
const findings = await scanner.scanAsync(text)

// Quick check (returns boolean)
const hasSecrets = scanner.quickCheck(text)

// Pattern management
scanner.addPattern(pattern)
scanner.removePattern(patternId)
scanner.getPatterns()
scanner.getPattern(patternId)
```

### Redaction

```typescript
import { redact, redactMatch, summarizeFindings, formatReport } from '@nachos/dlp'

// Redact all findings
const safeText = redact(text, findings, {
  replacement: '[REDACTED]',  // Default replacement
  partial: true,               // Show prefix/suffix
  showPrefix: 4,              // Characters to show at start
  showSuffix: 4,              // Characters to show at end
  maskFormat: 'fixed',        // 'fixed' or 'length'
  maskChar: '*'               // Mask character for 'length' format
})

// Redact single value
const redacted = redactMatch('ghp_1234...wxyz', { partial: true })
// => 'ghp_...wxyz'

// Get summary of findings
console.log(summarizeFindings(findings))

// Format detailed report
console.log(formatReport(findings, { showContext: true }))
```

### Validators

```typescript
import {
  calculateEntropy,
  validateLuhn,
  validateLength,
  validateChecksum
} from '@nachos/dlp'

// Shannon entropy
calculateEntropy('wJalrXUtnFEMI/K7MDENG')  // ~4.5

// Luhn algorithm (credit cards)
validateLuhn('4111111111111111')  // true

// Length validation
validateLength('secret', 5, 10)  // true

// Checksum validation
validateChecksum('4111111111111111', 'luhn')  // true
```

### Pattern Access

```typescript
import {
  patterns,
  awsPatterns,
  apiKeyPatterns,
  privateKeyPatterns,
  piiPatterns,
  getPatternById,
  getPatternsByCategory,
  getPatternsBySeverity
} from '@nachos/dlp'

// Get specific pattern
const awsKeyPattern = getPatternById('aws-access-key-id')

// Get patterns by category
const secretPatterns = getPatternsByCategory('secrets')

// Get patterns by severity
const criticalPatterns = getPatternsBySeverity('critical')
```

## Types

```typescript
interface Finding {
  patternId: string
  patternName: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  match: string
  redacted: string
  line?: number
  column?: number
  context?: string
  confidence: number
}

interface PatternDefinition {
  id: string
  name: string
  description?: string
  severity: Severity
  pattern: RegExp | string
  keywords?: string[]
  validators?: Validator[]
  falsePositives?: RegExp[]
}

type Validator =
  | { type: 'entropy'; min: number }
  | { type: 'luhn' }
  | { type: 'checksum'; algorithm: string }
  | { type: 'length'; min?: number; max?: number }
  | { type: 'custom'; fn: (match: string) => boolean }
```

## License

MIT
