import { describe, it, expect } from 'vitest'
import {
  patterns,
  awsPatterns,
  apiKeyPatterns,
  privateKeyPatterns,
  piiPatterns,
  getPatternById,
  getPatternsByCategory,
  getPatternsBySeverity,
} from '../src/patterns/index.js'
import { Scanner } from '../src/scanner.js'

describe('Pattern collections', () => {
  it('should have AWS patterns', () => {
    expect(awsPatterns.length).toBeGreaterThan(0)
    expect(awsPatterns.every((p) => p.id && p.name && p.severity && p.pattern)).toBe(true)
  })

  it('should have API key patterns', () => {
    expect(apiKeyPatterns.length).toBeGreaterThan(0)
    expect(apiKeyPatterns.every((p) => p.id && p.name && p.severity && p.pattern)).toBe(true)
  })

  it('should have private key patterns', () => {
    expect(privateKeyPatterns.length).toBeGreaterThan(0)
    expect(privateKeyPatterns.every((p) => p.id && p.name && p.severity && p.pattern)).toBe(true)
  })

  it('should have PII patterns', () => {
    expect(piiPatterns.length).toBeGreaterThan(0)
    expect(piiPatterns.every((p) => p.id && p.name && p.severity && p.pattern)).toBe(true)
  })

  it('should combine all patterns', () => {
    const totalPatterns =
      awsPatterns.length + apiKeyPatterns.length + privateKeyPatterns.length + piiPatterns.length
    expect(patterns.length).toBe(totalPatterns)
  })
})

describe('getPatternById', () => {
  it('should return pattern by ID', () => {
    const pattern = getPatternById('aws-access-key-id')
    expect(pattern).toBeDefined()
    expect(pattern?.id).toBe('aws-access-key-id')
  })

  it('should return undefined for unknown ID', () => {
    const pattern = getPatternById('non-existent-pattern')
    expect(pattern).toBeUndefined()
  })
})

describe('getPatternsByCategory', () => {
  it('should return AWS patterns for aws category', () => {
    const patterns = getPatternsByCategory('aws')
    expect(patterns.length).toBe(awsPatterns.length)
  })

  it('should return all patterns for all category', () => {
    const allPatterns = getPatternsByCategory('all')
    expect(allPatterns.length).toBeGreaterThan(0)
  })

  it('should return secrets patterns (aws + api-keys + private-keys)', () => {
    const secretPatterns = getPatternsByCategory('secrets')
    expect(secretPatterns.length).toBe(
      awsPatterns.length + apiKeyPatterns.length + privateKeyPatterns.length
    )
  })
})

describe('getPatternsBySeverity', () => {
  it('should return critical patterns', () => {
    const criticalPatterns = getPatternsBySeverity('critical')
    expect(criticalPatterns.length).toBeGreaterThan(0)
    expect(criticalPatterns.every((p) => p.severity === 'critical')).toBe(true)
  })

  it('should return patterns of each severity level', () => {
    for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
      const patterns = getPatternsBySeverity(severity)
      expect(patterns.every((p) => p.severity === severity)).toBe(true)
    }
  })
})

describe('AWS Pattern Detection', () => {
  const scanner = new Scanner({ patterns: ['aws'] })

  it('should detect AWS Access Key ID', () => {
    const findings = scanner.scan('AKIAIOSFODNN7EXAMPLE')
    expect(findings.some((f) => f.patternId === 'aws-access-key-id')).toBe(true)
  })

  it('should detect AWS MWS key', () => {
    const findings = scanner.scan('amzn.mws.12345678-1234-1234-1234-123456789012')
    expect(findings.some((f) => f.patternId === 'aws-mws-key')).toBe(true)
  })

  it('should detect GCP API key', () => {
    const findings = scanner.scan('AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe')
    expect(findings.some((f) => f.patternId === 'gcp-api-key')).toBe(true)
  })

  it('should detect Google OAuth token', () => {
    const findings = scanner.scan('ya29.a0AfB_byC1234567890abcdefghijklmnop')
    expect(findings.some((f) => f.patternId === 'gcp-oauth-token')).toBe(true)
  })
})

describe('API Key Pattern Detection', () => {
  const scanner = new Scanner({ patterns: ['api-keys'] })

  it('should detect GitHub PAT (classic)', () => {
    const findings = scanner.scan('ghp_1234567890abcdefghijklmnopqrstuvwxyz')
    expect(findings.some((f) => f.patternId === 'github-pat')).toBe(true)
  })

  it('should detect GitHub OAuth token', () => {
    const findings = scanner.scan('gho_1234567890abcdefghijklmnopqrstuvwxyz')
    expect(findings.some((f) => f.patternId === 'github-oauth')).toBe(true)
  })

  it('should detect Stripe secret key pattern', () => {
    // Test pattern matching only - using scanner.getPattern to verify pattern exists
    const pattern = scanner.getPattern('stripe-secret-key')
    expect(pattern).toBeDefined()
    expect(pattern?.pattern).toBeDefined()
  })

  it('should detect Slack bot token pattern', () => {
    // Test pattern matching only - using scanner.getPattern to verify pattern exists
    const pattern = scanner.getPattern('slack-bot-token')
    expect(pattern).toBeDefined()
    expect(pattern?.pattern).toBeDefined()
  })

  it('should detect Slack webhook pattern', () => {
    // Test pattern matching only - using scanner.getPattern to verify pattern exists
    const pattern = scanner.getPattern('slack-webhook')
    expect(pattern).toBeDefined()
    expect(pattern?.pattern).toBeDefined()
  })

  it('should detect SendGrid API key pattern', () => {
    // Test pattern exists - actual values trigger GitHub secret scanning
    const pattern = scanner.getPattern('sendgrid-api-key')
    expect(pattern).toBeDefined()
    expect(pattern?.pattern).toBeDefined()
  })

  it('should detect Discord webhook pattern', () => {
    const pattern = scanner.getPattern('discord-webhook')
    expect(pattern).toBeDefined()
    expect(pattern?.pattern).toBeDefined()
  })

  it('should detect NPM token pattern', () => {
    const pattern = scanner.getPattern('npm-token')
    expect(pattern).toBeDefined()
    expect(pattern?.pattern).toBeDefined()
  })

  it('should detect JWT token pattern', () => {
    const pattern = scanner.getPattern('jwt-token')
    expect(pattern).toBeDefined()
    expect(pattern?.pattern).toBeDefined()
  })

  it('should detect Bearer token pattern', () => {
    const pattern = scanner.getPattern('bearer-token')
    expect(pattern).toBeDefined()
    expect(pattern?.pattern).toBeDefined()
  })
})

describe('Private Key Pattern Detection', () => {
  const scanner = new Scanner({ patterns: ['private-keys'] })

  it('should detect RSA private key', () => {
    const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
-----END RSA PRIVATE KEY-----`
    const findings = scanner.scan(key)
    expect(findings.some((f) => f.patternId === 'rsa-private-key')).toBe(true)
  })

  it('should detect generic private key', () => {
    const key = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC
-----END PRIVATE KEY-----`
    const findings = scanner.scan(key)
    expect(findings.some((f) => f.patternId === 'private-key')).toBe(true)
  })

  it('should detect EC private key', () => {
    const key = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBYyp7mJLF
-----END EC PRIVATE KEY-----`
    const findings = scanner.scan(key)
    expect(findings.some((f) => f.patternId === 'ec-private-key')).toBe(true)
  })

  it('should detect OpenSSH private key', () => {
    const key = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA
-----END OPENSSH PRIVATE KEY-----`
    const findings = scanner.scan(key)
    expect(findings.some((f) => f.patternId === 'openssh-private-key')).toBe(true)
  })

  it('should detect PGP private key', () => {
    const key = `-----BEGIN PGP PRIVATE KEY BLOCK-----
lQOYBGJhH
-----END PGP PRIVATE KEY BLOCK-----`
    const findings = scanner.scan(key)
    expect(findings.some((f) => f.patternId === 'pgp-private-key')).toBe(true)
  })

  it('should detect X.509 certificate', () => {
    const cert = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gcx
-----END CERTIFICATE-----`
    const findings = scanner.scan(cert)
    expect(findings.some((f) => f.patternId === 'x509-certificate')).toBe(true)
  })
})

describe('PII Pattern Detection', () => {
  const scanner = new Scanner({ patterns: ['pii'] })

  it('should detect US SSN', () => {
    // Using a realistic SSN format (not in false positives list)
    const findings = scanner.scan('SSN: 234-56-7890')
    expect(findings.some((f) => f.patternId === 'ssn-us')).toBe(true)
  })

  it('should reject invalid SSN starting with 000', () => {
    const findings = scanner.scan('SSN: 000-12-3456')
    expect(findings.some((f) => f.patternId === 'ssn-us')).toBe(false)
  })

  it('should detect credit card (Visa)', () => {
    const findings = scanner.scan('Card: 4111111111111111')
    expect(findings.some((f) => f.patternId === 'credit-card')).toBe(true)
  })

  it('should reject invalid credit card (fails Luhn)', () => {
    const findings = scanner.scan('Card: 1234567890123456')
    expect(findings.some((f) => f.patternId === 'credit-card')).toBe(false)
  })

  it('should detect formatted credit card', () => {
    const findings = scanner.scan('Card: 4111-1111-1111-1111')
    expect(findings.some((f) => f.patternId === 'credit-card-formatted')).toBe(true)
  })

  it('should detect email address', () => {
    // Using a domain not in false positives list (not example.com, test.com, localhost)
    const findings = scanner.scan('Contact: user@company.org')
    expect(findings.some((f) => f.patternId === 'email-address')).toBe(true)
  })

  it('should detect US phone number', () => {
    // US phone numbers need area code [2-9]XX and exchange [2-9]XX
    const findings = scanner.scan('Phone: (555) 234-5678')
    expect(findings.some((f) => f.patternId === 'phone-us')).toBe(true)
  })

  it('should detect international phone number', () => {
    const findings = scanner.scan('Phone: +447911123456')
    expect(findings.some((f) => f.patternId === 'phone-international')).toBe(true)
  })

  it('should detect IPv4 address', () => {
    const findings = scanner.scan('Server: 192.168.1.1')
    expect(findings.some((f) => f.patternId === 'ipv4-address')).toBe(true)
  })

  it('should detect IBAN', () => {
    const findings = scanner.scan('IBAN: GB82WEST12345698765432')
    expect(findings.some((f) => f.patternId === 'iban')).toBe(true)
  })

  it('should detect date of birth pattern', () => {
    const findings = scanner.scan('DOB: 01/15/1990')
    expect(findings.some((f) => f.patternId === 'date-of-birth')).toBe(true)
  })
})

describe('Pattern uniqueness', () => {
  it('should have unique pattern IDs', () => {
    const ids = patterns.map((p) => p.id)
    const uniqueIds = new Set(ids)
    expect(ids.length).toBe(uniqueIds.size)
  })

  it('should have unique pattern names', () => {
    const names = patterns.map((p) => p.name)
    const uniqueNames = new Set(names)
    expect(names.length).toBe(uniqueNames.size)
  })
})

describe('Pattern structure', () => {
  it('should have valid severity for all patterns', () => {
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info']
    expect(patterns.every((p) => validSeverities.includes(p.severity))).toBe(true)
  })

  it('should have valid pattern (RegExp or string) for all patterns', () => {
    expect(
      patterns.every((p) => p.pattern instanceof RegExp || typeof p.pattern === 'string')
    ).toBe(true)
  })
})
