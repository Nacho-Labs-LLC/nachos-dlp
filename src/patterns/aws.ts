import type { PatternDefinition } from '../types.js'

export const awsPatterns: PatternDefinition[] = [
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    description: 'AWS Access Key ID used for programmatic access',
    severity: 'critical',
    pattern:
      /(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])/g,
    keywords: ['aws', 'amazon', 'access', 'key', 'akia', 'credential'],
    validators: [
      { type: 'length', min: 20, max: 20 },
      { type: 'entropy', min: 3.0 },
    ],
    examples: {
      positive: ['AKIAIOSFODNN7EXAMPLE', 'ASIAJEXAMPLEKEY12345'],
      negative: ['AKIANOTAREALKEY', 'not-an-aws-key'],
    },
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    description: 'AWS Secret Access Key for authentication',
    severity: 'critical',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    keywords: ['aws', 'secret', 'access', 'key', 'credential', 'amazon'],
    validators: [
      { type: 'length', min: 40, max: 40 },
      { type: 'entropy', min: 4.5 },
    ],
    examples: {
      positive: ['wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
      negative: ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
    },
  },
  {
    id: 'aws-session-token',
    name: 'AWS Session Token',
    description: 'AWS temporary session token for STS credentials',
    severity: 'critical',
    pattern: /(?<![A-Za-z0-9/+=])FwoGZXIvYXdzE[A-Za-z0-9/+=]{200,1000}(?![A-Za-z0-9/+=])/g,
    keywords: ['aws', 'session', 'token', 'sts', 'temporary'],
    validators: [{ type: 'entropy', min: 4.0 }],
    examples: {
      positive: [],
      negative: [],
    },
  },
  {
    id: 'aws-mws-key',
    name: 'AWS MWS Key',
    description: 'Amazon Marketplace Web Service authentication key',
    severity: 'high',
    pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    keywords: ['mws', 'marketplace', 'amazon', 'merchant'],
    validators: [],
    examples: {
      positive: ['amzn.mws.12345678-1234-1234-1234-123456789012'],
      negative: [],
    },
  },
  {
    id: 'aws-cognito-pool-id',
    name: 'AWS Cognito Pool ID',
    description: 'Amazon Cognito Identity Pool ID',
    severity: 'medium',
    pattern: /[a-z]{2}-[a-z]+-\d:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi,
    keywords: ['cognito', 'pool', 'identity', 'aws'],
    validators: [],
    examples: {
      positive: ['us-east-1:12345678-1234-1234-1234-123456789012'],
      negative: [],
    },
  },
]
