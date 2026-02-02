import type { PatternDefinition } from '../types.js'

export const awsPatterns: PatternDefinition[] = [
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    description: 'AWS Access Key ID used for programmatic access',
    severity: 'critical',
    pattern: /(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])/g,
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

  // GCP Patterns
  {
    id: 'gcp-api-key',
    name: 'Google Cloud API Key',
    description: 'Google Cloud Platform API key',
    severity: 'high',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    keywords: ['google', 'gcp', 'api', 'key', 'cloud'],
    validators: [{ type: 'entropy', min: 4.0 }],
    examples: {
      positive: ['AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe'],
      negative: [],
    },
  },
  {
    id: 'gcp-service-account',
    name: 'Google Cloud Service Account',
    description: 'GCP service account email pattern',
    severity: 'medium',
    pattern: /[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com/gi,
    keywords: ['service', 'account', 'gcp', 'google', 'iam'],
    validators: [],
    examples: {
      positive: ['my-service@my-project.iam.gserviceaccount.com'],
      negative: [],
    },
  },
  {
    id: 'gcp-oauth-token',
    name: 'Google OAuth Token',
    description: 'Google OAuth access token',
    severity: 'high',
    pattern: /ya29\.[0-9A-Za-z\-_]+/g,
    keywords: ['google', 'oauth', 'token', 'access'],
    validators: [{ type: 'entropy', min: 4.0 }],
    examples: {
      positive: ['ya29.a0AfB_byC1234567890abcdefghijklmnop'],
      negative: [],
    },
  },

  // Azure Patterns
  {
    id: 'azure-storage-key',
    name: 'Azure Storage Account Key',
    description: 'Microsoft Azure storage account access key',
    severity: 'critical',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{86}==(?![A-Za-z0-9/+=])/g,
    keywords: ['azure', 'storage', 'account', 'key', 'microsoft'],
    validators: [{ type: 'entropy', min: 5.0 }],
    examples: {
      positive: [],
      negative: [],
    },
  },
  {
    id: 'azure-connection-string',
    name: 'Azure Connection String',
    description: 'Azure service connection string',
    severity: 'critical',
    pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]+;?/gi,
    keywords: ['azure', 'connection', 'string', 'endpoint'],
    validators: [],
    examples: {
      positive: ['DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123=='],
      negative: [],
    },
  },
  {
    id: 'azure-client-secret',
    name: 'Azure AD Client Secret',
    description: 'Azure Active Directory application client secret',
    severity: 'critical',
    pattern: /[a-zA-Z0-9~_.-]{34,40}/g,
    keywords: ['azure', 'client', 'secret', 'ad', 'active', 'directory'],
    validators: [{ type: 'entropy', min: 4.5 }],
    falsePositives: [/^[a-z]+$/i, /^[0-9]+$/],
    examples: {
      positive: [],
      negative: [],
    },
  },
  {
    id: 'azure-sas-token',
    name: 'Azure SAS Token',
    description: 'Azure Shared Access Signature token',
    severity: 'high',
    pattern: /[?&]sig=[A-Za-z0-9%]+(&|$)/g,
    keywords: ['azure', 'sas', 'signature', 'token', 'blob'],
    validators: [],
    examples: {
      positive: ['?sv=2020-08-04&sig=abc123%3D'],
      negative: [],
    },
  },
]
