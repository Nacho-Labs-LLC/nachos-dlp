import type { PatternDefinition } from '../types.js'

export const gcpPatterns: PatternDefinition[] = [
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
  {
    id: 'gcp-service-account-key-json',
    name: 'GCP Service Account Key (JSON)',
    description: 'Google Cloud service account private key embedded in JSON',
    severity: 'critical',
    pattern: /"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/g,
    keywords: ['private_key', 'service_account', 'gcp', 'google', 'json'],
    validators: [],
    examples: {
      positive: ['"private_key": "-----BEGIN RSA PRIVATE KEY-----'],
      negative: [],
    },
  },
  {
    id: 'gcp-oauth-client-secret',
    name: 'GCP OAuth Client Secret',
    description: 'Google OAuth client secret from credentials JSON',
    severity: 'high',
    pattern: /"client_secret"\s*:\s*"[A-Za-z0-9_-]{24,}"/g,
    keywords: ['client_secret', 'oauth', 'google', 'gcp'],
    validators: [],
    examples: {
      positive: ['"client_secret": "GOCSPX-abcdefghijklmnopqrstuvwx"'],
      negative: [],
    },
  },
  {
    id: 'gcp-firebase-key',
    name: 'Firebase API Key',
    description: 'Firebase / Google Cloud project API key',
    severity: 'high',
    pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
    keywords: ['firebase', 'fcm', 'push', 'notification', 'google'],
    validators: [{ type: 'entropy', min: 4.0 }],
    examples: {
      positive: [],
      negative: [],
    },
  },
]
