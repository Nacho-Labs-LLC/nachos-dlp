import type { PatternDefinition } from '../types.js'

export const chatPlatformPatterns: PatternDefinition[] = [
  // Telegram
  {
    id: 'telegram-bot-token',
    name: 'Telegram Bot Token',
    description: 'Telegram Bot API token (numeric bot ID + alphanumeric secret)',
    severity: 'high',
    pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g,
    keywords: ['telegram', 'bot', 'token', 'api'],
    validators: [{ type: 'entropy', min: 3.5 }],
    examples: {
      positive: ['1234567890:ABCDefGHIJKlmNOPQrsTUVwxyz_1234567'],
      negative: [],
    },
  },

  // WhatsApp
  {
    id: 'whatsapp-webhook-verify-token',
    name: 'WhatsApp Webhook Verify Token',
    description: 'WhatsApp Business API webhook verification token',
    severity: 'medium',
    pattern: /(?:WHATSAPP_VERIFY_TOKEN|whatsapp.*verify.*token)\s*[:=]\s*["']?([^\s"']{8,})["']?/gi,
    keywords: ['whatsapp', 'webhook', 'verify', 'token'],
    validators: [],
    examples: {
      positive: ['WHATSAPP_VERIFY_TOKEN=my_secret_token_123'],
      negative: [],
    },
  },
  {
    id: 'whatsapp-api-token',
    name: 'WhatsApp Business API Token',
    description: 'Meta WhatsApp Business API bearer token',
    severity: 'high',
    pattern: /EAA[A-Za-z0-9]{50,}/g,
    keywords: ['whatsapp', 'meta', 'facebook', 'api', 'token', 'business'],
    validators: [{ type: 'entropy', min: 4.0 }],
    examples: {
      positive: [],
      negative: [],
    },
  },
  {
    id: 'whatsapp-app-secret',
    name: 'WhatsApp App Secret',
    description: 'Meta/WhatsApp application secret for webhook signature verification',
    severity: 'critical',
    pattern: /(?:WHATSAPP_APP_SECRET|app.?secret)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
    keywords: ['whatsapp', 'app', 'secret', 'meta', 'facebook'],
    validators: [],
    examples: {
      positive: ['WHATSAPP_APP_SECRET=abcdef1234567890abcdef1234567890'],
      negative: [],
    },
  },

  // Line Messaging
  {
    id: 'line-channel-access-token',
    name: 'Line Channel Access Token',
    description: 'Line Messaging API channel access token',
    severity: 'high',
    pattern: /[A-Za-z0-9+/=]{172}/g,
    keywords: ['line', 'channel', 'access', 'token', 'messaging'],
    validators: [{ type: 'entropy', min: 5.0 }],
    examples: {
      positive: [],
      negative: [],
    },
  },

  // Matrix
  {
    id: 'matrix-access-token',
    name: 'Matrix Access Token',
    description: 'Matrix homeserver access token',
    severity: 'high',
    pattern: /syt_[A-Za-z0-9_]{40,}/g,
    keywords: ['matrix', 'access', 'token', 'homeserver'],
    validators: [{ type: 'entropy', min: 4.0 }],
    examples: {
      positive: [],
      negative: [],
    },
  },
]
