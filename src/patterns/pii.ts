import type { PatternDefinition } from '../types.js'

export const piiPatterns: PatternDefinition[] = [
  // Social Security Numbers
  {
    id: 'ssn-us',
    name: 'US Social Security Number',
    description: 'US Social Security Number (SSN)',
    severity: 'critical',
    pattern: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
    keywords: ['ssn', 'social', 'security', 'number', 'tax'],
    validators: [
      { type: 'length', min: 9, max: 11 },
      {
        type: 'custom',
        fn: (match: string) => {
          const digits = match.replace(/\D/g, '')
          // SSN cannot start with 000, 666, or 900-999
          const area = parseInt(digits.substring(0, 3), 10)
          if (area === 0 || area === 666 || area >= 900) return false
          // Group cannot be 00
          const group = parseInt(digits.substring(3, 5), 10)
          if (group === 0) return false
          // Serial cannot be 0000
          const serial = parseInt(digits.substring(5), 10)
          if (serial === 0) return false
          return true
        },
      },
    ],
    falsePositives: [/000-00-0000/, /123-45-6789/, /111-11-1111/],
    examples: {
      positive: ['123-45-6789', '123 45 6789', '123456789'],
      negative: ['000-00-0000', '666-12-3456', '900-12-3456'],
    },
  },

  // Credit Card Numbers
  {
    id: 'credit-card',
    name: 'Credit Card Number',
    description: 'Credit card number (Visa, MasterCard, Amex, Discover)',
    severity: 'critical',
    pattern:
      /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
    keywords: ['credit', 'card', 'payment', 'visa', 'mastercard', 'amex'],
    validators: [{ type: 'luhn' }],
    falsePositives: [/^0+$/, /1234567890/],
    examples: {
      positive: ['4111111111111111', '5500000000000004'],
      negative: ['1234567890123456'],
    },
  },
  {
    id: 'credit-card-formatted',
    name: 'Formatted Credit Card Number',
    description: 'Credit card number with spaces or dashes',
    severity: 'critical',
    pattern:
      /\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/g,
    keywords: ['credit', 'card', 'payment'],
    validators: [{ type: 'luhn' }],
    examples: {
      positive: ['4111-1111-1111-1111', '4111 1111 1111 1111'],
      negative: [],
    },
  },

  // Email addresses (can be PII in certain contexts)
  {
    id: 'email-address',
    name: 'Email Address',
    description: 'Email address (potential PII)',
    severity: 'low',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    keywords: ['email', 'mail', 'contact'],
    validators: [],
    falsePositives: [/example\.com$/, /test\.com$/, /localhost$/],
    examples: {
      positive: ['user@example.com'],
      negative: ['not-an-email'],
    },
  },

  // Phone Numbers
  {
    id: 'phone-us',
    name: 'US Phone Number',
    description: 'US phone number in various formats',
    severity: 'medium',
    pattern: /(?:\+?1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b/g,
    keywords: ['phone', 'tel', 'mobile', 'cell', 'contact'],
    validators: [{ type: 'length', min: 10, max: 17 }],
    falsePositives: [/555-0[0-1][0-9]{2}/, /123-456-7890/],
    examples: {
      positive: ['(555) 123-4567', '555-123-4567', '+1 555 123 4567'],
      negative: ['123-456-7890'],
    },
  },
  {
    id: 'phone-international',
    name: 'International Phone Number',
    description: 'International phone number with country code',
    severity: 'medium',
    pattern: /\+[1-9]\d{6,14}\b/g,
    keywords: ['phone', 'tel', 'international', 'mobile'],
    validators: [{ type: 'length', min: 8, max: 16 }],
    examples: {
      positive: ['+447911123456', '+14155551234'],
      negative: [],
    },
  },

  // IP Addresses
  {
    id: 'ipv4-address',
    name: 'IPv4 Address',
    description: 'IPv4 address (may indicate infrastructure)',
    severity: 'low',
    pattern:
      /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    keywords: ['ip', 'address', 'server', 'host'],
    validators: [
      {
        type: 'custom',
        fn: (match: string) => {
          // Exclude common non-routable ranges for lower priority
          if (match.startsWith('127.')) return true // localhost
          if (match.startsWith('0.')) return false
          return true
        },
      },
    ],
    falsePositives: [/^0\.0\.0\.0$/, /^255\.255\.255\.255$/],
    examples: {
      positive: ['192.168.1.1', '10.0.0.1'],
      negative: ['0.0.0.0', '999.999.999.999'],
    },
  },

  // Passport Numbers
  {
    id: 'passport-us',
    name: 'US Passport Number',
    description: 'US passport number',
    severity: 'high',
    pattern: /\b[A-Z]?\d{8,9}\b/g,
    keywords: ['passport', 'travel', 'document', 'id'],
    validators: [{ type: 'length', min: 8, max: 10 }],
    examples: {
      positive: ['123456789', 'A12345678'],
      negative: [],
    },
  },

  // Driver's License (generic US pattern)
  {
    id: 'drivers-license',
    name: 'Drivers License Number',
    description: 'Potential US drivers license number',
    severity: 'high',
    pattern: /\b[A-Z]{1,2}\d{5,8}\b/g,
    keywords: ['driver', 'license', 'dl', 'id'],
    validators: [{ type: 'length', min: 6, max: 10 }],
    examples: {
      positive: ['D12345678', 'FL123456'],
      negative: [],
    },
  },

  // Bank Account Numbers
  {
    id: 'iban',
    name: 'IBAN',
    description: 'International Bank Account Number',
    severity: 'high',
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b/g,
    keywords: ['iban', 'bank', 'account', 'international'],
    validators: [],
    examples: {
      positive: ['GB82WEST12345698765432'],
      negative: [],
    },
  },
  {
    id: 'routing-number',
    name: 'US Bank Routing Number',
    description: 'US ABA bank routing number',
    severity: 'high',
    pattern: /\b[0-9]{9}\b/g,
    keywords: ['routing', 'aba', 'bank', 'transit'],
    validators: [
      {
        type: 'custom',
        fn: (match: string) => {
          // ABA routing number checksum
          const d = match.split('').map(Number)
          if (d.length !== 9) {
            return false
          }
          const [d0, d1, d2, d3, d4, d5, d6, d7, d8] = d as [
            number,
            number,
            number,
            number,
            number,
            number,
            number,
            number,
            number,
          ]
          const sum = 3 * (d0 + d3 + d6) + 7 * (d1 + d4 + d7) + (d2 + d5 + d8)
          return sum % 10 === 0
        },
      },
    ],
    examples: {
      positive: ['021000021', '011401533'],
      negative: ['123456789'],
    },
  },

  // Date of Birth patterns
  {
    id: 'date-of-birth',
    name: 'Date of Birth',
    description: 'Potential date of birth in common formats',
    severity: 'medium',
    pattern:
      /\b(?:dob|birth.?date|date.?of.?birth)\s*[:=]?\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b/gi,
    keywords: ['dob', 'birth', 'date', 'birthday'],
    validators: [],
    examples: {
      positive: ['DOB: 01/15/1990', 'birth_date=1990-01-15'],
      negative: [],
    },
  },

  // Medical Record Numbers
  {
    id: 'medical-record',
    name: 'Medical Record Number',
    description: 'Potential medical record number',
    severity: 'high',
    pattern: /\b(?:mrn|medical.?record|patient.?id)\s*[:=]?\s*[A-Z0-9]{6,12}\b/gi,
    keywords: ['mrn', 'medical', 'record', 'patient', 'health'],
    validators: [],
    examples: {
      positive: ['MRN: ABC123456', 'patient_id=12345678'],
      negative: [],
    },
  },
]
