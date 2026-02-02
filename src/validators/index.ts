import type { Validator } from '../types.js'

/**
 * Calculate Shannon entropy of a string
 * Higher entropy = more random = more likely to be a real secret
 */
export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0

  const charCounts = new Map<string, number>()
  for (const char of str) {
    charCounts.set(char, (charCounts.get(char) || 0) + 1)
  }

  let entropy = 0
  const len = str.length
  for (const count of charCounts.values()) {
    const freq = count / len
    entropy -= freq * Math.log2(freq)
  }

  return entropy
}

/**
 * Luhn algorithm for validating credit card numbers and similar checksums
 */
export function validateLuhn(numStr: string): boolean {
  // Remove spaces and dashes
  const digits = numStr.replace(/[\s-]/g, '')

  // Must be all digits
  if (!/^\d+$/.test(digits)) return false
  if (digits.length < 2) return false

  let sum = 0
  let isEven = false

  // Process from right to left
  for (let i = digits.length - 1; i >= 0; i--) {
    const digitChar = digits[i]
    if (!digitChar) return false
    let digit = parseInt(digitChar, 10)

    if (isEven) {
      digit *= 2
      if (digit > 9) {
        digit -= 9
      }
    }

    sum += digit
    isEven = !isEven
  }

  return sum % 10 === 0
}

/**
 * Validate string length
 */
export function validateLength(str: string, min?: number, max?: number): boolean {
  if (min !== undefined && str.length < min) return false
  if (max !== undefined && str.length > max) return false
  return true
}

/**
 * Common checksum algorithms
 */
export function validateChecksum(str: string, algorithm: string): boolean {
  switch (algorithm.toLowerCase()) {
    case 'mod10':
    case 'luhn':
      return validateLuhn(str)

    case 'mod11': {
      // Used in some IBANs and tax IDs
      const digits = str.replace(/\D/g, '')
      if (digits.length < 2) return false

      let sum = 0
      let weight = 2
      for (let i = digits.length - 2; i >= 0; i--) {
        const digitChar = digits[i]
        if (!digitChar) return false
        sum += parseInt(digitChar, 10) * weight
        weight++
        if (weight > 7) weight = 2
      }

      const checkDigit = (11 - (sum % 11)) % 11
      const lastDigitChar = digits[digits.length - 1]
      if (!lastDigitChar) return false
      const lastDigit = parseInt(lastDigitChar, 10)
      return checkDigit === lastDigit || (checkDigit === 10 && lastDigit === 0)
    }

    default:
      // Unknown algorithm - pass by default
      return true
  }
}

/**
 * Run a validator against a match
 */
export function runValidator(validator: Validator, match: string): boolean {
  switch (validator.type) {
    case 'entropy':
      return calculateEntropy(match) >= validator.min

    case 'luhn':
      return validateLuhn(match)

    case 'checksum':
      return validateChecksum(match, validator.algorithm)

    case 'length':
      return validateLength(match, validator.min, validator.max)

    case 'custom':
      return validator.fn(match)

    default:
      return true
  }
}

/**
 * Run all validators for a pattern match
 * Returns true if ALL validators pass
 */
export function runValidators(validators: Validator[], match: string): boolean {
  return validators.every((v) => runValidator(v, match))
}

/**
 * Calculate confidence score based on validators and other factors
 */
export function calculateConfidence(
  match: string,
  validators: Validator[],
  keywords?: string[],
  context?: string,
): number {
  let confidence = 0.5 // Base confidence

  // Entropy contribution (0-0.3)
  const entropy = calculateEntropy(match)
  if (entropy > 4.5) confidence += 0.3
  else if (entropy > 3.5) confidence += 0.2
  else if (entropy > 2.5) confidence += 0.1

  // Validators passing (0-0.2)
  if (validators.length > 0) {
    const validatorScore = runValidators(validators, match) ? 0.2 : -0.2
    confidence += validatorScore
  }

  // Keyword presence in context (0-0.15)
  if (keywords && context) {
    const lowerContext = context.toLowerCase()
    const keywordMatches = keywords.filter((k) => lowerContext.includes(k.toLowerCase()))
    if (keywordMatches.length > 0) {
      confidence += Math.min(0.15, keywordMatches.length * 0.05)
    }
  }

  // Clamp to [0, 1]
  return Math.max(0, Math.min(1, confidence))
}
