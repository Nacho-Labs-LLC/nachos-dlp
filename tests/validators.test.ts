import { describe, it, expect } from 'vitest'
import {
  calculateEntropy,
  validateLuhn,
  validateLength,
  validateChecksum,
  runValidator,
  runValidators,
  calculateConfidence,
} from '../src/validators/index.js'
import type { Validator } from '../src/types.js'

describe('calculateEntropy', () => {
  it('should return 0 for empty string', () => {
    expect(calculateEntropy('')).toBe(0)
  })

  it('should return 0 for single character', () => {
    expect(calculateEntropy('a')).toBe(0)
  })

  it('should return low entropy for repeated characters', () => {
    expect(calculateEntropy('aaaaaaaaaa')).toBe(0)
  })

  it('should return higher entropy for mixed characters', () => {
    const lowEntropy = calculateEntropy('aaaaabbbbb')
    const highEntropy = calculateEntropy('a1b2c3d4e5')
    expect(highEntropy).toBeGreaterThan(lowEntropy)
  })

  it('should return high entropy for random-looking strings', () => {
    const entropy = calculateEntropy('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
    expect(entropy).toBeGreaterThan(4)
  })

  it('should handle special characters', () => {
    const entropy = calculateEntropy('!@#$%^&*()_+-=[]{}|;:,.<>?')
    expect(entropy).toBeGreaterThan(3)
  })
})

describe('validateLuhn', () => {
  it('should validate correct credit card numbers', () => {
    expect(validateLuhn('4111111111111111')).toBe(true) // Visa test
    expect(validateLuhn('5500000000000004')).toBe(true) // MC test
    expect(validateLuhn('378282246310005')).toBe(true) // Amex test
  })

  it('should reject invalid credit card numbers', () => {
    expect(validateLuhn('1234567890123456')).toBe(false)
    expect(validateLuhn('0000000000000000')).toBe(true) // All zeros passes Luhn
    expect(validateLuhn('1111111111111111')).toBe(false)
  })

  it('should handle formatted numbers with spaces', () => {
    expect(validateLuhn('4111 1111 1111 1111')).toBe(true)
    expect(validateLuhn('4111-1111-1111-1111')).toBe(true)
  })

  it('should reject non-numeric strings', () => {
    expect(validateLuhn('abcd')).toBe(false)
    expect(validateLuhn('4111-abcd-1111-1111')).toBe(false)
  })

  it('should reject too short strings', () => {
    expect(validateLuhn('1')).toBe(false)
    expect(validateLuhn('')).toBe(false)
  })
})

describe('validateLength', () => {
  it('should validate strings within range', () => {
    expect(validateLength('hello', 3, 10)).toBe(true)
    expect(validateLength('hi', 2, 2)).toBe(true)
  })

  it('should reject strings outside range', () => {
    expect(validateLength('hi', 5, 10)).toBe(false)
    expect(validateLength('hello world', 3, 5)).toBe(false)
  })

  it('should work with only min', () => {
    expect(validateLength('hello', 3)).toBe(true)
    expect(validateLength('hi', 5)).toBe(false)
  })

  it('should work with only max', () => {
    expect(validateLength('hi', undefined, 5)).toBe(true)
    expect(validateLength('hello world', undefined, 5)).toBe(false)
  })

  it('should work with no constraints', () => {
    expect(validateLength('anything')).toBe(true)
  })
})

describe('validateChecksum', () => {
  it('should validate using luhn algorithm', () => {
    expect(validateChecksum('4111111111111111', 'luhn')).toBe(true)
    expect(validateChecksum('4111111111111111', 'mod10')).toBe(true)
  })

  it('should return true for unknown algorithms', () => {
    expect(validateChecksum('test', 'unknown')).toBe(true)
  })
})

describe('runValidator', () => {
  it('should run entropy validator', () => {
    const validator: Validator = { type: 'entropy', min: 4 }
    expect(runValidator(validator, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')).toBe(true)
    expect(runValidator(validator, 'aaaaaaaaaa')).toBe(false)
  })

  it('should run luhn validator', () => {
    const validator: Validator = { type: 'luhn' }
    expect(runValidator(validator, '4111111111111111')).toBe(true)
    expect(runValidator(validator, '1234567890123456')).toBe(false)
  })

  it('should run length validator', () => {
    const validator: Validator = { type: 'length', min: 5, max: 10 }
    expect(runValidator(validator, 'hello')).toBe(true)
    expect(runValidator(validator, 'hi')).toBe(false)
  })

  it('should run checksum validator', () => {
    const validator: Validator = { type: 'checksum', algorithm: 'luhn' }
    expect(runValidator(validator, '4111111111111111')).toBe(true)
  })

  it('should run custom validator', () => {
    const validator: Validator = {
      type: 'custom',
      fn: (match) => match.startsWith('test'),
    }
    expect(runValidator(validator, 'test123')).toBe(true)
    expect(runValidator(validator, 'hello')).toBe(false)
  })
})

describe('runValidators', () => {
  it('should return true if all validators pass', () => {
    const validators: Validator[] = [
      { type: 'length', min: 5 },
      { type: 'entropy', min: 2 },
    ]
    expect(runValidators(validators, 'hello world')).toBe(true)
  })

  it('should return false if any validator fails', () => {
    const validators: Validator[] = [
      { type: 'length', min: 5 },
      { type: 'entropy', min: 10 }, // Very high entropy requirement
    ]
    expect(runValidators(validators, 'hello')).toBe(false)
  })

  it('should return true for empty validators array', () => {
    expect(runValidators([], 'anything')).toBe(true)
  })
})

describe('calculateConfidence', () => {
  it('should return base confidence for simple match', () => {
    const confidence = calculateConfidence('test', [], undefined, undefined)
    expect(confidence).toBeGreaterThanOrEqual(0.5)
    expect(confidence).toBeLessThanOrEqual(1)
  })

  it('should increase confidence for high entropy', () => {
    const lowEntropyConfidence = calculateConfidence('aaaaaaaaaa', [], undefined, undefined)
    const highEntropyConfidence = calculateConfidence(
      'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      [],
      undefined,
      undefined,
    )
    expect(highEntropyConfidence).toBeGreaterThan(lowEntropyConfidence)
  })

  it('should increase confidence when keywords match in context', () => {
    const withoutKeywords = calculateConfidence('secret123', [], undefined, 'some random text')
    const withKeywords = calculateConfidence(
      'secret123',
      [],
      ['aws', 'secret', 'key'],
      'this is my aws secret key',
    )
    expect(withKeywords).toBeGreaterThan(withoutKeywords)
  })

  it('should clamp confidence to [0, 1]', () => {
    const confidence = calculateConfidence(
      'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      [],
      ['aws', 'secret', 'key', 'credential', 'access'],
      'aws secret key credential access token',
    )
    expect(confidence).toBeLessThanOrEqual(1)
    expect(confidence).toBeGreaterThanOrEqual(0)
  })
})
