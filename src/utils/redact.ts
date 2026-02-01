import type { Finding } from '../types.js'

export interface RedactOptions {
  replacement?: string
  showPrefix?: number
  showSuffix?: number
}

export function redact(
  text: string,
  findings: Finding[],
  options: RedactOptions = {}
): string {
  const { replacement = '[REDACTED]' } = options
  // TODO: Implement redaction
  return text
}
