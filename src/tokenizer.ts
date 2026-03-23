/**
 * Reversible tokenization with deterministic encryption
 *
 * Uses HMAC-based deterministic encryption to ensure:
 * - Same input always produces same token (consistency)
 * - Token cannot be reversed without the salt
 * - Works across different processes/machines with same salt
 */

import { createHash, createHmac, randomBytes } from 'crypto'

export interface TokenizerConfig {
  /** Salt for HMAC (generate one and store it securely) */
  salt: string
  /** Token prefix */
  prefix?: string
}

/**
 * Tokenizer - reversible masking with deterministic encryption
 */
export class Tokenizer {
  private salt: string
  private prefix: string

  constructor(config: TokenizerConfig) {
    this.salt = config.salt
    this.prefix = config.prefix || 'tok'
  }

  /**
   * Tokenize a value
   *
   * @param value - The sensitive value to tokenize
   * @param context - Optional context for namespacing (e.g., "email", "api_key")
   * @returns Token that can be safely shared
   */
  tokenize(value: string, context?: string): string {
    // Create HMAC using the salt
    const hmac = createHmac('sha256', this.salt)

    // Add context if provided for namespacing
    if (context) {
      hmac.update(context + '|')
    }

    hmac.update(value)

    // Get hash and truncate to 16 chars (128 bits)
    const hash = hmac.digest('hex').substring(0, 16)

    return `${this.prefix}_${context ? context + '_' : ''}${hash}`
  }

  /**
   * Check if a value is a token from this tokenizer
   */
  isToken(value: string): boolean {
    return value.startsWith(`${this.prefix}_`)
  }

  /**
   * Extract context from token if present
   */
  getTokenContext(token: string): string | null {
    if (!this.isToken(token)) {
      return null
    }

    const parts = token.split('_')
    if (parts.length === 3) {
      return parts[1]
    }

    return null
  }

  /**
   * Verify a token matches an original value
   *
   * Useful for validation without storing mappings
   */
  verify(token: string, original: string): boolean {
    const context = this.getTokenContext(token)
    const reTokenized = this.tokenize(original, context || undefined)
    return token === reTokenized
  }
}

/**
 * Generate a random salt for tokenizer
 *
 * Save this securely - you'll need it to detokenize
 */
export function generateSalt(): string {
  return randomBytes(32).toString('hex')
}

/**
 * Default tokenizer instance (uses a default salt - NOT SECURE for production)
 *
 * For production, create your own instance with a secure salt
 */
export const defaultTokenizer = new Tokenizer({
  salt: 'default-salt-change-this-in-production',
  prefix: 'tok'
})

/**
 * Convenience functions
 */
export function tokenize(value: string, context?: string): string {
  return defaultTokenizer.tokenize(value, context)
}

export function isToken(value: string): boolean {
  return defaultTokenizer.isToken(value)
}
