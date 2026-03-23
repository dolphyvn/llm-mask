/**
 * Tests for new features
 */

import { DataMasker } from './masker.js'
import { ContextMasker } from './context-detection.js'
import { Tokenizer } from './tokenizer.js'
import { formatEmail, formatApiKey } from './formatter.js'

describe('Masking Levels', () => {
  it('should mask only API keys at basic level', () => {
    const masker = new DataMasker()
    const text = "Contact john@acme.com with key sk-proj-abc123xyz789"
    const result = masker.mask(text, { level: 'basic' })

    expect(result.masked).toContain('[OPENAI_KEY_1]')
    expect(result.masked).toContain('john@acme.com') // Email NOT masked at basic level
  })

  it('should mask PII at standard level', () => {
    const masker = new DataMasker()
    const text = "Contact john@acme.com with key sk-proj-abc123xyz789"
    const result = masker.mask(text, { level: 'standard' })

    expect(result.masked).toContain('[OPENAI_KEY_1]')
    expect(result.masked).toContain('[EMAIL_1]')
  })

  it('should mask everything at aggressive level', () => {
    const masker = new DataMasker()
    const text = "Connecting to https://internal.api.com with user@test.com"
    const result = masker.mask(text, { level: 'aggressive' })

    expect(result.masked).toContain('[INTERNAL_URL_')
    expect(result.masked).toContain('[EMAIL_')
  })
})

describe('Preserve Format Masking', () => {
  it('should format email as j***@a***.com', () => {
    const result = formatEmail('john@acme.com')
    expect(result.formatted).toBe('j***@a***.com')
    expect(result.original).toBe('john@acme.com')
  })

  it('should format API key preserving prefix', () => {
    const result = formatApiKey('sk-proj-abc123xyz789')
    expect(result.formatted).toContain('sk-proj-')
    expect(result.formatted).toContain('*')
    expect(result.original).toBe('sk-proj-abc123xyz789')
  })

  it('should use preserveFormat option in masker', () => {
    const masker = new DataMasker()
    const text = "Contact john@acme.com"
    const result = masker.mask(text, { preserveFormat: true })

    expect(result.masked).toContain('j***@a***.com')
    expect(result.masked).not.toContain('[EMAIL_1]')
  })
})

describe('Context-Aware Masking', () => {
  it('should preserve JSON keys and mask values', () => {
    const masker = new ContextMasker()
    const json = '{"user": "john@acme.com", "key": "sk-proj-abc"}'
    const result = masker.mask(json)

    expect(result.masked).toContain('"user":')
    expect(result.masked).not.toContain('john@acme.com')
    expect(result.context).toBe('json')
  })

  it('should preserve SQL identifiers', () => {
    const masker = new ContextMasker()
    const sql = "SELECT * FROM users WHERE email = 'john@test.com'"
    const result = masker.mask(sql)

    expect(result.masked).toContain('SELECT')
    expect(result.masked).toContain('FROM users')
    expect(result.masked).not.toContain('john@test.com')
    expect(result.context).toBe('sql')
  })

  it('should detect plaintext context', () => {
    const masker = new ContextMasker()
    const result = masker.mask('Just some random text')

    expect(result.context).toBe('plaintext')
  })
})

describe('Tokenizer', () => {
  const salt = 'test-salt-for-tokenizer'

  it('should tokenize consistently', () => {
    const tokenizer = new Tokenizer({ salt })
    const token1 = tokenizer.tokenize('secret-value')
    const token2 = tokenizer.tokenize('secret-value')

    expect(token1).toBe(token2)
    expect(token1).toMatch(/^tok_[a-f0-9]{16}$/)
  })

  it('should tokenize differently for different values', () => {
    const tokenizer = new Tokenizer({ salt })
    const token1 = tokenizer.tokenize('value1')
    const token2 = tokenizer.tokenize('value2')

    expect(token1).not.toBe(token2)
  })

  it('should verify tokens correctly', () => {
    const tokenizer = new Tokenizer({ salt })
    const token = tokenizer.tokenize('secret')

    expect(tokenizer.verify(token, 'secret')).toBe(true)
    expect(tokenizer.verify(token, 'wrong')).toBe(false)
  })

  it('should use context for namespacing', () => {
    const tokenizer = new Tokenizer({ salt })
    const token1 = tokenizer.tokenize('value', 'email')
    const token2 = tokenizer.tokenize('value', 'api_key')

    expect(token1).not.toBe(token2)
    expect(token1).toContain('email_')
    expect(token2).toContain('api_key_')
  })
})

describe('Format Result Types', () => {
  it('should return FormatResult for email', () => {
    const result = formatEmail('test@example.com')
    expect(typeof result).toBe('object')
    expect(result).toHaveProperty('formatted')
    expect(result).toHaveProperty('original')
  })

  it('should return string for SSN', () => {
    const { formatSSN } = require('./formatter')
    const result = formatSSN('123-45-6789')
    expect(typeof result).toBe('string')
  })
})
