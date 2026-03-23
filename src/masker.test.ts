/**
 * Tests for llm-mask
 */

// Note: tests use bun's built-in test framework (available globally in bun test)
// In TypeScript we can't easily import bun:test types, so we declare them

declare global {
  const describe: any
  const it: any
  const test: any
  const expect: any
}
import { DataMasker, mask, unmask, clearMasker } from './masker.js'

describe('DataMasker', () => {
  it('should mask API keys', () => {
    const masker = new DataMasker()
    const text = "API key sk-proj-abc123xyz789 is expired"
    const result = masker.mask(text)

    expect(result.masked).toContain('[OPENAI_KEY_1]')
    expect(result.masked).not.toContain('sk-proj-abc123xyz789')
    expect(result.stats.byPattern.openai_api_key).toBe(1)
    expect(result.stats.total).toBe(1)
  })

  it('should mask emails', () => {
    const masker = new DataMasker()
    const text = "Contact john@acme.com for details"
    const result = masker.mask(text)

    expect(result.masked).toContain('[EMAIL_1]')
    expect(result.masked).not.toContain('john@acme.com')
  })

  it('should mask IP addresses', () => {
    const masker = new DataMasker()
    const text = "Request from 192.168.1.100 was blocked"
    const result = masker.mask(text)

    expect(result.masked).toContain('[IP_1]')
    expect(result.masked).not.toContain('192.168.1.100')
  })

  it('should mask multiple patterns in one text', () => {
    const masker = new DataMasker()
    const text = "User john@acme.com connected from 192.168.1.1 with key sk-abc123456789xyz"
    const result = masker.mask(text)

    expect(result.masked).toContain('[EMAIL_1]')
    expect(result.masked).toContain('[IP_1]')
    expect(result.masked).toContain('[OPENAI_KEY_1]')
    expect(result.stats.total).toBeGreaterThanOrEqual(3)
  })

  it('should use consistent placeholders for same value', () => {
    const masker = new DataMasker()
    const text = "Email john@acme.com appears twice: john@acme.com"
    const result = masker.mask(text)

    const matches = result.masked.match(/\[EMAIL_1\]/g)
    expect(matches?.length).toBe(2)
    expect(result.masked).not.toContain('[EMAIL_2]')
  })

  it('should unmask correctly', () => {
    const masker = new DataMasker()
    const original = "Contact john@acme.com"
    const { masked } = masker.mask(original)
    const unmasked = masker.unmask(masked)

    expect(unmasked).toBe(original)
  })

  it('should mask JWT tokens', () => {
    const masker = new DataMasker()
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    const result = masker.mask(`Token: ${jwt}`)

    expect(result.masked).toContain('[JWT_1]')
    expect(result.masked).not.toContain(jwt)
  })

  it('should mask AWS access keys', () => {
    const masker = new DataMasker()
    const text = "AWS key: AKIAIOSFODNN7EXAMPLE"
    const result = masker.mask(text)

    expect(result.masked).toContain('[AWS_ACCESS_KEY_1]')
    expect(result.masked).not.toContain('AKIAIOSFODNN7EXAMPLE')
  })

  it('should mask UUIDs', () => {
    const masker = new DataMasker()
    const text = "User ID: 550e8400-e29b-41d4-a716-446655440000"
    const result = masker.mask(text)

    expect(result.masked).toContain('[UUID_1]')
    expect(result.masked).not.toContain('550e8400-e29b-41d4-a716-446655440000')
  })

  it('should mask URLs with credentials', () => {
    const masker = new DataMasker()
    const text = "Connecting to postgres://user:password@localhost/db"
    const result = masker.mask(text)

    expect(result.masked).toContain('[CREDENTIALS_1]')
    expect(result.masked).not.toContain('user:password')
  })

  it('should mask credit cards', () => {
    const masker = new DataMasker()
    const text = "Card: 4111 1111 1111 1111"
    const result = masker.mask(text)

    expect(result.masked).toContain('[CARD_1]')
    expect(result.masked).not.toContain('4111 1111 1111 1111')
  })

  it('should mask SSNs', () => {
    const masker = new DataMasker()
    const text = "SSN: 123-45-6789"
    const result = masker.mask(text)

    expect(result.masked).toContain('[SSN_1]')
    expect(result.masked).not.toContain('123-45-6789')
  })

  it('should clear mappings', () => {
    const masker = new DataMasker()
    masker.mask("john@acme.com")
    expect(masker.getMappingCount()).toBeGreaterThan(0)

    masker.clear()
    expect(masker.getMappingCount()).toBe(0)
  })

  it('should handle empty text', () => {
    const masker = new DataMasker()
    const result = masker.mask('')

    expect(result.masked).toBe('')
    expect(result.stats.total).toBe(0)
  })

  it('should handle text with no sensitive data', () => {
    const masker = new DataMasker()
    const text = "Hello world, this is a normal message"
    const result = masker.mask(text)

    expect(result.masked).toBe(text)
    expect(result.stats.total).toBe(0)
  })

  it('should preserve original text structure', () => {
    const masker = new DataMasker()
    const text = "Error: API key sk-abc123456789xyz failed for user test@example.com at 10.0.0.1"
    const result = masker.mask(text)

    expect(result.masked).toMatch(/Error: API key \[OPENAI_KEY_\d+\] failed for user \[EMAIL_\d+\] at \[IP_\d+\]/)
  })
})

describe('convenience functions', () => {
  it('should work with default masker', () => {
    const result = mask("Secret: sk-proj-abc123456789xyz")

    expect(result.masked).toContain('[OPENAI_KEY_1]')

    const unmasked = unmask(result.masked)
    expect(unmasked).toContain('sk-proj-abc123456789xyz')

    clearMasker()
  })
})

describe('realistic scenarios', () => {
  it('should mask error logs', () => {
    const masker = new DataMasker()
    const log = `[ERROR] 2024-03-23T10:30:00Z Failed to authenticate user john@company.com
Reason: API key sk-proj-abc123xyz789 expired
Request from IP: 192.168.1.100
Request ID: 550e8400-e29b-41d4-a716-446655440000`

    const result = masker.mask(log)

    expect(result.masked).not.toContain('john@company.com')
    expect(result.masked).not.toContain('sk-proj-abc123xyz789')
    expect(result.masked).not.toContain('192.168.1.100')
    expect(result.masked).not.toContain('550e8400-e29b-41d4-a716-446655440000')

    expect(result.masked).toContain('[EMAIL_1]')
    expect(result.masked).toContain('[OPENAI_KEY_1]')
    expect(result.masked).toContain('[IP_1]')
    expect(result.masked).toContain('[UUID_1]')
  })

  it('should mask stack traces', () => {
    const masker = new DataMasker()
    const trace = `Error: Connection refused
    at /Users/john/projects/api/src/db.ts:42:15
    at connectToDatabase (/home/john/api/lib/db.js:120:5)
    URL: postgresql://admin:secret123@localhost:5432/mydb`

    const result = masker.mask(trace)

    expect(result.masked).not.toContain('Users/john')
    expect(result.masked).not.toContain('home/john')
    expect(result.masked).not.toContain('admin:secret123')

    expect(result.masked).toContain('[PATH_')
    expect(result.masked).toContain('[CREDENTIALS_1]')
  })
})
