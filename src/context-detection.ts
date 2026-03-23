/**
 * Smart context detection - mask values while preserving structure
 *
 * Detects SQL, JSON, YAML, code and masks only values
 */

import { DataMasker } from './masker.js'

export type ContextType = 'sql' | 'json' | 'yaml' | 'xml' | 'code' | 'plaintext'

export interface ContextMaskResult {
  masked: string
  context: ContextType
  stats: {
    valuesMasked: number
    identifiersPreserved: number
  }
}

/**
 * Detect context type from content
 */
export function detectContext(content: string): ContextType {
  const trimmed = content.trim()

  // JSON
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    return 'json'
  }
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return 'json'
  }

  // YAML
  if (/^[\w\s-]+:/.test(trimmed)) {
    return 'yaml'
  }

  // SQL
  const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|INTO|VALUES|JOIN)\b/i
  if (sqlKeywords.test(content)) {
    return 'sql'
  }

  // XML
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<!DOCTYPE') || /<[^>]+>/.test(trimmed)) {
    return 'xml'
  }

  // Code-like (has function/class definitions, imports, etc.)
  if (/^(\s*(import|export|from|const|let|var|function|class|def|pub|fn)\b)/m.test(content)) {
    return 'code'
  }

  return 'plaintext'
}

/**
 * Context-aware masker
 */
export class ContextMasker {
  private masker: DataMasker

  constructor() {
    this.masker = new DataMasker()
  }

  /**
   * Mask content with context awareness
   */
  mask(content: string): ContextMaskResult {
    const context = detectContext(content)

    switch (context) {
      case 'json':
        return this.maskJSON(content)
      case 'sql':
        return this.maskSQL(content)
      case 'yaml':
        return this.maskYAML(content)
      case 'xml':
        return this.maskXML(content)
      default:
        return this.maskPlaintext(content, context)
    }
  }

  /**
   * Mask JSON - preserve keys, mask values
   */
  private maskJSON(content: string): ContextMaskResult {
    let valuesMasked = 0
    let identifiersPreserved = 0

    try {
      const obj = JSON.parse(content)

      const maskValue = (val: unknown): unknown => {
        if (typeof val === 'string') {
          const result = this.masker.mask(val)
          if (result.stats.total > 0) {
            valuesMasked++
            return result.masked
          }
          return val
        }
        if (Array.isArray(val)) {
          return val.map(maskValue)
        }
        if (val && typeof val === 'object') {
          const result: Record<string, unknown> = {}
          for (const [key, value] of Object.entries(val)) {
            identifiersPreserved++
            result[key] = maskValue(value)
          }
          return result
        }
        return val
      }

      const maskedObj = maskValue(obj)
      const masked = JSON.stringify(maskedObj, null, 2)

      return { masked, context: 'json', stats: { valuesMasked, identifiersPreserved } }
    } catch {
      // Not valid JSON, fall back to plaintext
      return this.maskPlaintext(content, 'plaintext')
    }
  }

  /**
   * Mask SQL - preserve identifiers, mask string literals
   */
  private maskSQL(content: string): ContextMaskResult {
    let valuesMasked = 0
    let identifiersPreserved = 0

    // Match SQL string literals
    const lines = content.split('\n')
    const maskedLines = lines.map(line => {
      // Mask string literals
      let masked = line.replace(/'([^']+)'/g, (match, value) => {
        const result = this.masker.mask(value)
        if (result.stats.total > 0) {
          valuesMasked++
          return `'${result.masked}'`
        }
        return match
      })

      // Preserve identifiers (table names, column names)
      identifiersPreserved += (line.match(/\b[A-Z][A-Z0-9_]*\b/g) || []).length

      return masked
    })

    return {
      masked: maskedLines.join('\n'),
      context: 'sql',
      stats: { valuesMasked, identifiersPreserved }
    }
  }

  /**
   * Mask YAML - preserve keys, mask values
   */
  private maskYAML(content: string): ContextMaskResult {
    let valuesMasked = 0
    let identifiersPreserved = 0

    const lines = content.split('\n')
    const maskedLines = lines.map(line => {
      // Check if this is a key-value line
      const match = line.match(/^(\s*)([\w-]+):\s*(.+)$/)
      if (match) {
        const [, indent, key, value] = match
        const result = this.masker.mask(value.trim())

        if (result.stats.total > 0) {
          valuesMasked++
          return `${indent}${key}: ${result.masked}`
        }

        identifiersPreserved++
        return line
      }

      // Check for array items
      const arrayMatch = line.match(/^(\s*)-\s*(.+)/)
      if (arrayMatch) {
        const [, indent, value] = arrayMatch
        const result = this.masker.mask(value.trim())

        if (result.stats.total > 0) {
          valuesMasked++
          return `${indent}- ${result.masked}`
        }

        return line
      }

      return line
    })

    return {
      masked: maskedLines.join('\n'),
      context: 'yaml',
      stats: { valuesMasked, identifiersPreserved }
    }
  }

  /**
   * Mask XML - preserve tags/attributes, mask text content
   */
  private maskXML(content: string): ContextMaskResult {
    let valuesMasked = 0
    let identifiersPreserved = 0

    // Count tags (identifiers)
    identifiersPreserved += (content.match(/<[\w:]+/g) || []).length

    // Mask text content between tags
    let masked = content.replace(/>([^<]+)</g, (match, text) => {
      if (text.trim().length === 0) return match

      const result = this.masker.mask(text.trim())
      if (result.stats.total > 0) {
        valuesMasked++
        return `>${result.masked}<`
      }
      return match
    })

    // Mask attribute values
    masked = masked.replace(/(\s+[\w:]+)=["']([^"']+)["']/g, (match, attr, value) => {
      const result = this.masker.mask(value)
      if (result.stats.total > 0) {
        valuesMasked++
        return `${attr}="${result.masked}"`
      }
      return match
    })

    return { masked, context: 'xml', stats: { valuesMasked, identifiersPreserved } }
  }

  /**
   * Regular plaintext masking
   */
  private maskPlaintext(content: string, context: ContextType): ContextMaskResult {
    const result = this.masker.mask(content)
    return {
      masked: result.masked,
      context,
      stats: { valuesMasked: result.stats.total, identifiersPreserved: 0 }
    }
  }
}

/**
 * Convenience function
 */
export function maskWithContext(content: string): ContextMaskResult {
  const masker = new ContextMasker()
  return masker.mask(content)
}
