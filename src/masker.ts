/**
 * Core DataMasker class
 *
 * This is the main class for masking sensitive data.
 * Mappings are stored in-memory ONLY and never written to disk.
 */

import type { MaskPattern, MaskResult, MaskStats, MaskerConfig } from './types.js'
import { BUILTIN_PATTERNS, getPatternsByLevel } from './patterns.js'
import { formatByPattern, type FormatResult } from './formatter.js'

export interface MaskOptions {
  /** Masking level: basic (secrets), standard (+PII), aggressive (everything) */
  level?: 'basic' | 'standard' | 'aggressive'
  /** Preserve format (j***@a***.com instead of [EMAIL_1]) */
  preserveFormat?: boolean
  /** Callback for each masking operation (for audit logging) */
  onMask?: (event: MaskEvent) => void
}

export interface MaskEvent {
  patternName: string
  placeholder: string
  inputLength: number
  timestamp: number
}

/**
 * DataMasker - masks sensitive data while preserving semantic meaning
 *
 * Key security principles:
 * 1. Mappings are NEVER written to disk
 * 2. Mappings are cleared after each operation (call clear() explicitly)
 * 3. Same value in same text gets same placeholder (consistency)
 * 4. Placeholders are semantic - [EMAIL_1] not [REDACTED_1]
 */
export class DataMasker {
  private allPatterns: MaskPattern[]
  private patterns: MaskPattern[]
  private mappings: Map<string, string> = new Map()
  private reverseMappings: Map<string, { value: string; pattern: string }> = new Map()
  private patternCounts: Record<string, number> = {}
  private onMaskCallback?: (event: MaskEvent) => void

  constructor(config?: MaskerConfig) {
    // Get base patterns (all by default)
    let patterns = [...BUILTIN_PATTERNS]

    // Filter out excluded patterns
    if (config?.excludePatterns?.length) {
      patterns = patterns.filter(p => !config.excludePatterns?.includes(p.name))
    }

    // Add custom patterns
    if (config?.customPatterns?.length) {
      patterns = [...patterns, ...config.customPatterns]
    }

    // Sort by priority (descending - higher priority first)
    this.allPatterns = patterns.sort((a, b) => (b.priority || 50) - (a.priority || 50))
    this.patterns = this.allPatterns
  }

  /**
   * Set masking callback
   */
  onMask(callback: (event: MaskEvent) => void): void {
    this.onMaskCallback = callback
  }

  /**
   * Mask sensitive data in text
   */
  mask(text: string, options?: MaskOptions): MaskResult {
    // Reset state for this masking operation
    this.mappings.clear()
    this.reverseMappings.clear()
    this.patternCounts = {}

    // Filter patterns by level if specified
    let patterns = this.patterns
    if (options?.level) {
      patterns = getPatternsByLevel(options.level)
      // Re-apply custom patterns and exclusions from constructor
      patterns = patterns.filter(p =>
        !this.allPatterns.find(ap => ap.name === p.name) ||
        this.patterns.find(sp => sp.name === p.name)
      )
    }

    let result = text

    // Apply each pattern in priority order
    for (const pattern of patterns) {
      result = this.applyPattern(result, pattern, options?.preserveFormat || false)
    }

    const stats: MaskStats = {
      byPattern: { ...this.patternCounts },
      total: Object.values(this.patternCounts).reduce((sum, count) => sum + count, 0)
    }

    return {
      masked: result,
      mappings: new Map(this.mappings),
      stats
    }
  }

  /**
   * Unmask text by replacing placeholders with original values
   */
  unmask(text: string): string {
    let result = text

    // Sort by placeholder length (descending) to handle overlapping
    const entries = Array.from(this.mappings.entries())
      .sort((a, b) => b[0].length - a[0].length)

    for (const [placeholder, value] of entries) {
      // Escape special regex characters in placeholder
      const escaped = placeholder.replace(/[[\]{}()*+?.\\^$|]/g, '\\$&')
      result = result.replace(new RegExp(escaped, 'g'), value)
    }

    return result
  }

  /**
   * Get the original value for a placeholder
   */
  getValue(placeholder: string): string | undefined {
    return this.mappings.get(placeholder)
  }

  /**
   * Clear all mappings from memory
   */
  clear(): void {
    this.mappings.clear()
    this.reverseMappings.clear()
    this.patternCounts = {}
  }

  /**
   * Get current mapping count
   */
  getMappingCount(): number {
    return this.mappings.size
  }

  /**
   * Apply a single pattern to text
   */
  private applyPattern(text: string, pattern: MaskPattern, preserveFormat: boolean): string {
    if (!pattern.regex.global) {
      pattern = { ...pattern, regex: new RegExp(pattern.regex.source, pattern.regex.flags + 'g') }
    }

    const valueToPlaceholder = new Map<string, string>()
    let count = 0

    const result = text.replace(pattern.regex, (match, ...groups) => {
      // Determine the actual sensitive value
      let sensitiveValue = match
      let prefix = ''
      let suffix = ''

      // For patterns with capture groups, extract the sensitive part
      const actualGroups = groups.slice(0, -3)

      if (actualGroups.length > 0 && actualGroups[0] !== undefined) {
        // Check if pattern uses $N syntax (for preserving context)
        const placeholder = pattern.placeholder(1)
        if (placeholder.includes('$')) {
          // This pattern preserves context - use it as-is
          count++
          const finalPlaceholder = pattern.placeholder(count)

          // Emit audit event
          this.emitMaskEvent(pattern.name, finalPlaceholder, match.length)

          this.patternCounts[pattern.name] = (this.patternCounts[pattern.name] || 0) + 1
          this.mappings.set(finalPlaceholder, match)

          return this.substituteGroups(finalPlaceholder, groups)
        }

        // Extract the actual sensitive value from last capture group
        sensitiveValue = actualGroups[actualGroups.length - 1] as string
        // Find prefix/suffix if we have multiple groups
        if (actualGroups.length >= 2) {
          prefix = actualGroups[0] as string || ''
          suffix = actualGroups[actualGroups.length - 1] as string || ''
        }
      }

      // Check if we've already assigned a placeholder for this value (consistency)
      if (valueToPlaceholder.has(sensitiveValue)) {
        const existingPlaceholder = valueToPlaceholder.get(sensitiveValue)!

        // Update mapping for unmasking
        if (!this.mappings.has(existingPlaceholder)) {
          this.mappings.set(existingPlaceholder, match)
        }
        this.patternCounts[pattern.name] = (this.patternCounts[pattern.name] || 0) + 1

        return existingPlaceholder
      }

      // Generate new placeholder
      count++
      const placeholder = pattern.placeholder(count)
      valueToPlaceholder.set(sensitiveValue, placeholder)

      // Store mappings for unmasking
      this.mappings.set(placeholder, match)
      this.reverseMappings.set(placeholder, { value: sensitiveValue, pattern: pattern.name })

      // Emit audit event
      this.emitMaskEvent(pattern.name, placeholder, match.length)

      this.patternCounts[pattern.name] = (this.patternCounts[pattern.name] || 0) + 1

      // Use preserve format if requested and we have a formatter for this pattern
      if (preserveFormat) {
        const formatted = formatByPattern(pattern.name, sensitiveValue)
        if (typeof formatted === 'object' && 'formatted' in formatted) {
          return match.replace(sensitiveValue, (formatted as FormatResult).formatted)
        }
      }

      return placeholder
    })

    return result
  }

  /**
   * Emit mask event for audit logging
   */
  private emitMaskEvent(patternName: string, placeholder: string, inputLength: number): void {
    if (this.onMaskCallback) {
      this.onMaskCallback({
        patternName,
        placeholder,
        inputLength,
        timestamp: Date.now()
      })
    }
  }

  /**
   * Replace $1, $2, etc. with actual capture group values
   */
  private substituteGroups(template: string, groups: unknown[]): string {
    const actualGroups = groups.slice(0, -3)
    return template.replace(/\$(\d+)/g, (_, index) => {
      const idx = parseInt(index, 10) - 1
      return idx < actualGroups.length ? String(actualGroups[idx] || '') : ''
    })
  }

  /**
   * Mask multiple values in an object (recursive)
   */
  maskObject(obj: unknown, options?: MaskOptions): unknown {
    if (typeof obj === 'string') {
      return this.mask(obj, options).masked
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.maskObject(item, options))
    }

    if (obj && typeof obj === 'object') {
      const result: Record<string, unknown> = {}
      for (const [key, value] of Object.entries(obj)) {
        result[key] = this.maskObject(value, options)
      }
      return result
    }

    return obj
  }

  /**
   * Create a summary of what was masked
   */
  summarize(stats: MaskStats): string {
    const parts: string[] = []

    for (const [pattern, count] of Object.entries(stats.byPattern)) {
      parts.push(`${pattern}: ${count}`)
    }

    return `Masked ${stats.total} items: ${parts.join(', ')}`
  }
}

/**
 * Singleton instance with default configuration
 */
export const defaultMasker = new DataMasker()

/**
 * Convenience function: mask text with default masker
 */
export function mask(text: string, options?: MaskOptions): MaskResult {
  return defaultMasker.mask(text, options)
}

/**
 * Convenience function: unmask text with default masker
 */
export function unmask(text: string): string {
  return defaultMasker.unmask(text)
}

/**
 * Convenience function: clear default masker
 */
export function clearMasker(): void {
  defaultMasker.clear()
}
