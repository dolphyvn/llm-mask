/**
 * Core types for llm-mask
 */

/**
 * A masking pattern definition
 */
export interface MaskPattern {
  /** Pattern name for logging and categorization */
  name: string

  /** Regex to detect the sensitive pattern */
  regex: RegExp

  /** Generate placeholder for this pattern */
  placeholder: (index: number) => string

  /** Whether to preserve format (e.g., j***@a***.com vs [EMAIL_1]) */
  preserveFormat?: boolean

  /** Priority - higher patterns are applied first */
  priority?: number
}

/**
 * Result of masking operation
 */
export interface MaskResult {
  /** Text with sensitive values replaced */
  masked: string

  /** Mapping of placeholders to original values (in-memory only!) */
  mappings: Map<string, string>

  /** Statistics about what was masked */
  stats: MaskStats
}

/**
 * Statistics about masking operation
 */
export interface MaskStats {
  /** Count of each pattern type masked */
  byPattern: Record<string, number>

  /** Total number of replacements */
  total: number
}

/**
 * Configuration for the masker
 */
export interface MaskerConfig {
  /** Custom patterns to add (merged with built-ins) */
  customPatterns?: MaskPattern[]

  /** Patterns to exclude from built-ins */
  excludePatterns?: string[]

  /** Whether to preserve format when possible */
  preserveFormat?: boolean

  /** Unique separator for multi-part replacements */
  separator?: string
}

/**
 * Masking level - determines how aggressive masking is
 */
export enum MaskLevel {
  /** Only clear secrets (API keys, passwords) */
  BASIC = 'basic',

  /** Secrets + PII (emails, phones, addresses) */
  STANDARD = 'standard',

  /** Everything including URLs, file paths, numbers that might be IDs */
  AGGRESSIVE = 'aggressive'
}
