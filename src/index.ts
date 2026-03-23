/**
 * llm-mask - Mask sensitive data before sending to LLMs
 *
 * @example
 * ```ts
 * import { mask, unmask } from 'llm-mask'
 *
 * const { masked, mappings, stats } = mask(text)
 * // Send 'masked' to LLM
 *
 * const original = unmask(llmResponse)
 * clearMasker()
 * ```
 */

// Main exports
export { DataMasker, defaultMasker, mask, unmask, clearMasker } from './masker.js'
export type { MaskOptions, MaskEvent } from './masker.js'

// Types
export type {
  MaskPattern,
  MaskResult,
  MaskStats,
  MaskerConfig,
  MaskLevel
} from './types.js'

// Pattern utilities
export {
  BUILTIN_PATTERNS,
  getPatternsByLevel,
  getPatternByName
} from './patterns.js'

// Formatter (preserve format masking)
export {
  formatEmail,
  formatApiKey,
  formatCreditCard,
  formatPhone,
  formatSSN,
  formatUUID,
  formatIP,
  formatURLWithCreds,
  formatByPattern
} from './formatter.js'
export type { FormatResult } from './formatter.js'

// Config loader
export {
  loadConfig,
  createMaskerConfig,
  getMaskLevel
} from './config.js'
export type { ConfigFile, LoadedConfig } from './config.js'

// Scanner (scan codebases)
export {
  Scanner,
  scanDirectory,
  ScanError
} from './scanner.js'
export type { ScanResult, ScanReport, ScanOptions } from './scanner.js'

// Diff masking
export { DiffMasker, maskDiff } from './diff-masking.js'
export type { DiffOptions, MaskedDiff } from './diff-masking.js'

// Context detection
export {
  ContextMasker,
  maskWithContext,
  detectContext
} from './context-detection.js'
export type { ContextType, ContextMaskResult } from './context-detection.js'

// Tokenizer (reversible masking)
export {
  Tokenizer,
  defaultTokenizer,
  tokenize,
  isToken,
  generateSalt
} from './tokenizer.js'
export type { TokenizerConfig } from './tokenizer.js'

// Audit logging
export {
  AuditLogger,
  createAuditLogger
} from './audit.js'
export type { AuditEvent, AuditLoggerOptions } from './audit.js'

// Language patterns
export {
  PYTHON_PATTERNS,
  JAVASCRIPT_PATTERNS,
  GO_PATTERNS,
  RUBY_PATTERNS,
  TERRAFORM_PATTERNS,
  LANGUAGE_PATTERNS,
  getPatternsByLanguage,
  detectLanguageFromPath
} from './language-patterns.js'

// Secure executor (NEW in v0.3)
export {
  SecureExecutor,
  execRedacted,
  kubectl,
  sshExec
} from './executor.js'
export type { ExecOptions, ExecResult, KubernetesExecOptions, SSHExecOptions } from './executor.js'
