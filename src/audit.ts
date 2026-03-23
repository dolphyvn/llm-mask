/**
 * Audit logging for masking operations
 *
 * Logs masking events WITHOUT the actual sensitive values
 * Only records: timestamp, pattern type, placeholder, length
 */

import { writeFileSync, appendFileSync, existsSync } from 'fs'
import { dirname } from 'path'
import { mkdirSync } from 'fs'

export interface AuditEvent {
  timestamp: number
  patternName: string
  placeholder: string
  inputLength: number
  context?: string
}

export interface AuditLoggerOptions {
  /** Log file path */
  file?: string
  /** Include in console output */
  console?: boolean
  /** Context to include in each log entry */
  context?: string
}

/**
 * Audit logger - records masking operations safely
 */
export class AuditLogger {
  private file?: string
  private consoleOutput: boolean
  private context?: string
  private buffer: AuditEvent[] = []

  constructor(options: AuditLoggerOptions = {}) {
    this.file = options.file
    this.consoleOutput = options.console || false
    this.context = options.context
  }

  /**
   * Log a masking event
   */
  log(event: AuditEvent): void {
    const logEvent: AuditEvent = {
      ...event,
      context: this.context
    }

    // Add to buffer for batch writing
    this.buffer.push(logEvent)

    // Console output if enabled
    if (this.consoleOutput) {
      console.error('[AUDIT]', JSON.stringify(logEvent))
    }

    // Write to file if configured
    if (this.file) {
      this.writeToFile(logEvent)
    }
  }

  /**
   * Write event to file (append)
   */
  private writeToFile(event: AuditEvent): void {
    try {
      // Ensure directory exists
      const dir = dirname(this.file!)
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true })
      }

      // Append as JSONL (one JSON object per line)
      appendFileSync(this.file!, JSON.stringify(event) + '\n')
    } catch (error) {
      console.error('Failed to write audit log:', error)
    }
  }

  /**
   * Flush buffer and clear
   */
  flush(): AuditEvent[] {
    const events = [...this.buffer]
    this.buffer = []
    return events
  }

  /**
   * Get buffered events
   */
  getBuffer(): AuditEvent[] {
    return [...this.buffer]
  }

  /**
   * Clear buffer
   */
  clear(): void {
    this.buffer = []
  }
}

/**
 * Create audit logger from environment or config
 */
export function createAuditLogger(options?: AuditLoggerOptions): AuditLogger {
  return new AuditLogger({
    file: options?.file || process.env.LLM_MASK_AUDIT_FILE,
    console: options?.console || process.env.LLM_MASK_AUDIT_CONSOLE === 'true',
    context: options?.context
  })
}
