/**
 * Diff masking - mask git diff output for safe LLM code review
 *
 * Preserves diff structure while masking sensitive data
 */

import { execSync } from 'child_process'
import { DataMasker } from './masker.js'

export interface DiffOptions {
  /** Base branch or commit */
  base?: string
  /** Head branch or commit (default: working directory) */
  head?: string
  /** Git options */
  gitDir?: string
  /** Masking level */
  level?: 'basic' | 'standard' | 'aggressive'
  /** Path to restrict diff */
  path?: string
}

export interface MaskedDiff {
  maskedDiff: string
  originalLineCount: number
  stats: {
    filesChanged: number
    linesAdded: number
    linesRemoved: number
    masksApplied: number
  }
}

/**
 * Masker for git diff output
 */
export class DiffMasker {
  private masker: DataMasker

  constructor() {
    this.masker = new DataMasker()
  }

  /**
   * Get git diff and mask it
   */
  maskDiff(options: DiffOptions = {}): MaskedDiff {
    const diff = this.getDiff(options)
    const lines = diff.split('\n')

    let filesChanged = 0
    let linesAdded = 0
    let linesRemoved = 0
    let masksApplied = 0

    const maskedLines = lines.map(line => {
      // Track diff metadata
      if (line.startsWith('diff --git')) {
        filesChanged++
      }
      if (line.startsWith('+') && !line.startsWith('++')) {
        linesAdded++
      }
      if (line.startsWith('-') && !line.startsWith('--')) {
        linesRemoved++
      }

      // Don't mask diff metadata
      if (line.startsWith('diff ') ||
          line.startsWith('index ') ||
          line.startsWith('@') ||
          line.startsWith('---') ||
          line.startsWith('+++') ||
          line === '') {
        return line
      }

      // Mask the line content (preserve the +/- prefix)
      const prefix = line.charAt(0) === '+' || line.charAt(0) === '-' ? line.charAt(0) : ''
      const content = prefix ? line.slice(1) : line

      const result = this.masker.mask(content, { level: options.level })
      masksApplied += result.stats.total

      return prefix + result.masked
    })

    return {
      maskedDiff: maskedLines.join('\n'),
      originalLineCount: lines.length,
      stats: {
        filesChanged,
        linesAdded,
        linesRemoved,
        masksApplied
      }
    }
  }

  /**
   * Get git diff output
   */
  private getDiff(options: DiffOptions): string {
    const args = ['diff', '--color=never', '--unified=3']

    if (options.base) {
      if (options.head) {
        args.push(`${options.base}...${options.head}`)
      } else {
        args.push(options.base)
      }
    }

    if (options.path) {
      args.push('--', options.path)
    }

    try {
      const cmd = ['git']
      if (options.gitDir) {
        cmd.push(`--git-dir=${options.gitDir}`)
      }
      cmd.push(...args)

      return execSync(cmd.join(' '), {
        encoding: 'utf-8',
        maxBuffer: 50 * 1024 * 1024 // 50MB
      })
    } catch (error) {
      throw new Error(`Failed to get git diff: ${error}`)
    }
  }

  /**
   * Format masked diff for display
   */
  format(maskedDiff: MaskedDiff): string {
    const lines: string[] = []

    lines.push('📝 Masked Git Diff')
    lines.push('')
    lines.push(`Files changed: ${maskedDiff.stats.filesChanged}`)
    lines.push(`Lines added: ${maskedDiff.stats.linesAdded}`)
    lines.push(`Lines removed: ${maskedDiff.stats.linesRemoved}`)
    lines.push(`Masks applied: ${maskedDiff.stats.masksApplied}`)
    lines.push('')
    lines.push('---')
    lines.push('')

    lines.push(maskedDiff.maskedDiff)

    return lines.join('\n')
  }
}

/**
 * Convenience function to mask git diff
 */
export function maskDiff(options?: DiffOptions): string {
  const masker = new DiffMasker()
  const result = masker.maskDiff(options)
  return result.maskedDiff
}
