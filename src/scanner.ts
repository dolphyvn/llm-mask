/**
 * Scanner - scan codebases for sensitive data
 *
 * Recursively scans directories, finds files, checks for patterns
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'fs'
import { join, extname, relative, resolve } from 'path'
import { DataMasker } from './masker.js'
import type { MaskStats } from './types.js'

export interface ScanResult {
  file: string
  line: number
  pattern: string
  placeholder: string
  lineContent: string
}

export interface ScanReport {
  scans: {
    totalFiles: number
    scannedFiles: number
    skippedFiles: number
  }
  findings: ScanResult[]
  summary: {
    byPattern: Record<string, number>
    byFile: Record<string, number>
    total: number
  }
}

export interface ScanOptions {
  /** File extensions to scan (empty = all) */
  extensions?: string[]
  /** Patterns to exclude (regex) */
  excludePatterns?: RegExp[]
  /** Directories to skip */
  skipDirs?: string[]
  /** Max file size in bytes */
  maxSize?: number
  /** Fail on detection (for CI/CD) */
  failOnDetect?: boolean
  /** Masking level */
  level?: 'basic' | 'standard' | 'aggressive'
}

const DEFAULT_SKIP_DIRS = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'target',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  '.nuxt',
  'coverage'
]

const TEXT_EXTENSIONS = [
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.go', '.rs', '.java', '.kt', '.swift',
  '.sh', '.bash', '.zsh', '.fish',
  '.env', '.config', '.conf', '.ini', '.yaml', '.yml', '.json', '.toml',
  '.md', '.txt', '.csv', '.log',
  '.sql', '.graphql', '.gql',
  '.html', '.css', '.scss', '.less',
  '.xml', '.dto'
]

/**
 * Scanner - find secrets in codebases
 */
export class Scanner {
  private masker: DataMasker
  private options: Required<ScanOptions>

  constructor(options: ScanOptions = {}) {
    this.masker = new DataMasker()
    this.options = {
      extensions: options.extensions || TEXT_EXTENSIONS,
      excludePatterns: options.excludePatterns || [],
      skipDirs: [...DEFAULT_SKIP_DIRS, ...(options.skipDirs || [])],
      maxSize: options.maxSize || 1024 * 1024, // 1MB default
      failOnDetect: options.failOnDetect || false,
      level: options.level || 'standard'
    }
  }

  /**
   * Scan a directory recursively
   */
  async scan(dir: string): Promise<ScanReport> {
    const findings: ScanResult[] = []
    let totalFiles = 0
    let scannedFiles = 0
    let skippedFiles = 0

    const walkDir = (currentDir: string) => {
      try {
        const entries = readdirSync(currentDir)

        for (const entry of entries) {
          const fullPath = join(currentDir, entry)
          const stat = statSync(fullPath)

          // Skip directories in skip list
          if (stat.isDirectory()) {
            if (this.options.skipDirs.includes(entry)) {
              continue
            }
            walkDir(fullPath)
            continue
          }

          // Only scan files
          if (!stat.isFile()) {
            continue
          }

          totalFiles++

          // Check file extension
          const ext = extname(entry)
          if (this.options.extensions.length > 0 &&
              !this.options.extensions.includes(ext)) {
            skippedFiles++
            continue
          }

          // Check file size
          if (stat.size > this.options.maxSize) {
            skippedFiles++
            continue
          }

          // Check exclude patterns
          const relPath = relative(dir, fullPath)
          if (this.options.excludePatterns.some(pattern => pattern.test(relPath))) {
            skippedFiles++
            continue
          }

          // Scan the file
          const fileFindings = this.scanFile(fullPath)
          findings.push(...fileFindings)
          scannedFiles++
        }
      } catch (error) {
        // Skip files we can't read (permissions, etc.)
        skippedFiles++
      }
    }

    walkDir(resolve(dir))

    // Generate summary
    const byPattern: Record<string, number> = {}
    const byFile: Record<string, number> = {}

    for (const finding of findings) {
      byPattern[finding.pattern] = (byPattern[finding.pattern] || 0) + 1
      const relPath = relative(dir, finding.file)
      byFile[relPath] = (byFile[relPath] || 0) + 1
    }

    const report: ScanReport = {
      scans: {
        totalFiles,
        scannedFiles,
        skippedFiles
      },
      findings,
      summary: {
        byPattern,
        byFile,
        total: findings.length
      }
    }

    // Fail if requested and findings exist
    if (this.options.failOnDetect && findings.length > 0) {
      throw new ScanError(
        `Found ${findings.length} sensitive pattern(s) in codebase`,
        report
      )
    }

    return report
  }

  /**
   * Scan a single file
   */
  scanFile(filePath: string): ScanResult[] {
    const findings: ScanResult[] = []

    try {
      const content = readFileSync(filePath, 'utf-8')
      const lines = content.split('\n')

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        const result = this.masker.mask(line, { level: this.options.level })

        // Check if anything was masked
        if (result.stats.total > 0) {
          // Find which patterns matched
          for (const [pattern, count] of Object.entries(result.stats.byPattern)) {
            for (let j = 0; j < count; j++) {
              findings.push({
                file: filePath,
                line: i + 1,
                pattern,
                placeholder: `[${pattern.toUpperCase()}_${j + 1}]`,
                lineContent: line.trim()
              })
            }
          }
        }
      }
    } catch (error) {
      // Skip files that can't be read as text
    }

    return findings
  }

  /**
   * Format report as text
   */
  formatReport(report: ScanReport, baseDir: string): string {
    const lines: string[] = []

    lines.push('🔍 llm-mask Scan Report')
    lines.push('')
    lines.push(`Scanned: ${report.scans.scannedFiles} files`)
    lines.push(`Skipped: ${report.scans.skippedFiles} files`)
    lines.push(`Findings: ${report.summary.total} sensitive pattern(s)`)
    lines.push('')

    if (report.findings.length === 0) {
      lines.push('✅ No sensitive patterns detected!')
      return lines.join('\n')
    }

    lines.push('⚠️  Findings:')
    lines.push('')

    // Group by file
    const byFile: Record<string, ScanResult[]> = {}
    for (const finding of report.findings) {
      const relPath = relative(baseDir, finding.file)
      if (!byFile[relPath]) {
        byFile[relPath] = []
      }
      byFile[relPath].push(finding)
    }

    for (const [file, fileFindings] of Object.entries(byFile)) {
      lines.push(`${file}:`)

      for (const finding of fileFindings) {
        const icon = this.getSeverityIcon(finding.pattern)
        lines.push(`  ${icon} Line ${finding.line}: ${finding.pattern}`)
        lines.push(`    ${finding.lineContent.substring(0, 80)}${finding.lineContent.length > 80 ? '...' : ''}`)
      }

      lines.push('')
    }

    // Summary by pattern
    lines.push('Summary by pattern:')
    for (const [pattern, count] of Object.entries(report.summary.byPattern)) {
      lines.push(`  ${pattern}: ${count}`)
    }

    return lines.join('\n')
  }

  /**
   * Get severity icon for pattern
   */
  private getSeverityIcon(pattern: string): string {
    const critical = [
      'openai_api_key', 'anthropic_api_key', 'stripe_live_key',
      'aws_access_key', 'aws_secret', 'github_token'
    ]

    const warning = [
      'email', 'ip_address', 'uuid', 'jwt_token', 'api_key_equals'
    ]

    if (critical.some(p => pattern.includes(p))) {
      return '❌'
    }
    if (warning.some(p => pattern.includes(p))) {
      return '⚠️ '
    }
    return '🔒'
  }
}

/**
 * Error thrown when sensitive patterns are detected
 */
export class ScanError extends Error {
  public report: ScanReport

  constructor(message: string, report: ScanReport) {
    super(message)
    this.name = 'ScanError'
    this.report = report
  }
}

/**
 * Convenience function to scan a directory
 */
export async function scanDirectory(
  dir: string,
  options?: ScanOptions
): Promise<ScanReport> {
  const scanner = new Scanner(options)
  return scanner.scan(dir)
}
