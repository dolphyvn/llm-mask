#!/usr/bin/env node
/**
 * Enhanced CLI tool for llm-mask
 *
 * Usage:
 *   llm-mask [options] [text]
 *   cat file.txt | llm-mask [options]
 *   llm-mask scan /path/to/code [options]
 *   llm-mask diff [base] [head] [options]
 */

import { DataMasker } from './masker.js'
import { Scanner, scanDirectory } from './scanner.js'
import { DiffMasker } from './diff-masking.js'
import { ContextMasker } from './context-detection.js'
import { loadConfig, getMaskLevel, createMaskerConfig } from './config.js'
import { Tokenizer } from './tokenizer.js'
import { BUILTIN_PATTERNS } from './patterns.js'
import { resolve } from 'path'

interface Args {
  text?: string
  check: boolean
  level: string
  unmask: boolean
  patterns: boolean
  json: boolean
  stdin: boolean
  preserveFormat: boolean
  context: boolean
  scan?: string
  diff: boolean
  diffBase?: string
  diffHead?: string
  failOnDetect: boolean
  extensions?: string
  skipDirs?: string
  config?: string
}

function parseArgs(args: string[]): Args {
  const result: {
    text?: string
    check: boolean
    level: string
    unmask: boolean
    patterns: boolean
    json: boolean
    stdin: boolean
    preserveFormat: boolean
    context: boolean
    scan?: string
    diff: boolean
    diffBase?: string
    diffHead?: string
    failOnDetect: boolean
    extensions?: string
    skipDirs?: string
    config?: string
  } = {
    check: false,
    level: 'standard',
    unmask: false,
    patterns: false,
    json: false,
    stdin: false,
    preserveFormat: false,
    context: false,
    diff: false,
    failOnDetect: false
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]

    switch (arg) {
      case '--check':
      case '-c':
        result.check = true
        break
      case '--level':
      case '-l':
        result.level = args[++i] || 'standard'
        break
      case '--unmask':
      case '-u':
        result.unmask = true
        break
      case '--patterns':
      case '-p':
        result.patterns = true
        break
      case '--json':
      case '-j':
        result.json = true
        break
      case '--preserve-format':
      case '-f':
        result.preserveFormat = true
        break
      case '--context':
        result.context = true
        break
      case '--scan':
        result.scan = args[++i] || '.'
        break
      case '--diff':
        result.diff = true
        break
      case '--fail-on-detect':
        result.failOnDetect = true
        break
      case '--extensions':
        result.extensions = args[++i]
        break
      case '--skip-dirs':
        result.skipDirs = args[++i]
        break
      case '--config':
        result.config = args[++i]
        break
      case '--base':
        result.diffBase = args[++i]
        break
      case '--head':
        result.diffHead = args[++i]
        break
      case '--':
        result.text = args.slice(i + 1).join(' ')
        return result
      case '-':
        result.stdin = true
        break
      default:
        if (!arg.startsWith('-')) {
          result.text = args.slice(i).join(' ')
          return result
        }
    }
  }

  return result
}

function formatOutput(data: unknown, json: boolean): string {
  if (json) {
    return JSON.stringify(data, null, 2)
  }

  if (typeof data === 'object' && data !== null) {
    const obj = data as Record<string, unknown>
    if (obj.masked !== undefined) {
      return String(obj.masked)
    }
    if (obj.unmasked !== undefined) {
      return String(obj.unmasked)
    }
    if (obj.summary !== undefined) {
      return String(obj.summary)
    }
    if (obj.patterns !== undefined && Array.isArray(obj.patterns)) {
      const patterns = obj.patterns as Array<{ name: string; priority?: number; placeholder: string }>
      return `Available patterns (${obj.total}):\n\n` +
        patterns.map(p => `  ${p.name.padEnd(30)} priority: ${p.priority ?? 50}  →  ${p.placeholder}`).join('\n')
    }
  }

  return String(data)
}

async function main() {
  const args = parseArgs(process.argv.slice(2))

  // Load config
  const config = loadConfig(args.config)
  const maskerConfig = createMaskerConfig(config)
  const level = getMaskLevel(config, args.level)

  // Handle --patterns
  if (args.patterns) {
    const patterns = BUILTIN_PATTERNS.map(p => ({
      name: p.name,
      priority: p.priority,
      placeholder: p.placeholder(1)
    }))

    console.log(formatOutput({ patterns, total: patterns.length }, args.json))
    return
  }

  // Handle --scan
  if (args.scan) {
    const scanner = new Scanner({
      level: level as any,
      failOnDetect: args.failOnDetect,
      extensions: args.extensions ? args.extensions.split(',') : undefined,
      skipDirs: args.skipDirs ? args.skipDirs.split(',') : undefined
    })

    try {
      const report = await scanner.scan(args.scan)
      console.log(scanner.formatReport(report, resolve(args.scan)))
    } catch (error) {
      if (error instanceof Error && error.name === 'ScanError') {
        const scanError = error as any
        console.log(scanner.formatReport(scanError.report, resolve(args.scan)))
        process.exit(1)
      }
      throw error
    }
    return
  }

  // Handle --diff
  if (args.diff) {
    const diffMasker = new DiffMasker()
    const result = diffMasker.maskDiff({
      base: args.diffBase,
      head: args.diffHead,
      level: level as any
    })
    console.log(diffMasker.format(result))
    return
  }

  // Get input text
  let text = args.text

  if (args.stdin || !text) {
    const chunks: Buffer[] = []
    for await (const chunk of process.stdin) {
      chunks.push(chunk)
    }
    text = Buffer.concat(chunks).toString('utf-8').trim()
  }

  if (!text) {
    console.error('llm-mask - Mask sensitive data before sending to LLMs')
    console.error('')
    console.error('Usage:')
    console.error('  llm-mask [options] "text"')
    console.error('  echo "text" | llm-mask [options]')
    console.error('  llm-mask scan /path/to/code [options]')
    console.error('  llm-mask diff [base] [head] [options]')
    console.error('')
    console.error('Options:')
    console.error('  --check, -c         Dry run: show what would be masked')
    console.error('  --level, -l         Masking level (basic|standard|aggressive)')
    console.error('  --preserve-format, -f  Preserve format (j***@a***.com)')
    console.error('  --context           Smart context detection (SQL, JSON, etc.)')
    console.error('  --unmask, -u        Unmask previously masked text')
    console.error('  --patterns, -p      List all available patterns')
    console.error('  --json, -j          Output as JSON')
    console.error('  --scan <path>       Scan codebase for secrets')
    console.error('  --diff              Mask git diff output')
    console.error('  --fail-on-detect    Exit with error if secrets found (for CI)')
    console.error('  --extensions <exts> File extensions to scan (comma-separated)')
    console.error('  --skip-dirs <dirs>  Directories to skip (comma-separated)')
    console.error('  --config <path>     Path to config file')
    console.error('')
    console.error('Examples:')
    console.error('  llm-mask "API key sk-proj-123 expired for user@email.com"')
    console.error('  llm-mask --scan ./src --fail-on-detect')
    console.error('  git diff main | llm-mask --diff')
    console.error('  llm-mask --preserve-format "Contact john@acme.com"')
    process.exit(1)
  }

  // Create masker with config
  const masker = new DataMasker(maskerConfig)

  // Handle --unmask
  if (args.unmask) {
    const unmasked = masker.unmask(text)
    console.log(formatOutput({ unmasked }, args.json))
    return
  }

  // Handle --context
  if (args.context) {
    const contextMasker = new ContextMasker()
    const result = contextMasker.mask(text)
    console.log(formatOutput({
      masked: result.masked,
      context: result.context,
      stats: result.stats
    }, args.json))
    return
  }

  // Handle --check (dry run)
  if (args.check) {
    const result = masker.mask(text, { level: level as any })
    console.log(formatOutput({
      wouldMask: result.stats,
      summary: `Would mask ${result.stats.total} items`,
      original: text,
      masked: result.masked
    }, args.json))
    return
  }

  // Default: mask the text
  const result = masker.mask(text, {
    level: level as any,
    preserveFormat: args.preserveFormat
  })
  console.log(formatOutput({
    masked: result.masked,
    stats: result.stats,
    summary: masker.summarize(result.stats)
  }, args.json))
}

main().catch((error) => {
  console.error('Error:', error instanceof Error ? error.message : error)
  process.exit(1)
})
