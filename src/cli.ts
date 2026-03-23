#!/usr/bin/env node
/**
 * Enhanced CLI tool for llm-mask
 *
 * Usage:
 *   llm-mask [command] [options] [arguments]
 *
 * Commands:
 *   exec <cmd>       Execute command with redaction
 *   kube <args>      Execute kubectl with redaction
 *   ssh <host>       Execute SSH with redaction
 *   scan <path>      Scan codebase for secrets
 *   diff             Mask git diff
 *
 * Or use as pipe:
 *   echo "text" | llm-mask [options]
 */

import { Command } from 'commander'
import { readFileSync } from 'fs'
import { resolve } from 'path'

// Import commands
import { registerExecCommands } from './commands.js'

// Import existing functionality
import { mask, unmask, clearMasker } from './masker.js'
import { Scanner } from './scanner.js'
import { DiffMasker } from './diff-masking.js'
import { ContextMasker } from './context-detection.js'
import { loadConfig, getMaskLevel, createMaskerConfig } from './config.js'
import { BUILTIN_PATTERNS } from './patterns.js'

const program = new Command()

program
  .name('llm-mask')
  .description('Mask sensitive data before sending to LLMs')
  .version('0.3.0')

// === Legacy pipe/input functionality ===

const handlePipeInput = async (text: string, options: any) => {
  const config = loadConfig(options.config)
  const maskerConfig = createMaskerConfig(config)
  const level = getMaskLevel(config, options.level)

  // Create fresh masker with config
  const { DataMasker } = await import('./masker.js')
  const masker = new DataMasker(maskerConfig)

  if (options.unmask) {
    const unmasked = masker.unmask(text)
    console.log(options.json ? JSON.stringify({ unmasked }) : unmasked)
    return
  }

  if (options.context) {
    const { ContextMasker } = await import('./context-detection.js')
    const contextMasker = new ContextMasker()
    const result = contextMasker.mask(text)
    console.log(options.json ? JSON.stringify(result, null, 2) : result.masked)
    return
  }

  if (options.check) {
    const result = masker.mask(text, { level: (options.level as any) })
    if (options.json) {
      console.log(JSON.stringify({
        wouldMask: result.stats,
        original: text,
        masked: result.masked
      }, null, 2))
    } else {
      console.log(`Would mask: ${result.stats.total} items`)
      console.log(`Masked: ${result.masked}`)
    }
    return
  }

  // Default masking
  const result = masker.mask(text, {
    level: (options.level as any),
    preserveFormat: options.preserveFormat
  })

  if (options.json) {
    console.log(JSON.stringify({
      masked: result.masked,
      stats: result.stats
    }, null, 2))
  } else {
    console.log(result.masked)
  }
}

// === Input reading ===

async function readInput(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf-8').trim()
}

// === Legacy flags (for pipe mode) ===

program
  .option('-l, --level <level>', 'Masking level (basic|standard|aggressive)')
  .option('-f, --preserve-format', 'Preserve format (j***@a***.com)')
  .option('--context', 'Smart context detection (SQL, JSON, etc.)')
  .option('-u, --unmask', 'Unmask previously masked text')
  .option('-c, --check', 'Dry run: show what would be masked')
  .option('-p, --patterns', 'List all available patterns')
  .option('-j, --json', 'Output as JSON')
  .option('--config <path>', 'Path to config file')

// Register exec commands
registerExecCommands(program)

// === Scan command ===

program
  .command('scan [path]')
  .description('Scan codebase for secrets')
  .option('-l, --level <level>', 'Masking level', 'standard')
  .option('--fail-on-detect', 'Exit with error if secrets found')
  .option('--extensions <exts>', 'File extensions (comma-separated)')
  .option('--skip-dirs <dirs>', 'Directories to skip (comma-separated)')
  .action(async (path, options) => {
    const scanner = new Scanner({
      level: options.level,
      failOnDetect: options.failOnDetect,
      extensions: options.extensions?.split(','),
      skipDirs: options.skipDirs?.split(',')
    })

    try {
      const report = await scanner.scan(path || '.')
      console.log(scanner.formatReport(report, resolve(path || '.')))
    } catch (error) {
      if (error instanceof Error && error.name === 'ScanError') {
        const scanError = error as any
        console.log(scanner.formatReport(scanError.report, resolve(path || '.')))
        process.exit(1)
      }
      throw error
    }
  })

// === Diff command ===

program
  .command('diff')
  .description('Mask git diff output')
  .option('--base <branch>', 'Base branch or commit')
  .option('--head <branch>', 'Head branch or commit')
  .option('-l, --level <level>', 'Masking level', 'standard')
  .option('--path <path>', 'Path to restrict diff to')
  .action(async (options) => {
    const diffMasker = new DiffMasker()
    const result = diffMasker.maskDiff({
      base: options.base,
      head: options.head,
      level: options.level,
      path: options.path
    })
    console.log(diffMasker.format(result))
  })

// === Patterns command ===

program
  .command('patterns')
  .description('List all available patterns')
  .action(() => {
    const patterns = BUILTIN_PATTERNS.map(p => ({
      name: p.name,
      priority: p.priority,
      example: p.placeholder(1)
    }))

    console.log(`Available patterns (${patterns.length}):\n`)
    patterns.forEach(p => {
      console.log(`  ${p.name.padEnd(30)} priority: ${p.priority ?? 50}  →  ${p.example}`)
    })
  })

// === Default handler (pipe mode) ===

program
  .action(async (options) => {
    // If no command specified, check if we're receiving piped input
    const stdin = await readInput()

    if (stdin || options.patterns) {
      if (options.patterns) {
        // List patterns
        const patterns = BUILTIN_PATTERNS.map(p => ({
          name: p.name,
          priority: p.priority,
          example: p.placeholder(1)
        }))

        console.log(`Available patterns (${patterns.length}):\n`)
        patterns.forEach(p => {
          console.log(`  ${p.name.padEnd(30)} priority: ${p.priority ?? 50}  →  ${p.example}`)
        })
        return
      }

      if (stdin) {
        await handlePipeInput(stdin, options)
        return
      }
    }

    // No input, show help
    program.outputHelp()
  })

// === Dynamic imports for lazy loading ===

async function main() {
  await program.parseAsync(process.argv)
}

main().catch((error) => {
  console.error('Error:', error instanceof Error ? error.message : error)
  process.exit(1)
})
