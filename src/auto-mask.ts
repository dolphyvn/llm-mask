#!/usr/bin/env node
/**
 * Auto-Mask Mode for llm-mask
 *
 * Continuously monitors input and automatically masks sensitive data
 * Usage: llm-mask auto [--clipboard] [--watch <file>]
 */

import { Command } from 'commander'
import { readFileSync } from 'fs'
// @ts-ignore - chokidar
import watch from 'chokidar'
// @ts-ignore - clipboardy
import clipboard from 'clipboardy'
import { mask } from './masker.js'
import { loadConfig, getMaskLevel, createMaskerConfig } from './config.js'

type MaskLevel = 'basic' | 'standard' | 'aggressive'

const program = new Command()

program
  .name('llm-mask auto')
  .description('Auto-mask mode: continuously mask sensitive data')
  .version('0.3.0')
  .option('-l, --level <level>', 'Masking level (basic|standard|aggressive)', 'standard')
  .option('-f, --preserve-format', 'Preserve format')
  .option('-c, --config <path>', 'Path to config file')
  .option('--clipboard', 'Watch clipboard and auto-mask')
  .option('--watch <file>', 'Watch file for changes')
  .option('--watch-dir <dir>', 'Watch directory for file changes')
  .option('--once', 'Mask once and exit (for testing)')
  .option('--json', 'Output as JSON')
  .argument('[input]', 'Input text to mask (if not using --watch or --clipboard)')
  .action(async (input: string | undefined, options: any) => {
    const config = loadConfig(options.config)
    const maskerConfig = createMaskerConfig(config)
    const level: MaskLevel = (options.level || config.defaultLevel || 'standard') as MaskLevel
    const preserveFormat = options.preserveFormat || false

    // Single input mode
    if (input) {
      const { masked } = mask(input, { level, preserveFormat })
      console.log(options.json ? JSON.stringify({ masked, original: input }) : masked)
      return
    }

    // Watch mode
    if (options.watch) {
      console.log(`🔒 Auto-mask mode: Watching ${options.watch}`)
      console.log(`   Level: ${level}`)
      console.log(`   Press Ctrl+C to stop\n`)

      const watcher = watch(options.watch, {
        persistent: true,
        ignoreInitial: false
      })

      watcher.on('change', async (path: string) => {
        try {
          const content = readFileSync(path, 'utf-8')
          const { masked } = mask(content, { level, preserveFormat })
          console.log(`\n[${new Date().toLocaleTimeString()}] ${path}:`)
          console.log(`Masked: ${masked.substring(0, 200)}${masked.length > 200 ? '...' : ''}`)
        } catch (error) {
          console.error(`Error reading ${path}:`, error)
        }
      })

      // Keep process alive
      await new Promise(() => {})
    }

    // Directory watch mode
    if (options.watchDir) {
      console.log(`🔒 Auto-mask mode: Watching directory ${options.watchDir}`)
      console.log(`   Level: ${level}`)
      console.log(`   Press Ctrl+C to stop\n`)

      const watcher = watch(options.watchDir, {
        persistent: true,
        ignoreInitial: true
      })

      watcher.on('add', async (path: string) => {
        if (!path.match(/\.(log|txt|md|json|yaml|yml|env|conf|config)$/)) return
        try {
          const content = readFileSync(path, 'utf-8')
          const { masked } = mask(content, { level, preserveFormat })
          console.log(`\n[${new Date().toLocaleTimeString()}] ${path}:`)
          console.log(`Masked: ${masked.substring(0, 200)}${masked.length > 200 ? '...' : ''}`)
        } catch (error) {
          // Ignore errors for binary files
        }
      })

      watcher.on('change', async (path: string) => {
        if (!path.match(/\.(log|txt|md|json|yaml|yml|env|conf|config)$/)) return
        try {
          const content = readFileSync(path, 'utf-8')
          const { masked } = mask(content, { level, preserveFormat })
          console.log(`\n[${new Date().toLocaleTimeString()}] ${path}:`)
          console.log(`Masked: ${masked.substring(0, 200)}${masked.length > 200 ? '...' : ''}`)
        } catch (error) {
          // Ignore errors for binary files
        }
      })

      // Keep process alive
      await new Promise(() => {})
    }

    // Clipboard mode
    if (options.clipboard) {
      console.log('🔒 Auto-mask mode: Watching clipboard')
      console.log(`   Level: ${level}`)
      console.log(`   Press Ctrl+C to stop\n`)
      console.log('Copy any text, and it will be auto-masked!\n')

      let lastContent = ''

      const checkClipboard = async () => {
        try {
          const currentContent = await clipboard.read()
          if (currentContent && currentContent !== lastContent && currentContent.length > 0) {
            lastContent = currentContent
            const { masked } = mask(currentContent, { level, preserveFormat })

            console.log(`\n[${new Date().toLocaleTimeString()}] Clipboard masked:`)
            console.log(`Original: ${currentContent.substring(0, 100)}${currentContent.length > 100 ? '...' : ''}`)
            console.log(`Masked:   ${masked.substring(0, 100)}${masked.length > 100 ? '...' : ''}`)

            // Write masked version back to clipboard
            await clipboard.write(masked)
            console.log(`✓ Masked version written to clipboard`)
          }
        } catch (error) {
          // Clipboard might not be available
        }
      }

      // Check every 500ms
      const interval = setInterval(checkClipboard, 500)

      process.on('SIGINT', () => {
        clearInterval(interval)
        console.log('\n\n👋 Auto-mask mode stopped')
        process.exit(0)
      })

      // Keep process alive
      await new Promise(() => {})
    }

    // If no mode specified, show usage
    if (!input && !options.watch && !options.watchDir && !options.clipboard) {
      console.log(`
🔒 llm-mask Auto-Mask Mode

Auto-mask sensitive data in real-time.

Usage:
  llm-mask auto "text to mask"                    Mask once
  llm-mask auto --watch file.log                 Watch file
  llm-mask auto --watch-dir ./logs               Watch directory
  llm-mask auto --clipboard                      Watch clipboard

Options:
  -l, --level <level>        Masking level (basic|standard|aggressive)
  -f, --preserve-format     Preserve format (j***@a***.com)
  -c, --config <path>        Config file path
  --json                     Output as JSON

Examples:
  # Test auto-mask
  echo "My API key is sk-proj-abc" | llm-mask auto "My API key is sk-proj-abc"

  # Watch log file
  llm-mask auto --watch /var/log/app.log

  # Watch clipboard (anything copied gets masked)
  llm-mask auto --clipboard
`)
    }
  })

// Parse and execute
program.parseAsync(process.argv)
