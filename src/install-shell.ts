#!/usr/bin/env node
/**
 * Install llm-mask shell integration
 */

import { copyFileSync, mkdirSync, readFileSync, writeFileSync, existsSync } from 'fs'
import { homedir } from 'os'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const targetDir = `${homedir()}/.llm-mask`
const targetFile = `${targetDir}/shell-integration.sh`
const sourceFile = resolve(__dirname, '../shell-integration.sh')

console.log('🔒 Installing llm-mask shell integration...\n')

// Create target directory
try {
  mkdirSync(targetDir, { recursive: true })
} catch (error) {
  // Directory might already exist
}

// Copy shell integration file
copyFileSync(sourceFile, targetFile)

// Make it executable
const { chmodSync } = await import('fs')
chmodSync(targetFile, 0o755)

console.log(`✓ Shell integration installed to: ${targetFile}`)
console.log('\nTo enable, add this to your shell profile (~/.zshrc or ~/.bashrc):')
console.log('')
console.log('  # llm-mask shell integration')
console.log('  source ~/.llm-mask/shell-integration.sh')
console.log('')
console.log('Then reload your shell:')
console.log('  source ~/.zshrc  # or source ~/.bashrc')
console.log('')
console.log('Available commands after sourcing:')
console.log('  llm-mask-prompt on      # Enable auto-masking for commands')
console.log('  llm-mask-clipboard on   # Enable auto-masking for clipboard')
console.log('  llm-mask-status          # Show current status')
console.log('')
console.log('Quick aliases:')
console.log('  llm-mask-now            # Mask clipboard contents')
console.log('  llm-mask-cp             # Mask and copy to clipboard')
console.log('  auto-kubectl           # Run kubectl with auto-masking')
console.log('  auto-ssh               # Run ssh with auto-masking')
