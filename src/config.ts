/**
 * Configuration loader for llm-mask
 *
 * Loads custom patterns from .llm-mask-rules.json
 */

import { readFileSync, existsSync } from 'fs'
import { resolve } from 'path'
import { homedir } from 'os'
import type { MaskPattern, MaskerConfig } from './types.js'

export interface ConfigFile {
  customPatterns?: Array<{
    name: string
    regex: string
    placeholder: string
    priority?: number
  }>
  defaultLevel?: 'basic' | 'standard' | 'aggressive'
  excludePatterns?: string[]
  auditLog?: boolean
  auditLogFile?: string
}

export interface LoadedConfig {
  customPatterns: MaskPattern[]
  defaultLevel: 'basic' | 'standard' | 'aggressive'
  excludePatterns: string[]
  auditLog: boolean
  auditLogFile: string
}

const DEFAULT_CONFIG: LoadedConfig = {
  customPatterns: [],
  defaultLevel: 'standard',
  excludePatterns: [],
  auditLog: false,
  auditLogFile: ''
}

/**
 * Search for config file in multiple locations:
 * 1. ./.llm-mask-rules.json (current directory)
 * 2. ~/.llm-mask-rules.json (home directory)
 * 3. ~/.config/llm-mask/rules.json (XDG config)
 */
function findConfigPath(startDir: string = process.cwd()): string | null {
  const paths = [
    resolve(startDir, '.llm-mask-rules.json'),
    resolve(homedir(), '.llm-mask-rules.json'),
    resolve(homedir(), '.config', 'llm-mask', 'rules.json')
  ]

  for (const path of paths) {
    if (existsSync(path)) {
      return path
    }
  }

  return null
}

/**
 * Load config file
 */
export function loadConfig(configPath?: string): LoadedConfig {
  const path = configPath || findConfigPath()

  if (!path || !existsSync(path)) {
    return DEFAULT_CONFIG
  }

  try {
    const content = readFileSync(path, 'utf-8')
    const raw: ConfigFile = JSON.parse(content)

    // Convert regex strings to RegExp objects
    const customPatterns: MaskPattern[] = (raw.customPatterns || []).map(p => ({
      name: p.name,
      regex: new RegExp(p.regex, 'g'),
      placeholder: (i: number) => p.placeholder.replace('{i}', String(i)),
      priority: p.priority || 50
    }))

    return {
      customPatterns,
      defaultLevel: raw.defaultLevel || 'standard',
      excludePatterns: raw.excludePatterns || [],
      auditLog: raw.auditLog || false,
      auditLogFile: raw.auditLogFile || ''
    }
  } catch (error) {
    console.error(`Failed to load config from ${path}:`, error)
    return DEFAULT_CONFIG
  }
}

/**
 * Merge loaded config with MaskerConfig
 */
export function createMaskerConfig(loaded: LoadedConfig): MaskerConfig {
  return {
    customPatterns: loaded.customPatterns,
    excludePatterns: loaded.excludePatterns
  }
}

/**
 * Get mask level from config or default
 */
export function getMaskLevel(loaded: LoadedConfig, cliLevel?: string): string {
  return cliLevel || loaded.defaultLevel
}
