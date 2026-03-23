/**
 * Secure executor - run commands and redact sensitive output
 *
 * Key principle: Credentials work for the command, but output is redacted
 * before the LLM sees it.
 */

import { spawn } from 'child_process'
import { DataMasker } from './masker.js'
import type { MaskResult } from './types.js'

export interface ExecOptions {
  /** Command to execute (optional for specialized executors like kubectl/ssh) */
  command?: string
  /** Arguments */
  args?: string[]
  /** Working directory */
  cwd?: string
  /** Environment variables (merged with process.env) */
  env?: Record<string, string>
  /** Timeout in milliseconds (default: 30000) */
  timeout?: number
  /** Redaction level */
  level?: 'basic' | 'standard' | 'aggressive'
  /** Preserve format in redacted output */
  preserveFormat?: boolean
  /** Redact specific patterns only */
  redactPatterns?: string[]
  /** Include stderr in output */
  includeStderr?: boolean
  /** Include exit code in output */
  includeExitCode?: boolean
}

export interface ExecResult {
  stdout: string
  stderr: string
  exitCode: number | null
  signal: string | null
  timedOut: boolean
  redacted: {
    stdout: string
    stderr: string
    stats: MaskResult['stats']
  }
}

export interface KubernetesExecOptions extends ExecOptions {
  /** Kubernetes namespace */
  namespace?: string
  /** Pod name */
  pod?: string
  /** Container name */
  container?: string
  /** Context from kubeconfig */
  context?: string
  /** Command to execute in pod */
  execCommand?: string
}

export interface SSHExecOptions extends ExecOptions {
  /** SSH host */
  host: string
  /** SSH user */
  user?: string
  /** Port */
  port?: number
  /** Identity file (private key) */
  identity?: string
  /** Command to run on remote host */
  remoteCommand?: string
}

/**
 * Secure executor - runs commands and redacts output
 */
export class SecureExecutor {
  private masker: DataMasker

  constructor() {
    this.masker = new DataMasker()
  }

  /**
   * Execute a command and return both original and redacted output
   */
  async exec(options: ExecOptions): Promise<ExecResult> {
    const {
      command,
      args = [],
      cwd,
      env,
      timeout = 30000,
      includeStderr = true,
      includeExitCode = false,
      level = 'standard',
      preserveFormat = false,
      redactPatterns
    } = options

    // Validate command for direct exec calls
    if (!command) {
      throw new Error('Command is required for exec(). Use kubectl() or ssh() for specialized operations.')
    }

    return new Promise((resolve) => {
      const startTime = Date.now()
      let timedOut = false
      let timeoutHandle: NodeJS.Timeout | undefined

      // Spawn the process
      const proc = spawn(command, args, {
        cwd,
        env: { ...process.env, ...env },
        timeout: undefined // We handle timeout ourselves
      })

      let stdout = ''
      let stderr = ''
      let exitCode: number | null = null
      let signal: string | null = null

      // Set timeout
      if (timeout > 0) {
        timeoutHandle = setTimeout(() => {
          timedOut = true
          proc.kill('SIGTERM')
          // Force kill if it doesn't terminate
          setTimeout(() => proc.kill('SIGKILL'), 5000)
        }, timeout)
      }

      // Collect output
      proc.stdout?.on('data', (data) => {
        stdout += data.toString()
      })

      proc.stderr?.on('data', (data) => {
        stderr += data.toString()
      })

      // Handle process exit
      proc.on('close', (code, sig) => {
        if (timeoutHandle) {
          clearTimeout(timeoutHandle)
        }

        const duration = Date.now() - startTime

        // Redact output
        const maskOptions: any = { level, preserveFormat }

        // Filter by patterns if specified
        if (redactPatterns && redactPatterns.length > 0) {
          // Custom redaction logic would go here
          // For now, use default masking
        }

        const stdoutResult = this.masker.mask(stdout, maskOptions)
        const stderrResult = this.masker.mask(stderr, maskOptions)

        resolve({
          stdout,
          stderr,
          exitCode: code,
          signal: sig,
          timedOut,
          redacted: {
            stdout: stdoutResult.masked,
            stderr: stderrResult.masked,
            stats: {
              ...stdoutResult.stats,
              byPattern: {
                ...stdoutResult.stats.byPattern,
                ...Object.entries(stderrResult.stats.byPattern).reduce(
                  (acc, [k, v]) => ({ ...acc, [k]: (acc[k] || 0) + v }),
                  {} as Record<string, number>
                )
              },
              total: stdoutResult.stats.total + stderrResult.stats.total
            }
          }
        })
      })
    })
  }

  /**
   * Execute a kubectl command
   */
  async kubectl(options: KubernetesExecOptions): Promise<ExecResult> {
    const args: string[] = []

    // Add context
    if (options.context) {
      args.push('--context', options.context)
    }

    // Add namespace
    if (options.namespace) {
      args.push('--namespace', options.namespace)
    }

    // Build the kubectl command
    if (options.pod) {
      // Exec into a pod
      if (options.container) {
        args.push('exec', '-c', options.container, options.pod, '--')
      } else {
        args.push('exec', options.pod, '--')
      }

      // Add command if provided
      if (options.execCommand) {
        args.push(options.execCommand)
      }
    } else {
      // Regular kubectl command
      args.push(...(options.args || []))
    }

    return this.exec({
      command: 'kubectl',
      args,
      cwd: options.cwd,
      env: options.env,
      timeout: options.timeout,
      level: options.level,
      preserveFormat: options.preserveFormat,
      includeStderr: options.includeStderr,
      includeExitCode: options.includeExitCode
    })
  }

  /**
   * Execute a command via SSH
   */
  async ssh(options: SSHExecOptions): Promise<ExecResult> {
    const args: string[] = []

    // Add port
    if (options.port) {
      args.push('-p', String(options.port))
    }

    // Add identity file
    if (options.identity) {
      args.push('-i', options.identity)
    }

    // Add host
    const host = options.user ? `${options.user}@${options.host}` : options.host
    args.push(host)

    // Add remote command
    if (options.remoteCommand) {
      args.push(options.remoteCommand)
    }

    return this.exec({
      command: 'ssh',
      args,
      cwd: options.cwd,
      env: options.env,
      timeout: options.timeout,
      level: options.level,
      preserveFormat: options.preserveFormat,
      includeStderr: options.includeStderr,
      includeExitCode: options.includeExitCode
    })
  }

  /**
   * Execute a command and return only redacted output (for LLM consumption)
   */
  async execRedacted(options: ExecOptions): Promise<string> {
    const result = await this.exec(options)

    // Combine stdout and stderr
    let output = result.redacted.stdout

    if (options.includeStderr !== false && result.redacted.stderr) {
      output += '\n' + result.redacted.stderr
    }

    if (options.includeExitCode && result.exitCode !== null) {
      output += `\n[Exit code: ${result.exitCode}]`
    }

    if (result.timedOut) {
      output += '\n[Command timed out]'
    }

    if (result.signal) {
      output += `\n[Terminated by signal: ${result.signal}]`
    }

    return output
  }

  /**
   * Format exec result for display
   */
  formatResult(result: ExecResult, showOriginal: boolean = false): string {
    const lines: string[] = []

    if (result.timedOut) {
      lines.push('⏱️  Command timed out')
    }

    if (result.signal) {
      lines.push(`💥 Terminated by signal: ${result.signal}`)
    }

    if (result.exitCode !== null && result.exitCode !== 0) {
      lines.push(`❌ Exit code: ${result.exitCode}`)
    }

    // Show redacted output by default
    if (!showOriginal) {
      lines.push('--- Redacted Output ---')
      lines.push(result.redacted.stdout)

      if (result.redacted.stderr) {
        lines.push('--- Redacted Stderr ---')
        lines.push(result.redacted.stderr)
      }

      if (result.redacted.stats.total > 0) {
        lines.push('')
        lines.push(`🔒 Redacted ${result.redacted.stats.total} item(s)`)
      }
    } else {
      // Show original (WARNING: contains sensitive data)
      lines.push('⚠️  ORIGINAL OUTPUT (MAY CONTAIN SENSITIVE DATA)')
      lines.push('---')
      lines.push(result.stdout)

      if (result.stderr) {
        lines.push('--- Stderr ---')
        lines.push(result.stderr)
      }
    }

    return lines.join('\n')
  }
}

/**
 * Convenience function
 */
export async function execRedacted(options: ExecOptions): Promise<string> {
  const executor = new SecureExecutor()
  return executor.execRedacted(options)
}

/**
 * Kubernetes convenience function
 */
export async function kubectl(options: KubernetesExecOptions): Promise<ExecResult> {
  const executor = new SecureExecutor()
  return executor.kubectl(options)
}

/**
 * SSH convenience function
 */
export async function sshExec(options: SSHExecOptions): Promise<ExecResult> {
  const executor = new SecureExecutor()
  return executor.ssh(options)
}
