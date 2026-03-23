/**
 * Tests for SecureExecutor
 */

import { describe, it, expect, beforeEach, mock } from 'bun:test'
import { SecureExecutor } from './executor.js'

describe('SecureExecutor', () => {
  let executor: SecureExecutor

  beforeEach(() => {
    executor = new SecureExecutor()
  })

  describe('exec', () => {
    it('should execute a simple command and return redacted output', async () => {
      const result = await executor.exec({
        command: 'echo',
        args: ['hello world'],
        level: 'standard'
      })

      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('hello world')
      expect(result.signal).toBeNull()
      expect(result.timedOut).toBe(false)
      expect(result.redacted.stats.total).toBe(0)
    })

    it('should redact sensitive data in output', async () => {
      const apiKey = 'sk-proj-abc123xyz456'
      const result = await executor.exec({
        command: 'echo',
        args: [`API key is ${apiKey}`],
        level: 'standard'
      })

      expect(result.stdout).toContain(apiKey)
      expect(result.redacted.stdout).not.toContain(apiKey)
      expect(result.redacted.stdout).toContain('[OPENAI_KEY_1]')
      expect(result.redacted.stats.total).toBeGreaterThan(0)
    })

    it('should redact email addresses in output', async () => {
      const email = 'user@example.com'
      const result = await executor.exec({
        command: 'echo',
        args: [`Contact: ${email}`],
        level: 'standard'
      })

      expect(result.stdout).toContain(email)
      expect(result.redacted.stdout).not.toContain(email)
      expect(result.redacted.stdout).toContain('[EMAIL_1]')
    })

    it('should preserve format when requested', async () => {
      const email = 'user@example.com'
      const result = await executor.exec({
        command: 'echo',
        args: [email],
        level: 'standard',
        preserveFormat: true
      })

      expect(result.redacted.stdout).toMatch(/u\*+@e\*+/) // j***@a*** style
    })

    it('should handle stderr output', async () => {
      const result = await executor.exec({
        command: 'sh',
        args: ['-c', 'echo error >&2'],
        level: 'standard'
      })

      expect(result.stderr).toContain('error')
      expect(result.redacted.stderr).toContain('error')
    })

    it('should handle non-zero exit codes', async () => {
      const result = await executor.exec({
        command: 'sh',
        args: ['-c', 'exit 42'],
        level: 'standard'
      })

      expect(result.exitCode).toBe(42)
    })

    it('should handle command timeout', async () => {
      const result = await executor.exec({
        command: 'sleep',
        args: ['100'],
        timeout: 100,
        level: 'standard'
      })

      expect(result.timedOut).toBe(true)
      expect(result.signal).toBe('SIGTERM')
    })

    it('should throw error when command is missing', async () => {
      await expect(executor.exec({
        args: ['hello']
      } as any)).rejects.toThrow('Command is required')
    })

    it('should respect aggressive masking level', async () => {
      const result = await executor.exec({
        command: 'echo',
        args: ['Call me at 555-123-4567'],
        level: 'aggressive'
      })

      expect(result.redacted.stdout).toContain('[PHONE_1]')
      expect(result.redacted.stats.total).toBeGreaterThan(0)
    })
  })

  describe('kubectl', () => {
    it('should build kubectl args correctly for pod exec', async () => {
      // Mock the exec method to avoid actual kubectl calls
      const execSpy = mock(() => Promise.resolve({
        stdout: 'command output',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: 'command output',
          stderr: '',
          stats: { total: 0, byPattern: {} }
        }
      }))

      executor.exec = execSpy

      await executor.kubectl({
        namespace: 'production',
        pod: 'my-pod',
        container: 'app',
        execCommand: 'ls /app',
        level: 'standard'
      })

      const callArgs = execSpy.mock.calls[0]
      expect(callArgs[0].command).toBe('kubectl')
      expect(callArgs[0].args).toContain('--namespace')
      expect(callArgs[0].args).toContain('production')
      expect(callArgs[0].args).toContain('exec')
      expect(callArgs[0].args).toContain('-c')
      expect(callArgs[0].args).toContain('app')
      expect(callArgs[0].args).toContain('my-pod')
    })

    it('should build kubectl args for regular commands', async () => {
      const execSpy = mock(() => Promise.resolve({
        stdout: 'pods listed',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: 'pods listed',
          stderr: '',
          stats: { total: 0, byPattern: {} }
        }
      }))

      executor.exec = execSpy

      await executor.kubectl({
        args: ['get', 'pods'],
        level: 'standard'
      })

      const callArgs = execSpy.mock.calls[0]
      expect(callArgs[0].command).toBe('kubectl')
      expect(callArgs[0].args).toContain('get')
      expect(callArgs[0].args).toContain('pods')
    })

    it('should include context when specified', async () => {
      const execSpy = mock(() => Promise.resolve({
        stdout: 'output',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: 'output',
          stderr: '',
          stats: { total: 0, byPattern: {} }
        }
      }))

      executor.exec = execSpy

      await executor.kubectl({
        context: 'minikube',
        args: ['get', 'pods'],
        level: 'standard'
      })

      const callArgs = execSpy.mock.calls[0]
      expect(callArgs[0].args).toContain('--context')
      expect(callArgs[0].args).toContain('minikube')
    })
  })

  describe('ssh', () => {
    it('should build ssh command with host', async () => {
      const execSpy = mock(() => Promise.resolve({
        stdout: 'remote output',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: 'remote output',
          stderr: '',
          stats: { total: 0, byPattern: {} }
        }
      }))

      executor.exec = execSpy

      await executor.ssh({
        host: 'example.com',
        remoteCommand: 'ls /tmp',
        level: 'standard'
      })

      const callArgs = execSpy.mock.calls[0]
      expect(callArgs[0].command).toBe('ssh')
      expect(callArgs[0].args).toContain('example.com')
      expect(callArgs[0].args).toContain('ls /tmp')
    })

    it('should build ssh command with user and host', async () => {
      const execSpy = mock(() => Promise.resolve({
        stdout: 'output',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: 'output',
          stderr: '',
          stats: { total: 0, byPattern: {} }
        }
      }))

      executor.exec = execSpy

      await executor.ssh({
        host: 'example.com',
        user: 'ubuntu',
        remoteCommand: 'whoami',
        level: 'standard'
      })

      const callArgs = execSpy.mock.calls[0]
      expect(callArgs[0].args).toContain('ubuntu@example.com')
    })

    it('should include port when specified', async () => {
      const execSpy = mock(() => Promise.resolve({
        stdout: 'output',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: 'output',
          stderr: '',
          stats: { total: 0, byPattern: {} }
        }
      }))

      executor.exec = execSpy

      await executor.ssh({
        host: 'example.com',
        port: 2222,
        level: 'standard'
      })

      const callArgs = execSpy.mock.calls[0]
      expect(callArgs[0].args).toContain('-p')
      expect(callArgs[0].args).toContain('2222')
    })

    it('should include identity file when specified', async () => {
      const execSpy = mock(() => Promise.resolve({
        stdout: 'output',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: 'output',
          stderr: '',
          stats: { total: 0, byPattern: {} }
        }
      }))

      executor.exec = execSpy

      await executor.ssh({
        host: 'example.com',
        identity: '~/.ssh/my_key',
        level: 'standard'
      })

      const callArgs = execSpy.mock.calls[0]
      expect(callArgs[0].args).toContain('-i')
      expect(callArgs[0].args).toContain('~/.ssh/my_key')
    })
  })

  describe('execRedacted', () => {
    it('should return only redacted output', async () => {
      const apiKey = 'sk-proj-abc123xyz456def789'
      const result = await executor.execRedacted({
        command: 'echo',
        args: [`My key is ${apiKey}`],
        level: 'standard'
      })

      // Should not contain the actual key
      expect(result).not.toContain(apiKey)
      // Should contain a placeholder
      expect(result).toContain('[OPENAI_KEY_1]')
    })

    it('should include stderr by default', async () => {
      const result = await executor.execRedacted({
        command: 'sh',
        args: ['-c', 'echo stdout; echo stderr >&2'],
        level: 'basic'
      })

      expect(result).toContain('stdout')
      expect(result).toContain('stderr')
    })

    it('should show exit code when requested', async () => {
      const result = await executor.execRedacted({
        command: 'sh',
        args: ['-c', 'exit 42'],
        includeExitCode: true,
        level: 'basic'
      })

      expect(result).toContain('Exit code: 42')
    })

    it('should show timeout message', async () => {
      const result = await executor.execRedacted({
        command: 'sleep',
        args: ['100'],
        timeout: 100,
        level: 'basic'
      })

      expect(result).toContain('Command timed out')
    })

    it('should show termination signal', async () => {
      const result = await executor.execRedacted({
        command: 'sh',
        args: ['-c', 'kill $$'],
        includeExitCode: true,
        level: 'basic'
      })

      expect(result).toMatch(/Terminated by signal:/)
    })
  })

  describe('formatResult', () => {
    it('should format successful result', () => {
      const result = {
        stdout: 'success',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: 'success',
          stderr: '',
          stats: { total: 0, byPattern: {} }
        }
      }

      const formatted = executor.formatResult(result)
      expect(formatted).toContain('Redacted Output')
      expect(formatted).toContain('success')
    })

    it('should format error result', () => {
      const result = {
        stdout: '',
        stderr: 'error occurred',
        exitCode: 1,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: '',
          stderr: 'error occurred',
          stats: { total: 0, byPattern: {} }
        }
      }

      const formatted = executor.formatResult(result)
      expect(formatted).toContain('Exit code: 1')
      expect(formatted).toContain('error occurred')
    })

    it('should format timeout result', () => {
      const result = {
        stdout: '',
        stderr: '',
        exitCode: null,
        signal: 'SIGTERM',
        timedOut: true,
        redacted: {
          stdout: '',
          stderr: '',
          stats: { total: 0, byPattern: {} }
        }
      }

      const formatted = executor.formatResult(result)
      expect(formatted).toContain('Command timed out')
      expect(formatted).toContain('SIGTERM')
    })

    it('should show redaction count', () => {
      const result = {
        stdout: 'api key: sk-proj-123',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: 'api key: [REDACTED]',
          stderr: '',
          stats: { total: 5, byPattern: { 'OPENAI_API_KEY': 5 } }
        }
      }

      const formatted = executor.formatResult(result)
      expect(formatted).toContain('Redacted 5 item(s)')
    })

    it('should show original output when requested', () => {
      const result = {
        stdout: 'sensitive data',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        redacted: {
          stdout: '[REDACTED]',
          stderr: '',
          stats: { total: 1, byPattern: {} }
        }
      }

      const formatted = executor.formatResult(result, true)
      expect(formatted).toContain('ORIGINAL OUTPUT')
      expect(formatted).toContain('sensitive data')
      expect(formatted).toContain('MAY CONTAIN SENSITIVE DATA')
    })
  })

  describe('credential isolation', () => {
    it('should mask credentials in command output while keeping them functional', async () => {
      // This test simulates the core use case:
      // - Credentials work for the actual command (it succeeds)
      // - But output is redacted before LLM sees it

      const apiKey = 'sk-proj-abc123xyz456'
      const dbUrl = 'postgresql://user:password123@localhost:5432/mydb'
      const sqlQuery = `SELECT * FROM users WHERE email = 'user@example.com'`

      // Mock a database query that returns sensitive data
      const result = await executor.exec({
        command: 'echo',
        args: [
          `Connected to DB: ${dbUrl}. Using API key: ${apiKey}. Query: ${sqlQuery}. Results: user@email.com, 555-123-4567, 192.168.1.1`
        ],
        level: 'standard'
      })

      // Command succeeds (exit code 0)
      expect(result.exitCode).toBe(0)

      // Original output contains sensitive data
      expect(result.stdout).toContain(apiKey)
      expect(result.stdout).toContain('password123')
      expect(result.stdout).toContain('user@email.com')
      expect(result.stdout).toContain('555-123-4567')
      expect(result.stdout).toContain('192.168.1.1')

      // Redacted output does NOT contain sensitive data
      expect(result.redacted.stdout).not.toContain(apiKey)
      expect(result.redacted.stdout).not.toContain('user@email.com')
      expect(result.redacted.stdout).not.toContain('555-123-4567')
      expect(result.redacted.stdout).not.toContain('192.168.1.1')

      // But still contains structure/non-sensitive parts
      expect(result.redacted.stdout).toContain('Connected to DB')
      expect(result.redacted.stdout).toContain('Using API key:')
      expect(result.redacted.stdout).toContain('Query:')
      expect(result.redacted.stdout).toContain('Results:')

      // Stats confirm redactions occurred
      expect(result.redacted.stats.total).toBeGreaterThan(0)
    })

    it('should preserve JSON structure while masking values', async () => {
      const jsonOutput = JSON.stringify({
        database_url: 'postgresql://user:password123@localhost:5432/db',
        api_key: 'sk-proj-abc123xyz456',
        admin_email: 'admin@example.com'
      }, null, 2)

      const result = await executor.exec({
        command: 'echo',
        args: [jsonOutput],
        level: 'standard',
        preserveFormat: false
      })

      // Redacted output should preserve structure but mask values
      expect(result.redacted.stdout).toContain('{')
      expect(result.redacted.stdout).toContain('database_url')
      expect(result.redacted.stdout).toContain('api_key')
      expect(result.redacted.stdout).toContain('admin_email')

      // But actual values are redacted
      expect(result.redacted.stdout).not.toContain('password123')
      expect(result.redacted.stdout).not.toContain('sk-proj-abc123xyz456')
      expect(result.redacted.stdout).not.toContain('admin@example.com')
    })

    it('should handle multiple sensitive patterns in one output', async () => {
      const sensitiveOutput = `
        Database: postgresql://user:pass123@localhost/db
        API Key: sk-proj-abcdef123456
        Email: user@example.com
        Phone: 555-123-4567
        IP: 192.168.1.1
        Credit Card: 4532-1234-5678-9010
        SSN: 123-45-6789
      `

      const result = await executor.exec({
        command: 'echo',
        args: [sensitiveOutput],
        level: 'aggressive'
      })

      // Count how many different patterns were redacted
      const patternCount = Object.keys(result.redacted.stats.byPattern).length

      // Should have redacted multiple pattern types
      expect(patternCount).toBeGreaterThan(3)
      expect(result.redacted.stats.total).toBeGreaterThan(5)

      // Verify none of the sensitive data remains
      expect(result.redacted.stdout).not.toContain('pass123')
      expect(result.redacted.stdout).not.toContain('sk-proj-abcdef123456')
      expect(result.redacted.stdout).not.toContain('user@example.com')
      expect(result.redacted.stdout).not.toContain('555-123-4567')
      expect(result.redacted.stdout).not.toContain('192.168.1.1')
      expect(result.redacted.stdout).not.toContain('4532-1234-5678-9010')
      expect(result.redacted.stdout).not.toContain('123-45-6789')
    })
  })
})
