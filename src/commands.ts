/**
 * CLI commands for exec functionality
 */

import { Command } from 'commander'
import { SecureExecutor } from './executor.js'

/**
 * Register exec commands with commander program
 */
export function registerExecCommands(program: Command): void {
  // Main exec command
  program
    .command('exec [command...]')
    .description('Execute a command and redact sensitive output')
    .option('-l, --level <level>', 'Masking level (basic|standard|aggressive)', 'standard')
    .option('-f, --preserve-format', 'Preserve format in redacted output')
    .option('-t, --timeout <ms>', 'Command timeout in milliseconds', '30000')
    .option('--original', 'Show original output (WARNING: contains sensitive data)')
    .option('--json', 'Output as JSON')
    .action(async (command, options) => {
      if (!command || command.length === 0) {
        console.error('Error: command required')
        process.exit(1)
      }

      const executor = new SecureExecutor()

      try {
        const result = await executor.exec({
          command: command[0],
          args: command.slice(1),
          timeout: parseInt(options.timeout),
          level: options.level,
          preserveFormat: options.preserveFormat
        })

        if (options.json) {
          console.log(JSON.stringify(result, null, 2))
        } else {
          console.log(executor.formatResult(result, options.original))
        }

        // Exit with the same code as the command
        if (result.exitCode !== null) {
          process.exit(result.exitCode)
        }
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : error)
        process.exit(1)
      }
    })

  // Kubernetes command
  program
    .command('kube [kubectl-args...]')
    .description('Execute kubectl commands with output redaction')
    .option('-n, --namespace <ns>', 'Kubernetes namespace')
    .option('-c, --context <ctx>', 'Kubectl context')
    .option('--pod <pod>', 'Pod name (for exec)')
    .option('--container <container>', 'Container name (for exec)')
    .option('--exec <cmd>', 'Command to execute in pod')
    .option('-l, --level <level>', 'Masking level', 'standard')
    .option('-f, --preserve-format', 'Preserve format in output')
    .option('--json', 'Output as JSON')
    .action(async (kubectlArgs, options) => {
      const executor = new SecureExecutor()

      try {
        const result = await executor.kubectl({
          args: kubectlArgs.length > 0 ? kubectlArgs : ['get', 'pods', '-o', 'wide'],
          namespace: options.namespace,
          context: options.context,
          pod: options.pod,
          container: options.container,
          execCommand: options.exec,
          level: options.level,
          preserveFormat: options.preserveFormat
        })

        if (options.json) {
          console.log(JSON.stringify(result, null, 2))
        } else {
          console.log(executor.formatResult(result))
        }
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : error)
        process.exit(1)
      }
    })

  // SSH command
  program
    .command('ssh <host>')
    .description('Execute SSH commands with output redaction')
    .option('-u, --user <user>', 'SSH user')
    .option('-p, --port <port>', 'SSH port')
    .option('-i, --identity <file>', 'Identity file (private key)')
    .option('-c, --command <cmd>', 'Command to execute on remote host')
    .option('-l, --level <level>', 'Masking level', 'standard')
    .option('-f, --preserve-format', 'Preserve format in output')
    .option('--json', 'Output as JSON')
    .action(async (host, options) => {
      const executor = new SecureExecutor()

      try {
        const result = await executor.ssh({
          host,
          user: options.user,
          port: options.port ? parseInt(options.port) : undefined,
          identity: options.identity,
          remoteCommand: options.command,
          level: options.level,
          preserveFormat: options.preserveFormat
        })

        if (options.json) {
          console.log(JSON.stringify(result, null, 2))
        } else {
          console.log(executor.formatResult(result))
        }
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : error)
        process.exit(1)
      }
    })
}
