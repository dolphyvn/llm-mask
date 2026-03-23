/**
 * Enhanced MCP Server for llm-mask
 *
 * Provides tools for Claude Code and other AI agents
 *
 * New in v0.3: Secure exec tools - run commands without exposing credentials to LLM
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from '@modelcontextprotocol/sdk/types.js'
import { DataMasker } from './masker.js'
import { Scanner } from './scanner.js'
import { DiffMasker } from './diff-masking.js'
import { ContextMasker } from './context-detection.js'
import { BUILTIN_PATTERNS } from './patterns.js'
import { SecureExecutor } from './executor.js'

const masker = new DataMasker()
const scanner = new Scanner()
const diffMasker = new DiffMasker()
const contextMasker = new ContextMasker()
const executor = new SecureExecutor()

const TOOLS: Tool[] = [
  // === Original masking tools ===
  {
    name: 'mask_data',
    description: `Mask sensitive data (API keys, emails, IPs, PII) before sending to LLM.`,
    inputSchema: {
      type: 'object',
      properties: {
        text: {
          type: 'string',
          description: 'The text to mask'
        },
        level: {
          type: 'string',
          enum: ['basic', 'standard', 'aggressive']
        },
        preserveFormat: {
          type: 'boolean',
          description: 'Preserve format (j***@a***.com instead of [EMAIL_1])'
        }
      },
      required: ['text']
    }
  },
  {
    name: 'check_masking',
    description: 'Dry-run: Check what WOULD be masked.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string' },
        level: { type: 'string', enum: ['basic', 'standard', 'aggressive'] }
      },
      required: ['text']
    }
  },
  {
    name: 'scan_directory',
    description: 'Scan a directory for sensitive data (secrets, API keys, PII).',
    inputSchema: {
      type: 'object',
      properties: {
        directory: { type: 'string' },
        level: { type: 'string', enum: ['basic', 'standard', 'aggressive'] },
        extensions: { type: 'string' }
      },
      required: ['directory']
    }
  },
  {
    name: 'mask_diff',
    description: 'Mask git diff output for safe LLM code review.',
    inputSchema: {
      type: 'object',
      properties: {
        base: { type: 'string' },
        head: { type: 'string' },
        path: { type: 'string' },
        level: { type: 'string', enum: ['basic', 'standard', 'aggressive'] }
      }
    }
  },
  {
    name: 'mask_context',
    description: `Context-aware masking - detects SQL, JSON, YAML and masks only values while preserving structure.`,
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string' }
      },
      required: ['text']
    }
  },
  {
    name: 'list_patterns',
    description: 'List all available masking patterns.',
    inputSchema: {
      type: 'object',
      properties: {
        filter: { type: 'string' }
      }
    }
  },
  {
    name: 'clear_mappings',
    description: 'Clear all in-memory mappings.',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },

  // === NEW: Secure exec tools ===
  {
    name: 'exec_redacted',
    description: `Execute a command and return redacted output (safe for LLM).

IMPORTANT: The command executes with REAL credentials, but the output
is redacted before the LLM sees it. Useful for:
- Running kubectl to inspect clusters
- Running commands that might output secrets
- Executing scripts with sensitive output

The LLM never sees: actual passwords, API keys, IPs, etc.
The command still works: credentials are functional`,
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: 'Command to execute (e.g., "kubectl", "cat", "ls")'
        },
        args: {
          type: 'array',
          items: { type: 'string' },
          description: 'Command arguments'
        },
        cwd: {
          type: 'string',
          description: 'Working directory'
        },
        timeout: {
          type: 'number',
          description: 'Timeout in milliseconds (default: 30000)'
        },
        level: {
          type: 'string',
          enum: ['basic', 'standard', 'aggressive'],
          description: 'Redaction level'
        },
        preserveFormat: {
          type: 'boolean',
          description: 'Preserve format in redacted output'
        },
        includeStderr: {
          type: 'boolean',
          description: 'Include stderr in output'
        }
      },
      required: ['command']
    }
  },
  {
    name: 'kube_exec',
    description: `Execute kubectl commands with redacted output.

Supports:
- Regular kubectl commands (get, describe, apply, etc.)
- Pod exec (run commands in containers)
- All kubectl flags (--namespace, --context, etc.)

Example: { "command": "get", "args": ["pods", "-o", "wide"] }`,
    inputSchema: {
      type: 'object',
      properties: {
        args: {
          type: 'array',
          items: { type: 'string' },
          description: 'kubectl arguments (e.g., ["get", "pods", "-o", "wide"])'
        },
        namespace: {
          type: 'string',
          description: 'Kubernetes namespace'
        },
        context: {
          type: 'string',
          description: 'kubectl context'
        },
        pod: {
          type: 'string',
          description: 'Pod name (for exec operations)'
        },
        container: {
          type: 'string',
          description: 'Container name (for pod exec)'
        },
        remoteCommand: {
          type: 'string',
          description: 'Command to execute in pod (for pod exec)'
        },
        level: {
          type: 'string',
          enum: ['basic', 'standard', 'aggressive']
        },
        preserveFormat: {
          type: 'boolean'
        },
        timeout: {
          type: 'number'
        }
      },
      required: ['args']
    }
  },
  {
    name: 'ssh_exec',
    description: `Execute SSH commands with redacted output.

Supports:
- Remote command execution
- Custom identity files
- Port and user specification
- All SSH options

Example: { "host": "server.example.com", "command": "ls -la /etc" }`,
    inputSchema: {
      type: 'object',
      properties: {
        host: {
          type: 'string',
          description: 'SSH host (required)'
        },
        user: {
          type: 'string',
          description: 'SSH user'
        },
        port: {
          type: 'number',
          description: 'SSH port'
        },
        identity: {
          type: 'string',
          description: 'Path to private key file'
        },
        command: {
          type: 'string',
          description: 'Command to execute on remote host'
        },
        level: {
          type: 'string',
          enum: ['basic', 'standard', 'aggressive']
        },
        preserveFormat: {
          type: 'boolean'
        },
        timeout: {
          type: 'number'
        }
      },
      required: ['host']
    }
  }
]

const server = new Server(
  {
    name: 'llm-mask',
    version: '0.3.0'
  },
  {
    capabilities: {
      tools: {}
    }
  }
)

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: TOOLS }
})

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params

  try {
    switch (name) {
      // === Masking tools ===
      case 'mask_data': {
        const text = args?.text as string
        const result = masker.mask(text, {
          level: (args?.level as any) || 'standard',
          preserveFormat: args?.preserveFormat as boolean || false
        })

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              masked: result.masked,
              stats: result.stats
            }, null, 2)
          }]
        }
      }

      case 'check_masking': {
        const text = args?.text as string
        const result = masker.mask(text, { level: (args?.level as any) || 'standard' })

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              wouldMask: result.stats
            }, null, 2)
          }]
        }
      }

      case 'scan_directory': {
        const report = await scanner.scan(args?.directory as string || '.')
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              scans: report.scans,
              summary: report.summary,
              findings: report.findings.slice(0, 50)
            }, null, 2)
          }]
        }
      }

      case 'mask_diff': {
        const result = diffMasker.maskDiff({
          base: args?.base as string | undefined,
          head: args?.head as string | undefined,
          level: (args?.level as any) || 'standard',
          path: args?.path as string | undefined
        })

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              maskedDiff: result.maskedDiff,
              stats: result.stats
            }, null, 2)
          }]
        }
      }

      case 'mask_context': {
        const text = args?.text as string
        const result = contextMasker.mask(text)

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              masked: result.masked,
              context: result.context,
              stats: result.stats
            }, null, 2)
          }]
        }
      }

      case 'list_patterns': {
        const filter = args?.filter as string | undefined
        let patterns = BUILTIN_PATTERNS
        if (filter) {
          patterns = patterns.filter(p => p.name.includes(filter))
        }

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              patterns: patterns.map(p => ({
                name: p.name,
                priority: p.priority,
                example: p.placeholder(1)
              })),
              total: patterns.length
            }, null, 2)
          }]
        }
      }

      case 'clear_mappings': {
        const count = masker.getMappingCount()
        masker.clear()

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              cleared: true,
              mappingsRemoved: count
            }, null, 2)
          }]
        }
      }

      // === NEW: Secure exec tools ===
      case 'exec_redacted': {
        const result = await executor.exec({
          command: args?.command as string,
          args: args?.args as string[] | undefined,
          cwd: args?.cwd as string | undefined,
          timeout: args?.timeout as number | undefined,
          level: (args?.level as any) || 'standard',
          preserveFormat: args?.preserveFormat as boolean || false,
          includeStderr: args?.includeStderr as boolean !== false
        })

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              redacted: {
                output: result.redacted.stdout,
                stderr: result.redacted.stderr,
                stats: result.redacted.stats
              },
              exitCode: result.exitCode,
              signal: result.signal,
              timedOut: result.timedOut,
              warning: 'Original output contains sensitive data and was redacted'
            }, null, 2)
          }]
        }
      }

      case 'kube_exec': {
        const result = await executor.kubectl({
          args: args?.args as string[],
          namespace: args?.namespace as string | undefined,
          context: args?.context as string | undefined,
          pod: args?.pod as string | undefined,
          container: args?.container as string | undefined,
          execCommand: args?.remoteCommand as string | undefined,
          level: (args?.level as any) || 'standard',
          preserveFormat: args?.preserveFormat as boolean || false,
          timeout: args?.timeout as number | undefined
        })

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              redacted: {
                output: result.redacted.stdout,
                stderr: result.redacted.stderr,
                stats: result.redacted.stats
              },
              exitCode: result.exitCode,
              signal: result.signal,
              timedOut: result.timedOut
            }, null, 2)
          }]
        }
      }

      case 'ssh_exec': {
        const result = await executor.ssh({
          host: args?.host as string,
          user: args?.user as string | undefined,
          port: args?.port as number | undefined,
          identity: args?.identity as string | undefined,
          remoteCommand: args?.command as string | undefined,
          level: (args?.level as any) || 'standard',
          preserveFormat: args?.preserveFormat as boolean || false,
          timeout: args?.timeout as number | undefined
        })

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              redacted: {
                output: result.redacted.stdout,
                stderr: result.redacted.stderr,
                stats: result.redacted.stats
              },
              exitCode: result.exitCode,
              signal: result.signal,
              timedOut: result.timedOut
            }, null, 2)
          }]
        }
      }

      default:
        throw new Error(`Unknown tool: ${name}`)
    }
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: error instanceof Error ? error.message : String(error),
          tool: name
        })
      }],
      isError: true
    }
  }
})

async function main() {
  const transport = new StdioServerTransport()
  await server.connect(transport)

  console.error('llm-mask MCP server running (v0.3.0)')
}

main().catch((error) => {
  console.error('Fatal error:', error)
  process.exit(1)
})
