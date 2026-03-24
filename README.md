# llm-mask

> **Mask sensitive data before sending to cloud LLMs. Enable safe AI adoption without compromising security.**

**Version 0.3.0** - Now with exec/kube/ssh commands for credential isolation.

---

## The Problem

Modern AI assistants (Claude, GPT-4, etc.) are incredibly powerful, but using them with internal systems poses significant security risks:

- **Credential leakage**: API keys, passwords, tokens accidentally exposed to LLMs
- **Data exposure**: Customer data, internal IPs, employee PII sent to external services
- **Compliance violations**: HIPAA, GDPR, SOX requirements prevent cloud LLM usage
- **Shadow IT**: Teams use unauthorized AI tools, creating unmonitored data flows

**Result**: Security teams block cloud LLM access entirely, and the organization loses out on AI productivity gains.

---

## The Solution

`llm-mask` is a security tool that **redacts sensitive data before it reaches the LLM**, while preserving the semantic structure needed for analysis:

```bash
# Before: Risky
echo "Check the API logs at https://internal.company.com/logs using key sk-proj-abc123" | claude

# After: Safe
echo "Check the API logs at https://internal.company.com/logs using key sk-proj-abc123" | llm-mask | claude
# Output: "Check the API logs at h***://i********.c********.c**/l*** using key s**-p**-a**"
```

**What makes it different:**
- ✅ **Format-preserving masking**: `j***@a***.com` instead of `[EMAIL_1]` - LLM can still analyze patterns
- ✅ **Credential isolation**: Run commands with real credentials, output redacted for LLMs
- ✅ **Context-aware**: Understands SQL, JSON, YAML - masks values, preserves structure
- ✅ **Deterministic**: Same input always produces same output - safe for logging

---

## Security Objectives

| Objective | How It's Achieved |
|-----------|-------------------|
| **Zero data exposure** | Sensitive values redacted before leaving your machine |
| **Credential isolation** | Commands execute with real creds, output sanitized before LLM sees it |
| **Audit-safe logging** | Only masked data in logs, no secrets in memory or disk |
| **Compliance-ready** | Helps meet HIPAA/GDPR/SOX requirements for data handling |
| **No semantic loss** | Preserved structure lets LLMs analyze without seeing sensitive values |
| **Deterministic** | Same input → same output, reversible with your salt (optional) |

---

## Features

✅ **23 Built-in Patterns** - API keys, emails, IPs, PII, URLs, UUIDs, hashes, file paths
✅ **Credential Isolation** - Execute commands with real credentials, output redacted for LLMs
✅ **Kubernetes Support** - Run kubectl commands safely with automatic redaction
✅ **SSH Support** - Execute remote commands without exposing credentials
✅ **Masking Levels** - basic (secrets), standard (+PII), aggressive (everything)
✅ **Preserve Format** - `j***@a***.com` instead of `[EMAIL_1]`
✅ **Custom Patterns** - Define your own via config file
✅ **Scan Codebases** - Find secrets in entire projects
✅ **Diff Masking** - Safe git diff for LLM code review
✅ **Context Detection** - Smart masking for SQL, JSON, YAML
✅ **Language Patterns** - Python, JavaScript, Go, Ruby, Terraform
✅ **Reversible Tokenization** - Deterministic encryption with salt
✅ **Audit Logging** - Safe logging without actual values
✅ **CI/CD Integration** - GitHub Actions workflow included

## Quick Start

```bash
npm install -g llm-mask
```

### Basic Usage

```bash
# Mask sensitive data
echo "API key sk-proj-abc123 expired for john@acme.com" | llm-mask

# Preserve format for readability
llm-mask --preserve-format "Contact john@acme.com"

# Mask only secrets (not emails)
llm-mask --level basic "Contact john@acme.com with key sk-abc123"

# Scan codebase for secrets
llm-mask scan ./src

# Mask git diff for safe code review
git diff main | llm-mask diff

# Context-aware masking (preserves structure)
llm-mask --context '{"user": "john@acme.com", "key": "sk-abc123"}'

# Execute commands with credential isolation
llm-mask exec kubectl get secrets -n production
llm-mask kube -n production get secrets
llm-mask ssh user@server "cat /etc/secrets/db.conf"
```

## Credential Isolation (NEW!)

The core principle: **Credentials work for the command, but output is redacted before the LLM sees it.**

### Exec Command

Run any command and automatically redact sensitive output:

```bash
# Show environment variables without exposing actual values
llm-mask exec env | grep -i key

# Run database queries safely
llm-mask exec psql -c "SELECT * FROM users"

# Check AWS credentials without revealing them
llm-mask exec aws sts get-caller-identity
```

### Kubernetes Command

Execute kubectl commands with automatic redaction:

```bash
# List secrets (values are masked)
llm-mask kube -n production get secrets

# Execute into a pod and run commands
llm-mask kube -n production --pod my-app --exec "env | grep -i password"

# Get config with credentials masked
llm-mask kube -n staging config

# Full kubectl command passthrough with redaction
llm-mask kube --context minikube get pods -o yaml
```

### SSH Command

Execute commands on remote servers without exposing credentials in LLM context:

```bash
# Execute remote command with redacted output
llm-mask ssh user@production-server "cat /etc/secrets/app.conf"

# With custom port and identity
llm-mask ssh -p 2222 -i ~/.ssh/deploy_key deploy@server "systemctl status"

# Interactive mode (for debugging, output is still redacted)
llm-mask ssh user@test-server
```

### Example Use Case

Debugging a Kubernetes issue with an LLM:

```bash
# Without llm-mask - DANGER!
kubectl get secrets -n production
# Output: password=SuperSecret123, api_key=sk-proj-abc123

# With llm-mask - SAFE!
llm-mask kube -n production get secrets
# Output: password=[CREDENTIALS_1], api_key=[OPENAI_KEY_1]
# 🔒 Redacted 2 item(s)

# Now you can share this with an LLM for debugging
# without leaking actual credentials!
```

## Features Deep Dive

### 1. Masking Levels

Control what gets masked:

```bash
--level basic       # Only API keys/secrets (priority 90+)
--level standard    # + PII like emails, phones (priority 40+) [default]
--level aggressive  # Everything including URLs, file paths
```

### 2. Preserve Format

Keep structure visible while protecting values:

```bash
$ llm-mask --preserve-format "Email: john@acme.com"
Email: j***@a***.com

$ llm-mask --preserve-format "Card: 4111 1111 1111 1111"
Card: 4111 ************ 1111
```

### 3. Custom Patterns File

Create `.llm-mask-rules.json` in your project:

```json
{
  "customPatterns": [
    {
      "name": "employee_id",
      "regex": "\\bEMP-[0-9]{6}\\b",
      "placeholder": "[EMPLOYEE_ID_{i}]"
    },
    {
      "name": "internal_ticket",
      "regex": "\\bTICKET-[A-Z]{3}-[0-9]{4}\\b",
      "placeholder": "[TICKET_{i}]"
    }
  ],
  "defaultLevel": "standard",
  "auditLog": true
}
```

### 4. Scan & Report

Scan entire codebases for leaked secrets:

```bash
$ llm-mask scan ./src

🔍 llm-mask Scan Report

Scanned: 47 files
Skipped: 123 files
Findings: 3 sensitive pattern(s)

⚠️  Findings:

config.ts:
  ❌ Line 15: openai_api_key
    const apiKey = "sk-proj-abc123xyz789abcdef123"

.env.example:
  ⚠️  Line 8: email
    support@example.com

db.ts:
  ❌ Line 42: url_with_creds
    postgresql://admin:password@localhost/db
```

### 5. Diff Masking

Safe code review with LLMs:

```bash
# Mask git diff output
git diff main | llm-mask diff

# Or use the diff mode directly
llm-mask diff --base main --head feature-branch
```

### 6. Context Detection

Smart masking that preserves structure:

```bash
# JSON - preserves keys, masks values
$ llm-mask --context '{"email": "john@test.com"}'
{"email": "[EMAIL_1]"}

# SQL - preserves identifiers, masks literals
$ llm-mask --context "SELECT * FROM users WHERE email = 'john@test.com'"
SELECT * FROM users WHERE email = '[EMAIL_1]'

# YAML - preserves keys, masks values
$ llm-mask --context "api_key: sk-proj-abc123"
api_key: [OPENAI_KEY_1]
```

### 7. Language-Specific Patterns

Automatically detects and masks language-specific patterns:

| Language | Patterns |
|----------|----------|
| Python | Django SECRET_KEY, SQLAlchemy URLs, boto3 keys |
| JavaScript/TypeScript | Firebase configs, JWT tokens, MongoDB URIs |
| Go | AWS SDK configs, env structs |
| Ruby | Rails secret_key_base, DB passwords |
| Terraform | AWS access/secret keys |

### 8. Reversible Tokenization

For production use with deterministic encryption:

```typescript
import { Tokenizer } from 'llm-mask'

const tokenizer = new Tokenizer({
  salt: 'your-secure-salt-here'  // Generate with: llm-tokenizer-generate-salt
})

// Tokenize (deterministic - same input = same output)
const token = tokenizer.tokenize('john@test.com')
// Returns: "tok_a1b2c3d4e5f6g7h8"

// Verify without storing mappings
tokenizer.verify(token, 'john@test.com')  // true
tokenizer.verify(token, 'wrong@email.com')  // false
```

### 9. Audit Logging

Safe logging without sensitive values:

```typescript
import { AuditLogger } from 'llm-mask'

const logger = new AuditLogger({
  file: './audit.log',
  console: true
})

logger.log({
  timestamp: 1234567890,
  patternName: 'email',
  placeholder: '[EMAIL_1]',
  inputLength: 123,
  context: 'user-registration'
})
```

### 10. CI/CD Integration

GitHub Actions workflow included:

```yaml
# .github/workflows/llm-mask-check.yml
name: llm-mask - Check for Leaked Secrets
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx llm-mask scan . --fail-on-detect
```

## CLI Options

```
Usage: llm-mask [options] [text]

Options:
  --check, -c         Dry run: show what would be masked
  --level, -l         Masking level (basic|standard|aggressive)
  --preserve-format, -f  Preserve format (j***@a***.com)
  --context           Smart context detection (SQL, JSON, etc.)
  --unmask, -u        Unmask previously masked text
  --patterns, -p      List all available patterns
  --json, -j          Output as JSON
  --config <path>     Path to config file

Commands:
  exec [command...]   Execute command with output redaction
  kube [kubectl-args] Execute kubectl with output redaction
  ssh <host>          Execute SSH command with output redaction
  scan [path]         Scan codebase for secrets
  diff                Mask git diff output
  patterns            List all available patterns

Examples:
  # Pipe mode
  echo "API key sk-proj-123" | llm-mask

  # Exec commands
  llm-mask exec env | grep -i key
  llm-mask kube -n production get secrets
  llm-mask ssh user@server "cat /etc/secrets/app.conf"

  # Scan codebase
  llm-mask scan ./src --fail-on-detect

  # Git diff
  git diff main | llm-mask diff

  # Preserve format
  llm-mask --preserve-format "Contact john@acme.com"
```

## Built-in Patterns

| Category | Patterns | Example |
|----------|----------|---------|
| API Keys | OpenAI, Anthropic, Stripe, AWS, GitHub, JWT | `[OPENAI_KEY_1]` |
| PII | Emails, SSNs, Credit Cards, Phones | `[EMAIL_1]` |
| URLs | URLs with credentials, internal URLs | `[CREDENTIALS_1]@` |
| Network | IPv4, IPv6 | `[IP_1]` |
| Identifiers | UUIDs, SHA256, MD5 hashes | `[UUID_1]` |
| Files | Unix paths, Windows paths | `[PATH_1]` |

## MCP Server

Add to Claude Code settings.json:

```json
{
  "mcpServers": {
    "llm-mask": {
      "command": "node",
      "args": ["/path/to/llm-mask/dist/mcp-server.js"]
    }
  }
}
```

Available tools:
- `mask_data` - Mask text with options
- `unmask_data` - Unmask (trusted only)
- `check_masking` - Dry run
- `scan_directory` - Scan codebase
- `mask_diff` - Mask git diff
- `mask_context` - Context-aware masking
- `list_patterns` - List patterns
- `clear_mappings` - Clear memory
- `exec_redacted` - Execute command with output redaction (NEW!)
- `kube_exec` - Execute kubectl with redaction (NEW!)
- `ssh_exec` - Execute SSH command with redaction (NEW!)

## Security & Data Protection

### How It Works

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Claude     │  asks   │  llm-mask   │  sends  │  LLM API    │
│  Code       │────────▶│  MCP Server │────────▶│  (Claude)   │
│  (Local)    │         │  (Local)    │         │  (Remote)   │
└─────────────┘         └─────────────┘         └─────────────┘
      │                       │                        │
      │                       │  masked data           │
      │                       │  only                  │
      └───────────────────────┴────────────────────────┘
                 Your sensitive data NEVER leaves your machine
```

**The key insight**: llm-mask runs **locally on your machine**. The MCP server:
1. Receives requests from Claude Code
2. Masks the data **before** anything leaves your machine
3. Sends only masked data to the LLM

### What is Protected ✅

| Scenario | Protected? | How |
|----------|-----------|-----|
| Explicit masking via MCP tools | ✅ Yes | Data masked locally before sending |
| Using `exec_redacted` tool | ✅ Yes | Command runs locally, output masked before LLM sees it |
| Using `kube_exec` tool | ✅ Yes | Credentials work for kubectl, output is masked |
| Using `ssh_exec` tool | ✅ Yes | Credentials work for SSH, output is masked |

### What is NOT Protected ⚠️

| Scenario | Risk | Why |
|----------|------|-----|
| You paste sensitive data directly in chat | ❌ Not protected | Goes straight to LLM without masking |
| You share file contents without masking | ❌ Not protected | File content sent directly to LLM |
| Claude Code reads files independently | ❌ Not protected | MCP doesn't intercept file reads |

### Example Usage

```typescript
// ❌ BAD - Pasting directly (NOT protected)
User: "Help me debug this error with API key sk-proj-abc123"
// → The key goes directly to Claude's API

// ✅ GOOD - Using MCP tool (protected)
User: "Help me debug this error"
[Claude uses mask_data tool]
// → Data masked locally, only [OPENAI_KEY_1] sent to LLM

// ✅ GOOD - Using exec_redacted (credential isolation)
User: "Check why my kubernetes secrets are failing"
[Claude uses kube_exec tool]
// → kubectl runs with your credentials
// → Output masked: "password=[CREDENTIALS_1]"
// → LLM sees structure but NOT actual credentials
```

### Security Model

```
Your Machine                          Remote (Anthropic)
─────────────                        ────────────────────
┌─────────────────────────────────────────────────────────┐
│  Sensitive Data: sk-proj-abc123xyz456                    │
│                                                           │
│  MCP Server masks it → [OPENAI_KEY_1]                    │
│                                                           │
│  Only this is sent → [OPENAI_KEY_1]  ──────────────▶    │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

### Important Limitations

1. **You must actively use the MCP tools** - Claude won't automatically mask everything
2. **File reads bypass MCP** - When Claude reads files directly, that data isn't masked
3. **MCP mappings are ephemeral** - Stored only in memory, cleared when MCP server restarts
4. **Trust model** - You're trusting the llm-mask code running locally

### Best Practices

```bash
# 1. Scan your codebase before sharing
llm-mask scan ./src

# 2. Use exec_redacted for command output
llm-mask exec kubectl get secrets

# 3. Mask git diffs before sharing
git diff main | llm-mask diff

# 4. When in doubt, pipe through llm-mask
cat sensitive-file.json | llm-mask | llm # share masked output
```

### Summary

**Yes, your sensitive data is protected** WHEN you use the MCP tools. But it's not automatic - you (or Claude) need to explicitly use the masking tools. The protection happens **locally before anything leaves your machine**.

## Library Usage

```typescript
import {
  mask,
  unmask,
  clearMasker,
  Scanner,
  ContextMasker,
  Tokenizer,
  SecureExecutor
} from 'llm-mask'

// Basic masking
const { masked, mappings, stats } = mask("Email: john@test.com")

// Preserve format
const { masked } = mask("john@test.com", { preserveFormat: true })

// Masking levels
const { masked } = mask(text, { level: 'basic' })

// Context-aware
const contextMasker = new ContextMasker()
const { masked, context } = contextMasker.mask(jsonString)

// Scan codebase
const scanner = new Scanner({ failOnDetect: true })
const report = await scanner.scan('./src')

// Tokenization
const tokenizer = new Tokenizer({ salt: 'secure-salt' })
const token = tokenizer.tokenize('sensitive-value')

// Execute commands with credential isolation
const executor = new SecureExecutor()
const result = await executor.exec({
  command: 'kubectl',
  args: ['get', 'secrets', '-n', 'production'],
  level: 'standard'
})
// result.stdout - original output with credentials
// result.redacted.stdout - masked output for LLM

// Kubernetes convenience
const kubeResult = await executor.kubectl({
  namespace: 'production',
  pod: 'my-app',
  execCommand: 'env',
  level: 'standard'
})

// SSH convenience
const sshResult = await executor.ssh({
  host: 'server.example.com',
  user: 'admin',
  remoteCommand: 'cat /etc/secrets/app.conf',
  level: 'standard'
})

// Clear sensitive data from memory
clearMasker()
```

## License

MIT
