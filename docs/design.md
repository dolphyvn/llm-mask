# llm-mask Feature Expansion - Design Document

## Project Summary
Add 10 features to llm-mask for comprehensive data masking across development workflows.

## Target Users
- Developers using AI coding assistants (Claude Code, Codex, Cursor)
- DevOps engineers integrating LLMs into CI/CD
- Security teams reviewing code with AI assistance

## Problem Statement
Current llm-mask only supports:
- Basic pattern replacement with placeholders like [EMAIL_1]
- Single text input via CLI
- No workflow integration

## Proposed Solution: 10 Features

### 1. Masking Levels
- **basic**: Only API keys/secrets (priority 90+)
- **standard**: + PII (priority 40+)
- **aggressive**: Everything including URLs, paths

### 2. Preserve Format Masking
- Keep structure visible: `j***@a***.com` instead of `[EMAIL_1]`
- Partial masking for readability
- Useful for debugging while protecting data

### 3. Custom Patterns File
- `.llm-mask-rules.json` for project-specific patterns
- Supports CLI and library usage
- Extendable without code changes

### 4. Scan & Report Mode
- Scan entire codebases for secrets
- Report file locations and line numbers
- CI/CD integration ready

### 5. Diff Masking
- Mask git diff output for safe LLM code review
- Preserve line numbers and diff structure
- Works with any git-supported operation

### 6. Smart Context Detection
- Detect SQL, JSON, YAML, code
- Preserve structure (table names, keys)
- Mask only values, not identifiers

### 7. Reversible Tokenization
- Deterministic encryption with salt
- Same input = same token (consistency)
- Safe for production use

### 8. Audit Logging
- Log masking operations without actual values
- Timestamp, pattern type, placeholder only
- File or syslog output

### 9. CI/CD Integration
- GitHub Actions workflow
- Fails build if secrets detected
- Configurable severity levels

### 10. Language-Specific Patterns
- Python: Django SECRET_KEY, SQLAlchemy URLs
- JavaScript: Firebase configs, AWS SDK
- Go: env config structs, etc.
- Auto-detect file type

## Architecture

```
llm-mask/
├── src/
│   ├── masker.ts           # Core masking engine
│   ├── patterns.ts         # Built-in patterns
│   ├── formatters/         # Preserve format formatters
│   │   ├── email.ts
│   │   ├── card.ts
│   │   └── api-key.ts
│   ├── context/            # Smart context detection
│   │   ├── sql.ts
│   │   ├── json.ts
│   │   └── code.ts
│   ├── languages/          # Language-specific patterns
│   │   ├── python.ts
│   │   ├── javascript.ts
│   │   ├── go.ts
│   │   └── detector.ts
│   ├── tokenizer.ts        # Reversible tokenization
│   ├── audit.ts            # Audit logging
│   ├── scanner.ts          # Scan & report
│   ├── diff-masker.ts      # Git diff masking
│   ├── config.ts           # Config file loader
│   ├── cli.ts              # CLI (enhanced)
│   ├── mcp-server.ts       # MCP (enhanced)
│   └── index.ts
├── .github/workflows/
│   └── llm-mask-check.yml  # CI/CD integration
└── .llm-mask-rules.json    # Example custom patterns
```

## Implementation Order

1. **Foundation** (Day 1)
   - Config loader
   - Masking levels
   - Formatters base

2. **Core Features** (Day 1-2)
   - Preserve format masking
   - Custom patterns file
   - Reversible tokenization

3. **Workflow Features** (Day 2-3)
   - Scan & report
   - Diff masking
   - Smart context detection

4. **Language Support** (Day 3-4)
   - Language-specific patterns
   - File type detection

5. **Integration** (Day 4)
   - Audit logging
   - CI/CD workflow
   - MCP server updates

## Success Criteria
- All 10 features implemented
- 38 existing tests still pass
- 40+ new tests for new features
- Documentation updated
- CLI help text complete
