/**
 * Built-in masking patterns
 * These are organized by priority (higher = applied first)
 */

import type { MaskPattern } from './types.js'

/**
 * Built-in patterns for detecting sensitive data
 *
 * Priority order:
 * 1. API keys and secrets (most specific, most sensitive)
 * 2. Auth tokens and session IDs
 * 3. PII (emails, phones, SSNs, credit cards)
 * 4. Network identifiers (IPs, domains, URLs)
 * 5. Internal identifiers (UUIDs, potentially-sensitive numbers)
 */
export const BUILTIN_PATTERNS: MaskPattern[] = [
  // ===== Priority 100: API Keys and Secrets =====
  {
    name: 'anthropic_api_key',
    regex: /\b(sk-ant-[a-zA-Z0-9\-_]{20,})\b/g,
    placeholder: (i) => `[ANTHROPIC_KEY_${i}]`,
    priority: 100
  },
  {
    name: 'openai_api_key',
    regex: /\b(sk(-proj)?-[a-zA-Z0-9]{10,})\b/g,
    placeholder: (i) => `[OPENAI_KEY_${i}]`,
    priority: 100
  },
  {
    name: 'stripe_live_key',
    regex: /\b(sk_live_[a-zA-Z0-9]{24,})\b/g,
    placeholder: (i) => `[STRIPE_LIVE_KEY_${i}]`,
    priority: 100
  },
  {
    name: 'stripe_test_key',
    regex: /\b(sk_test_[a-zA-Z0-9]{24,})\b/g,
    placeholder: (i) => `[STRIPE_TEST_KEY_${i}]`,
    priority: 100
  },
  {
    name: 'aws_access_key',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    placeholder: (i) => `[AWS_ACCESS_KEY_${i}]`,
    priority: 100
  },
  {
    name: 'github_token',
    regex: /\b(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}\b/g,
    placeholder: (i) => `[GITHUB_TOKEN_${i}]`,
    priority: 100
  },
  {
    name: 'jwt_token',
    regex: /\b(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b/g,
    placeholder: (i) => `[JWT_${i}]`,
    priority: 100
  },
  // Generic API key patterns (must come after specific ones)
  {
    name: 'api_key_equals',
    regex: /(['"]?(api_key|apikey|api-key|x-api-key|authorization|bearer|token)['"]?\s*[:=]\s*['"]?)([a-zA-Z0-9\-_\.]{16,})(['"]?)/gi,
    placeholder: (i) => `$1[API_KEY_${i}]$4`,
    priority: 95
  },
  {
    name: 'aws_secret',
    regex: /(['"]?(aws_secret_access_key|secret_access_key|secret_key)['"]?\s*[:=]\s*['"]?)([a-zA-Z0-9/+=]{16,})(['"]?)/gi,
    placeholder: (i) => `$1[AWS_SECRET_${i}]$4`,
    priority: 95
  },
  {
    name: 'session_token',
    regex: /(['"]?(session|session_id|sessionid|sess)['"]?\s*[:=]\s*['"]?)([a-zA-Z0-9\-_]{16,})(['"]?)/gi,
    placeholder: (i) => `$1[SESSION_${i}]$4`,
    priority: 90
  },

  // ===== Priority 80: PII =====
  {
    name: 'email',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    placeholder: (i) => `[EMAIL_${i}]`,
    priority: 80
  },
  {
    name: 'ssn',
    regex: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g,
    placeholder: (i) => `[SSN_${i}]`,
    priority: 80
  },
  {
    name: 'credit_card',
    regex: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    placeholder: (i) => `[CARD_${i}]`,
    priority: 80
  },
  {
    name: 'phone_us',
    regex: /\b(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
    placeholder: (i) => `[PHONE_${i}]`,
    priority: 80
  },

  // ===== Priority 60: URLs =====
  {
    name: 'url_with_creds',
    regex: /\b([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^:/\s]+):([^\s@/]+)@/g,
    placeholder: (i) => `$1[CREDENTIALS_${i}]@`,
    priority: 60
  },
  {
    name: 'url_internal',
    regex: /\bhttps?:\/\/(?:[a-zA-Z0-9-]+\.)?(?:internal|private|localhost|127\.0\.0\.1|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)[^\s]*\b/gi,
    placeholder: (i) => `[INTERNAL_URL_${i}]`,
    priority: 55
  },

  // ===== Priority 40: Network =====
  {
    name: 'ip_address',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    placeholder: (i) => `[IP_${i}]`,
    priority: 40
  },
  {
    name: 'ipv6',
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    placeholder: (i) => `[IPV6_${i}]`,
    priority: 40
  },

  // ===== Priority 30: Identifiers =====
  {
    name: 'uuid',
    regex: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    placeholder: (i) => `[UUID_${i}]`,
    priority: 30
  },
  {
    name: 'hash_sha256',
    regex: /\b[a-f0-9]{64}\b/g,
    placeholder: (i) => `[SHA256_${i}]`,
    priority: 25
  },
  {
    name: 'hash_md5',
    regex: /\b[a-f0-9]{32}\b/g,
    placeholder: (i) => `[MD5_${i}]`,
    priority: 25
  },

  // ===== Priority 20: File Paths =====
  {
    name: 'file_path_unix',
    regex: /\/(?:home|Users|var|etc|opt|usr|root|tmp)\/[^\s<>"{}|\\^`\[\]]*/g,
    placeholder: (i) => `[PATH_${i}]`,
    priority: 20
  },
  {
    name: 'file_path_windows',
    regex: /(?:[A-Z]:\\(?:Users|Program Files|Windows|ProgramData|temp)[^\s<>"{}|\\^`\[\]]*)|(?:\\\\[^\s<>"{}|\\^`\[\]]+)/g,
    placeholder: (i) => `[PATH_${i}]`,
    priority: 20
  }
]

/**
 * Get patterns by mask level
 */
export function getPatternsByLevel(level: string): MaskPattern[] {
  const priority = (p: MaskPattern) => p.priority ?? 50
  switch (level) {
    case 'basic':
      return BUILTIN_PATTERNS.filter(
        p => priority(p) >= 90
      )
    case 'standard':
      return BUILTIN_PATTERNS.filter(p => priority(p) >= 40)
    case 'aggressive':
      return BUILTIN_PATTERNS
    default:
      return BUILTIN_PATTERNS.filter(p => priority(p) >= 40)
  }
}

/**
 * Get pattern by name
 */
export function getPatternByName(name: string): MaskPattern | undefined {
  return BUILTIN_PATTERNS.find(p => p.name === name)
}
