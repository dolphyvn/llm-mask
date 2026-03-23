/**
 * Language-specific patterns
 *
 * Patterns for detecting secrets in Python, JavaScript, Go, etc.
 */

import type { MaskPattern } from './types.js'

/**
 * Python-specific patterns
 */
export const PYTHON_PATTERNS: MaskPattern[] = [
  {
    name: 'django_secret_key',
    regex: /(['"]?SECRET_KEY['"]?\s*[:=]\s*['"])([a-zA-Z0-9!@#$%^&*()_+\-=]{40,})(['"])/gi,
    placeholder: (i) => `$1[DJANGO_SECRET_${i}]$3`,
    priority: 100
  },
  {
    name: 'django_db_password',
    regex: /(['"]?(DATABASE_URL|DB_PASSWORD|DB_PASS)['"]?\s*[:=]\s*['"])([^'"]+)(['"])/gi,
    placeholder: (i) => `$1[DB_CREDENTIALS_${i}]$3`,
    priority: 95
  },
  {
    name: 'python_api_key',
    regex: /(['"]?(api_key|apikey|secret_key|access_token)['"]?\s*[:=]\s*['"])([a-zA-Z0-9\-_\.]{16,})(['"])/gi,
    placeholder: (i) => `$1[API_KEY_${i}]$3`,
    priority: 90
  },
  {
    name: 'aws_boto_key',
    regex: /boto3\.client\(['"](\w+)['"],\s*aws_access_key_id=['"]([A-Z0-9]{20})['"]/gi,
    placeholder: (i) => `boto3.client('$1', aws_access_key_id='[AWS_ACCESS_KEY_${i}]'`,
    priority: 100
  }
]

/**
 * JavaScript/TypeScript-specific patterns
 */
export const JAVASCRIPT_PATTERNS: MaskPattern[] = [
  {
    name: 'firebase_config',
    regex: /firebaseConfig\s*=\s*\{[^}]*apiKey:\s*['"]([a-zA-Z0-9\-_]{20,})['"]/gi,
    placeholder: (i) => `firebaseConfig = { ... apiKey: "[FIREBASE_KEY_${i}]"`,
    priority: 95
  },
  {
    name: 'jwt_token',
    regex: /(['"]?(jwt|token|access_token)['"]?\s*[:=]\s*['"]*)(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)(['"])/gi,
    placeholder: (i) => `$1[JWT_${i}]$3`,
    priority: 100
  },
  {
    name: 'mongodb_uri',
    regex: /mongodb:\/\/[^@]+:[^@]+@/gi,
    placeholder: (i) => `mongodb://[MONGO_CREDS_${i}]@`,
    priority: 95
  },
  {
    name: 'aws_sdk_config',
    regex: /AWS\.config\.update\(\{[^}]*accessKeyId:\s*['"]([A-Z0-9]{20})['"]/gi,
    placeholder: (i) => `AWS.config.update({ ...accessKeyId: "[AWS_ACCESS_KEY_${i}]"`,
    priority: 95
  },
  {
    name: 'oauth_token',
    regex: /(['"]?(oauth_token|access_token|bearer_token)['"]?\s*[:=]\s*['"])([a-zA-Z0-9\-_\.]{20,})(['"])/gi,
    placeholder: (i) => `$1[OAUTH_TOKEN_${i}]$3`,
    priority: 90
  }
]

/**
 * Go-specific patterns
 */
export const GO_PATTERNS: MaskPattern[] = [
  {
    name: 'go_env_struct',
    regex: /\b[A-Z]\w*Key\s*=\s*['"]([a-zA-Z0-9\-_]{20,})['"]/gi,
    placeholder: (i) => `[GO_KEY_${i}] = "[API_KEY_${i}]"`,
    priority: 90
  },
  {
    name: 'go_aws_config',
    regex: /aws\.Config\{[^}]*AccessKeyID:\s*aws\.String\(['"]([A-Z0-9]{20})['"]\)/gi,
    placeholder: (i) => `aws.Config{ ...AccessKeyID: aws.String("[AWS_ACCESS_KEY_${i}]")`,
    priority: 95
  }
]

/**
 * Ruby-specific patterns
 */
export const RUBY_PATTERNS: MaskPattern[] = [
  {
    name: 'rails_secret_key_base',
    regex: /config\.secret_key_base\s*=\s*['"]([a-zA-Z0-9]{60,})['"]/gi,
    placeholder: (i) => `config.secret_key_base = "[RAILS_SECRET_${i}]"`,
    priority: 100
  },
  {
    name: 'rails_db_password',
    regex: /(['"]?(password|PASSWORD)['"]\s*=>\s*['"])([^'"]+)(['"])/gi,
    placeholder: (i) => `$1[DB_PASSWORD_${i}]$3`,
    priority: 90
  }
]

/**
 * Terraform-specific patterns
 */
export const TERRAFORM_PATTERNS: MaskPattern[] = [
  {
    name: 'tf_aws_access_key',
    regex: /access_key\s*=\s*['"]([A-Z0-9]{20})['"]/gi,
    placeholder: (i) => `access_key = "[AWS_ACCESS_KEY_${i}]"`,
    priority: 100
  },
  {
    name: 'tf_secret_key',
    regex: /secret_key\s*=\s*['"]([a-zA-Z0-9/+=]{20,})['"]/gi,
    placeholder: (i) => `secret_key = "[AWS_SECRET_${i}]"`,
    priority: 100
  }
]

/**
 * All language-specific patterns
 */
export const LANGUAGE_PATTERNS: MaskPattern[] = [
  ...PYTHON_PATTERNS,
  ...JAVASCRIPT_PATTERNS,
  ...GO_PATTERNS,
  ...RUBY_PATTERNS,
  ...TERRAFORM_PATTERNS
]

/**
 * Get patterns by language
 */
export function getPatternsByLanguage(lang: string): MaskPattern[] {
  switch (lang.toLowerCase()) {
    case 'python':
    case 'py':
      return PYTHON_PATTERNS
    case 'javascript':
    case 'js':
    case 'typescript':
    case 'ts':
    case 'jsx':
    case 'tsx':
      return JAVASCRIPT_PATTERNS
    case 'go':
    case 'golang':
      return GO_PATTERNS
    case 'ruby':
    case 'rb':
      return RUBY_PATTERNS
    case 'terraform':
    case 'tf':
      return TERRAFORM_PATTERNS
    default:
      return []
  }
}

/**
 * Detect language from file extension
 */
export function detectLanguageFromPath(filePath: string): string | null {
  const ext = filePath.split('.').pop()?.toLowerCase()

  const languageMap: Record<string, string> = {
    'py': 'python',
    'js': 'javascript',
    'jsx': 'javascript',
    'ts': 'typescript',
    'tsx': 'typescript',
    'go': 'go',
    'rb': 'ruby',
    'tf': 'terraform',
    'hcl': 'terraform'
  }

  return ext ? languageMap[ext] || null : null
}
