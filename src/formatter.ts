/**
 * Preserve format formatters
 *
 * Instead of [EMAIL_1], show j***@a***.com
 */

export interface FormatResult {
  formatted: string
  original: string
}

/**
 * Format email with preserved structure
 * john@acme.com → j***@a***.com
 */
export function formatEmail(email: string): FormatResult {
  const [local, domain] = email.split('@')

  if (!local || !domain) {
    return { formatted: '***@***.***', original: email }
  }

  const maskedLocal = local.charAt(0) + '*'.repeat(Math.max(3, local.length - 1))
  const [domainName, ...domainParts] = domain.split('.')
  const maskedDomain = domainName.charAt(0) + '*'.repeat(Math.max(3, domainName.length - 1))
  const maskedDomainFull = [maskedDomain, ...domainParts].join('.')

  return {
    formatted: `${maskedLocal}@${maskedDomainFull}`,
    original: email
  }
}

/**
 * Format API key with preserved structure
 * sk-proj-abc123xyz → sk-proj-***********
 */
export function formatApiKey(key: string): FormatResult {
  // Detect prefix
  const match = key.match(/^(sk-[a-z0-9-]+|sk-ant-[a-z0-9-]+|AKIA[0-9A-Z]+)/i)

  if (match) {
    const prefix = match[1]
    const suffix = key.slice(prefix.length)
    return {
      formatted: prefix + '*'.repeat(Math.max(9, suffix.length)),
      original: key
    }
  }

  return {
    formatted: '*'.repeat(Math.min(key.length, 20)),
    original: key
  }
}

/**
 * Format credit card with preserved structure
 * 4111 1111 1111 1111 → 4111 ************ 1111
 */
export function formatCreditCard(card: string): string {
  const cleaned = card.replace(/[\s/]/g, '')

  if (cleaned.length < 13) {
    return '*'.repeat(cleaned.length)
  }

  const first = cleaned.slice(0, 4)
  const last = cleaned.slice(-4)

  return `${first} ${'*'.repeat(12)} ${last}`
}

/**
 * Format phone with preserved structure
 * +1-555-123-4567 → +1-555-***-****
 */
export function formatPhone(phone: string): string {
  // Find all digits
  const digits = phone.replace(/\D/g, '')

  if (digits.length < 7) {
    return '*'.repeat(phone.length)
  }

  // Preserve country code if present
  const countryLen = digits.length === 11 ? 1 : 0
  const countryCode = countryLen ? digits.slice(0, 1) + '-' : ''
  const areaCode = digits.slice(countryLen, countryLen + 3)
  const rest = digits.slice(countryLen + 3)

  return `${countryCode}${areaCode}-${'*'.repeat(rest.length)}`
}

/**
 * Format SSN with preserved structure
 * 123-45-6789 → ***-**-****
 */
export function formatSSN(ssn: string): string {
  return '***-**-****'
}

/**
 * Format UUID with preserved structure
 * 550e8400-e29b-41d4-a716-446655440000 → ********-****-****-****-************
 */
export function formatUUID(uuid: string): string {
  const parts = uuid.split('-')
  if (parts.length !== 5) {
    return '*'.repeat(uuid.length)
  }

  return parts.map(p => '*'.repeat(p.length)).join('-')
}

/**
 * Format IP address
 * 192.168.1.1 → ***.***.*.*
 */
export function formatIP(ip: string): string {
  return ip.replace(/\d+/g, m => '*'.repeat(m.length))
}

/**
 * Format URL with credentials
 * postgres://user:pass@localhost → postgres://***:***@localhost
 */
export function formatURLWithCreds(url: string): string {
  return url.replace(/([^:\/]+):([^\s@/]+)@/g, '$1:***@')
}

/**
 * Generic formatter that picks the right one based on pattern name
 */
export function formatByPattern(patternName: string, value: string): FormatResult | string {
  switch (patternName) {
    case 'email':
      return formatEmail(value)
    case 'openai_api_key':
    case 'anthropic_api_key':
    case 'stripe_live_key':
    case 'stripe_test_key':
    case 'aws_access_key':
    case 'github_token':
    case 'jwt_token':
      return formatApiKey(value)
    case 'credit_card':
      return { formatted: formatCreditCard(value), original: value }
    case 'phone_us':
    case 'phone_intl':
      return { formatted: formatPhone(value), original: value }
    case 'ssn':
      return { formatted: formatSSN(value), original: value }
    case 'uuid':
      return { formatted: formatUUID(value), original: value }
    case 'ip_address':
    case 'ipv6':
      return { formatted: formatIP(value), original: value }
    case 'url_with_creds':
      return { formatted: formatURLWithCreds(value), original: value }
    default:
      return { formatted: '*'.repeat(Math.min(value.length, 8)), original: value }
  }
}
