/**
 * @memoria/scrubber
 * Isomorphic, zero-dependency Double-Layer Secret Scrubber (RN-03 & Section 6 Architecture).
 * Runs in < 1ms in both Chrome Extension (client pre-flight) and Fastify/MCP Server.
 */

export type SecretCategory =
  | 'AI_API_KEY'
  | 'CLOUD_TOKEN'
  | 'JWT'
  | 'PRIVATE_KEY'
  | 'DB_PASS'
  | 'ENV_SECRET'
  | 'PAYMENT_CARD';

export interface SecretMatch {
  category: SecretCategory;
  replacement: string;
  redactedPreview: string;
  entropy?: number;
}

export interface ScrubberResult {
  cleanText: string;
  secretsBlockedCount: number;
  matches: SecretMatch[];
}

export interface ScrubberOptions {
  /**
   * Minimum Shannon entropy threshold (in bits per character) for generic
   * .env / assignment values. Defaults to 3.8 as specified in Section 6.
   */
  entropyThreshold?: number;
}

const DEFAULT_ENTROPY_THRESHOLD = 3.8;

/**
 * Computes the Shannon entropy (bits per symbol) of a string:
 * H(X) = - \sum P(x_i) \log_2 P(x_i)
 */
export function calculateShannonEntropy(input: string): number {
  if (!input || input.length === 0) {
    return 0;
  }

  const frequencies = new Map<string, number>();
  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    frequencies.set(ch, (frequencies.get(ch) ?? 0) + 1);
  }

  const len = input.length;
  let entropy = 0;

  for (const count of frequencies.values()) {
    const probability = count / len;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Validates a 13 to 19 digit payment card number using the ISO/IEC 7812 Luhn algorithm.
 * Accepts strings containing digits, spaces, or hyphens.
 */
export function isValidLuhn(rawInput: string): boolean {
  const digitsOnly = rawInput.replace(/[\s-]/g, '');

  if (!/^\d{13,19}$/.test(digitsOnly)) {
    return false;
  }

  // Reject trivial all-identical digit sequences (e.g., 0000000000000000)
  if (/^(\d)\1+$/.test(digitsOnly)) {
    return false;
  }

  let sum = 0;
  let shouldDouble = false;

  for (let i = digitsOnly.length - 1; i >= 0; i--) {
    let digit = digitsOnly.charCodeAt(i) - 48;

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

/**
 * Generates a safe, non-reversible masked preview of a secret for audit metadata
 * without retaining the sensitive payload in memory.
 */
function createRedactedPreview(rawSecret: string): string {
  const trimmed = rawSecret.trim();
  if (trimmed.length <= 8) {
    return '***';
  }
  return `${trimmed.slice(0, 4)}...${trimmed.slice(-2)}`;
}

// 1. PEM / SSH / PGP Private Key Blocks
const PRIVATE_KEY_REGEX =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g;

// 2. Database & Cache Connection Strings with Embedded Credentials
const DB_CONNECTION_REGEX =
  /((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?):\/\/[^:\s/]+:)([^@\s"']+)(@[^\s"']+)/gi;

// 3. Dev / Cloud Provider Tokens (GitHub, AWS, Stripe, Slack, Supabase)
const CLOUD_TOKEN_REGEX =
  /\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}|(?:AKIA|ASIA)[0-9A-Z]{16}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sbp_[a-fA-F0-9]{40})\b/g;

// 4. AI Provider API Keys (OpenAI, Anthropic, xAI, Groq)
const AI_API_KEY_REGEX =
  /\b(sk-ant-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9_-]{20,}|xai-[a-zA-Z0-9_-]{20,}|gsk_[a-zA-Z0-9_-]{20,})\b/g;

// 5. JSON Web Tokens (JWTs)
const JWT_REGEX =
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

// 6. .env Variables & Key-Value Secret Assignments Evaluated by Shannon Entropy
const ENV_ASSIGNMENT_REGEX =
  /(?<!\[)\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|api_key|apikey|private_key|access_token|auth_token|client_secret|service_role_key)[A-Za-z0-9_]*)\s*[:=]\s*(['"]?)([^\s'"`;,]{8,})\2/gi;

// 7. Candidate Payment Card Sequences (13-19 digits, optionally space or hyphen delimited)
const PAYMENT_CARD_CANDIDATE_REGEX =
  /(?<![A-Za-z0-9_-])(?:\d[ -]?){12,18}\d(?![A-Za-z0-9_-])/g;

/**
 * Scrubs all sensitive secrets, tokens, credentials, private keys, high-entropy
 * environment variables, and Luhn-validated payment card numbers from input text.
 */
export function scrubSecrets(
  text: string,
  options: ScrubberOptions = {}
): ScrubberResult {
  if (!text || typeof text !== 'string') {
    return {
      cleanText: '',
      secretsBlockedCount: 0,
      matches: [],
    };
  }

  const entropyThreshold = options.entropyThreshold ?? DEFAULT_ENTROPY_THRESHOLD;
  const matches: SecretMatch[] = [];
  let cleanText = text;

  // Step 1: Private Keys (PEM / RSA / EC / OPENSSH / PGP)
  cleanText = cleanText.replace(PRIVATE_KEY_REGEX, (fullMatch) => {
    const replacement = '[REDACTED_SECRET:PRIVATE_KEY]';
    matches.push({
      category: 'PRIVATE_KEY',
      replacement,
      redactedPreview: createRedactedPreview(fullMatch),
    });
    return replacement;
  });

  // Step 2: Database Connection Strings with Credentials
  cleanText = cleanText.replace(
    DB_CONNECTION_REGEX,
    (fullMatch, prefix: string, password: string, suffix: string) => {
      if (password.includes('[REDACTED_SECRET')) {
        return fullMatch;
      }
      const replacement = '[REDACTED_SECRET:DB_PASS]';
      matches.push({
        category: 'DB_PASS',
        replacement,
        redactedPreview: createRedactedPreview(password),
      });
      return `${prefix}${replacement}${suffix}`;
    }
  );

  // Step 3: Cloud & Dev Tokens (GitHub, AWS, Stripe, Slack, Supabase)
  cleanText = cleanText.replace(CLOUD_TOKEN_REGEX, (token) => {
    const replacement = '[REDACTED_SECRET:CLOUD_TOKEN]';
    matches.push({
      category: 'CLOUD_TOKEN',
      replacement,
      redactedPreview: createRedactedPreview(token),
    });
    return replacement;
  });

  // Step 4: AI Provider API Keys (OpenAI, Anthropic, xAI, Groq)
  cleanText = cleanText.replace(AI_API_KEY_REGEX, (apiKey) => {
    const replacement = '[REDACTED_SECRET:AI_API_KEY]';
    matches.push({
      category: 'AI_API_KEY',
      replacement,
      redactedPreview: createRedactedPreview(apiKey),
    });
    return replacement;
  });

  // Step 5: JSON Web Tokens (JWT)
  cleanText = cleanText.replace(JWT_REGEX, (jwt) => {
    const replacement = '[REDACTED_SECRET:JWT]';
    matches.push({
      category: 'JWT',
      replacement,
      redactedPreview: createRedactedPreview(jwt),
    });
    return replacement;
  });

  // Step 6: .env Variables and Secret Key-Value Assignments (Shannon Entropy > 3.8)
  cleanText = cleanText.replace(
    ENV_ASSIGNMENT_REGEX,
    (fullMatch, keyName: string, _quote: string, rawValue: string) => {
      if (
        keyName.toUpperCase().includes('REDACTED_SECRET') ||
        rawValue.includes('[REDACTED_SECRET') ||
        rawValue.includes('REDACTED_SECRET:')
      ) {
        return fullMatch;
      }

      const entropy = calculateShannonEntropy(rawValue);
      if (entropy <= entropyThreshold) {
        return fullMatch;
      }

      const replacement = '[REDACTED_SECRET]';
      matches.push({
        category: 'ENV_SECRET',
        replacement,
        redactedPreview: createRedactedPreview(rawValue),
        entropy: Number(entropy.toFixed(3)),
      });
      return `${keyName}=${replacement}`;
    }
  );

  // Step 7: Payment Card Numbers (13–19 digits passing Luhn check)
  cleanText = cleanText.replace(PAYMENT_CARD_CANDIDATE_REGEX, (candidate) => {
    // Do not match if hyphens & spaces are mixed inconsistently or if it fails Luhn
    const hasSpaces = candidate.includes(' ');
    const hasHyphens = candidate.includes('-');
    if (hasSpaces && hasHyphens) {
      return candidate;
    }

    if (!isValidLuhn(candidate)) {
      return candidate;
    }

    const replacement = '[REDACTED_SECRET:PAYMENT_CARD]';
    matches.push({
      category: 'PAYMENT_CARD',
      replacement,
      redactedPreview: createRedactedPreview(candidate.replace(/[\s-]/g, '')),
    });
    return replacement;
  });

  return {
    cleanText,
    secretsBlockedCount: matches.length,
    matches,
  };
}

/**
 * Recursively scrubs all string properties inside an arbitrary JSON-compatible
 * payload (used by Fastify/MCP middleware to enforce RN-03 across nested inputs).
 */
export function scrubPayload<T>(
  payload: T,
  options: ScrubberOptions = {}
): {
  cleanPayload: T;
  secretsBlockedCount: number;
  matches: SecretMatch[];
} {
  const aggregatedMatches: SecretMatch[] = [];

  function walk(value: unknown): unknown {
    if (typeof value === 'string') {
      const res = scrubSecrets(value, options);
      if (res.secretsBlockedCount > 0) {
        aggregatedMatches.push(...res.matches);
      }
      return res.cleanText;
    }

    if (Array.isArray(value)) {
      return value.map((item) => walk(item));
    }

    if (value !== null && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = walk(v);
      }
      return out;
    }

    return value;
  }

  const cleanPayload = walk(payload) as T;
  return {
    cleanPayload,
    secretsBlockedCount: aggregatedMatches.length,
    matches: aggregatedMatches,
  };
}
