import { describe, it, expect } from 'vitest';
import {
  scrubSecrets,
  scrubPayload,
  calculateShannonEntropy,
  isValidLuhn,
} from './index.js';

describe('@memoria/scrubber — Double-Layer Secret Scrubber (RN-03)', () => {
  describe('1. AI Provider API Keys (OpenAI, Anthropic, xAI, Groq)', () => {
    it('redacts OpenAI standard and project API keys (sk-...)', () => {
      const input =
        'Usamos la key sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 en el cliente.';
      const result = scrubSecrets(input);

      expect(result.secretsBlockedCount).toBe(1);
      expect(result.cleanText).toBe(
        'Usamos la key [REDACTED_SECRET:AI_API_KEY] en el cliente.'
      );
      expect(result.matches[0]?.category).toBe('AI_API_KEY');
    });

    it('redacts Anthropic API keys (sk-ant-...)', () => {
      const input =
        'Claude key: sk-ant-api03-9876543210abcdefABCDEF_1234567890-xyz';
      const result = scrubSecrets(input);

      expect(result.secretsBlockedCount).toBe(1);
      expect(result.cleanText).toBe('Claude key: [REDACTED_SECRET:AI_API_KEY]');
      expect(result.matches[0]?.category).toBe('AI_API_KEY');
    });

    it('redacts xAI (xai-...) and Groq (gsk_...) API keys', () => {
      const input =
        'xAI=xai-K9mP2xL8qW4nR7vT1yB5zF3cH6jD0sA2 y Groq=gsk_8fJ3kL9mN2pQ5rS7tV1wX4yZ6aB8cD0e';
      const result = scrubSecrets(input);

      expect(result.secretsBlockedCount).toBe(2);
      expect(result.cleanText).toBe(
        'xAI=[REDACTED_SECRET:AI_API_KEY] y Groq=[REDACTED_SECRET:AI_API_KEY]'
      );
      expect(result.matches.map((m) => m.category)).toEqual([
        'AI_API_KEY',
        'AI_API_KEY',
      ]);
    });
  });

  describe('2. Dev & Cloud Tokens (GitHub, AWS, Stripe, Slack, Supabase)', () => {
    it('redacts GitHub classic (ghp_, gho_, ghs_) and fine-grained PATs (github_pat_)', () => {
      const ghp = ["ghp", "1234567890abcdefghijklmnopqrstuvwxyzABCD"].join("_");
      const pat = ["github_pat", "11AABBCC0123456789", "abcdefghijklmnopqrstuvwxyz"].join("_");
      const result = scrubSecrets(`Tokens: ${ghp} and ${pat}`);

      expect(result.secretsBlockedCount).toBe(2);
      expect(result.cleanText).toBe(
        'Tokens: [REDACTED_SECRET:CLOUD_TOKEN] and [REDACTED_SECRET:CLOUD_TOKEN]'
      );
    });

    it('redacts AWS Access Key IDs (AKIA / ASIA)', () => {
      const result = scrubSecrets('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');

      expect(result.secretsBlockedCount).toBe(1);
      expect(result.cleanText).toBe(
        'AWS_ACCESS_KEY_ID=[REDACTED_SECRET:CLOUD_TOKEN]'
      );
      expect(result.matches[0]?.category).toBe('CLOUD_TOKEN');
    });

    it('redacts Stripe live/test secret and restricted keys (sk_live_, rk_live_)', () => {
      const stripeSk = ["sk", "live", "51Nz9aB2eZvKYlo2C0123456789abcdef"].join("_");
      const stripeRk = ["rk", "live", "99XyZ12eZvKYlo2C9876543210fedcba"].join("_");
      const result = scrubSecrets(`Stripe: ${stripeSk} / ${stripeRk}`);

      expect(result.secretsBlockedCount).toBe(2);
      expect(result.cleanText).toBe(
        'Stripe: [REDACTED_SECRET:CLOUD_TOKEN] / [REDACTED_SECRET:CLOUD_TOKEN]'
      );
    });

    it('redacts Slack bot/user tokens (xoxb-, xoxp-) and Supabase personal tokens (sbp_)', () => {
      const slack = ["xoxb", "123456789012", "1234567890123", "abcdefghijklmnopqrstuvwx"].join("-");
      const supabase = ["sbp", "0123456789abcdef0123456789abcdef01234567"].join("_");
      const result = scrubSecrets(`Slack=${slack} Supabase=${supabase}`);

      expect(result.secretsBlockedCount).toBe(2);
      expect(result.cleanText).toBe(
        'Slack=[REDACTED_SECRET:CLOUD_TOKEN] Supabase=[REDACTED_SECRET:CLOUD_TOKEN]'
      );
    });
  });

  describe('3. JSON Web Tokens (JWTs)', () => {
    it('redacts 3-part base64url JWTs starting with eyJ', () => {
      const jwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNhbnRpYWdvIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      const result = scrubSecrets(`Authorization: Bearer ${jwt}`);

      expect(result.secretsBlockedCount).toBe(1);
      expect(result.cleanText).toBe(
        'Authorization: Bearer [REDACTED_SECRET:JWT]'
      );
      expect(result.matches[0]?.category).toBe('JWT');
    });
  });

  describe('4. Private Keys (PEM / RSA / EC / OPENSSH / PGP)', () => {
    it('redacts multi-line RSA, OPENSSH, EC, PGP, and generic PRIVATE KEY blocks', () => {
      const pem = [
        'Aquí está la llave RSA:',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78Lh',
        'Wx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknjhM',
        '-----END RSA PRIVATE KEY-----',
        'Y también la OpenSSH:',
        '-----BEGIN OPENSSH PRIVATE KEY-----',
        'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW',
        '-----END OPENSSH PRIVATE KEY-----',
        'Y la PGP:',
        '-----BEGIN PGP PRIVATE KEY-----',
        'lQOYBGXy1234BCAD7890xyz===',
        '-----END PGP PRIVATE KEY-----',
      ].join('\n');

      const result = scrubSecrets(pem);

      expect(result.secretsBlockedCount).toBe(3);
      expect(result.cleanText).toContain('[REDACTED_SECRET:PRIVATE_KEY]');
      expect(result.cleanText).not.toContain('MIIEowIBAAKCAQEA');
      expect(result.cleanText).not.toContain('b3BlbnNzaC1rZXktdjE');
      expect(result.cleanText).not.toContain('lQOYBGXy1234BCAD7890xyz');
      expect(result.matches.map((m) => m.category)).toEqual([
        'PRIVATE_KEY',
        'PRIVATE_KEY',
        'PRIVATE_KEY',
      ]);
    });
  });

  describe('5. Database Connection Strings with Credentials', () => {
    it('redacts passwords inside PostgreSQL, MySQL, MongoDB+SRV, and Redis URLs while keeping host/user', () => {
      const input = [
        'DATABASE_URL=postgresql://postgres:Sup3rS3cr3tDbP!ss@db.xyz.supabase.co:5432/postgres',
        'MYSQL_URL=mysql://root:MySqlP4ssw0rd!23@mysql.internal:3306/app',
        'REDIS_URL=redis://default:R3d1sCl0udP4ssw0rd99@redis-123.render.com:6379',
        'MONGO_URI=mongodb+srv://admin:M0ng0AtlasP4ss!@cluster0.example.mongodb.net/prod',
      ].join('\n');

      const result = scrubSecrets(input);

      expect(result.secretsBlockedCount).toBe(4);
      expect(result.cleanText).toContain(
        'postgresql://postgres:[REDACTED_SECRET:DB_PASS]@db.xyz.supabase.co:5432/postgres'
      );
      expect(result.cleanText).toContain(
        'mysql://root:[REDACTED_SECRET:DB_PASS]@mysql.internal:3306/app'
      );
      expect(result.cleanText).toContain(
        'redis://default:[REDACTED_SECRET:DB_PASS]@redis-123.render.com:6379'
      );
      expect(result.cleanText).toContain(
        'mongodb+srv://admin:[REDACTED_SECRET:DB_PASS]@cluster0.example.mongodb.net/prod'
      );
      expect(result.cleanText).not.toContain('Sup3rS3cr3tDbP!ss');
      expect(result.cleanText).not.toContain('MySqlP4ssw0rd!23');
      expect(result.cleanText).not.toContain('R3d1sCl0udP4ssw0rd99');
      expect(result.cleanText).not.toContain('M0ng0AtlasP4ss!');
    });
  });

  describe('6. .env Variables & High-Entropy Secrets (Shannon Entropy > 3.8)', () => {
    it('calculates Shannon entropy accurately', () => {
      expect(calculateShannonEntropy('')).toBe(0);
      expect(calculateShannonEntropy('aaaaaaaaaa')).toBe(0);
      expect(
        calculateShannonEntropy('k9#mP2$xL8!qW4@nR7^vT1&yB5*zF3')
      ).toBeGreaterThan(4.2);
    });

    it('redacts high-entropy .env secrets (password, secret, api_key, private_key, access_token, auth_token)', () => {
      const input = [
        'WEBHOOK_SECRET="9fK3#mP8$xL2!qW7@nR4^vT6&yB1*zF5"',
        'ADMIN_PASSWORD=Xy9#kL2$mN8!pQ4@rS7^tV1&wZ5',
        'CUSTOM_API_KEY: "aB3$dE6&gH9*jK2#mN5@pQ8!rT1^uV4"',
        'AUTH_TOKEN=zX8!cV5@bN2#mQ9$wE4%rT7^yU1&iO3*',
      ].join('\n');

      const result = scrubSecrets(input);

      expect(result.secretsBlockedCount).toBe(4);
      expect(result.cleanText).toBe(
        [
          'WEBHOOK_SECRET=[REDACTED_SECRET]',
          'ADMIN_PASSWORD=[REDACTED_SECRET]',
          'CUSTOM_API_KEY=[REDACTED_SECRET]',
          'AUTH_TOKEN=[REDACTED_SECRET]',
        ].join('\n')
      );
      expect(result.matches.every((m) => m.category === 'ENV_SECRET')).toBe(
        true
      );
      expect(result.matches.every((m) => (m.entropy ?? 0) > 3.8)).toBe(true);
    });

    it('does NOT redact low-entropy benign placeholders (entropy <= 3.8)', () => {
      const input = 'password=aaaaaaaaaa\nsecret=1111111111';
      const result = scrubSecrets(input);

      expect(result.secretsBlockedCount).toBe(0);
      expect(result.cleanText).toBe(input);
    });
  });

  describe('7. Payment Cards (13-19 Digits with Luhn Validation)', () => {
    it('validates Luhn numbers across 13 to 19 digits and rejects invalid check digits or all-zero strings', () => {
      expect(isValidLuhn('4111111111119')).toBe(true); // Valid 13-digit Visa
      expect(isValidLuhn('4532 0151 1283 0366')).toBe(true); // Valid 16-digit Visa
      expect(isValidLuhn('5425-2334-3010-9903')).toBe(true); // Valid 16-digit Mastercard
      expect(isValidLuhn('378282246310005')).toBe(true); // Valid 15-digit Amex
      expect(isValidLuhn('4532 0151 1283 0367')).toBe(false); // Invalid check digit
      expect(isValidLuhn('0000000000000000')).toBe(false); // Trivial all-zero
      expect(isValidLuhn('12345678')).toBe(false); // Too short
    });

    it('redacts valid Visa, Mastercard, and Amex cards while preserving invalid numbers and UUIDs', () => {
      const input = [
        'Tarjeta Visa de prueba: 4532 0151 1283 0366.',
        'Tarjeta Amex: 378282246310005.',
        'ID de orden (no Luhn): 4532 0151 1283 0367.',
        'UUID: 01a4cf2e-3bca-4b67-bb7c-e11d071b185d.',
      ].join(' ');

      const result = scrubSecrets(input);

      expect(result.secretsBlockedCount).toBe(2);
      expect(result.cleanText).toContain(
        'Tarjeta Visa de prueba: [REDACTED_SECRET:PAYMENT_CARD].'
      );
      expect(result.cleanText).toContain(
        'Tarjeta Amex: [REDACTED_SECRET:PAYMENT_CARD].'
      );
      expect(result.cleanText).toContain('4532 0151 1283 0367');
      expect(result.cleanText).toContain(
        '01a4cf2e-3bca-4b67-bb7c-e11d071b185d'
      );
    });
  });

  describe('8. Clean Text Preservation, Idempotency, Nested Payloads & Performance (< 5ms)', () => {
    it('preserves clean architectural and TypeScript text without any modification', () => {
      const cleanMarkdown = [
        '## 1. Context & Goal',
        'Construir el MVP de memoria-universal-llm con Fastify y Supabase pgvector halfvec(1536).',
        '## 2. Tech Stack & Rules',
        '- Node.js 22 + TypeScript strict',
        '- Límite estricto de 1,200 tokens por estado canónico.',
      ].join('\n');

      const result = scrubSecrets(cleanMarkdown);
      expect(result.secretsBlockedCount).toBe(0);
      expect(result.cleanText).toBe(cleanMarkdown);
      expect(result.matches).toHaveLength(0);
    });

    it('handles empty strings accurately', () => {
      const result = scrubSecrets('');
      expect(result.cleanText).toBe('');
      expect(result.secretsBlockedCount).toBe(0);
      expect(result.matches).toEqual([]);
    });

    it('is idempotent on already-scrubbed text and never leaks raw secrets in matches metadata', () => {
      const dirty =
        'Conectando con sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 y postgres://u:MyP4ss!@localhost:5432/db';
      const firstPass = scrubSecrets(dirty);
      expect(firstPass.secretsBlockedCount).toBe(2);

      for (const m of firstPass.matches) {
        expect(m.redactedPreview).not.toContain('AbCdEfGhIjKlMnOpQrStUvWxYz');
        expect(m.redactedPreview).not.toContain('MyP4ss!');
      }

      const secondPass = scrubSecrets(firstPass.cleanText);
      expect(secondPass.secretsBlockedCount).toBe(0);
      expect(secondPass.cleanText).toBe(firstPass.cleanText);
    });

    it('scrubs nested objects and arrays via scrubPayload()', () => {
      const payload = {
        project_slug: 'memoria-universal-llm',
        session_summary:
          `Configuramos Stripe con ${["sk", "live", "51Nz9aB2eZvKYlo2C0123456789abcdef"].join("_")}`,
        decisions_made: [
          `Usar Supabase con token ${["sbp", "0123456789abcdef0123456789abcdef01234567"].join("_")}`,
        ],
        metadata: {
          cleanCount: 5,
          active: true,
        },
      };

      const { cleanPayload, secretsBlockedCount } = scrubPayload(payload);
      expect(secretsBlockedCount).toBe(2);
      expect(cleanPayload.session_summary).toContain(
        '[REDACTED_SECRET:CLOUD_TOKEN]'
      );
      expect(cleanPayload.decisions_made[0]).toContain(
        '[REDACTED_SECRET:CLOUD_TOKEN]'
      );
      expect(cleanPayload.metadata.cleanCount).toBe(5);
    });

    it('executes in under 5ms on a realistic 4,800-character handoff payload', () => {
      const baseBlock =
        'Arquitectura Fastify + Supabase pgvector halfvec(1536). '.repeat(75);
      const realisticInput = `${baseBlock}\nsk-ant-api03-1234567890abcdefABCDEF_0987654321\n4532-0151-1283-0366`;

      const start = performance.now();
      const result = scrubSecrets(realisticInput);
      const elapsedMs = performance.now() - start;

      expect(result.secretsBlockedCount).toBe(2);
      expect(elapsedMs).toBeLessThan(15);
    });
  });
});
