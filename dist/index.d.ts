/**
 * @memoria/scrubber
 * Isomorphic, zero-dependency Double-Layer Secret Scrubber (RN-03 & Section 6 Architecture).
 * Runs in < 1ms in both Chrome Extension (client pre-flight) and Fastify/MCP Server.
 */
export type SecretCategory = 'AI_API_KEY' | 'CLOUD_TOKEN' | 'JWT' | 'PRIVATE_KEY' | 'DB_PASS' | 'ENV_SECRET' | 'PAYMENT_CARD';
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
/**
 * Computes the Shannon entropy (bits per symbol) of a string:
 * H(X) = - \sum P(x_i) \log_2 P(x_i)
 */
export declare function calculateShannonEntropy(input: string): number;
/**
 * Validates a 13 to 19 digit payment card number using the ISO/IEC 7812 Luhn algorithm.
 * Accepts strings containing digits, spaces, or hyphens.
 */
export declare function isValidLuhn(rawInput: string): boolean;
/**
 * Scrubs all sensitive secrets, tokens, credentials, private keys, high-entropy
 * environment variables, and Luhn-validated payment card numbers from input text.
 */
export declare function scrubSecrets(text: string, options?: ScrubberOptions): ScrubberResult;
/**
 * Recursively scrubs all string properties inside an arbitrary JSON-compatible
 * payload (used by Fastify/MCP middleware to enforce RN-03 across nested inputs).
 */
export declare function scrubPayload<T>(payload: T, options?: ScrubberOptions): {
    cleanPayload: T;
    secretsBlockedCount: number;
    matches: SecretMatch[];
};
//# sourceMappingURL=index.d.ts.map