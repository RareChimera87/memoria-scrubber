# `@memoria/scrubber` 🛡️

**Zero-dependency isomorphic local secret scrubber for LLM context & MCP tools.**  
*(Filtro local isomórfico y sin dependencias para limpiar secretos en contextos de LLMs y herramientas MCP).*

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](./LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](./package.json)
[![Runtime](https://img.shields.io/badge/runtime-Browser%20%7C%20Node%20%7C%20Edge-blue.svg)](#)

`@memoria/scrubber` is the open-source security core of **[Memoria (1-Click Cross-LLM Handoff)](https://github.com/RareChimera87/memoria-scrubber)**. It executes in **< 1ms** directly inside browser extensions (Manifest V3), MCP servers, and Node/Edge runtimes to redact API keys, cloud credentials, database passwords, JWTs, private keys, high-entropy `.env` secrets, and credit card numbers **before a single byte leaves your machine**.

---

## Why `@memoria/scrubber`? (English)

When switching between **Claude**, **ChatGPT**, **Grok**, and **Cursor** in the middle of debugging a production issue, developers frequently paste stack traces, terminal outputs, or configuration snippets containing live credentials (`sk-ant-...`, `sk-proj-...`, `ghp_...`, `AKIA...`, `postgres://user:pass@...`).

`@memoria/scrubber` combines **three deterministic detection layers** with zero external dependencies:

1. **Deterministic Pattern Matching (Regex Layer):**
   - **AI Provider Keys (`AI_API_KEY`):** OpenAI (`sk-...`), Anthropic (`sk-ant-...`), xAI (`xai-...`), Groq (`gsk_...`).
   - **Cloud & Dev Tokens (`CLOUD_TOKEN`):** GitHub PATs (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), AWS Access Keys (`AKIA...`, `ASIA...`), Stripe (`sk_live_`, `rk_live_`, `sk_test_`), Slack (`xoxb-`, `xoxp-`), Supabase (`sbp_`).
   - **PEM / SSH / PGP Private Keys (`PRIVATE_KEY`):** Full multi-line `-----BEGIN ... PRIVATE KEY-----` block redaction.
   - **Database & Cache URLs (`DB_PASS`):** Redacts embedded passwords inside `postgres://`, `postgresql://`, `mysql://`, `mongodb+srv://`, `redis://`, and `amqps://` connection strings while preserving host/database structure for debugging.
   - **JSON Web Tokens (`JWT`):** Standard 3-part `eyJ...` Bearer/session tokens.
2. **Information Theory Layer (Shannon Entropy $H(X) > 3.8$):**
   - Inspects `.env` assignments and key-value pairs (`SECRET=...`, `API_KEY=...`, `PASSWORD=...`, `SERVICE_ROLE_KEY=...`).
   - Calculates Shannon entropy in bits per symbol:
     $$H(X) = -\sum P(x_i)\log_2 P(x_i)$$
   - Leaves harmless placeholders (`PASSWORD=changeme`, `API_KEY=your_key_here`) untouched so your code examples stay readable, while redacting real high-entropy secrets (`[REDACTED_SECRET]`).
3. **ISO/IEC 7812 Luhn Validation (`PAYMENT_CARD`):**
   - Validates 13–19 digit sequences against the Luhn checksum algorithm to redact real credit/debit cards without corrupting normal numeric IDs or timestamps.

### Quick Start

```ts
import { scrubSecrets, scrubPayload } from '@memoria/scrubber';

const rawContext = `
Debugging auth refresh bug:
DATABASE_URL=postgresql://admin:Sup3rS3cr3tP4ss!@db.internal:5432/prod
OPENAI_API_KEY=sk-proj-9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p
LOCAL_DEV_PASSWORD=password123
`;

const result = scrubSecrets(rawContext);

console.log(result.cleanText);
/*
Debugging auth refresh bug:
DATABASE_URL=postgresql://admin:[REDACTED_SECRET:DB_PASS]@db.internal:5432/prod
OPENAI_API_KEY=[REDACTED_SECRET:AI_API_KEY]
LOCAL_DEV_PASSWORD=password123
*/

console.log(result.secretsBlockedCount); // 2
console.log(result.matches);
// [
//   { category: 'DB_PASS', replacement: '[REDACTED_SECRET:DB_PASS]', redactedPreview: 'Sup3...s!' },
//   { category: 'AI_API_KEY', replacement: '[REDACTED_SECRET:AI_API_KEY]', redactedPreview: 'sk-p...4p' }
// ]
```

### Recursive JSON Payload Scrubbing (for MCP & REST Middleware)

```ts
import { scrubPayload } from '@memoria/scrubber';

const { cleanPayload, secretsBlockedCount } = scrubPayload({
  project_slug: 'invoice-api',
  blocks: {
    current_session_state: 'Token leak fixed. Key was ghp_xxxx_example_token_redacted_locally',
  },
});
```

---

## ¿Por qué `@memoria/scrubber`? (Español)

Cuando te quedas sin cuota en **Claude** a mitad de un bug y necesitas pasar tu sesión exacta a **ChatGPT**, **Grok** o **Cursor**, lo último que quieres es que tus API keys (`sk-...`), tokens de GitHub/AWS o contraseñas de base de datos salgan de tu máquina hacia la nube.

`@memoria/scrubber` es el motor open-source (MIT) que ejecuta **Memoria (1-Click Cross-LLM Handoff)** en doble capa:
1. **En tu navegador (Pre-Flight en la Extensión Chrome MV3):** Antes de enviar el contexto de tus 5 bloques canónicos (`STATE-UPSERT`), `@memoria/scrubber` limpia localmente cualquier secreto en menos de 1 milisegundo.
2. **En el Servidor MCP / API (Defensa en Profundidad):** Todo payload que entra por herramientas MCP (`save_memory_block`, `/handoff`) vuelve a pasar por `scrubPayload()` antes de tocar la base de datos.

### Cómo auditar y correr los tests localmente

```bash
git clone https://github.com/RareChimera87/memoria-scrubber.git
cd memoria-scrubber
npm install
npm test
```

---

## License

MIT © 2026 Memoria Labs (RareChimera87)
