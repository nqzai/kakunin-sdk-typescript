# @kakunin/sdk

[![npm version](https://img.shields.io/npm/v/@kakunin/sdk)](https://www.npmjs.com/package/@kakunin/sdk)
[![License](https://img.shields.io/npm/l/@kakunin/sdk)](https://github.com/nqzai/kakunin-sdk-typescript/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-kakunin.ai-blue)](https://www.kakunin.ai/docs)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/nqzai/kakunin-sdk-typescript/badge)](https://scorecard.dev/viewer/?uri=github.com/nqzai/kakunin-sdk-typescript)

TypeScript SDK for the [Kakunin](https://kakunin.ai) AI agent compliance API — X.509 certificate issuance, behavioral monitoring, and MiCA / EU AI Act compliance reporting. Talks to the hosted service; **[free sandbox keys](https://www.kakunin.ai/dashboard/api-keys)**, no self-hosting required. Need your own control plane? See [kakunin-core](https://github.com/nqzai/kakunin-core).

```bash
npm install @kakunin/sdk
```

## Quick start

```typescript
import { Kakunin } from '@kakunin/sdk';

const kkn = new Kakunin({ apiKey: process.env.KAKUNIN_API_KEY! });

// Register an agent and issue its X.509 certificate
const agent = await kkn.agents.create({
  name: 'TradeBot-1',
  model_hash: await Kakunin.computeModelHash('gpt-4o:2024-11'),
});
const cert = await kkn.agents.certify(agent.id);
console.log(cert.serial_number); // e.g. "c4f9-17a2"

// Ingest a behavioral event and get a real-time risk score
const event = await kkn.events.ingest({
  agentId: agent.id,
  actionType: 'transaction_initiated',
  details: { amount_usd: 50000, venue: 'NYSE' },
});
console.log(event.risk_band); // "low" | "medium" | "high"

// Verify a certificate (public — no auth required)
const verified = await kkn.verify.cert(cert.serial_number);
console.log(verified.status); // "active" | "revoked" | "expired"
```

## Sandbox mode

Use a `kak_test_...` key to hit the sandbox CA at no cost. Certificates are real X.509 but issued by a test root and have no regulatory validity.

```typescript
const sandbox = new Kakunin({ apiKey: 'kak_test_...' });
console.log(sandbox.isSandbox()); // true
```

## API surface

| Resource | Methods |
|---|---|
| `kkn.agents` | `create`, `get`, `list`, `update`, `certify`, `getRisk` |
| `kkn.events` | `ingest`, `list` |
| `kkn.certificates` | `revoke` |
| `kkn.verify` | `cert` (no auth) |
| `kkn.webhooks` | `constructEvent` |
| `Kakunin` (static) | `computeModelHash` |

## Enforcement middleware (`@kakunin/sdk/verify`)

Drop-in middleware that enforces the `X-Kakunin-Cert-Serial` header on inbound requests — for services that *receive* traffic from Kakunin-certified agents. Zero dependencies, 60s in-process cert cache, fail-closed by default with optional stale-cache fallback.

```typescript
// Next.js / Fetch API (also Cloudflare Workers, Hono, Remix)
import { kakuninMiddleware } from '@kakunin/sdk/verify';
const enforce = kakuninMiddleware();

export async function middleware(req: NextRequest) {
  const { agent, reject } = await enforce(req);
  if (!agent) return reject('Missing or invalid agent certificate');
}
```

```typescript
// Express
import { kakuninExpress } from '@kakunin/sdk/verify';
app.use('/api', kakuninExpress()); // attaches req.kakuninAgent

// Manual + revocation webhook cache eviction
import { createVerifier, handleRevocationWebhook } from '@kakunin/sdk/verify';
const verifier = createVerifier({ staleCacheFallback: true });
app.post('/webhooks/kakunin', (req, res) => {
  handleRevocationWebhook(verifier, req.body);
  res.sendStatus(200);
});
```

## Supabase RLS binding (`@kakunin/sdk/verify/supabase`)

Bind a verified agent certificate to a Supabase client so Postgres Row-Level Security constrains every query to the agent's identity and scopes. Verifies the cert (fail-closed), then mints a short-lived Supabase JWT — its lifetime never exceeds the certificate's expiry.

Requires the `@supabase/supabase-js` peer dependency. **Server-side only** — the Supabase JWT secret must never reach a browser.

```typescript
import { bindAgentSession } from '@kakunin/sdk/verify/supabase';

const supabase = await bindAgentSession({
  supabaseUrl: process.env.SUPABASE_URL!,
  supabaseAnonKey: process.env.SUPABASE_ANON_KEY!,
  supabaseJwtSecret: process.env.SUPABASE_JWT_SECRET!, // server-side secret
  serial: req.headers.get('x-kakunin-cert-serial')!,
});

// Every query is RLS-scoped to the agent (auth.jwt() ->> 'sub')
const { data } = await supabase.from('trades').select('*');
```

```sql
-- Supabase RLS policy: agents see only their own rows
create policy "agents read own rows" on trades for all
  using ( agent_id = (auth.jwt() ->> 'sub') );
```

`bindAgentSession` throws `KakuninVerifyError` for revoked/expired/unverifiable certs — no client is returned. For custom client construction, `mintAgentSupabaseJwt(agent, opts)` returns just the signed JWT.

## Webhook verification

```typescript
app.post('/webhooks/kakunin', async (req, res) => {
  const event = await kkn.webhooks.constructEvent(
    req.rawBody,
    req.headers['kakunin-signature'] as string,
    process.env.KAKUNIN_WEBHOOK_SECRET!,
  );
  if (event.event === 'certificate.revoked') {
    // block the agent immediately
  }
  res.sendStatus(200);
});
```

## Requirements

Node.js ≥ 18. Full docs at [docs.kakunin.ai](https://docs.kakunin.ai).
