/**
 * @kakunin/sdk/verify/supabase — bind a verified agent certificate to a
 * Supabase client so Postgres Row-Level Security constrains every query to the
 * agent's identity and scopes.
 *
 * Model: verify the agent's cert (fail-closed), then mint a short-lived
 * Supabase JWT (HS256, signed with the project's JWT secret) carrying the agent
 * as `sub` plus its scopes in `app_metadata`. The returned client sends that
 * JWT, so RLS policies can gate on `auth.jwt() ->> 'sub'` and the scopes claim.
 *
 * The JWT lifetime never exceeds the certificate's own expiry — an agent's DB
 * access cannot outlive its certificate.
 *
 * RLS example (Supabase SQL):
 *   create policy "agents read own tenant rows"
 *     on tenant_data for all
 *     using ( agent_id = (auth.jwt() ->> 'sub') );
 *
 * Requires `@supabase/supabase-js` (peer dependency) for {@link bindAgentSession}.
 * {@link mintAgentSupabaseJwt} has no peer dependency.
 *
 * SECURITY: the Supabase JWT secret is a server-side secret. Never ship it to a
 * browser or client bundle. Call these helpers only from trusted server code.
 */

import type { SupabaseClient } from '@supabase/supabase-js';
import { createVerifier } from './index.js';
import type { AgentInfo, KakuninVerifyOptions } from './types.js';

const DEFAULT_MAX_TTL_SECONDS = 3600; // 1 hour cap on minted JWTs

export interface BindAgentSessionOptions {
  /** Supabase project URL, e.g. https://xxxx.supabase.co */
  supabaseUrl: string;
  /** Supabase anon/publishable key (the JWT in the Authorization header overrides its role). */
  supabaseAnonKey: string;
  /**
   * Supabase project **JWT secret** (HS256). Server-side secret — never expose
   * to a browser. Found in Supabase → Project Settings → API → JWT Settings.
   */
  supabaseJwtSecret: string;
  /** Certificate serial of the agent to verify and bind. */
  serial: string;
  /**
   * Upper bound on the minted JWT's lifetime, in seconds. The effective expiry
   * is min(this, certificate expiry). Default 3600 (1h).
   */
  maxTtlSeconds?: number;
  /**
   * Options forwarded to the underlying certificate verifier (baseUrl, timeout,
   * fail-closed policy, caching). Verification is always fail-closed by default.
   */
  verifyOptions?: KakuninVerifyOptions;
}

// ── base64url + HS256 (Web Crypto — edge/worker compatible, zero deps) ────────

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  // btoa is available in browsers, workers, and Node ≥ 16 globals.
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function utf8(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

async function signHS256(signingInput: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    utf8(secret) as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, utf8(signingInput) as BufferSource);
  return base64UrlEncode(new Uint8Array(sig));
}

export interface AgentSupabaseClaims {
  aud: 'authenticated';
  role: 'authenticated';
  sub: string;
  iat: number;
  exp: number;
  app_metadata: {
    provider: 'kakunin';
    cert_serial: string;
    cert_status: string;
    scopes: string[];
  };
  user_metadata: { is_agent: true };
}

/**
 * Build the JWT claim set for a verified agent. Exposed for testing and for
 * callers that manage Supabase client construction themselves.
 *
 * `exp` is capped at the certificate's own expiry so DB access can never
 * outlive the certificate.
 */
export function buildAgentSupabaseClaims(
  agent: AgentInfo,
  serial: string,
  maxTtlSeconds: number | undefined = DEFAULT_MAX_TTL_SECONDS,
  now: number = Math.floor(Date.now() / 1000)
): AgentSupabaseClaims {
  const certExpiry = Math.floor(new Date(agent.expires_at).getTime() / 1000);
  if (!Number.isFinite(certExpiry)) {
    throw new Error('Certificate expires_at is not a valid date');
  }
  const requestedExp = now + Math.max(1, Math.floor(maxTtlSeconds));
  const exp = Math.min(requestedExp, certExpiry);
  if (exp <= now) {
    throw new Error('Certificate is already expired; refusing to mint a session token');
  }
  return {
    aud: 'authenticated',
    role: 'authenticated',
    sub: agent.agent_id,
    iat: now,
    exp,
    app_metadata: {
      provider: 'kakunin',
      cert_serial: serial,
      cert_status: agent.certificate_status,
      scopes: agent.permitted_actions ?? [],
    },
    user_metadata: { is_agent: true },
  };
}

/**
 * Mint a signed Supabase JWT (HS256) for a verified agent. Pure — no cert
 * verification, no Supabase dependency. Prefer {@link bindAgentSession} unless
 * you have already verified the certificate yourself.
 */
export async function mintAgentSupabaseJwt(
  agent: AgentInfo,
  opts: { supabaseJwtSecret: string; serial: string; maxTtlSeconds?: number | undefined },
  now?: number
): Promise<string> {
  if (!opts.supabaseJwtSecret) throw new Error('supabaseJwtSecret is required');
  const claims = buildAgentSupabaseClaims(agent, opts.serial, opts.maxTtlSeconds, now);
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(utf8(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(utf8(JSON.stringify(claims)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await signHS256(signingInput, opts.supabaseJwtSecret);
  return `${signingInput}.${signature}`;
}

/**
 * Verify an agent certificate (fail-closed) and return a Supabase client scoped
 * to that agent via a short-lived signed JWT. Every query on the returned
 * client is constrained by your RLS policies to the agent's identity/scopes.
 *
 * Throws {@link KakuninVerifyError} if the certificate is revoked, expired, or
 * unverifiable — no client is returned in that case.
 *
 * @example
 * const supabase = await bindAgentSession({
 *   supabaseUrl: process.env.SUPABASE_URL!,
 *   supabaseAnonKey: process.env.SUPABASE_ANON_KEY!,
 *   supabaseJwtSecret: process.env.SUPABASE_JWT_SECRET!,
 *   serial: req.headers.get('x-kakunin-cert-serial')!,
 * });
 * const { data } = await supabase.from('trades').select('*'); // RLS-scoped
 */
export async function bindAgentSession(opts: BindAgentSessionOptions): Promise<SupabaseClient> {
  if (!opts.serial) throw new Error('serial is required');
  if (!opts.supabaseUrl || !opts.supabaseAnonKey) {
    throw new Error('supabaseUrl and supabaseAnonKey are required');
  }
  if (!opts.supabaseJwtSecret) throw new Error('supabaseJwtSecret is required');

  // Fail-closed cert verification (throws KakuninVerifyError if not active).
  const verifier = createVerifier(opts.verifyOptions);
  const agent = await verifier.cert(opts.serial);

  const token = await mintAgentSupabaseJwt(agent, {
    supabaseJwtSecret: opts.supabaseJwtSecret,
    serial: opts.serial,
    maxTtlSeconds: opts.maxTtlSeconds,
  });

  // Import lazily so the peer dependency is only needed when this function runs.
  const { createClient } = await import('@supabase/supabase-js');
  return createClient(opts.supabaseUrl, opts.supabaseAnonKey, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
}
