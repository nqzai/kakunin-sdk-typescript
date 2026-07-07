/**
 * @kakunin/sdk/verify — drop-in enforcement middleware for Kakunin AI agent certificates.
 *
 * Verifies X-Kakunin-Cert-Serial on inbound requests.
 * Works with any framework that uses the Fetch API Request/Response model
 * (Next.js, Cloudflare Workers, Hono, Remix) or standard Node.js http.IncomingMessage.
 *
 * Usage (Next.js middleware):
 *   import { kakuninMiddleware } from '@kakunin/sdk/verify';
 *   export const middleware = kakuninMiddleware();
 *
 * Usage (Express):
 *   import { kakuninExpress } from '@kakunin/sdk/verify';
 *   app.use(kakuninExpress());
 *
 * Usage (manual):
 *   import { createVerifier } from '@kakunin/sdk/verify';
 *   const verify = createVerifier();
 *   const agent = await verify.cert(serial);
 */

export type {
  AgentInfo,
  MessageVerifyResult,
  FinancialScope,
  CertificateStatus,
  KakuninVerifyOptions,
  VerifyTimeoutPolicy,
} from './types.js';
export { KakuninVerifyError } from './types.js';

import { CertCache } from './cache.js';
import { KakuninApiClient } from './client.js';
import type { AgentInfo, KakuninVerifyOptions, MessageVerifyResult } from './types.js';
import { KakuninVerifyError } from './types.js';

const DEFAULT_CACHE_TTL_MS = 60_000;

// ── Core verifier ─────────────────────────────────────────────────────────────

export interface KakuninVerifier {
  /**
   * Verify a certificate serial. Returns AgentInfo if active.
   * Throws KakuninVerifyError if revoked, expired, or not found.
   * Results are cached for cacheTtlMs (default 60s).
   */
  cert(serial: string): Promise<AgentInfo>;

  /**
   * Verify a signed message. Uses POST /v1/verify/message (no auth, no cache).
   * Returns MessageVerifyResult — check .valid before trusting the payload.
   */
  message(
    payload: Record<string, unknown>,
    signature: string,
    certificateSerial: string
  ): Promise<MessageVerifyResult>;

  /**
   * Invalidate a cached cert entry immediately.
   * Call this in your certificate.revoked webhook handler.
   */
  invalidate(serial: string): void;
}

/** Returns true for errors that indicate the API is unreachable (not auth/data errors). */
function isNetworkError(err: unknown): boolean {
  if (err instanceof Error) {
    // AbortError = timeout; TypeError = network failure (DNS, refused, etc.)
    return err.name === 'AbortError' || err instanceof TypeError;
  }
  return false;
}

export function createVerifier(options: KakuninVerifyOptions = {}): KakuninVerifier {
  const cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  const timeoutPolicy = options.onVerifyTimeout ?? 'fail-closed';
  const staleFallback = options.staleCacheFallback ?? false;
  const cache = new CertCache(cacheTtlMs);
  const api = new KakuninApiClient(options.baseUrl, options.verifyTimeoutMs);

  return {
    async cert(serial: string): Promise<AgentInfo> {
      if (cacheTtlMs > 0) {
        const cached = cache.get(serial);
        if (cached) return cached;
      }

      let info: AgentInfo;
      try {
        info = await api.fetchCertInfo(serial);
      } catch (err) {
        if (isNetworkError(err)) {
          // Try stale cache before applying timeout policy
          if (staleFallback && cacheTtlMs > 0) {
            const stale = cache.getStale(serial);
            if (stale) return stale;
          }
          if (timeoutPolicy === 'fail-open') {
            // Caller (middleware) receives null agent — request passes through
            throw Object.assign(new KakuninVerifyError('Verify API unreachable', 503, serial), {
              isFailOpen: true,
            });
          }
          // fail-closed default
          throw new KakuninVerifyError('Verify API unreachable — request blocked (fail-closed)', 503, serial);
        }
        throw err;
      }

      if (info.certificate_status !== 'active') {
        throw new KakuninVerifyError(
          `Certificate is ${info.certificate_status}`,
          403,
          serial
        );
      }

      if (cacheTtlMs > 0) {
        cache.set(serial, info);
      }

      return info;
    },

    async message(
      payload: Record<string, unknown>,
      signature: string,
      certificateSerial: string
    ): Promise<MessageVerifyResult> {
      return api.verifyMessage(payload, signature, certificateSerial);
    },

    invalidate(serial: string): void {
      cache.invalidate(serial);
    },
  };
}

// ── Fetch-API middleware (Next.js, Cloudflare Workers, Hono) ──────────────────

export interface KakuninMiddlewareResult {
  /** Populated when verification passes. Attach to your request context. */
  agent: AgentInfo | null;
  /** Call this to produce a 401/403 response when verification fails. */
  reject: (message: string, status?: number) => Response;
}

/**
 * Creates a Next.js / Fetch API middleware that enforces X-Kakunin-Cert-Serial.
 *
 * Returns null when the serial is missing/invalid so you can choose whether to
 * reject or allow anonymous requests through.
 *
 * @example
 * // middleware.ts (Next.js)
 * import { kakuninMiddleware } from '@kakunin/sdk/verify';
 * const enforce = kakuninMiddleware();
 *
 * export async function middleware(req: NextRequest) {
 *   const { agent, reject } = await enforce(req);
 *   if (!agent) return reject('Missing or invalid agent certificate');
 *   // req.agent is now typed AgentInfo
 * }
 */
export function kakuninMiddleware(options: KakuninVerifyOptions = {}) {
  const verifier = createVerifier(options);

  return async function enforce(req: Request): Promise<KakuninMiddlewareResult> {
    const reject = (message: string, status = 401): Response =>
      new Response(JSON.stringify({ error: message }), {
        status,
        headers: { 'Content-Type': 'application/json' },
      });

    const serial = req.headers.get('x-kakunin-cert-serial');
    if (!serial) {
      return { agent: null, reject };
    }

    try {
      const agent = await verifier.cert(serial);
      return { agent, reject };
    } catch (err) {
      if (err instanceof KakuninVerifyError) {
        // fail-open network error: treat as anonymous so caller decides
        if ((err as KakuninVerifyError & { isFailOpen?: boolean }).isFailOpen) {
          return { agent: null, reject };
        }
        // fail-closed (or auth error): reject preserves the upstream status
        const upstreamStatus = err.status;
        const failReject = (message: string, status = upstreamStatus): Response =>
          new Response(JSON.stringify({ error: message }), {
            status,
            headers: { 'Content-Type': 'application/json' },
          });
        return { agent: null, reject: failReject };
      }
      throw err;
    }
  };
}

// ── Express-style middleware ───────────────────────────────────────────────────

export interface KakuninRequest {
  headers: Record<string, string | string[] | undefined>;
  kakuninAgent?: AgentInfo;
}

export interface KakuninResponse {
  status(code: number): KakuninResponse;
  json(body: unknown): void;
}

type NextFn = (err?: unknown) => void;

/**
 * Express-compatible middleware. Attaches `req.kakuninAgent` on success.
 * Calls next(err) on unexpected errors; returns 401/403 on cert failure.
 *
 * @example
 * import { kakuninExpress } from '@kakunin/sdk/verify';
 * app.use('/api', kakuninExpress());
 */
export function kakuninExpress(options: KakuninVerifyOptions = {}) {
  const verifier = createVerifier(options);

  return async function middleware(
    req: KakuninRequest,
    res: KakuninResponse,
    next: NextFn
  ): Promise<void> {
    const rawSerial = req.headers['x-kakunin-cert-serial'];
    const serial = Array.isArray(rawSerial) ? rawSerial[0] : rawSerial;

    if (!serial) {
      res.status(401).json({ error: 'Missing X-Kakunin-Cert-Serial header' });
      return;
    }

    try {
      req.kakuninAgent = await verifier.cert(serial);
      next();
    } catch (err) {
      if (err instanceof KakuninVerifyError) {
        res.status(err.status).json({ error: err.message });
      } else {
        next(err);
      }
    }
  };
}

// ── Webhook helper — cache invalidation ───────────────────────────────────────

/**
 * Handles Kakunin `certificate.revoked` webhook payloads.
 * Call this in your webhook endpoint to evict the cert from the local cache
 * so the next request immediately sees the revocation.
 *
 * @example
 * const verifier = createVerifier();
 *
 * // POST /webhooks/kakunin
 * app.post('/webhooks/kakunin', (req, res) => {
 *   handleRevocationWebhook(verifier, req.body);
 *   res.sendStatus(200);
 * });
 */
export function handleRevocationWebhook(
  verifier: KakuninVerifier,
  payload: { event?: string; serial_number?: string }
): void {
  if (payload.event === 'certificate.revoked' && payload.serial_number) {
    verifier.invalidate(payload.serial_number);
  }
}
