/**
 * Kakunin Webhook Helpers
 *
 * Verify HMAC-SHA256 signatures on inbound webhook deliveries.
 * Prevents spoofed webhook payloads from triggering revocation or alert logic.
 *
 * Usage:
 *   const payload = await kkn.webhooks.constructEvent(rawBody, signature, secret);
 */

import type { WebhookEventType, WebhookPayload } from './types.js';
import { KakuninError } from './types.js';

/** HTTP header name carrying the HMAC-SHA256 webhook signature. */
export const SIGNATURE_HEADER = 'x-kakunin-signature';
const TOLERANCE_MS = 5 * 60 * 1000; // 5 minutes

async function hmacSha256(key: string, data: string): Promise<string> {
  // Works in both Node.js 18+ and browser (Web Crypto API)
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export class WebhooksHelper {
  /**
   * Verify a Kakunin webhook signature and parse the payload.
   *
   * @param rawBody - Raw request body as string (do NOT parse before passing)
   * @param signature - Value of the x-kakunin-signature header
   * @param secret - Webhook signing secret from the Kakunin dashboard
   * @param toleranceMs - Max age of the webhook in ms. Default: 5 minutes
   *
   * @throws {KakuninError} If signature is invalid or payload is stale
   *
   * @example
   * // Next.js route handler
   * const rawBody = await req.text();
   * const sig = req.headers.get('x-kakunin-signature') ?? '';
   * const event = await kkn.webhooks.constructEvent(rawBody, sig, process.env.KAKUNIN_WEBHOOK_SECRET!);
   *
   * if (event.event === 'certificate.revoked') {
   *   await verifier.invalidate(event.data.serial_number);
   * }
   */
  async constructEvent<T = Record<string, unknown>>(
    rawBody: string,
    signature: string,
    secret: string,
    toleranceMs = TOLERANCE_MS,
  ): Promise<WebhookPayload<T>> {
    // Signature format: t=<timestamp>,v1=<hmac>
    const parts: Record<string, string> = {};
    for (const part of signature.split(',')) {
      const idx = part.indexOf('=');
      if (idx > 0) {
        parts[part.slice(0, idx)] = part.slice(idx + 1);
      }
    }

    const timestamp = parts['t'];
    const receivedHmac = parts['v1'];

    if (!timestamp || !receivedHmac) {
      throw new KakuninError('Invalid webhook signature format', 400, 'invalid_signature');
    }

    const age = Date.now() - parseInt(timestamp, 10) * 1000;
    if (Math.abs(age) > toleranceMs) {
      throw new KakuninError(
        `Webhook timestamp too old (${Math.round(age / 1000)}s). Possible replay attack.`,
        400,
        'webhook_expired',
      );
    }

    const signedPayload = `${timestamp}.${rawBody}`;
    const expectedHmac = await hmacSha256(secret, signedPayload);

    if (!timingSafeEqual(expectedHmac, receivedHmac)) {
      throw new KakuninError('Webhook signature mismatch', 400, 'invalid_signature');
    }

    return JSON.parse(rawBody) as WebhookPayload<T>;
  }

  /**
   * Type-guard helpers for webhook event types.
   *
   * @example
   * const event = await kkn.webhooks.constructEvent(...);
   * if (kkn.webhooks.isCertRevoked(event)) {
   *   // event.data is typed as the revocation payload
   * }
   */
  isEventType<T extends Record<string, unknown> = Record<string, unknown>>(
    event: WebhookPayload<Record<string, unknown>>,
    type: WebhookEventType,
  ): event is WebhookPayload<T> {
    return event.event === type;
  }
}
