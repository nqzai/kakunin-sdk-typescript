export type CertificateStatus = 'active' | 'revoked' | 'expired' | 'suspended';

export interface FinancialScope {
  max_single_trade_usd: number | null;
  daily_limit_usd: number | null;
  permitted_instruments: string[];
  permitted_venues: string[];
  leverage_permitted: boolean;
  max_leverage_ratio: number | null;
}

export interface AgentInfo {
  agent_id: string;
  agent_name: string;
  certificate_status: CertificateStatus;
  serial_number: string;
  issued_at: string;
  expires_at: string;
  model_hash: string | null;
  permitted_actions: string[];
  financial_scope: FinancialScope | null;
  halt_receipt: Record<string, unknown> | null;
}

export interface MessageVerifyResult {
  valid: boolean;
  certificate_status: CertificateStatus | null;
  agent_id: string | null;
  agent_name: string | null;
  model_hash: string | null;
}

/**
 * What to do when the Kakunin verify API is unreachable (timeout or network error).
 * - 'fail-closed' (default): throw KakuninVerifyError — the request is blocked
 * - 'fail-open': allow the request through (agent is null in middleware)
 *
 * staleCacheFallback takes priority over this policy when a stale cache entry exists.
 */
export type VerifyTimeoutPolicy = 'fail-closed' | 'fail-open';

export interface KakuninVerifyOptions {
  /** Base URL of the Kakunin API. Default: https://api.kakunin.ai/v1 */
  baseUrl?: string;
  /**
   * TTL in ms for the verified-cert cache. Default: 60_000 (60s).
   * Set to 0 to disable caching (always hits the API).
   */
  cacheTtlMs?: number;
  /**
   * Request timeout for verify API calls in ms. Default: 5_000 (5s).
   * If the API does not respond within this window, onVerifyTimeout policy applies.
   */
  verifyTimeoutMs?: number;
  /**
   * Policy applied when the verify API is unreachable or times out.
   * Default: 'fail-closed' — the request is blocked with 503.
   *
   * If staleCacheFallback is true and a stale cache entry exists, it is served
   * instead of applying this policy.
   */
  onVerifyTimeout?: VerifyTimeoutPolicy;
  /**
   * Serve a stale cache entry when the verify API is unreachable, instead of
   * applying onVerifyTimeout policy. Stale window: up to 5× cacheTtlMs.
   * Default: false.
   */
  staleCacheFallback?: boolean;
  /** Called when a request is rejected. Default: throws KakuninVerifyError. */
  onUnauthorized?: (reason: string, serial: string | null) => Response | Promise<Response>;
}

export class KakuninVerifyError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly serial: string | null = null
  ) {
    super(message);
    this.name = 'KakuninVerifyError';
  }
}
