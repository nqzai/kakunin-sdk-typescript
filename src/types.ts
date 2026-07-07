/**
 * Kakunin SDK — Core Types
 *
 * All request/response types are Zod-validated at runtime.
 * Types here are the TypeScript interfaces derived from API contracts.
 */

// ── Agent ─────────────────────────────────────────────────────────────────────

export type AgentStatus = 'pending' | 'active' | 'suspended' | 'retired';

export interface FinancialScope {
  max_single_trade_usd: number;
  daily_limit_usd: number;
  permitted_instruments: string[];
  permitted_venues: string[];
  leverage_permitted: boolean;
  max_leverage_ratio?: number;
}

export interface Agent {
  id: string;
  tenant_id: string;
  name: string;
  model_hash: string;
  model: string | null;
  version: string | null;
  description: string | null;
  status: AgentStatus;
  metadata: Record<string, unknown>;
  inbox_address: string | null;
  created_at: string;
  updated_at: string;
  certificates?: Certificate[];
}

export interface CreateAgentParams {
  /** Human-readable name for the agent */
  name: string;
  /**
   * SHA-256 hash of the model weights/config.
   * Required before certifying. Use Kakunin.computeModelHash() to generate.
   */
  model_hash: string;
  /** Model identifier e.g. "gpt-4o", "claude-3-5-sonnet" */
  model?: string;
  /** Semver or build tag e.g. "v3.2.1" */
  version?: string;
  description?: string;
  /** Financial scope encoded in the X.509 certificate */
  financial_scope?: FinancialScope;
  metadata?: Record<string, unknown>;
}

export interface UpdateAgentParams {
  name?: string;
  model_hash?: string;
  model?: string | null;
  version?: string | null;
  description?: string | null;
  status?: AgentStatus;
  metadata?: Record<string, unknown>;
}

export interface ListAgentsParams {
  status?: AgentStatus;
  limit?: number;
  offset?: number;
}

// ── Certificate ───────────────────────────────────────────────────────────────

export type CertificateStatus = 'active' | 'revoked' | 'expired';

export interface Certificate {
  id: string;
  agent_id: string;
  tenant_id: string;
  serial_number: string;
  certificate_pem: string;
  status: CertificateStatus;
  issued_at: string;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
}

export interface RevokeParams {
  reason: string;
}

export interface RevokeResult {
  certificate_id: string;
  status: 'revoked';
  revoked_at: string;
  reason: string;
}

// ── Events ────────────────────────────────────────────────────────────────────

export type ActionType =
  | 'api_call'
  | 'authentication_attempt'
  | 'authentication_failure'
  | 'data_access'
  | 'data_mutation'
  | 'transaction_initiated'
  | 'transaction_anomaly'
  | 'unauthorized_access_attempt'
  | 'message_signed'
  | 'message_verification_failed';

export type RiskBand = 'low' | 'medium' | 'high';

export interface IngestEventParams {
  agentId: string;
  actionType: ActionType;
  chainId?: string;
  sessionId?: string;
  /** ISO 8601 timestamp. Defaults to server-side now(). */
  occurredAt?: string;
  details?: Record<string, unknown>;
}

export interface EventResult {
  event_id: string;
  risk_score: number;
  risk_band: RiskBand;
  action_type: ActionType;
  occurred_at: string;
  revocation_check_queued: boolean;
}

export interface BehaviorEvent {
  id: string;
  agent_id: string;
  action_type: ActionType;
  risk_score: number;
  risk_band: RiskBand;
  occurred_at: string;
  source_ip: string | null;
  payload: Record<string, unknown>;
}

export interface ListEventsParams {
  agent_id?: string;
  band?: RiskBand;
  action_type?: ActionType;
  before?: string;
  limit?: number;
}

export interface ListEventsResult {
  data: BehaviorEvent[];
  pagination: {
    limit: number;
    has_next_page: boolean;
    next_cursor: string | null;
  };
}

// ── Risk ──────────────────────────────────────────────────────────────────────

export interface RiskProfile {
  agent_id: string;
  agent_name: string;
  agent_status: AgentStatus;
  window_days: 30;
  window_start: string;
  total_events: number;
  avg_score: number;
  dominant_band: RiskBand;
  high_risk_event_count: number;
  event_counts_by_type: Record<string, { count: number; avg_score: number }>;
  recent_high_risk_events: Array<{
    id: string;
    action_type: ActionType;
    risk_score: number;
    occurred_at: string;
    source_ip: string | null;
  }>;
  trend: Array<{
    date: string;
    avg_score: number;
    event_count: number;
    dominant_band: RiskBand;
  }>;
  drift: {
    drift_score: number | null;
    drift_band: 'normal' | 'elevated' | 'anomalous' | null;
    contributing_factors: string[] | null;
    computed_at: string | null;
    drift_trend: 'increasing' | 'decreasing' | 'stable' | null;
    baseline_established_at: string | null;
    baseline_events_analyzed: number | null;
    note?: string;
  };
}

// ── Verify (public, no auth) ──────────────────────────────────────────────────

export interface VerifiedAgent {
  status: CertificateStatus;
  serial: string;
  agent_name: string;
  operator_org: string | null;
  permitted_actions: string[];
  model_hash: string | null;
  valid_from: string;
  valid_until: string;
  issuer: string;
  revocation_reason: string | null;
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

export type WebhookEventType =
  | 'certificate.issued'
  | 'certificate.revoked'
  | 'risk.alert'
  | 'agent.created'
  | 'agent.updated';

export interface WebhookPayload<T = Record<string, unknown>> {
  id: string;
  event: WebhookEventType;
  tenant_id: string;
  created_at: string;
  data: T;
}

// ── SDK config ────────────────────────────────────────────────────────────────

export interface KakuninConfig {
  /** API key — kak_live_... or kak_test_... for sandbox */
  apiKey: string;
  /** Override base URL for self-hosted or staging. Default: https://api.kakunin.ai/v1 */
  baseUrl?: string;
  /** Request timeout in ms. Default: 10_000 */
  timeoutMs?: number;
  /** Max retries on 5xx/network errors. Default: 3 */
  maxRetries?: number;
}

// ── Errors ────────────────────────────────────────────────────────────────────

export class KakuninError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
    public readonly requestId?: string,
  ) {
    super(message);
    this.name = 'KakuninError';
  }
}

export class KakuninRateLimitError extends KakuninError {
  constructor(
    message: string,
    public readonly retryAfter: number,
    requestId?: string,
  ) {
    super(message, 429, 'rate_limit_exceeded', requestId);
    this.name = 'KakuninRateLimitError';
  }
}

export class KakuninAuthError extends KakuninError {
  constructor(message: string, requestId?: string) {
    super(message, 401, 'unauthorized', requestId);
    this.name = 'KakuninAuthError';
  }
}

// ── List result wrapper ───────────────────────────────────────────────────────

export interface ListResult<T> {
  data: T[];
  meta: {
    total: number;
    limit: number;
    offset: number;
  };
}
