/**
 * @kakunin/sdk — Official TypeScript SDK for the Kakunin AI Agent KYC Platform
 *
 * Kakunin issues X.509 cryptographic identities to AI agents, monitors their
 * behavior in real time, and generates MiCA & EU AI Act compliance reports.
 *
 * Usage:
 *   import { Kakunin } from '@kakunin/sdk';
 *
 *   const kkn = new Kakunin({ apiKey: process.env.KAKUNIN_API_KEY! });
 *
 *   const agent = await kkn.agents.create({ name: 'My Bot', model_hash: '...' });
 *   const cert  = await kkn.agents.certify(agent.id);
 *   const event = await kkn.events.ingest({ agentId: agent.id, actionType: 'api_call' });
 *
 * Sandbox mode: use kak_test_... keys — hits a real sandbox CA at no cost.
 *
 * @see https://docs.kakunin.ai
 */

export type {
  Agent,
  AgentStatus,
  Certificate,
  CertificateStatus,
  CreateAgentParams,
  UpdateAgentParams,
  ListAgentsParams,
  FinancialScope,
  ActionType,
  RiskBand,
  IngestEventParams,
  EventResult,
  BehaviorEvent,
  ListEventsParams,
  ListEventsResult,
  RiskProfile,
  VerifiedAgent,
  RevokeParams,
  RevokeResult,
  WebhookEventType,
  WebhookPayload,
  KakuninConfig,
  ListResult,
} from './types.js';

export { KakuninError, KakuninRateLimitError, KakuninAuthError } from './types.js';

import { KakuninHttpClient } from './client.js';
import { AgentsResource } from './resources/agents.js';
import { EventsResource } from './resources/events.js';
import { CertificatesResource } from './resources/certificates.js';
import { VerifyResource } from './resources/verify.js';
import { WebhooksHelper } from './webhooks.js';
import type { KakuninConfig } from './types.js';

/**
 * Kakunin SDK client.
 *
 * @example
 * const kkn = new Kakunin({ apiKey: process.env.KAKUNIN_API_KEY! });
 *
 * // Sandbox mode (kak_test_... key)
 * const sandbox = new Kakunin({ apiKey: 'kak_test_...' });
 * console.log(sandbox.isSandbox()); // true
 */
export class Kakunin {
  /** Agent registration, certification, risk profiling */
  readonly agents: AgentsResource;
  /** Behavioral event ingestion and querying */
  readonly events: EventsResource;
  /** Certificate revocation lifecycle */
  readonly certificates: CertificatesResource;
  /** Public certificate verification (no auth) */
  readonly verify: VerifyResource;
  /** Webhook signature verification */
  readonly webhooks: WebhooksHelper;

  private readonly http: KakuninHttpClient;

  constructor(config: KakuninConfig) {
    if (!config.apiKey) {
      throw new Error(
        '[Kakunin] apiKey is required. Get your key at https://kakunin.ai/dashboard',
      );
    }

    this.http = new KakuninHttpClient(
      config.apiKey,
      config.baseUrl,
      config.timeoutMs,
      config.maxRetries,
    );

    this.agents = new AgentsResource(this.http);
    this.events = new EventsResource(this.http);
    this.certificates = new CertificatesResource(this.http);
    this.verify = new VerifyResource(this.http);
    this.webhooks = new WebhooksHelper();
  }

  /**
   * Returns true when using a sandbox (kak_test_...) API key.
   * Sandbox certificates are issued by a test CA and have no regulatory validity.
   */
  isSandbox(): boolean {
    return this.http.isSandbox();
  }

  /**
   * Compute a SHA-256 model hash from raw bytes or a string.
   *
   * Pass model weights buffer, a JSON config string, or any deterministic
   * representation of the model. The hash binds the agent's identity to the
   * exact model version in the X.509 certificate.
   *
   * @example
   * // From a file (Node.js)
   * import { readFileSync } from 'fs';
   * const weights = readFileSync('./model.bin');
   * const hash = await Kakunin.computeModelHash(weights);
   *
   * // From a config string
   * const hash = await Kakunin.computeModelHash(JSON.stringify({ model: 'gpt-4o', version: '2024-08' }));
   */
  static async computeModelHash(input: BufferSource | string): Promise<string> {
    const encoder = new TextEncoder();
    const data = typeof input === 'string' ? encoder.encode(input) : input;
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hex = Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return `sha256:${hex}`;
  }
}

export default Kakunin;
