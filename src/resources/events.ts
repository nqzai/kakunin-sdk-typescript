/**
 * Kakunin Events Resource
 *
 * kkn.events.ingest()  → POST /v1/events
 * kkn.events.list()    → GET  /v1/events
 *
 * Events feed the rolling 30-day risk score engine.
 * High-risk events (band=high) trigger async revocation checks via QStash.
 */

import type { KakuninHttpClient } from '../client.js';
import type {
  EventResult,
  IngestEventParams,
  ListEventsParams,
  ListEventsResult,
} from '../types.js';

export class EventsResource {
  constructor(private readonly http: KakuninHttpClient) {}

  /**
   * Ingest a behavioral event for an agent.
   * Returns the risk score, band, and whether a revocation check was queued.
   * Latency: p99 200ms.
   *
   * @example
   * const result = await kkn.events.ingest({
   *   agentId: agent.id,
   *   actionType: 'transaction_initiated',
   *   details: { amount: 840, currency: 'EUR', venue: 'euronext' },
   * });
   * // → { risk_score: 0.12, risk_band: 'low', revocation_check_queued: false }
   */
  async ingest(params: IngestEventParams): Promise<EventResult> {
    const res = await this.http.request<{ data: EventResult }>('/events', {
      method: 'POST',
      body: params,
    });
    return res.data;
  }

  /**
   * List behavioral events for the tenant (cursor-based pagination).
   * Filter by agent_id, risk band, or action_type.
   *
   * @example
   * const events = await kkn.events.list({ agent_id: agent.id, band: 'high' });
   * // Paginate:
   * const next = await kkn.events.list({ before: events.pagination.next_cursor });
   */
  async list(params: ListEventsParams = {}): Promise<ListEventsResult> {
    return this.http.request<ListEventsResult>('/events', {
      query: {
        agent_id: params.agent_id,
        band: params.band,
        action_type: params.action_type,
        before: params.before,
        limit: params.limit,
      },
    });
  }
}
