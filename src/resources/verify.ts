/**
 * Kakunin Verify Resource — Public endpoints, no authentication required.
 *
 * kkn.verify.cert()   → GET /v1/verify/:serial
 *
 * Counterparties, regulators, and auditors use these endpoints to confirm
 * agent identity without needing an API key.
 * Globally CDN-cached, p99 < 500ms.
 */

import type { KakuninHttpClient } from '../client.js';
import type { VerifiedAgent } from '../types.js';

export class VerifyResource {
  constructor(private readonly http: KakuninHttpClient) {}

  /**
   * Verify an agent certificate by serial number.
   * Public endpoint — no authentication required.
   * Cached 60s at the edge.
   *
   * @example
   * const agent = await kkn.verify.cert('c4f9-17a2-6b8e');
   * if (agent.status !== 'active') throw new Error('Agent cert not active');
   * if (!agent.permitted_actions.includes('write:drafts')) throw new Error('Scope exceeded');
   */
  async cert(serial: string): Promise<VerifiedAgent> {
    const res = await this.http.request<{ data: VerifiedAgent }>(
      `/verify/${encodeURIComponent(serial)}`,
      { skipAuth: true },
    );
    return res.data;
  }
}
