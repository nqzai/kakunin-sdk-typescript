/**
 * Kakunin Agents Resource
 *
 * kkn.agents.create()   → POST /v1/agents
 * kkn.agents.get()      → GET  /v1/agents/:id
 * kkn.agents.list()     → GET  /v1/agents
 * kkn.agents.update()   → PATCH /v1/agents/:id
 * kkn.agents.certify()  → POST /v1/agents/:id/certify
 * kkn.agents.getRisk()  → GET  /v1/agents/:id/risk
 */

import type { KakuninHttpClient } from '../client.js';
import type {
  Agent,
  Certificate,
  CreateAgentParams,
  ListAgentsParams,
  ListResult,
  RiskProfile,
  UpdateAgentParams,
} from '../types.js';

export class AgentsResource {
  constructor(private readonly http: KakuninHttpClient) {}

  /**
   * Register a new AI agent. Returns agent with status "pending".
   * Must call certify() to issue an X.509 certificate before the agent can sign.
   *
   * @example
   * const agent = await kkn.agents.create({
   *   name: 'Invoicing Bot v3.2',
   *   model_hash: await Kakunin.computeModelHash(modelWeightsBuffer),
   *   model: 'gpt-4o',
   *   permittedActions: ['read:invoices', 'write:drafts'],
   * });
   */
  async create(params: CreateAgentParams): Promise<Agent> {
    const res = await this.http.request<{ data: Agent }>('/agents', {
      method: 'POST',
      body: params,
    });
    return res.data;
  }

  /**
   * Get a single agent by ID, including its certificate history.
   */
  async get(agentId: string): Promise<Agent> {
    const res = await this.http.request<{ data: Agent }>(`/agents/${agentId}`);
    return res.data;
  }

  /**
   * List all agents for the tenant. Supports status filter and pagination.
   */
  async list(params: ListAgentsParams = {}): Promise<ListResult<Agent>> {
    return this.http.request<ListResult<Agent>>('/agents', {
      query: {
        status: params.status,
        limit: params.limit,
        offset: params.offset,
      },
    });
  }

  /**
   * Update agent name, model_hash, version, or status.
   * Status transitions: pending → active (auto on certify), active → suspended/retired.
   */
  async update(agentId: string, params: UpdateAgentParams): Promise<Agent> {
    const res = await this.http.request<{ data: Agent }>(`/agents/${agentId}`, {
      method: 'PATCH',
      body: params,
    });
    return res.data;
  }

  /**
   * Issue an X.509 certificate for the agent via AWS KMS.
   * Private key never leaves KMS. Returns the full certificate record including PEM.
   * Latency: < 3s end-to-end.
   *
   * Requires agent.model_hash to be set.
   * Returns 409 if agent already has an active certificate.
   *
   * @example
   * const cert = await kkn.agents.certify(agent.id);
   * console.log(cert.serial_number); // c4f9-17a2-6b8e
   * console.log(cert.expires_at);    // 2027-04-11T...
   */
  async certify(agentId: string): Promise<Certificate> {
    const res = await this.http.request<{ data: Certificate }>(`/agents/${agentId}/certify`, {
      method: 'POST',
      body: {},
    });
    return res.data;
  }

  /**
   * Get the rolling 30-day risk profile for an agent.
   * Includes trend, per-action-type breakdown, drift score, and recent high-risk events.
   * Designed for agents to self-assess compliance posture.
   *
   * @example
   * const risk = await kkn.agents.getRisk(agent.id);
   * if (risk.dominant_band === 'high') {
   *   console.warn('Agent at high risk — review recent events');
   * }
   */
  async getRisk(agentId: string): Promise<RiskProfile> {
    const res = await this.http.request<{ data: RiskProfile }>(`/agents/${agentId}/risk`);
    return res.data;
  }
}
