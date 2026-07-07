import { describe, it, expect, vi } from 'vitest';
import { createVerifier, kakuninMiddleware, kakuninExpress, handleRevocationWebhook, KakuninVerifyError } from '../src/verify/index.js';
import type { AgentInfo, KakuninRequest, KakuninResponse } from '../src/verify/index.js';

const ACTIVE_AGENT: AgentInfo = {
  agent_id: 'agt-123',
  agent_name: 'TradeBot',
  certificate_status: 'active',
  serial_number: '3A:F2:91:CC',
  issued_at: '2026-05-18T00:00:00Z',
  expires_at: '2027-05-18T00:00:00Z',
  model_hash: 'sha256:abc',
  permitted_actions: ['transaction_initiated'],
  financial_scope: null,
  halt_receipt: null,
};

const REVOKED_AGENT: AgentInfo = { ...ACTIVE_AGENT, certificate_status: 'revoked' };

function mockFetch(response: { data: AgentInfo } | { error: string }, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status < 400,
    status,
    json: () => Promise.resolve(response),
  });
}

// ── createVerifier ─────────────────────────────────────────────────────────────

describe('createVerifier', () => {
  it('returns AgentInfo for active cert', async () => {
    globalThis.fetch = mockFetch({ data: ACTIVE_AGENT });
    const verifier = createVerifier({ cacheTtlMs: 0 });
    const agent = await verifier.cert('3A:F2:91:CC');
    expect(agent.agent_id).toBe('agt-123');
  });

  it('throws KakuninVerifyError for revoked cert', async () => {
    globalThis.fetch = mockFetch({ data: REVOKED_AGENT });
    const verifier = createVerifier({ cacheTtlMs: 0 });
    await expect(verifier.cert('3A:F2:91:CC')).rejects.toThrow(KakuninVerifyError);
  });

  it('throws KakuninVerifyError on 404', async () => {
    globalThis.fetch = mockFetch({ error: 'Certificate not found' }, 404);
    const verifier = createVerifier({ cacheTtlMs: 0 });
    await expect(verifier.cert('MISSING')).rejects.toThrow(KakuninVerifyError);
  });

  it('caches active cert — only one fetch call', async () => {
    const fetchMock = mockFetch({ data: ACTIVE_AGENT });
    globalThis.fetch = fetchMock;
    const verifier = createVerifier({ cacheTtlMs: 60_000 });
    await verifier.cert('3A:F2:91:CC');
    await verifier.cert('3A:F2:91:CC');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('invalidate() forces re-fetch on next call', async () => {
    const fetchMock = mockFetch({ data: ACTIVE_AGENT });
    globalThis.fetch = fetchMock;
    const verifier = createVerifier({ cacheTtlMs: 60_000 });
    await verifier.cert('3A:F2:91:CC');
    verifier.invalidate('3A:F2:91:CC');
    await verifier.cert('3A:F2:91:CC');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

// ── kakuninMiddleware (Fetch API) ─────────────────────────────────────────────

describe('kakuninMiddleware', () => {
  it('returns agent when serial valid', async () => {
    globalThis.fetch = mockFetch({ data: ACTIVE_AGENT });
    const enforce = kakuninMiddleware({ cacheTtlMs: 0 });
    const req = new Request('https://example.com', {
      headers: { 'x-kakunin-cert-serial': '3A:F2:91:CC' },
    });
    const { agent } = await enforce(req);
    expect(agent?.agent_id).toBe('agt-123');
  });

  it('returns null agent when header missing', async () => {
    globalThis.fetch = mockFetch({ data: ACTIVE_AGENT });
    const enforce = kakuninMiddleware({ cacheTtlMs: 0 });
    const req = new Request('https://example.com');
    const { agent } = await enforce(req);
    expect(agent).toBeNull();
  });

  it('returns null agent when cert revoked', async () => {
    globalThis.fetch = mockFetch({ data: REVOKED_AGENT });
    const enforce = kakuninMiddleware({ cacheTtlMs: 0 });
    const req = new Request('https://example.com', {
      headers: { 'x-kakunin-cert-serial': '3A:F2:91:CC' },
    });
    const { agent } = await enforce(req);
    expect(agent).toBeNull();
  });

  it('reject() returns correct status + JSON body', async () => {
    globalThis.fetch = mockFetch({ data: ACTIVE_AGENT });
    const enforce = kakuninMiddleware({ cacheTtlMs: 0 });
    const req = new Request('https://example.com');
    const { reject } = await enforce(req);
    const response = reject('Missing cert', 401);
    expect(response.status).toBe(401);
    const body = await response.json() as { error: string };
    expect(body.error).toBe('Missing cert');
  });
});

// ── kakuninExpress ────────────────────────────────────────────────────────────

describe('kakuninExpress', () => {
  it('calls next() and sets req.kakuninAgent on success', async () => {
    globalThis.fetch = mockFetch({ data: ACTIVE_AGENT });
    const middleware = kakuninExpress({ cacheTtlMs: 0 });

    const req: KakuninRequest = { headers: { 'x-kakunin-cert-serial': '3A:F2:91:CC' } };
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() } as unknown as KakuninResponse;
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith();
    expect(req.kakuninAgent?.agent_id).toBe('agt-123');
  });

  it('returns 401 when header missing', async () => {
    const middleware = kakuninExpress({ cacheTtlMs: 0 });
    const req: KakuninRequest = { headers: {} };
    const statusMock = vi.fn().mockReturnThis();
    const jsonMock = vi.fn();
    const res = { status: statusMock, json: jsonMock } as unknown as KakuninResponse;
    const next = vi.fn();

    await middleware(req, res, next);

    expect(statusMock).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });
});

// ── handleRevocationWebhook ───────────────────────────────────────────────────

describe('handleRevocationWebhook', () => {
  it('calls invalidate on certificate.revoked event', async () => {
    const fetchMock = mockFetch({ data: ACTIVE_AGENT });
    globalThis.fetch = fetchMock;
    const verifier = createVerifier({ cacheTtlMs: 60_000 });
    await verifier.cert('3A:F2:91:CC');

    handleRevocationWebhook(verifier, {
      event: 'certificate.revoked',
      serial_number: '3A:F2:91:CC',
    });

    // Next call should hit API again (cache evicted)
    await verifier.cert('3A:F2:91:CC');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('ignores non-revocation events', async () => {
    const fetchMock = mockFetch({ data: ACTIVE_AGENT });
    globalThis.fetch = fetchMock;
    const verifier = createVerifier({ cacheTtlMs: 60_000 });
    await verifier.cert('3A:F2:91:CC');

    handleRevocationWebhook(verifier, { event: 'risk.alert', serial_number: '3A:F2:91:CC' });

    await verifier.cert('3A:F2:91:CC');
    expect(fetchMock).toHaveBeenCalledTimes(1); // still cached
  });
});
