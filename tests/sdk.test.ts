/**
 * @kakunin/sdk — Unit Tests
 *
 * Mocks fetch globally. Tests client retry, error mapping, resource wrappers,
 * webhook verification, and model hash utility.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Kakunin, KakuninError, KakuninAuthError } from '../src/index.js';

// ── Fetch mock helpers ────────────────────────────────────────────────────────

function mockFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (key: string) => headers[key.toLowerCase()] ?? null,
    },
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

function mockFetchSequence(responses: Array<{ status: number; body: unknown }>) {
  let call = 0;
  return vi.fn().mockImplementation(() => {
    const r = responses[call++] ?? responses[responses.length - 1];
    return Promise.resolve({
      ok: (r?.status ?? 200) >= 200 && (r?.status ?? 200) < 300,
      status: r?.status ?? 200,
      headers: { get: () => null },
      json: () => Promise.resolve(r?.body),
    });
  });
}

// ── Setup ─────────────────────────────────────────────────────────────────────

let kkn: Kakunin;

beforeEach(() => {
  kkn = new Kakunin({ apiKey: 'kak_test_abc123', maxRetries: 1 });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Constructor ───────────────────────────────────────────────────────────────

describe('Kakunin constructor', () => {
  it('throws if apiKey missing', () => {
    expect(() => new Kakunin({ apiKey: '' })).toThrow('[Kakunin] apiKey is required');
  });

  it('detects sandbox from kak_test_ prefix', () => {
    const sandbox = new Kakunin({ apiKey: 'kak_test_xxx' });
    expect(sandbox.isSandbox()).toBe(true);
  });

  it('live key is not sandbox', () => {
    const live = new Kakunin({ apiKey: 'kak_live_xxx' });
    expect(live.isSandbox()).toBe(false);
  });
});

// ── computeModelHash ──────────────────────────────────────────────────────────

describe('Kakunin.computeModelHash', () => {
  it('returns sha256: prefixed hex string', async () => {
    const hash = await Kakunin.computeModelHash('test-model-v1.0');
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('is deterministic', async () => {
    const h1 = await Kakunin.computeModelHash('my-model');
    const h2 = await Kakunin.computeModelHash('my-model');
    expect(h1).toBe(h2);
  });

  it('differs for different inputs', async () => {
    const h1 = await Kakunin.computeModelHash('model-v1');
    const h2 = await Kakunin.computeModelHash('model-v2');
    expect(h1).not.toBe(h2);
  });
});

// ── Agents ────────────────────────────────────────────────────────────────────

describe('kkn.agents.create', () => {
  it('returns agent on 201', async () => {
    const agent = { id: 'agt_1', name: 'Test Bot', status: 'pending' };
    global.fetch = mockFetch(201, { data: agent });

    const result = await kkn.agents.create({ name: 'Test Bot', model_hash: 'sha256:abc' });
    expect(result.id).toBe('agt_1');
    expect(result.status).toBe('pending');
  });

  it('throws KakuninError on 422', async () => {
    global.fetch = mockFetch(422, { error: 'Agent limit reached' });
    await expect(kkn.agents.create({ name: 'X', model_hash: 'sha256:abc' }))
      .rejects.toThrow('Agent limit reached');
  });
});

describe('kkn.agents.certify', () => {
  it('returns certificate on 201', async () => {
    const cert = { id: 'cert_1', serial_number: 'c4f9-17a2', status: 'active' };
    global.fetch = mockFetch(201, { data: cert });

    const result = await kkn.agents.certify('agt_1');
    expect(result.serial_number).toBe('c4f9-17a2');
    expect(result.status).toBe('active');
  });

  it('throws on 409 (already certified)', async () => {
    global.fetch = mockFetch(409, { error: 'Agent already has an active certificate' });
    await expect(kkn.agents.certify('agt_1')).rejects.toThrow('already has an active certificate');
  });
});

describe('kkn.agents.getRisk', () => {
  it('returns risk profile', async () => {
    const profile = { agent_id: 'agt_1', dominant_band: 'low', avg_score: 0.12 };
    global.fetch = mockFetch(200, { data: profile });

    const result = await kkn.agents.getRisk('agt_1');
    expect(result.dominant_band).toBe('low');
    expect(result.avg_score).toBe(0.12);
  });
});

// ── Events ────────────────────────────────────────────────────────────────────

describe('kkn.events.ingest', () => {
  it('returns scored event result', async () => {
    const eventResult = { event_id: 'evt_1', risk_score: 0.12, risk_band: 'low', revocation_check_queued: false };
    global.fetch = mockFetch(200, { data: eventResult });

    const result = await kkn.events.ingest({
      agentId: 'agt_1',
      actionType: 'api_call',
      details: { endpoint: '/api/invoices' },
    });

    expect(result.risk_band).toBe('low');
    expect(result.revocation_check_queued).toBe(false);
  });

  it('flags high risk events', async () => {
    const eventResult = { event_id: 'evt_2', risk_score: 0.91, risk_band: 'high', revocation_check_queued: true };
    global.fetch = mockFetch(200, { data: eventResult });

    const result = await kkn.events.ingest({
      agentId: 'agt_1',
      actionType: 'unauthorized_access_attempt',
    });

    expect(result.risk_band).toBe('high');
    expect(result.revocation_check_queued).toBe(true);
  });
});

// ── Certificates ──────────────────────────────────────────────────────────────

describe('kkn.certificates.revoke', () => {
  it('returns revocation result', async () => {
    const revokeResult = { certificate_id: 'cert_1', status: 'revoked', revoked_at: '2026-05-20T00:00:00Z', reason: 'Compromised' };
    global.fetch = mockFetch(200, { data: revokeResult });

    const result = await kkn.certificates.revoke('cert_1', { reason: 'Compromised' });
    expect(result.status).toBe('revoked');
  });
});

// ── Verify (public) ───────────────────────────────────────────────────────────

describe('kkn.verify.cert', () => {
  it('returns verified agent info — no auth header sent', async () => {
    const agentInfo = { status: 'active', serial: 'c4f9-17a2', agent_name: 'Bot' };
    const fetchMock = mockFetch(200, { data: agentInfo });
    global.fetch = fetchMock;

    const result = await kkn.verify.cert('c4f9-17a2');
    expect(result.status).toBe('active');

    // Verify no Authorization header was sent
    const calledHeaders = (fetchMock.mock.calls[0] as unknown[][])[1] as { headers: Record<string, string> };
    expect(calledHeaders.headers['Authorization']).toBeUndefined();
  });
});

// ── Error handling ────────────────────────────────────────────────────────────

describe('Error mapping', () => {
  it('throws KakuninAuthError on 401', async () => {
    global.fetch = mockFetch(401, { error: 'Invalid API key' });
    await expect(kkn.agents.get('agt_1')).rejects.toThrow(KakuninAuthError);
  });

  it('retries on 500 then succeeds', async () => {
    const agent = { id: 'agt_1', name: 'Bot', status: 'active' };
    global.fetch = mockFetchSequence([
      { status: 500, body: { error: 'Internal error' } },
      { status: 200, body: { data: agent } },
    ]);

    const result = await kkn.agents.get('agt_1');
    expect(result.id).toBe('agt_1');
  });

  it('throws after max retries exhausted on 500', async () => {
    global.fetch = mockFetch(500, { error: 'Server error' });
    await expect(kkn.agents.get('agt_1')).rejects.toThrow(KakuninError);
  });
});

// ── Webhooks ──────────────────────────────────────────────────────────────────

describe('kkn.webhooks.constructEvent', () => {
  const secret = 'whsec_test_secret';

  async function buildSignature(payload: string, secret: string, timestamp: number) {
    const encoder = new TextEncoder();
    const signed = `${timestamp}.${payload}`;
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(signed));
    const hex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
    return `t=${timestamp},v1=${hex}`;
  }

  it('verifies a valid signature', async () => {
    const payload = JSON.stringify({ event: 'certificate.revoked', id: 'evt_1', data: {} });
    const ts = Math.floor(Date.now() / 1000);
    const sig = await buildSignature(payload, secret, ts);

    const event = await kkn.webhooks.constructEvent(payload, sig, secret);
    expect(event.event).toBe('certificate.revoked');
  });

  it('throws on invalid signature', async () => {
    const payload = JSON.stringify({ event: 'certificate.revoked' });
    const ts = Math.floor(Date.now() / 1000);
    const sig = `t=${ts},v1=badhash`;

    await expect(kkn.webhooks.constructEvent(payload, sig, secret))
      .rejects.toThrow('signature mismatch');
  });

  it('throws on stale timestamp', async () => {
    const payload = JSON.stringify({ event: 'certificate.revoked' });
    const staleTs = Math.floor(Date.now() / 1000) - 400;
    const sig = await buildSignature(payload, secret, staleTs);

    await expect(kkn.webhooks.constructEvent(payload, sig, secret, 60_000))
      .rejects.toThrow('timestamp too old');
  });
});
