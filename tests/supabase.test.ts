import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  buildAgentSupabaseClaims,
  mintAgentSupabaseJwt,
  bindAgentSession,
} from '../src/verify/supabase.js';
import type { AgentInfo } from '../src/verify/types.js';
import { KakuninVerifyError } from '../src/verify/index.js';

const NOW = 1_800_000_000; // fixed epoch seconds for deterministic exp

function agent(overrides: Partial<AgentInfo> = {}): AgentInfo {
  return {
    agent_id: 'agt-123',
    agent_name: 'TradeBot',
    certificate_status: 'active',
    serial_number: '3A:F2:91:CC',
    issued_at: new Date((NOW - 86_400) * 1000).toISOString(),
    expires_at: new Date((NOW + 365 * 86_400) * 1000).toISOString(), // ~1yr out
    model_hash: 'sha256:abc',
    permitted_actions: ['trade.execute', 'data.read'],
    financial_scope: null,
    halt_receipt: null,
    ...overrides,
  };
}

function decodeSegment(seg: string): Record<string, unknown> {
  const b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

describe('buildAgentSupabaseClaims', () => {
  it('maps agent identity + scopes into Supabase claims', () => {
    const c = buildAgentSupabaseClaims(agent(), '3A:F2:91:CC', 3600, NOW);
    expect(c.sub).toBe('agt-123');
    expect(c.aud).toBe('authenticated');
    expect(c.role).toBe('authenticated');
    expect(c.app_metadata.provider).toBe('kakunin');
    expect(c.app_metadata.cert_serial).toBe('3A:F2:91:CC');
    expect(c.app_metadata.cert_status).toBe('active');
    expect(c.app_metadata.scopes).toEqual(['trade.execute', 'data.read']);
    expect(c.user_metadata.is_agent).toBe(true);
    expect(c.iat).toBe(NOW);
    expect(c.exp).toBe(NOW + 3600); // maxTtl applies when cert expiry is far
  });

  it('caps exp at certificate expiry when the cert expires before maxTtl', () => {
    const soon = agent({ expires_at: new Date((NOW + 120) * 1000).toISOString() });
    const c = buildAgentSupabaseClaims(soon, 's', 3600, NOW);
    expect(c.exp).toBe(NOW + 120); // cert expiry, not now+3600
  });

  it('throws when the certificate is already expired', () => {
    const expired = agent({ expires_at: new Date((NOW - 10) * 1000).toISOString() });
    expect(() => buildAgentSupabaseClaims(expired, 's', 3600, NOW)).toThrow(/expired/i);
  });

  it('throws on an invalid expires_at', () => {
    const bad = agent({ expires_at: 'not-a-date' });
    expect(() => buildAgentSupabaseClaims(bad, 's', 3600, NOW)).toThrow(/valid date/i);
  });
});

describe('mintAgentSupabaseJwt', () => {
  it('produces a well-formed HS256 JWT with a valid signature', async () => {
    const secret = 'super-secret-supabase-jwt-secret';
    const jwt = await mintAgentSupabaseJwt(agent(), { supabaseJwtSecret: secret, serial: 's' }, NOW);

    const [h, p, sig] = jwt.split('.');
    expect(h && p && sig).toBeTruthy();

    const header = decodeSegment(h);
    expect(header.alg).toBe('HS256');
    expect(header.typ).toBe('JWT');

    const payload = decodeSegment(p);
    expect(payload.sub).toBe('agt-123');

    // Recompute the HMAC and confirm the signature matches (no forgery).
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const expected = new Uint8Array(
      await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${h}.${p}`))
    );
    const expectedB64 = Buffer.from(expected).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(sig).toBe(expectedB64);
  });

  it('requires a secret', async () => {
    await expect(
      mintAgentSupabaseJwt(agent(), { supabaseJwtSecret: '', serial: 's' }, NOW)
    ).rejects.toThrow(/secret/i);
  });
});

describe('bindAgentSession (fail-closed)', () => {
  afterEach(() => vi.unstubAllGlobals());

  const baseOpts = {
    supabaseUrl: 'https://proj.supabase.co',
    supabaseAnonKey: 'anon-key',
    supabaseJwtSecret: 'jwt-secret',
    serial: '3A:F2:91:CC',
  };

  it('throws (no client) when the certificate is revoked', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ data: { ...agent({ certificate_status: 'revoked' }) } }),
    }));
    await expect(bindAgentSession({ ...baseOpts, verifyOptions: { cacheTtlMs: 0 } }))
      .rejects.toBeInstanceOf(KakuninVerifyError);
  });

  it('requires serial + supabase params', async () => {
    await expect(bindAgentSession({ ...baseOpts, serial: '' })).rejects.toThrow(/serial/i);
    await expect(bindAgentSession({ ...baseOpts, supabaseJwtSecret: '' })).rejects.toThrow(/secret/i);
  });
});
