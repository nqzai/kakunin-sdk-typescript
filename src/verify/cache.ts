import type { AgentInfo } from './types.js';

interface CacheEntry {
  data: AgentInfo;
  expiresAt: number;
  /** Entries are kept past TTL for stale fallback (up to staleUntil). */
  staleUntil: number;
}

/**
 * In-process LRU-style cert cache. Capped at 1000 entries.
 * Revoked certs are evicted immediately via invalidate().
 * On `certificate.revoked` webhook: call invalidate(serial).
 *
 * Stale entries are retained past TTL for up to 5× TTL so that
 * staleCacheFallback can serve them when the verify API is unreachable.
 */
export class CertCache {
  private readonly store = new Map<string, CacheEntry>();
  private readonly ttlMs: number;
  private static readonly MAX_ENTRIES = 1000;
  private static readonly STALE_MULTIPLIER = 5;

  constructor(ttlMs: number) {
    this.ttlMs = ttlMs;
  }

  /** Returns a fresh (non-expired) entry, or null. */
  get(serial: string): AgentInfo | null {
    const entry = this.store.get(serial);
    if (!entry) return null;
    if (Date.now() > entry.staleUntil) {
      this.store.delete(serial);
      return null;
    }
    if (Date.now() > entry.expiresAt) return null; // stale — caller must use getStale
    return entry.data;
  }

  /**
   * Returns the most recent entry for a serial regardless of TTL, or null if
   * the entry is missing or past the stale window. Used for API failover.
   */
  getStale(serial: string): AgentInfo | null {
    const entry = this.store.get(serial);
    if (!entry) return null;
    if (Date.now() > entry.staleUntil) {
      this.store.delete(serial);
      return null;
    }
    return entry.data;
  }

  set(serial: string, data: AgentInfo): void {
    if (this.store.size >= CertCache.MAX_ENTRIES) {
      const oldest = this.store.keys().next().value;
      if (oldest) this.store.delete(oldest);
    }
    const now = Date.now();
    this.store.set(serial, {
      data,
      expiresAt: now + this.ttlMs,
      staleUntil: now + this.ttlMs * CertCache.STALE_MULTIPLIER,
    });
  }

  /** Call on certificate.revoked webhook to block immediately. */
  invalidate(serial: string): void {
    this.store.delete(serial);
  }

  clear(): void {
    this.store.clear();
  }
}
