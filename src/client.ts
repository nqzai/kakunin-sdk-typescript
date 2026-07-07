/**
 * Kakunin HTTP Client
 *
 * Handles auth headers, request timeout, exponential backoff retry on 5xx/network,
 * and consistent error mapping. All SDK resources use this client.
 */

import { KakuninAuthError, KakuninError, KakuninRateLimitError } from './types.js';

const DEFAULT_BASE_URL = 'https://api.kakunin.ai/v1';
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RETRIES = 3;

/** Jitter factor for exponential backoff — avoids thundering herd */
const BACKOFF_BASE_MS = 300;
const BACKOFF_MAX_MS = 10_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffMs(attempt: number): number {
  const exp = Math.min(BACKOFF_BASE_MS * 2 ** attempt, BACKOFF_MAX_MS);
  // ±25% jitter
  return exp * (0.75 + Math.random() * 0.5);
}

function isRetryable(status: number): boolean {
  return status === 429 || status >= 500;
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
  /** Skip auth header — used for public verify endpoints */
  skipAuth?: boolean;
  /** Override timeout for this request */
  timeoutMs?: number;
}

export class KakuninHttpClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;

  constructor(
    apiKey: string,
    baseUrl = DEFAULT_BASE_URL,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxRetries = DEFAULT_MAX_RETRIES,
  ) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
    this.maxRetries = maxRetries;
  }

  isSandbox(): boolean {
    return this.apiKey.startsWith('kak_test_');
  }

  async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const { method = 'GET', body, query, skipAuth = false, timeoutMs } = options;

    let url = `${this.baseUrl}${path}`;
    if (query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined) params.set(k, String(v));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': `@kakunin/sdk/0.2.0 node/${typeof process !== 'undefined' ? process.version : 'browser'}`,
    };

    if (!skipAuth) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const effectiveTimeout = timeoutMs ?? this.timeoutMs;
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await sleep(backoffMs(attempt - 1));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), effectiveTimeout);

      const fetchInit: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };
      if (body !== undefined) {
        fetchInit.body = JSON.stringify(body);
      }

      let res: Response;
      try {
        res = await fetch(url, fetchInit);
      } catch (err) {
        clearTimeout(timer);
        lastError = err;
        // Network error — retry
        if (attempt < this.maxRetries) continue;
        throw new KakuninError(
          err instanceof Error ? err.message : 'Network error',
          0,
          'network_error',
        );
      } finally {
        clearTimeout(timer);
      }

      if (res.status === 401 || res.status === 403) {
        const body = await res.json().catch(() => ({ error: res.statusText })) as { error?: string };
        throw new KakuninAuthError(body.error ?? 'Unauthorized');
      }

      if (res.status === 429) {
        const retryAfter = parseInt(res.headers.get('Retry-After') ?? '60', 10);
        const body = await res.json().catch(() => ({ error: 'Rate limit exceeded' })) as { error?: string };
        if (attempt < this.maxRetries) {
          await sleep(retryAfter * 1000);
          continue;
        }
        throw new KakuninRateLimitError(body.error ?? 'Rate limit exceeded', retryAfter);
      }

      if (!res.ok && isRetryable(res.status) && attempt < this.maxRetries) {
        lastError = new KakuninError(`HTTP ${res.status}`, res.status);
        continue;
      }

      if (!res.ok) {
        const errBody = await res.json().catch(() => ({ error: res.statusText })) as { error?: string; code?: string };
        throw new KakuninError(
          errBody.error ?? `HTTP ${res.status}`,
          res.status,
          errBody.code,
          res.headers.get('x-request-id') ?? undefined,
        );
      }

      // 204 No Content
      if (res.status === 204) return undefined as T;

      const json = await res.json() as T;
      return json;
    }

    throw lastError instanceof Error
      ? lastError
      : new KakuninError('Max retries exceeded', 0, 'max_retries_exceeded');
  }
}
