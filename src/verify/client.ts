import type { AgentInfo, MessageVerifyResult } from './types.js';
import { KakuninVerifyError } from './types.js';

const DEFAULT_BASE_URL = 'https://api.kakunin.ai/v1';
const DEFAULT_TIMEOUT_MS = 5_000;

export class KakuninApiClient {
  private readonly baseUrl: string;
  readonly timeoutMs: number;

  constructor(baseUrl = DEFAULT_BASE_URL, timeoutMs = DEFAULT_TIMEOUT_MS) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  async fetchCertInfo(serial: string): Promise<AgentInfo> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/verify/${encodeURIComponent(serial)}`, {
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText })) as { error?: string };
      throw new KakuninVerifyError(
        body.error ?? 'Failed to verify certificate',
        res.status,
        serial
      );
    }
    const json = await res.json() as { data: AgentInfo };
    return json.data;
  }

  async verifyMessage(
    payload: Record<string, unknown>,
    signature: string,
    certificateSerial: string
  ): Promise<MessageVerifyResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/verify/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, signature, certificateSerial }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    const json = await res.json() as { data: MessageVerifyResult };
    return json.data;
  }
}
