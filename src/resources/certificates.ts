/**
 * Kakunin Certificates Resource
 *
 * kkn.certificates.revoke() → POST /v1/certificates/:id/revoke
 *
 * Certificate issuance is done via kkn.agents.certify().
 * This resource handles post-issuance lifecycle (revocation).
 */

import type { KakuninHttpClient } from '../client.js';
import type { RevokeParams, RevokeResult } from '../types.js';

export class CertificatesResource {
  constructor(private readonly http: KakuninHttpClient) {}

  /**
   * Manually revoke an active certificate.
   * Also suspends the owning agent — it cannot emit events until reactivated.
   * Triggers CRL regeneration and fires a certificate.revoked webhook.
   *
   * Returns 409 if already revoked, 422 if expired.
   *
   * @example
   * await kkn.certificates.revoke(cert.id, {
   *   reason: 'Compromised model weights detected in supply chain audit',
   * });
   */
  async revoke(certificateId: string, params: RevokeParams): Promise<RevokeResult> {
    const res = await this.http.request<{ data: RevokeResult }>(
      `/certificates/${certificateId}/revoke`,
      { method: 'POST', body: params },
    );
    return res.data;
  }
}
