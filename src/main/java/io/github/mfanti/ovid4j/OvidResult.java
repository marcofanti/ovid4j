// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import java.util.List;

/**
 * Result of {@link Ovid#verifyOvid}.
 *
 * @param valid whether every verification check passed
 * @param principal the verified agent subject ({@code ""} when invalid)
 * @param mandate the verified authorization detail ({@link AuthorizationDetail#EMPTY} when invalid)
 * @param chain flattened delegation chain: {@code sub} identifiers root first, leaf last.
 *     For full chain data (agent_pub, iat, exp, sig) inspect {@code mandate.parentChain()}.
 * @param expiresIn seconds until expiry (0 when invalid)
 */
public record OvidResult(
    boolean valid,
    String principal,
    AuthorizationDetail mandate,
    List<String> chain,
    long expiresIn) {

  static OvidResult invalid() {
    return new OvidResult(false, "", AuthorizationDetail.EMPTY, List.of(), 0);
  }
}
