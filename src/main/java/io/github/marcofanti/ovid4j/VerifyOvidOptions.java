// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import java.security.PublicKey;
import java.util.List;

/**
 * Options for {@link Ovid#verifyOvid}.
 *
 * @param trustedRoots accepted root public keys; a token is only valid if its
 *     chain anchors to one of these
 * @param maxChainDepth maximum chain depth to accept (default 5 when null)
 */
public record VerifyOvidOptions(List<PublicKey> trustedRoots, Integer maxChainDepth) {

  public static final int DEFAULT_MAX_CHAIN_DEPTH = 5;

  public VerifyOvidOptions {
    trustedRoots = trustedRoots == null ? List.of() : List.copyOf(trustedRoots);
  }

  public static VerifyOvidOptions of(PublicKey... trustedRoots) {
    return new VerifyOvidOptions(List.of(trustedRoots), null);
  }

  int effectiveMaxChainDepth() {
    return maxChainDepth == null ? DEFAULT_MAX_CHAIN_DEPTH : maxChainDepth;
  }
}
