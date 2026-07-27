// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import java.util.Set;

/**
 * OVID wire-protocol version vs package version.
 *
 * <p>{@code ovid_version} on a token is a <b>protocol / shape switch</b>, not the
 * package version. Verification branches on it: chain-protocol versions take the
 * nested ChainLink walk (crypto path); anything else is rejected by this port
 * (the TypeScript library falls back to a legacy single-key path instead).
 *
 * <p>Never set {@code ovid_version} from the build version. Bumping ovid4j must
 * not change the token field unless the wire shape actually changes — and then
 * {@link #CHAIN_PROTOCOL_VERSIONS} must be updated in the same commit.
 */
public final class Protocol {

  /** Wire-format protocol version stamped into newly minted tokens. */
  public static final String OVID_PROTOCOL_VERSION = "0.4.0";

  /**
   * Protocol versions that use nested-signature ChainLink verification.
   * Add a new entry only when minting a new wire shape that verify understands.
   */
  public static final Set<String> CHAIN_PROTOCOL_VERSIONS = Set.of(OVID_PROTOCOL_VERSION);

  /** True when {@code ovid_version} should take the v0.4+ chain verification path. */
  public static boolean isChainProtocolVersion(Object version) {
    return version instanceof String s && CHAIN_PROTOCOL_VERSIONS.contains(s);
  }

  private Protocol() {}
}
