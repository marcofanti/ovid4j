// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * ChainLink signing and verification (ovid_version 0.4.0).
 *
 * <p>Canonical signed bytes (MUST be byte-exact for interop):
 * <pre>"ovid-chain-link/v1\n" + sub + "\n" + agent_pub + "\n" + iat + "\n" + exp</pre>
 * UTF-8 encoded; {@code iat}/{@code exp} rendered as decimal integers with no
 * leading zeros ({@code Long.toString}, matching JavaScript {@code String(value)}
 * for the unix-seconds range). The signature is raw Ed25519 over those bytes,
 * base64url without padding.
 */
public final class ChainLinks {

  private static final String CHAIN_LINK_PREFIX = "ovid-chain-link/v1\n";

  /** Build the exact byte string that a ChainLink's {@code sig} covers. */
  public static byte[] canonicalChainLinkBytes(String sub, String agentPub, long iat, long exp) {
    String text = CHAIN_LINK_PREFIX + sub + '\n' + agentPub + '\n' + iat + '\n' + exp;
    return text.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Sign a ChainLink payload with the parent's Ed25519 private key.
   * Returns the {@code sig} value as a base64url string.
   */
  public static String signChainLink(
      String sub, String agentPub, long iat, long exp, PrivateKey signerPrivateKey) {
    try {
      Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(signerPrivateKey);
      signer.update(canonicalChainLinkBytes(sub, agentPub, iat, exp));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("chain link signing failed for sub " + sub, e);
    }
  }

  /**
   * Verify a ChainLink's signature was produced by {@code verifierPublicKey}
   * over the canonical byte string for the link's (sub, agent_pub, iat, exp).
   */
  public static boolean verifyChainLink(ChainLink link, PublicKey verifierPublicKey) {
    try {
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(verifierPublicKey);
      verifier.update(canonicalChainLinkBytes(link.sub(), link.agentPub(), link.iat(), link.exp()));
      return verifier.verify(Base64.getUrlDecoder().decode(link.sig()));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * Anchoring check: does a trusted-root public key match a ChainLink's
   * base64url {@code agent_pub}?
   */
  public static boolean trustedRootMatches(PublicKey trustedKey, String agentPub) {
    try {
      return Keys.exportPublicKeyBase64(trustedKey).equals(agentPub);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  private ChainLinks() {}
}
