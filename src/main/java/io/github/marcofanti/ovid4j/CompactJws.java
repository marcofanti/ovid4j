// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Minimal compact JWS (RFC 7515) for the single algorithm OVID uses: EdDSA
 * (Ed25519). Signing input is {@code ASCII(base64url(header) "." base64url(payload))};
 * the signature is the raw 64-byte Ed25519 signature, base64url without padding.
 *
 * <p>Deliberately not a general JOSE implementation: one algorithm, no
 * {@code alg} negotiation, no unsecured JWS — the classic JWT pitfalls are
 * unrepresentable.
 *
 * @param headerJson decoded protected header JSON
 * @param payloadJson decoded payload JSON
 * @param signingInput the exact ASCII bytes the signature covers
 * @param signature decoded signature bytes
 */
record CompactJws(String headerJson, String payloadJson, byte[] signingInput, byte[] signature) {

  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64D = Base64.getUrlDecoder();

  /** Serialize and sign a compact JWS with an Ed25519 private key. */
  static String sign(String headerJson, String payloadJson, PrivateKey key) {
    String signingInput =
        B64.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8))
            + '.'
            + B64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
    try {
      Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(key);
      signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
      return signingInput + '.' + B64.encodeToString(signer.sign());
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("JWS signing failed", e);
    }
  }

  /**
   * Split a compact JWS and decode its parts without verifying anything.
   *
   * @throws IllegalArgumentException if the token is not three base64url segments
   */
  static CompactJws parse(String jwt) {
    String[] parts = jwt.split("\\.", -1);
    if (parts.length != 3) {
      throw new IllegalArgumentException("compact JWS must have 3 segments, got " + parts.length);
    }
    String signingInput = parts[0] + '.' + parts[1];
    return new CompactJws(
        new String(B64D.decode(parts[0]), StandardCharsets.UTF_8),
        new String(B64D.decode(parts[1]), StandardCharsets.UTF_8),
        signingInput.getBytes(StandardCharsets.US_ASCII),
        B64D.decode(parts[2]));
  }

  /** Verify this JWS's Ed25519 signature against a public key. */
  boolean verifySignature(PublicKey key) {
    try {
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(key);
      verifier.update(signingInput);
      return verifier.verify(signature);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }
}
