// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Ed25519 keypair generation and the raw/base64url public-key encoding used
 * on the OVID wire ({@code agent_pub} fields).
 *
 * <p>The wire format is the raw 32-byte Ed25519 public key, base64url without
 * padding — the same bytes WebCrypto/jose expose as JWK {@code x}. The JDK
 * encodes public keys as X.509 SubjectPublicKeyInfo (a fixed 12-byte DER
 * prefix followed by those 32 raw bytes), so import/export strips or adds
 * that prefix.
 */
public final class Keys {

  /** DER prefix of an Ed25519 SubjectPublicKeyInfo: SEQUENCE, OID 1.3.101.112, BIT STRING. */
  private static final byte[] SPKI_ED25519_PREFIX =
      HexFormat.of().parseHex("302a300506032b6570032100");

  /** Generate an Ed25519 keypair for OVID. */
  public static KeyPair generate() {
    try {
      return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("JDK does not provide Ed25519 (requires Java 15+)", e);
    }
  }

  /** Export a public key as the base64url raw 32-byte form used in {@code agent_pub}. */
  public static String exportPublicKeyBase64(PublicKey publicKey) {
    byte[] spki = publicKey.getEncoded();
    if (spki.length != SPKI_ED25519_PREFIX.length + 32
        || !Arrays.equals(spki, 0, SPKI_ED25519_PREFIX.length,
            SPKI_ED25519_PREFIX, 0, SPKI_ED25519_PREFIX.length)) {
      throw new IllegalArgumentException(
          "not an Ed25519 SubjectPublicKeyInfo encoding: " + publicKey.getAlgorithm());
    }
    byte[] raw = Arrays.copyOfRange(spki, SPKI_ED25519_PREFIX.length, spki.length);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
  }

  /** Import a base64url raw Ed25519 public key (as stored in {@code agent_pub}). */
  public static PublicKey importPublicKeyBase64(String base64url) {
    byte[] raw = Base64.getUrlDecoder().decode(base64url);
    if (raw.length != 32) {
      throw new IllegalArgumentException(
          "Ed25519 public key must be 32 raw bytes, got " + raw.length);
    }
    byte[] spki = new byte[SPKI_ED25519_PREFIX.length + 32];
    System.arraycopy(SPKI_ED25519_PREFIX, 0, spki, 0, SPKI_ED25519_PREFIX.length);
    System.arraycopy(raw, 0, spki, SPKI_ED25519_PREFIX.length, 32);
    try {
      return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalArgumentException("invalid Ed25519 public key", e);
    }
  }

  private Keys() {}
}
