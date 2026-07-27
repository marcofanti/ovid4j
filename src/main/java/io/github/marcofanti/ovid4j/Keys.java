// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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

  /** DER prefix of an Ed25519 PKCS#8 PrivateKeyInfo: SEQUENCE, version 0, OID, OCTET STRING(seed). */
  private static final byte[] PKCS8_ED25519_PREFIX =
      HexFormat.of().parseHex("302e020100300506032b657004220420");

  /**
   * Export a private key as its base64url raw 32-byte Ed25519 seed — the same
   * bytes as JWK {@code d}, so a key exported here imports in the TypeScript
   * library and vice versa.
   *
   * <p>Upstream keeps private keys non-extractable (WebCrypto); this port
   * exposes export solely so keys can live in an external secret manager
   * instead of on disk. Callers own the handling discipline: hold the value in
   * memory only, never log or persist it outside the secret manager.
   */
  public static String exportPrivateKeyBase64(PrivateKey privateKey) {
    byte[] pkcs8 = privateKey.getEncoded();
    if (pkcs8.length != PKCS8_ED25519_PREFIX.length + 32
        || !Arrays.equals(pkcs8, 0, PKCS8_ED25519_PREFIX.length,
            PKCS8_ED25519_PREFIX, 0, PKCS8_ED25519_PREFIX.length)) {
      throw new IllegalArgumentException(
          "not an Ed25519 PKCS#8 v1 encoding: " + privateKey.getAlgorithm());
    }
    byte[] seed = Arrays.copyOfRange(pkcs8, PKCS8_ED25519_PREFIX.length, pkcs8.length);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(seed);
  }

  /** Import a base64url raw 32-byte Ed25519 seed as a private key. */
  public static PrivateKey importPrivateKeyBase64(String base64url) {
    byte[] seed = Base64.getUrlDecoder().decode(base64url);
    if (seed.length != 32) {
      throw new IllegalArgumentException(
          "Ed25519 private key must be 32 raw seed bytes, got " + seed.length);
    }
    byte[] pkcs8 = new byte[PKCS8_ED25519_PREFIX.length + 32];
    System.arraycopy(PKCS8_ED25519_PREFIX, 0, pkcs8, 0, PKCS8_ED25519_PREFIX.length);
    System.arraycopy(seed, 0, pkcs8, PKCS8_ED25519_PREFIX.length, 32);
    try {
      return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalArgumentException("invalid Ed25519 private key", e);
    }
  }

  /** Rebuild a keypair from the two base64url wire encodings. */
  public static KeyPair importKeyPairBase64(String publicBase64url, String privateBase64url) {
    return new KeyPair(
        importPublicKeyBase64(publicBase64url), importPrivateKeyBase64(privateBase64url));
  }

  private Keys() {}
}
