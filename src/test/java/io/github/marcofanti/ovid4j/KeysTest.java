// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class KeysTest {

  @Test
  void generatesEd25519Keypairs() {
    // The JDK reports the family name "EdDSA" for keys from the "Ed25519" generator.
    KeyPair pair = Keys.generate();
    assertTrue(java.util.Set.of("Ed25519", "EdDSA").contains(pair.getPublic().getAlgorithm()));
    assertTrue(java.util.Set.of("Ed25519", "EdDSA").contains(pair.getPrivate().getAlgorithm()));
  }

  @Test
  void exportsRaw32BytePublicKeyAsBase64UrlWithoutPadding() {
    String exported = Keys.exportPublicKeyBase64(Keys.generate().getPublic());
    assertFalse(exported.contains("="), "no padding");
    assertFalse(exported.contains("+"), "url-safe alphabet");
    assertFalse(exported.contains("/"), "url-safe alphabet");
    assertEquals(32, Base64.getUrlDecoder().decode(exported).length);
  }

  @Test
  void importExportRoundTrips() {
    PublicKey original = Keys.generate().getPublic();
    String exported = Keys.exportPublicKeyBase64(original);
    PublicKey imported = Keys.importPublicKeyBase64(exported);
    assertEquals(exported, Keys.exportPublicKeyBase64(imported));
    assertEquals(original, imported);
  }

  @Test
  void distinctKeypairsHaveDistinctPublicKeys() {
    assertNotEquals(
        Keys.exportPublicKeyBase64(Keys.generate().getPublic()),
        Keys.exportPublicKeyBase64(Keys.generate().getPublic()));
  }

  @Test
  void importRejectsWrongLength() {
    String tooShort = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[16]);
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Keys.importPublicKeyBase64(tooShort));
    assertTrue(e.getMessage().contains("32"));
  }

  @Test
  void importRejectsGarbage() {
    assertThrows(IllegalArgumentException.class, () -> Keys.importPublicKeyBase64("not base64!!"));
  }
}
