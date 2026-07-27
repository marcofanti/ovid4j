// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class ChainLinksTest {

  @Test
  void canonicalBytesAreByteExact() {
    byte[] bytes = ChainLinks.canonicalChainLinkBytes("a/b", "PUBKEY", 1777561629L, 1777563429L);
    assertArrayEquals(
        "ovid-chain-link/v1\na/b\nPUBKEY\n1777561629\n1777563429"
            .getBytes(StandardCharsets.UTF_8),
        bytes);
  }

  @Test
  void signAndVerifyRoundTrips() {
    KeyPair signer = Keys.generate();
    String agentPub = Keys.exportPublicKeyBase64(Keys.generate().getPublic());
    String sig = ChainLinks.signChainLink("root/child", agentPub, 100, 200, signer.getPrivate());
    ChainLink link = new ChainLink("root/child", agentPub, 100, 200, sig);
    assertTrue(ChainLinks.verifyChainLink(link, signer.getPublic()));
  }

  @Test
  void verifyFailsWithWrongKey() {
    KeyPair signer = Keys.generate();
    String agentPub = Keys.exportPublicKeyBase64(Keys.generate().getPublic());
    String sig = ChainLinks.signChainLink("root/child", agentPub, 100, 200, signer.getPrivate());
    ChainLink link = new ChainLink("root/child", agentPub, 100, 200, sig);
    assertFalse(ChainLinks.verifyChainLink(link, Keys.generate().getPublic()));
  }

  @Test
  void verifyFailsWhenAnyFieldIsTampered() {
    KeyPair signer = Keys.generate();
    String agentPub = Keys.exportPublicKeyBase64(Keys.generate().getPublic());
    String sig = ChainLinks.signChainLink("root/child", agentPub, 100, 200, signer.getPrivate());
    assertFalse(
        ChainLinks.verifyChainLink(
            new ChainLink("root/evil", agentPub, 100, 200, sig), signer.getPublic()));
    assertFalse(
        ChainLinks.verifyChainLink(
            new ChainLink("root/child", agentPub, 100, 999, sig), signer.getPublic()));
    assertFalse(
        ChainLinks.verifyChainLink(
            new ChainLink("root/child", agentPub, 100, 200, "AAAA"), signer.getPublic()));
  }

  @Test
  void trustedRootMatchesComparesExportedKey() {
    KeyPair root = Keys.generate();
    String rootPub = Keys.exportPublicKeyBase64(root.getPublic());
    assertTrue(ChainLinks.trustedRootMatches(root.getPublic(), rootPub));
    assertFalse(ChainLinks.trustedRootMatches(Keys.generate().getPublic(), rootPub));
  }
}
