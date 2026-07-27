// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import static io.github.mfanti.ovid4j.TestSupport.readMandate;
import static io.github.mfanti.ovid4j.TestSupport.rootOptions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.List;
import org.junit.jupiter.api.Test;

class DelegationTest {

  private final KeyPair rootKeys = Keys.generate();
  private final OvidToken root =
      Ovid.createOvid(rootOptions(rootKeys).ttlSeconds(3600).build());

  private OvidToken spawn(OvidToken parent, long ttlSeconds) {
    return Ovid.createOvid(
        CreateOvidOptions.builder()
            .issuerKeys(parent.keys())
            .issuerOvid(parent)
            .mandate(readMandate())
            .ttlSeconds(ttlSeconds)
            .build());
  }

  @Test
  void verifiesDepth2Chain() {
    OvidToken child = spawn(root, 600);
    OvidResult result = Ovid.verifyOvid(child.jwt(), VerifyOvidOptions.of(rootKeys.getPublic()));
    assertTrue(result.valid());
    assertEquals(child.claims().sub(), result.principal());
    assertEquals(List.of(root.claims().sub(), child.claims().sub()), result.chain());
  }

  @Test
  void verifiesDepth3Chain() {
    OvidToken child = spawn(root, 1200);
    OvidToken grandchild = spawn(child, 600);
    OvidResult result =
        Ovid.verifyOvid(grandchild.jwt(), VerifyOvidOptions.of(rootKeys.getPublic()));
    assertTrue(result.valid());
    assertEquals(
        List.of(root.claims().sub(), child.claims().sub(), grandchild.claims().sub()),
        result.chain());
    // Chain data in the mandate is complete: root first, leaf last.
    List<ChainLink> chain = result.mandate().parentChain();
    assertEquals(3, chain.size());
    assertEquals(grandchild.claims().sub(), chain.getLast().sub());
  }

  @Test
  void depth3ChainFailsUnderDifferentRoot() {
    OvidToken grandchild = spawn(spawn(root, 1200), 600);
    assertFalse(
        Ovid.verifyOvid(grandchild.jwt(), VerifyOvidOptions.of(Keys.generate().getPublic()))
            .valid());
  }

  @Test
  void maxChainDepthOptionRejectsDeeperChains() {
    OvidToken grandchild = spawn(spawn(root, 1200), 600);
    OvidResult result =
        Ovid.verifyOvid(
            grandchild.jwt(),
            new VerifyOvidOptions(List.of(rootKeys.getPublic()), 2));
    assertFalse(result.valid());
  }

  @Test
  void siblingCannotForgeAnotherAgentsToken() {
    OvidToken childA = spawn(root, 600);
    OvidToken childB = spawn(root, 600);
    // Sibling B re-signs A's payload with B's own (legitimately attested) key.
    // A's leaf link binds A's key, so the JWT signature check must fail.
    String forged =
        TestSupport.tamperAndResign(childA.jwt(), p -> {}, childB.keys().getPrivate());
    assertFalse(Ovid.verifyOvid(forged, VerifyOvidOptions.of(rootKeys.getPublic())).valid());
  }

  @Test
  void grandchildLinkSignedByRootInsteadOfParentFails() {
    OvidToken child = spawn(root, 1200);
    OvidToken grandchild = spawn(child, 600);
    // Rebuild the grandchild's leaf link, but attested by the ROOT's key
    // instead of its immediate parent — every link must be signed by its
    // direct parent, so this chain must not verify.
    List<ChainLink> chain =
        grandchild.claims().authorizationDetails().getFirst().parentChain();
    ChainLink leaf = chain.getLast();
    ChainLink resigned =
        new ChainLink(
            leaf.sub(),
            leaf.agentPub(),
            leaf.iat(),
            leaf.exp(),
            ChainLinks.signChainLink(
                leaf.sub(), leaf.agentPub(), leaf.iat(), leaf.exp(), rootKeys.getPrivate()));
    // The re-signed link verifies under root's key but must not under the parent's.
    assertTrue(ChainLinks.verifyChainLink(resigned, rootKeys.getPublic()));
    assertFalse(
        ChainLinks.verifyChainLink(
            resigned, Keys.importPublicKeyBase64(chain.get(1).agentPub())));
  }
}
