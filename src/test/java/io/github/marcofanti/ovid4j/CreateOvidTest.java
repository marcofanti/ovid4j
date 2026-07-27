// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import static io.github.marcofanti.ovid4j.TestSupport.readMandate;
import static io.github.marcofanti.ovid4j.TestSupport.rootOptions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class CreateOvidTest {

  @Test
  void mintsRootTokenWithSelfSignedSingleLinkChain() {
    KeyPair keys = Keys.generate();
    OvidToken token = Ovid.createOvid(rootOptions(keys).build());

    assertEquals(3, token.jwt().split("\\.").length);
    OvidClaims claims = token.claims();
    assertEquals(claims.jti(), claims.sub());
    assertEquals("test", claims.iss());
    assertNull(claims.parentOvid());
    assertEquals(claims.iat() + Ovid.DEFAULT_TTL, claims.exp());

    AuthorizationDetail detail = claims.authorizationDetails().getFirst();
    assertEquals("cedar", detail.rarFormat());
    assertEquals(Protocol.OVID_PROTOCOL_VERSION, detail.ovidVersion());
    assertEquals(Keys.exportPublicKeyBase64(keys.getPublic()), detail.agentPub());

    assertEquals(1, detail.parentChain().size());
    ChainLink root = detail.parentChain().getFirst();
    assertEquals(claims.sub(), root.sub());
    assertEquals(detail.agentPub(), root.agentPub());
    // Root links are self-signed.
    assertTrue(ChainLinks.verifyChainLink(root, keys.getPublic()));
    // Root token: agentKeys == issuerKeys.
    assertEquals(keys, token.keys());
  }

  @Test
  void honorsCustomAgentIdIssuerTtlAndKid() {
    OvidToken token =
        Ovid.createOvid(
            rootOptions(Keys.generate())
                .agentId("acme/agent-1")
                .issuer("acme")
                .ttlSeconds(60)
                .kid("key-1")
                .build());
    assertEquals("acme/agent-1", token.claims().sub());
    assertEquals("acme", token.claims().iss());
    assertEquals(token.claims().iat() + 60, token.claims().exp());
    assertTrue(token.jwt().startsWith(base64Header("{\"alg\":\"EdDSA\",\"typ\":\"ovid+jwt\",\"kid\":\"key-1\"}")));
  }

  @Test
  void autogeneratesPathStyleAgentId() {
    OvidToken token = Ovid.createOvid(rootOptions(Keys.generate()).issuer("acme").build());
    assertTrue(token.claims().sub().matches("acme/agent-[0-9a-f]{8}"));
  }

  @Test
  void requiresMandate() {
    CreateOvidOptions options = CreateOvidOptions.builder().issuerKeys(Keys.generate()).build();
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Ovid.createOvid(options));
    assertTrue(e.getMessage().contains("required"));
  }

  @Test
  void rejectsNonCedarRarFormat() {
    CreateOvidOptions options =
        CreateOvidOptions.builder()
            .issuerKeys(Keys.generate())
            .mandate(new AuthorizationDetail("agent_mandate", "xacml", "x", null, null, null))
            .build();
    assertThrows(IllegalArgumentException.class, () -> Ovid.createOvid(options));
  }

  @Test
  void rejectsInvalidCedarSyntax() {
    CreateOvidOptions options =
        CreateOvidOptions.builder()
            .issuerKeys(Keys.generate())
            .mandate(AuthorizationDetail.agentMandate("permit(principal, action, resource"))
            .build();
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Ovid.createOvid(options));
    assertTrue(e.getMessage().contains("Cedar"));
  }

  @Test
  void childLifetimeCannotExceedParent() {
    OvidToken parent = Ovid.createOvid(rootOptions(Keys.generate()).ttlSeconds(600).build());
    CreateOvidOptions child =
        CreateOvidOptions.builder()
            .issuerKeys(parent.keys())
            .issuerOvid(parent)
            .mandate(readMandate())
            .ttlSeconds(6000)
            .build();
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Ovid.createOvid(child));
    assertTrue(e.getMessage().contains("Lifetime attenuation"));
  }

  @Test
  void chainDepthIsCappedAtFive() {
    OvidToken current = Ovid.createOvid(rootOptions(Keys.generate()).ttlSeconds(100_000).build());
    for (int depth = 2; depth <= 5; depth++) {
      current =
          Ovid.createOvid(
              CreateOvidOptions.builder()
                  .issuerKeys(current.keys())
                  .issuerOvid(current)
                  .mandate(readMandate())
                  .ttlSeconds(100_000 - depth * 1000L)
                  .build());
      assertEquals(
          depth, current.claims().authorizationDetails().getFirst().parentChain().size());
    }
    OvidToken depth5 = current;
    CreateOvidOptions depth6 =
        CreateOvidOptions.builder()
            .issuerKeys(depth5.keys())
            .issuerOvid(depth5)
            .mandate(readMandate())
            .ttlSeconds(1000)
            .build();
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Ovid.createOvid(depth6));
    assertTrue(e.getMessage().contains("exceeds max"));
  }

  @Test
  void childGetsFreshKeypairAndParentAttestedLink() {
    OvidToken parent = Ovid.createOvid(rootOptions(Keys.generate()).ttlSeconds(3600).build());
    OvidToken child =
        Ovid.createOvid(
            CreateOvidOptions.builder()
                .issuerKeys(parent.keys())
                .issuerOvid(parent)
                .mandate(readMandate())
                .ttlSeconds(600)
                .build());

    assertNotNull(child.keys());
    assertTrue(child.claims().sub().startsWith(parent.claims().sub() + "/"));
    assertEquals(parent.claims().jti(), child.claims().parentOvid());

    var chain = child.claims().authorizationDetails().getFirst().parentChain();
    assertEquals(2, chain.size());
    // Child link is signed by the parent's key, not the child's.
    assertTrue(ChainLinks.verifyChainLink(chain.get(1), parent.keys().getPublic()));
    assertEquals(
        Keys.exportPublicKeyBase64(child.keys().getPublic()), chain.get(1).agentPub());
  }

  private static String base64Header(String json) {
    return java.util.Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }
}
