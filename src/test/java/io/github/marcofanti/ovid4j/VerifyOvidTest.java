// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import static io.github.marcofanti.ovid4j.TestSupport.READ_POLICY;
import static io.github.marcofanti.ovid4j.TestSupport.rootOptions;
import static io.github.marcofanti.ovid4j.TestSupport.tamperAndResign;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

class VerifyOvidTest {

  private final KeyPair rootKeys = Keys.generate();
  private final OvidToken token = Ovid.createOvid(rootOptions(rootKeys).build());

  @Test
  void verifiesValidRootToken() {
    OvidResult result = Ovid.verifyOvid(token.jwt(), VerifyOvidOptions.of(rootKeys.getPublic()));
    assertTrue(result.valid());
    assertEquals(token.claims().sub(), result.principal());
    assertEquals(READ_POLICY, result.mandate().policySet());
    assertEquals(List.of(token.claims().sub()), result.chain());
    assertTrue(result.expiresIn() > 0 && result.expiresIn() <= Ovid.DEFAULT_TTL);
  }

  @Test
  void rejectsUnknownRoot() {
    OvidResult result =
        Ovid.verifyOvid(token.jwt(), VerifyOvidOptions.of(Keys.generate().getPublic()));
    assertFalse(result.valid());
    assertEquals("", result.principal());
    assertEquals(AuthorizationDetail.EMPTY, result.mandate());
  }

  @Test
  void rejectsEmptyTrustedRoots() {
    assertFalse(Ovid.verifyOvid(token.jwt(), new VerifyOvidOptions(List.of(), null)).valid());
    assertFalse(Ovid.verifyOvid(token.jwt(), null).valid());
  }

  @Test
  void rejectsGarbageJwt() {
    VerifyOvidOptions options = VerifyOvidOptions.of(rootKeys.getPublic());
    assertFalse(Ovid.verifyOvid("not-a-jwt", options).valid());
    assertFalse(Ovid.verifyOvid("a.b", options).valid());
    assertFalse(Ovid.verifyOvid("!!!.@@@.###", options).valid());
    assertFalse(Ovid.verifyOvid("", options).valid());
  }

  @Test
  void rejectsExpiredToken() {
    Clock afterExpiry =
        Clock.fixed(
            Instant.ofEpochSecond(token.claims().exp()).plus(Duration.ofSeconds(1)),
            ZoneOffset.UTC);
    assertFalse(
        Ovid.verifyOvid(token.jwt(), VerifyOvidOptions.of(rootKeys.getPublic()), afterExpiry)
            .valid());
  }

  @Test
  void rejectsTamperedPayloadEvenWhenResignedByNonLeafKey() {
    // Attacker changes the mandate and re-signs with a key they control —
    // the JWT signature no longer matches the chain-attested leaf key.
    String forged =
        tamperAndResign(
            token.jwt(),
            payload ->
                ((com.fasterxml.jackson.databind.node.ObjectNode)
                        payload.path("authorization_details").path(0))
                    .put("policySet", "permit(principal, action, resource);"),
            Keys.generate().getPrivate());
    assertFalse(Ovid.verifyOvid(forged, VerifyOvidOptions.of(rootKeys.getPublic())).valid());
  }

  @Test
  void rejectsSubMismatchWithLeafLink() {
    // Even re-signed with the legitimate leaf key, sub must match the leaf link.
    String forged =
        tamperAndResign(token.jwt(), p -> p.put("sub", "evil/agent"), rootKeys.getPrivate());
    assertFalse(Ovid.verifyOvid(forged, VerifyOvidOptions.of(rootKeys.getPublic())).valid());
  }

  @Test
  void rejectsJwtExpBeyondLeafLinkExp() {
    String forged =
        tamperAndResign(
            token.jwt(),
            p -> p.put("exp", token.claims().exp() + 3600),
            rootKeys.getPrivate());
    assertFalse(Ovid.verifyOvid(forged, VerifyOvidOptions.of(rootKeys.getPublic())).valid());
  }

  @Test
  void rejectsBackdatedJwtIat() {
    String forged =
        tamperAndResign(
            token.jwt(), p -> p.put("iat", token.claims().iat() - 3600), rootKeys.getPrivate());
    assertFalse(Ovid.verifyOvid(forged, VerifyOvidOptions.of(rootKeys.getPublic())).valid());
  }

  @Test
  void rejectsNonChainProtocolVersion() {
    String forged =
        tamperAndResign(
            token.jwt(),
            payload ->
                ((com.fasterxml.jackson.databind.node.ObjectNode)
                        payload.path("authorization_details").path(0))
                    .put("ovid_version", "0.3.1"),
            rootKeys.getPrivate());
    // This port rejects legacy tokens instead of falling back to single-key verify.
    assertFalse(Ovid.verifyOvid(forged, VerifyOvidOptions.of(rootKeys.getPublic())).valid());
  }

  @Test
  void rejectsWrongJwtTyp() {
    CompactJws jws = CompactJws.parse(token.jwt());
    String forged =
        CompactJws.sign("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", jws.payloadJson(),
            rootKeys.getPrivate());
    assertFalse(Ovid.verifyOvid(forged, VerifyOvidOptions.of(rootKeys.getPublic())).valid());
  }

  @Test
  void acceptsAnyMatchingRootAmongSeveral() {
    OvidResult result =
        Ovid.verifyOvid(
            token.jwt(),
            new VerifyOvidOptions(
                List.of(Keys.generate().getPublic(), rootKeys.getPublic()), null));
    assertTrue(result.valid());
  }
}
