// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.InputStream;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Golden-fixture interop: tokens minted by the TypeScript reference library
 * ({@code @clawdreyhepburn/ovid}) must verify in this port. Fixtures are
 * regenerated with {@code interop/generate-ts-fixtures.mjs}.
 */
class InteropTsFixturesTest {

  private static JsonNode fixtures;
  private static PublicKey rootKey;
  private static Clock fixtureClock;

  @BeforeAll
  static void loadFixtures() throws Exception {
    try (InputStream in =
        InteropTsFixturesTest.class.getResourceAsStream("/interop/ts-fixtures.json")) {
      assertNotNull(in, "missing src/test/resources/interop/ts-fixtures.json — "
          + "run interop/generate-ts-fixtures.mjs");
      fixtures = Json.MAPPER.readTree(in);
    }
    rootKey = Keys.importPublicKeyBase64(fixtures.path("rootPublicKey").asText());
    fixtureClock =
        Clock.fixed(
            Instant.ofEpochSecond(fixtures.path("generatedAt").asLong() + 60), ZoneOffset.UTC);
  }

  private static OvidResult verifyFixture(String name) {
    return Ovid.verifyOvid(
        fixtures.path("tokens").path(name).path("jwt").asText(),
        VerifyOvidOptions.of(rootKey),
        fixtureClock);
  }

  private static List<String> expectedChain(String name) {
    List<String> subs = new ArrayList<>();
    fixtures.path("tokens").path(name).path("chain").forEach(n -> subs.add(n.asText()));
    return subs;
  }

  @Test
  void verifiesTsMintedRootToken() {
    OvidResult result = verifyFixture("root");
    assertTrue(result.valid());
    assertEquals(expectedChain("root"), result.chain());
    assertEquals(expectedChain("root").getLast(), result.principal());
    assertEquals(Protocol.OVID_PROTOCOL_VERSION, result.mandate().ovidVersion());
  }

  @Test
  void verifiesTsMintedDepth2Token() {
    OvidResult result = verifyFixture("depth2");
    assertTrue(result.valid());
    assertEquals(expectedChain("depth2"), result.chain());
    assertEquals(2, result.mandate().parentChain().size());
  }

  @Test
  void verifiesTsMintedDepth3Token() {
    OvidResult result = verifyFixture("depth3");
    assertTrue(result.valid());
    assertEquals(expectedChain("depth3"), result.chain());
    assertEquals(3, result.mandate().parentChain().size());
  }

  @Test
  void tsTokenRejectedUnderForeignRoot() {
    OvidResult result =
        Ovid.verifyOvid(
            fixtures.path("tokens").path("depth2").path("jwt").asText(),
            VerifyOvidOptions.of(Keys.generate().getPublic()),
            fixtureClock);
    assertFalse(result.valid());
  }

  @Test
  void tamperedTsTokenRejected() {
    String forged =
        TestSupport.tamperAndResign(
            fixtures.path("tokens").path("depth3").path("jwt").asText(),
            p -> p.put("sub", "evil/agent"),
            Keys.generate().getPrivate());
    assertFalse(Ovid.verifyOvid(forged, VerifyOvidOptions.of(rootKey), fixtureClock).valid());
  }

  @Test
  void tsTokenRejectedAfterExpiry() {
    long exp = fixtures.path("tokens").path("root").path("exp").asLong();
    Clock afterExpiry = Clock.fixed(Instant.ofEpochSecond(exp + 1), ZoneOffset.UTC);
    assertFalse(
        Ovid.verifyOvid(
                fixtures.path("tokens").path("root").path("jwt").asText(),
                VerifyOvidOptions.of(rootKey),
                afterExpiry)
            .valid());
  }
}
