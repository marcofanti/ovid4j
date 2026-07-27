// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import static io.github.marcofanti.ovid4j.TestSupport.readMandate;
import static io.github.marcofanti.ovid4j.TestSupport.rootOptions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class RenewOvidTest {

  private final KeyPair rootKeys = Keys.generate();

  @Test
  void renewsRootTokenKeepingIdentityAndMandate() {
    OvidToken original = Ovid.createOvid(rootOptions(rootKeys).ttlSeconds(600).build());
    Clock later =
        Clock.fixed(Instant.ofEpochSecond(original.claims().iat() + 500), ZoneOffset.UTC);
    OvidToken renewed = Ovid.renewOvid(original, rootKeys, 600L, later);

    assertEquals(original.claims().sub(), renewed.claims().sub());
    assertEquals(original.claims().iss(), renewed.claims().iss());
    assertEquals(
        original.claims().authorizationDetails().getFirst().policySet(),
        renewed.claims().authorizationDetails().getFirst().policySet());
    assertTrue(renewed.claims().exp() > original.claims().exp());
    assertTrue(
        Ovid.verifyOvid(renewed.jwt(), VerifyOvidOptions.of(rootKeys.getPublic()), later).valid());
  }

  @Test
  void refusesToRenewChainedToken() {
    OvidToken root = Ovid.createOvid(rootOptions(rootKeys).ttlSeconds(3600).build());
    OvidToken child =
        Ovid.createOvid(
            CreateOvidOptions.builder()
                .issuerKeys(root.keys())
                .issuerOvid(root)
                .mandate(readMandate())
                .ttlSeconds(600)
                .build());
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Ovid.renewOvid(child, rootKeys, null));
    assertTrue(e.getMessage().contains("chained"));
  }

  @Test
  void refusesRenewalWithForeignKeys() {
    OvidToken original = Ovid.createOvid(rootOptions(rootKeys).build());
    KeyPair attacker = Keys.generate();
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class, () -> Ovid.renewOvid(original, attacker, null));
    assertTrue(e.getMessage().contains("does not match the root link"));
  }
}
