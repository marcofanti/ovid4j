// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.marcofanti.ovid4j.MandateBuilder.BuildResult;
import io.github.marcofanti.ovid4j.MandateBuilder.GrantIntent;
import io.github.marcofanti.ovid4j.MandateBuilder.MandateIntent;
import io.github.marcofanti.ovid4j.MandateBuilder.ResourceConstraint;
import java.util.List;
import org.junit.jupiter.api.Test;

class MandateBuilderTest {

  @Test
  void emptyIntentEmitsSafeDefault() {
    BuildResult result = MandateBuilder.buildMandate(MandateIntent.empty());
    assertEquals(
        "permit(principal, action in [Ovid::Action::\"read\", Ovid::Action::\"search\", "
            + "Ovid::Action::\"summarize\"], resource);",
        result.policySet());
    assertEquals("default: read, search, summarize", result.summary());
    assertEquals(1, result.warnings().size());
    assertTrue(CedarSyntax.validateCedarSyntax(result.policySet()).valid());
  }

  @Test
  void singleActionUsesEqualityClause() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(List.of(GrantIntent.of("read")), null, null, null));
    assertEquals("permit(principal, action == Ovid::Action::\"read\", resource);",
        result.policySet());
  }

  @Test
  void multipleActionsUseInClause() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(List.of(GrantIntent.of("read", "write")), null, null, null));
    assertEquals(
        "permit(principal, action in [Ovid::Action::\"read\", Ovid::Action::\"write\"], "
            + "resource);",
        result.policySet());
  }

  @Test
  void shellIdsEmitOneStatementPerId() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(
                List.of(GrantIntent.of(ResourceConstraint.ids("Shell", "git", "npm"), "exec")),
                null,
                null,
                null));
    assertEquals(
        "permit(principal, action == Ovid::Action::\"exec\", resource == Ovid::Shell::\"git\");\n"
            + "permit(principal, action == Ovid::Action::\"exec\", "
            + "resource == Ovid::Shell::\"npm\");",
        result.policySet());
  }

  @Test
  void apiKindNormalizesToWebEndpoint() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(
                List.of(
                    GrantIntent.of(ResourceConstraint.ids("API", "api.github.com"), "fetch")),
                null,
                null,
                null));
    assertTrue(result.policySet().contains("Ovid::WebEndpoint::\"api.github.com\""));
  }

  @Test
  void pathGlobsEmitWhenClauses() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(
                List.of(
                    GrantIntent.of(
                        ResourceConstraint.paths("File", "**/workspace/**"), "read")),
                null,
                null,
                null));
    assertEquals(
        "permit(principal, action == Ovid::Action::\"read\", resource) "
            + "when { resource.path like \"**/workspace/**\" };",
        result.policySet());
    assertTrue(CedarSyntax.validateCedarSyntax(result.policySet()).valid());
  }

  @Test
  void forbidGrantsEmitForbidStatements() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(
                List.of(GrantIntent.of("read")),
                List.of(GrantIntent.of(ResourceConstraint.ids("Shell", "rm"), "exec")),
                1800L,
                null));
    assertTrue(
        result.policySet().contains(
            "forbid(principal, action == Ovid::Action::\"exec\", "
                + "resource == Ovid::Shell::\"rm\");"));
    assertEquals(1800L, result.ttlSeconds());
    assertEquals("allow read (any); deny exec Shell [rm]", result.summary());
  }

  @Test
  void unknownActionsAreDroppedWithWarning() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(
                List.of(GrantIntent.of("read", "launch_missiles")), null, null, null));
    assertEquals("permit(principal, action == Ovid::Action::\"read\", resource);",
        result.policySet());
    assertTrue(result.warnings().getFirst().contains("launch_missiles"));
  }

  @Test
  void allGrantsInvalidCompilesToExplicitDenyAll() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(List.of(GrantIntent.of("fly")), null, null, null));
    assertTrue(result.policySet().startsWith("forbid(principal, action in ["));
    assertTrue(result.warnings().stream().anyMatch(w -> w.contains("grants nothing")));
    assertTrue(CedarSyntax.validateCedarSyntax(result.policySet()).valid());
  }

  @Test
  void typeOnlyConstraintFallsBackToWildcardWithWarning() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(
                List.of(
                    new GrantIntent(
                        List.of("read"), new ResourceConstraint("File", null, null), null)),
                null,
                null,
                null));
    assertEquals("permit(principal, action == Ovid::Action::\"read\", resource);",
        result.policySet());
    assertTrue(result.warnings().getFirst().contains("kind not enforced"));
  }

  @Test
  void unsafeResourceIdThrows() {
    MandateIntent intent =
        new MandateIntent(
            List.of(GrantIntent.of(ResourceConstraint.ids("Shell", "rm\");permit(x"), "exec")),
            null,
            null,
            null);
    assertThrows(IllegalArgumentException.class, () -> MandateBuilder.buildMandate(intent));
  }

  @Test
  void unsafePathGlobThrows() {
    MandateIntent intent =
        new MandateIntent(
            List.of(GrantIntent.of(ResourceConstraint.paths("File", "/tmp/\"};forbid"), "read")),
            null,
            null,
            null);
    assertThrows(IllegalArgumentException.class, () -> MandateBuilder.buildMandate(intent));
  }

  @Test
  void invalidNamespaceThrows() {
    MandateIntent intent =
        new MandateIntent(List.of(GrantIntent.of("read")), null, null, "Bad Namespace");
    assertThrows(IllegalArgumentException.class, () -> MandateBuilder.buildMandate(intent));
  }

  @Test
  void customNamespaceIsUsed() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(List.of(GrantIntent.of("read")), null, null, "Acme"));
    assertEquals("permit(principal, action == Acme::Action::\"read\", resource);",
        result.policySet());
  }

  @Test
  void mandateTagWrapsPolicyWithTtl() {
    MandateBuilder.TagResult tag =
        MandateBuilder.buildMandateTag(
            new MandateIntent(List.of(GrantIntent.of("read")), null, 1800L, null));
    assertEquals(
        "[OVID_TTL:1800]\n[OVID_MANDATE]\n"
            + "permit(principal, action == Ovid::Action::\"read\", resource);\n"
            + "[/OVID_MANDATE]",
        tag.tag());
  }

  @Test
  void mandateTagOmitsTtlLineWhenAbsent() {
    MandateBuilder.TagResult tag =
        MandateBuilder.buildMandateTag(
            new MandateIntent(List.of(GrantIntent.of("read")), null, null, null));
    assertTrue(tag.tag().startsWith("[OVID_MANDATE]\n"));
  }

  @Test
  void builtMandatesAreAcceptedByCreateOvid() {
    BuildResult result =
        MandateBuilder.buildMandate(
            new MandateIntent(
                List.of(
                    GrantIntent.of(ResourceConstraint.paths("File", "**/workspace/**"), "read"),
                    GrantIntent.of(ResourceConstraint.ids("Shell", "git", "gh"), "exec")),
                List.of(GrantIntent.of(ResourceConstraint.ids("Shell", "rm", "sudo"), "exec")),
                1800L,
                null));
    OvidToken token =
        Ovid.createOvid(
            CreateOvidOptions.builder()
                .issuerKeys(Keys.generate())
                .mandate(AuthorizationDetail.agentMandate(result.policySet()))
                .build());
    assertEquals(result.policySet(),
        token.claims().authorizationDetails().getFirst().policySet());
  }
}
