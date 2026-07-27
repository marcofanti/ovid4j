// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CedarSyntaxTest {

  private static CedarSyntax.Result validate(String policy) {
    return CedarSyntax.validateCedarSyntax(policy);
  }

  @Test
  void acceptsSimplePermit() {
    assertTrue(
        validate("permit(principal, action == Ovid::Action::\"read_file\", resource);").valid());
  }

  @Test
  void acceptsPermitWithWhenClause() {
    assertTrue(
        validate(
                "permit(principal, action == Ovid::Action::\"read\", resource) "
                    + "when { resource.path like \"/src/*\" };")
            .valid());
  }

  @Test
  void acceptsMultipleStatements() {
    assertTrue(
        validate(
                "permit(principal, action == Ovid::Action::\"read\", resource);\n"
                    + "forbid(principal, action == Ovid::Action::\"exec\", resource);")
            .valid());
  }

  @Test
  void rejectsEmptyPolicy() {
    CedarSyntax.Result result = validate("   ");
    assertFalse(result.valid());
    assertEquals("Policy set is empty", result.error());
  }

  @Test
  void rejectsPolicyWithoutPermitOrForbid() {
    assertFalse(validate("allow(principal, action, resource);").valid());
  }

  @Test
  void rejectsUnmatchedOpenParen() {
    assertFalse(validate("permit(principal, action, resource;").valid());
  }

  @Test
  void rejectsUnmatchedCloseParen() {
    assertFalse(validate("permit principal), action, resource;").valid());
  }

  @Test
  void rejectsUnmatchedQuote() {
    assertFalse(validate("permit(principal, action == Ovid::Action::\"read, resource);").valid());
  }

  @Test
  void rejectsMissingSemicolon() {
    CedarSyntax.Result result = validate("permit(principal, action, resource)");
    assertFalse(result.valid());
    assertEquals("Statement missing terminating semicolon", result.error());
  }

  @Test
  void rejectsMissingSemicolonBetweenStatements() {
    assertFalse(
        validate(
                "permit(principal, action, resource)\n"
                    + "permit(principal, action, resource);")
            .valid());
  }
}
