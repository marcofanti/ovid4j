// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.security.PrivateKey;

/** Shared helpers for exercising failure paths. */
final class TestSupport {

  static final String READ_POLICY =
      "permit(principal, action == Ovid::Action::\"read_file\", resource);";

  static AuthorizationDetail readMandate() {
    return AuthorizationDetail.agentMandate(READ_POLICY);
  }

  static CreateOvidOptions.Builder rootOptions(java.security.KeyPair keys) {
    return CreateOvidOptions.builder().issuerKeys(keys).issuer("test").mandate(readMandate());
  }

  /**
   * Decode a JWT payload, apply a mutation, and re-sign the token with the
   * given private key — simulating an attacker who can author tokens but does
   * not hold the legitimately attested key.
   */
  static String tamperAndResign(
      String jwt, java.util.function.Consumer<ObjectNode> mutate, PrivateKey signWith) {
    try {
      CompactJws jws = CompactJws.parse(jwt);
      ObjectNode payload = (ObjectNode) Json.MAPPER.readTree(jws.payloadJson());
      mutate.accept(payload);
      return CompactJws.sign(
          jws.headerJson(), Json.MAPPER.writeValueAsString(payload), signWith);
    } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  private TestSupport() {}
}
