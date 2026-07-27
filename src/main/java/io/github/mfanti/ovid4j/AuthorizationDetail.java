// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * RFC 9396 {@code authorization_details} entry for OVID agent mandates,
 * per draft-cecchetti-oauth-rar-cedar-02 adapted for agent mandates.
 *
 * @param type application-defined type (required by RFC 9396); {@code "agent_mandate"} for OVID
 * @param rarFormat must be {@code "cedar"} to use this profile
 * @param policySet Cedar policy text — the agent's mandate
 * @param parentChain OVID delegation chain, root first, leaf last (0.4.0+ shape only;
 *     this port does not accept the pre-0.4 {@code string[]} shape)
 * @param agentPub agent's raw Ed25519 public key, base64url
 * @param ovidVersion wire protocol version that minted this token
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthorizationDetail(
    @JsonProperty("type") String type,
    @JsonProperty("rarFormat") String rarFormat,
    @JsonProperty("policySet") String policySet,
    @JsonProperty("parent_chain") List<ChainLink> parentChain,
    @JsonProperty("agent_pub") String agentPub,
    @JsonProperty("ovid_version") String ovidVersion) {

  /** Mandate carried by every invalid {@link OvidResult}. */
  public static final AuthorizationDetail EMPTY =
      new AuthorizationDetail("agent_mandate", "cedar", "", null, null, null);

  /** Convenience constructor for the caller-facing part (type, rarFormat, policySet). */
  public static AuthorizationDetail cedar(String type, String policySet) {
    return new AuthorizationDetail(type, "cedar", policySet, null, null, null);
  }

  /** Cedar mandate of type {@code agent_mandate} — the standard OVID shape. */
  public static AuthorizationDetail agentMandate(String policySet) {
    return cedar("agent_mandate", policySet);
  }
}
