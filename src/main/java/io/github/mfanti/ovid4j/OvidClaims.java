// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * OVID JWT payload claims.
 *
 * @param jti JWT ID; by convention the agent's path-style identifier
 * @param iss issuer — the human or organization the root agent serves
 * @param sub subject — the agent this token identifies (equal to jti for OVIDs)
 * @param iat issued-at, unix seconds
 * @param exp expiry, unix seconds
 * @param authorizationDetails RFC 9396 carrier for the agent's mandate(s)
 * @param parentOvid parent's jti; informational only, the source of truth is the parent_chain
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OvidClaims(
    @JsonProperty("jti") String jti,
    @JsonProperty("iss") String iss,
    @JsonProperty("sub") String sub,
    @JsonProperty("iat") long iat,
    @JsonProperty("exp") long exp,
    @JsonProperty("authorization_details") List<AuthorizationDetail> authorizationDetails,
    @JsonProperty("parent_ovid") String parentOvid) {}
