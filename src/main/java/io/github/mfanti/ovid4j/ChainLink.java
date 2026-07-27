// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A single link in the OVID delegation chain (ovid_version 0.4.0+).
 *
 * <p>Each link carries a cryptographic attestation from its parent binding
 * (sub, agent_pub, iat, exp), enabling verifiers to walk the chain back to a
 * trusted root without needing the intermediate JWTs.
 *
 * <p>Canonical signed bytes for {@code sig} (MUST be byte-exact for interop):
 * <pre>"ovid-chain-link/v1\n" + sub + "\n" + agent_pub + "\n" + iat + "\n" + exp</pre>
 * encoded as UTF-8; {@code iat}/{@code exp} are decimal integers with no leading
 * zeros. The signature is raw Ed25519 (64 bytes), base64url without padding.
 *
 * <p>Root links are self-signed: {@code sig} verifies against the key named by
 * this link's own {@code agent_pub}, which must match one of the verifier's
 * trusted roots.
 *
 * @param sub the agent subject this link represents
 * @param agentPub base64url-encoded raw Ed25519 public key bound to {@code sub}
 * @param iat issued-at (unix seconds); must be >= parent link's iat
 * @param exp expiry (unix seconds); must be <= parent link's exp
 * @param sig base64url Ed25519 signature by the PARENT's key over the canonical bytes
 */
public record ChainLink(
    @JsonProperty("sub") String sub,
    @JsonProperty("agent_pub") String agentPub,
    @JsonProperty("iat") long iat,
    @JsonProperty("exp") long exp,
    @JsonProperty("sig") String sig) {}
