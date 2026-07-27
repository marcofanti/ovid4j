// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import java.security.KeyPair;

/**
 * A freshly minted OVID: the signed JWT, its decoded claims, and the agent's
 * own keypair (needed to issue derived OVIDs to sub-agents).
 *
 * <p>Handle with care: {@code keys} contains the agent's private key. Never
 * serialize it into transcripts, logs, or spawn task text.
 */
public record OvidToken(String jwt, OvidClaims claims, KeyPair keys) {}
