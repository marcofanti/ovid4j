// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * OVID issuance and verification — the port of the TypeScript library's
 * {@code createOvid} / {@code renewOvid} / {@code verifyOvid}.
 *
 * <p>Deviations from the TypeScript library (all documented in the README):
 * legacy pre-0.4.0 tokens are rejected instead of verified via the single-key
 * fallback, the deprecated single-key {@code verifyOvid} overload is not
 * offered, and the JWT header's {@code typ} must be {@code ovid+jwt} (the
 * documented wire format).
 */
public final class Ovid {

  static final long DEFAULT_TTL = 1800;
  static final int DEFAULT_MAX_CHAIN_DEPTH = 5;
  private static final SecureRandom RANDOM = new SecureRandom();

  // ────────────────────────────────────────────────────────────────────────
  // Issuance
  // ────────────────────────────────────────────────────────────────────────

  public static OvidToken createOvid(CreateOvidOptions options) {
    return createOvid(options, Clock.systemUTC());
  }

  /** Clock-injectable variant for tests and fixture generation. */
  public static OvidToken createOvid(CreateOvidOptions options, Clock clock) {
    if (options.issuerKeys() == null) {
      throw new IllegalArgumentException("issuerKeys is required");
    }
    List<AuthorizationDetail> details = validatedDetails(options);

    OvidClaims parentClaims =
        options.issuerOvid() == null ? null : options.issuerOvid().claims();

    long ttlSeconds = options.ttlSeconds() == null ? DEFAULT_TTL : options.ttlSeconds();
    long now = clock.instant().getEpochSecond();
    long childExp = now + ttlSeconds;
    if (parentClaims != null && childExp > parentClaims.exp()) {
      throw new IllegalArgumentException(
          "Lifetime attenuation violation: child expiry exceeds parent expiry");
    }

    // Root: issuerKeys IS the token's binding keypair; its chain link is
    // self-signed. Child: fresh keypair for the new agent; the parent signs
    // the chain link (its attestation) while the child signs its own JWT.
    boolean isRoot = parentClaims == null;
    KeyPair agentKeys = isRoot ? options.issuerKeys() : Keys.generate();
    String agentPub = Keys.exportPublicKeyBase64(agentKeys.getPublic());

    String issuerName =
        options.issuer() != null
            ? options.issuer()
            : parentClaims != null ? parentClaims.sub() : "root";
    String agentId =
        options.agentId() != null ? options.agentId() : issuerName + "/agent-" + randomHex(4);

    List<ChainLink> existingChain = existingChain(parentClaims);
    if (existingChain.size() + 1 > DEFAULT_MAX_CHAIN_DEPTH) {
      throw new IllegalArgumentException(
          "Chain depth " + (existingChain.size() + 1) + " exceeds max " + DEFAULT_MAX_CHAIN_DEPTH);
    }

    ChainLink thisLink =
        new ChainLink(
            agentId,
            agentPub,
            now,
            childExp,
            ChainLinks.signChainLink(
                agentId, agentPub, now, childExp, options.issuerKeys().getPrivate()));

    List<ChainLink> parentChain = new ArrayList<>(existingChain);
    parentChain.add(thisLink);

    List<AuthorizationDetail> finalDetails = new ArrayList<>(details);
    AuthorizationDetail first = finalDetails.getFirst();
    finalDetails.set(
        0,
        new AuthorizationDetail(
            first.type(),
            first.rarFormat(),
            first.policySet(),
            List.copyOf(parentChain),
            agentPub,
            Protocol.OVID_PROTOCOL_VERSION));

    OvidClaims claims =
        new OvidClaims(
            agentId,
            issuerName,
            agentId,
            now,
            childExp,
            List.copyOf(finalDetails),
            parentClaims == null ? null : parentClaims.jti());

    String jwt = signJwt(claims, options.kid(), agentKeys);
    return new OvidToken(jwt, claims, agentKeys);
  }

  /**
   * Renew an OVID token's expiry without changing its mandate or identity.
   *
   * <p>Only roots can be renewed, and only with the same keypair that anchors
   * the root link — otherwise any caller could re-root someone else's token
   * under their own key (trust laundering). Chained tokens must be re-minted
   * by their parent instead.
   */
  public static OvidToken renewOvid(OvidToken existingToken, KeyPair issuerKeys, Long ttlSeconds) {
    return renewOvid(existingToken, issuerKeys, ttlSeconds, Clock.systemUTC());
  }

  public static OvidToken renewOvid(
      OvidToken existingToken, KeyPair issuerKeys, Long ttlSeconds, Clock clock) {
    List<AuthorizationDetail> existingDetails = existingToken.claims().authorizationDetails();
    AuthorizationDetail detail =
        existingDetails == null || existingDetails.isEmpty() ? null : existingDetails.getFirst();
    List<ChainLink> chain = detail == null ? null : detail.parentChain();

    if (chain == null || chain.isEmpty()) {
      throw new IllegalArgumentException(
          "Cannot renew a legacy (pre-0.4.0) OVID token: parent_chain lacks cryptographic "
              + "attestations required to prove root identity. Mint a fresh token with "
              + "createOvid() instead.");
    }
    if (chain.size() > 1) {
      throw new IllegalArgumentException(
          "Cannot renew a chained (non-root) OVID token: only the parent can reissue. "
              + "Ask the parent to mint a new child token instead.");
    }
    String issuerPub = Keys.exportPublicKeyBase64(issuerKeys.getPublic());
    if (!issuerPub.equals(chain.getFirst().agentPub())) {
      throw new IllegalArgumentException(
          "renewOvid: issuerKeys does not match the root link's agent_pub. "
              + "Only the original root keypair can renew a root token.");
    }

    CreateOvidOptions.Builder renewed =
        CreateOvidOptions.builder()
            .issuerKeys(issuerKeys)
            .authorizationDetails(
                existingToken.claims().authorizationDetails().stream()
                    .map(d -> AuthorizationDetail.cedar(d.type(), d.policySet()))
                    .toList())
            .agentId(existingToken.claims().sub())
            .issuer(existingToken.claims().iss());
    if (ttlSeconds != null) {
      renewed.ttlSeconds(ttlSeconds);
    }
    return createOvid(renewed.build(), clock);
  }

  // ────────────────────────────────────────────────────────────────────────
  // Verification
  // ────────────────────────────────────────────────────────────────────────

  public static OvidResult verifyOvid(String jwt, VerifyOvidOptions options) {
    return verifyOvid(jwt, options, Clock.systemUTC());
  }

  /**
   * Verify an OVID JWT against a set of trusted root public keys. Never
   * throws: any malformed or failing token yields {@code valid == false}.
   */
  public static OvidResult verifyOvid(String jwt, VerifyOvidOptions options, Clock clock) {
    if (options == null || options.trustedRoots().isEmpty()) {
      return OvidResult.invalid();
    }
    try {
      CompactJws jws = CompactJws.parse(jwt);
      JsonNode header = Json.MAPPER.readTree(jws.headerJson());
      if (!"EdDSA".equals(header.path("alg").asText())
          || !"ovid+jwt".equals(header.path("typ").asText())) {
        return OvidResult.invalid();
      }

      // Peek at the (unverified) payload to find the chain; nothing from the
      // peek is trusted until the signatures below pass.
      JsonNode payload = Json.MAPPER.readTree(jws.payloadJson());
      JsonNode detailPeek = payload.path("authorization_details").path(0);
      JsonNode chainNode = detailPeek.path("parent_chain");
      if (!Protocol.isChainProtocolVersion(detailPeek.path("ovid_version").asText(null))
          || !isChainLinkArray(chainNode)) {
        // Legacy (pre-0.4.0) tokens are not cryptographically walkable; this
        // port rejects them rather than falling back to single-key verification.
        return OvidResult.invalid();
      }

      List<ChainLink> chain = new ArrayList<>();
      for (JsonNode linkNode : chainNode) {
        chain.add(Json.MAPPER.treeToValue(linkNode, ChainLink.class));
      }
      return verifyV04(jws, payload, chain, options, clock);
    } catch (RuntimeException | JsonProcessingException e) {
      return OvidResult.invalid();
    }
  }

  private static OvidResult verifyV04(
      CompactJws jws,
      JsonNode payloadNode,
      List<ChainLink> chain,
      VerifyOvidOptions options,
      Clock clock)
      throws JsonProcessingException {
    if (chain.isEmpty() || chain.size() > options.effectiveMaxChainDepth()) {
      return OvidResult.invalid();
    }

    // Anchor: a trusted root whose exported public key matches chain[0].agent_pub.
    PublicKey anchorKey = null;
    for (PublicKey root : options.trustedRoots()) {
      if (ChainLinks.trustedRootMatches(root, chain.getFirst().agentPub())) {
        anchorKey = root;
        break;
      }
    }
    if (anchorKey == null || !ChainLinks.verifyChainLink(chain.getFirst(), anchorKey)) {
      return OvidResult.invalid();
    }

    // Walk: each subsequent link is signed by its parent's agent_pub, with
    // lifetime attenuation enforced at every step.
    for (int i = 1; i < chain.size(); i++) {
      ChainLink parent = chain.get(i - 1);
      ChainLink child = chain.get(i);
      if (child.exp() > parent.exp() || child.iat() < parent.iat()) {
        return OvidResult.invalid();
      }
      PublicKey parentKey = Keys.importPublicKeyBase64(parent.agentPub());
      if (!ChainLinks.verifyChainLink(child, parentKey)) {
        return OvidResult.invalid();
      }
    }

    // The leaf link holds the only key that can legitimately have signed this JWT.
    ChainLink leaf = chain.getLast();
    PublicKey leafKey = Keys.importPublicKeyBase64(leaf.agentPub());
    if (!jws.verifySignature(leafKey)) {
      return OvidResult.invalid();
    }

    OvidClaims claims = Json.MAPPER.treeToValue(payloadNode, OvidClaims.class);
    if (!leaf.sub().equals(claims.sub())) {
      return OvidResult.invalid();
    }

    long now = clock.instant().getEpochSecond();
    long expiresIn = claims.exp() - now;
    if (expiresIn <= 0) {
      return OvidResult.invalid();
    }
    // JWT exp must not exceed the leaf link's exp, and its iat must not
    // predate the leaf link's iat — otherwise a child could outlive or
    // backdate what its parent actually attested.
    if (claims.exp() > leaf.exp() || claims.iat() < leaf.iat()) {
      return OvidResult.invalid();
    }

    List<AuthorizationDetail> details = claims.authorizationDetails();
    AuthorizationDetail detail = details == null || details.isEmpty() ? null : details.getFirst();
    if (detail == null || detail.policySet() == null || detail.policySet().isEmpty()) {
      return OvidResult.invalid();
    }

    AuthorizationDetail mandate =
        detail.type() == null || detail.type().isEmpty()
            ? new AuthorizationDetail(
                "agent_mandate",
                detail.rarFormat(),
                detail.policySet(),
                detail.parentChain(),
                detail.agentPub(),
                detail.ovidVersion())
            : detail;

    return new OvidResult(
        true, claims.sub(), mandate, chain.stream().map(ChainLink::sub).toList(), expiresIn);
  }

  // ────────────────────────────────────────────────────────────────────────
  // Helpers
  // ────────────────────────────────────────────────────────────────────────

  private static List<AuthorizationDetail> validatedDetails(CreateOvidOptions options) {
    List<AuthorizationDetail> details = options.authorizationDetails();
    if (details == null || details.isEmpty()) {
      throw new IllegalArgumentException("authorizationDetails (or a mandate) is required");
    }
    for (AuthorizationDetail detail : details) {
      if (detail == null
          || !"cedar".equals(detail.rarFormat())
          || detail.policySet() == null
          || detail.policySet().isEmpty()
          || detail.type() == null
          || detail.type().isEmpty()) {
        throw new IllegalArgumentException(
            "mandate is required with type, rarFormat \"cedar\", and a non-empty policySet");
      }
      CedarSyntax.Result syntax = CedarSyntax.validateCedarSyntax(detail.policySet());
      if (!syntax.valid()) {
        throw new IllegalArgumentException("Invalid Cedar policy syntax: " + syntax.error());
      }
    }
    return details;
  }

  private static List<ChainLink> existingChain(OvidClaims parentClaims) {
    if (parentClaims == null) {
      return List.of();
    }
    List<AuthorizationDetail> parentDetails = parentClaims.authorizationDetails();
    AuthorizationDetail parentDetail =
        parentDetails == null || parentDetails.isEmpty() ? null : parentDetails.getFirst();
    List<ChainLink> parentChain = parentDetail == null ? null : parentDetail.parentChain();
    if (parentChain == null || parentChain.isEmpty()) {
      // Parent is a legacy (pre-0.4.0) token whose chain carries no
      // attestations we could extend; refuse rather than emit something that
      // claims to be verifiable but isn't.
      throw new IllegalArgumentException(
          "Cannot mint v0.4.0 child under legacy (pre-0.4.0) parent: parent_chain lacks "
              + "cryptographic attestations. Re-mint the parent with v0.4.0 first.");
    }
    return parentChain;
  }

  private static String signJwt(OvidClaims claims, String kid, KeyPair agentKeys) {
    ObjectNode header = Json.MAPPER.createObjectNode();
    header.put("alg", "EdDSA");
    header.put("typ", "ovid+jwt");
    if (kid != null) {
      header.put("kid", kid);
    }
    try {
      return CompactJws.sign(
          Json.MAPPER.writeValueAsString(header),
          Json.MAPPER.writeValueAsString(claims),
          agentKeys.getPrivate());
    } catch (JsonProcessingException e) {
      throw new IllegalStateException("failed to serialize OVID claims", e);
    }
  }

  private static boolean isChainLinkArray(JsonNode node) {
    if (!node.isArray() || node.isEmpty()) {
      return false;
    }
    JsonNode first = node.get(0);
    return first.isObject()
        && first.path("sub").isTextual()
        && first.path("agent_pub").isTextual()
        && first.path("sig").isTextual();
  }

  private static String randomHex(int bytes) {
    byte[] buf = new byte[bytes];
    RANDOM.nextBytes(buf);
    return HexFormat.of().formatHex(buf);
  }

  private Ovid() {}
}
