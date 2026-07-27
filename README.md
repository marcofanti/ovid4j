# ovid4j

**Unofficial Java port of [OVID](https://github.com/clawdreyhepburn/ovid) — cryptographic identity documents for AI agents.**

Ed25519-signed JWTs with delegation chains: each sub-agent carries a tamper-proof
badge saying who it is, who created it, what mandate (Cedar policy) it holds, and
when it expires. Wire-compatible with `@clawdreyhepburn/ovid` protocol **0.4.0**:
tokens minted here verify in the TypeScript library and vice versa (covered by
cross-implementation tests, see [Interop](#interop)).

For the concepts — ambient authority, chains, mandates, how OVID fits with
OVID-ME and Carapace — read the [upstream README](https://github.com/clawdreyhepburn/ovid#readme).
This README covers the Java API and where this port differs.

## Requirements

- Java 26 (Ed25519 is JDK-native; no crypto dependencies)
- Maven

Single runtime dependency: Jackson (`jackson-databind`) for JWT claims JSON.

## Quick start

```java
import io.github.marcofanti.ovid4j.*;
import java.security.KeyPair;

// Primary agent creates a keypair (do this once, persist it)
KeyPair primaryKeys = Keys.generate();

// Spawn a sub-agent with a signed identity and Cedar mandate
OvidToken reviewer = Ovid.createOvid(CreateOvidOptions.builder()
    .issuerKeys(primaryKeys)
    .issuer("clawdrey")
    .mandate(AuthorizationDetail.agentMandate(
        "permit(principal, action == Ovid::Action::\"read_file\", resource);"))
    .ttlSeconds(1800)
    .build());

System.out.println(reviewer.jwt());  // standard JWT string

// Verify: walks the chain leaf → root, anchors against trusted roots
OvidResult result = Ovid.verifyOvid(reviewer.jwt(),
    VerifyOvidOptions.of(primaryKeys.getPublic()));
if (result.valid()) {
  result.principal();  // "clawdrey/agent-7f3a"
  result.mandate();    // verified AuthorizationDetail with Cedar policySet
  result.chain();      // ["clawdrey/agent-7f3a"] — subs, root first
  result.expiresIn();  // seconds until expiry
}

// Delegation: sub-agents issue OVIDs to their own sub-agents
OvidToken helper = Ovid.createOvid(CreateOvidOptions.builder()
    .issuerKeys(reviewer.keys())
    .issuerOvid(reviewer)
    .mandate(AuthorizationDetail.agentMandate(
        "permit(principal, action == Ovid::Action::\"read_file\", resource);"))
    .ttlSeconds(600)   // must be shorter than the parent's remaining lifetime
    .build());
```

### Mandate builder

Compile a structured intent into a Cedar policySet instead of writing raw Cedar:

```java
import io.github.marcofanti.ovid4j.MandateBuilder.*;

BuildResult mandate = MandateBuilder.buildMandate(new MandateIntent(
    List.of(
        GrantIntent.of(ResourceConstraint.paths("File", "**/workspace/**"), "read"),
        GrantIntent.of(ResourceConstraint.ids("Shell", "git", "gh", "npm"), "exec")),
    List.of(
        GrantIntent.of(ResourceConstraint.ids("Shell", "rm", "sudo"), "exec")),  // forbid — always wins
    1800L,
    null));
// mandate.policySet() is ready for AuthorizationDetail.agentMandate(...)
```

Unsafe ids/globs throw rather than emit injectable Cedar; unknown actions are
dropped with a warning; empty intents compile to the safe default
(read/search/summarize) and all-invalid intents to an explicit deny-all.
`MandateBuilder.buildMandateTag(...)` emits the `[OVID_TTL]`/`[OVID_MANDATE]`
spawn-task block.

## API surface

| TypeScript (`@clawdreyhepburn/ovid`) | Java |
|---|---|
| `generateKeypair()` | `Keys.generate()` |
| `exportPublicKeyBase64` / `importPublicKeyBase64` | `Keys.exportPublicKeyBase64` / `Keys.importPublicKeyBase64` |
| `createOvid(options)` | `Ovid.createOvid(CreateOvidOptions)` |
| `renewOvid(token, keys, ttl)` | `Ovid.renewOvid(token, keys, ttl)` (roots only, same semantics) |
| `verifyOvid(jwt, { trustedRoots, maxChainDepth })` | `Ovid.verifyOvid(jwt, VerifyOvidOptions)` |
| `validateCedarSyntax` | `CedarSyntax.validateCedarSyntax` |
| `buildMandate` / `buildMandateTag` | `MandateBuilder.buildMandate` / `buildMandateTag` |
| `MANDATE_ACTIONS`, `RESOURCE_KINDS`, `OVID_TO_JANS`, … | `Vocabulary` |
| `OVID_PROTOCOL_VERSION`, `CHAIN_PROTOCOL_VERSIONS` | `Protocol` |

`Ovid.createOvid`/`verifyOvid`/`renewOvid` accept an optional `java.time.Clock`
for deterministic tests (the TypeScript library uses the wall clock internally).
All verification failures return `OvidResult.valid() == false`; issuance
failures throw `IllegalArgumentException` with the same messages as upstream.

## Deviations from the TypeScript library

Intentional differences, all on the strict side:

1. **Legacy (pre-0.4.0) tokens are rejected**, not verified. Upstream falls back
   to single-key JWT verification for `ovid_version <= 0.3.x` tokens (whose
   chains are not cryptographically walkable) with a deprecation warning. This
   port verifies only chain-protocol (`0.4.0`) tokens.
2. **No deprecated single-key `verifyOvid(jwt, key)` overload.** Use
   `VerifyOvidOptions.of(key)`.
3. **The JWT header `typ` must be `ovid+jwt`** and `alg` must be `EdDSA`, per the
   documented wire format (upstream documents but does not currently enforce `typ`).
4. **Non-extractable keys (upstream's C5) don't map to the JCA.** Java private
   keys are in-memory objects; the equivalent discipline here is: never serialize
   `OvidToken.keys()` — nothing in this library will do it for you.

The wire format is unchanged: canonical chain-link bytes
(`ovid-chain-link/v1\n<sub>\n<agent_pub>\n<iat>\n<exp>`), raw-32-byte base64url
Ed25519 public keys, and the claim/field names are byte-compatible.

### Why no JOSE library

OVID uses exactly one JOSE feature: EdDSA compact JWS. The JDK has native
Ed25519, so the port implements the ~60-line compact serialization directly
(`CompactJws`) instead of pulling in a JOSE dependency (Nimbus would also drag
in Tink for OKP signing). One fixed algorithm, no `alg` negotiation — the
classic JWT confusion attacks are unrepresentable.

## Development

```bash
mvn test     # 75 tests, includes golden-fixture interop against TS-minted tokens
mvn package
```

### Interop

Cross-implementation compatibility is tested in both directions:

- **TS → Java:** `src/test/resources/interop/ts-fixtures.json` holds tokens
  (depths 1–3) minted by the TypeScript reference library; `InteropTsFixturesTest`
  verifies them. Regenerate with
  `node interop/generate-ts-fixtures.mjs [path/to/ovid/dist/index.js]`
  (after `npm install && npm run build` in the ovid repo).
- **Java → TS:** `mvn test` writes freshly minted Java tokens to
  `target/interop/java-tokens.json`; then
  `node interop/verify-java-tokens.mjs` verifies them with the reference
  library and checks foreign-root rejection.

## License & attribution (the fine print)

- **License:** [Apache-2.0](LICENSE), same as the original.
- **Derivative work:** this is an independent Java port of
  [OVID](https://github.com/clawdreyhepburn/ovid), Copyright 2026
  Clawdrey Hepburn LLC. The original copyright and NOTICE attribution are
  preserved in [NOTICE](NOTICE), together with the statement of changes.
- **Trademark:** "OVID" is a trademark of Clawdrey Hepburn LLC. The name
  "ovid4j" refers to the protocol this library implements. This project is
  **unofficial** and is **not endorsed by, affiliated with, or sponsored by
  Clawdrey Hepburn LLC**. Apache-2.0 §6 grants no trademark rights.
- Behavioral differences from the original are listed under
  [Deviations](#deviations-from-the-typescript-library); everything else aims
  to be a faithful, wire-compatible port of upstream v0.5.0 (wire protocol 0.4.0).
