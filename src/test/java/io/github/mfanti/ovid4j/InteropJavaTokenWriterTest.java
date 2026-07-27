// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import static io.github.mfanti.ovid4j.TestSupport.readMandate;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

/**
 * Reverse interop: mints Java tokens and writes them to
 * {@code target/interop/java-tokens.json} for verification by the TypeScript
 * reference library via {@code interop/verify-java-tokens.mjs}.
 */
class InteropJavaTokenWriterTest {

  private static final long LONG_TTL = 10L * 365 * 24 * 3600;

  @Test
  void mintsAndWritesTokensForTsVerification() throws Exception {
    KeyPair rootKeys = Keys.generate();
    OvidToken root =
        Ovid.createOvid(
            CreateOvidOptions.builder()
                .issuerKeys(rootKeys)
                .issuer("ovid4j-interop")
                .agentId("ovid4j-interop/root")
                .mandate(readMandate())
                .ttlSeconds(LONG_TTL)
                .build());
    OvidToken depth2 = spawn(root, "ovid4j-interop/root/child", LONG_TTL - 100);
    OvidToken depth3 = spawn(depth2, "ovid4j-interop/root/child/grandchild", LONG_TTL - 200);

    // Sanity: everything verifies locally before we hand it to the TS side.
    VerifyOvidOptions options = VerifyOvidOptions.of(rootKeys.getPublic());
    assertTrue(Ovid.verifyOvid(root.jwt(), options).valid());
    assertTrue(Ovid.verifyOvid(depth2.jwt(), options).valid());
    assertTrue(Ovid.verifyOvid(depth3.jwt(), options).valid());

    ObjectNode out = Json.MAPPER.createObjectNode();
    out.put("rootPublicKey", Keys.exportPublicKeyBase64(rootKeys.getPublic()));
    ObjectNode tokens = out.putObject("tokens");
    writeToken(tokens, "root", root);
    writeToken(tokens, "depth2", depth2);
    writeToken(tokens, "depth3", depth3);

    Path outFile = Path.of("target", "interop", "java-tokens.json");
    Files.createDirectories(outFile.getParent());
    Files.writeString(outFile, Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(out));
  }

  private static OvidToken spawn(OvidToken parent, String agentId, long ttlSeconds) {
    return Ovid.createOvid(
        CreateOvidOptions.builder()
            .issuerKeys(parent.keys())
            .issuerOvid(parent)
            .agentId(agentId)
            .mandate(readMandate())
            .ttlSeconds(ttlSeconds)
            .build());
  }

  private static void writeToken(ObjectNode tokens, String name, OvidToken token) {
    ObjectNode node = tokens.putObject(name);
    node.put("jwt", token.jwt());
    ArrayNode chain = node.putArray("chain");
    token.claims().authorizationDetails().getFirst().parentChain()
        .forEach(link -> chain.add(link.sub()));
  }
}
