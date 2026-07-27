// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import org.junit.jupiter.api.Test;

/** The subprocess contract of {@link OvidCli}: JSON in, JSON out, exit codes. */
class OvidCliTest {

  private static final String POLICY = TestSupport.READ_POLICY;

  private record CliRun(int exitCode, JsonNode output) {}

  private static CliRun cli(String command, String stdinJson) {
    ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    int exitCode =
        OvidCli.run(
            new String[] {command},
            new ByteArrayInputStream(stdinJson.getBytes(StandardCharsets.UTF_8)),
            new PrintStream(stdout, true, StandardCharsets.UTF_8));
    try {
      return new CliRun(exitCode, Json.MAPPER.readTree(stdout.toString(StandardCharsets.UTF_8)));
    } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
      throw new IllegalStateException("CLI wrote non-JSON output: " + stdout, e);
    }
  }

  private static JsonNode ok(String command, String stdinJson) {
    CliRun run = cli(command, stdinJson);
    assertEquals(0, run.exitCode(), () -> "CLI failed: " + run.output());
    return run.output();
  }

  // ── keygen ──────────────────────────────────────────────────────────────

  @Test
  void keygenEmitsImportableKeypair() {
    JsonNode keys = ok("keygen", "");
    KeyPair imported =
        Keys.importKeyPairBase64(keys.get("publicKey").asText(), keys.get("privateKey").asText());
    assertEquals(keys.get("publicKey").asText(), Keys.exportPublicKeyBase64(imported.getPublic()));
  }

  @Test
  void privateKeySeedRoundTripsThroughExportAndSignsVerifiably() throws Exception {
    KeyPair original = Keys.generate();
    String seed = Keys.exportPrivateKeyBase64(original.getPrivate());
    byte[] message = "ovid4j seed round-trip".getBytes(StandardCharsets.UTF_8);

    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(Keys.importPrivateKeyBase64(seed));
    signer.update(message);
    byte[] sig = signer.sign();

    Signature verifier = Signature.getInstance("Ed25519");
    verifier.initVerify(original.getPublic());
    verifier.update(message);
    assertTrue(verifier.verify(sig));
  }

  @Test
  void privateKeyImportRejectsWrongLength() {
    assertThrows(IllegalArgumentException.class, () -> Keys.importPrivateKeyBase64("AAAA"));
  }

  // ── create + verify ─────────────────────────────────────────────────────

  @Test
  void createdRootVerifiesAgainstItsOwnPublicKey() throws Exception {
    JsonNode keys = ok("keygen", "");
    JsonNode created =
        ok(
            "create",
            Json.MAPPER.writeValueAsString(
                Json.MAPPER
                    .createObjectNode()
                    .put("name", "cli-test/root")
                    .put("policySet", POLICY)
                    .set("keys", keys.deepCopy())));
    assertEquals("cli-test/root", created.get("sub").asText());
    assertEquals(keys.get("publicKey").asText(), created.get("publicKey").asText());

    JsonNode verified = verify(created.get("jwt").asText(), keys.get("publicKey").asText());
    assertTrue(verified.get("valid").asBoolean());
    assertEquals("cli-test/root", verified.get("principal").asText());
    assertEquals(POLICY, verified.get("policySet").asText());
    assertEquals(1, verified.get("chain").size());
  }

  @Test
  void createWithoutKeysGeneratesThem() throws Exception {
    JsonNode created =
        ok(
            "create",
            Json.MAPPER.writeValueAsString(
                Json.MAPPER
                    .createObjectNode()
                    .put("name", "cli-test/fresh")
                    .put("policySet", POLICY)));
    JsonNode verified = verify(created.get("jwt").asText(), created.get("publicKey").asText());
    assertTrue(verified.get("valid").asBoolean());
  }

  @Test
  void childMintedUnderParentCarriesTwoLinkChain() throws Exception {
    JsonNode keys = ok("keygen", "");
    JsonNode root =
        ok(
            "create",
            Json.MAPPER.writeValueAsString(
                Json.MAPPER
                    .createObjectNode()
                    .put("name", "cli-test/root")
                    .put("policySet", POLICY)
                    .set("keys", keys.deepCopy())));
    JsonNode child =
        ok(
            "create",
            Json.MAPPER.writeValueAsString(
                Json.MAPPER
                    .createObjectNode()
                    .put("name", "cli-test/root/child")
                    .put("policySet", POLICY)
                    .set(
                        "parent",
                        Json.MAPPER
                            .createObjectNode()
                            .put("jwt", root.get("jwt").asText())
                            .put("publicKey", root.get("publicKey").asText())
                            .put("privateKey", root.get("privateKey").asText()))));

    // Child binds a fresh keypair; the chain still anchors at the root key.
    assertNotEquals(root.get("publicKey").asText(), child.get("publicKey").asText());
    JsonNode verified = verify(child.get("jwt").asText(), keys.get("publicKey").asText());
    assertTrue(verified.get("valid").asBoolean());
    assertEquals("cli-test/root/child", verified.get("principal").asText());
    assertEquals(2, verified.get("chain").size());
    assertEquals("cli-test/root", verified.get("chain").get(0).asText());
  }

  @Test
  void verifyRejectsForeignRoot() throws Exception {
    JsonNode created =
        ok(
            "create",
            Json.MAPPER.writeValueAsString(
                Json.MAPPER
                    .createObjectNode()
                    .put("name", "cli-test/root")
                    .put("policySet", POLICY)));
    JsonNode foreign = ok("keygen", "");
    JsonNode verified = verify(created.get("jwt").asText(), foreign.get("publicKey").asText());
    assertFalse(verified.get("valid").asBoolean());
  }

  private static JsonNode verify(String jwt, String trustedRoot) throws Exception {
    var request = Json.MAPPER.createObjectNode().put("jwt", jwt);
    request.putArray("trustedRoots").add(trustedRoot);
    return ok("verify", Json.MAPPER.writeValueAsString(request));
  }

  // ── cedar ───────────────────────────────────────────────────────────────

  @Test
  void cedarAcceptsValidAndRejectsInvalidPolicy() {
    assertTrue(ok("cedar", "{\"policySet\": \"" + POLICY.replace("\"", "\\\"") + "\"}")
        .get("valid").asBoolean());
    CliRun bad = cli("cedar", "{\"policySet\": \"permit(principal\"}");
    assertEquals(0, bad.exitCode());
    assertFalse(bad.output().get("valid").asBoolean());
    assertTrue(bad.output().has("error"));
  }

  // ── error contract ──────────────────────────────────────────────────────

  @Test
  void missingFieldReportsJsonErrorAndExitCodeOne() {
    CliRun run = cli("create", "{\"policySet\": \"x\"}");
    assertEquals(1, run.exitCode());
    assertTrue(run.output().get("error").asText().contains("name"));
  }

  @Test
  void unknownCommandFailsWithUsage() {
    CliRun run = cli("frobnicate", "{}");
    assertEquals(1, run.exitCode());
    assertTrue(run.output().get("error").asText().contains("usage"));
  }
}
