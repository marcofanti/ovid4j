// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line bridge so non-JVM callers (shell, Python, anything that can run
 * a subprocess) can mint and verify OVID tokens with this library.
 *
 * <p>Usage: {@code java -jar ovid4j-cli.jar <keygen|create|verify|cedar>} —
 * each subcommand reads one JSON object from stdin ({@code keygen} ignores
 * stdin) and writes one JSON object to stdout. Errors are reported as
 * {@code {"error": "..."}} with exit code 1; {@code verify} reports a failing
 * token as {@code {"valid": false}} with exit code 0, mirroring
 * {@link Ovid#verifyOvid} never throwing.
 */
public final class OvidCli {

  public static void main(String[] args) {
    System.exit(run(args, System.in, System.out));
  }

  static int run(String[] args, InputStream in, PrintStream out) {
    try {
      String command = args.length == 1 ? args[0] : "";
      JsonNode input = readInput(command, in);
      ObjectNode output =
          switch (command) {
            case "keygen" -> keygen();
            case "create" -> create(input);
            case "verify" -> verify(input);
            case "cedar" -> cedar(input);
            default -> throw new IllegalArgumentException(
                "usage: ovid4j-cli <keygen|create|verify|cedar> (JSON on stdin)");
          };
      out.println(Json.MAPPER.writeValueAsString(output));
      return 0;
    } catch (RuntimeException | IOException e) {
      ObjectNode error = Json.MAPPER.createObjectNode();
      error.put("error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
      try {
        out.println(Json.MAPPER.writeValueAsString(error));
      } catch (IOException unreachable) {
        throw new IllegalStateException(unreachable);
      }
      return 1;
    }
  }

  private static JsonNode readInput(String command, InputStream in) throws IOException {
    if ("keygen".equals(command)) {
      return Json.MAPPER.createObjectNode();
    }
    String body = new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
    if (body.isEmpty()) {
      throw new IllegalArgumentException(command + " requires a JSON object on stdin");
    }
    JsonNode node = Json.MAPPER.readTree(body);
    if (!node.isObject()) {
      throw new IllegalArgumentException(command + " stdin must be a JSON object");
    }
    return node;
  }

  private static ObjectNode keygen() {
    KeyPair keys = Keys.generate();
    ObjectNode output = Json.MAPPER.createObjectNode();
    output.put("publicKey", Keys.exportPublicKeyBase64(keys.getPublic()));
    output.put("privateKey", Keys.exportPrivateKeyBase64(keys.getPrivate()));
    return output;
  }

  private static ObjectNode create(JsonNode input) throws IOException {
    String name = requiredText(input, "name");
    String policySet = requiredText(input, "policySet");

    CreateOvidOptions.Builder options =
        CreateOvidOptions.builder()
            .mandate(AuthorizationDetail.agentMandate(policySet))
            .agentId(name);
    if (input.hasNonNull("ttlSeconds")) {
      options.ttlSeconds(input.get("ttlSeconds").asLong());
    }

    JsonNode parent = input.get("parent");
    if (parent != null && !parent.isNull()) {
      OvidToken parentToken = parentToken(parent);
      options.issuerOvid(parentToken).issuerKeys(parentToken.keys());
    } else {
      KeyPair issuerKeys =
          input.hasNonNull("keys")
              ? Keys.importKeyPairBase64(
                  requiredText(input.get("keys"), "publicKey"),
                  requiredText(input.get("keys"), "privateKey"))
              : Keys.generate();
      options.issuerKeys(issuerKeys).issuer(name);
    }

    OvidToken token = Ovid.createOvid(options.build());
    ObjectNode output = Json.MAPPER.createObjectNode();
    output.put("jwt", token.jwt());
    output.put("sub", token.claims().sub());
    output.put("exp", token.claims().exp());
    output.put("publicKey", Keys.exportPublicKeyBase64(token.keys().getPublic()));
    output.put("privateKey", Keys.exportPrivateKeyBase64(token.keys().getPrivate()));
    return output;
  }

  /** Rebuild the parent {@link OvidToken} from its wire JWT plus its keypair. */
  private static OvidToken parentToken(JsonNode parent) throws IOException {
    String jwt = requiredText(parent, "jwt");
    KeyPair keys =
        Keys.importKeyPairBase64(
            requiredText(parent, "publicKey"), requiredText(parent, "privateKey"));
    OvidClaims claims =
        Json.MAPPER.treeToValue(
            Json.MAPPER.readTree(CompactJws.parse(jwt).payloadJson()), OvidClaims.class);
    return new OvidToken(jwt, claims, keys);
  }

  private static ObjectNode verify(JsonNode input) {
    String jwt = requiredText(input, "jwt");
    JsonNode rootsNode = input.get("trustedRoots");
    if (rootsNode == null || !rootsNode.isArray() || rootsNode.isEmpty()) {
      throw new IllegalArgumentException("verify requires a non-empty trustedRoots array");
    }
    List<PublicKey> roots = new ArrayList<>();
    for (JsonNode root : rootsNode) {
      roots.add(Keys.importPublicKeyBase64(root.asText()));
    }
    Integer maxChainDepth =
        input.hasNonNull("maxChainDepth") ? input.get("maxChainDepth").asInt() : null;

    OvidResult result = Ovid.verifyOvid(jwt, new VerifyOvidOptions(roots, maxChainDepth));
    ObjectNode output = Json.MAPPER.createObjectNode();
    output.put("valid", result.valid());
    if (!result.valid()) {
      return output;
    }
    output.put("principal", result.principal());
    output.put("expiresIn", result.expiresIn());
    output.put("policySet", result.mandate().policySet());
    ArrayNode chain = output.putArray("chain");
    result.chain().forEach(chain::add);
    return output;
  }

  private static ObjectNode cedar(JsonNode input) {
    CedarSyntax.Result result = CedarSyntax.validateCedarSyntax(requiredText(input, "policySet"));
    ObjectNode output = Json.MAPPER.createObjectNode();
    output.put("valid", result.valid());
    if (!result.valid()) {
      output.put("error", result.error());
    }
    return output;
  }

  private static String requiredText(JsonNode node, String field) {
    JsonNode value = node == null ? null : node.get(field);
    if (value == null || !value.isTextual() || value.asText().isEmpty()) {
      throw new IllegalArgumentException("missing required string field \"" + field + "\"");
    }
    return value.asText();
  }

  private OvidCli() {}
}
