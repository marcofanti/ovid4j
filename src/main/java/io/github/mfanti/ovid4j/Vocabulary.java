// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import java.util.List;
import java.util.Map;

/**
 * Shared authorization vocabulary for the OVID stack.
 *
 * <p>One conceptual model, two projections: {@code Ovid::*} for per-agent
 * mandates, {@code Jans::*} for the Carapace deployment ceiling. This is NOT
 * RBAC — no roles or profiles, only actions plus resource constraints that
 * compile to Cedar.
 */
public final class Vocabulary {

  /** Agent-facing mandate verbs ({@code Ovid::Action}). */
  public static final List<String> MANDATE_ACTIONS =
      List.of(
          "read", "write", "edit", "exec", "fetch", "search", "browse", "send", "delegate",
          "remember", "recall", "call_tool", "summarize");

  /** Resource kinds addressable in a mandate. {@code API} normalizes to {@code WebEndpoint}. */
  public static final List<String> RESOURCE_KINDS =
      List.of("File", "Shell", "Tool", "WebEndpoint", "Channel", "Memory", "Session", "API");

  /** Default safe mandate when no intent is supplied. */
  public static final List<String> DEFAULT_MANDATE_ACTIONS = List.of("read", "search", "summarize");

  /**
   * Projection from an Ovid mandate action to the Carapace (Jans) action and
   * resource kind. Actions absent from {@link #OVID_TO_JANS} have no direct
   * deployment-ceiling equivalent (OVID-only verbs).
   */
  public record JansProjection(String action, String resourceKind) {}

  public static final Map<String, JansProjection> OVID_TO_JANS =
      Map.of(
          "exec", new JansProjection("exec_command", "Shell"),
          "fetch", new JansProjection("call_api", "API"),
          "search", new JansProjection("call_api", "API"),
          "browse", new JansProjection("call_api", "API"),
          "call_tool", new JansProjection("call_tool", "Tool"),
          "read", new JansProjection("call_tool", "Tool"),
          "write", new JansProjection("call_tool", "Tool"),
          "edit", new JansProjection("call_tool", "Tool"));

  /** OpenClaw built-in tool name → default Ovid action (plugin mapper source). */
  public static final Map<String, String> OPENCLAW_TOOL_TO_ACTION =
      Map.ofEntries(
          Map.entry("read", "read"),
          Map.entry("write", "write"),
          Map.entry("edit", "edit"),
          Map.entry("exec", "exec"),
          Map.entry("process", "exec"),
          Map.entry("web_fetch", "fetch"),
          Map.entry("web_search", "search"),
          Map.entry("browser", "browse"),
          Map.entry("message", "send"),
          Map.entry("sessions_spawn", "delegate"),
          Map.entry("memory_search", "recall"),
          Map.entry("memory_get", "recall"),
          Map.entry("tts", "call_tool"),
          Map.entry("image", "read"),
          Map.entry("pdf", "read"),
          Map.entry("image_generate", "call_tool"),
          Map.entry("video_generate", "call_tool"));

  public static boolean isMandateAction(String x) {
    return x != null && MANDATE_ACTIONS.contains(x);
  }

  public static boolean isResourceKind(String x) {
    return x != null && RESOURCE_KINDS.contains(x);
  }

  /** Normalize {@code API} → {@code WebEndpoint} for Ovid entity typing. */
  public static String ovidResourceKind(String kind) {
    return "API".equals(kind) ? "WebEndpoint" : kind;
  }

  /** Normalize {@code WebEndpoint} → {@code API} for Jans entity typing. */
  public static String jansResourceKind(String kind) {
    return "WebEndpoint".equals(kind) ? "API" : kind;
  }

  private Vocabulary() {}
}
