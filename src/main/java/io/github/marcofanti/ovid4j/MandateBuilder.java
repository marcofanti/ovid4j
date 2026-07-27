// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.marcofanti.ovid4j;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Mandate builder — compile a structured intent into a Cedar policySet.
 *
 * <p>Authoring raw Cedar in a spawn task is error-prone; filling a constrained
 * form is not. Output is a policySet string that the OVID-ME fallback engine
 * and cedar-wasm both accept, so the same mandate is enforceable and provable.
 *
 * <p>Only emits the Cedar subset the OVID-ME fallback parser supports:
 * {@code permit/forbid(principal, action == Ovid::Action::"x" | action in [...], resource
 * [== Ovid::Kind::"id"]) [when { resource.path like "glob" }];} — no {@code unless},
 * no boolean operators, no {@code context.*}. Deny-by-default: an empty allow
 * list yields a policySet that grants nothing.
 */
public final class MandateBuilder {

  /**
   * Resource scoping for a grant.
   *
   * @param type Cedar entity kind; null for a bare action grant (resource wildcard)
   * @param in exact resource ids ({@code resource == Ovid::<Type>::"id"}); binary
   *     names for Shell, tool names for Tool, hostnames for WebEndpoint
   * @param pathLike path globs ({@code when { resource.path like "glob" }});
   *     meaningful for File/Memory; each glob becomes its own statement
   */
  public record ResourceConstraint(String type, List<String> in, List<String> pathLike) {
    public static ResourceConstraint ids(String type, String... ids) {
      return new ResourceConstraint(type, List.of(ids), null);
    }

    public static ResourceConstraint paths(String type, String... globs) {
      return new ResourceConstraint(type, null, List.of(globs));
    }
  }

  /**
   * One grant: one or more mandate verbs, optional resource scoping, and an
   * effect ({@code permit} default, or {@code forbid}).
   */
  public record GrantIntent(List<String> actions, ResourceConstraint resource, String effect) {
    public static GrantIntent of(String... actions) {
      return new GrantIntent(List.of(actions), null, null);
    }

    public static GrantIntent of(ResourceConstraint resource, String... actions) {
      return new GrantIntent(List.of(actions), resource, null);
    }
  }

  /**
   * The full intent: allows, forbids (always win, per Cedar), a TTL hint, and
   * an optional Cedar namespace (default {@code Ovid}).
   */
  public record MandateIntent(
      List<GrantIntent> allow, List<GrantIntent> forbid, Long ttlSeconds, String namespace) {
    public static MandateIntent empty() {
      return new MandateIntent(null, null, null, null);
    }
  }

  /** Compiled result: the policySet plus a human summary and non-fatal warnings. */
  public record BuildResult(
      String policySet, Long ttlSeconds, String summary, List<String> warnings) {}

  /** Tag block for spawn tasks plus the underlying build result. */
  public record TagResult(String tag, BuildResult result) {}

  private static final Pattern IDENT = Pattern.compile("^[A-Za-z0-9_.+@:-]+$");
  private static final Pattern UNSAFE_GLOB = Pattern.compile("[\"\\n\\r\\\\]");
  private static final Pattern NAMESPACE = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*$");

  /** Compile a structured intent into a Cedar policySet string + metadata. */
  public static BuildResult buildMandate(MandateIntent intent) {
    if (intent == null) {
      intent = MandateIntent.empty();
    }
    List<String> warnings = new ArrayList<>();
    String ns = intent.namespace() == null ? "Ovid" : intent.namespace();
    if (!NAMESPACE.matcher(ns).matches()) {
      throw new IllegalArgumentException("invalid Cedar namespace: \"" + ns + "\"");
    }

    List<GrantIntent> allow = intent.allow() == null ? List.of() : intent.allow();
    List<GrantIntent> forbid = intent.forbid() == null ? List.of() : intent.forbid();
    List<String> stmts = new ArrayList<>();

    if (allow.isEmpty() && forbid.isEmpty()) {
      stmts.add(
          "permit(principal, "
              + actionClause(ns, Vocabulary.DEFAULT_MANDATE_ACTIONS)
              + ", resource);");
      warnings.add("no intent supplied — emitted default read/search/summarize mandate");
    } else {
      for (GrantIntent g : allow) {
        stmts.addAll(emitGrant(ns, g, "permit", warnings));
      }
      for (GrantIntent g : forbid) {
        stmts.addAll(emitGrant(ns, g, "forbid", warnings));
      }
      if (stmts.isEmpty()) {
        // Everything was dropped/empty → deny-all. Cedar is default-deny
        // anyway, but an explicit forbid documents intent and satisfies validators.
        stmts.add(
            "forbid(principal, " + actionClause(ns, Vocabulary.MANDATE_ACTIONS) + ", resource);");
        warnings.add("all grants were empty or invalid — mandate grants nothing");
      }
    }

    return new BuildResult(
        String.join("\n", stmts), intent.ttlSeconds(), summarize(allow, forbid), warnings);
  }

  /**
   * Emit the spawn-task tag block that the openclaw-ovid hook parses:
   * {@code [OVID_TTL:n]} then {@code [OVID_MANDATE] ... [/OVID_MANDATE]},
   * ready to prepend to a spawn task string.
   */
  public static TagResult buildMandateTag(MandateIntent intent) {
    BuildResult result = buildMandate(intent);
    String ttlLine = result.ttlSeconds() != null ? "[OVID_TTL:" + result.ttlSeconds() + "]\n" : "";
    String tag = ttlLine + "[OVID_MANDATE]\n" + result.policySet() + "\n[/OVID_MANDATE]";
    return new TagResult(tag, result);
  }

  // ────────────────────────────────────────────────────────────────────────

  private static List<String> emitGrant(
      String ns, GrantIntent grant, String forcedEffect, List<String> warnings) {
    String effect = forcedEffect != null ? forcedEffect
        : grant.effect() != null ? grant.effect() : "permit";
    List<String> actions = new ArrayList<>();
    for (String a : grant.actions() == null ? List.<String>of() : grant.actions()) {
      if (Vocabulary.isMandateAction(a)) {
        actions.add(a);
      } else {
        warnings.add("dropped unknown action \"" + a + "\"");
      }
    }
    if (actions.isEmpty()) {
      return List.of();
    }

    String clause = actionClause(ns, actions);
    ResourceConstraint rc = grant.resource();
    boolean hasIds = rc != null && rc.in() != null && !rc.in().isEmpty();
    boolean hasGlobs = rc != null && rc.pathLike() != null && !rc.pathLike().isEmpty();

    if (rc == null || (!hasIds && !hasGlobs && rc.type() == null)) {
      return List.of(effect + "(principal, " + clause + ", resource);");
    }

    List<String> stmts = new ArrayList<>();
    if (hasIds) {
      String kind = rc.type() != null ? Vocabulary.ovidResourceKind(rc.type()) : "Tool";
      for (String id : rc.in()) {
        stmts.add(
            effect + "(principal, " + clause + ", resource == "
                + ns + "::" + kind + "::" + quoteId(id) + ");");
      }
    }
    if (hasGlobs) {
      for (String glob : rc.pathLike()) {
        stmts.add(
            effect + "(principal, " + clause + ", resource) when { resource.path like \""
                + sanitizeGlob(glob) + "\" };");
      }
    }
    if (rc.type() != null && !hasIds && !hasGlobs) {
      // Cedar can't express "any resource of type T" in the supported subset,
      // so fall back to a wildcard-resource grant and note it.
      warnings.add(
          "resource.type \"" + rc.type()
              + "\" with no ids/paths → wildcard resource (kind not enforced in fallback engine)");
      stmts.add(effect + "(principal, " + clause + ", resource);");
    }
    return stmts;
  }

  private static String actionClause(String ns, List<String> actions) {
    if (actions.size() == 1) {
      return "action == " + ns + "::Action::\"" + actions.getFirst() + "\"";
    }
    List<String> qualified = actions.stream().map(a -> ns + "::Action::\"" + a + "\"").toList();
    return "action in [" + String.join(", ", qualified) + "]";
  }

  private static String quoteId(String id) {
    if (!IDENT.matcher(id).matches()) {
      throw new IllegalArgumentException("unsafe resource id for Cedar literal: \"" + id + "\"");
    }
    return "\"" + id + "\"";
  }

  private static String sanitizeGlob(String glob) {
    if (UNSAFE_GLOB.matcher(glob).find()) {
      throw new IllegalArgumentException("unsafe path glob for Cedar literal: \"" + glob + "\"");
    }
    return glob;
  }

  private static String summarize(List<GrantIntent> allow, List<GrantIntent> forbid) {
    if (allow.isEmpty() && forbid.isEmpty()) {
      return "default: read, search, summarize";
    }
    List<String> parts = new ArrayList<>();
    for (GrantIntent g : allow) {
      parts.add(describeGrant("allow", g));
    }
    for (GrantIntent g : forbid) {
      parts.add(describeGrant("deny", g));
    }
    return String.join("; ", parts);
  }

  private static String describeGrant(String prefix, GrantIntent g) {
    String acts = String.join("/", g.actions() == null ? List.of() : g.actions());
    ResourceConstraint rc = g.resource();
    if (rc == null) {
      return prefix + " " + acts + " (any)";
    }
    if (rc.in() != null && !rc.in().isEmpty()) {
      String kind = rc.type() != null ? rc.type() : "Tool";
      return prefix + " " + acts + " " + kind + " [" + String.join(",", rc.in()) + "]";
    }
    if (rc.pathLike() != null && !rc.pathLike().isEmpty()) {
      return prefix + " " + acts + " path [" + String.join(",", rc.pathLike()) + "]";
    }
    if (rc.type() != null) {
      return prefix + " " + acts + " " + rc.type() + ":*";
    }
    return prefix + " " + acts;
  }

  private MandateBuilder() {}
}
