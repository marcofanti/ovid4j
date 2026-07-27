// ovid4j — Java port of OVID (https://github.com/clawdreyhepburn/ovid), Apache-2.0.
package io.github.mfanti.ovid4j;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Basic structural validation for Cedar policy text.
 * Not a full parser — catches obvious syntax issues.
 */
public final class CedarSyntax {

  /** Validation outcome; {@code error} is null when valid. */
  public record Result(boolean valid, String error) {
    static Result ok() {
      return new Result(true, null);
    }

    static Result fail(String error) {
      return new Result(false, error);
    }
  }

  private static final Pattern PERMIT = Pattern.compile("\\bpermit\\b");
  private static final Pattern FORBID = Pattern.compile("\\bforbid\\b");
  private static final Pattern STATEMENT = Pattern.compile("\\b(permit|forbid)\\s*\\(");
  private static final Pattern NEXT_STATEMENT = Pattern.compile("^(permit|forbid)\\b");

  public static Result validateCedarSyntax(String policySet) {
    String trimmed = policySet.trim();

    if (trimmed.isEmpty()) {
      return Result.fail("Policy set is empty");
    }

    if (!PERMIT.matcher(trimmed).find() && !FORBID.matcher(trimmed).find()) {
      return Result.fail("Policy must contain at least one \"permit\" or \"forbid\" statement");
    }

    boolean inSingleQuote = false;
    boolean inDoubleQuote = false;
    int parenDepth = 0;

    for (int i = 0; i < trimmed.length(); i++) {
      char ch = trimmed.charAt(i);
      char prev = i > 0 ? trimmed.charAt(i - 1) : '\0';

      if (ch == '"' && !inSingleQuote && prev != '\\') {
        inDoubleQuote = !inDoubleQuote;
      } else if (ch == '\'' && !inDoubleQuote && prev != '\\') {
        inSingleQuote = !inSingleQuote;
      } else if (!inSingleQuote && !inDoubleQuote) {
        if (ch == '(') {
          parenDepth++;
        } else if (ch == ')') {
          parenDepth--;
          if (parenDepth < 0) {
            return Result.fail("Unmatched closing parenthesis");
          }
        }
      }
    }

    if (inSingleQuote || inDoubleQuote) {
      return Result.fail("Unmatched quote in policy text");
    }
    if (parenDepth != 0) {
      return Result.fail("Unmatched opening parenthesis");
    }

    // Each permit/forbid block must end with a semicolon.
    Matcher statement = STATEMENT.matcher(trimmed);
    while (statement.find()) {
      int endIdx = closingParenIndex(trimmed, statement.start());
      if (!semicolonFollows(trimmed, endIdx)) {
        return Result.fail("Statement missing terminating semicolon");
      }
    }

    return Result.ok();
  }

  private static int closingParenIndex(String text, int from) {
    int depth = 0;
    boolean foundOpen = false;
    for (int i = from; i < text.length(); i++) {
      char c = text.charAt(i);
      if (c == '(') {
        depth++;
        foundOpen = true;
      } else if (c == ')') {
        depth--;
        if (depth == 0 && foundOpen) {
          return i;
        }
      }
    }
    return from;
  }

  private static boolean semicolonFollows(String text, int closeParenIdx) {
    // Skip optional whitespace/braces/conditions; must eventually hit a
    // semicolon before the next top-level permit/forbid.
    int braceDepth = 0;
    for (int i = closeParenIdx + 1; i < text.length(); i++) {
      char c = text.charAt(i);
      if (c == '{') {
        braceDepth++;
      } else if (c == '}') {
        braceDepth--;
      } else if (c == ';' && braceDepth == 0) {
        return true;
      }
      int sliceEnd = Math.min(i + 7, text.length());
      if (braceDepth == 0 && NEXT_STATEMENT.matcher(text.substring(i, sliceEnd)).find()) {
        return false;
      }
    }
    return false;
  }

  private CedarSyntax() {}
}
