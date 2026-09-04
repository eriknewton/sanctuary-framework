/**
 * Sanctuary MCP Server — Shared string normalization
 *
 * Small, dependency-free string helpers shared across modules that need
 * identical trimming behavior for operator-configured values (endpoints,
 * URLs, filesystem home paths). One implementation avoids the drift that a
 * hand-mirrored regex, copied file to file, invites (AGENTS.md rule 5: cross-
 * file registries and parsers are shared, checked for the whole set).
 */

/**
 * Strip every trailing "/" character from `value`.
 *
 * Implemented as a linear backward scan rather than the equivalent regex
 * (`/\/+$/`) because a `+` quantifier anchored at the end of the string can
 * be super-linear on adversarial input shaped as a long run of slashes
 * followed by a non-slash character (the trailing "$" never matches, so a
 * backtracking engine retries the "+" match at every starting position
 * before giving up); a single backward scan is O(n) regardless of how the
 * input is shaped.
 */
export function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === "/") {
    end -= 1;
  }
  return end === value.length ? value : value.slice(0, end);
}
