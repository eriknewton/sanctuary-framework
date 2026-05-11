/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-1 Trap Registry.
 *
 * Per-fortress in-memory registry of deployed honeypot traps. Holds
 * the live TrapSpec set + provides path-matching for the runtime
 * dispatcher.
 *
 * Lifecycle:
 *   deploy(spec):         activates the trap; idempotent on trap_id.
 *   undeploy(trapId):     removes the trap; returns whether anything
 *                         was actually removed (idempotent).
 *   list():               returns the live trap set as a fresh array.
 *   findMatching(path,m): returns the first trap matching the request.
 *
 * Castle-walking discipline:
 *   - Read-only path against deployed traps; mutating calls land here
 *     deliberately from the management routes.
 *   - No outbound surface; the registry is purely server-local state.
 *   - Per-fortress isolation: one registry instance per fortress. The
 *     dispatcher wires one registry per dashboard instance.
 *
 * Path-matching glob:
 *   *   matches one path segment (no slashes)
 *   **  matches multiple path segments (zero or more, including
 *       slashes)
 *   anything else is a literal character. The pattern is anchored at
 *   both ends so `/admin` does NOT match `/admin/foo`; the operator
 *   must use `/admin/**` to match prefix-style.
 */

import type { TrapSpec } from "./types.js";

export interface TrapMatchInput {
  /** Request URL path. */
  path: string;
  /** Uppercased HTTP method. */
  method: string;
}

export class TrapRegistry {
  private readonly traps = new Map<string, TrapSpec>();

  /**
   * Deploy a trap. Idempotent on `trap_id`: re-deploying replaces the
   * previous spec for that id. Returns true on first deploy, false on
   * re-deploy (so callers can branch audit emission).
   */
  deploy(spec: TrapSpec): boolean {
    const isNew = !this.traps.has(spec.trap_id);
    this.traps.set(spec.trap_id, spec);
    return isNew;
  }

  /**
   * Undeploy by trap_id. Returns true when a trap was removed, false
   * when no trap had that id (idempotent).
   */
  undeploy(trapId: string): boolean {
    return this.traps.delete(trapId);
  }

  /** List deployed traps. Returns a fresh array; mutation is safe. */
  list(): TrapSpec[] {
    return [...this.traps.values()];
  }

  /** Look up a single trap by id. */
  get(trapId: string): TrapSpec | undefined {
    return this.traps.get(trapId);
  }

  /**
   * Find the first trap matching the request. Iteration order is
   * insertion order; operators who deploy multiple overlapping traps
   * see the earliest-deployed one fire. Tests cover this contract.
   */
  findMatching(input: TrapMatchInput): TrapSpec | undefined {
    for (const spec of this.traps.values()) {
      if (matchesTrap(spec, input)) return spec;
    }
    return undefined;
  }

  /** Drop every trap. Tests use this between runs; not surfaced via API. */
  clear(): void {
    this.traps.clear();
  }
}

/**
 * Returns true when `input` matches the trap's `trigger`. Exposed for
 * tests + the runtime path; the registry uses it internally.
 */
export function matchesTrap(spec: TrapSpec, input: TrapMatchInput): boolean {
  if (spec.trap_class !== "http_endpoint") return false;
  const trigger = spec.trigger;
  if (trigger.method && trigger.method.toUpperCase() !== input.method.toUpperCase()) {
    return false;
  }
  const re = compileGlob(trigger.path_pattern);
  return re.test(input.path);
}

/**
 * Compile a glob pattern to an anchored RegExp. Exposed for tests so
 * the path-matching contract is testable without standing up a full
 * runtime trap.
 *
 *   *  -> [^/]*    (one segment)
 *   ** -> .*       (multiple segments)
 *
 * Regex special characters in the pattern are escaped; only `*` and
 * `**` retain their glob semantics.
 */
export function compileGlob(pattern: string): RegExp {
  // Token-walk to handle `**` before `*` so the doubled form does not
  // get rewritten as two single-stars.
  let out = "";
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i]!;
    if (ch === "*" && pattern[i + 1] === "*") {
      out += ".*";
      i += 2;
      continue;
    }
    if (ch === "*") {
      out += "[^/]*";
      i += 1;
      continue;
    }
    // Escape regex metacharacters.
    if ("\\^$.|?+()[]{}".includes(ch)) {
      out += `\\${ch}`;
    } else {
      out += ch;
    }
    i += 1;
  }
  return new RegExp(`^${out}$`);
}
