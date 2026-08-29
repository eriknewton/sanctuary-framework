export function flagValue(argv: string[], name: string): string | undefined {
  const prefix = `${name}=`;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === name) return argv[i + 1];
    if (arg.startsWith(prefix)) return arg.slice(prefix.length);
  }
  return undefined;
}

export interface ConsumedFlagValue {
  argv: string[];
  value?: string;
  error?: string;
}

export function consumeFlagValue(argv: string[], name: string): ConsumedFlagValue {
  const prefix = `${name}=`;
  const filtered: string[] = [];
  let value: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === name) {
      const next = argv[i + 1];
      // Reject ANY dash-leading next token, not just a `--`-prefixed one:
      // `--fortress -h` previously consumed `-h` (a short flag, not a path)
      // as the value, because only the `--` form was rejected. A value that
      // legitimately begins with `-` (a dash-leading directory name) stays
      // expressible via the unambiguous `--fortress=<path>` equals form,
      // which has no "is this the next flag?" question to answer.
      if (next === undefined || next.length === 0) {
        return { argv, error: `${name} requires a value` };
      }
      if (next.startsWith("-")) {
        // The refusal itself teaches the escape hatch, so a dash-leading
        // path is discoverable exactly where an operator first hits the
        // rejection, not only in a comment.
        return {
          argv,
          error: `${name} requires a value (for a value beginning with "-", use the ${name}=<value> form)`,
        };
      }
      if (value !== undefined) {
        return { argv, error: `${name} may only be provided once` };
      }
      value = next;
      i += 1;
      continue;
    }
    if (arg.startsWith(prefix)) {
      const next = arg.slice(prefix.length);
      if (next.length === 0) {
        return { argv, error: `${name} requires a value` };
      }
      if (value !== undefined) {
        return { argv, error: `${name} may only be provided once` };
      }
      value = next;
      continue;
    }
    filtered.push(arg);
  }

  return value === undefined ? { argv: filtered } : { argv: filtered, value };
}

/**
 * Usage-error exit code for a CLI invocation that never ran because argv
 * itself was malformed (as opposed to an operation that ran and failed).
 * Matches the "2 = usage error" convention already documented elsewhere in
 * this CLI (`audit-chain repair-plan --help`'s own exit-code table,
 * `audit-chain-repair-plan.ts`'s `REPAIR_PLAN_EXIT_USAGE`, and
 * `secrets.ts`'s `assertNoFortressFlag` comment: "2 is this command's
 * usage-error code ... 1 is reserved for an operation that ran and failed;
 * nothing ran here").
 *
 * IC-30 fix-round finding #4: before this constant existed, a
 * `consumeFlagValue` refusal for `--fortress` exited 1 in most migrated
 * verbs but 2 in `state-disclose.ts`, an inconsistency an operator (or a
 * script checking `$?`) could not rely on. Every migrated verb's fortress-
 * flag-parse refusal now returns this exit code.
 */
export const FORTRESS_FLAG_USAGE_EXIT_CODE = 2;

/**
 * Canonical rendering for a `consumeFlagValue` refusal on `--fortress` (or
 * a `--fortress`-family alias like `--storage`/`--fortress-path`): every
 * migrated verb prints exactly this shape for the SAME underlying error, so
 * what an operator sees does not depend on which file happens to implement
 * the verb they typed. IC-30 fix-round finding #4: before this helper
 * existed, the identical `consumeFlagValue` error rendered as `Error: ...`
 * in some verbs, `<verb>: ...` in others, a raw unprefixed message in
 * `restore-attest.ts`, and (for `audit-chain export`) fell through to the
 * top-level dispatcher's unrelated "Sanctuary MCP Server failed to start"
 * message. Callers append their own trailing newline when writing to a
 * `Writable` (this function does not, so it is also usable with
 * `console.error`, which appends its own).
 */
export function fortressFlagRefusalText(message: string): string {
  return `Error: ${message}`;
}

/**
 * Shared wording for "two aliases of the same flag were both given in one
 * invocation". IC-30 fix-round finding #3: a caller that resolves an alias
 * pair via `a.value ?? b.value` (as `restore-attest.ts`'s `--fortress`/
 * `--storage`, `audit-chain-export.ts`'s/`audit-chain-repair-plan.ts`'s/
 * `intelligence.ts`'s `--fortress`/`--fortress-path` all do) silently picks
 * whichever alias it happens to resolve second, regardless of which one the
 * operator actually meant or which order they typed them in, unless it
 * checks "both defined" FIRST and routes that case through this message
 * instead of letting `??` silently choose. Used by every migrated site with
 * this shape; `rotate-master.ts` and `reset-passphrase.ts` have the same
 * `--fortress`/`--storage` alias pair but are pre-existing, untouched by
 * this fix round, and do not call this helper -- noted here, not silently
 * left to look fixed by association.
 */
export function aliasConflictMessage(primary: string, alias: string): string {
  return `${primary} and ${alias} are aliases for the same value; provide at most one`;
}

/**
 * Repeatable counterpart of `consumeFlagValue`, with the SAME fail-closed
 * validation applied to EVERY occurrence: a caller must never let a
 * requested value silently vanish because the next token looked like a
 * flag, or land the wrong string because a bare `--` prefix consumed the
 * FOLLOWING flag as if it were this option's value. Each occurrence's value
 * must be present, non-blank (not empty, not whitespace-only), and, for the
 * bare-token form (`--name value`, as opposed to `--name=value`), not itself
 * `--`-prefixed -- the `=` form has no such ambiguity to guard against,
 * since the operator explicitly bound the value with `=`.
 */
export interface ConsumedFlagValues {
  argv: string[];
  values: string[];
  error?: string;
}

export function consumeFlagValues(argv: string[], name: string): ConsumedFlagValues {
  const prefix = `${name}=`;
  const filtered: string[] = [];
  const values: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === name) {
      const next = argv[i + 1];
      // NOT the same dash boundary as consumeFlagValue's IC-30 fix-round
      // widening (`-` vs `--`): no repeatable-flag caller currently needs a
      // dash-leading value, so this stays at its narrower original check
      // rather than being widened speculatively; widen it the same way if a
      // caller ever needs the stronger guarantee.
      if (next === undefined || next.trim().length === 0 || next.startsWith("--")) {
        return { argv, values: [], error: `${name} requires a value` };
      }
      values.push(next);
      i += 1;
      continue;
    }
    if (arg.startsWith(prefix)) {
      const next = arg.slice(prefix.length);
      if (next.trim().length === 0) {
        return { argv, values: [], error: `${name} requires a value` };
      }
      values.push(next);
      continue;
    }
    filtered.push(arg);
  }

  return { argv: filtered, values };
}

export function unknownFlagWithPrefix(
  argv: string[],
  name: string,
  allowedRelatedFlags: string[] = [],
): string | undefined {
  const knownFlags = [name, ...allowedRelatedFlags];
  const allowed = new Set(knownFlags);
  for (const arg of argv) {
    const flagName = flagNameFromToken(arg);
    if (flagName === undefined || allowed.has(flagName)) continue;
    if (flagName.startsWith(name)) return flagName;
    if (knownFlags.some((known) => isEditDistanceAtMostOne(flagName, known))) {
      return flagName;
    }
  }
  return undefined;
}

function flagNameFromToken(arg: string): string | undefined {
  if (!arg.startsWith("--") || arg === "--") return undefined;
  return arg.split("=", 1)[0];
}

function isEditDistanceAtMostOne(a: string, b: string): boolean {
  if (a === b) return true;
  const lengthDelta = Math.abs(a.length - b.length);
  if (lengthDelta > 1) return false;

  if (a.length === b.length) {
    let firstMismatch = -1;
    let mismatchCount = 0;
    for (let i = 0; i < a.length; i++) {
      if (a[i] === b[i]) continue;
      if (firstMismatch === -1) firstMismatch = i;
      mismatchCount += 1;
      if (mismatchCount > 2) return false;
    }
    if (mismatchCount === 1) return true;
    if (mismatchCount !== 2 || firstMismatch < 0 || firstMismatch + 1 >= a.length) {
      return false;
    }
    return (
      a[firstMismatch] === b[firstMismatch + 1] &&
      a[firstMismatch + 1] === b[firstMismatch] &&
      a.slice(firstMismatch + 2) === b.slice(firstMismatch + 2)
    );
  }

  const shorter = a.length < b.length ? a : b;
  const longer = a.length < b.length ? b : a;
  let skipped = false;
  for (let shortIndex = 0, longIndex = 0; longIndex < longer.length; longIndex++) {
    if (shorter[shortIndex] === longer[longIndex]) {
      shortIndex += 1;
      continue;
    }
    if (skipped) return false;
    skipped = true;
  }
  return true;
}

export function flagValues(argv: string[], name: string): string[] {
  const values: string[] = [];
  const prefix = `${name}=`;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === name) {
      if (argv[i + 1] !== undefined) values.push(argv[++i]!);
      continue;
    }
    if (arg.startsWith(prefix)) values.push(arg.slice(prefix.length));
  }
  return values;
}

export function hasFlag(argv: string[], name: string): boolean {
  const prefix = `${name}=`;
  return argv.some((arg) => arg === name || arg.startsWith(prefix));
}

/**
 * POSIX single-quote-with-escaping: wraps `value` in single quotes,
 * escaping any embedded single quote as `'\''` (close-quote, escaped
 * quote, reopen-quote) so the result is safe to paste as ONE argument
 * into a POSIX shell command line. Round-4 fix (independent gate on
 * #1304, P2): a suggested-command hint that interpolates an operator's
 * REAL fortress path unquoted breaks the moment that path contains a
 * space or a shell metacharacter (`/tmp/My Fortress` splits into two
 * arguments; the intended target is `<user>'s Fortress`, not the string
 * that follows it). NOT consolidated here with the near-identical
 * private `shellQuote` helpers already living in cli/deploy.ts and
 * cli/castle-wall.ts (pre-existing, out of scope for this fix) - a
 * future cleanup pass can fold all three into one shared export.
 */
export function shellQuoteSingleArg(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}
