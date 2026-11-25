/**
 * state_RUNTIME: the Node runtime must satisfy the engine range of the pinned
 * Sigstore packages BEFORE any of them is imported. Outside that range their
 * behavior is not what their maintainers test, so a verification result from
 * them would not be evidence; the verb refuses instead of running them.
 */

/**
 * Must match `engines.node` of the exact-pinned `@sigstore/verify`,
 * `@sigstore/bundle` and `@sigstore/core` in server/package.json (all three
 * declare the same range). Pinned by test/verify-release/runtime.test.ts, which
 * reads the installed packages' package.json files.
 */
export const SIGSTORE_ENGINE_RANGE = "^22.22.2 || ^24.15.0 || >=26.0.0";

interface Version { major: number; minor: number; patch: number }
type Comparator = { op: "^" | ">="; version: Version };

const STRICT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function parseVersion(text: string): Version | null {
  const match = STRICT_VERSION.exec(text);
  if (match === null) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

function compare(a: Version, b: Version): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch;
}

/**
 * Parse the small range grammar the pinned packages use: comparators joined by
 * `||`, each `^X.Y.Z` or `>=X.Y.Z`. Anything else throws, so a future range in
 * another shape fails the build-time pin test instead of being misread.
 */
export function parseEngineRange(range: string): Comparator[] {
  return range.split("||").map(part => {
    const token = part.trim();
    const op = token.startsWith(">=") ? ">=" : token.startsWith("^") ? "^" : null;
    const version = op === null ? null : parseVersion(token.slice(op.length));
    if (op === null || version === null) throw new Error(`unsupported engine range comparator: ${token}`);
    return { op, version };
  });
}

/**
 * True iff `nodeVersion` (as `process.versions.node`, no leading `v`) satisfies
 * `range`. `^X.Y.Z` with X > 0 means >= X.Y.Z and < (X+1).0.0. A version that is
 * not exactly X.Y.Z, such as a prerelease build, does not satisfy.
 */
export function satisfiesEngineRange(nodeVersion: string, range: string = SIGSTORE_ENGINE_RANGE): boolean {
  const version = parseVersion(nodeVersion);
  if (version === null) return false;
  return parseEngineRange(range).some(({ op, version: floor }) => {
    if (compare(version, floor) < 0) return false;
    if (op === ">=") return true;
    // The caret ceiling is the next major; the pinned ranges have no 0.x caret.
    return version.major === floor.major;
  });
}
