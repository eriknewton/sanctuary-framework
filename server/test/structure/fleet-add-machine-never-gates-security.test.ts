/**
 * Fleet control plane, Add-Machine slice: the "never gates security" source
 * invariant (build spec section 4 + section 6 item 5).
 *
 * The capacity pre-check on `POST /api/fleet/enroll-token` (and the read on
 * `GET /api/fleet/capacity`) is advisory MANAGEMENT-CAPACITY UX, not
 * enforcement. The real node-count enforcement is the already-shipped
 * `applyFleetCap` on the CENTRAL roster, unchanged by this slice. This is a
 * grep-style structural guard (cheap insurance, per the build spec) that the
 * new handler bodies and the new pure capacity module reference NO
 * wall/enforcement/local-dashboard/policy-push/kill-safety symbol - so a bug
 * in this slice can only ever over-block enrollment (fail-closed), never
 * touch a node's Castle Wall, its local dashboard, kill safety, or free
 * policy-push.
 *
 * Scope: the pure `fleet-capacity.ts` module (whole file, it has no other
 * responsibility) plus the THREE new handler/helper bodies inside
 * `dashboard.ts` (`computeFleetCapacity`, `handleFleetCapacity`,
 * `handleFleetEnrollToken`), extracted by source text between their `private`
 * declaration and the next `private`/closing-brace boundary at the same
 * indent. Extracting just these bodies (not the whole 6000+ line file, which
 * legitimately imports castle-wall/guardian symbols for OTHER routes) keeps
 * the guard meaningful rather than trivially green or trivially red.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";

const SERVER_ROOT = path.resolve(__dirname, "../..");

/** Forbidden symbol substrings: wall / enforcement / local-dashboard / policy-push / kill-safety. */
const FORBIDDEN_PATTERNS: RegExp[] = [
  /castle-?wall/i,
  /CastleWall/,
  /policy-?push/i,
  /policyPush/i,
  /kill-?safety/i,
  /killSafety/i,
  /guardian/i,
  /applyFleetCap/, // the enforcement gate itself: never re-invoked by this slice
  /enforcementDep/i,
  /localDashboard/i,
  /local-dashboard/i,
];

/**
 * Extract a named method's SOURCE TEXT from `dashboard.ts` by locating its
 * `private ... methodName(` declaration and scanning forward to the matching
 * closing brace (simple brace-depth counter; adequate for well-formed TS).
 */
function extractMethodBody(source: string, methodName: string): string {
  const declPattern = new RegExp(
    `private\\s+(?:async\\s+)?${methodName}\\s*\\(`,
  );
  const match = declPattern.exec(source);
  if (!match) {
    throw new Error(`Could not locate method '${methodName}' in dashboard.ts`);
  }
  const startIdx = match.index;
  // Find the opening brace of the method body (first `{` after the match).
  let braceStart = source.indexOf("{", startIdx);
  if (braceStart === -1) {
    throw new Error(`Could not locate opening brace for '${methodName}'`);
  }
  let depth = 0;
  let i = braceStart;
  for (; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) break;
    }
  }
  if (depth !== 0) {
    throw new Error(`Unbalanced braces while extracting '${methodName}'`);
  }
  return source.slice(startIdx, i + 1);
}

describe("Add-Machine slice never gates security (source invariant)", () => {
  it("fleet-capacity.ts (the pure capacity view) references no wall/enforcement/policy-push/kill-safety symbol", () => {
    const source = readFileSync(
      path.join(SERVER_ROOT, "src/entitlement/fleet-capacity.ts"),
      "utf8",
    );
    // Strip the module doc-comment's OWN prose, which legitimately NAMES these
    // concepts to explain what the module is NOT (e.g. "never touches a wall /
    // enforcement ... path"). The invariant is about CODE REFERENCES (imports,
    // calls, identifiers), not about the module being forbidden from
    // discussing the boundary in English. Strip all block/line comments
    // before scanning, mirroring the em-dash guard's code-only scan.
    const codeOnly = source
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/.*$/gm, "$1");
    const hits = FORBIDDEN_PATTERNS.filter((re) => re.test(codeOnly));
    expect(hits).toEqual([]);
  });

  it("handleFleetCapacity + computeFleetCapacity reference no wall/enforcement/policy-push/kill-safety symbol", () => {
    const source = readFileSync(
      path.join(SERVER_ROOT, "src/principal-policy/dashboard.ts"),
      "utf8",
    );
    for (const method of ["computeFleetCapacity", "handleFleetCapacity"]) {
      const body = extractMethodBody(source, method);
      const codeOnly = body
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/(^|[^:])\/\/.*$/gm, "$1");
      const hits = FORBIDDEN_PATTERNS.filter((re) => re.test(codeOnly));
      expect({ method, hits }).toEqual({ method, hits: [] });
    }
  });

  it("handleFleetEnrollToken references no wall/enforcement/policy-push/kill-safety symbol", () => {
    const source = readFileSync(
      path.join(SERVER_ROOT, "src/principal-policy/dashboard.ts"),
      "utf8",
    );
    const body = extractMethodBody(source, "handleFleetEnrollToken");
    const codeOnly = body
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/.*$/gm, "$1");
    const hits = FORBIDDEN_PATTERNS.filter((re) => re.test(codeOnly));
    expect(hits).toEqual([]);
  });

  it("the enroll-token route arm's auth gate is the SAME requireToken pattern as /api/fleet/activate (source proof, not re-implemented)", () => {
    const source = readFileSync(
      path.join(SERVER_ROOT, "src/principal-policy/dashboard.ts"),
      "utf8",
    );
    // The route arm must call checkAuth with requireToken:true before
    // dispatching to the handler - assert the two are textually adjacent in
    // the route table (a cheap proxy for "auth precedes mutation").
    const armPattern =
      /url\.pathname === "\/api\/fleet\/enroll-token"[\s\S]{0,1200}?checkAuth\(req, url, res, \{ requireToken: true \}\)[\s\S]{0,200}?handleFleetEnrollToken\(req, res\)/;
    expect(armPattern.test(source)).toBe(true);
  });
});
