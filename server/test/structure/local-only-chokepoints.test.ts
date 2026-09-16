/**
 * Request-scoped local-only structural chokepoints (2026-09-15 slice).
 *
 * Mirrors `test/structure/q5e-selector-chokepoints.test.ts`'s technique:
 * assert code SHAPE via source-text ordering rather than only behavior, so a
 * future edit that reorders these checks (and thereby lets a hosted client
 * get constructed before the local-only guard runs) fails a test even if no
 * behavioral test happens to exercise that exact ordering.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const srcRoot = join(here, "..", "..", "src");

describe("local-only request-scoped constraint — structural chokepoints", () => {
  it("invoke() refuses a conflicting local-only request BEFORE getOrIssueHandle is ever called", async () => {
    const selector = await readFile(join(srcRoot, "intelligence", "selector.ts"), "utf8");
    const invokeStart = selector.indexOf("private async invoke(");
    const invokeEnd = selector.indexOf("private recordRecentFailure(", invokeStart);
    expect(invokeStart).toBeGreaterThan(0);
    expect(invokeEnd).toBeGreaterThan(invokeStart);
    const body = selector.slice(invokeStart, invokeEnd);

    const localOnlyCheck = body.indexOf("requestLocalOnly && resolvedChoice !== \"local\"");
    const handleConstruction = body.indexOf("const handle = await this.getOrIssueHandle(surface, choice");
    expect(localOnlyCheck).toBeGreaterThan(0);
    expect(handleConstruction).toBeGreaterThan(0);
    expect(localOnlyCheck).toBeLessThan(handleConstruction);
  });

  it("the local-only refusal branch returns before touching the request further (no fallthrough to handle issuance)", async () => {
    const selector = await readFile(join(srcRoot, "intelligence", "selector.ts"), "utf8");
    const guardStart = selector.indexOf("if (requestLocalOnly && resolvedChoice !== \"local\") {");
    expect(guardStart).toBeGreaterThan(0);
    const guardEnd = selector.indexOf("\n    }\n", guardStart);
    const guardBody = selector.slice(guardStart, guardEnd);
    expect(guardBody).toContain("return failureResponse(");
    expect(guardBody).toContain("local_only_violation");
  });

  it("getOrIssueHandle refuses a conflicting local-only request BEFORE the issuedHandles cache lookup or issueHandle", async () => {
    const selector = await readFile(join(srcRoot, "intelligence", "selector.ts"), "utf8");
    const start = selector.indexOf("private async getOrIssueHandle(");
    const end = selector.indexOf("private async issueHandle(", start);
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const body = selector.slice(start, end);

    const localOnlyGuard = body.indexOf("opts?.localOnly");
    const cacheLookup = body.indexOf("this.issuedHandles.get(key)");
    expect(localOnlyGuard).toBeGreaterThan(0);
    expect(cacheLookup).toBeGreaterThan(0);
    expect(localOnlyGuard).toBeLessThan(cacheLookup);
  });

  it("tryNextSubstrate checks the local-only constraint as its first statement, ahead of every other fallback gate", async () => {
    const selector = await readFile(join(srcRoot, "intelligence", "selector.ts"), "utf8");
    const start = selector.indexOf("private async tryNextSubstrate(");
    const end = selector.indexOf("private async getOrIssueHandle(", start);
    expect(start).toBeGreaterThan(0);
    const body = selector.slice(start, end);

    const localOnlyGuard = body.indexOf("if (isLocalOnlyRequest(req)) return null;");
    const degradeSilentGuard = body.indexOf('if (this.config.fallback[surface] !== "degrade-silent") return null;');
    expect(localOnlyGuard).toBeGreaterThan(0);
    expect(degradeSilentGuard).toBeGreaterThan(0);
    expect(localOnlyGuard).toBeLessThan(degradeSilentGuard);
  });

  it("the only production sites that construct VeniceClient are inside the selector class, and only one is reachable from an invocation", async () => {
    const selector = await readFile(join(srcRoot, "intelligence", "selector.ts"), "utf8");
    // Precedent for this style of inventory assertion:
    // q5e-selector-chokepoints.test.ts's "freezes the repo-wide Ollama
    // construction ... inventory" test. There are exactly two construction
    // sites in this file: the key-validation probe (`setVeniceApiKey` ->
    // `validateVeniceAndRecord`, an operator CONFIG WRITE unrelated to any
    // one request's localOnly flag) and the invocation-path handle issuer
    // (`veniceHandle`, reached only through `issueHandle`, which the
    // local-only guards in `invoke()` and `getOrIssueHandle()` gate). A
    // local-only request can only ever be safe from hosted-client
    // construction if the invocation path has exactly one such site, and
    // this pins that count so a new invocation-path construction site
    // cannot silently appear ungated.
    expect(selector.match(/new VeniceClient\(/g)).toHaveLength(2);
    const veniceHandleStart = selector.indexOf("private veniceHandle(");
    const veniceHandleEnd = selector.indexOf("private frontierHandle(", veniceHandleStart);
    expect(veniceHandleStart).toBeGreaterThan(0);
    expect(veniceHandleEnd).toBeGreaterThan(veniceHandleStart);
    const veniceHandleBody = selector.slice(veniceHandleStart, veniceHandleEnd);
    expect(veniceHandleBody.match(/new VeniceClient\(/g)).toHaveLength(1);
  });
});
