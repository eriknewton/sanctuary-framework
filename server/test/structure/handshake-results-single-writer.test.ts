/**
 * handshakeResults shared substrate: single-writer chokepoint (MUST-FIX 3,
 * register §Z RECHECK fix-round).
 *
 * `handshakeResults` is read by federation (peer registration), the
 * operator dashboard (handshake panel), and reputation/bridge tier
 * resolution — the "shared substrate" the self-vouch class exploited before
 * `recordHandshakeResult` (handshake/tools.ts) became the single producer
 * chokepoint every write funnels through. Two backstops make that structural
 * rather than convention-dependent:
 *
 *   1. `createHandshakeTools` exposes the map to every external consumer as
 *      `ReadonlyMap<string, HandshakeResult>` (only the producer's internal
 *      closure keeps a mutable reference) — TypeScript refuses a `.set(`
 *      call at any consumer call site.
 *   2. This source-text scan is a mutation-resistant BACKSTOP: even a call
 *      site that casts around the type (a legitimate escape hatch for test
 *      fixtures, illegitimate in production `src/`) is caught here, and the
 *      scan also asserts every known consumer actually DECLARES the
 *      ReadonlyMap type rather than the file quietly reverting to `Map`.
 */

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");

const PRODUCER = "handshake/tools.ts";
const WRITE_PATTERN = /\bhandshakeResults\s*\.\s*set\s*\(/;

// Files that mention the write pattern only in a COMMENT (explaining the
// invariant, not violating it). Each entry documents why it is exempt so
// adding to this list is a deliberate, reviewable act.
const COMMENT_ONLY_EXEMPT: Record<string, string> = {
  "handshake/protocol.ts":
    "comment cross-referencing the producer chokepoint (register §Z RECHECK), no actual .set( call",
};

/** True when every line matching WRITE_PATTERN in `text` is a `//` comment line. */
function onlyCommentMatches(text: string): boolean {
  return text
    .split("\n")
    .filter((line) => WRITE_PATTERN.test(line))
    .every((line) => line.trimStart().startsWith("//"));
}

const CONSUMERS_REQUIRING_READONLY_MAP = [
  "federation/tools.ts",
  "bridge/tools.ts",
  "reputation/tools.ts",
  "reputation/tiers.ts",
  "principal-policy/dashboard.ts",
];

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

function rel(full: string): string {
  return relative(SERVER_SRC, full).split("\\").join("/");
}

describe("handshakeResults shared substrate: single-writer chokepoint", () => {
  const files = tsFiles(SERVER_SRC).map((full) => ({
    rel: rel(full),
    text: readFileSync(full, "utf-8"),
  }));

  it("only the producer (handshake/tools.ts) writes .set() into the handshakeResults map", () => {
    const offenders = files
      .filter((f) => f.rel !== PRODUCER)
      .filter((f) => WRITE_PATTERN.test(f.text))
      .filter((f) => !(f.rel in COMMENT_ONLY_EXEMPT && onlyCommentMatches(f.text)))
      .map((f) => f.rel);
    expect(
      offenders,
      "these files write handshakeResults.set(...) outside the producer chokepoint " +
        "(recordHandshakeResult in handshake/tools.ts); a second writer reopens the " +
        "self-vouch class every consumer of the shared map inherits: " +
        offenders.join(", ")
    ).toEqual([]);
  });

  it("sanity: the producer itself does write .set() (the pattern is not dead)", () => {
    const producer = files.find((f) => f.rel === PRODUCER);
    expect(producer, "handshake/tools.ts must exist").toBeDefined();
    expect(WRITE_PATTERN.test(producer!.text)).toBe(true);
  });

  it("every known consumer declares ReadonlyMap<string, HandshakeResult>, not a mutable Map, for its handshakeResults parameter", () => {
    const offenders: string[] = [];
    for (const consumerRel of CONSUMERS_REQUIRING_READONLY_MAP) {
      const f = files.find((x) => x.rel === consumerRel);
      expect(f, `expected consumer surface ${consumerRel} to exist`).toBeDefined();
      if (!f!.text.includes("ReadonlyMap<string, HandshakeResult>")) {
        offenders.push(consumerRel);
      }
    }
    expect(
      offenders,
      "these consumers must type their handshakeResults parameter as " +
        "ReadonlyMap<string, HandshakeResult> (widening back to a mutable Map " +
        "silently reopens the single-writer invariant): " + offenders.join(", ")
    ).toEqual([]);
  });

  it("the producer's return type widens handshakeResults to ReadonlyMap for external consumers", () => {
    const producer = files.find((f) => f.rel === PRODUCER)!;
    expect(producer.text).toContain("handshakeResults: ReadonlyMap<string, HandshakeResult>;");
  });
});
