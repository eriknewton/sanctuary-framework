import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

function around(source: string, anchor: string): string {
  const index = source.indexOf(anchor);
  expect(index, `missing source anchor: ${anchor}`).toBeGreaterThanOrEqual(0);
  return source.slice(Math.max(0, index - 650), index + anchor.length + 350);
}

function expectNear(source: string, anchor: string, snippets: readonly string[]): void {
  const window = around(source, anchor);
  for (const snippet of snippets) {
    expect(window).toContain(snippet);
  }
}

describe("v1 router invariant comment hygiene", () => {
  it("keeps the bearer-boundary rationale at the session token parser", () => {
    const source = read("server/src/v1/router.ts");

    expectNear(source, 'const parts = header.split(" ");', [
      "Bearer-boundary invariant",
      "ceremony-minted",
      "dashboard auth token",
      "same generic",
    ]);
  });

  it("keeps token-crypto ownership at validateToken", () => {
    const source = read("server/src/v1/router.ts");

    expectNear(source, "return ctx.sessions.validateToken(parts[1]);", [
      "validateToken owns the cryptographic checks",
      "GCM tag, expiry, generation",
      "never decodes header bytes into claims itself",
    ]);
  });
});
