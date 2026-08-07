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
  return source.slice(Math.max(0, index - 700), index + anchor.length + 700);
}

function expectNear(
  source: string,
  anchor: string,
  snippets: readonly string[]
): void {
  const window = around(source, anchor);
  for (const snippet of snippets) {
    expect(window).toContain(snippet);
  }
}

describe("Guardian master-rotation invariant comments", () => {
  it("keeps the producer id-to-pubkey mapping invariant at payload assembly", () => {
    const source = read("server/src/mesh/guardian/master-rotation.ts");

    expectNear(source, "return {\n    old_master_pubkey:", [
      "Producer mapping invariant",
      "signatures by guardian_id",
      "wire payload carries guardian_pubkey",
      "verifyGuardianQuorum already proved every id",
      "canonical input",
    ]);
  });

  it("keeps the receiver pubkey-to-id reducer invariant at acceptance", () => {
    const source = read("server/src/mesh/guardian/master-rotation.ts");

    expectNear(source, "return { guardian_id: guardian.guardian_id", [
      "Receiver identity-reducer invariant",
      "event carries public keys",
      "quorum counting happens on pinned guardian_id",
      "claimed ids are never trusted across the wire",
    ]);
  });

  it("keeps the receiver canonical-input invariant before quorum verification", () => {
    const source = read("server/src/mesh/guardian/master-rotation.ts");

    expectNear(source, "verifyGuardianQuorum({\n    input,", [
      "Receiver canonical-input invariant",
      "receiver's pinned fortress_id",
      "roster_version, distinct ids, threshold",
      "payload cannot smuggle an alternate fortress_id",
    ]);
  });
});
