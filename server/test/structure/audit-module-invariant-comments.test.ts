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

describe("Audit module invariant comments", () => {
  it("keeps audit/chain canonical JSON and checkpoint signature invariants pinned", () => {
    const source = read("server/src/audit/chain.ts");

    expectNear(source, ".filter((key) => record[key] !== undefined)", [
      "Invariant: `undefined` means \"field absent,\" never signable data",
      "standalone verifier carries this exact rule",
    ]);
    expectNear(source, "return stringToBytes(`${AUDIT_CHECKPOINT_DOMAIN_PREFIX}", [
      "Invariant: checkpoint signatures never range over bare canonical JSON",
      "domain prefix, including its trailing newline",
    ]);
    expectNear(source, "fromBase64urlStrict(signature)", [
      "Invariant: callers supply logical payload fields",
      "lenient",
      "decoding would let altered strings",
    ]);
  });

  it("keeps operational audit-log hash-chain and checkpoint invariants pinned", () => {
    const source = read("server/src/operational/audit-log.ts");

    expectNear(source, "const entryHash = computeAuditEntryHash({", [
      "Hash-chain invariant",
      "covers the previous hash and the",
      "encrypted payload bytes",
      "checked on every reload",
    ]);
    expectNear(source, "let expectedSequence = expectedSequenceSeed;", [
      "Seed is resolved by resolveChainSeed",
      "authenticated rotation anchor",
    ]);
    expectNear(source, "const expectedRoot = computeAuditRoot(hashes);", [
      "Checkpoint root invariant",
      "recomputed from the",
      "verified entry hashes on load",
      "cannot bless a changed",
      "span by carrying its own root_hash",
    ]);
    expectNear(source, "if (resolvedPublicKeys.length === 0) {", [
      "Checkpoint trust-basis invariant",
      "embedded public key is part of the",
      "checkpoint being verified",
      "explicitly asks for an internal-consistency check",
      "never a reason to retry against the embedded copy",
    ]);
    expectNear(source, "root_hash: computeAuditRoot(hashes),", [
      "Checkpoint write invariant",
      "derived from persisted entry",
      "hashes collected while the write lock is held",
      "while the write lock is held",
    ]);
    expectNear(source, "signed = (await this.checkpointSigner(payload)) ?? null;", [
      "not an identity-less fortress",
      "diagnostic only",
      "IC-05-DG",
    ]);
    expectNear(source, "unsigned_reason: \"no signing identity available", [
      "store whose adapter cannot reach identity records",
      "is serialized as `unsigned`",
      "silently trusting a fallback key",
    ]);
  });

  it("keeps the IC-05 checkpoint-identity wiring pinned at the constructor default", () => {
    const source = read("server/src/operational/audit-log.ts");

    expectNear(source, "const fortressCheckpointIdentity = createFortressCheckpointIdentityBinding(", [
      "DERIVED from the",
      "constructor's own required arguments",
      "injection seam",
      "Fail-closed-on-absence was rejected",
      "honest `unsigned`",
    ]);
  });
});
