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
    expectNear(source, "const record: AuditCheckpointRecord = {", [
      "is serialized as `unsigned`",
      "COSMETIC",
      "zero trust weight",
      "identity-absence",
    ]);
  });

  it("keeps the IC-05-DG downgrade-detection invariant comments pinned at their enforcement sites", () => {
    const source = read("server/src/operational/audit-log.ts");

    // The absence rule (review finding 3): a thrown control-record read is
    // indeterminate, never absent and never TAMPERED.
    expectNear(source, "return { status: \"unreadable\", detail: failureMessage(err) };", [
      "Absence rule",
      "Treat-error-as-absent",
      "chmod",
    ]);
    // DELTA-3: committed tip + uncommitted floor is impossible by
    // construction; observing it reads as tampered, never quiet.
    expectNear(source, "data.lowest_signed_checkpoint_sequence === null", [
      "DELTA-3",
      "impossible by construction",
      "TAMPERED, never quiet",
    ]);
    // The LD6 chokepoint: re-read + monotone merge + pre-dispatch assert.
    expectNear(source, "private async writeSigningControlRecord(", [
      "never from memory",
      "immediately before dispatching the durable write",
      "detached-late-completion",
    ]);
    // The monotone floor merge (NEW-1): null sentinel, never raised.
    expectNear(source, "lowest_signed_checkpoint_sequence` is a MIN over NON-NULL values", [
      "not-yet-committed sentinel",
      "raising it IS the attack",
    ]);
    // Enumeration completeness (R3-e): stamps only from complete,
    // coverage-finding-free passes.
    expectNear(source, "private async readCheckpointsWithCompleteness(", [
      "may never stamp state",
      "blind to DELETION",
    ]);
    expectNear(source, "the checkpoint enumeration is partial", [
      "different verdicts",
      "fail\n      // closed on the BLINDNESS",
    ]);
    // Bound checkpoint identity (NEW-2).
    expectNear(source, "if (keySeq === null || keySeq !== record.checkpoint_sequence) {", [
      "sequence MUST equal",
      "byte-copy",
      "loud AND sterile",
    ]);
    // The coverage predicates consume signed references only (never a walk).
    expectNear(source, "const previous = checkpoint.previous_checkpoint_sequence;", [
      "INSIDE the signed",
      "tamper-evident",
      "bound existence, never",
    ]);
    // Ring membership, not range (review finding 9), and the clock-
    // independence discharge of rule 10.
    expectNear(source, "if (incidentRing.has(checkpoint.checkpoint_sequence)) {", [
      "ring MEMBERSHIP is the predicate",
      "day-one-corruption",
    ]);
    expectNear(source, "const verdictFloor = Math.min(latchFloor, headFloor, storeFloor);", [
      "deleting any one memory",
      "no verdict consumes a timestamp",
    ]);
    // The constructional-only carve-out (review finding 2), both halves.
    expectNear(source, "if (this.signingDetectionMode === \"non-fortress\") {", [
      "AT CONSTRUCTION",
      "no storage state can manufacture",
      "every runtime failure below is a FINDING",
    ]);
    // Recovery latches before it re-stamps (NEW-3).
    expectNear(source, "private async performSigningRecoveryWrites(", [
      "LATCHES BEFORE it",
      "cannot silence it",
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
