/**
 * Fleet license ledger — EXTERNAL monotonic anti-rollback anchor (PR-1
 * fast-follow) adversarial tests.
 *
 * These are the acceptance criteria for the freshness residual: an OLD but
 * genuinely-signed ledger snapshot, or an EMPTY ledger, must be caught by the
 * external master-MAC'd generation anchor even though every signature inside the
 * substituted file is valid. Plus the F1 failure-class guards: a partial persist
 * (blob at gen N+1, anchor still N) must read as BENIGN (never a false-brick),
 * and a tampered/wrong-key anchor must fail toward tampered (never silently ok).
 *
 * A raw-key issuer signer is used so a dropped check fails loudly here.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair, generateIdentityId } from "../../src/core/identity.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { randomBytes } from "../../src/core/random.js";
import {
  appendRow,
  emptyLedger,
  issueLicense,
  revokeLicense,
  type IssueLicenseParams,
  type IssuerSigner,
  type Ledger,
} from "../../src/entitlement/ledger.js";
import {
  LEDGER_GENERATION_ANCHOR_META_KEY,
  checkLedgerFreshness,
  readLedgerGenerationAnchor,
  writeLedgerGenerationAnchor,
} from "../../src/entitlement/ledger-antirollback.js";

const issuer = generateKeypair();
const NOW = 1_800_000_000;
const ISSUER_ID = generateIdentityId(issuer.publicKey);
const sign: IssuerSigner = (m) => ed25519.sign(m, issuer.privateKey);
/** A 32-byte master key for the anchor MAC (any fixed value works for tests). */
const master = randomBytes(32);
const wrongMaster = randomBytes(32);

function params(overrides: Partial<IssueLicenseParams> = {}): IssueLicenseParams {
  return {
    licenseId: `lic-${Math.random().toString(36).slice(2, 10)}`,
    subject: "fleet-op",
    tier: "fleet",
    pricingUnit: "node",
    entitledCount: 10,
    period: "monthly",
    notBefore: NOW,
    notAfter: NOW + 30 * 86_400,
    graceUntil: null,
    featureFlags: ["roster"],
    issuer: ISSUER_ID,
    ...overrides,
  };
}

/** Append one row at the next generation. */
function issueInto(ledger: Ledger, id: string): Ledger {
  const { row } = issueLicense(params({ licenseId: id }), sign, NOW);
  return appendRow(ledger, row, sign, issuer.publicKey, (ledger.generation ?? 0) + 1);
}

/** A fresh in-memory storage with the anchor advanced to `generation`. */
async function storageWithAnchor(generation: number): Promise<MemoryStorage> {
  const storage = new MemoryStorage();
  if (generation > 0) {
    await writeLedgerGenerationAnchor(storage, master, generation);
  }
  return storage;
}

describe("ledger anti-rollback — the generation anchor (read/write/monotonic)", () => {
  it("an ABSENT anchor reads as generation 0 (additive; pre-feature fortress trips nothing)", async () => {
    const storage = new MemoryStorage();
    const anchor = await readLedgerGenerationAnchor(storage, master);
    expect(anchor.status).toBe("absent");
  });

  it("a written anchor round-trips as valid under the same master", async () => {
    const storage = await storageWithAnchor(3);
    const anchor = await readLedgerGenerationAnchor(storage, master);
    expect(anchor.status).toBe("valid");
    if (anchor.status === "valid") expect(anchor.data.generation).toBe(3);
  });

  it("refuses to LOWER the anchor (monotonic write-guard)", async () => {
    const storage = await storageWithAnchor(5);
    await expect(
      writeLedgerGenerationAnchor(storage, master, 4),
    ).rejects.toThrow(/refusing to lower/);
    // An equal or higher generation is accepted.
    await expect(
      writeLedgerGenerationAnchor(storage, master, 5),
    ).resolves.toBeUndefined();
    await expect(
      writeLedgerGenerationAnchor(storage, master, 6),
    ).resolves.toBeUndefined();
  });

  it("a wrong-master (tampered/forged) anchor reads INVALID, not absent, not valid", async () => {
    const storage = await storageWithAnchor(2);
    // The real master cannot authenticate an anchor MAC'd under a different key.
    const anchor = await readLedgerGenerationAnchor(storage, wrongMaster);
    expect(anchor.status).toBe("invalid");
  });

  it("a corrupted anchor record reads INVALID (fail toward tampered)", async () => {
    const storage = await storageWithAnchor(2);
    // Corrupt the stored bytes: garbage that is not the signed record.
    await storage.write(
      "_meta",
      LEDGER_GENERATION_ANCHOR_META_KEY,
      new TextEncoder().encode('{"not":"a valid anchor"}'),
    );
    const anchor = await readLedgerGenerationAnchor(storage, master);
    expect(anchor.status).toBe("invalid");
  });
});

describe("ledger anti-rollback — checkLedgerFreshness (the acceptance criteria)", () => {
  it("a fresh ledger + matching anchor verifies ok", async () => {
    let ledger = emptyLedger();
    ledger = issueInto(ledger, "a"); // gen 1
    ledger = issueInto(ledger, "b"); // gen 2
    const storage = await storageWithAnchor(2);
    const v = await checkLedgerFreshness(ledger, issuer.publicKey, storage, master);
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.ledgerGeneration).toBe(2);
      expect(v.anchorGeneration).toBe(2);
    }
  });

  it("OLD-SNAPSHOT REPLAY: a genuine older ledger (gen < anchor) → tampered", async () => {
    let ledger = emptyLedger();
    ledger = issueInto(ledger, "a"); // gen 1
    const oldSnapshot = structuredClone(ledger); // genuine, gen 1, all sigs valid
    ledger = issueInto(ledger, "b"); // gen 2 (the current state)
    // The anchor tracks the current state (gen 2). The attacker swaps in the old
    // gen-1 snapshot — its head signature is genuinely valid, but its generation
    // is below the anchor.
    const storage = await storageWithAnchor(2);
    const v = await checkLedgerFreshness(oldSnapshot, issuer.publicKey, storage, master);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toMatch(/below the external anchor|rollback/);
  });

  it("EMPTY-LEDGER SUBSTITUTION: empty ledger (gen 0) vs anchor > 0 → tampered", async () => {
    // The attacker erases the whole issuance record. The empty ledger passes the
    // within-chain integrity check (genesis floor) but its generation is 0 < the
    // non-zero anchor, so freshness catches it — independent of the row-count>0
    // head guard.
    const storage = await storageWithAnchor(4);
    const v = await checkLedgerFreshness(emptyLedger(), issuer.publicKey, storage, master);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toMatch(/older or empty|below the external anchor/);
  });

  it("BENIGN FIRST ISSUE: empty ledger + absent anchor (0 vs 0) → ok", async () => {
    const storage = new MemoryStorage(); // no anchor written → reads as 0
    const v = await checkLedgerFreshness(emptyLedger(), issuer.publicKey, storage, master);
    expect(v.ok).toBe(true);
  });

  it("PARTIAL PERSIST (F1): ledger saved at gen N+1 but anchor still N → OK (benign lag), NOT brick", async () => {
    // Mirror the crash-between-blob-and-anchor state: the durable blob advanced
    // to gen 2, but the anchor bump (which the mutate path does AFTER saveLedger)
    // never ran, so the anchor is still gen 1. Verify uses `>=`, so this is a
    // benign lag, never a false-brick.
    let ledger = emptyLedger();
    ledger = issueInto(ledger, "a"); // gen 1
    ledger = issueInto(ledger, "b"); // gen 2 (blob is durable at gen 2)
    const storage = await storageWithAnchor(1); // anchor lagged at gen 1
    const v = await checkLedgerFreshness(ledger, issuer.publicKey, storage, master);
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.ledgerGeneration).toBe(2);
      expect(v.anchorGeneration).toBe(1);
    }
  });

  it("ANCHOR TAMPERED/WRONG-KEY: a present-but-unauthenticated anchor → tampered (fail-closed)", async () => {
    let ledger = emptyLedger();
    ledger = issueInto(ledger, "a"); // gen 1
    // Anchor present but MAC'd under the WRONG master → invalid under the real
    // master → the freshness check must fail toward tampered, not silently pass.
    const storage = new MemoryStorage();
    await writeLedgerGenerationAnchor(storage, wrongMaster, 1);
    const v = await checkLedgerFreshness(ledger, issuer.publicKey, storage, master);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toMatch(/did not authenticate|tampered/);
  });

  it("within-chain tamper is still caught (integrity runs first)", async () => {
    let ledger = emptyLedger();
    ledger = issueInto(ledger, "a");
    const tampered = structuredClone(ledger);
    tampered.rows[0]!.token.claims.entitledCount = 9999; // breaks the row hash
    const storage = await storageWithAnchor(1);
    const v = await checkLedgerFreshness(tampered, issuer.publicKey, storage, master);
    expect(v.ok).toBe(false);
  });

  it("revoke advances the generation; a pre-revoke snapshot is a rollback", async () => {
    let ledger = emptyLedger();
    ledger = issueInto(ledger, "a"); // gen 1
    ledger = issueInto(ledger, "b"); // gen 2
    const preRevoke = structuredClone(ledger); // gen 2, "b" active
    const revoked = revokeLicense(
      ledger, "b", NOW + 100, "chargeback", sign, issuer.publicKey,
      (ledger.generation ?? 0) + 1, // gen 3
    );
    const storage = await storageWithAnchor(revoked.generation!); // anchor at gen 3
    // The current (revoked) ledger verifies fresh.
    expect((await checkLedgerFreshness(revoked, issuer.publicKey, storage, master)).ok).toBe(true);
    // Swapping in the pre-revoke snapshot (gen 2, shows "b" still active) is a
    // rollback: gen 2 < anchor gen 3.
    const stale = await checkLedgerFreshness(preRevoke, issuer.publicKey, storage, master);
    expect(stale.ok).toBe(false);
  });
});

describe("ledger anti-rollback — one-mutation self-healing lag (Fix 3, honest residual)", () => {
  it("a crash-lagged anchor self-heals on the NEXT mutation to N+2, then the lagged snapshots read tampered", async () => {
    // Reproduce the exact crash state the residual documents: the durable BLOB
    // advanced to gen N+1 but the process crashed BEFORE the anchor bump, so the
    // anchor lags at N. This is benign (verify uses `>=`), but the last mutation
    // is not yet rollback-protected. The NEXT mutation must self-heal.
    const N = 1;
    let ledger = emptyLedger();
    ledger = issueInto(ledger, "a"); // gen 1  (N)
    ledger = issueInto(ledger, "b"); // gen 2  (N+1) — the durable blob
    const blobGen = ledger.generation!;
    expect(blobGen).toBe(N + 1);

    // Snapshots that must become tampered once the anchor self-heals past them.
    let atGenN = emptyLedger();
    atGenN = issueInto(atGenN, "a"); // a genuine gen-1 (N) snapshot
    const atGenNplus1 = structuredClone(ledger); // genuine gen-2 (N+1) snapshot

    // Anchor lagged at N (the crash window). The current blob (N+1 >= N) still
    // verifies — a benign lag, NOT a brick.
    const storage = await storageWithAnchor(N); // anchor at gen 1
    const benign = await checkLedgerFreshness(ledger, issuer.publicKey, storage, master);
    expect(benign.ok).toBe(true);
    if (benign.ok) {
      expect(benign.ledgerGeneration).toBe(N + 1);
      expect(benign.anchorGeneration).toBe(N);
    }

    // The NEXT mutation self-heals: it computes
    // nextGeneration = max(ledgerGen=N+1, anchorGen=N) + 1 = N+2, mutates, and
    // advances the anchor to N+2 (mirroring the CLI mutate path).
    const anchorRead = await readLedgerGenerationAnchor(storage, master);
    const anchorGen = anchorRead.status === "valid" ? anchorRead.data.generation : 0;
    const nextGeneration = Math.max(ledger.generation ?? 0, anchorGen) + 1;
    expect(nextGeneration).toBe(N + 2); // 3

    const healed = appendRow(
      ledger,
      issueLicense(params({ licenseId: "c" }), sign, NOW).row,
      sign,
      issuer.publicKey,
      nextGeneration,
    );
    await writeLedgerGenerationAnchor(storage, master, nextGeneration); // anchor → N+2

    // The healed ledger verifies fresh at the self-healed floor.
    const healedVerdict = await checkLedgerFreshness(healed, issuer.publicKey, storage, master);
    expect(healedVerdict.ok).toBe(true);
    if (healedVerdict.ok) expect(healedVerdict.anchorGeneration).toBe(N + 2);

    // The residual is now BOUNDED + closed: replaying EITHER the gen-N or the
    // gen-(N+1) snapshot below the self-healed anchor (N+2) reads as tampered.
    const replayN = await checkLedgerFreshness(atGenN, issuer.publicKey, storage, master);
    expect(replayN.ok).toBe(false);
    if (!replayN.ok) expect(replayN.reason).toMatch(/below the external anchor|rollback|older or empty/);

    const replayNplus1 = await checkLedgerFreshness(atGenNplus1, issuer.publicKey, storage, master);
    expect(replayNplus1.ok).toBe(false);
    if (!replayNplus1.ok)
      expect(replayNplus1.reason).toMatch(/below the external anchor|rollback|older or empty/);
  });
});

describe("ledger anti-rollback — legacy #868 back-compat (no false-brick)", () => {
  it("a legacy ledger with NO generation field still verifies (v1 head fallback), anchor absent → ok", async () => {
    // Build a legacy-shaped ledger: sign the head under the V1 message
    // (rowCount, finalRowHash) with NO generation, exactly as #868 did. We do
    // this by constructing the row via the module then re-signing the head the
    // old way. Simplest faithful reproduction: take a current single-row ledger
    // and strip generation + re-sign the head under v1.
    let ledger = emptyLedger();
    ledger = issueInto(ledger, "legacy-1"); // gen 1, v2 head
    // Reproduce a v1 ledger: remove `generation` and re-sign the head over the
    // v1 message. The v1 head domain body is canonicalJson({rowCount, finalRowHash}).
    const legacy: Ledger = structuredClone(ledger);
    delete legacy.generation;
    const finalHash = legacy.rows[legacy.rows.length - 1]!.rowHash;
    // Build the EXACT v1 head body via the module's own canonicalJson so it is
    // byte-identical to what headMessage(rowCount, finalRowHash) produced in #868
    // (no `generation` field → v1).
    const { canonicalJson } = await import("../../src/audit/chain.js");
    const v1Body = canonicalJson({ rowCount: legacy.rows.length, finalRowHash: finalHash });
    const v1Msg = new TextEncoder().encode(`sanctuary.fleet.ledger.head.v1\n${v1Body}`);
    const { toBase64url } = await import("../../src/core/encoding.js");
    legacy.headSignature = toBase64url(ed25519.sign(v1Msg, issuer.privateKey));
    // Absent anchor → generation 0; legacy ledger.generation undefined → 0; 0 >= 0.
    const storage = new MemoryStorage();
    const v = await checkLedgerFreshness(legacy, issuer.publicKey, storage, master);
    expect(v.ok).toBe(true);
  });
});
