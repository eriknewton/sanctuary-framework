/**
 * IC-05-DG planted-divergence proofs, part 2: the deletion probes (design
 * §f-4b, the review's and re-gate's attacks run verbatim as tests).
 *
 * D7 shapes: prefix/interior deletion (predecessor-existence), committed-tail
 * deletion (tip commitment), boundary-strip (the re-gate NEW-1 3-op attack;
 * floor witness), junk substitution and the planted duplicate (NEW-2 bound
 * identity), and recovery-marker persistence (NEW-3).
 */
import { describe, expect, it } from "vitest";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";
import {
  AUDIT_SIGNING_LATCH_V2_KEY,
  AUDIT_SIGNING_HEAD_KEY,
  CHECKPOINT_NAMESPACE,
  buildSignedFortress,
  checkpointKey,
  deleteCheckpoint,
  deleteControlRecord,
  findingsOfKind,
  hardFindings,
  lenientFindings,
  strictReadError,
  stripCheckpoint,
} from "../helpers/signing-fixture.js";

async function latchExists(storage: {
  read: (n: string, k: string) => Promise<Uint8Array | null>;
}): Promise<boolean> {
  return (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY)) !== null;
}

describe("IC-05-DG §f-4b: deletion probes (D7)", () => {
  it("(i) prefix deletion + latch deletion: deleted-predecessor fires and NO latch is re-established (recovery vetoed by coverage findings)", async () => {
    const { storage, masterKey } = await buildSignedFortress(4);
    await deleteCheckpoint(storage, 1);
    await deleteCheckpoint(storage, 2);
    await deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY);

    const findings = await lenientFindings(storage, masterKey);
    const downgrades = findingsOfKind(findings, "checkpoint_signing_downgrade");
    // c3's signed reference to c2 dangles.
    expect(
      downgrades.some(
        (finding) =>
          finding.variant === "deleted-predecessor" && finding.sequence === 2
      )
    ).toBe(true);
    // The load-bearing assertion: recovery did NOT stamp a latch above the
    // deleted prefix.
    expect(await latchExists(storage)).toBe(false);
    // Strict fails closed.
    expect((await strictReadError(storage, masterKey))?.name).toBe(
      "AuditIntegrityError"
    );
  });

  it("(ii) interior deletion with the latch kept: deleted-predecessor fires", async () => {
    const { storage, masterKey } = await buildSignedFortress(5);
    await deleteCheckpoint(storage, 3);

    const findings = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").some(
        (finding) =>
          finding.variant === "deleted-predecessor" && finding.sequence === 3
      )
    ).toBe(true);
  });

  it("(iii) committed-tail deletion with the head kept: MISSING_TAIL fires from the tip commitment", async () => {
    const { storage, masterKey } = await buildSignedFortress(4);
    await deleteCheckpoint(storage, 4);

    const findings = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").some(
        (finding) => finding.variant === "deleted-tail"
      )
    ).toBe(true);
    // Linkage alone can NEVER catch this (the writer re-chains to the
    // surviving highest): assert no deleted-predecessor fired, proving the
    // tip commitment is the only witness here.
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").some(
        (finding) => finding.variant === "deleted-predecessor"
      )
    ).toBe(false);
  });

  it("(iv) tail + head deletion: head recovery fires strict-closed, latches, and the SECOND load still emits the warn-grade latched finding naming the ambiguity", async () => {
    const { storage, masterKey } = await buildSignedFortress(4);
    await deleteCheckpoint(storage, 4);
    await deleteControlRecord(storage, AUDIT_SIGNING_HEAD_KEY);

    const first = await lenientFindings(storage, masterKey);
    const recovered = findingsOfKind(first, "checkpoint_signing_head_recovered");
    expect(hardFindings(recovered).length).toBeGreaterThanOrEqual(1);

    // A MAC'd marker latched in the re-created head.
    const headRaw = await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY);
    expect(headRaw).not.toBeNull();
    const head = JSON.parse(bytesToString(headRaw!));
    expect(
      head.data.latched.some(
        (marker: { marker_kind: string }) => marker.marker_kind === "head_recreated"
      )
    ).toBe(true);

    // Loads 2..N: warn-grade latched finding, permanent, text names the
    // honest-write-failure-vs-deletion ambiguity.
    const second = await lenientFindings(storage, masterKey);
    const laterRecovery = findingsOfKind(second, "checkpoint_signing_head_recovered");
    expect(laterRecovery.length).toBeGreaterThanOrEqual(1);
    expect(laterRecovery.every((finding) => finding.severity === "warn")).toBe(true);
    expect(laterRecovery[0]!.message).toContain("locally");
    expect(laterRecovery[0]!.message).toContain("indistinguishable");
    // Warn-grade only: strict now loads (functional healing) while the
    // finding stays visible forever.
    expect(await strictReadError(storage, masterKey)).toBeNull();
  });

  it("(v) junk substitution at a deleted key: malformed finding, enumeration PARTIAL, no stamping, strict fails closed", async () => {
    const { storage, masterKey } = await buildSignedFortress(4);
    await deleteCheckpoint(storage, 2);
    await deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY);
    await storage.write(
      CHECKPOINT_NAMESPACE,
      checkpointKey(2),
      stringToBytes("{ not a checkpoint }")
    );

    const findings = await lenientFindings(storage, masterKey);
    expect(findingsOfKind(findings, "checkpoint_malformed").length).toBeGreaterThanOrEqual(1);
    expect(
      findingsOfKind(findings, "checkpoint_signing_state_indeterminate").length
    ).toBeGreaterThanOrEqual(1);
    // No stamping from a partial pass.
    expect(await latchExists(storage)).toBe(false);
    expect((await strictReadError(storage, masterKey))?.name).toBe(
      "AuditIntegrityError"
    );
  });

  it("(vi) boundary-strip (re-gate NEW-1's 3-op attack, verbatim): rolled-floor fires hard, the stripped boundary reads UNSIGNED_DOWNGRADE against the WITNESSED floor, no re-arm, stays fired on a second load", async () => {
    const { storage, masterKey } = await buildSignedFortress(6);
    // delete c1..c3, STRIP c4 (leave it present, unsigned), delete the
    // latch, leave the head.
    for (const sequence of [1, 2, 3]) await deleteCheckpoint(storage, sequence);
    await stripCheckpoint(storage, 4);
    await deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY);

    const findings = await lenientFindings(storage, masterKey);
    const downgrades = findingsOfKind(findings, "checkpoint_signing_downgrade");
    // The floor predicate fires on BOTH legs: no verified record at the
    // witnessed floor (c1 deleted) and earliest verified (c5) > witness (c1).
    const rolled = downgrades.filter((finding) => finding.variant === "rolled-floor");
    expect(rolled.length).toBeGreaterThanOrEqual(1);
    expect(rolled[0]!.expected).toBe(1);
    // The predecessor predicate honestly does NOT fire: stripping the
    // boundary removed the only dangling signed reference (c5.previous = 4,
    // and a bound record exists at 4). The floor witness is what carries
    // this attack.
    expect(
      downgrades.some((finding) => finding.variant === "deleted-predecessor")
    ).toBe(false);
    // c4 classifies against the WITNESSED floor (c1), not the surviving
    // earliest (c5): UNSIGNED_DOWNGRADE (the fix-round-1 arithmetic error,
    // inverted into an assertion).
    expect(
      downgrades.some(
        (finding) => finding.variant === "strip" && finding.sequence === 4
      )
    ).toBe(true);
    // No latch re-established over rolled-floor evidence.
    expect(await latchExists(storage)).toBe(false);
    // Strict fails closed.
    expect((await strictReadError(storage, masterKey))?.name).toBe(
      "AuditIntegrityError"
    );

    // Second load: the head witness survives, so it STAYS fired (no
    // self-heal, no re-arm).
    const second = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(second, "checkpoint_signing_downgrade").some(
        (finding) => finding.variant === "rolled-floor"
      )
    ).toBe(true);
    expect(await latchExists(storage)).toBe(false);
  });

  it("(vii) planted duplicate (re-gate NEW-2's attack): a byte-copy of a validly signed record at a deleted key is loud AND sterile", async () => {
    const { storage, masterKey } = await buildSignedFortress(6);
    await deleteCheckpoint(storage, 3);
    // Plant c5's (validly signed) bytes at c3's key.
    const c5 = await storage.read(CHECKPOINT_NAMESPACE, checkpointKey(5));
    await storage.write(CHECKPOINT_NAMESPACE, checkpointKey(3), c5!);

    const findings = await lenientFindings(storage, masterKey);
    const malformed = findingsOfKind(findings, "checkpoint_malformed");
    const boundIdentity = malformed.filter(
      (finding) => finding.variant === "bound-identity"
    );
    // DELTA-2 diagnostic payload: BOTH sequences.
    expect(boundIdentity.length).toBe(1);
    expect(boundIdentity[0]!.expected).toBe(3);
    expect(boundIdentity[0]!.actual).toBe(5);
    // PARTIAL: scoped indeterminate finding + no stamping + strict closed.
    expect(
      findingsOfKind(findings, "checkpoint_signing_state_indeterminate").length
    ).toBeGreaterThanOrEqual(1);
    expect((await strictReadError(storage, masterKey))?.name).toBe(
      "AuditIntegrityError"
    );
    // Sterile: the plant satisfied no reference and no second c5 entered the
    // verified set (no duplicate-sequence finding fired, because the plant
    // was rejected at the read boundary — before the verified set).
    expect(
      malformed.some((finding) => finding.variant === "duplicate-sequence")
    ).toBe(false);
  });

  it("(vii) variant: overwriting a LIVE record in place with another record's bytes trips the same bound-identity check", async () => {
    const { storage, masterKey } = await buildSignedFortress(6);
    const c5 = await storage.read(CHECKPOINT_NAMESPACE, checkpointKey(5));
    await storage.write(CHECKPOINT_NAMESPACE, checkpointKey(3), c5!);

    const findings = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_malformed").some(
        (finding) =>
          finding.variant === "bound-identity" &&
          finding.expected === 3 &&
          finding.actual === 5
      )
    ).toBe(true);
    expect((await strictReadError(storage, masterKey))?.name).toBe(
      "AuditIntegrityError"
    );
  });

  it("(viii) recovery-latch persistence (NEW-3): latch+head deleted on a clean store, recovery latches; deleting the head AGAIN re-fires and re-latches", async () => {
    const { storage, masterKey } = await buildSignedFortress(3);
    await deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY);
    await deleteControlRecord(storage, AUDIT_SIGNING_HEAD_KEY);

    // Recovery pass: strict-closed, both recovery kinds fire hard.
    const first = await lenientFindings(storage, masterKey);
    expect(
      hardFindings(findingsOfKind(first, "checkpoint_signing_head_recovered")).length
    ).toBeGreaterThanOrEqual(1);
    expect(
      hardFindings(findingsOfKind(first, "checkpoint_signing_floor_recovered")).length
    ).toBeGreaterThanOrEqual(1);

    // Loads 2..N: warn-grade latched findings persist.
    for (let load = 0; load < 2; load++) {
      const later = await lenientFindings(storage, masterKey);
      const warns = [
        ...findingsOfKind(later, "checkpoint_signing_head_recovered"),
        ...findingsOfKind(later, "checkpoint_signing_floor_recovered"),
      ];
      expect(warns.length).toBeGreaterThanOrEqual(2);
      expect(warns.every((finding) => finding.severity === "warn")).toBe(true);
    }

    // Delete the head AGAIN: head_recovered re-fires (hard) and re-latches.
    await deleteControlRecord(storage, AUDIT_SIGNING_HEAD_KEY);
    const reFired = await lenientFindings(storage, masterKey);
    expect(
      hardFindings(findingsOfKind(reFired, "checkpoint_signing_head_recovered")).length
    ).toBeGreaterThanOrEqual(1);
    const headRaw = await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY);
    const head = JSON.parse(bytesToString(headRaw!));
    expect(
      head.data.latched.some(
        (marker: { marker_kind: string }) => marker.marker_kind === "head_recreated"
      )
    ).toBe(true);
  });

  it("delete ALL signed checkpoints with the head kept: MISSING_TAIL and rolled-floor both fire, hard, and stay fired", async () => {
    const { storage, masterKey } = await buildSignedFortress(3);
    for (const sequence of [1, 2, 3]) await deleteCheckpoint(storage, sequence);

    for (let load = 0; load < 2; load++) {
      const findings = await lenientFindings(storage, masterKey);
      const downgrades = findingsOfKind(findings, "checkpoint_signing_downgrade");
      expect(downgrades.some((finding) => finding.variant === "deleted-tail")).toBe(true);
      expect(downgrades.some((finding) => finding.variant === "rolled-floor")).toBe(true);
      expect(hardFindings(downgrades).length).toBe(downgrades.length);
    }
  });

  it("the 3-op paper attack composed with head deletion (move 2: the 4-op dual-control-record band) terminates in the permanent latched warn, never silence and never a wrong hard heal", async () => {
    const { storage, masterKey } = await buildSignedFortress(6);
    for (const sequence of [1, 2, 3]) await deleteCheckpoint(storage, sequence);
    await stripCheckpoint(storage, 4);
    await deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY);
    await deleteControlRecord(storage, AUDIT_SIGNING_HEAD_KEY);

    // Recovery pass: strict-closed once (hard recovery findings).
    const first = await lenientFindings(storage, masterKey);
    expect(
      hardFindings([
        ...findingsOfKind(first, "checkpoint_signing_head_recovered"),
        ...findingsOfKind(first, "checkpoint_signing_floor_recovered"),
      ]).length
    ).toBeGreaterThanOrEqual(2);

    // Thereafter: permanent warn, functional healing (strict loads), c4
    // reads below the recovered floor (local evidence honestly cannot prove
    // c4 was ever inside the signed range — §g residual #2, priced exactly).
    const second = await lenientFindings(storage, masterKey);
    const warns = [
      ...findingsOfKind(second, "checkpoint_signing_head_recovered"),
      ...findingsOfKind(second, "checkpoint_signing_floor_recovered"),
    ];
    expect(warns.length).toBeGreaterThanOrEqual(1);
    expect(warns.every((finding) => finding.severity === "warn")).toBe(true);
    expect(findingsOfKind(second, "checkpoint_signing_downgrade")).toEqual([]);
    expect(await strictReadError(storage, masterKey)).toBeNull();
  });
});
