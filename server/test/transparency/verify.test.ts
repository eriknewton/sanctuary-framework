/**
 * Offline verifier security properties. Each negative test fails without
 * the corresponding check: forged signatures, counter rollback/gaps/
 * duplicates, replaced checkpoints, tampered counters, key confusion.
 */
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import {
  checkpointSigningBytes,
  computeCheckpointHash,
  type EnforcementCheckpointPayload,
  type EnforcementCheckpointRecord,
} from "../../src/transparency/checkpoint.js";
import {
  verifyTransparencyCheckpoints,
} from "../../src/transparency/verify.js";

const PRIVATE_KEY = randomBytes(32);
const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY);
const PUBLIC_KEY_B64 = toBase64url(PUBLIC_KEY);

function payloadAt(
  counter: number,
  previousHash: string,
  highestSequence: number
): EnforcementCheckpointPayload {
  return {
    checkpoint_kind: "enforcement-checkpoint",
    schema_version: 1,
    counter,
    previous_checkpoint_hash: previousHash,
    issued_at: `2026-06-0${counter}T00:00:00.000Z`,
    fortress_id: "fortress-test",
    audit: {
      merkle_root: "a".repeat(64),
      lowest_sequence: 1,
      highest_sequence: highestSequence,
      head_hash: "b".repeat(64),
      entry_count: highestSequence,
    },
    policy: { rules_sha256: "c".repeat(64), rules_count: 1, manifest_sha256: null },
    daemon: { version: "1.3.3", binary_sha256: "d".repeat(64) },
    enforcement: { total_allowed: counter, total_blocked: 0, rules: [] },
  };
}

function sign(
  payload: EnforcementCheckpointPayload,
  privateKey = PRIVATE_KEY
): EnforcementCheckpointRecord {
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    ...payload,
    signer_kid: `castle-wall:${toBase64url(publicKey)}`,
    signature: toBase64url(
      ed25519.sign(checkpointSigningBytes(payload), privateKey)
    ),
    signature_algorithm: "Ed25519",
    payload_encoding: "domain-separated-canonical-json-v1",
    public_key: toBase64url(publicKey),
  };
}

/** Build a valid chain of n checkpoints (counters 1..n, linked hashes). */
function makeChain(n: number): EnforcementCheckpointRecord[] {
  const records: EnforcementCheckpointRecord[] = [];
  let previousHash = "GENESIS";
  for (let counter = 1; counter <= n; counter++) {
    const payload = payloadAt(counter, previousHash, counter * 10);
    records.push(sign(payload));
    previousHash = computeCheckpointHash(payload);
  }
  return records;
}

describe("verify-transparency offline verifier", () => {
  it("PASSES a valid chain against the pinned key", () => {
    const report = verifyTransparencyCheckpoints(makeChain(3), {
      publicKey: PUBLIC_KEY_B64,
    });
    expect(report.verdict).toBe("PASS");
    expect(report.checkpoints_verified).toBe(3);
    expect(report.counter_range).toEqual({ from: 1, to: 3 });
    expect(report.signature_basis).toBe("pinned");
    expect(report.findings).toHaveLength(0);
    // Honesty: the report always states what it could NOT check.
    expect(report.not_checked.length).toBeGreaterThan(0);
    expect(report.not_checked.join(" ")).toContain("self-reported");
  });

  it("FAILS with no key and no explicit embedded-key opt-in (no silent downgrade)", () => {
    const report = verifyTransparencyCheckpoints(makeChain(1), {});
    expect(report.verdict).toBe("FAIL");
    expect(report.findings.some((f) => f.kind === "no_public_key")).toBe(true);
  });

  it("embedded-key verification requires opt-in and is labeled as weaker", () => {
    const report = verifyTransparencyCheckpoints(makeChain(2), {
      trustEmbedded: true,
    });
    expect(report.verdict).toBe("PASS");
    expect(report.signature_basis).toBe("embedded");
    expect(report.not_checked.join(" ")).toContain("internal consistency");
  });

  it("REJECTS a forged signature (tampered counters break verification)", () => {
    const chain = makeChain(2);
    // Adversary edits the signed counters without the key.
    const tampered = {
      ...chain[1]!,
      enforcement: { ...chain[1]!.enforcement, total_blocked: 9999 },
    };
    const report = verifyTransparencyCheckpoints([chain[0]!, tampered], {
      publicKey: PUBLIC_KEY_B64,
    });
    expect(report.verdict).toBe("FAIL");
    expect(
      report.findings.some(
        (f) => f.kind === "signature_invalid" && f.counter === 2
      )
    ).toBe(true);
  });

  it("REJECTS signatures from the wrong key", () => {
    const report = verifyTransparencyCheckpoints(makeChain(1), {
      publicKey: toBase64url(ed25519.getPublicKey(randomBytes(32))),
    });
    expect(report.verdict).toBe("FAIL");
    expect(report.findings.every((f) => f.kind === "signature_invalid")).toBe(
      true
    );
  });

  it("DETECTS a counter gap (withheld or deleted checkpoint)", () => {
    const chain = makeChain(3);
    const report = verifyTransparencyCheckpoints([chain[0]!, chain[2]!], {
      publicKey: PUBLIC_KEY_B64,
    });
    expect(report.verdict).toBe("FAIL");
    expect(
      report.findings.some((f) => f.kind === "counter_gap" && f.counter === 3)
    ).toBe(true);
  });

  it("DETECTS duplicate counters (fork / replay)", () => {
    const chain = makeChain(2);
    const fork = sign(payloadAt(2, computeCheckpointHash(payloadAt(1, "GENESIS", 10)), 25));
    const report = verifyTransparencyCheckpoints([...chain, fork], {
      publicKey: PUBLIC_KEY_B64,
    });
    expect(report.verdict).toBe("FAIL");
    expect(report.findings.some((f) => f.kind === "counter_duplicate")).toBe(
      true
    );
  });

  it("DETECTS a replaced checkpoint via previous-hash linkage", () => {
    const chain = makeChain(3);
    // Replace checkpoint 2 with a validly-signed but different payload; 3 no
    // longer links to it.
    const replacement = sign(
      payloadAt(2, chain[1]!.previous_checkpoint_hash, 999)
    );
    const report = verifyTransparencyCheckpoints(
      [chain[0]!, replacement, chain[2]!],
      { publicKey: PUBLIC_KEY_B64 }
    );
    expect(report.verdict).toBe("FAIL");
    expect(
      report.findings.some(
        (f) => f.kind === "previous_hash_mismatch" && f.counter === 3
      )
    ).toBe(true);
  });

  it("DETECTS an audit-log head moving backwards between checkpoints (rollback)", () => {
    const first = payloadAt(1, "GENESIS", 50);
    const secondPayload = payloadAt(2, computeCheckpointHash(first), 10);
    const report = verifyTransparencyCheckpoints(
      [sign(first), sign(secondPayload)],
      { publicKey: PUBLIC_KEY_B64 }
    );
    expect(report.verdict).toBe("FAIL");
    expect(report.findings.some((f) => f.kind === "counter_rollback")).toBe(
      true
    );
  });

  it("DETECTS cross-record fortress and signing-key drift", () => {
    const chain = makeChain(2);
    const otherKeyPayload = payloadAt(
      3,
      computeCheckpointHash(payloadAt(2, chain[1]!.previous_checkpoint_hash, 20)),
      30
    );
    const driftRecord = {
      ...sign({ ...otherKeyPayload, fortress_id: "fortress-other" }, randomBytes(32)),
    };
    const report = verifyTransparencyCheckpoints([...chain, driftRecord], {
      trustEmbedded: true,
    });
    expect(report.verdict).toBe("FAIL");
    expect(report.findings.some((f) => f.kind === "fortress_id_mismatch")).toBe(true);
    expect(report.findings.some((f) => f.kind === "signing_key_mismatch")).toBe(true);
  });

  it("FAILS on empty and malformed input", () => {
    expect(verifyTransparencyCheckpoints([], {}).verdict).toBe("FAIL");
    expect(verifyTransparencyCheckpoints("nonsense", {}).verdict).toBe("FAIL");
    expect(
      verifyTransparencyCheckpoints([{ bogus: true }], {
        publicKey: PUBLIC_KEY_B64,
      }).findings.some((f) => f.kind === "schema_error")
    ).toBe(true);
  });

  it("FAILS a withheld-prefix suffix (counters 3..4, genesis 1..2 missing) by default", () => {
    // A bundle missing checkpoints 1..N must NOT read as a clean PASS: exit 0
    // means "complete from genesis". A withheld prefix is detectable from
    // records[0].counter !== 1 and is a finding, not a downgraded note.
    const chain = makeChain(4).slice(2); // counters 3..4
    const report = verifyTransparencyCheckpoints(chain, {
      publicKey: PUBLIC_KEY_B64,
    });
    expect(report.verdict).toBe("FAIL");
    expect(report.findings.some((f) => f.kind === "counter_prefix_missing")).toBe(
      true
    );
  });

  it("reports a partial suffix as PARTIAL (never PASS) under --allow-partial", () => {
    const chain = makeChain(4).slice(2); // counters 3..4
    const report = verifyTransparencyCheckpoints(chain, {
      publicKey: PUBLIC_KEY_B64,
      allowPartial: true,
    });
    // Distinct PARTIAL verdict: incomplete evidence must never be readable as a
    // clean complete-from-genesis PASS by any verdict-gating caller.
    expect(report.verdict).toBe("PARTIAL");
    expect(report.verdict).not.toBe("PASS");
    expect(report.counter_range).toEqual({ from: 3, to: 4 });
    expect(report.findings.some((f) => f.kind === "counter_prefix_missing")).toBe(
      false
    );
    expect(report.not_checked.join(" ")).toContain("partial chain");
    expect(report.not_checked.join(" ")).toContain("suffix fragment");
  });

  it("GENESIS SPOOF: counter-1 record with a non-sentinel previous hash FAILS even with --allow-partial", () => {
    // HIGH-1 regression: a bundle whose earliest record claims counter 1 but
    // carries a 64-hex previous_checkpoint_hash (asserting an undisclosed
    // predecessor) must NEVER pass. It is a forged origin or a withheld prefix
    // wearing a genesis counter; --allow-partial cannot launder a counter-1
    // assertion, because claiming counter 1 IS claiming to be the genesis.
    const forgedOrigin = payloadAt(1, "e".repeat(64), 10); // non-GENESIS prev hash
    const second = payloadAt(2, computeCheckpointHash(forgedOrigin), 20);
    const chain = [sign(forgedOrigin), sign(second)];

    const strict = verifyTransparencyCheckpoints(chain, {
      publicKey: PUBLIC_KEY_B64,
    });
    expect(strict.verdict).toBe("FAIL");
    expect(
      strict.findings.some((f) => f.kind === "genesis_sentinel_mismatch")
    ).toBe(true);

    // --allow-partial must not rescue it: still FAIL, still the same finding.
    const partial = verifyTransparencyCheckpoints(chain, {
      publicKey: PUBLIC_KEY_B64,
      allowPartial: true,
    });
    expect(partial.verdict).toBe("FAIL");
    expect(partial.verdict).not.toBe("PASS");
    expect(partial.verdict).not.toBe("PARTIAL");
    expect(
      partial.findings.some((f) => f.kind === "genesis_sentinel_mismatch")
    ).toBe(true);
  });

  it("GENESIS SPOOF: a genuine genesis (counter 1 with the GENESIS sentinel) PASSES", () => {
    // The honest emitter writes "GENESIS" for the first checkpoint; that and
    // only that is a clean genesis-rooted PASS.
    const report = verifyTransparencyCheckpoints(makeChain(3), {
      publicKey: PUBLIC_KEY_B64,
    });
    expect(report.verdict).toBe("PASS");
    expect(report.findings).toHaveLength(0);
    expect(makeChain(3)[0]!.previous_checkpoint_hash).toBe("GENESIS");
  });

  it("DETECTS a misplaced genesis sentinel on a non-earliest record", () => {
    // A spliced second origin in the middle of a chain: counter 2 carrying the
    // GENESIS sentinel. This both breaks linkage and trips the explicit guard.
    const first = payloadAt(1, "GENESIS", 10);
    const spliced = payloadAt(2, "GENESIS", 20); // wrong: should link to #1
    const report = verifyTransparencyCheckpoints(
      [sign(first), sign(spliced)],
      { publicKey: PUBLIC_KEY_B64 }
    );
    expect(report.verdict).toBe("FAIL");
    expect(
      report.findings.some((f) => f.kind === "genesis_sentinel_misplaced")
    ).toBe(true);
  });

  it("PASSES a genesis-rooted complete chain (counter 1..N)", () => {
    const chain = makeChain(4); // counters 1..4
    const report = verifyTransparencyCheckpoints(chain, {
      publicKey: PUBLIC_KEY_B64,
    });
    expect(report.verdict).toBe("PASS");
    expect(report.counter_range).toEqual({ from: 1, to: 4 });
    expect(report.findings).toHaveLength(0);
  });

  it("accepts a bundle wrapper and a single record", () => {
    const chain = makeChain(2);
    const bundle = {
      format: "SANCTUARY_TRANSPARENCY_BUNDLE_V1",
      exported_at: new Date().toISOString(),
      public_key: PUBLIC_KEY_B64,
      checkpoints: chain,
    };
    expect(
      verifyTransparencyCheckpoints(bundle, { publicKey: PUBLIC_KEY_B64 }).verdict
    ).toBe("PASS");
    expect(
      verifyTransparencyCheckpoints(chain[0]!, { publicKey: PUBLIC_KEY_B64 })
        .verdict
    ).toBe("PASS");
  });
});
