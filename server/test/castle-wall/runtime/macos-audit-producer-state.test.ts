import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ed25519 } from "@noble/curves/ed25519";
import { afterEach, describe, expect, it } from "vitest";

import {
  seedMacOSAuditProducerStateFromLocalAnchor,
} from "../../../src/castle-wall/runtime/macos-audit-producer-state.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import type { PersistedChainAnchor } from "../../../src/castle-wall/runtime/audit-consumer.js";
import { CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";

const privateKey = ed25519.utils.randomPrivateKey();
const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
const CAPTURED_AT_MS = 1_750_000_000_000;

describe("macOS audit producer cursor recovery", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function tempStatePath(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "cw-producer-state-"));
    tempDirs.push(dir);
    return join(dir, "audit-producer-chain-state.json");
  }

  it("raises a stale root cursor from the verified local consumer anchor", async () => {
    const statePath = await tempStatePath();
    await writeFile(
      statePath,
      JSON.stringify({
        next_seq: 576,
        prior_sha256_hex: "a".repeat(64),
        schema_version: 1,
      }),
    );
    const body = signedBody(28_173);
    const expectedPrior = sha256Hex(body);

    const result = await seedMacOSAuditProducerStateFromLocalAnchor({
      chainAnchorSource: async () => signedAnchor({ seq: 28_173, body }),
      pinnedProducerKeyB64url: publicKeyB64url,
      statePath,
    });

    expect(result).toMatchObject({
      kind: "seeded",
      previousNextSeq: 576,
      nextSeq: 28_174,
      priorSha256Hex: expectedPrior,
      replacedInvalidState: false,
    });
    await expect(readJson(statePath)).resolves.toEqual({
      next_seq: 28_174,
      prior_sha256_hex: expectedPrior,
      schema_version: 1,
    });
  });

  it("does not roll back a cursor already ahead of the local flow anchor", async () => {
    const statePath = await tempStatePath();
    await writeFile(
      statePath,
      JSON.stringify({
        next_seq: 30_000,
        prior_sha256_hex: "b".repeat(64),
        schema_version: 1,
      }),
    );

    const result = await seedMacOSAuditProducerStateFromLocalAnchor({
      chainAnchorSource: async () => signedAnchor({ seq: 28_173 }),
      pinnedProducerKeyB64url: publicKeyB64url,
      statePath,
    });

    expect(result).toMatchObject({
      kind: "current",
      nextSeq: 30_000,
      priorSha256Hex: "b".repeat(64),
    });
    await expect(readJson(statePath)).resolves.toMatchObject({
      next_seq: 30_000,
      prior_sha256_hex: "b".repeat(64),
    });
  });

  it("refuses a same-seq cursor whose prior hash conflicts with the verified anchor", async () => {
    const statePath = await tempStatePath();
    await writeFile(
      statePath,
      JSON.stringify({
        next_seq: 28_174,
        prior_sha256_hex: "d".repeat(64),
        schema_version: 1,
      }),
    );

    await expect(
      seedMacOSAuditProducerStateFromLocalAnchor({
        chainAnchorSource: async () => signedAnchor({ seq: 28_173 }),
        pinnedProducerKeyB64url: publicKeyB64url,
        statePath,
      }),
    ).rejects.toThrow(/cursor state conflict/);
    await expect(readJson(statePath)).resolves.toEqual({
      next_seq: 28_174,
      prior_sha256_hex: "d".repeat(64),
      schema_version: 1,
    });
  });

  it("refuses to seed from an anchor whose producer signature does not verify", async () => {
    const statePath = await tempStatePath();
    const body = signedBody(28_173);

    await expect(
      seedMacOSAuditProducerStateFromLocalAnchor({
        chainAnchorSource: async () =>
          signedAnchor({
            seq: 28_173,
            body,
            signatureB64url: signBody(signedBody(1), 1),
          }),
        pinnedProducerKeyB64url: publicKeyB64url,
        statePath,
      }),
    ).rejects.toThrow(/persisted_anchor_signature_invalid/);
    await expect(stat(statePath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("skips a genuine fresh install with no local chain anchor", async () => {
    const statePath = await tempStatePath();

    const result = await seedMacOSAuditProducerStateFromLocalAnchor({
      chainAnchorSource: async () => null,
      pinnedProducerKeyB64url: publicKeyB64url,
      statePath,
    });

    expect(result).toEqual({ kind: "skipped", reason: "no_anchor" });
    await expect(stat(statePath)).rejects.toMatchObject({ code: "ENOENT" });
  });
});

function signedAnchor(input: {
  seq: number;
  body?: string;
  signatureB64url?: string;
}): PersistedChainAnchor {
  const body = input.body ?? signedBody(input.seq);
  return {
    kind: "persisted",
    seq: input.seq,
    signedCanonicalJson: body,
    signatureB64url:
      input.signatureB64url ?? signBody(body, input.seq),
    keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    capturedAtUnixMs: CAPTURED_AT_MS,
    chainBasis: "producer_signed_body",
    identityId: "fortress/uid/503",
  };
}

function signedBody(seq: number): string {
  return canonicalize({
    timestamp: "2026-08-06T16:00:00.000Z",
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "fortress/uid/503",
    result: "blocked",
    details: {
      agent_id: "fortress/uid/503",
      dest_ip: "203.0.113.9",
      dest_port: 443,
      dest_protocol: "tcp",
      decision: "drop",
      prior_sha256_hex: "c".repeat(64),
      rule_id: null,
      seq,
      source: "macos_extension",
    },
  });
}

function signBody(canonical: string, seq: number): string {
  return toBase64url(
    ed25519.sign(producerSigningBytes(canonical, CAPTURED_AT_MS, seq), privateKey),
  );
}

function sha256Hex(utf8: string): string {
  return createHash("sha256").update(utf8, "utf8").digest("hex");
}

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8"));
}
