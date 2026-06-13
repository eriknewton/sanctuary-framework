/**
 * Tests for the A2/B2 re-pin (trust-anchor migration) flow.
 *
 * Asserts:
 *  - buildPinRotationProof produces an OLD-key-signed binding (audit continuity);
 *  - runRePin drives the helper, records the rotation proof, and is idempotent
 *    when the retiring key is already gone (re-assert, not a second rotation);
 *  - the active-config path was relocated out of /tmp into the protected dir,
 *    with /tmp kept only as a read-fallback constant.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";

import {
  runProvisionPin,
  runRePin,
  buildPinRotationProof,
} from "../../../src/cli/castle-wall.js";
import {
  CASTLE_WALL_ACTIVE_CONFIG_PATH,
  CASTLE_WALL_ACTIVE_CONFIG_LEGACY_PATH,
} from "../../../src/castle-wall/runtime/socket-path.js";
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { encrypt } from "../../../src/core/encryption.js";
import { toBase64url, fromBase64url, stringToBytes } from "../../../src/core/encoding.js";
import type { ShimInvoker } from "../../../src/castle-wall/runtime/helper-signer.js";

const silent = new Writable({
  write(_chunk, _encoding, callback) {
    callback();
  },
});

function capture(): { stream: Writable; text(): string } {
  let buf = "";
  return {
    stream: new Writable({
      write(chunk, _enc, cb) {
        buf += chunk.toString();
        cb();
      },
    }),
    text: () => buf,
  };
}

function makeMockHelper() {
  const seed = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(seed);
  const invoke: ShimInvoker = async (args, stdin) => {
    const mode = args[0];
    if (mode === "get-pubkey" || mode === "re-pin") {
      return { stdout: toBase64url(pub), stderr: "", code: 0 };
    }
    const sig = ed25519.sign(stdin ?? new Uint8Array(0), seed);
    return { stdout: toBase64url(sig), stderr: "", code: 0 };
  };
  return { pub, invoke };
}

describe("castle-wall re-pin : buildPinRotationProof", () => {
  it("produces an OLD-key-signed binding that verifies against the old pubkey", () => {
    const masterKey = generateRandomKey();
    const oldSeed = ed25519.utils.randomPrivateKey();
    const oldPub = ed25519.getPublicKey(oldSeed);
    const oldEnc = encrypt(oldSeed, masterKey);
    const newPub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    const rotatedAt = "2026-06-05T00:00:00.000Z";

    const proof = buildPinRotationProof({
      oldPublicKey: oldPub,
      oldEncryptedPrivateKey: oldEnc,
      encryptionKey: masterKey,
      newPublicKey: newPub,
      rotatedAt,
    });

    expect(proof.old_public_key).toBe(toBase64url(oldPub));
    expect(proof.new_public_key).toBe(toBase64url(newPub));

    // Reconstruct the signed payload (the 5 fields, no signature) and verify.
    const eventData = JSON.stringify({
      old_public_key: proof.old_public_key,
      new_public_key: proof.new_public_key,
      identity_id: proof.identity_id,
      reason: proof.reason,
      rotated_at: proof.rotated_at,
    });
    const ok = ed25519.verify(
      fromBase64url(proof.signature),
      stringToBytes(eventData),
      oldPub,
    );
    expect(ok).toBe(true);
  });
});

describe("castle-wall re-pin : runRePin", () => {
  it("migrates the pin to the helper key and records the rotation proof", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-repin-"));
    try {
      const masterKey = generateRandomKey();
      const recoveryKey = toBase64url(masterKey);
      const env = {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      };
      // Provision K_old (local).
      expect(await runProvisionPin({ out: silent, err: silent, env })).toBe(0);

      const helper = makeMockHelper();
      const out = capture();
      const rc = await runRePin([], {
        out: out.stream,
        err: silent,
        env,
        platform: "darwin",
        signerClientInvoke: helper.invoke,
      });
      expect(rc).toBe(0);
      // The fingerprint printed is the helper key's.
      expect(out.text()).toMatch(/migrated to the signer helper/);

      // The rotation proof is in the audit log.
      const auditLog = new AuditLog(
        new FilesystemStorage(join(fortressPath, "state")),
        masterKey,
        { integrityMode: "lenient" },
      );
      const q = await auditLog.query({ layer: "l1", limit: 1000 });
      const rePinEntry = q.entries.find(
        (e) => e.details?.source === "castle-wall-re-pin",
      );
      expect(rePinEntry).toBeTruthy();
      const proof = (rePinEntry!.details as Record<string, unknown>).rotation_proof as {
        old_public_key: string;
        new_public_key: string;
      };
      expect(proof.new_public_key).toBe(toBase64url(helper.pub));
    } finally {
      await rm(fortressPath, { recursive: true, force: true });
    }
  });

  it("is idempotent when the retiring key is already gone (re-assert)", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-repin-idem-"));
    try {
      const masterKey = generateRandomKey();
      const env = {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: toBase64url(masterKey),
      };
      expect(await runProvisionPin({ out: silent, err: silent, env })).toBe(0);
      // Simulate a prior re-pin having retired the local private key.
      await unlink(join(fortressPath, "castle-pinned-privkey.enc"));

      const helper = makeMockHelper();
      const out = capture();
      const rc = await runRePin([], {
        out: out.stream,
        err: silent,
        env,
        platform: "darwin",
        signerClientInvoke: helper.invoke,
      });
      expect(rc).toBe(0);
      expect(out.text()).toMatch(/re-asserted/);
    } finally {
      await rm(fortressPath, { recursive: true, force: true });
    }
  });

  it("fails when no signer-client is configured and none auto-discovered", async () => {
    const err = capture();
    const rc = await runRePin([], {
      out: silent,
      err: err.stream,
      env: { SANCTUARY_STORAGE_PATH: "/tmp/does-not-matter" },
      platform: "darwin",
      // F1 (drill 06-13): re-pin now auto-discovers the bundled shim on darwin.
      // Pin the discovery seam to "nothing found" so this fail-closed test is
      // independent of whether the build host has the Castle Wall app installed.
      signerClientCandidates: [],
      fileExistsFn: async () => false,
    });
    expect(rc).toBe(1);
    expect(err.text()).toMatch(/signer-client shim path unknown/);
  });
});

describe("castle-wall : active-config relocation", () => {
  it("relocated the active-config path out of /tmp into the protected dir", () => {
    expect(CASTLE_WALL_ACTIVE_CONFIG_PATH).toBe(
      "/Library/Application Support/Sanctuary/castle-active.json",
    );
    expect(CASTLE_WALL_ACTIVE_CONFIG_PATH.startsWith("/tmp")).toBe(false);
  });

  it("keeps /tmp only as a legacy read-fallback constant", () => {
    expect(CASTLE_WALL_ACTIVE_CONFIG_LEGACY_PATH).toBe(
      "/tmp/sanctuary-castle-active.json",
    );
  });
});
