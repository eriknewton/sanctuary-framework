/**
 * Observe Option A CLI coverage for F-OBSNOINPUT.
 *
 * The regression lived above the pure fold/store layer: `observe candidates`
 * opened only the master-key audit chain, while safe-mode denials were written
 * to the boot-token-keyed `boot-audit/<fingerprint>` chain. These tests drive
 * the real CLI refresh/list path against filesystem-backed audit segments so
 * the fixture has to be opened by the command itself.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";

import { ed25519 } from "@noble/curves/ed25519";

import {
  runObserveCandidates,
  runObservePromote,
  runObserveStatus,
} from "../../../src/cli/castle-wall-observe.js";
import {
  deriveSafeModeAuditKey,
  generateBootToken,
  persistBootToken,
  safeModeAuditStoragePath,
} from "../../../src/castle-wall/boot/boot-token.js";
import {
  exclusiveRoutingMarkerPath,
  renderExclusiveRoutingMarker,
} from "../../../src/castle-wall/allowlist/index.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../../src/castle-wall/constants.js";
import {
  producerSigningBytes,
  resolveProducerPubKeyPath,
} from "../../../src/castle-wall/runtime/producer-signature.js";
import { fortressIdFromStoragePath } from "../../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { IdentityManager } from "../../../src/cognitive/tools.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { hashToString } from "../../../src/core/hashing.js";
import { stringToBytes, toBase64url } from "../../../src/core/encoding.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";

// Force `loadFortressProducerKey` onto its fortress-relative Linux branch so
// this test is deterministic on a macOS dev machine that happens to have a
// real Sanctuary root helper publishing a host-wide key at
// CASTLE_WALL_MACOS_AUDIT_PRODUCER_PUBKEY_PATH; this fixture always owns the
// fortress-relative key, never that host file. Do this through the option
// `loadFortressProducerKey` was built to take (see
// `src/castle-wall/runtime/producer-signature.ts`'s `ProducerKeyLoadOptions`)
// rather than by spoofing `process.platform` globally: a global spoof also
// flips `FilesystemStorage`'s descriptor-path strategy onto the Linux
// `/proc/self/fd/<fd>` capability check, which does not exist on Darwin and
// fails every call with ENOENT (the observe CLI's real refresh path opens a
// namespace lock on every invocation this test exercises).
vi.mock("../../../src/castle-wall/runtime/producer-signature.js", async (importOriginal) => {
  const actual = await importOriginal<
    typeof import("../../../src/castle-wall/runtime/producer-signature.js")
  >();
  return {
    ...actual,
    loadFortressProducerKey: (storagePath: string) =>
      actual.loadFortressProducerKey(storagePath, { platform: "linux" }),
  };
});

const SIGNED_AT_MS = 1_777_777_777_777;
const AGENT_UID = 501;
const GATE_UID = 602;

class Capture extends Writable {
  chunks: string[] = [];

  override _write(chunk: unknown, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    cb();
  }

  text(): string {
    return this.chunks.join("");
  }
}

interface CliFortress {
  fortressPath: string;
  recoveryKey: string;
  bootTokenPath: string;
  bootAuditLog: AuditLog;
  producerPrivateKey: Uint8Array;
  subject: string;
}

describe("observe candidates Option A CLI source enumeration", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    vi.restoreAllMocks();
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeCliFortress(): Promise<CliFortress> {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-observe-option-a-cli-"));
    tempDirs.push(fortressPath);

    const masterKey = generateRandomKey();
    const recoveryKey = toBase64url(masterKey);
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    await storage.write("_meta", "recovery-key-hash", stringToBytes(hashToString(masterKey)));

    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const manager = new IdentityManager(storage, masterKey);
    const { storedIdentity } = createIdentity("test-agent", identityEncKey, "passphrase");
    await manager.save(storedIdentity);

    const producerPrivateKey = ed25519.utils.randomPrivateKey();
    await mkdir(join(fortressPath, "policy", "egress"), { recursive: true, mode: 0o700 });
    await writeFile(resolveProducerPubKeyPath(fortressPath), ed25519.getPublicKey(producerPrivateKey));

    const bootToken = generateBootToken();
    const bootTokenPath = join(fortressPath, "boot-token.bin");
    await persistBootToken(bootToken, { path: bootTokenPath });
    const bootAuditPath = safeModeAuditStoragePath(fortressPath, bootToken);
    await mkdir(bootAuditPath, { recursive: true, mode: 0o700 });
    const bootAuditLog = new AuditLog(
      new FilesystemStorage(bootAuditPath),
      deriveSafeModeAuditKey(bootToken),
      { consultSplitBoundary: false },
    );

    return {
      fortressPath,
      recoveryKey,
      bootTokenPath,
      bootAuditLog,
      producerPrivateKey,
      subject: `${fortressIdFromStoragePath(fortressPath)}/uid-${AGENT_UID}`,
    };
  }

  async function appendBootDeniedFlow(
    fortress: CliFortress,
    host: string = "boot-only.example.com",
  ): Promise<void> {
    const timestamp = "2026-07-29T10:00:00.000Z";
    const seq = 17;
    const details = {
      agent_id: "agent-1",
      agent_template: "claude-code",
      dest_host: host,
      dest_ip: "203.0.113.55",
      dest_port: 443,
      dest_protocol: "tcp",
      opaque: false,
      decision_provenance: "default_deny",
    };
    const body = JSON.stringify({
      timestamp,
      layer: "l1",
      operation: "egress_blocked",
      identity_id: fortress.subject,
      result: "failure",
      details,
    });
    const signature = ed25519.sign(
      producerSigningBytes(body, SIGNED_AT_MS, seq),
      fortress.producerPrivateKey,
    );

    await fortress.bootAuditLog.appendCritical({
      timestamp,
      layer: "l1",
      operation: "egress_blocked",
      identity_id: fortress.subject,
      result: "failure",
      details: {
        ...details,
        seq,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(signature),
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
          CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
          CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      },
    });
  }

  it("opens the boot-audit chain and prevents a false empty text listing", async () => {
    const fortress = await makeCliFortress();
    await appendBootDeniedFlow(fortress);

    const out = new Capture();
    const err = new Capture();
    const code = await runObserveCandidates(["--fortress", fortress.fortressPath], {
      out,
      err,
      bootTokenPath: fortress.bootTokenPath,
      env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
    });

    expect(code).toBe(0);
    expect(err.text()).not.toContain("could not read every audit source");
    expect(out.text()).toContain("boot-only.example.com:443");
    expect(out.text()).not.toContain("No candidates.");
  });

  it("emits boot-audit read_ok witness in JSON from the real refresh path", async () => {
    const fortress = await makeCliFortress();
    await appendBootDeniedFlow(fortress);

    const out = new Capture();
    const code = await runObserveCandidates(
      ["--json", "--fortress", fortress.fortressPath],
      {
        out,
        err: new Capture(),
        bootTokenPath: fortress.bootTokenPath,
        env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
      },
    );

    expect(code).toBe(0);
    const payload = JSON.parse(out.text()) as {
      status: string;
      definitive_empty: boolean;
      candidates: Array<{ host: string | null; port: number }>;
      source_reads: Array<{
        source_id: string;
        status: string;
        entries_read?: number;
        candidate_rows?: number;
      }>;
    };
    expect(payload.status).toBe("populated");
    expect(payload.definitive_empty).toBe(false);
    expect(payload.candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ host: "boot-only.example.com", port: 443 }),
      ]),
    );
    const bootRead = payload.source_reads.find((source) => source.source_id === "boot-audit");
    expect(bootRead).toMatchObject({
      source_id: "boot-audit",
      status: "read_ok",
      entries_read: expect.any(Number),
      candidate_rows: 1,
    });
    expect(bootRead?.entries_read).toBeGreaterThan(0);
  });

  it("renders exclusive-mode empty listings as undetermined in text and JSON", async () => {
    const fortress = await makeCliFortress();
    await writeFile(
      exclusiveRoutingMarkerPath(fortress.fortressPath),
      renderExclusiveRoutingMarker({
        agent_uid: AGENT_UID,
        gate_uid: GATE_UID,
        agent_id: "agent-1",
        agent_template: "claude-code",
      }),
      { mode: 0o600 },
    );

    const textOut = new Capture();
    const textCode = await runObserveCandidates(["--fortress", fortress.fortressPath], {
      out: textOut,
      err: new Capture(),
      bootTokenPath: fortress.bootTokenPath,
      env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
    });
    expect(textCode).toBe(0);
    expect(textOut.text()).toContain("UNDETERMINED");
    expect(textOut.text()).toContain(
      "gate denials are structurally unavailable as an observe source",
    );
    expect(textOut.text()).not.toContain("No candidates.");

    const jsonOut = new Capture();
    const jsonCode = await runObserveCandidates(
      ["--json", "--fortress", fortress.fortressPath],
      {
        out: jsonOut,
        err: new Capture(),
        bootTokenPath: fortress.bootTokenPath,
        env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
      },
    );
    expect(jsonCode).toBe(0);
    const payload = JSON.parse(jsonOut.text()) as {
      status: string;
      definitive_empty: boolean;
      gate_denials: { status: string; reason?: string };
      undetermined_reason?: string;
    };
    expect(payload.status).toBe("undetermined");
    expect(payload.definitive_empty).toBe(false);
    expect(payload.gate_denials).toEqual({
      status: "structurally_unavailable",
      reason: "gate denials are structurally unavailable as an observe source",
    });
    expect(payload.undetermined_reason).toBe(
      "gate denials are structurally unavailable as an observe source",
    );
  });

  it("status and promote --all render empty store state as UNDETERMINED in text and JSON when no refresh witness exists", async () => {
    const fortress = await makeCliFortress();
    await appendBootDeniedFlow(fortress);

    const statusTextOut = new Capture();
    const statusTextCode = await runObserveStatus(["--fortress", fortress.fortressPath], {
      out: statusTextOut,
      err: new Capture(),
      bootTokenPath: fortress.bootTokenPath,
      env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
    });
    expect(statusTextCode).toBe(0);
    expect(statusTextOut.text()).toContain("UNDETERMINED");
    expect(statusTextOut.text()).toContain("pending candidates in store: 0");
    expect(statusTextOut.text()).toContain("last refresh: none");
    expect(statusTextOut.text()).not.toContain("Pending candidates: 0\n");

    const statusJsonOut = new Capture();
    const statusJsonCode = await runObserveStatus(
      ["--json", "--fortress", fortress.fortressPath],
      {
        out: statusJsonOut,
        err: new Capture(),
        bootTokenPath: fortress.bootTokenPath,
        env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
      },
    );
    expect(statusJsonCode).toBe(0);
    const statusPayload = JSON.parse(statusJsonOut.text()) as {
      pending_candidates: number;
      candidate_status: string;
      definitive_empty: boolean;
      last_refresh: { status: string };
      undetermined_reason?: string;
    };
    expect(statusPayload.pending_candidates).toBe(0);
    expect(statusPayload.candidate_status).toBe("undetermined");
    expect(statusPayload.definitive_empty).toBe(false);
    expect(statusPayload.last_refresh.status).toBe("none");
    expect(statusPayload.undetermined_reason).toBe("no observe refresh outcome is recorded");

    const promoteTextOut = new Capture();
    const promoteTextCode = await runObservePromote(["--all", "--fortress", fortress.fortressPath], {
      out: promoteTextOut,
      err: new Capture(),
      bootTokenPath: fortress.bootTokenPath,
      env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
    });
    expect(promoteTextCode).toBe(0);
    expect(promoteTextOut.text()).toContain("UNDETERMINED");
    expect(promoteTextOut.text()).toContain("last refresh: none");
    expect(promoteTextOut.text()).not.toContain("Nothing to promote");

    const promoteJsonOut = new Capture();
    const promoteJsonCode = await runObservePromote(
      ["--json", "--all", "--fortress", fortress.fortressPath],
      {
        out: promoteJsonOut,
        err: new Capture(),
        bootTokenPath: fortress.bootTokenPath,
        env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
      },
    );
    expect(promoteJsonCode).toBe(0);
    const promotePayload = JSON.parse(promoteJsonOut.text()) as {
      status: string;
      nothing_to_promote: boolean;
      pending_candidates: number;
      last_refresh: { status: string };
      undetermined_reason?: string;
    };
    expect(promotePayload.status).toBe("undetermined");
    expect(promotePayload.nothing_to_promote).toBe(false);
    expect(promotePayload.pending_candidates).toBe(0);
    expect(promotePayload.last_refresh.status).toBe("none");
    expect(promotePayload.undetermined_reason).toBe("no observe refresh outcome is recorded");
  });

  it("status and promote --all may claim verified empty in text and JSON only after an all-read_ok refresh witness", async () => {
    const fortress = await makeCliFortress();
    const refreshOut = new Capture();
    const refreshCode = await runObserveCandidates(["--fortress", fortress.fortressPath], {
      out: refreshOut,
      err: new Capture(),
      bootTokenPath: fortress.bootTokenPath,
      env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
    });
    expect(refreshCode).toBe(0);
    expect(refreshOut.text()).toContain("No candidates.");

    const statusTextOut = new Capture();
    const statusTextCode = await runObserveStatus(["--fortress", fortress.fortressPath], {
      out: statusTextOut,
      err: new Capture(),
      bootTokenPath: fortress.bootTokenPath,
      env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
    });
    expect(statusTextCode).toBe(0);
    expect(statusTextOut.text()).toContain("Pending candidates in store: 0");
    expect(statusTextOut.text()).toContain("all sources read_ok");
    expect(statusTextOut.text()).not.toContain("UNDETERMINED");

    const statusJsonOut = new Capture();
    const statusJsonCode = await runObserveStatus(
      ["--json", "--fortress", fortress.fortressPath],
      {
        out: statusJsonOut,
        err: new Capture(),
        bootTokenPath: fortress.bootTokenPath,
        env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
      },
    );
    expect(statusJsonCode).toBe(0);
    const statusPayload = JSON.parse(statusJsonOut.text()) as {
      candidate_status: string;
      definitive_empty: boolean;
      last_refresh: { status: string; source_reads: Array<{ status: string }> };
    };
    expect(statusPayload.candidate_status).toBe("empty_verified");
    expect(statusPayload.definitive_empty).toBe(true);
    expect(statusPayload.last_refresh.status).toBe("refreshed");
    expect(statusPayload.last_refresh.source_reads.every((source) => source.status === "read_ok")).toBe(true);

    const promoteTextOut = new Capture();
    const promoteTextCode = await runObservePromote(["--all", "--fortress", fortress.fortressPath], {
      out: promoteTextOut,
      err: new Capture(),
      bootTokenPath: fortress.bootTokenPath,
      env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
    });
    expect(promoteTextCode).toBe(0);
    expect(promoteTextOut.text()).toContain("Nothing to promote");
    expect(promoteTextOut.text()).toContain("all sources read_ok");
    expect(promoteTextOut.text()).not.toContain("UNDETERMINED");

    const promoteJsonOut = new Capture();
    const promoteJsonCode = await runObservePromote(
      ["--json", "--all", "--fortress", fortress.fortressPath],
      {
        out: promoteJsonOut,
        err: new Capture(),
        bootTokenPath: fortress.bootTokenPath,
        env: { SANCTUARY_RECOVERY_KEY: fortress.recoveryKey },
      },
    );
    expect(promoteJsonCode).toBe(0);
    const promotePayload = JSON.parse(promoteJsonOut.text()) as {
      status: string;
      nothing_to_promote: boolean;
      last_refresh: { status: string; source_reads: Array<{ status: string }> };
    };
    expect(promotePayload.status).toBe("nothing_to_promote_verified");
    expect(promotePayload.nothing_to_promote).toBe(true);
    expect(promotePayload.last_refresh.status).toBe("refreshed");
    expect(promotePayload.last_refresh.source_reads.every((source) => source.status === "read_ok")).toBe(true);
  });
});
