/**
 * CAPABILITY (STATE-DISCLOSE-UNATTRIB-01), CLI half: `sanctuary
 * state_disclose_unattributed` is a WIRED consumer of the disclosure surface,
 * not a module with tests of its own.
 *
 * This is the test AGENTS.md assurance rule 4 asks for. It seeds a real
 * keychain-free fortress on disk, plants the one persisted shape whose writer
 * cannot be established, and drives the shipped command function end to end, so
 * a change that leaves the surface intact while unhooking the operator's route
 * to it reds here rather than passing.
 *
 * Three properties, each with its own discriminator:
 *
 *   - APPROVED: the command exits 0, the content reaches the operator, and the
 *     output is LABELLED - the notice appears above and below the content, so a
 *     reader who scrolls a long value past the top of the terminal still sees
 *     it;
 *   - DENIED: an approval channel that says no produces a non-zero exit and NO
 *     content on stdout. Asserting the absence of the content, not merely the
 *     exit code, is what distinguishes a real gate from one that prints first
 *     and reports later;
 *   - the subcommand is registered, so shell completion and the dispatcher
 *     agree the verb exists.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";

import { runStateDiscloseUnattributedCommand } from "../../src/cli/state-disclose.js";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";
import { UNATTRIBUTED_DISCLOSURE_NOTICE } from "../../src/cognitive/state-store.js";
import { UNATTRIBUTED_DISCLOSURE_OPERATION } from "../../src/cognitive/unattributed-disclosure.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hashToString } from "../../src/core/hashing.js";
import { deriveNamespaceKey } from "../../src/core/key-derivation.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { ApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type { ApprovalResponse } from "../../src/principal-policy/types.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StateEntry } from "../../src/cognitive/state-store.js";
import { runInit as runInitRaw, type InitOptions } from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

const NAMESPACE = "memories";
const KEY = "orphaned";
const CONTENT = "the-owner-must-still-reach-this-through-the-cli";

// ── Keychain-free fortress seeding (mirrors test/cli/file-grant-revoke-error-handling.test.ts) ──

function unescapeSecurityToken(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}

function readSecurityToken(input: string | undefined, flag: string): string {
  const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = input?.match(
    new RegExp(`${escapedFlag} "((?:[^"\\\\]|\\\\.)*)"`)
  );
  return match ? unescapeSecurityToken(match[1]!) : "";
}

function makeRecoveryKeychainMock(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
} {
  const stored = new Map<string, string>();
  const keyFor = (account: string, service: string): string =>
    `${account}:${service}`;
  const exec = async (
    cmd: string,
    args: string[],
    input?: string
  ): Promise<ExecResult> => {
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    if (args[0] === "-i") {
      stored.set(
        keyFor(readSecurityToken(input, "-a"), readSecurityToken(input, "-s")),
        readSecurityToken(input, "-w")
      );
      return { stdout: "", stderr: "", code: 0 };
    }
    if (args[0] === "find-generic-password") {
      const account = args[args.indexOf("-a") + 1] ?? "";
      const service = args[args.indexOf("-s") + 1] ?? "";
      const value = stored.get(keyFor(account, service));
      if (value) return { stdout: value + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "not found", code: 44 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };
  return { exec };
}

async function runInit(
  options: InitOptions
): Promise<Awaited<ReturnType<typeof runInitRaw>>> {
  const keychain = makeRecoveryKeychainMock();
  return runInitRaw(options, {
    recoveryKeychain: {
      home: "/tmp/sanctuary-test-home",
      platformOverride: "darwin",
      exec: keychain.exec,
    },
  });
}

function extractRecoveryKey(fileContent: string): string {
  const keyLine = fileContent
    .split("\n")
    .map((l) => l.trim())
    .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l));
  if (!keyLine) throw new Error("recovery key not found");
  return keyLine;
}

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

class FixedChannel implements ApprovalChannel {
  calls = 0;
  constructor(private readonly decision: "approve" | "deny") {}
  async requestApproval(): Promise<ApprovalResponse> {
    this.calls += 1;
    return {
      decision: this.decision,
      decided_at: "2026-08-18T00:00:04.000Z",
      decided_by: "human",
    };
  }
}

describe("sanctuary state_disclose_unattributed (CLI)", () => {
  let tmp: string;
  let fortressPath: string;
  let recoveryKey: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-state-disclose-cli-"));
    fortressPath = join(tmp, "fortress");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: false,
    });
    recoveryKey = extractRecoveryKey(
      await readFile(result.recoveryKeyDisclosurePath, "utf-8")
    );

    // Plant the one persisted shape whose writer cannot be established: a
    // legacy (schema-1) entry whose `kid` resolves to no stored identity and to
    // no authenticated registry key.
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: fortressPath,
    });
    const plaintext = stringToBytes(CONTENT);
    const entry: StateEntry = {
      v: 1,
      payload: encrypt(plaintext, deriveNamespaceKey(masterKey, NAMESPACE)),
      ver: 1,
      // ED25519_SIGNATURE_BYTES = 64; the value is irrelevant because no key
      // resolves for `kid`, which is the point of this fixture.
      sig: toBase64url(new Uint8Array(64)),
      kid: "sanctuary-no-such-writer-identity",
      integrity_hash: hashToString(plaintext),
      metadata: { written_at: "2026-08-18T00:00:05.000Z" },
    };
    await storage.write(NAMESPACE, KEY, stringToBytes(JSON.stringify(entry)));
    masterKey.fill(0);
  });

  afterEach(async () => {
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort temp cleanup
    }
  });

  it("registers the subcommand so the dispatcher and completion agree it exists", () => {
    expect([...TOP_LEVEL_SUBCOMMANDS]).toContain(
      UNATTRIBUTED_DISCLOSURE_OPERATION
    );
  });

  it("discloses the content, labelled above and below, and audits the call", async () => {
    process.env.SANCTUARY_RECOVERY_KEY = recoveryKey;
    const out = new StringWritable();
    const err = new StringWritable();
    const channel = new FixedChannel("approve");

    const code = await runStateDiscloseUnattributedCommand({
      argv: [
        "--fortress",
        fortressPath,
        "--namespace",
        NAMESPACE,
        "--key",
        KEY,
      ],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      approvalChannel: channel,
    });

    expect(code).toBe(0);
    expect(channel.calls).toBe(1);
    expect(out.text).toContain(CONTENT);
    expect(out.text).toContain("writer:    not_established");
    // Labelled at BOTH ends: one occurrence would be satisfied by a banner an
    // operator scrolls past.
    expect(out.text.split(UNATTRIBUTED_DISCLOSURE_NOTICE).length - 1).toBe(2);

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      recoveryKey,
      storagePathHint: fortressPath,
    });
    const auditLog = new AuditLog(storage, masterKey);
    const audit = await auditLog.query({
      operation_type: UNATTRIBUTED_DISCLOSURE_OPERATION,
    });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details).toMatchObject({
      namespace: NAMESPACE,
      key: KEY,
    });
    masterKey.fill(0);
  });

  it("discloses nothing when the Tier-1 approval is refused", async () => {
    process.env.SANCTUARY_RECOVERY_KEY = recoveryKey;
    const out = new StringWritable();
    const err = new StringWritable();
    const channel = new FixedChannel("deny");

    const code = await runStateDiscloseUnattributedCommand({
      argv: [
        "--fortress",
        fortressPath,
        "--namespace",
        NAMESPACE,
        "--key",
        KEY,
      ],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
      approvalChannel: channel,
    });

    expect(code).not.toBe(0);
    expect(channel.calls).toBe(1);
    // The content itself, not just the exit code: a gate that renders before it
    // reports would pass an exit-code-only assertion.
    expect(out.text).not.toContain(CONTENT);
    expect(err.text).toContain("Denied");
  });
});
