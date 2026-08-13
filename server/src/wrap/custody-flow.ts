/**
 * Sanctuary wrap — custody establishment flow
 *
 * The interactive-CLI face of the unified custody scheme
 * (core/master-custody.ts) used by `sanctuary wrap`:
 *
 *  - Fresh fortress: establish one master, wrapped under the resolved
 *    passphrase, then mint a recovery key (a wrap of that same master) and
 *    force capture + re-entry verification on interactive runs.
 *  - Legacy fortress: migrate in place on this unlock (same master, no data
 *    re-encryption), then complete custody by minting the recovery wrap the
 *    legacy scheme never had — the 2026-06-12 incident cure.
 *  - Recovery-key-custody fortress (created by `sanctuary init`): enroll
 *    the passphrase as a NEW wrap by first unlocking with the recovery key
 *    (interactive prompt) — never by deriving a parallel master.
 *
 * Every degraded decision (headless install, unverified capture) is audited
 * as a distinct path, never a silent relaxation (F6/F13).
 */

import { dirname, join } from "node:path";
import { createInterface } from "node:readline/promises";

import { FilesystemStorage } from "../storage/filesystem.js";
import { AuditLog } from "../operational/audit-log.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  establishMaster,
  mintRecoveryWrap,
  prepareRecoveryWrap,
  verifyRecoveryWrapByReentry,
  wrapMasterWithPassphrase,
  writeCustodyEnvelope,
  readCustodyEnvelope,
  CustodyUnlockError,
  type CustodyEnvelope,
  type EstablishMasterResult,
} from "../core/master-custody.js";
import {
  discloseRecoveryKey,
  preflightRecoveryKeyOutputFile,
  verifyRecoveryKeyReentry,
  writeRecoveryKeyFile,
  type DisclosureIo,
} from "./recovery-key-disclosure.js";

export interface WrapCustodyOptions {
  storagePath: string;
  /** The resolved fortress passphrase (always present on the wrap path). */
  passphrase: string;
  /** True when an operator is present at a TTY. */
  interactive: boolean;
  /** Test seam: stdin/stderr streams for prompts. */
  io?: DisclosureIo;
  /** Stage recovery outside the fortress without printing it to an agent transcript. */
  agentGuided?: boolean;
  /** Test seam: simulate a destination race after preflight, before O_EXCL. */
  beforeAgentRecoveryFileCreate?: () => void | Promise<void>;
}

export function agentGuidedRecoveryOutputPath(
  storagePath: string,
  fortressId: string = fortressIdFromStoragePath(storagePath),
): string {
  return join(
    dirname(storagePath),
    "Sanctuary Recovery",
    `${fortressId}-recovery-key.txt`,
  );
}

export interface WrapCustodyResult {
  masterKey: Uint8Array;
  /** Null when migration was deferred (unverifiable existing data). */
  envelope: CustodyEnvelope | null;
  /** Disclosed this run (newly minted recovery key), if any. */
  mintedRecoveryKey: boolean;
  origin: EstablishMasterResult["origin"] | "recovery-unlock-enroll";
}

async function promptLine(
  question: string,
  io?: DisclosureIo
): Promise<string> {
  const input = io?.input ?? process.stdin;
  const output = io?.output ?? process.stderr;
  const rl = createInterface({ input, output });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

/**
 * Establish (or migrate, or enroll into) the fortress's custody for the
 * wrap path. Returns the unlocked master and the current envelope.
 */
export async function establishWrapCustody(
  opts: WrapCustodyOptions
): Promise<WrapCustodyResult> {
  const storage = new FilesystemStorage(join(opts.storagePath, "state"));
  const installMode = opts.interactive ? "interactive" : "headless";

  let result: EstablishMasterResult;
  let origin: WrapCustodyResult["origin"];
  try {
    result = await establishMaster({
      storage,
      passphrase: opts.passphrase,
      firstRun: { installMode, mintRecoveryKey: false },
      storagePathHint: opts.storagePath,
    });
    origin = result.origin;
  } catch (err) {
    if (!(err instanceof CustodyUnlockError)) throw err;

    // The passphrase did not unlock. If this fortress's custody is
    // recovery-key-based (created by `sanctuary init`, no passphrase wrap
    // enrolled yet), the correct move is to unlock with the recovery key
    // and ADD the passphrase as a new wrap — never to derive a parallel
    // master. Anything else stays fail-closed.
    const envelope = await readCustodyEnvelope(storage);
    const recoveryCustody =
      (envelope !== null &&
        envelope.wraps.some((w) => w.type === "recovery-key") &&
        !envelope.wraps.some((w) => w.type === "passphrase")) ||
      (envelope === null &&
        (await storage.read("_meta", "recovery-key-hash")) !== null &&
        (await storage.read("_meta", "key-params")) === null);
    if (!recoveryCustody || !opts.interactive) {
      throw err;
    }

    const entered = await promptLine(
      "\nThis fortress was created with a recovery key and has no passphrase enrolled.\n" +
        "Enter the recovery key to unlock it and enroll this passphrase: ",
      opts.io
    );
    result = await establishMaster({
      storage,
      recoveryKey: entered,
      storagePathHint: opts.storagePath,
    });
    if (result.envelope) {
      const passphraseWrap = await wrapMasterWithPassphrase(
        result.masterKey,
        opts.passphrase,
        { verified: true }
      );
      result.envelope = await writeCustodyEnvelope(
        storage,
        {
          ...result.envelope,
          wraps: [...result.envelope.wraps, passphraseWrap],
        },
        result.masterKey
      );
      origin = "recovery-unlock-enroll";
    } else {
      // Migration was deferred (unverifiable existing data) — the recovery
      // key unlocked legacy-style; no envelope exists to enroll into yet.
      origin = result.origin;
    }
  }

  let envelope = result.envelope;
  const masterKey = result.masterKey;
  const auditLog = new AuditLog(storage, masterKey);
  const fortressId = fortressIdFromStoragePath(opts.storagePath);

  if (origin !== "envelope") {
    await auditLog.appendCritical({
      layer: "l2",
      operation:
        origin === "first-run"
          ? "custody_envelope_created"
          : origin === "recovery-unlock-enroll"
            ? "custody_wrap_added"
            : origin === "legacy-deferred"
              ? "custody_migration_deferred"
              : "custody_legacy_migrated",
      identity_id: fortressId,
      result: "success",
      details: envelope
        ? {
            install_mode: envelope.install_mode,
            wrap_types: envelope.wraps.map((w) => w.type),
            verified_wraps: envelope.wraps.filter((w) => w.verified).length,
            origin,
            source: "sanctuary-wrap",
          }
        : {
            origin,
            source: "sanctuary-wrap",
            reason:
              "existing data could not be evidence-checked against this master; envelope not written",
          },
    });
  }

  if (!envelope) {
    // Migration deferred: no envelope to mint into. Loud, honest, no
    // silent custody claims — the fortress stays legacy until verifiable
    // evidence exists (e.g. after the first identity is created).
    (opts.io?.output ?? process.stderr).write(
      "\n  Note: this fortress's custody migration was DEFERRED — its existing data\n" +
        "  could not be verified against the supplied credential, so no recovery\n" +
        "  key was issued this run. Re-run wrap after the fortress has been used\n" +
        "  (a stored identity gives migration its verification evidence).\n"
    );
    await auditLog.flush();
    return { masterKey, envelope: null, mintedRecoveryKey: false, origin };
  }

  // Complete custody: every wrap-managed fortress must hold a recovery-key
  // wrap of the one true master, captured by the operator. This is the step
  // that makes a passphrase fortress actually recoverable.
  let mintedRecoveryKey = false;
  if (!envelope.wraps.some((w) => w.type === "recovery-key")) {
    const agentRecoveryPath = opts.agentGuided
      ? agentGuidedRecoveryOutputPath(opts.storagePath, fortressId)
      : undefined;
    if (agentRecoveryPath !== undefined) {
      // Fail before minting: a pre-existing destination must never leave the
      // new recovery wrap with no safely handed-off key.
      await preflightRecoveryKeyOutputFile(agentRecoveryPath);
    }
    let disclosure: { filePath: string; fileWritten: boolean };
    if (agentRecoveryPath !== undefined) {
      const prepared = prepareRecoveryWrap(envelope, masterKey);
      // The custom writer is O_EXCL + O_NOFOLLOW. Commit the envelope only
      // after that atomic handoff succeeds; if an attacker wins the path race,
      // the fortress retains no orphaned recovery wrap.
      await opts.beforeAgentRecoveryFileCreate?.();
      const written = await writeRecoveryKeyFile({
        storagePath: opts.storagePath,
        recoveryKeyFilePath: agentRecoveryPath,
        recoveryKey: prepared.recoveryKey,
        fortressId,
      });
      envelope = await writeCustodyEnvelope(storage, prepared.envelope, masterKey);
      disclosure = { filePath: written.filePath, fileWritten: written.written };
    } else {
      const minted = await mintRecoveryWrap(storage, envelope, masterKey);
      envelope = minted.envelope;
      const result = await discloseRecoveryKey({
        recoveryKey: minted.recoveryKey,
        storagePath: opts.storagePath,
        fortressId,
        mode: "no-confirm", // re-entry verification below replaces the Y/N prompt
        ...(opts.io ? { io: opts.io } : {}),
      });
      disclosure = { filePath: result.filePath, fileWritten: result.fileWritten };
    }
    mintedRecoveryKey = true;
    if (agentRecoveryPath !== undefined) {
      (opts.io?.output ?? process.stderr).write(
        `\n  Recovery material staged locally for the operator at:\n` +
          `    ${disclosure.filePath}\n` +
          `  The installing agent must not read this file. The operator should move it\n` +
          `  into a password manager in a private local session, then delete the file.\n`,
      );
    }
    if (!disclosure.fileWritten) {
      // A recovery-key.txt already existed (a stale artifact from a legacy
      // path — the misleading-file trap from the 2026-06-12 incident).
      // Single-issuance protects the existing file; make the mismatch LOUD.
      (opts.io?.output ?? process.stderr).write(
        "\n  WARNING: an existing recovery-key.txt was found and was NOT overwritten.\n" +
          "  Its key is OUTDATED and does not unlock this fortress. The key printed\n" +
          "  in the banner above is the real one — save THAT, then delete the stale file.\n"
      );
      await auditLog.appendCritical({
        layer: "l2",
        operation: "custody_stale_recovery_file_detected",
        identity_id: fortressId,
        result: "failure",
        details: { path: disclosure.filePath },
      });
    }

    if (opts.interactive) {
      const envelopeForReentry = envelope;
      await verifyRecoveryKeyReentry({
        check: async (entered) => {
          try {
            envelope = await verifyRecoveryWrapByReentry(
              storage,
              envelopeForReentry,
              entered
            );
            return true;
          } catch {
            return false;
          }
        },
        ...(opts.io ? { io: opts.io } : {}),
      });
    } else {
      await auditLog.appendCritical({
        layer: "l2",
        operation: "custody_headless_install",
        identity_id: fortressId,
        result: "success",
        details: {
          source: "sanctuary-wrap",
          reason: "non-interactive recovery-key capture (unverified)",
        },
      });
    }

    await auditLog.appendCritical({
      layer: "l2",
      operation: "custody_wrap_added",
      identity_id: fortressId,
      result: "success",
      details: {
        wrap_type: "recovery-key",
        verified: envelope.wraps.find((w) => w.type === "recovery-key")
          ?.verified ?? false,
      },
    });
  }

  await auditLog.flush();
  return { masterKey, envelope, mintedRecoveryKey, origin };
}
