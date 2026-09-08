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
 * The credential arrives already resolved, from the ONE resolver in
 * `wrap/custody-credential.ts`, and may be a passphrase, a recovery key, or the
 * fortress's enrolled OS-keyring custody factor. This module does not choose or
 * mint credentials; choosing is the resolver's job and minting is reachable
 * only through it.
 *
 * Every degraded decision (headless install, unverified capture) is audited
 * as a distinct path, never a silent relaxation (F6/F13).
 */

import { basename, dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";

import { FilesystemStorage } from "../storage/filesystem.js";
import type { CrossProcessLockLease } from "../storage/cross-process-lock.js";
import { readFileCustody } from "../storage/custody-fs.js";
import { AuditLog } from "../operational/audit-log.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import {
  constantTimeEqual,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import {
  establishMaster,
  mintRecoveryWrap,
  prepareRecoveryWrap,
  prepareRecoveryWrapWithKey,
  verifyRecoveryWrapByReentry,
  wrapMasterWithPassphrase,
  writeCustodyEnvelope,
  readCustodyEnvelope,
  acquireFortressMasterWriteBarrier,
  CustodyUnlockError,
  type CustodyEnvelope,
  type EstablishMasterResult,
  withCustodyWriteLock,
} from "../core/master-custody.js";
import type { MasterWriteBarrierLease } from "../storage/cross-process-lock.js";
import {
  AGENT_GUIDED_RECOVERY_DIRNAME,
  RECOVERY_OUT_ENV_VAR,
  discloseRecoveryKey,
  preflightRecoveryKeyOutputFile,
  verifyRecoveryKeyReentry,
  writeRecoveryKeyFile,
  type DisclosureIo,
} from "./recovery-key-disclosure.js";

/**
 * The credential custody establishment opens the fortress with, as produced by
 * the shared resolver (`wrap/custody-credential.ts`). Three kinds, because a
 * fortress created by `sanctuary init` holds a recovery-key wrap and an
 * OS-keyring custody wrap and NO passphrase wrap: a passphrase-only parameter
 * here is what forced `protect` to mint a passphrase that could not open it.
 */
export type WrapCustodyCredential =
  | { kind: "passphrase"; value: string }
  | { kind: "recovery-key"; value: string }
  | { kind: "keychain-key"; value: Uint8Array };

interface WrapCustodyOptionsBase {
  storagePath: string;
  /** True when an operator is present at a TTY. */
  interactive: boolean;
  /** Test seam: stdin/stderr streams for prompts. */
  io?: DisclosureIo;
  /** Stage recovery outside the fortress without printing it to an agent transcript. */
  agentGuided?: boolean;
  /** Test seam: simulate a destination race after preflight, before O_EXCL. */
  beforeAgentRecoveryFileCreate?: () => void | Promise<void>;
  /** Test seam: simulate a crash after staging succeeds, before envelope commit. */
  afterAgentRecoveryFileCreate?: () => void | Promise<void>;
  /**
   * Persist an explicit operator-supplied passphrase only after custody has
   * positively authenticated it and all envelope writes have completed.
   * This callback runs while the custody write lock is still held.
   */
  persistAuthenticatedPassphrase?: (
    value: string,
  ) => Promise<{ location: string; source: string }>;
}

/**
 * Exactly one credential shape reaches custody establishment. Expressed as a
 * union rather than two optional fields so "neither supplied" and "both
 * supplied" are both unrepresentable at the type level (AGENTS.md rule 3: a
 * dependency that gates a security property is required, not optional).
 * `passphrase` is the legacy spelling of `credential: { kind: "passphrase" }`.
 */
export type WrapCustodyOptions = WrapCustodyOptionsBase &
  (
    | { passphrase: string; credential?: undefined }
    | { credential: WrapCustodyCredential; passphrase?: undefined }
  );

/**
 * Project the credential union onto `establishMaster`'s parameter names. One
 * place, so a new credential kind cannot be silently dropped by a call site
 * that only knew about passphrases.
 */
function credentialFields(
  credential: WrapCustodyCredential,
): { passphrase: string } | { recoveryKey: string } | { keychainKey: Uint8Array } {
  switch (credential.kind) {
    case "passphrase":
      return { passphrase: credential.value };
    case "recovery-key":
      return { recoveryKey: credential.value };
    case "keychain-key":
      return { keychainKey: credential.value };
  }
}

/**
 * The staged recovery destination beside a fortress, never inside it.
 *
 * `storagePath` is normalized here as well as at every caller's own
 * resolution point (`resolveFortressPath` in wrap/init.ts) because the whole
 * containment property rests on `dirname`: for `/a/b/c/..` the lexical
 * dirname is `/a/b/c`, which is INSIDE the `/a/b` fortress the key protects,
 * while the normalized dirname is `/a`. A caller that hands this function an
 * un-normalized path must not be able to relocate the plaintext recovery key
 * into the fortress, so the normalization lives at both ends.
 *
 * Must agree with `resolveFortressPath` in server/src/wrap/init.ts about what
 * normalization means (lexical `resolve`, deliberately not realpath: the
 * fortress id is derived from the same string).
 */
export function agentGuidedRecoveryOutputPath(
  storagePath: string,
  fortressId: string = fortressIdFromStoragePath(storagePath),
): string {
  return join(
    // Must match AGENT_GUIDED_RECOVERY_DIRNAME in
    // server/src/wrap/recovery-key-disclosure.ts: the preflight there decides
    // whether it may tighten a destination's parent by comparing that exact
    // basename, so a literal restated here would silently unlock the
    // mode-change branch for a directory named the same by coincidence, or
    // lock it out for the real staging directory.
    dirname(resolve(storagePath)),
    AGENT_GUIDED_RECOVERY_DIRNAME,
    `${fortressId}-recovery-key.txt`,
  );
}

/**
 * True when the default staging destination would land INSIDE the fortress it
 * protects, which happens for exactly one shape: a fortress directory that is
 * itself named `Sanctuary Recovery`, so `dirname(fortress)/Sanctuary Recovery`
 * resolves back onto the fortress.
 *
 * This is a NAME COLLISION, not an operator error, and it is an availability
 * defect rather than a containment one: the containment guard correctly
 * refuses the destination, but the operator passed no `--recovery-out` and so
 * reads a refusal about a path they never chose. Callers check this before
 * minting any custody material and refuse with the remedy instead.
 */
export function agentGuidedRecoveryDefaultCollidesWithFortress(
  storagePath: string,
): boolean {
  const fortress = resolve(storagePath);
  return resolve(dirname(fortress), AGENT_GUIDED_RECOVERY_DIRNAME) === fortress;
}

/**
 * The ONE remedy sentence for that collision, so `sanctuary init` and the
 * wrap-first mint cannot tell the operator two different things about the
 * same directory name. Both callers check
 * `agentGuidedRecoveryDefaultCollidesWithFortress` before minting and refuse
 * with this text; only the remedy clause differs, because `init` accepts
 * `--recovery-out` and `protect` does not (parseWrapArgs rejects unknown
 * flags), so a wrap-first mint must be sent through `init` rather than told
 * to pass a flag it cannot pass.
 *
 * Must match the callers in `runInit` (server/src/wrap/init.ts) and
 * `establishWrapCustody` below, which import this rather than re-spelling
 * the sentence.
 */
export function agentGuidedRecoveryDefaultCollisionMessage(
  storagePath: string,
  caller: "init" | "wrap",
): string {
  const fortress = resolve(storagePath);
  const remedy =
    caller === "init"
      ? `Re-run with --recovery-out <path> (or set ${RECOVERY_OUT_ENV_VAR}) naming a ` +
        `destination outside ${fortress}, or choose a different --fortress directory name`
      : `Run \`sanctuary init --fortress ${fortress} --recovery-out <path>\` first (or set ` +
        `${RECOVERY_OUT_ENV_VAR} for init) naming a destination outside the fortress, then ` +
        "protect; or choose a different --fortress directory name. protect itself accepts " +
        "no --recovery-out flag";
  return (
    `the fortress directory is named "${basename(fortress)}", which is the same ` +
    "name Sanctuary uses for its default recovery staging directory beside the fortress, so " +
    `the default destination would land inside the fortress the key protects. ${remedy}`
  );
}

export interface WrapCustodyResult {
  masterKey: Uint8Array;
  /** Null when migration was deferred (unverifiable existing data). */
  envelope: CustodyEnvelope | null;
  /** Disclosed this run (newly minted recovery key), if any. */
  mintedRecoveryKey: boolean;
  origin: EstablishMasterResult["origin"] | "recovery-unlock-enroll";
  /** Present only when persistAuthenticatedPassphrase completed successfully. */
  persistedPassphrase?: { location: string; source: string };
}

const AGENT_RECOVERY_RECEIPT_PURPOSE = "agent-guided-recovery-staging-v1";
const RECOVERY_KEY_VALUE = /^[A-Za-z0-9_-]{43}$/;

function stagedRecoveryReceipt(
  envelope: CustodyEnvelope,
  masterKey: Uint8Array,
  fortressId: string,
  recoveryKey: string,
): string {
  const receiptKey = derivePurposeKey(masterKey, AGENT_RECOVERY_RECEIPT_PURPOSE);
  try {
    return toBase64url(hmacSha256(
      receiptKey,
      stringToBytes(`${fortressId}\0${envelope.mac}\0${recoveryKey}`),
    ));
  } finally {
    receiptKey.fill(0);
  }
}

function valueAfterLabel(content: string, label: string): string | null {
  const lines = content.split(/\r?\n/);
  const index = lines.indexOf(label);
  return index >= 0 ? lines[index + 1]?.trim() ?? null : null;
}

async function resumeAuthenticatedAgentRecoveryFile(input: {
  filePath: string;
  envelope: CustodyEnvelope;
  masterKey: Uint8Array;
  fortressId: string;
}): Promise<CustodyEnvelope | null> {
  let content: string;
  try {
    const uid = process.getuid?.();
    content = await readFileCustody(input.filePath, {
      encoding: "utf8",
      mode: { exact: 0o600 },
      ...(uid === undefined ? {} : {
        uid,
        parent: { uid, mode: { rejectGroupOrOther: true } },
      }),
      verifyPathIdentity: true,
    });
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }

  const recoveryKey = valueAfterLabel(content, "Recovery key:");
  const receipt = valueAfterLabel(content, "Recovery staging receipt:");
  if (!recoveryKey || !receipt || !RECOVERY_KEY_VALUE.test(recoveryKey)) {
    throw new Error(
      `Existing agent-guided recovery file is not an authenticated interrupted handoff: ${input.filePath}`,
    );
  }
  const expected = stagedRecoveryReceipt(
    input.envelope,
    input.masterKey,
    input.fortressId,
    recoveryKey,
  );
  let receiptMatches: boolean;
  try {
    receiptMatches = constantTimeEqual(fromBase64url(receipt), fromBase64url(expected));
  } catch {
    receiptMatches = false;
  }
  if (!receiptMatches) {
    throw new Error(
      `Existing agent-guided recovery file is not an authenticated interrupted handoff: ${input.filePath}`,
    );
  }
  const prepared = prepareRecoveryWrapWithKey(
    input.envelope,
    input.masterKey,
    recoveryKey,
  );
  return prepared.envelope;
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
  // Same pre-mint availability check `sanctuary init` runs, for the same
  // reason: a fortress directory named `Sanctuary Recovery` makes the DEFAULT
  // staging path resolve back inside the fortress, and the containment guard
  // then refuses a destination the operator never chose. It runs BEFORE the
  // write barrier and before `establishMaster`, so a colliding name leaves no
  // passphrase envelope behind for a retry to trip over, and ONLY when this
  // invocation would actually stage there: the same predicate the staging
  // step below applies (staged-beside-fortress AND no recovery-key wrap yet).
  // A fortress that already holds a recovery wrap (for example after the
  // `init --recovery-out` route this sentence names) is not refused, or the
  // sentence's own remedy would dead-end. The envelope read is read-only and
  // fails closed on an unreadable envelope, like every other reader.
  // Failure mode from the outside: a refusal that names a path appearing
  // nowhere in the command the operator typed.
  if (
    (opts.agentGuided || !opts.interactive) &&
    agentGuidedRecoveryDefaultCollidesWithFortress(opts.storagePath)
  ) {
    const existing = await readCustodyEnvelope(storage);
    const hasRecoveryWrap =
      existing !== null && existing.wraps.some((w) => w.type === "recovery-key");
    if (!hasRecoveryWrap) {
      throw new Error(
        agentGuidedRecoveryDefaultCollisionMessage(opts.storagePath, "wrap"),
      );
    }
  }
  // S2: acquire the shared master-rotation barrier BEFORE the custody write
  // lock, matching rotateMaster's (barrier -> custody-lock) order, and hand it
  // to establishMaster as `heldBarrier` so it never takes a SECOND barrier under
  // the custody lock. Taking the custody lock first and letting establishMaster
  // acquire the barrier under it is the opposing (custody-lock -> barrier) order
  // that deadlocks a concurrent rotate-master until both bounded locks
  // force-abort — which can knock rotation off its ceremony. Fail closed on an
  // environmental barrier loss: establishing custody is a WRITE.
  const barrier = await acquireFortressMasterWriteBarrier(storage);
  try {
    return await withCustodyWriteLock(
      storage,
      (lease) => establishWrapCustodyLocked(opts, storage, lease, barrier),
      { metadata: { owner: "wrap-custody" } },
    );
  } finally {
    await barrier.release();
  }
}

async function establishWrapCustodyLocked(
  opts: WrapCustodyOptions,
  storage: FilesystemStorage,
  lease: CrossProcessLockLease,
  barrier: MasterWriteBarrierLease,
): Promise<WrapCustodyResult> {
  const installMode = opts.interactive ? "interactive" : "headless";
  const credential: WrapCustodyCredential =
    opts.credential ?? { kind: "passphrase", value: opts.passphrase! };

  let result: EstablishMasterResult;
  let origin: WrapCustodyResult["origin"];
  try {
    result = await establishMaster({
      storage,
      ...credentialFields(credential),
      // `firstRun` CREATES custody. Only a passphrase may do that: a
      // recovery-key or OS-keyring credential exists because a fortress
      // already does, so reaching first-run with one means the envelope went
      // missing under us, and inventing custody there would strand the real
      // one. Those kinds fail closed instead.
      ...(credential.kind === "passphrase"
        ? { firstRun: { installMode, mintRecoveryKey: false } }
        : {}),
      storagePathHint: opts.storagePath,
      // Reuse the caller-held barrier; do not acquire a second one (S2).
      heldBarrier: barrier,
    });
    origin = result.origin;
  } catch (err) {
    if (!(err instanceof CustodyUnlockError)) throw err;
    // The interactive recovery-key enrolment below ADDS a passphrase wrap, so
    // it is meaningful only when a passphrase is what failed to unlock.
    if (credential.kind !== "passphrase") throw err;

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
      // Reuse the caller-held barrier; do not acquire a second one (S2).
      heldBarrier: barrier,
    });
    if (result.envelope) {
      const passphraseWrap = await wrapMasterWithPassphrase(
        result.masterKey,
        credential.value,
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
    // ordinary noninteractive protect/wrap also stages recovery outside the
    // fortress so recovery bytes never appear in a headless agent transcript.
    const stagesRecoveryBesideFortress = opts.agentGuided || !opts.interactive;
    const agentRecoveryPath = stagesRecoveryBesideFortress
      ? agentGuidedRecoveryOutputPath(opts.storagePath, fortressId)
      : undefined;
    let disclosure: { filePath: string; fileWritten: boolean };
    if (agentRecoveryPath !== undefined) {
      const resumedEnvelope = await resumeAuthenticatedAgentRecoveryFile({
        filePath: agentRecoveryPath,
        envelope,
        masterKey,
        fortressId,
      });
      if (resumedEnvelope !== null) {
        envelope = await writeCustodyEnvelope(storage, resumedEnvelope, masterKey);
        disclosure = { filePath: agentRecoveryPath, fileWritten: true };
      } else {
        // Fail before minting: a pre-existing destination must never leave the
        // new recovery wrap with no safely handed-off key.
        await preflightRecoveryKeyOutputFile(agentRecoveryPath);
        const prepared = prepareRecoveryWrap(envelope, masterKey);
        const recoveryReceipt = stagedRecoveryReceipt(
          envelope,
          masterKey,
          fortressId,
          prepared.recoveryKey,
        );
        // The custom writer is O_EXCL + O_NOFOLLOW. Commit the envelope only
        // after that atomic handoff succeeds; if an attacker wins the path race,
        // the fortress retains no orphaned recovery wrap.
        await opts.beforeAgentRecoveryFileCreate?.();
        const written = await writeRecoveryKeyFile({
          storagePath: opts.storagePath,
          recoveryKeyFilePath: agentRecoveryPath,
          recoveryKey: prepared.recoveryKey,
          fortressId,
          recoveryReceipt,
        });
        await opts.afterAgentRecoveryFileCreate?.();
        envelope = await writeCustodyEnvelope(storage, prepared.envelope, masterKey);
        disclosure = { filePath: written.filePath, fileWritten: written.written };
      }
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
  lease.assertHeld();
  let persistedPassphrase: { location: string; source: string } | undefined;
  try {
    // Only a passphrase can be persisted as one. A recovery key or an
    // OS-keyring custody factor authenticated custody without ever being a
    // passphrase, so there is nothing to write into the passphrase store, and
    // writing one would be minting custody from a machine-resident factor
    // (docs/custody-recovery-posture.md forbids exactly that).
    persistedPassphrase =
      credential.kind === "passphrase"
        ? await opts.persistAuthenticatedPassphrase?.(credential.value)
        : undefined;
  } finally {
    lease.assertHeld();
  }
  return {
    masterKey,
    envelope,
    mintedRecoveryKey,
    origin,
    ...(persistedPassphrase === undefined ? {} : { persistedPassphrase }),
  };
}
