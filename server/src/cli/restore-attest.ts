/**
 * Sanctuary MCP Server — `sanctuary restore-attest` CLI subcommand
 *
 * The operator's audited acknowledgement of a suspected custody rollback
 * (anti-rollback Stage 1, core/anti-rollback.ts). When the boot cross-check
 * detects that the on-disk custody epoch is older than a surviving witness, it
 * FREEZES trust-bearing writes (new identities, reputation import, Castle-pin
 * provisioning, transparency checkpoint emission) and tells the operator to run
 * this verb.
 *
 * What it does:
 *  - Requires the fortress passphrase (Tier-1-shaped: attestation is a custody
 *    act, gated on a real credential — an attacker WITHOUT the current master,
 *    which is exactly the Stage-1 threat actor, cannot invoke it).
 *  - Re-baselines the monotonic epoch witness to the CURRENT on-disk epoch (it
 *    cannot fabricate a higher epoch, so it cannot forge freshness).
 *  - Clears the freeze, re-enabling trust-bearing writes.
 *  - Writes a PERMANENT audit entry (`custody_restore_attested`) recording that
 *    this fortress was acknowledged as restored from an earlier epoch. The
 *    rollback becomes an honest event in the history rather than a hidden one —
 *    and a malicious operator's use of this verb (the A2 threat) is visible to
 *    any second reader of the audit chain.
 *
 * This is NOT a rollback-laundering path: it is passphrase-gated and audited,
 * and it only re-baselines to the epoch that is already on disk.
 */

import { homedir } from "node:os";
import { join } from "node:path";

import { resolveStoragePath } from "../paths.js";
import {
  aliasConflictMessage,
  consumeFlagValue,
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
} from "./argv.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  readCustodyEnvelope,
  unwrapMaster,
  verifyEnvelopeMac,
  envelopeEpochOf,
  CustodyUnlockError,
  withCustodyWriteLock,
} from "../core/master-custody.js";
import { fromBase64url } from "../core/encoding.js";
import { promptHiddenLine, type RawModeStdin } from "./hidden-prompt.js";
import {
  isRollbackFrozen,
  restoreAttest,
} from "../core/anti-rollback.js";
import { AuditLog } from "../operational/audit-log.js";

export interface RestoreAttestCliArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  /**
   * Stdin source for prompts. Typed as {@link RawModeStdin} — the exact shape
   * the hidden-prompt raw-mode reader needs — so it reaches `promptHiddenLine`
   * with no cast.
   */
  stdin?: RawModeStdin;
  storagePath?: string;
  home?: string;
  /** Test seam: passphrase without the interactive prompt. */
  passphraseOverride?: string;
  /**
   * Test seam for `--recovery-key-prompt`: supplies the recovery key without a
   * real TTY hidden prompt. Mirrors {@link passphraseOverride}; when set, the
   * interactive-terminal requirement and hidden prompt are bypassed.
   */
  recoveryKeyOverride?: string;
  /** Test seam: pause after under-lock authentication, before audit/attest. */
  beforeAttestationCommit?: () => void | Promise<void>;
}

interface ParsedArgs {
  storage?: string;
  help: boolean;
  /**
   * Private `--recovery-key-prompt`: attest with the human-held RECOVERY KEY
   * instead of the passphrase, read from a hidden interactive prompt. For the
   * second-host / lost-passphrase case where the passphrase is not to hand but
   * the recovery key is.
   */
  recoveryKeyPrompt: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { help: false, recoveryKeyPrompt: false };
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress/--storage value must refuse, never silently resolve the default fortress; wrong-fortress custody-restore attestation is a constraint-5 violation.
  const fortress = consumeFlagValue(argv, "--fortress");
  if (fortress.error !== undefined) throw new Error(fortress.error);
  const storage = consumeFlagValue(fortress.argv, "--storage");
  if (storage.error !== undefined) throw new Error(storage.error);
  // IC-30 fix-round finding #3: --fortress and --storage are ALIASES for the
  // same value, not independent flags. Before this check, giving both
  // silently picked whichever alias `consumeFlagValue` happened to check
  // second (--storage), regardless of argv order -- a change from this
  // module's PRE-fix-round hand-rolled parser, where the LAST occurrence in
  // argv order won, so `--fortress /a --storage /b` kept working (storage
  // wins either way) but `--storage /b --fortress /a` silently flipped from
  // /a to /b. An operator who typed both, in either order, gets a refusal
  // naming the ambiguity instead of a guess.
  if (fortress.value !== undefined && storage.value !== undefined) {
    throw new Error(aliasConflictMessage("--fortress", "--storage"));
  }
  if (storage.value !== undefined || fortress.value !== undefined) {
    out.storage = storage.value ?? fortress.value;
  }

  for (let i = 0; i < storage.argv.length; i++) {
    const a = storage.argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--recovery-key-prompt") out.recoveryKeyPrompt = true;
    else if (a && a.startsWith("--")) {
      throw new Error(`Unknown flag: ${a}`);
    }
  }
  return out;
}

function printUsage(out: NodeJS.WritableStream): void {
  out.write(`
Usage: sanctuary restore-attest [options]

Acknowledge a suspected custody rollback and unfreeze trust-bearing writes.

Sanctuary freezes trust-bearing writes (new identities, reputation import,
Castle-pin provisioning, transparency checkpoint emission) when it detects that
this fortress's on-disk custody epoch is older than a surviving witness — which
happens when you legitimately restore a snapshot (Time Machine, backup, dotfile
sync, cloning to a new machine) OR when an attacker rolled custody back.

This command re-baselines the epoch witness to the current on-disk epoch, clears
the freeze, and records a permanent audit entry that the fortress was restored.
It requires the fortress passphrase. It can ONLY re-baseline to the epoch already
on disk — it cannot forge a newer one.

If you did NOT restore anything and do not recognize this rollback, treat it as a
possible attack and rotate the master ('sanctuary rotate-master') BEFORE attesting.

Options:
  --fortress <path>       Override the fortress storage path.
  --storage <path>        Alias for --fortress.
  --recovery-key-prompt   Attest with your human-held RECOVERY KEY instead of the
                          passphrase, read from a hidden interactive prompt (for
                          the second-host / lost-passphrase case). Requires a
                          terminal; never accepts the key from argv/env/pipe.
  --help, -h              Show this help.

The fortress passphrase is read from SANCTUARY_PASSPHRASE when set, otherwise
read from a hidden interactive-terminal prompt. Piped passphrases are refused.
With --recovery-key-prompt the recovery key is prompted instead, and
SANCTUARY_PASSPHRASE is ignored.
`);
}

export async function runRestoreAttestCommand(
  args: RestoreAttestCliArgs
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  // `process.stdin` (tty.ReadStream) structurally satisfies RawModeStdin, so no
  // cast is needed to reach the hidden-prompt reader.
  const stdin: RawModeStdin = args.stdin ?? process.stdin;
  const home = args.home ?? homedir();

  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(args.argv);
  } catch (e) {
    // IC-30 fix-round finding #4: parseArgs only ever throws for a
    // malformed flag (missing/duplicate/aliased --fortress or --storage, or
    // an unknown flag), so every path through this catch is a usage error --
    // render it with the same canonical shape + exit code every other
    // migrated verb uses, instead of the raw, unprefixed message this used
    // to print with exit 1.
    err.write(`${fortressFlagRefusalText(e instanceof Error ? e.message : String(e))}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  if (parsed.help) {
    printUsage(out);
    return 0;
  }

  const storagePath =
    parsed.storage ?? args.storagePath ?? resolveStoragePath(process.env, home);
  const statePath = join(storagePath, "state");
  const fortressId = fortressIdFromStoragePath(storagePath);

  out.write(`\nSanctuary restore-attest\nStorage: ${storagePath}\n\n`);

  let master: Uint8Array | null = null;
  // Function-scoped so the outer `finally` zeroes the decoded recovery key on
  // EVERY path, including when `unwrapMaster` throws for a wrong key (the most
  // common failure) before any inline scrub could run.
  let recoveryKeyBytes: Uint8Array | null = null;
  try {
    let passphrase: string | null = null;
    // Prompt before acquiring the custody/master lock: a human can take an
    // arbitrary amount of time, and no writer should be blocked while the
    // command is merely waiting for input. The credential is authenticated
    // only after the lock and a fresh envelope reread below.
    if (parsed.recoveryKeyPrompt) {
      // Private recovery-key attestation: the second-host / lost-passphrase
      // case. The recovery key is read from a hidden interactive prompt only —
      // never argv/env/pipe — so it cannot be scraped from a process list or a
      // CI log.
      if (!stdin.isTTY && args.recoveryKeyOverride === undefined) {
        err.write(
          "Refusing: --recovery-key-prompt requires an interactive terminal.\n" +
            "The recovery key is read from a hidden prompt only.\n"
        );
        return 1;
      }
      const entered = (
        args.recoveryKeyOverride ??
        (await promptHiddenLine(stdin, "Recovery key", { err }))
      ).trim();
      if (!entered) {
        err.write("Aborted: no recovery key entered.\n");
        return 1;
      }
      try {
        recoveryKeyBytes = fromBase64url(entered);
      } catch {
        err.write("Aborted: the recovery key is not valid base64url.\n");
        return 1;
      }
      // 32 = the 256-bit recovery key width (see decodeRecoveryKey in
      // core/master-custody.ts, the sibling check on the same value).
      if (recoveryKeyBytes.length !== 32) {
        err.write("Aborted: the recovery key has the wrong length.\n");
        return 1;
      }
    } else {
      // Passphrase: explicit test seam / env first, then a TTY-only hidden
      // prompt. Never consume a custody credential from a pipe.
      passphrase =
        args.passphraseOverride ?? process.env.SANCTUARY_PASSPHRASE ?? "";
      if (!passphrase) {
        if (!stdin.isTTY) {
          err.write(
            "Refusing: a fortress passphrase requires an interactive terminal.\n" +
              "The passphrase is read from a hidden prompt only.\n"
          );
          return 1;
        }
        passphrase = (
          await promptHiddenLine(stdin, "Fortress passphrase", { err })
        ).trim();
      }
      if (!passphrase) {
        err.write("Aborted: no passphrase provided.\n");
        return 1;
      }

    }

    const storage = new FilesystemStorage(statePath);
    return await withCustodyWriteLock(
      storage,
      async (lease) => {
        lease.assertHeld();
        // Fresh under-lock reread: reset/init/rotation cannot replace custody
        // between authentication and the audit+witness/freeze transaction.
        const envelope = await readCustodyEnvelope(storage);
        if (!envelope) {
          err.write(
            "This fortress does not have envelope-format custody; there is no epoch\n" +
              "witness to attest. Nothing to do.\n"
          );
          return 1;
        }
        if (recoveryKeyBytes !== null) {
          master = await unwrapMaster(envelope, { recoveryKey: recoveryKeyBytes });
        } else {
          master = await unwrapMaster(envelope, { passphrase: passphrase! });
        }
        verifyEnvelopeMac(envelope, master);

        await args.beforeAttestationCommit?.();
        lease.assertHeld();

    const frozen = await isRollbackFrozen(storage, master);
    if (!frozen.frozen) {
      out.write(
        "No rollback freeze is in effect on this fortress. Re-baselining the epoch\n" +
          "witness to the current epoch anyway (harmless) and recording the attestation.\n\n"
      );
    }

    const currentEpoch = envelopeEpochOf(envelope);
    const epochId =
      typeof envelope.epoch_id === "string" && envelope.epoch_id.length > 0
        ? envelope.epoch_id
        : `restore-attest:epoch-${currentEpoch}`;

    // Permanent, honest audit record written + flushed FIRST (codex r2 HIGH:
    // atomicity). restoreAttest awaits this callback BEFORE lowering the witness
    // or clearing the freeze; if the audit append/flush throws, nothing is
    // mutated and the freeze survives. Never key material (CLAUDE.md #6).
    const auditLog = new AuditLog(storage, master);
    const result = await restoreAttest({
      storage,
      master,
      currentEpoch,
      epochId,
      fortressId,
      assertLockHeld: lease.assertHeld,
      recordAttestation: async (ctx) => {
        lease.assertHeld();
        await auditLog.appendCritical({
          layer: "l2",
          operation: "custody_restore_attested",
          identity_id: fortressId,
          result: "success",
          details: {
            attested_epoch: ctx.attestedEpoch,
            epoch_id: ctx.epochId,
            unfroze_trust_bearing_writes: ctx.willUnfreeze,
            ...(ctx.priorFreeze
              ? {
                  detected_observed_epoch: ctx.priorFreeze.observed_epoch,
                  detected_witnessed_epoch: ctx.priorFreeze.witnessed_epoch,
                  detected_at: ctx.priorFreeze.frozen_at,
                  witness_source: ctx.priorFreeze.witness_source,
                }
              : {}),
          },
        });
        lease.assertHeld();
        await auditLog.flush();
        lease.assertHeld();
      },
    });

    out.write(
      `Attested: custody epoch re-baselined to ${result.attestedEpoch}.\n` +
        (result.unfroze
          ? "Trust-bearing writes are UNFROZEN.\n"
          : "No freeze was in effect; witness re-baselined.\n") +
        "A permanent audit entry (custody_restore_attested) records this restore.\n"
    );
        lease.assertHeld();
        return 0;
      },
      { metadata: { owner: "restore-attest" } },
    );
  } catch (e) {
    if (e instanceof CustodyUnlockError) {
      err.write(`${e.message}\n`);
      return 1;
    }
    err.write(
      `restore-attest failed: ${e instanceof Error ? e.message : String(e)}\n`
    );
    return 1;
  } finally {
    // TypeScript does not model assignments made inside the locked async
    // callback above, but `master` is populated at runtime before any
    // authenticated mutation. Preserve the outer finally as the single scrub
    // point for both callback success and callback failure.
    (master as Uint8Array | null)?.fill(0);
    if (recoveryKeyBytes) recoveryKeyBytes.fill(0); // covers the unwrap-throw path
  }
}
