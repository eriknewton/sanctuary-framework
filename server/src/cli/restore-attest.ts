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

import { createInterface, Interface as ReadlineInterface } from "node:readline";
import { homedir } from "node:os";
import { join } from "node:path";

import { resolveStoragePath } from "../paths.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  readCustodyEnvelope,
  unwrapMaster,
  verifyEnvelopeMac,
  envelopeEpochOf,
  CustodyUnlockError,
} from "../core/master-custody.js";
import {
  isRollbackFrozen,
  restoreAttest,
} from "../core/anti-rollback.js";
import { AuditLog } from "../l2-operational/audit-log.js";

export interface RestoreAttestCliArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  stdin?: NodeJS.ReadableStream & { isTTY?: boolean };
  storagePath?: string;
  home?: string;
  /** Test seam: passphrase without the interactive prompt. */
  passphraseOverride?: string;
}

interface ParsedArgs {
  storage?: string;
  help: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if ((a === "--fortress" || a === "--storage") && argv[i + 1]) {
      out.storage = argv[++i];
    } else if (a && a.startsWith("--")) {
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
  --fortress <path>   Override the fortress storage path.
  --storage <path>    Alias for --fortress.
  --help, -h          Show this help.

The fortress passphrase is read from SANCTUARY_PASSPHRASE when set, otherwise
prompted.
`);
}

class LineReader {
  private readonly rl: ReadlineInterface;
  private readonly queue: string[] = [];
  private readonly waiters: Array<(line: string) => void> = [];
  private closed = false;

  constructor(stdin: NodeJS.ReadableStream) {
    this.rl = createInterface({ input: stdin });
    this.rl.on("line", (line) => {
      const w = this.waiters.shift();
      if (w) w(line);
      else this.queue.push(line);
    });
    this.rl.on("close", () => {
      this.closed = true;
      while (this.waiters.length > 0) this.waiters.shift()!("");
    });
  }

  next(): Promise<string> {
    if (this.queue.length > 0) return Promise.resolve(this.queue.shift()!);
    if (this.closed) return Promise.resolve("");
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.rl.close();
    } catch {
      // already closed
    }
  }
}

export async function runRestoreAttestCommand(
  args: RestoreAttestCliArgs
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const stdin =
    args.stdin ?? (process.stdin as NodeJS.ReadableStream & { isTTY?: boolean });
  const home = args.home ?? homedir();

  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(args.argv);
  } catch (e) {
    err.write(`${e instanceof Error ? e.message : String(e)}\n`);
    return 1;
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

  const lines = new LineReader(stdin);
  const prompt = async (q: string): Promise<string> => {
    err.write(q);
    return lines.next();
  };

  let master: Uint8Array | null = null;
  try {
    const storage = new FilesystemStorage(statePath);

    const envelope = await readCustodyEnvelope(storage);
    if (!envelope) {
      err.write(
        "This fortress does not have envelope-format custody; there is no epoch\n" +
          "witness to attest. Nothing to do.\n"
      );
      return 1;
    }

    // Passphrase: env first, then prompt.
    let passphrase =
      args.passphraseOverride ?? process.env.SANCTUARY_PASSPHRASE ?? "";
    if (!passphrase) {
      passphrase = (await prompt("Fortress passphrase: ")).trim();
    }
    if (!passphrase) {
      err.write("Aborted: no passphrase provided.\n");
      return 1;
    }

    // Unlock the master from a REAL credential (the gate) and authenticate the
    // envelope under it before trusting the on-disk epoch.
    master = await unwrapMaster(envelope, { passphrase });
    verifyEnvelopeMac(envelope, master);

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
      recordAttestation: async (ctx) => {
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
        await auditLog.flush();
      },
    });

    out.write(
      `Attested: custody epoch re-baselined to ${result.attestedEpoch}.\n` +
        (result.unfroze
          ? "Trust-bearing writes are UNFROZEN.\n"
          : "No freeze was in effect; witness re-baselined.\n") +
        "A permanent audit entry (custody_restore_attested) records this restore.\n"
    );
    return 0;
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
    if (master) master.fill(0);
    lines.close();
  }
}
