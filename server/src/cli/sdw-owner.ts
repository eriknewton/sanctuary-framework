/** Interactive operator management for the durable IC-16 SDW owner binding. */

import { createInterface } from "node:readline";
import { stat } from "node:fs/promises";
import { join } from "node:path";

import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { AuditLog } from "../operational/audit-log.js";
import { resolveStoragePath } from "../paths.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { recoverInterruptedExitImportsOrThrow } from "../exit/bundle.js";
import {
  claimSdwOwnerForOperator,
  readSdwOwnerPin,
  transferSdwOwnerForOperator,
} from "../sdw/memory-isolation.js";
import { consumeFlagValue } from "./argv.js";

const OWNER_REF = "fleet-self";

export interface SdwOwnerCommandArgs {
  readonly argv: string[];
  readonly out?: NodeJS.WritableStream;
  readonly err?: NodeJS.WritableStream;
  readonly stdin?: NodeJS.ReadableStream & { isTTY?: boolean };
  readonly env?: NodeJS.ProcessEnv;
  readonly storagePath?: string;
}

interface ParsedArgs {
  readonly command: "status" | "claim" | "transfer";
  readonly fortress?: string;
  readonly agentId?: string;
  readonly fromAgentId?: string;
  readonly toAgentId?: string;
}

function usage(out: NodeJS.WritableStream): void {
  out.write(`Usage: sanctuary sdw-owner <status|claim|transfer> [options]

Manage the authenticated one-owner-per-fortress binding for Sovereign Data
Warehouse memory. Claim and transfer are interactive-only; there is no
unattended or --no-confirm path.

  status
  claim --agent-id <wrapped-agent-id>
  transfer --from-agent-id <current-id> --to-agent-id <new-id>

Options:
  --fortress <path>  Override the fortress path.
  --help, -h         Show this help.

Custody is read from SANCTUARY_PASSPHRASE or SANCTUARY_RECOVERY_KEY.
Stop the dashboard and all wrapped agents before claim or transfer.
If a compare-replace lock remains after a crash, run sanctuary doctor. Never
remove it while any Sanctuary process may be running; after stopping every
process and confirming the holder is dead, remove only the exact path doctor
reports.
`);
}

function parseArgs(argv: readonly string[]): ParsedArgs | "help" {
  if (argv.includes("--help") || argv.includes("-h")) return "help";
  const command = argv[0];
  if (command !== "status" && command !== "claim" && command !== "transfer") {
    throw new Error("expected status, claim, or transfer");
  }
  const fortress = consumeFlagValue(argv.slice(1), "--fortress");
  if (fortress.error !== undefined) throw new Error(fortress.error);
  const agent = consumeFlagValue(fortress.argv, "--agent-id");
  if (agent.error !== undefined) throw new Error(agent.error);
  const from = consumeFlagValue(agent.argv, "--from-agent-id");
  if (from.error !== undefined) throw new Error(from.error);
  const to = consumeFlagValue(from.argv, "--to-agent-id");
  if (to.error !== undefined) throw new Error(to.error);
  if (to.argv.length > 0) throw new Error(`unknown argument: ${to.argv[0]}`);
  if (command === "claim" && !agent.value) {
    throw new Error("claim requires --agent-id <wrapped-agent-id>");
  }
  if (command === "transfer" && (!from.value || !to.value)) {
    throw new Error(
      "transfer requires --from-agent-id <current-id> and --to-agent-id <new-id>",
    );
  }
  return {
    command,
    ...(fortress.value !== undefined ? { fortress: fortress.value } : {}),
    ...(agent.value !== undefined ? { agentId: agent.value } : {}),
    ...(from.value !== undefined ? { fromAgentId: from.value } : {}),
    ...(to.value !== undefined ? { toAgentId: to.value } : {}),
  };
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function promptLines(
  stdin: NodeJS.ReadableStream,
  err: NodeJS.WritableStream,
  prompts: readonly string[],
): Promise<string[]> {
  const rl = createInterface({ input: stdin, terminal: false });
  const iterator = rl[Symbol.asyncIterator]();
  try {
    const answers: string[] = [];
    for (const prompt of prompts) {
      err.write(prompt);
      const next = await iterator.next();
      answers.push(next.done ? "" : next.value);
    }
    return answers;
  } finally {
    rl.close();
  }
}

export async function runSdwOwnerCommand(args: SdwOwnerCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const stdin = args.stdin ?? process.stdin;
  const env = args.env ?? process.env;
  let parsed: ParsedArgs | "help";
  try {
    parsed = parseArgs(args.argv);
  } catch (error) {
    err.write(`sdw-owner: ${error instanceof Error ? error.message : String(error)}\n`);
    usage(err);
    return 2;
  }
  if (parsed === "help") {
    usage(out);
    return 0;
  }

  const storagePath =
    parsed.fortress ??
    args.storagePath ??
    env.SANCTUARY_FORTRESS_PATH ??
    resolveStoragePath(env);
  if (parsed.command !== "status" && (await exists(join(storagePath, "runtime.json")))) {
    err.write(
      "Refusing owner mutation while runtime.json exists. Stop the dashboard and all wrapped agents first.\n",
    );
    return 1;
  }
  if (parsed.command !== "status" && args.stdin === undefined && process.stdin.isTTY !== true) {
    err.write(
      "sdw-owner claim/transfer are interactive-only and require typed confirmation; there is no --no-confirm.\n",
    );
    return 1;
  }

  const storage = new FilesystemStorage(join(storagePath, "state"));
  let masterKey: Uint8Array | undefined;
  try {
    masterKey = await resolveCliMasterKey(storage, {
      ...(env.SANCTUARY_PASSPHRASE !== undefined
        ? { passphrase: env.SANCTUARY_PASSPHRASE }
        : {}),
      ...(env.SANCTUARY_RECOVERY_KEY !== undefined
        ? { recoveryKey: env.SANCTUARY_RECOVERY_KEY }
        : {}),
      storagePathHint: storagePath,
    });
    const fortressId = fortressIdFromStoragePath(storagePath);

    if (parsed.command === "status") {
      const pin = await readSdwOwnerPin(storage, masterKey);
      if (pin.status === "absent") {
        out.write("SDW owner: unassigned\n");
        return 3;
      }
      if (pin.status === "invalid") {
        err.write("SDW owner pin is present but failed authentication.\n");
        return 1;
      }
      out.write(`SDW owner: ${pin.data.agent_id}\n`);
      out.write(`Pinned at: ${pin.data.pinned_at}\n`);
      return 0;
    }

    const target = parsed.command === "claim" ? parsed.agentId! : parsed.toAgentId!;
    const [typedId, typedVerb] = await promptLines(stdin, err, [
      `Type the new wrapped-agent id (${target}) to continue: `,
      `Type ${parsed.command === "claim" ? "CLAIM" : "TRANSFER"} (uppercase) to continue: `,
    ]);
    if (
      typedId.trim() !== target ||
      typedVerb.trim() !== (parsed.command === "claim" ? "CLAIM" : "TRANSFER")
    ) {
      err.write("Aborted: confirmation did not match.\n");
      return 1;
    }

    const auditLog = new AuditLog(storage, masterKey);
    await recoverInterruptedExitImportsOrThrow(storage, auditLog);
    const operation = parsed.command === "claim" ? "sdw_owner_claim" : "sdw_owner_transfer";
    await auditLog.appendCritical({
      layer: "l1",
      operation: `${operation}_requested`,
      identity_id: "principal",
      result: "success",
      details: {
        target_agent_id: target,
        ...(parsed.command === "transfer"
          ? { expected_agent_id: parsed.fromAgentId! }
          : {}),
      },
    });

    const result =
      parsed.command === "claim"
        ? await claimSdwOwnerForOperator({
            storage,
            masterKey,
            fortressId,
            ownerRef: OWNER_REF,
            agentId: parsed.agentId!,
          })
        : await transferSdwOwnerForOperator({
            storage,
            masterKey,
            fortressId,
            ownerRef: OWNER_REF,
            expectedAgentId: parsed.fromAgentId!,
            newAgentId: parsed.toAgentId!,
          });
    const succeeded =
      (parsed.command === "claim" && result.status === "claimed") ||
      (parsed.command === "transfer" && result.status === "transferred");
    await auditLog.appendCritical({
      layer: "l1",
      operation: succeeded ? operation : `${operation}_refused`,
      identity_id: "principal",
      result: succeeded ? "success" : "failure",
      details: { target_agent_id: target, outcome: result.status },
    });
    if (!succeeded) {
      err.write(`SDW owner ${parsed.command} refused: ${result.status}.\n`);
      if (result.status === "claim_lost") {
        err.write("Another owner won the atomic claim; run sdw-owner status before retrying.\n");
      }
      return 1;
    }
    out.write(`SDW owner ${parsed.command === "claim" ? "claimed by" : "transferred to"} ${target}.\n`);
    return 0;
  } catch (error) {
    err.write(`sdw-owner failed: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  } finally {
    masterKey?.fill(0);
  }
}
