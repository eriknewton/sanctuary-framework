/**
 * Sanctuary MCP Server -- `sanctuary file-grant` CLI subcommand.
 *
 * Governed File-Grant v1 (box-local, read-only). Operator-facing surface for
 * minting, listing, and revoking a box-local read grant that hands an agent
 * access to a specific operator file or directory.
 *
 * Verbs:
 *   mint    Tier-1 FORCED. Fires the approval gate through the same
 *           non-relaxable classification an MCP-exposed `file_grant` tool
 *           would use. The CLI is the operator's own direct, out-of-band
 *           presence (not an MCP agent session), so approval is resolved
 *           through an interactive stdin prompt rather than a remote
 *           channel; a non-interactive invocation (no TTY) fails closed to
 *           denial rather than hanging or silently approving.
 *   list    Tier-3 auto-allow. Read-only; renders active grants.
 *   revoke  Tier-3 auto-allow (safe-direction: revoke only reduces access).
 *           Idempotent.
 *
 * See Review/Sanctuary/Fleet_or_FileGrant_GovernedFileGrant_v1_Build_Spec_2026-07-07.md
 * for the full spec this implements.
 */

import { mkdir } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { FilesystemStorage } from "../storage/filesystem.js";
import { StateStore } from "../cognitive/state-store.js";
import { IdentityManager } from "../cognitive/tools.js";
import type { StoredIdentity } from "../core/identity.js";
import { AuditLog } from "../operational/audit-log.js";
import { BaselineTracker } from "../principal-policy/baseline.js";
import { ApprovalGate } from "../principal-policy/gate.js";
import { loadPrincipalPolicy } from "../principal-policy/loader.js";
import type { ApprovalChannel } from "../principal-policy/approval-channel.js";
import type { ApprovalRequest, ApprovalResponse } from "../principal-policy/types.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { loadConfig, type SanctuaryConfig } from "../config.js";
import {
  FILE_GRANT_DEFAULTS,
  FileGrantStore,
  PosixFileGrantFsOps,
  mintFileGrant,
  revokeFileGrant,
  listFileGrants,
  recordFileGrantListAudit,
  reconcileFileGrantTree,
  parseFileGrantTtlDuration,
} from "../file-grant/index.js";

export interface FileGrantCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function flagValue(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary file-grant <command> [options]

Governed File-Grant v1 (box-local, read-only). Hands an agent access to a
specific operator file or directory on this same box.

Commands:
  mint    Mint a new read grant. Tier-1 FORCED (requires approval).
  list    List active grants. Tier-3 (auto-allow, read-only).
  revoke  Revoke a grant by id. Tier-3 (auto-allow, safe-direction).

Run "sanctuary file-grant <command> --help" for command-specific options.
`
  );
}

function printMintHelp(out: Writable): void {
  write(
    out,
    `sanctuary file-grant mint. Mint a box-local read grant.

Usage:
  sanctuary file-grant mint --agent <agent-id> --path <abs-path> [--dir] \\
    [--ttl <duration> | --no-ttl] [--fortress <path>] [--passphrase <val>]

Description:
  Mints a grant recording that <agent-id> may read <abs-path>. This is a
  FORCED Tier-1 operation: no hand-authored policy can relax it, and it
  requires an explicit yes/no approval on this terminal before it takes
  effect. The grant is persisted as an encrypted, signed, monotonic-versioned
  state object and a tree entry is placed. v1 reports an HONEST enforcement
  label and never overclaims: "unmet" when the agent uid already owns the
  source or no dedicated agent account exists (nothing to enforce);
  "configured" when a real uid split exists but the on-hardware read-scope has
  not yet been verified (the functional read primitive + its verification are
  the separate acceptance drill); "met" only once that verification passes.

Options:
  --agent <id>        The agent identity this grant is for. Required.
  --path <abs-path>   Absolute source path (file or directory). Required.
  --dir               The path is a directory (default: a single file).
  --ttl <duration>    Expiry, e.g. 30s, 5m, 24h, 7d. Default: 24h.
  --no-ttl            Mint a standing (no-expiry) grant. Mutually exclusive
                      with --ttl. Minting a standing grant is still Tier-1
                      like every mint; it always renders as
                      "standing (no expiry)" wherever listed, never hidden.
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.

Environment:
  SANCTUARY_PASSPHRASE    Key derivation passphrase.
  SANCTUARY_RECOVERY_KEY  Recovery key alternative to passphrase.
`
  );
}

function printListHelp(out: Writable): void {
  write(
    out,
    `sanctuary file-grant list. List active file grants.

Usage:
  sanctuary file-grant list [--agent <agent-id>] [--json] \\
    [--fortress <path>] [--passphrase <val>]

Options:
  --agent <id>        Only show grants for this agent.
  --json              Output as JSON.
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.
`
  );
}

function printRevokeHelp(out: Writable): void {
  write(
    out,
    `sanctuary file-grant revoke. Revoke a file grant.

Usage:
  sanctuary file-grant revoke --grant <grant-id> [--fortress <path>] \\
    [--passphrase <val>]

Description:
  Marks the grant revoked and scrubs its tree entry. Safe-direction
  (Tier-3, auto-allow): revoking only ever reduces access. Idempotent:
  revoking an already-revoked grant is a no-op success.

  Revoke is the operator's DELETE-access story: it removes the placed tree
  entry (ending access) and audits the change. The grant record itself is
  retained as "revoked" for the audit trail; to also purge the underlying
  record, delete it from the "_file_grants" state namespace directly.

Options:
  --grant <id>        The grant to revoke. Required.
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.
`
  );
}

export async function runFileGrantCommand(
  args: FileGrantCommandArgs
): Promise<number> {
  const argv = args.argv;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printUsage(out);
    return 0;
  }

  const command = argv[0]!;
  const rest = argv.slice(1);

  switch (command) {
    case "mint":
      if (hasFlag(rest, "--help") || hasFlag(rest, "-h")) {
        printMintHelp(out);
        return 0;
      }
      return cmdMint(rest, out, err, env);
    case "list":
      if (hasFlag(rest, "--help") || hasFlag(rest, "-h")) {
        printListHelp(out);
        return 0;
      }
      return cmdList(rest, out, err, env);
    case "revoke":
      if (hasFlag(rest, "--help") || hasFlag(rest, "-h")) {
        printRevokeHelp(out);
        return 0;
      }
      return cmdRevoke(rest, out, err, env);
    default:
      write(err, `Unknown file-grant command: ${command}\n`);
      printUsage(err);
      return 2;
  }
}

interface Bootstrapped {
  config: SanctuaryConfig;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  grantStore: FileGrantStore;
  fsOps: PosixFileGrantFsOps;
  primary: StoredIdentity;
}

/**
 * Shared bootstrap for every file-grant subcommand: resolves the fortress
 * storage path, derives the master key from a passphrase or recovery key
 * (mirrors `cli/identity.ts`'s cmdShow bootstrap byte-for-byte), loads the
 * identity manager, and wires the grant store + real POSIX FsOps. Returns
 * null (having already written an operator-facing error) when bootstrap
 * cannot proceed.
 */
async function bootstrap(
  argv: string[],
  err: Writable,
  env: NodeJS.ProcessEnv
): Promise<Bootstrapped | null> {
  const fortressFlag = flagValue(argv, "--fortress");
  if (fortressFlag) {
    process.env.SANCTUARY_STORAGE_PATH = fortressFlag;
  }

  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;

  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: sanctuary file-grant requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n"
    );
    return null;
  }

  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const stateStoragePath = join(config.storage_path, "state");
  const storage = new FilesystemStorage(stateStoragePath);

  const masterKey = await resolveCliMasterKey(storage, {
    ...(passphrase !== undefined ? { passphrase } : {}),
    ...(recoveryKey !== undefined ? { recoveryKey } : {}),
    storagePathHint: config.storage_path,
  });

  const identityManager = new IdentityManager(storage, masterKey);
  const loadResult = await identityManager.load();
  if (loadResult.loaded === 0) {
    write(
      err,
      loadResult.total > 0
        ? "Error: identity files found but none could be decrypted. Wrong passphrase?\n"
        : "No identities found in this fortress. Run `sanctuary identity create` first.\n"
    );
    return null;
  }
  const primary = identityManager.getDefault();
  if (!primary) {
    write(err, "No primary identity set.\n");
    return null;
  }

  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const grantStore = new FileGrantStore(stateStore, {
    identityId: primary.identity_id,
    encryptedPrivateKey: primary.encrypted_private_key,
    identityEncryptionKey: identityEncKey,
  });
  const fsOps = new PosixFileGrantFsOps(config.storage_path);

  return { config, storage, masterKey, auditLog, grantStore, fsOps, primary };
}

/**
 * Interactive approval channel for a Tier-1 file-grant mint run directly
 * from the operator's own terminal. Not an MCP stdio session, so (unlike
 * `StderrApprovalChannel`) stdin is free to read from. Fails CLOSED to
 * denial, never approval, when stdin is not an interactive TTY -- a
 * non-interactive invocation cannot supply informed consent, so a script
 * that pipes stdin (or a CI job) must not silently mint a grant.
 */
class CliPromptApprovalChannel implements ApprovalChannel {
  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    write(process.stderr, formatApprovalPrompt(request));

    if (!process.stdin.isTTY) {
      return {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "stderr:non-interactive",
      };
    }

    const rl = createInterface({ input: process.stdin, output: process.stderr });
    try {
      const answer = await rl.question("Approve this file-grant mint? [y/N] ");
      const approved = /^y(es)?$/i.test(answer.trim());
      return {
        decision: approved ? "approve" : "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };
    } finally {
      rl.close();
    }
  }
}

function formatApprovalPrompt(request: ApprovalRequest): string {
  const contextLines = Object.entries(request.context)
    .map(([k, v]) => `  ${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join("\n");
  return (
    "\n" +
    "Sanctuary: Tier-1 approval required\n" +
    `  Operation: ${request.operation}\n` +
    `  Reason:    ${request.reason}\n` +
    "  Details:\n" +
    contextLines +
    "\n"
  );
}

async function cmdMint(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv
): Promise<number> {
  const agentId = flagValue(argv, "--agent");
  const path = flagValue(argv, "--path");
  const isDir = hasFlag(argv, "--dir");
  const ttlFlag = flagValue(argv, "--ttl");
  const noTtl = hasFlag(argv, "--no-ttl");

  if (!agentId || !path) {
    write(
      err,
      "Usage: sanctuary file-grant mint --agent <agent-id> --path <abs-path> [--dir] [--ttl <duration> | --no-ttl]\n"
    );
    return 2;
  }
  if (ttlFlag !== undefined && noTtl) {
    write(err, "Usage: choose only one TTL mode: --ttl <duration> or --no-ttl.\n");
    return 2;
  }
  if (noTtl && !FILE_GRANT_DEFAULTS.allow_standing_grant) {
    write(err, "Standing (no-expiry) grants are not permitted by this build's defaults.\n");
    return 2;
  }

  let ttlSeconds: number | null;
  try {
    ttlSeconds = noTtl
      ? null
      : ttlFlag !== undefined
        ? parseFileGrantTtlDuration(ttlFlag)
        : FILE_GRANT_DEFAULTS.default_ttl_seconds;
  } catch (parseErr) {
    write(err, `Error: ${(parseErr as Error).message}\n`);
    return 2;
  }

  const boot = await bootstrap(argv, err, env);
  if (!boot) return 1;

  // Reconcile the tree on this mutating touch: scrub any expired grant's tree
  // entry and flip its persisted status, so access never outlives its TTL.
  await reconcileFileGrantTree({
    store: boot.grantStore,
    fsOps: boot.fsOps,
    now: new Date(),
    auditLog: boot.auditLog,
    reconciledBy: boot.primary.identity_id,
  });

  const policy = await loadPrincipalPolicy(boot.config.storage_path);
  const baseline = new BaselineTracker(boot.storage, boot.masterKey);
  const channel = new CliPromptApprovalChannel();
  const gate = new ApprovalGate(policy, baseline, channel, boot.auditLog);

  const gateResult = await gate.evaluate("file_grant", {
    agent_id: agentId,
    path,
    mode: "read",
    ttl_seconds: ttlSeconds,
  });
  if (!gateResult.allowed) {
    write(err, "Denied: file-grant mint was not approved.\n");
    return 1;
  }

  try {
    const { grant, enforcement } = await mintFileGrant(
      {
        subjectAgentId: agentId,
        scope: { kind: isDir ? "dir" : "file", path },
        mode: "read",
        ttlSeconds,
        createdBy: boot.primary.identity_id,
      },
      {
        fsOps: boot.fsOps,
        store: boot.grantStore,
        now: new Date(),
        auditLog: boot.auditLog,
      }
    );
    write(out, `Grant minted: ${grant.grant_id}\n`);
    write(out, `  subject_agent_id: ${grant.subject_agent_id}\n`);
    write(out, `  scope: ${grant.scope.kind} ${grant.scope.path}\n`);
    write(out, `  expires_at: ${grant.expires_at ?? "standing (no expiry)"}\n`);
    write(out, `  ${enforcementLine(enforcement)}\n`);
    return 0;
  } catch (mintErr) {
    write(
      err,
      `Error: mint did not complete; a best-effort rollback was attempted, so no ` +
        `grant should remain active. ${(mintErr as Error).message}\n`
    );
    return 1;
  }
}

/** Honest, never-overclaiming enforcement line for the mint output. */
function enforcementLine(enforcement: "met" | "unverified" | "unmet"): string {
  switch (enforcement) {
    case "met":
      return "enforcement: met (agent-uid read-scope verified on this host)";
    case "unverified":
      return (
        "enforcement: configured (grant recorded and tree entry placed; the " +
        "agent-uid read-scope has NOT been verified on this hardware -- the " +
        "functional read primitive and its verification are the acceptance drill)"
      );
    case "unmet":
    default:
      return (
        "enforcement: unmet (grant recorded, but there is no boundary to " +
        "enforce -- the agent uid already owns the source, or no dedicated " +
        "agent account is present on this host)"
      );
  }
}

async function cmdList(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv
): Promise<number> {
  const agentFilter = flagValue(argv, "--agent");
  const json = hasFlag(argv, "--json");

  const boot = await bootstrap(argv, err, env);
  if (!boot) return 1;

  // Reconcile on this list touch too (R2-4). `list` already audits (Fix 6), so
  // it is no longer purely read-only; reconciling here (safe-direction cleanup:
  // reconcile only ever REDUCES access) means ANY list/mint/revoke touch scrubs
  // an expired grant's tree entry, so a mint-once-then-only-list box never keeps
  // an expired symlink alive. HONEST BOUND: a fully-idle box (one that never
  // mints, revokes, OR lists) still relies on an out-of-band sweep -- the
  // exported `reconcileFileGrantTree` is the reusable entry point a future
  // `file-grant sweep` / cron calls to cover that case.
  await reconcileFileGrantTree({
    store: boot.grantStore,
    fsOps: boot.fsOps,
    now: new Date(),
    auditLog: boot.auditLog,
    reconciledBy: boot.primary.identity_id,
  });

  const filter = agentFilter ? { subjectAgentId: agentFilter } : undefined;
  const grants = await listFileGrants(boot.grantStore, new Date(), filter);
  // Tier-3 auto-allow AND audited (build spec section 3.2): record the access.
  await recordFileGrantListAudit(
    boot.auditLog,
    boot.primary.identity_id,
    filter,
    grants.length
  );

  if (json) {
    write(out, JSON.stringify(grants, null, 2) + "\n");
    return 0;
  }

  if (grants.length === 0) {
    write(out, "No file grants.\n");
    return 0;
  }

  for (const grant of grants) {
    write(
      out,
      `${grant.grant_id}  ${grant.scope.kind}:${grant.scope.path}  mode=${grant.mode}  ` +
        `expires_at=${grant.expires_at ?? "standing (no expiry)"}  status=${grant.projected_status}\n`
    );
  }
  return 0;
}

async function cmdRevoke(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv
): Promise<number> {
  const grantId = flagValue(argv, "--grant");
  if (!grantId) {
    write(err, "Usage: sanctuary file-grant revoke --grant <grant-id>\n");
    return 2;
  }

  const boot = await bootstrap(argv, err, env);
  if (!boot) return 1;

  // R3-3 (round 4 completion): the revoke-time reconcile is now INSIDE the
  // same clean try/catch as `revokeFileGrant` below, not a bare `await`
  // beside it. `reconcileFileGrantTree` can throw a genuine scrub error
  // (ENOTDIR/EACCES) while scrubbing an UNRELATED expired/revoked grant's
  // tree entry -- that throw has nothing to do with the grant the operator
  // is actually revoking, but it still must never surface as an unhandled
  // rejection. Mirrors cmdMint's existing try/catch pattern.
  try {
    // Reconcile on this mutating touch too, so a listed-but-expired grant's
    // tree entry is scrubbed even if the operator only ever revokes.
    await reconcileFileGrantTree({
      store: boot.grantStore,
      fsOps: boot.fsOps,
      now: new Date(),
      auditLog: boot.auditLog,
      reconciledBy: boot.primary.identity_id,
    });

    const result = await revokeFileGrant(grantId, boot.primary.identity_id, {
      fsOps: boot.fsOps,
      store: boot.grantStore,
      now: new Date(),
      auditLog: boot.auditLog,
    });

    if (!result.found) {
      write(err, `No such grant: ${grantId}\n`);
      return 1;
    }

    write(
      out,
      result.alreadyRevoked
        ? `Grant ${grantId} was already revoked.\n`
        : `Grant ${grantId} revoked.\n`
    );
    return 0;
  } catch (revokeErr) {
    write(
      err,
      `Error: revoke did not complete cleanly. ${(revokeErr as Error).message}\n`
    );
    return 1;
  }
}
