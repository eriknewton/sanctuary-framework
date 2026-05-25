/**
 * Sanctuary `sanctuary erc8004` CLI subcommand.
 *
 * Operator-facing surface for ERC-8004 Identity Registry operations:
 *
 *   register  - initiate an ERC-8004 Identity Registry registration
 *               signature request. Flows through the three-tier policy
 *               gate. --auto-approve bypasses the inbox wait (operator
 *               pre-confirmed).
 *
 *   status    - check the status of a pending registration request by
 *               request_id.
 *
 * Castle-walking: no outbound surface. Signatures are produced locally;
 * on-chain broadcast is operator-side.
 */

import { Writable } from "node:stream";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import { FilesystemStorage } from "../storage/filesystem.js";
import { IdentityManager } from "../l1-cognitive/tools.js";
import { AuditLog } from "../l2-operational/audit-log.js";
import {
  deriveMasterKey,
  type KeyDerivationParams,
} from "../core/key-derivation.js";
import { bytesToString, fromBase64url } from "../core/encoding.js";
import { loadConfig } from "../config.js";
import { DefaultPolicyGate } from "../key-17/policy-gate.js";
import {
  handleErc8004Request,
  Erc8004PendingStore,
  isValidEthAddress,
  type Erc8004ToolResponse,
} from "../key-17/erc8004-tools.js";
import type { Erc8004Registration } from "../key-17/erc8004-identity-signer.js";
import { lockdownBanner, readLockdownStatus } from "../lockdown/status.js";
import { readStoredPassphrase } from "../wrap/passphrase.js";

export interface Erc8004CommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function flagValue(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  if (i === -1 || i + 1 >= argv.length) return undefined;
  return argv[i + 1];
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary erc8004 <command> [options]

Commands:
  register --registry <eip55-address> --chain <chain-id> --agent-id <id>
           --nonce <nonce> [--metadata-uri <uri>] [--counterparty <id>]
           [--auto-approve] [--json]
                  Initiate an ERC-8004 Identity Registry registration
                  signature request. Flows through the three-tier policy
                  gate before any signature is produced.

  status --request-id <id> [--json]
                  Check the status of a pending registration request.

Options:
  --registry <address>      EIP-55 checksummed Ethereum address of the
                            Identity Registry contract.
  --chain <chain-id>        Chain ID (1 = mainnet; testnets allowed).
  --agent-id <id>           Canonical agent identifier to register.
  --nonce <nonce>           Anti-replay nonce from the registry contract.
  --metadata-uri <uri>      Optional IPFS or HTTPS URI for off-chain metadata.
  --counterparty <id>       Optional counterparty for policy-gate matching.
  --auto-approve            Operator pre-confirms; skips inbox wait (still
                            validated by policy gate).
  --fortress <path>         Override the storage path.
  --passphrase <val>        Passphrase for master-key derivation.
  --json                    Output as JSON.
  --help, -h                Show this help.

Castle-walking note: this CLI never opens an outbound socket. Signatures
are produced locally. Submit the returned signature to the registry
contract via your wallet client; Sanctuary does not broadcast.
`,
  );
}

export async function runErc8004Command(
  args: Erc8004CommandArgs,
): Promise<number> {
  const argv = args.argv;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;

  if (argv.length === 0 || hasFlag(argv, "--help") || hasFlag(argv, "-h")) {
    printUsage(out);
    return 0;
  }

  const command = argv[0]!;
  if (command === "register") {
    return await cmdRegister(argv.slice(1), out, err, env);
  }
  if (command === "status") {
    return await cmdStatus(argv.slice(1), out, err);
  }
  write(err, `Unknown erc8004 command: ${command}\n`);
  write(err, `Run "sanctuary erc8004 --help" for usage.\n`);
  return 2;
}

interface FortressSnapshot {
  identityId: string;
  storagePath: string;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
}

async function loadFortressIdentity(
  argv: string[],
  env: NodeJS.ProcessEnv,
  err: Writable,
): Promise<FortressSnapshot | null> {
  const fortressFlag = flagValue(argv, "--fortress");
  if (fortressFlag) {
    process.env.SANCTUARY_STORAGE_PATH = fortressFlag;
  }
  let passphrase: string | undefined =
    flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  if (!passphrase && !recoveryKey) {
    try {
      const stored = await readStoredPassphrase({
        storagePath: fortressFlag ?? undefined,
      });
      if (stored) {
        passphrase = stored.value;
      }
    } catch {
      // Keychain unavailable -- fall through to error.
    }
    if (!passphrase) {
      write(
        err,
        "Error: sanctuary erc8004 requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n" +
          "       Keychain auto-discovery also failed.\n",
      );
      return null;
    }
  }
  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const stateStoragePath = join(config.storage_path, "state");
  const storage = new FilesystemStorage(stateStoragePath);

  let masterKey: Uint8Array;
  if (passphrase) {
    let existingParams: KeyDerivationParams | undefined;
    const raw = await storage.read("_meta", "key-params");
    if (raw) {
      existingParams = JSON.parse(bytesToString(raw)) as KeyDerivationParams;
    }
    const derivation = await deriveMasterKey(passphrase, existingParams);
    masterKey = derivation.key;
  } else if (recoveryKey) {
    masterKey = fromBase64url(recoveryKey);
  } else {
    return null;
  }

  const identityManager = new IdentityManager(storage, masterKey);
  const loadResult = await identityManager.load();
  if (loadResult.loaded === 0) {
    write(
      err,
      loadResult.total > 0
        ? "Error: identity files found but none could be decrypted. Wrong passphrase?\n"
        : "Error: no identities on this fortress yet. Run sanctuary wrap first.\n",
    );
    return null;
  }
  const primary = identityManager.getDefault();
  if (!primary) {
    write(
      err,
      "Error: no primary identity on this fortress yet. Run sanctuary wrap first.\n",
    );
    return null;
  }
  return {
    identityId: primary.identity_id,
    storagePath: config.storage_path,
    storage,
    masterKey,
  };
}

async function cmdRegister(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const registry = flagValue(argv, "--registry");
  const chainStr = flagValue(argv, "--chain");
  const agentId = flagValue(argv, "--agent-id");
  const nonceStr = flagValue(argv, "--nonce");
  const metadataUri = flagValue(argv, "--metadata-uri");
  const autoApprove = hasFlag(argv, "--auto-approve");
  const json = hasFlag(argv, "--json");

  if (!registry) {
    write(err, "Error: --registry is required.\n");
    return 1;
  }
  if (!isValidEthAddress(registry)) {
    write(
      err,
      "Error: --registry must be a valid EIP-55 Ethereum address (0x + 40 hex chars).\n",
    );
    return 1;
  }
  if (!chainStr) {
    write(err, "Error: --chain is required.\n");
    return 1;
  }
  const chainId = Number.parseInt(chainStr, 10);
  if (!Number.isFinite(chainId) || chainId < 1) {
    write(err, "Error: --chain must be a positive integer.\n");
    return 1;
  }
  if (!agentId) {
    write(err, "Error: --agent-id is required.\n");
    return 1;
  }
  if (!nonceStr) {
    write(err, "Error: --nonce is required.\n");
    return 1;
  }
  const nonce = Number.parseInt(nonceStr, 10);
  if (!Number.isFinite(nonce) || nonce < 0) {
    write(err, "Error: --nonce must be a non-negative integer.\n");
    return 1;
  }

  const snapshot = await loadFortressIdentity(argv, env, err);
  if (!snapshot) return 1;

  const lockdownStatus = await readLockdownStatus(snapshot.storagePath);

  const auditLog = new AuditLog(snapshot.storage, snapshot.masterKey);

  // Create policy gate with no approval callback (Tier 2 falls through
  // to the pending-approval path in handleErc8004Request).
  const policyGate = new DefaultPolicyGate({
    global_default: "operator_approval_required",
    erc8004: {
      default_decision: "operator_approval_required",
      counterparty_rules: [],
    },
  });

  const pendingStore = new Erc8004PendingStore();

  const registration: Erc8004Registration = {
    identity: agentId,
    registry,
    chain_id: chainId,
    nonce,
    timestamp: new Date().toISOString(),
    ...(metadataUri !== undefined ? { metadata_uri: metadataUri } : {}),
  };

  const result = await handleErc8004Request(
    {
      masterKey: snapshot.masterKey,
      operatorId: snapshot.identityId,
      policyGate,
      auditLog,
      identityId: snapshot.identityId,
      pendingStore,
      fortressId: snapshot.identityId,
    },
    registration,
    { autoApprove },
  );

  await auditLog.flush();

  if (json) {
    write(out, JSON.stringify(result, null, 2) + "\n");
    return 0;
  }

  write(out, lockdownBanner(lockdownStatus));
  printHumanResult(out, result, registry);
  return 0;
}

function printHumanResult(
  out: Writable,
  result: Erc8004ToolResponse,
  registryAddress: string,
): void {
  write(out, `ERC-8004 Identity Registry registration\n`);
  write(out, `  Request ID: ${result.request_id}\n`);
  write(out, `  Status:     ${result.status}\n`);

  if (result.status === "signed") {
    write(out, `  Signer:     ${result.signer_address}\n`);
    write(out, `  Signature:  ${result.signature}\n`);
    write(
      out,
      `\nNext step: submit this signature to ${registryAddress} via your\n` +
        `wallet client. Sanctuary does not broadcast on-chain transactions.\n`,
    );
  } else if (result.status === "pending_approval") {
    write(
      out,
      `\nThe request requires operator approval. Check your approval inbox\n` +
        `or re-run with --auto-approve to skip the inbox wait.\n`,
    );
  } else if (result.status === "denied") {
    write(out, `  Reason:     ${result.reason}\n`);
  }
}

async function cmdStatus(
  argv: string[],
  out: Writable,
  err: Writable,
): Promise<number> {
  const requestId = flagValue(argv, "--request-id");
  const json = hasFlag(argv, "--json");

  if (!requestId) {
    write(err, "Error: --request-id is required.\n");
    return 1;
  }

  // In CLI mode, pending requests are in-memory per process. Status
  // checking is primarily useful when the server is running and the
  // MCP tool created the request. For CLI-only flows, the result is
  // returned synchronously from `register`.
  if (json) {
    write(
      out,
      JSON.stringify(
        {
          request_id: requestId,
          note:
            "CLI status checks are limited to the current process. " +
            "For requests created via the MCP tool, use the MCP " +
            "tool's poll mode (pass request_id as input).",
        },
        null,
        2,
      ) + "\n",
    );
  } else {
    write(
      out,
      `Request ${requestId}: status checking is available via the MCP tool's\n` +
        `poll mode. CLI requests return results synchronously from "register".\n`,
    );
  }
  return 0;
}
