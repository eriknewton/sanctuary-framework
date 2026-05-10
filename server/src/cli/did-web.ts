/**
 * Sanctuary `sanctuary did-web` CLI subcommand.
 *
 * Foundation build verbs (Recognition-Layer Path C primary):
 *
 *   issue   — generate a did:web identifier for the operator's fortress.
 *             Requires --authority-host (the HTTPS host the operator
 *             controls and will serve the DID Document from).
 *
 *   show    — display the previously issued did:web identifier +
 *             artifact path. If none issued, prints a helpful
 *             "none configured" message.
 *
 * Persistence: the identifier is written to
 * `<storage_path>/recognition/did-web.json` (unencrypted; the DID
 * Document is a PUBLIC artifact by spec, designed to be served via
 * HTTPS). The CLI reads + writes this path; no separate DB.
 *
 * Castle-walking discipline:
 *   - No outbound network from this CLI. Issue is offline; show is a
 *     local file read. Operator-side HTTPS publication is documented
 *     in the issue output, not performed by Sanctuary.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";

import { FilesystemStorage } from "../storage/filesystem.js";
import { IdentityManager } from "../l1-cognitive/tools.js";
import {
  deriveMasterKey,
  type KeyDerivationParams,
} from "../core/key-derivation.js";
import { bytesToString, fromBase64url } from "../core/encoding.js";
import { loadConfig } from "../config.js";
import {
  issueDidWeb,
  publishDidWebDocument,
  type DidWebIdentifier,
} from "../recognition/did-web.js";

export interface DidWebCommandArgs {
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
  if (i === -1) return undefined;
  return argv[i + 1];
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary did-web <command> [options]

Commands:
  issue --authority-host <host> [--agent-label <label>] [--json]
                  Generate a did:web identifier bound to the operator's
                  fortress Ed25519 public key. Writes the DID Document
                  artifact to <storage>/recognition/did-web.json and
                  prints publication instructions for the operator's
                  HTTPS server.

  show [--json]   Display the previously issued did:web identifier.
                  Exits non-zero if none issued.

Options:
  --authority-host <host>   HTTPS host the operator controls and will
                            serve /.well-known/did.json from.
  --agent-label <label>     Optional agent-scoped identifier (label-safe;
                            alphanumeric + dash + underscore, 1-64 chars).
  --fortress <path>         Override the storage path.
  --passphrase <val>        Passphrase for master-key derivation.
  --json                    Output as JSON.
  --help, -h                Show this help.

Castle-walking note: did:web resolution is outbound HTTPS by design.
This CLI never opens an outbound socket. The opt-in surface is your
choice to run "did-web issue" with --authority-host; the resulting
artifact is yours to publish on your own infrastructure. Sanctuary
does not phone home.
`,
  );
}

export async function runDidWebCommand(
  args: DidWebCommandArgs,
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
  if (command === "issue") {
    return await cmdIssue(argv.slice(1), out, err, env);
  }
  if (command === "show") {
    return await cmdShow(argv.slice(1), out, err, env);
  }
  write(err, `Unknown did-web command: ${command}\n`);
  write(err, `Run "sanctuary did-web --help" for usage.\n`);
  return 2;
}

interface IdentitySnapshot {
  publicKey: Uint8Array;
  identityId: string;
  storagePath: string;
}

async function loadFortressIdentity(
  argv: string[],
  env: NodeJS.ProcessEnv,
  err: Writable,
): Promise<IdentitySnapshot | null> {
  const fortressFlag = flagValue(argv, "--fortress");
  if (fortressFlag) {
    process.env.SANCTUARY_STORAGE_PATH = fortressFlag;
  }
  const passphrase =
    flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: sanctuary did-web requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n",
    );
    return null;
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
    write(err, "Error: no primary identity on this fortress yet. Run sanctuary wrap first.\n");
    return null;
  }
  return {
    publicKey: fromBase64url(primary.public_key),
    identityId: primary.identity_id,
    storagePath: config.storage_path,
  };
}

async function cmdIssue(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const authorityHost = flagValue(argv, "--authority-host");
  const agentLabel = flagValue(argv, "--agent-label");
  const json = hasFlag(argv, "--json");
  if (!authorityHost) {
    write(err, "Error: --authority-host is required.\n");
    write(err, 'Example: sanctuary did-web issue --authority-host alice.example.com\n');
    return 1;
  }
  const snapshot = await loadFortressIdentity(argv, env, err);
  if (!snapshot) return 1;

  let identifier: DidWebIdentifier;
  try {
    identifier = await issueDidWeb({
      fortress_id: snapshot.identityId,
      authority_host: authorityHost,
      public_key: snapshot.publicKey,
      ...(agentLabel !== undefined ? { agent_label: agentLabel } : {}),
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    write(err, `Error: ${message}\n`);
    return 1;
  }

  const artifact = publishDidWebDocument(identifier);
  const persistDir = join(snapshot.storagePath, "recognition");
  await mkdir(persistDir, { recursive: true, mode: 0o700 });
  const persistPath = join(persistDir, "did-web.json");
  const record = {
    version: 1 as const,
    identifier: {
      did: identifier.did,
      created_at: identifier.created_at,
      authority_host: identifier.authority_host,
      fortress_id: identifier.fortress_id,
      ...(identifier.agent_label !== undefined
        ? { agent_label: identifier.agent_label }
        : {}),
      did_document: identifier.did_document,
    },
    artifact: {
      url: artifact.url,
      publish_path: artifact.publish_path,
      sha256: artifact.sha256,
    },
  };
  await writeFile(persistPath, JSON.stringify(record, null, 2), {
    mode: 0o600,
  });

  if (json) {
    write(out, JSON.stringify(record, null, 2) + "\n");
    return 0;
  }
  write(out, `did:web identifier issued.\n`);
  write(out, `  DID:            ${identifier.did}\n`);
  write(out, `  Authority host: ${identifier.authority_host}\n`);
  write(out, `  Created at:     ${identifier.created_at}\n`);
  write(out, `  Persisted:      ${persistPath}\n`);
  write(out, `\nNext step: publish the DID Document to your HTTPS host.\n`);
  write(out, `  Target URL:  ${artifact.url}\n`);
  write(out, `  SHA-256:     ${artifact.sha256}\n`);
  write(out, `  Artifact:    ${join(persistDir, "did.json")}\n`);
  const artifactPath = join(persistDir, "did.json");
  await writeFile(artifactPath, artifact.artifact, { mode: 0o644 });
  write(out, `\nCastle-walking note: this CLI never opens an outbound socket.\n`);
  write(out, `Publishing the DID Document is your operation; serve the artifact\n`);
  write(out, `at the URL above from infrastructure you control.\n`);
  return 0;
}

async function cmdShow(
  argv: string[],
  out: Writable,
  err: Writable,
  _env: NodeJS.ProcessEnv,
): Promise<number> {
  const json = hasFlag(argv, "--json");
  const fortressFlag = flagValue(argv, "--fortress");
  if (fortressFlag) {
    process.env.SANCTUARY_STORAGE_PATH = fortressFlag;
  }
  const config = await loadConfig();
  const persistPath = join(config.storage_path, "recognition", "did-web.json");
  let bytes: Buffer;
  try {
    bytes = await readFile(persistPath);
  } catch {
    write(
      err,
      `No did:web identifier configured on this fortress.\nRun "sanctuary did-web issue --authority-host <host>" to issue one.\n`,
    );
    return 1;
  }
  if (json) {
    write(out, bytes.toString("utf-8"));
    if (!bytes.toString("utf-8").endsWith("\n")) write(out, "\n");
    return 0;
  }
  type Record = {
    identifier: {
      did: string;
      authority_host: string;
      created_at: string;
      did_document: unknown;
    };
    artifact: { url: string; sha256: string };
  };
  const parsed = JSON.parse(bytes.toString("utf-8")) as Record;
  write(out, `did:web identifier on this fortress:\n`);
  write(out, `  DID:            ${parsed.identifier.did}\n`);
  write(out, `  Authority host: ${parsed.identifier.authority_host}\n`);
  write(out, `  Created at:     ${parsed.identifier.created_at}\n`);
  write(out, `  Publish URL:    ${parsed.artifact.url}\n`);
  write(out, `  SHA-256:        ${parsed.artifact.sha256}\n`);
  return 0;
}
