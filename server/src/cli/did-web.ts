/**
 * Sanctuary `sanctuary did-web` CLI subcommand.
 *
 * Foundation build verbs (Recognition-Layer Path C primary):
 *
 *   issue   - generate a did:web identifier for the operator's fortress.
 *             Requires --authority-host (the HTTPS host the operator
 *             controls and will serve the DID Document from).
 *
 *   show    - display the previously issued did:web identifier +
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
import { IdentityManager } from "../cognitive/tools.js";
import { AuditLog } from "../operational/audit-log.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { fromBase64url } from "../core/encoding.js";
import { loadConfig } from "../config.js";
import {
  applyDidWebRotationToRecord,
  buildDidWebHealthSnapshot,
  DID_WEB_AUDIT_OPS,
  identifierFromFortressDidWebRecord,
  issueDidWeb,
  loadFortressDidWebRecord,
  publishDidWebDocument,
  rotateDidWebKey,
  type DidWebIdentifier,
  type DidWebRotationReason,
} from "../recognition/did-web.js";
import {
  DidWebHostedRegistry,
  validateHandle,
} from "../recognition/did-web-hosted-registry.js";
import { lockdownBanner, readLockdownStatus } from "../lockdown/status.js";
import { readStoredPassphrase } from "../wrap/passphrase.js";
import { resolveStoragePath } from "../paths.js";
import { consumeFlagValue, flagValue } from "./argv.js";

export interface DidWebCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
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

  rotate-key --reason <periodic|compromised|manual> [--preserve-days <n>] [--json]
                  Rotate the local fortress identity key and update the
                  persisted did:web DID Document. Does not publish.

  key-history [--json]
                  Show did:web key rotation history for this fortress.

  register-hosted <handle> [--json]
                  Register this fortress's did:web DID Document under a
                  Sanctuary-hosted handle. The document will be served at
                  identity.sanctuaryprotocol.ai/<handle>/.well-known/did.json.
                  Operator keys sign the document; Sanctuary only hosts it.

Options:
  --authority-host <host>   HTTPS host the operator controls and will
                            serve /.well-known/did.json from.
  --agent-label <label>     Optional agent-scoped identifier (label-safe;
                            alphanumeric + dash + underscore, 1-64 chars).
  --fortress <path>         Override the storage path.
  --passphrase <val>        Passphrase for master-key derivation.
  --json                    Output as JSON.
  --help, -h                Show this help.

Fortress-config auto-inclusion (build 3): "issue" persists the record
at <storage>/recognition/did-web.json. This file IS the fortress's
registered did:web identifier. Subsequent "sanctuary exit export"
runs auto-include it in the manifest without any --did-web flag.
Per-fortress isolation is structural (different storage paths carry
different records). Use "sanctuary exit export --no-did-web" to
opt out for a specific export without removing the registration.

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

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printUsage(out);
    return 0;
  }

  const command = argv[0]!;
  if (command === "issue") {
    if (hasFlag(argv.slice(1), "--help") || hasFlag(argv.slice(1), "-h")) {
      printDidWebIssueHelp(out);
      return 0;
    }
    return await cmdIssue(argv.slice(1), out, err, env);
  }
  if (command === "show") {
    return await cmdShow(argv.slice(1), out, err, env);
  }
  if (command === "rotate-key") {
    return await cmdRotateKey(argv.slice(1), out, err, env);
  }
  if (command === "key-history") {
    return await cmdKeyHistory(argv.slice(1), out, err, env);
  }
  if (command === "register-hosted") {
    return await cmdRegisterHosted(argv.slice(1), out, err, env);
  }
  write(err, `Unknown did-web command: ${command}\n`);
  write(err, `Run "sanctuary did-web --help" for usage.\n`);
  return 2;
}

export function printDidWebIssueHelp(out: Writable = process.stdout): void {
  write(
    out,
    `sanctuary did-web issue. Generate and register a did:web identifier for this fortress.

Usage:
  sanctuary did-web issue --authority-host <host> [--agent-label <label>] [--json]

Description:
  Creates a did:web identifier bound to the fortress Ed25519 public key, writes
  the local recognition record, and emits publication instructions. This command
  does not publish or resolve outbound HTTPS.

Options:
  --authority-host <host>  HTTPS host that will serve /.well-known/did.json.
  --agent-label <label>    Optional agent-scoped label.
  --fortress <path>        Override the storage path.
  --passphrase <val>       Passphrase for master-key derivation.
  --json                   Output as JSON.
  --help, -h               Show this help.

Examples:
  sanctuary did-web issue --authority-host alice.example.com
  sanctuary did-web issue --authority-host example.com --agent-label claude --json
`,
  );
}

interface IdentitySnapshot {
  publicKey: Uint8Array;
  identityId: string;
  storagePath: string;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  identityManager: IdentityManager;
}

async function loadFortressIdentity(
  argv: string[],
  env: NodeJS.ProcessEnv,
  err: Writable,
): Promise<IdentitySnapshot | null> {
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // did-web operations are a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `Error: ${consumedFortress.error}\n`);
    return null;
  }
  if (consumedFortress.value !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = consumedFortress.value;
  }
  // Resolve to a CONCRETE path here rather than passing
  // `fortressFlag ?? undefined` down. The old form was right only by
  // construction of the caller: `undefined` makes the callee re-resolve
  // ambiently, and it happened to land on the same answer solely because the
  // line above promoted --fortress onto SANCTUARY_STORAGE_PATH first. That is
  // the "correct because of what the caller did three lines earlier" posture
  // this module's structural gate exists to retire, and the gate cannot see
  // it: `storagePath: <expr>` reads as naming a fortress even when the
  // expression is `undefined`. Resolving once, here, makes the answer explicit
  // and byte-identical to what the callee would have computed
  // (`resolveStoragePath(process.env, homedir())`).
  const storagePath = resolveStoragePath(process.env);
  let passphrase: string | undefined =
    flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  if (!passphrase && !recoveryKey) {
    // Auto-discover from Keychain / fallback file (same precedence as
    // sanctuary wrap and other CLI commands that resolve the passphrase).
    try {
      const stored = await readStoredPassphrase({ storagePath });
      if (stored) {
        passphrase = stored.value;
      }
    } catch {
      // Keychain unavailable or fallback unreadable — fall through to error.
    }
    if (!passphrase) {
      write(
        err,
        "Error: sanctuary did-web requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n" +
        "       Keychain auto-discovery also failed. Ensure the fortress passphrase is stored in your OS keychain.\n",
      );
      return null;
    }
  }
  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const stateStoragePath = join(config.storage_path, "state");
  const storage = new FilesystemStorage(stateStoragePath);

  if (!passphrase && !recoveryKey) {
    return null;
  }
  // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
  let masterKey: Uint8Array;
  try {
    masterKey = await resolveCliMasterKey(storage, {
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      storagePathHint: config.storage_path,
    });
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
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
    storage,
    masterKey,
    identityManager,
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

  const auditLog = new AuditLog(snapshot.storage, snapshot.masterKey);
  await auditLog.append("l1", "did-web.issue", snapshot.identityId, {
    did: identifier.did,
    authority_host: identifier.authority_host,
    ...(identifier.agent_label !== undefined
      ? { agent_label: identifier.agent_label }
      : {}),
  });

  if (json) {
    write(out, JSON.stringify(record, null, 2) + "\n");
    return 0;
  }
  write(out, `did:web identifier issued and registered on this fortress.\n`);
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
  write(out, `\nAuto-inclusion: subsequent "sanctuary exit export" runs will\n`);
  write(out, `auto-include this identifier in the bundle manifest. Pass\n`);
  write(out, `"--no-did-web" to opt out for a specific export.\n`);
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
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // did-web operations are a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `Error: ${consumedFortress.error}\n`);
    return 1;
  }
  if (consumedFortress.value !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = consumedFortress.value;
  }
  const config = await loadConfig();
  const lockdown_status = await readLockdownStatus(config.storage_path);
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
    write(
      out,
      JSON.stringify(
        {
          lockdown_status,
          record: JSON.parse(bytes.toString("utf-8")),
        },
        null,
        2,
      ) + "\n",
    );
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
  write(out, lockdownBanner(lockdown_status));
  write(out, `did:web identifier registered on this fortress:\n`);
  write(out, `  DID:            ${parsed.identifier.did}\n`);
  write(out, `  Authority host: ${parsed.identifier.authority_host}\n`);
  write(out, `  Created at:     ${parsed.identifier.created_at}\n`);
  write(out, `  Publish URL:    ${parsed.artifact.url}\n`);
  write(out, `  SHA-256:        ${parsed.artifact.sha256}\n`);
  write(out, `\nAuto-inclusion: subsequent "sanctuary exit export" runs auto-include\n`);
  write(out, `this identifier in the bundle manifest without --did-web. Pass\n`);
  write(out, `"--no-did-web" to opt out for a specific export.\n`);
  return 0;
}

function parseRotationReason(raw: string | undefined): DidWebRotationReason | null {
  const value = raw ?? "periodic";
  if (value === "periodic" || value === "compromised" || value === "manual") {
    return value;
  }
  return null;
}

function parsePreserveDays(raw: string | undefined): number | null {
  if (raw === undefined) return 90;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) return null;
  return n;
}

async function cmdRotateKey(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const json = hasFlag(argv, "--json");
  const reason = parseRotationReason(flagValue(argv, "--reason"));
  if (!reason) {
    write(err, "Error: --reason must be periodic, compromised, or manual.\n");
    return 1;
  }
  const preserveDays = parsePreserveDays(flagValue(argv, "--preserve-days"));
  if (preserveDays === null) {
    write(err, "Error: --preserve-days must be a non-negative integer.\n");
    return 1;
  }

  const snapshot = await loadFortressIdentity(argv, env, err);
  if (!snapshot) return 1;
  const record = await loadFortressDidWebRecord(snapshot.storagePath);
  if (!record) {
    write(
      err,
      `No did:web identifier configured on this fortress.\nRun "sanctuary did-web issue --authority-host <host>" first.\n`,
    );
    return 1;
  }
  const identityRotation = await snapshot.identityManager.rotate(
    snapshot.identityId,
    `did-web:${reason}`,
  );
  if (!identityRotation) {
    write(err, "Error: default identity disappeared before rotation.\n");
    return 1;
  }

  const identifier = identifierFromFortressDidWebRecord(record);
  const rotation = await rotateDidWebKey(identifier, {
    reason,
    preserve_old_key_for: preserveDays,
    now: () => new Date(identityRotation.rotationEvent.rotated_at),
    new_public_key: fromBase64url(identityRotation.updatedIdentity.public_key),
  });
  const rotatedIdentifier: DidWebIdentifier = {
    ...identifier,
    did_document: rotation.new_did_document,
    public_key: fromBase64url(rotation.new_public_key_b64u),
  };
  const artifact = publishDidWebDocument(rotatedIdentifier);
  const updated = applyDidWebRotationToRecord(record, rotation, artifact);
  const persistDir = join(snapshot.storagePath, "recognition");
  const persistPath = join(persistDir, "did-web.json");
  await mkdir(persistDir, { recursive: true, mode: 0o700 });
  await writeFile(persistPath, JSON.stringify(updated, null, 2), { mode: 0o600 });
  await writeFile(join(persistDir, "did.json"), artifact.artifact, { mode: 0o644 });
  const auditLog = new AuditLog(snapshot.storage, snapshot.masterKey);
  await auditLog.append("l1", DID_WEB_AUDIT_OPS.KEY_ROTATED, snapshot.identityId, {
    did: rotation.did,
    reason: rotation.rotation_reason,
    old_verification_method_id: rotation.old_verification_method_id,
    new_verification_method_id: rotation.new_verification_method_id,
    old_public_key_b64u: rotation.old_public_key_b64u,
    new_public_key_b64u: rotation.new_public_key_b64u,
    preserve_old_key_for: preserveDays,
  });
  await auditLog.flush();

  if (json) {
    write(out, JSON.stringify({ rotation, artifact, record: updated }, null, 2) + "\n");
    return 0;
  }
  write(out, `did:web key rotated.\n`);
  write(out, `  DID:            ${rotation.did}\n`);
  write(out, `  Reason:         ${rotation.rotation_reason}\n`);
  write(out, `  Rotated at:     ${rotation.rotated_at}\n`);
  write(out, `  Old key:        ${rotation.old_verification_method_id}\n`);
  write(out, `  New key:        ${rotation.new_verification_method_id}\n`);
  write(out, `  Persisted:      ${persistPath}\n`);
  write(out, `  Publish URL:    ${artifact.url}\n`);
  write(out, `  SHA-256:        ${artifact.sha256}\n`);
  write(out, `\nCastle-walking note: rotation is local and opens no outbound socket.\n`);
  write(out, `Publish the updated DID Document from your own HTTPS authority host.\n`);
  return 0;
}

async function cmdKeyHistory(
  argv: string[],
  out: Writable,
  err: Writable,
  _env: NodeJS.ProcessEnv,
): Promise<number> {
  const json = hasFlag(argv, "--json");
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // did-web operations are a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `Error: ${consumedFortress.error}\n`);
    return 1;
  }
  if (consumedFortress.value !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = consumedFortress.value;
  }
  const config = await loadConfig();
  const record = await loadFortressDidWebRecord(config.storage_path);
  if (!record) {
    write(
      err,
      `No did:web identifier configured on this fortress.\nRun "sanctuary did-web issue --authority-host <host>" to issue one.\n`,
    );
    return 1;
  }
  const health = buildDidWebHealthSnapshot(record);
  if (json) {
    write(out, JSON.stringify(health, null, 2) + "\n");
    return 0;
  }
  write(out, `did:web key history for ${record.identifier.did}\n`);
  if (health.last_rotation) {
    write(out, `Last rotation: ${health.last_rotation.rotated_at} (${health.last_rotation.reason})\n`);
  } else {
    write(out, `No rotations recorded yet.\n`);
  }
  write(
    out,
    `Recommended periodic rotation in: ${health.days_until_recommended_rotation ?? "unknown"} days\n`,
  );
  for (const entry of health.key_history) {
    write(
      out,
      `- ${entry.rotated_at} ${entry.reason}: ${entry.old_verification_method_id} -> ${entry.new_verification_method_id}\n`,
    );
  }
  return 0;
}

const HOSTED_AUTHORITY_HOST = "identity.sanctuaryprotocol.ai";

async function cmdRegisterHosted(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const json = hasFlag(argv, "--json");
  const handle = argv.find((a) => !a.startsWith("--"));
  if (!handle) {
    write(err, "Error: <handle> is required.\n");
    write(
      err,
      'Example: sanctuary did-web register-hosted my-operator\n',
    );
    return 1;
  }
  const handleError = validateHandle(handle);
  if (handleError) {
    write(err, `Error: ${handleError}\n`);
    return 1;
  }

  const snapshot = await loadFortressIdentity(argv, env, err);
  if (!snapshot) return 1;

  let identifier: DidWebIdentifier;
  try {
    identifier = await issueDidWeb({
      fortress_id: snapshot.identityId,
      authority_host: HOSTED_AUTHORITY_HOST,
      public_key: snapshot.publicKey,
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    write(err, `Error: ${message}\n`);
    return 1;
  }

  const hostedDid = `did:web:${HOSTED_AUTHORITY_HOST}:${handle}`;
  const didDocument = {
    ...identifier.did_document,
    id: hostedDid,
    verificationMethod: identifier.did_document.verificationMethod.map((vm) => ({
      ...vm,
      id: `${hostedDid}#${vm.id.split("#")[1]}`,
      controller: hostedDid,
    })),
    authentication: identifier.did_document.authentication.map((a) =>
      `${hostedDid}#${a.split("#")[1]}`,
    ),
    assertionMethod: identifier.did_document.assertionMethod.map((a) =>
      `${hostedDid}#${a.split("#")[1]}`,
    ),
  };

  const registry = new DidWebHostedRegistry({
    storage: snapshot.storage,
    masterKey: snapshot.masterKey,
    fortressId: snapshot.identityId,
  });

  const entry = await registry.set(handle, didDocument);

  const auditLog = new AuditLog(snapshot.storage, snapshot.masterKey);
  await auditLog.append("l1", DID_WEB_AUDIT_OPS.PUBLISHED, snapshot.identityId, {
    did: hostedDid,
    operator_handle: handle,
    authority_host: HOSTED_AUTHORITY_HOST,
    hosted: true,
  });
  await auditLog.flush();

  if (json) {
    write(
      out,
      JSON.stringify(
        {
          did: hostedDid,
          operator_handle: handle,
          authority_host: HOSTED_AUTHORITY_HOST,
          published_at: entry.published_at,
          did_document: didDocument,
        },
        null,
        2,
      ) + "\n",
    );
    return 0;
  }
  write(out, `did:web identifier registered under Sanctuary-hosted handle.\n`);
  write(out, `  DID:            ${hostedDid}\n`);
  write(out, `  Handle:         ${handle}\n`);
  write(out, `  Authority host: ${HOSTED_AUTHORITY_HOST}\n`);
  write(out, `  Published at:   ${entry.published_at}\n`);
  write(out, `\nThe DID Document will be served at:\n`);
  write(
    out,
    `  https://${HOSTED_AUTHORITY_HOST}/${handle}/.well-known/did.json\n`,
  );
  write(out, `\nCastle-walking note: your signing key never leaves the fortress.\n`);
  write(out, `Sanctuary hosts the document; you control the keys.\n`);
  return 0;
}
