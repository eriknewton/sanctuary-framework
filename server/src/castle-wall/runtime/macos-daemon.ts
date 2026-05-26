import { randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { bytesToString, toBase64url } from "../../core/encoding.js";
import { sign as identitySign } from "../../core/identity.js";
import { decrypt, encrypt, type EncryptedPayload } from "../../core/encryption.js";
import type { AuditLog } from "../../l2-operational/audit-log.js";
import type { AllowlistRule } from "../allowlist/schema.js";
import { validateRule } from "../allowlist/schema.js";
import { verifyManifestSignature } from "../allowlist/parse.js";
import type { SignedManifest } from "../allowlist/manifest.js";
import type {
  DecisionResponse,
  PolicyReloadRequest,
  PolicyReloadResponse,
} from "../ipc/messages.js";
import {
  buildSignedManifest,
  type ManifestSigningKey,
} from "./manifest-publisher.js";
import { MacOSFlowEventConsumer } from "./macos-flow-events.js";
import { MacOSFlowIpcListener } from "./macos-ipc-listener.js";
import {
  CASTLE_WALL_ACTIVE_CONFIG_PATH,
  resolveCastleWallSocketPath,
} from "./socket-path.js";

const CASTLE_PINNED_PUBKEY = "castle-pinned-pubkey.bin";
const CASTLE_PINNED_PRIVKEY = "castle-pinned-privkey.enc";

export const CASTLE_WALL_ALREADY_RUNNING_MESSAGE =
  "Castle Wall daemon already running for this fortress (PID <pid>). Multi-wrap-per-fortress is Phase 3.";

export interface MacOSCastleWallDaemonInput {
  fortressPath: string;
  fortressId: string;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  platform?: NodeJS.Platform;
  socketPath?: string;
  activeConfigPath?: string;
  listenerFactory?: (options: MacOSCastleWallListenerOptions) => MacOSCastleWallListenerHandle;
}

export type MacOSCastleWallListenerOptions = ConstructorParameters<
  typeof MacOSFlowIpcListener
>[0];

export interface MacOSCastleWallListenerHandle {
  start(): Promise<void>;
  stop(): Promise<void>;
  broadcastManifestUpdate(): Promise<number>;
  broadcastDecisionResponse(response: DecisionResponse): Promise<number>;
}

export interface MacOSCastleWallDaemonHandle {
  socketPath: string;
  reloadPolicy(): Promise<PolicyReloadResponse>;
  stop(): Promise<void>;
}

interface ManifestState {
  signed: SignedManifest;
  rules: AllowlistRule[];
}

interface LoadedSigningKey extends ManifestSigningKey {
  publicKey: Uint8Array;
}

interface ActiveCastleWallConfig {
  socket_path: string;
  fortress_id: string;
  pid: number;
  started_at: string;
}

export async function startMacOSCastleWallDaemon(
  input: MacOSCastleWallDaemonInput,
): Promise<MacOSCastleWallDaemonHandle> {
  const socketPath =
    input.socketPath ??
    resolveCastleWallSocketPath({
      platform: input.platform ?? process.platform,
      fortressId: input.fortressId,
      fortressPath: input.fortressPath,
    }).path;
  const activeConfigPath = input.activeConfigPath ?? CASTLE_WALL_ACTIVE_CONFIG_PATH;

  await assertActiveConfigNotOwnedByLiveProcess(activeConfigPath);
  await assertSocketNotOwnedByLiveProcess(socketPath);
  await mkdir(join(input.fortressPath, "policy", "egress", "rules"), {
    recursive: true,
    mode: 0o700,
  });

  const signingKey = await loadSigningKey(input.fortressPath, input.masterKey);
  let manifestState = await loadManifestState({
    fortressPath: input.fortressPath,
    fortressId: input.fortressId,
    signingKey,
  });
  const pendingRequests = new Set<string>();
  let listener: MacOSCastleWallListenerHandle;

  const consumer = new MacOSFlowEventConsumer({
    manifestProvider: {
      currentSnapshot() {
        return {
          signed_manifest: manifestState.signed,
          rules: manifestState.rules,
        };
      },
    },
    approvalQueue: {
      async enqueue(input) {
        pendingRequests.add(input.requestId);
      },
    },
    auditSink: input.auditLog,
    defaultApprovalTimeoutSeconds: 30,
  });

  const listenerOptions: MacOSCastleWallListenerOptions = {
    socketPath,
    consumer,
    handshakeSigner: {
      fortressId: input.fortressId,
      signingKeyId: signingKey.signingKeyId,
      signNonce(nonce) {
        return identitySign(nonce, signingKey.encryptedPrivateKey, signingKey.encryptionKey);
      },
    },
    adminHandler: {
      async reloadPolicy(request) {
        return reloadPolicy(request);
      },
      async handleDecision(response) {
        if (!pendingRequests.has(response.request_id)) {
          return { ok: false, error: `no pending request matches ${response.request_id}` };
        }
        pendingRequests.delete(response.request_id);
        await listener.broadcastDecisionResponse(response);
        await input.auditLog.append(
          "l1",
          "operator_decision",
          input.fortressId,
          {
            request_id: response.request_id,
            decision: response.decision,
            learn: response.learn,
            source: "castle-wall-cli",
          },
          "success",
        );
        await input.auditLog.flush();
        return { ok: true };
      },
    },
  };
  listener = input.listenerFactory
    ? input.listenerFactory(listenerOptions)
    : new MacOSFlowIpcListener(listenerOptions);

  let activeConfigWritten = false;
  try {
    await listener.start();
    await writeActiveConfig(activeConfigPath, {
      socket_path: socketPath,
      fortress_id: input.fortressId,
      pid: process.pid,
      started_at: new Date().toISOString(),
    });
    activeConfigWritten = true;
    await input.auditLog.append(
      "l1",
      "filter_started",
      input.fortressId,
      { socket_path: socketPath, source: "sanctuary-wrap" },
      "success",
    );
    await input.auditLog.flush();
  } catch (err) {
    if (activeConfigWritten) {
      await removeActiveConfigIfCurrent(activeConfigPath, socketPath, input.fortressId);
    }
    await listener.stop().catch(() => undefined);
    throw err;
  }

  async function reloadPolicy(
    request?: PolicyReloadRequest,
  ): Promise<PolicyReloadResponse> {
    try {
      manifestState = await loadManifestState({
        fortressPath: input.fortressPath,
        fortressId: input.fortressId,
        signingKey,
      });
      const emitted = await listener.broadcastManifestUpdate();
      await input.auditLog.append(
        "l1",
        "policy_loaded",
        input.fortressId,
        {
          loaded_rule_count: manifestState.rules.length,
          emitted_subscribers: emitted,
          source: "castle-wall-reload",
        },
        "success",
      );
      await input.auditLog.flush();
      return {
        type: "policy_reload_response",
        request_id: request?.request_id ?? randomBytes(16).toString("hex"),
        ok: true,
        loaded_manifest_signature_b64url: manifestState.signed.signature.signature_b64url,
        loaded_rule_count: manifestState.rules.length,
      };
    } catch (err) {
      await input.auditLog.append(
        "l1",
        "policy_validation_failed",
        input.fortressId,
        { error: err instanceof Error ? err.message : String(err) },
        "failure",
      );
      await input.auditLog.flush();
      return {
        type: "policy_reload_response",
        request_id: request?.request_id ?? randomBytes(16).toString("hex"),
        ok: false,
        loaded_manifest_signature_b64url: manifestState.signed.signature.signature_b64url,
        loaded_rule_count: manifestState.rules.length,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  return {
    socketPath,
    reloadPolicy,
    async stop() {
      try {
        await listener.stop();
        await input.auditLog.append(
          "l1",
          "filter_stopped",
          input.fortressId,
          { socket_path: socketPath, source: "sanctuary-wrap" },
          "success",
        );
        await input.auditLog.flush();
      } finally {
        await removeActiveConfigIfCurrent(activeConfigPath, socketPath, input.fortressId);
      }
    },
  };
}

async function loadSigningKey(
  fortressPath: string,
  masterKey: Uint8Array,
): Promise<LoadedSigningKey> {
  const publicKey = await readFile(join(fortressPath, CASTLE_PINNED_PUBKEY));
  if (publicKey.length !== 32) {
    throw new Error(`Pinned public key must be 32 bytes (found ${publicKey.length}).`);
  }
  let encryptedPrivateKey = JSON.parse(
    await readFile(join(fortressPath, CASTLE_PINNED_PRIVKEY), "utf8"),
  ) as EncryptedPayload;
  const privateKey = decrypt(encryptedPrivateKey, masterKey);
  try {
    if (privateKey.length === 64) {
      encryptedPrivateKey = encrypt(privateKey.slice(0, 32), masterKey);
    } else if (privateKey.length !== 32) {
      throw new Error(`Pinned private key must decrypt to 32 bytes (found ${privateKey.length}).`);
    }
  } finally {
    privateKey.fill(0);
  }
  return {
    signingKeyId: `castle-wall:${toBase64url(publicKey)}`,
    encryptedPrivateKey,
    encryptionKey: masterKey,
    publicKey,
  };
}

async function loadManifestState(input: {
  fortressPath: string;
  fortressId: string;
  signingKey: LoadedSigningKey;
}): Promise<ManifestState> {
  const rulesDir = join(input.fortressPath, "policy", "egress", "rules");
  const rules: AllowlistRule[] = [];
  let filenames: string[] = [];
  try {
    filenames = (await readdir(rulesDir)).filter((name) => name.endsWith(".json"));
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code !== "ENOENT") throw err;
  }
  filenames.sort();
  for (const filename of filenames) {
    const raw = await readFile(join(rulesDir, filename));
    const parsed = JSON.parse(bytesToString(raw)) as AllowlistRule;
    const issues = validateRule(parsed);
    if (issues.length > 0) {
      throw new Error(`rule ${filename} invalid: ${issues.join("; ")}`);
    }
    rules.push(parsed);
  }
  const { signed } = buildSignedManifest({
    fortressId: input.fortressId,
    issuedAt: new Date().toISOString(),
    rules,
    signingKey: input.signingKey,
  });
  const verifyResult = verifyManifestSignature(signed, input.signingKey.publicKey);
  if (!verifyResult.ok) {
    throw new Error(`manifest signature verification failed: ${verifyResult.error}`);
  }
  return { signed, rules };
}

async function assertSocketNotOwnedByLiveProcess(socketPath: string): Promise<void> {
  try {
    await stat(socketPath);
    throw new Error(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") return;
    throw err;
  }
}

async function assertActiveConfigNotOwnedByLiveProcess(configPath: string): Promise<void> {
  const config = await readActiveConfig(configPath);
  if (!config) return;
  if (isPidAlive(config.pid)) {
    throw new Error(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);
  }
}

async function writeActiveConfig(
  configPath: string,
  config: ActiveCastleWallConfig,
): Promise<void> {
  await mkdir(dirname(configPath), { recursive: true, mode: 0o755 });
  const tempPath = `${configPath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(config)}\n`, {
    encoding: "utf8",
    mode: 0o644,
  });
  await rename(tempPath, configPath);
}

async function removeActiveConfigIfCurrent(
  configPath: string,
  socketPath: string,
  fortressId: string,
): Promise<void> {
  const config = await readActiveConfig(configPath);
  if (
    config &&
    config.pid === process.pid &&
    config.socket_path === socketPath &&
    config.fortress_id === fortressId
  ) {
    await unlink(configPath).catch((err: unknown) => {
      const code = err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
      if (code !== "ENOENT") throw err;
    });
  }
}

async function readActiveConfig(configPath: string): Promise<ActiveCastleWallConfig | null> {
  let raw: string;
  try {
    raw = await readFile(configPath, "utf8");
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") return null;
    throw err;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<ActiveCastleWallConfig>;
    if (
      typeof parsed.socket_path !== "string" ||
      typeof parsed.fortress_id !== "string" ||
      typeof parsed.pid !== "number" ||
      !Number.isInteger(parsed.pid) ||
      typeof parsed.started_at !== "string"
    ) {
      return null;
    }
    return {
      socket_path: parsed.socket_path,
      fortress_id: parsed.fortress_id,
      pid: parsed.pid,
      started_at: parsed.started_at,
    };
  } catch {
    return null;
  }
}

function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code = err instanceof Error && "code" in err
      ? (err as NodeJS.ErrnoException).code
      : undefined;
    return code === "EPERM";
  }
}
