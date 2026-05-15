/**
 * Sanctuary MCP Server — Sovereignty Profile
 *
 * Encrypted store for the sovereignty profile configuration.
 * Controls which Sanctuary features are active and how they behave.
 *
 * The profile is stored encrypted in a reserved namespace (_sovereignty_profile)
 * using AES-256-GCM with HKDF domain separation, following the same pattern
 * as ContextGatePolicyStore.
 *
 * Security invariants:
 * - Profile is stored in a reserved namespace (underscore-prefixed)
 * - L1 state tools cannot read or write reserved namespaces
 * - Profile changes only come through dedicated profile tools (Tier 1)
 *   or the dashboard
 * - All changes are audit-logged
 */

import { rename as renameFile } from "node:fs/promises";
import { join } from "node:path";
import type { StorageBackend } from "./storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "./core/encryption.js";
import { derivePurposeKey } from "./core/key-derivation.js";
import { stringToBytes, bytesToString } from "./core/encoding.js";
import { ProfileLoadError, type ProfileFailureClassification } from "./errors/profile-error.js";

// ── Types ───────────────────────────────────────────────────────────────

export interface UpstreamServer {
  name: string;           // Human-readable name (e.g., "filesystem", "github")
  transport: {
    type: "stdio" | "sse";
    command?: string;     // For stdio: the command to run
    args?: string[];      // For stdio: command arguments
    url?: string;         // For SSE: the server URL
    env?: Record<string, string>; // Environment variables to pass
  };
  enabled: boolean;
  default_tier: 1 | 2 | 3;  // Default tier for all tools from this server
  tool_overrides?: Record<string, { tier: 1 | 2 | 3 }>; // Per-tool tier overrides
  // v1.1: Remote-bound privacy enforcement binding.
  // When set, every proxied tool call to this server flows through the
  // LocalPrivacyEngine before forwarding. Defaults: destination_category is
  // "tool-api" if omitted; privacy_policy_id absent means the operator has
  // not bound a policy and outbound traffic fails closed unless the proxy
  // router was started without privacy enforcement at all.
  destination_category?: "inference" | "tool-api" | "logging" | "analytics" | "peer-agent" | "custom";
  privacy_policy_id?: string;
  privacy_identity_id?: string;
}

export interface SovereigntyProfile {
  version: 1;
  features: {
    audit_logging: { enabled: boolean };
    injection_detection: { enabled: boolean; sensitivity?: "low" | "medium" | "high" };
    context_gating: { enabled: boolean; policy_id?: string };
    // SEC-057: approval_gate is NOT a toggleable feature — it is core enforcement.
    // The approval gate is always active. This field is read-only and always true.
    approval_gate: { enabled: true };
    zk_proofs: { enabled: boolean };
  };
  upstream_servers?: UpstreamServer[];
  updated_at: string; // ISO 8601
}

/** Partial feature update — all fields optional */
export interface SovereigntyProfileUpdate {
  audit_logging?: { enabled?: boolean };
  injection_detection?: { enabled?: boolean; sensitivity?: "low" | "medium" | "high" };
  context_gating?: { enabled?: boolean; policy_id?: string };
  // SEC-057: approval_gate cannot be disabled — omit or pass enabled: true only
  approval_gate?: { enabled?: true };
  zk_proofs?: { enabled?: boolean };
  upstream_servers?: UpstreamServer[];
}

// ── Constants ───────────────────────────────────────────────────────────

const NAMESPACE = "_sovereignty_profile";
const PROFILE_KEY = "active";
const HKDF_DOMAIN = "sovereignty-profile";

// ── Default Profile ─────────────────────────────────────────────────────

export function createDefaultProfile(): SovereigntyProfile {
  return {
    version: 1,
    features: {
      audit_logging: { enabled: true },
      injection_detection: { enabled: true },
      context_gating: { enabled: false },
      approval_gate: { enabled: true }, // SEC-057: always enabled — core enforcement
      zk_proofs: { enabled: false },
    },
    updated_at: new Date().toISOString(),
  };
}

// ── Profile Store ───────────────────────────────────────────────────────

/**
 * Sovereignty profile store — encrypted under L1 sovereignty.
 *
 * Stores the active sovereignty profile in a reserved namespace.
 * On first load, creates the default profile automatically.
 */
export class SovereigntyProfileStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private profile: SovereigntyProfile | null = null;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, HKDF_DOMAIN);
  }

  /**
   * Load the active sovereignty profile from encrypted storage.
   * Creates the default profile on first run.
   */
  async load(): Promise<SovereigntyProfile> {
    if (this.profile) return this.profile;

    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(NAMESPACE, PROFILE_KEY);
    } catch (err) {
      throw new ProfileLoadError({
        path: profileStoragePath(),
        classification: "unreadable",
        detail: "Sanctuary could not read the encrypted sovereignty profile. Corruption cannot be determined until the file is readable.",
        recovery: "Fix storage permissions or the storage backend error, then retry. Sanctuary did not create a replacement profile.",
        cause: err,
      });
    }
    if (raw) {
      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        assertEncryptedPayloadShape(encrypted);
        const decrypted = decrypt(encrypted, this.encryptionKey);
        const profile = JSON.parse(bytesToString(decrypted));
        assertSovereigntyProfileShape(profile);
        this.profile = profile;
        return this.profile!;
      } catch (err) {
        const classification = classifyProfileLoadFailure(err);
        const quarantinedPath = await this.quarantineProfile(raw);
        throw new ProfileLoadError({
          path: profileStoragePath(),
          classification,
          detail: profileFailureDetail(classification, err),
          recovery: "Inspect the quarantined bytes, verify the passphrase or key material, restore a known-good profile, or intentionally create a new profile before retrying.",
          quarantinedPath,
          cause: err,
        });
      }
    }

    // First run only: create default
    this.profile = createDefaultProfile();
    await this.persist();
    return this.profile;
  }

  /**
   * Get the current profile. Must call load() first.
   */
  get(): SovereigntyProfile {
    if (!this.profile) {
      throw new Error("SovereigntyProfileStore: call load() before get()");
    }
    return this.profile;
  }

  /**
   * Apply a partial update to the profile.
   * Returns the updated profile.
   */
  async update(updates: SovereigntyProfileUpdate): Promise<SovereigntyProfile> {
    if (!this.profile) {
      await this.load();
    }

    // SEC-057: Core enforcement features cannot be disabled.
    // Type system prevents enabled:false at compile time; runtime guard catches raw JSON.
    if (updates.approval_gate && (updates.approval_gate as Record<string, unknown>).enabled === false) {
      throw new Error("approval_gate cannot be disabled; it is a core enforcement feature");
    }

    const features = this.profile!.features;

    if (updates.audit_logging !== undefined) {
      if (updates.audit_logging.enabled !== undefined) {
        if (typeof updates.audit_logging.enabled !== "boolean") {
          throw new Error("audit_logging.enabled must be a boolean");
        }
        features.audit_logging.enabled = updates.audit_logging.enabled;
      }
    }

    if (updates.injection_detection !== undefined) {
      if (updates.injection_detection.enabled !== undefined) {
        if (typeof updates.injection_detection.enabled !== "boolean") {
          throw new Error("injection_detection.enabled must be a boolean");
        }
        features.injection_detection.enabled = updates.injection_detection.enabled;
      }
      if (updates.injection_detection.sensitivity !== undefined) {
        const valid = ["low", "medium", "high"];
        if (!valid.includes(updates.injection_detection.sensitivity)) {
          throw new Error("injection_detection.sensitivity must be low, medium, or high");
        }
        features.injection_detection.sensitivity = updates.injection_detection.sensitivity;
      }
    }

    if (updates.context_gating !== undefined) {
      if (updates.context_gating.enabled !== undefined) {
        if (typeof updates.context_gating.enabled !== "boolean") {
          throw new Error("context_gating.enabled must be a boolean");
        }
        features.context_gating.enabled = updates.context_gating.enabled;
      }
      if (updates.context_gating.policy_id !== undefined) {
        if (typeof updates.context_gating.policy_id !== "string" || updates.context_gating.policy_id.length > 256) {
          throw new Error("context_gating.policy_id must be a string of 256 characters or fewer");
        }
        features.context_gating.policy_id = updates.context_gating.policy_id;
      }
    }

    if (updates.approval_gate !== undefined) {
      if (updates.approval_gate.enabled !== undefined) {
        if (typeof updates.approval_gate.enabled !== "boolean") {
          throw new Error("approval_gate.enabled must be a boolean");
        }
        features.approval_gate.enabled = updates.approval_gate.enabled;
      }
    }

    if (updates.zk_proofs !== undefined) {
      if (updates.zk_proofs.enabled !== undefined) {
        if (typeof updates.zk_proofs.enabled !== "boolean") {
          throw new Error("zk_proofs.enabled must be a boolean");
        }
        features.zk_proofs.enabled = updates.zk_proofs.enabled;
      }
    }

    if (updates.upstream_servers !== undefined) {
      if (!Array.isArray(updates.upstream_servers)) {
        throw new Error("upstream_servers must be an array");
      }
      // Validate each server entry
      for (const server of updates.upstream_servers) {
        if (!server.name || typeof server.name !== "string") {
          throw new Error("Each upstream server must have a name");
        }
        if (server.name.length > 128) {
          throw new Error("Upstream server name must be 128 characters or fewer");
        }
        // Validate name is safe for use in tool namespaces (alphanumeric, hyphens, underscores)
        if (!/^[a-zA-Z0-9_-]+$/.test(server.name)) {
          throw new Error("Upstream server name must contain only alphanumeric characters, hyphens, and underscores");
        }
        if (!server.transport || typeof server.transport !== "object") {
          throw new Error("Each upstream server must have a transport configuration");
        }
        if (server.transport.type !== "stdio" && server.transport.type !== "sse") {
          throw new Error("Transport type must be 'stdio' or 'sse'");
        }
        if (server.transport.type === "stdio" && !server.transport.command) {
          throw new Error("stdio transport requires a command");
        }
        if (server.transport.type === "sse" && !server.transport.url) {
          throw new Error("sse transport requires a url");
        }
        if (typeof server.enabled !== "boolean") {
          throw new Error("Each upstream server must have enabled as a boolean");
        }
        if (![1, 2, 3].includes(server.default_tier)) {
          throw new Error("default_tier must be 1, 2, or 3");
        }
        if (server.tool_overrides) {
          for (const [, override] of Object.entries(server.tool_overrides)) {
            if (![1, 2, 3].includes(override.tier)) {
              throw new Error("tool_overrides tier must be 1, 2, or 3");
            }
          }
        }
      }
      this.profile!.upstream_servers = updates.upstream_servers;
    }

    this.profile!.updated_at = new Date().toISOString();
    await this.persist();
    return this.profile!;
  }

  /**
   * Persist the current profile to encrypted storage.
   */
  private async persist(): Promise<void> {
    const serialized = stringToBytes(JSON.stringify(this.profile));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      NAMESPACE,
      PROFILE_KEY,
      stringToBytes(JSON.stringify(encrypted))
    );
  }

  private async quarantineProfile(raw: Uint8Array): Promise<string> {
    const quarantineKey = `${PROFILE_KEY}.corrupted.${new Date().toISOString()}`;
    const filesystemQuarantinePath = await quarantineFilesystemProfile(
      this.storage,
      quarantineKey
    );
    if (filesystemQuarantinePath) {
      return filesystemQuarantinePath;
    }
    await this.storage.write(NAMESPACE, quarantineKey, raw);
    await this.storage.delete(NAMESPACE, PROFILE_KEY, false);
    return `${NAMESPACE}/${quarantineKey}`;
  }
}

function profileStoragePath(): string {
  return `${NAMESPACE}/${PROFILE_KEY}`;
}

async function quarantineFilesystemProfile(
  storage: StorageBackend,
  quarantineKey: string
): Promise<string | null> {
  const basePath = filesystemBasePath(storage);
  if (!basePath) return null;
  const sourcePath = filesystemEntryPath(basePath, NAMESPACE, PROFILE_KEY);
  const quarantinePath = filesystemEntryPath(basePath, NAMESPACE, quarantineKey);
  try {
    await renameFile(sourcePath, quarantinePath);
    return quarantinePath;
  } catch (err) {
    if (isErrno(err, "ENOENT")) return null;
    throw err;
  }
}

function filesystemBasePath(storage: StorageBackend): string | null {
  const candidate = (storage as { basePath?: unknown }).basePath;
  return typeof candidate === "string" ? candidate : null;
}

function filesystemEntryPath(basePath: string, namespace: string, key: string): string {
  return join(basePath, bijectiveEncode(namespace), `${bijectiveEncode(key)}.enc`);
}

const SAFE_CHARS = /[^A-Za-z0-9_.\-]/g;

function bijectiveEncode(name: string): string {
  return name.replace(SAFE_CHARS, (ch) =>
    "!" + ch.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()
  );
}

function isErrno(err: unknown, code: string): boolean {
  return (
    err instanceof Error &&
    "code" in err &&
    (err as NodeJS.ErrnoException).code === code
  );
}

function classifyProfileLoadFailure(err: unknown): ProfileFailureClassification {
  if (err instanceof SyntaxError) return "corrupted";
  if (err instanceof ProfileSchemaError) return "schema-mismatch";
  if (err instanceof EncryptedPayloadSchemaError) return "corrupted";
  return "wrong-key";
}

function profileFailureDetail(
  classification: ProfileFailureClassification,
  err: unknown
): string {
  const cause = err instanceof Error ? ` Cause: ${err.message}` : "";
  if (classification === "wrong-key") {
    return `Encrypted profile authentication failed. This usually means wrong-key, tampered ciphertext, or corrupted ciphertext, and AES-GCM cannot distinguish those cases.${cause}`;
  }
  if (classification === "schema-mismatch") {
    return `The decrypted profile does not match the expected Sanctuary profile schema.${cause}`;
  }
  return `The encrypted profile bytes are malformed or truncated before schema validation could run.${cause}`;
}

class EncryptedPayloadSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncryptedPayloadSchemaError";
  }
}

class ProfileSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProfileSchemaError";
  }
}

function assertEncryptedPayloadShape(payload: unknown): asserts payload is EncryptedPayload {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new EncryptedPayloadSchemaError("encrypted payload must be an object");
  }
  const p = payload as Record<string, unknown>;
  if (p.v !== 1) throw new EncryptedPayloadSchemaError("encrypted payload version must be 1");
  if (p.alg !== "aes-256-gcm") {
    throw new EncryptedPayloadSchemaError("encrypted payload algorithm must be aes-256-gcm");
  }
  for (const field of ["iv", "ct", "ts"] as const) {
    if (typeof p[field] !== "string") {
      throw new EncryptedPayloadSchemaError(`encrypted payload field ${field} must be a string`);
    }
  }
}

function assertSovereigntyProfileShape(profile: unknown): asserts profile is SovereigntyProfile {
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
    throw new ProfileSchemaError("profile must be an object");
  }
  const p = profile as Record<string, unknown>;
  if (p.version !== 1) throw new ProfileSchemaError("profile.version must be 1");
  if (!p.features || typeof p.features !== "object" || Array.isArray(p.features)) {
    throw new ProfileSchemaError("profile.features must be an object");
  }
  const features = p.features as Record<string, unknown>;
  assertBooleanFeature(features, "audit_logging");
  assertBooleanFeature(features, "injection_detection");
  assertBooleanFeature(features, "context_gating");
  assertBooleanFeature(features, "zk_proofs");
  assertBooleanFeature(features, "approval_gate");
  const injectionDetection = features.injection_detection as Record<string, unknown>;
  if (
    injectionDetection.sensitivity !== undefined &&
    injectionDetection.sensitivity !== "low" &&
    injectionDetection.sensitivity !== "medium" &&
    injectionDetection.sensitivity !== "high"
  ) {
    throw new ProfileSchemaError("profile.features.injection_detection.sensitivity must be low, medium, or high");
  }
  const contextGating = features.context_gating as Record<string, unknown>;
  if (
    contextGating.policy_id !== undefined &&
    (typeof contextGating.policy_id !== "string" || contextGating.policy_id.length > 256)
  ) {
    throw new ProfileSchemaError("profile.features.context_gating.policy_id must be a string of 256 characters or fewer");
  }
  if ((features.approval_gate as Record<string, unknown>).enabled !== true) {
    throw new ProfileSchemaError("profile.features.approval_gate.enabled must be true");
  }
  if (typeof p.updated_at !== "string" || Number.isNaN(Date.parse(p.updated_at))) {
    throw new ProfileSchemaError("profile.updated_at must be an ISO timestamp string");
  }
  if (p.upstream_servers !== undefined) {
    assertUpstreamServersShape(p.upstream_servers);
  }
}

function assertBooleanFeature(features: Record<string, unknown>, key: string): void {
  const value = features[key];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProfileSchemaError(`profile.features.${key} must be an object`);
  }
  if (typeof (value as Record<string, unknown>).enabled !== "boolean") {
    throw new ProfileSchemaError(`profile.features.${key}.enabled must be a boolean`);
  }
}

function assertUpstreamServersShape(value: unknown): asserts value is UpstreamServer[] {
  if (!Array.isArray(value)) {
    throw new ProfileSchemaError("profile.upstream_servers must be an array");
  }
  for (const server of value) {
    if (!server || typeof server !== "object" || Array.isArray(server)) {
      throw new ProfileSchemaError("each upstream server must be an object");
    }
    const s = server as Record<string, unknown>;
    if (typeof s.name !== "string" || s.name.length === 0 || s.name.length > 128) {
      throw new ProfileSchemaError("each upstream server must have a name of 1 to 128 characters");
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(s.name)) {
      throw new ProfileSchemaError("upstream server name must contain only alphanumeric characters, hyphens, and underscores");
    }
    if (!s.transport || typeof s.transport !== "object" || Array.isArray(s.transport)) {
      throw new ProfileSchemaError("each upstream server must have a transport configuration");
    }
    const transport = s.transport as Record<string, unknown>;
    if (transport.type !== "stdio" && transport.type !== "sse") {
      throw new ProfileSchemaError("upstream server transport type must be stdio or sse");
    }
    if (transport.type === "stdio" && typeof transport.command !== "string") {
      throw new ProfileSchemaError("stdio upstream server transport requires a command");
    }
    if (transport.type === "sse" && typeof transport.url !== "string") {
      throw new ProfileSchemaError("sse upstream server transport requires a url");
    }
    if (typeof s.enabled !== "boolean") {
      throw new ProfileSchemaError("each upstream server must have enabled as a boolean");
    }
    if (s.default_tier !== 1 && s.default_tier !== 2 && s.default_tier !== 3) {
      throw new ProfileSchemaError("upstream server default_tier must be 1, 2, or 3");
    }
    if (s.tool_overrides !== undefined) {
      if (!s.tool_overrides || typeof s.tool_overrides !== "object" || Array.isArray(s.tool_overrides)) {
        throw new ProfileSchemaError("upstream server tool_overrides must be an object");
      }
      for (const override of Object.values(s.tool_overrides as Record<string, unknown>)) {
        if (!override || typeof override !== "object" || Array.isArray(override)) {
          throw new ProfileSchemaError("upstream server tool_overrides entries must be objects");
        }
        const tier = (override as Record<string, unknown>).tier;
        if (tier !== 1 && tier !== 2 && tier !== 3) {
          throw new ProfileSchemaError("upstream server tool_overrides tier must be 1, 2, or 3");
        }
      }
    }
  }
}
