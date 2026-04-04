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

import type { StorageBackend } from "./storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "./core/encryption.js";
import { derivePurposeKey } from "./core/key-derivation.js";
import { stringToBytes, bytesToString } from "./core/encoding.js";

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

    const raw = await this.storage.read(NAMESPACE, PROFILE_KEY);
    if (raw) {
      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        this.profile = JSON.parse(bytesToString(decrypted));
        return this.profile!;
      } catch {
        // Corrupted — recreate default
      }
    }

    // First run or corrupted: create default
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
      throw new Error("approval_gate cannot be disabled — it is a core enforcement feature");
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
}
