/**
 * Sanctuary MCP Server — Configuration
 *
 * Loads and validates server configuration from file or environment variables.
 */

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

export interface SanctuaryConfig {
  version: string;
  storage_path: string;
  principal_id?: string;

  state: {
    encryption: "aes-256-gcm";
    key_protection: "passphrase" | "hardware-key" | "none";
    key_derivation: "argon2id";
    integrity: "merkle-sha256";
    identity_provider: "ed25519";
  };

  execution: {
    environment: "local-process" | "docker" | "tee";
    attestation: boolean;
    resource_limits: {
      max_memory_mb: number;
      max_storage_mb: number;
      max_cpu_percent: number;
    };
  };

  disclosure: {
    proof_system: "groth16" | "plonk" | "commitment-only";
    default_policy: "minimum-necessary" | "withhold-all";
  };

  reputation: {
    mode: "self-custodied" | "service-mediated";
    attestation_format: "eas-compatible";
    export_format: "SANCTUARY_REP_V1";
    service_endpoints: string[];
  };

  transport: "stdio" | "http";
  http_port: number;

  dashboard: {
    enabled: boolean;
    port: number;
    host: string;
  };
}

/** Default configuration */
export function defaultConfig(): SanctuaryConfig {
  return {
    version: "0.3.0",
    storage_path: join(homedir(), ".sanctuary"),
    state: {
      encryption: "aes-256-gcm",
      key_protection: "none",
      key_derivation: "argon2id",
      integrity: "merkle-sha256",
      identity_provider: "ed25519",
    },
    execution: {
      environment: "local-process",
      attestation: true,
      resource_limits: {
        max_memory_mb: 512,
        max_storage_mb: 1024,
        max_cpu_percent: 50,
      },
    },
    disclosure: {
      proof_system: "commitment-only",
      default_policy: "minimum-necessary",
    },
    reputation: {
      mode: "self-custodied",
      attestation_format: "eas-compatible",
      export_format: "SANCTUARY_REP_V1",
      service_endpoints: [],
    },
    transport: "stdio",
    http_port: 3500,
    dashboard: {
      enabled: false,
      port: 3501,
      host: "127.0.0.1",
    },
  };
}

/**
 * Load configuration from file, falling back to defaults.
 */
export async function loadConfig(
  configPath?: string
): Promise<SanctuaryConfig> {
  const config = defaultConfig();

  // Override from environment
  if (process.env.SANCTUARY_STORAGE_PATH) {
    config.storage_path = process.env.SANCTUARY_STORAGE_PATH;
  }
  if (process.env.SANCTUARY_TRANSPORT) {
    config.transport = process.env.SANCTUARY_TRANSPORT as "stdio" | "http";
  }
  if (process.env.SANCTUARY_HTTP_PORT) {
    config.http_port = parseInt(process.env.SANCTUARY_HTTP_PORT, 10);
  }
  if (process.env.SANCTUARY_DASHBOARD_ENABLED === "true") {
    config.dashboard.enabled = true;
  }
  if (process.env.SANCTUARY_DASHBOARD_PORT) {
    config.dashboard.port = parseInt(process.env.SANCTUARY_DASHBOARD_PORT, 10);
  }
  if (process.env.SANCTUARY_DASHBOARD_HOST) {
    config.dashboard.host = process.env.SANCTUARY_DASHBOARD_HOST;
  }

  // Override from config file
  const path =
    configPath ?? join(config.storage_path, "sanctuary.json");

  try {
    const raw = await readFile(path, "utf-8");
    const fileConfig = JSON.parse(raw);
    return deepMerge(config, fileConfig);
  } catch {
    // No config file — use defaults
    return config;
  }
}

/**
 * Save configuration to file.
 */
export async function saveConfig(
  config: SanctuaryConfig,
  configPath?: string
): Promise<void> {
  const path =
    configPath ?? join(config.storage_path, "sanctuary.json");
  await writeFile(path, JSON.stringify(config, null, 2), { mode: 0o600 });
}

/** Deep merge two objects (target takes precedence) */
function deepMerge(base: object, override: object): SanctuaryConfig {
  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      typeof result[key] === "object" &&
      result[key] !== null
    ) {
      result[key] = deepMerge(
        result[key] as object,
        value as object
      );
    } else {
      result[key] = value;
    }
  }
  return result as unknown as SanctuaryConfig;
}
