/**
 * Sanctuary MCP Server — Configuration
 *
 * Loads and validates server configuration from file or environment variables.
 */

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json");

/** Package version, exported for use by other modules (avoids duplicate require paths). */
export const SANCTUARY_VERSION = PKG_VERSION;

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
    /** Bearer token for dashboard auth. If "auto", one is generated at startup. */
    auth_token?: string;
    /** Auto-open dashboard in default browser on startup. Default: true for localhost. */
    auto_open?: boolean;
    /** TLS cert/key paths for HTTPS dashboard. */
    tls?: {
      cert_path: string;
      key_path: string;
    };
  };

  webhook: {
    enabled: boolean;
    /** URL to POST approval requests to */
    url: string;
    /** Shared secret for HMAC-SHA256 signatures */
    secret: string;
    /** Port for callback listener (receives approval responses) */
    callback_port: number;
    /** Host for callback listener */
    callback_host: string;
  };
}

/** Default configuration */
export function defaultConfig(): SanctuaryConfig {
  return {
    version: PKG_VERSION,
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
    webhook: {
      enabled: false,
      url: "",
      secret: "",
      callback_port: 3502,
      callback_host: "127.0.0.1",
    },
  };
}

/**
 * Load configuration from file, falling back to defaults.
 *
 * Precedence (highest wins): CLI flags > env vars > config file > defaults
 * This matches the standard config precedence pattern used by most tools.
 */
export async function loadConfig(
  configPath?: string
): Promise<SanctuaryConfig> {
  let config = defaultConfig();

  // Phase 1: Merge config file on top of defaults
  const storagePath = process.env.SANCTUARY_STORAGE_PATH ?? config.storage_path;
  const path = configPath ?? join(storagePath, "sanctuary.json");

  try {
    const raw = await readFile(path, "utf-8");
    const fileConfig = JSON.parse(raw);
    config = deepMerge(config, fileConfig);
  } catch (err) {
    // Re-throw validation errors — only swallow file-not-found
    if (err instanceof Error && err.message.includes("unimplemented features")) {
      throw err;
    }
    // No config file — continue with defaults
  }

  // Phase 2: Apply env var overrides ON TOP of file config (env always wins)
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
  if (process.env.SANCTUARY_DASHBOARD_ENABLED === "false") {
    config.dashboard.enabled = false;
  }
  if (process.env.SANCTUARY_DASHBOARD_PORT) {
    config.dashboard.port = parseInt(process.env.SANCTUARY_DASHBOARD_PORT, 10);
  }
  if (process.env.SANCTUARY_DASHBOARD_HOST) {
    config.dashboard.host = process.env.SANCTUARY_DASHBOARD_HOST;
  }
  if (process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN) {
    config.dashboard.auth_token = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
  }
  if (process.env.SANCTUARY_DASHBOARD_AUTO_OPEN === "true") {
    config.dashboard.auto_open = true;
  }
  if (process.env.SANCTUARY_DASHBOARD_AUTO_OPEN === "false") {
    config.dashboard.auto_open = false;
  }
  if (process.env.SANCTUARY_DASHBOARD_TLS_CERT && process.env.SANCTUARY_DASHBOARD_TLS_KEY) {
    config.dashboard.tls = {
      cert_path: process.env.SANCTUARY_DASHBOARD_TLS_CERT,
      key_path: process.env.SANCTUARY_DASHBOARD_TLS_KEY,
    };
  }
  if (process.env.SANCTUARY_WEBHOOK_ENABLED === "true") {
    config.webhook.enabled = true;
  }
  if (process.env.SANCTUARY_WEBHOOK_ENABLED === "false") {
    config.webhook.enabled = false;
  }
  if (process.env.SANCTUARY_WEBHOOK_URL) {
    config.webhook.url = process.env.SANCTUARY_WEBHOOK_URL;
  }
  if (process.env.SANCTUARY_WEBHOOK_SECRET) {
    config.webhook.secret = process.env.SANCTUARY_WEBHOOK_SECRET;
  }
  if (process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT) {
    config.webhook.callback_port = parseInt(process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT, 10);
  }
  if (process.env.SANCTUARY_WEBHOOK_CALLBACK_HOST) {
    config.webhook.callback_host = process.env.SANCTUARY_WEBHOOK_CALLBACK_HOST;
  }

  // Phase 3: Always stamp the running version from package.json (Bug 2 fix —
  // sanctuary.json may store a stale version from first run)
  config.version = PKG_VERSION;

  validateConfig(config);
  return config;
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

/**
 * Validate that config does not reference unimplemented features.
 * Throws a descriptive error if any unimplemented value is found.
 * This prevents silent security degradation (SEC-019).
 */
export function validateConfig(config: SanctuaryConfig): void {
  const errors: string[] = [];

  // Implemented key_protection values: "passphrase", "none"
  // Unimplemented: "hardware-key" (planned for future FIDO2/WebAuthn support)
  const implementedKeyProtection = new Set(["passphrase", "none"]);
  if (!implementedKeyProtection.has(config.state.key_protection)) {
    errors.push(
      `Unimplemented config value: state.key_protection = "${config.state.key_protection}". ` +
      `Only ${[...implementedKeyProtection].map(v => `"${v}"`).join(", ")} are currently implemented. ` +
      `Using an unimplemented key protection mode would silently degrade security.`
    );
  }

  // Implemented environment values: "local-process", "docker"
  // Unimplemented: "tee" (TEE-backed execution attestation not yet integrated)
  const implementedEnvironment = new Set(["local-process", "docker"]);
  if (!implementedEnvironment.has(config.execution.environment)) {
    errors.push(
      `Unimplemented config value: execution.environment = "${config.execution.environment}". ` +
      `Only ${[...implementedEnvironment].map(v => `"${v}"`).join(", ")} are currently implemented. ` +
      `Using an unimplemented environment would silently degrade security.`
    );
  }

  // Implemented proof_system values: "commitment-only"
  // Unimplemented: "groth16", "plonk" (SNARK proof systems not yet available)
  const implementedProofSystem = new Set(["commitment-only"]);
  if (!implementedProofSystem.has(config.disclosure.proof_system)) {
    errors.push(
      `Unimplemented config value: disclosure.proof_system = "${config.disclosure.proof_system}". ` +
      `Only ${[...implementedProofSystem].map(v => `"${v}"`).join(", ")} is currently implemented. ` +
      `Using an unimplemented proof system would silently degrade security.`
    );
  }

  // Implemented disclosure.default_policy values: "minimum-necessary"
  // Unimplemented: "withhold-all" (global withhold policy not yet implemented)
  const implementedDisclosurePolicy = new Set(["minimum-necessary"]);
  if (!implementedDisclosurePolicy.has(config.disclosure.default_policy)) {
    errors.push(
      `Unimplemented config value: disclosure.default_policy = "${config.disclosure.default_policy}". ` +
      `Only ${[...implementedDisclosurePolicy].map(v => `"${v}"`).join(", ")} is currently implemented. ` +
      `Using an unimplemented disclosure policy would silently skip disclosure controls.`
    );
  }

  // Implemented reputation.mode values: "self-custodied"
  // Unimplemented: "service-mediated" (third-party reputation service not yet integrated)
  const implementedReputationMode = new Set(["self-custodied"]);
  if (!implementedReputationMode.has(config.reputation.mode)) {
    errors.push(
      `Unimplemented config value: reputation.mode = "${config.reputation.mode}". ` +
      `Only ${[...implementedReputationMode].map(v => `"${v}"`).join(", ")} is currently implemented. ` +
      `Using an unimplemented reputation mode would silently skip reputation verification.`
    );
  }

  if (errors.length > 0) {
    throw new Error(
      `Sanctuary configuration references unimplemented features:\n${errors.join("\n")}`
    );
  }
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
