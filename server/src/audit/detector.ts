/**
 * Sanctuary MCP Server — Environment Detector
 *
 * Read-only environment fingerprinting. Probes the local filesystem to detect
 * what sovereignty infrastructure is installed (Sanctuary config, OpenClaw, etc.).
 *
 * IMPORTANT: This module is strictly read-only. It MUST NOT write, create, modify,
 * or delete any files or make any network requests.
 */

import { readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import type { SanctuaryConfig } from "../config.js";
import type { EnvironmentFingerprint, OpenClawConfigAudit } from "./types.js";

/**
 * Strip single-line comments (// ...), block comments, and trailing commas
 * from a JSON5-ish string so it can be parsed by JSON.parse.
 */
function lenientJsonParse(raw: string): unknown {
  // Remove single-line comments
  let cleaned = raw.replace(/\/\/[^\n]*/g, "");
  // Remove block comments
  cleaned = cleaned.replace(/\/\*[\s\S]*?\*\//g, "");
  // Remove trailing commas before } or ]
  cleaned = cleaned.replace(/,\s*([\]}])/g, "$1");
  return JSON.parse(cleaned);
}

/**
 * Check if a file exists (read-only).
 */
async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Safely read a file, returning null if it doesn't exist or can't be read.
 */
async function safeReadFile(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf-8");
  } catch {
    return null;
  }
}

/**
 * Detect the local environment and produce a fingerprint.
 * This function is strictly read-only.
 */
export async function detectEnvironment(
  config: SanctuaryConfig,
  deepScan: boolean
): Promise<EnvironmentFingerprint> {
  const fingerprint: EnvironmentFingerprint = {
    sanctuary_installed: true, // We're running inside Sanctuary
    sanctuary_version: config.version,
    openclaw_detected: false,
    openclaw_version: null,
    openclaw_config: null,
    node_version: process.version,
    platform: `${process.platform}-${process.arch}`,
  };

  if (!deepScan) {
    return fingerprint;
  }

  // Detect OpenClaw
  const home = homedir();
  const openclawConfigPath = join(home, ".openclaw", "openclaw.json");
  const openclawEnvPath = join(home, ".openclaw", ".env");
  const openclawMemoryPath = join(home, ".openclaw", "workspace", "MEMORY.md");
  const openclawMemoryDir = join(home, ".openclaw", "workspace", "memory");

  const configExists = await fileExists(openclawConfigPath);
  const envExists = await fileExists(openclawEnvPath);
  const memoryExists = await fileExists(openclawMemoryPath);
  const memoryDirExists = await fileExists(openclawMemoryDir);

  // OpenClaw is detected if its config file or workspace exists
  if (configExists || memoryExists || memoryDirExists) {
    fingerprint.openclaw_detected = true;
    fingerprint.openclaw_config = await auditOpenClawConfig(
      openclawConfigPath,
      openclawEnvPath,
      openclawMemoryPath,
      configExists,
      envExists,
      memoryExists
    );
  }

  return fingerprint;
}

/**
 * Audit OpenClaw configuration (read-only).
 */
async function auditOpenClawConfig(
  configPath: string,
  envPath: string,
  _memoryPath: string,
  configExists: boolean,
  envExists: boolean,
  memoryExists: boolean
): Promise<OpenClawConfigAudit> {
  const audit: OpenClawConfigAudit = {
    config_path: configExists ? configPath : null,
    require_approval_enabled: false,
    sandbox_policy_active: false,
    sandbox_allow_list: [],
    sandbox_deny_list: [],
    memory_encrypted: false,     // Stock OpenClaw never encrypts memory
    env_file_exposed: false,
    gateway_token_set: false,
    dm_pairing_enabled: false,
    mcp_bridge_active: false,
  };

  // Parse OpenClaw config
  if (configExists) {
    const raw = await safeReadFile(configPath);
    if (raw) {
      try {
        const parsed = lenientJsonParse(raw) as Record<string, unknown>;

        // Check for version
        // OpenClaw may store version at top level
        // (We don't set openclaw_version on the fingerprint here — caller does that)

        // Check hooks for requireApproval
        const hooks = parsed.hooks as Record<string, unknown> | undefined;
        if (hooks) {
          const beforeToolCall = hooks.before_tool_call;
          if (beforeToolCall) {
            const hookStr = JSON.stringify(beforeToolCall);
            audit.require_approval_enabled = hookStr.includes("requireApproval");
          }
        }

        // Check sandbox policy
        const tools = parsed.tools as Record<string, unknown> | undefined;
        if (tools) {
          const sandbox = tools.sandbox as Record<string, unknown> | undefined;
          if (sandbox) {
            const sandboxTools = sandbox.tools as Record<string, unknown> | undefined;
            if (sandboxTools) {
              audit.sandbox_policy_active = true;
              if (Array.isArray(sandboxTools.allow)) {
                audit.sandbox_allow_list = sandboxTools.allow.filter(
                  (item): item is string => typeof item === "string"
                );
              }
              // Also check alsoAllow (OpenClaw v2026.3.28+)
              if (Array.isArray(sandboxTools.alsoAllow)) {
                audit.sandbox_allow_list = [
                  ...audit.sandbox_allow_list,
                  ...sandboxTools.alsoAllow.filter(
                    (item): item is string => typeof item === "string"
                  ),
                ];
              }
              if (Array.isArray(sandboxTools.deny)) {
                audit.sandbox_deny_list = sandboxTools.deny.filter(
                  (item): item is string => typeof item === "string"
                );
              }
            }
          }
        }

        // Check for MCP bridge
        const mcpServers = parsed.mcpServers as Record<string, unknown> | undefined;
        if (mcpServers && Object.keys(mcpServers).length > 0) {
          audit.mcp_bridge_active = true;
        }
      } catch {
        // Config exists but couldn't be parsed — leave defaults
      }
    }
  }

  // Check .env for plaintext secrets
  if (envExists) {
    const envContent = await safeReadFile(envPath);
    if (envContent) {
      const secretPatterns = [
        /[A-Z_]*API_KEY\s*=/,
        /[A-Z_]*TOKEN\s*=/,
        /[A-Z_]*SECRET\s*=/,
        /[A-Z_]*PASSWORD\s*=/,
        /[A-Z_]*PRIVATE_KEY\s*=/,
      ];
      audit.env_file_exposed = secretPatterns.some((p) => p.test(envContent));
      audit.gateway_token_set = /OPENCLAW_GATEWAY_TOKEN\s*=/.test(envContent);
    }
  }

  // Memory is always plaintext in stock OpenClaw
  if (memoryExists) {
    audit.memory_encrypted = false;
  }

  return audit;
}
