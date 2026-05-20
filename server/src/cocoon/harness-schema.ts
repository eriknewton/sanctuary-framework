import { basename, dirname, sep } from "node:path";

export type HarnessSchema =
  | { kind: "openclaw"; nativeKey: "mcp.servers" }
  | { kind: "claude-code"; nativeKey: "mcpServers" }
  | { kind: "cursor"; nativeKey: "mcpServers" }
  | { kind: "hermes"; nativeKey: "mcp_servers" }
  | { kind: "cline"; nativeKey: "mcpServers" }
  | { kind: "generic"; nativeKey: "mcpServers" };

export function detectHarnessSchema(
  configPath: string,
  configContent: object
): HarnessSchema {
  const file = basename(configPath).toLowerCase();
  const parent = basename(dirname(configPath)).toLowerCase();
  const normalizedPath = configPath.toLowerCase().split(sep).join("/");
  const obj = configContent as Record<string, unknown>;

  if (
    /^openclaw.*\.json$/.test(file) ||
    normalizedPath.includes("/.openclaw/") ||
    normalizedPath.includes("/application support/openclaw/") ||
    hasNestedMcpServers(obj) ||
    hasAnyKey(obj, ["openClawVersion", "openclawVersion", "openclaw_version"])
  ) {
    return { kind: "openclaw", nativeKey: "mcp.servers" };
  }

  if (
    (file === "cli-config.json" && normalizedPath.includes("/.hermes/")) ||
    normalizedPath.includes("/.config/hermes/") ||
    hasPlainObject(obj.mcp_servers)
  ) {
    return { kind: "hermes", nativeKey: "mcp_servers" };
  }

  if (
    file === "cline_mcp_settings.json" ||
    normalizedPath.includes("/saoudrizwan.claude-dev/")
  ) {
    return { kind: "cline", nativeKey: "mcpServers" };
  }

  if (file === "mcp.json" && parent === ".cursor") {
    return { kind: "cursor", nativeKey: "mcpServers" };
  }

  if (
    file === "claude.json" ||
    file === ".claude.json" ||
    file === "claude_desktop_config.json" ||
    normalizedPath.includes("/.claude/") ||
    normalizedPath.includes("/claude-code/") ||
    hasPlainObject(obj.mcpServers)
  ) {
    return { kind: "claude-code", nativeKey: "mcpServers" };
  }

  return { kind: "generic", nativeKey: "mcpServers" };
}

function hasNestedMcpServers(obj: Record<string, unknown>): boolean {
  const mcp = obj.mcp as Record<string, unknown> | undefined;
  return hasPlainObject(mcp?.servers);
}

function hasPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function hasAnyKey(obj: Record<string, unknown>, keys: string[]): boolean {
  return keys.some((key) => Object.prototype.hasOwnProperty.call(obj, key));
}
