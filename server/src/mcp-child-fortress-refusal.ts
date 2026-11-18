import { isAbsolute, resolve } from "node:path";

// Must match initializedFortressExists in evidence-pack/existing-fortress.ts; the child retains its root-link policy.
export { initializedFortressExists as mcpChildFortressExists } from "./evidence-pack/existing-fortress.js";
import { initializedFortressExists as mcpChildFortressExists } from "./evidence-pack/existing-fortress.js";

import { loadConfig } from "./config.js";

export const FORTRESS_NOT_FOUND_EXIT_CODE = 78;
export const FORTRESS_LIFECYCLE_DOCS_URL =
  "https://github.com/eriknewton/sanctuary-framework/blob/main/server/docs/fortress-lifecycle.md";

export interface FortressNotFoundErrorLine {
  level: "error";
  code: "FORTRESS_NOT_FOUND";
  fortress_path: string;
  message: string;
  docs_url: string;
  caller_kind: "mcp_child";
}

export function buildFortressNotFoundErrorLine(
  fortressPath: string,
): FortressNotFoundErrorLine {
  return {
    level: "error",
    code: "FORTRESS_NOT_FOUND",
    fortress_path: fortressPath,
    message:
      "Sanctuary fortress not found at the resolved path. The MCP child refuses to silently initialize a fortress. Run sanctuary init to create one explicitly, or set SANCTUARY_FORTRESS_PATH to point at an existing fortress.",
    docs_url: FORTRESS_LIFECYCLE_DOCS_URL,
    caller_kind: "mcp_child",
  };
}

export async function resolveMcpChildFortressPath(): Promise<string> {
  const config = await loadConfig();
  return isAbsolute(config.storage_path)
    ? config.storage_path
    : resolve(process.cwd(), config.storage_path);
}

export async function refuseMissingMcpChildFortressOrExit(): Promise<void> {
  const fortressPath = await resolveMcpChildFortressPath();
  if (await mcpChildFortressExists(fortressPath)) return;

  process.stderr.write(
    `${JSON.stringify(buildFortressNotFoundErrorLine(fortressPath))}\n`,
  );
  process.exit(FORTRESS_NOT_FOUND_EXIT_CODE);
}
