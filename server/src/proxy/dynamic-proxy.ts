import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { ToolDefinition } from "../router.js";
import type { ProxyRouter } from "./proxy-router.js";

const PROXY_TOOL_PREFIX = "proxy/";

export interface DynamicProxyToolRegistryOptions {
  tools: ToolDefinition[];
  proxyRouter: ProxyRouter;
  notifyListChanged?: () => Promise<void>;
}

export interface DynamicProxyRefreshResult {
  changed: boolean;
  tool_count: number;
}

export class DynamicProxyToolRegistry {
  private tools: ToolDefinition[];
  private proxyRouter: ProxyRouter;
  private notifyListChanged?: () => Promise<void>;
  private fingerprint = "";

  constructor(options: DynamicProxyToolRegistryOptions) {
    this.tools = options.tools;
    this.proxyRouter = options.proxyRouter;
    this.notifyListChanged = options.notifyListChanged;
  }

  refresh(): DynamicProxyRefreshResult {
    const nextProxyTools = this.proxyRouter.getProxiedTools();
    const nextFingerprint = fingerprintTools(nextProxyTools);
    if (nextFingerprint === this.fingerprint) {
      return { changed: false, tool_count: nextProxyTools.length };
    }

    for (let idx = this.tools.length - 1; idx >= 0; idx -= 1) {
      if (this.tools[idx]!.name.startsWith(PROXY_TOOL_PREFIX)) {
        this.tools.splice(idx, 1);
      }
    }

    this.tools.push(...nextProxyTools);
    this.fingerprint = nextFingerprint;
    void this.notifyListChanged?.().catch(() => {});
    return { changed: true, tool_count: nextProxyTools.length };
  }
}

export function enableToolListChangedNotifications(server: Server): void {
  server.registerCapabilities({
    tools: {
      listChanged: true,
    },
  });
}

function fingerprintTools(tools: ToolDefinition[]): string {
  return tools
    .map((tool) => `${tool.name}\u0000${JSON.stringify(tool.inputSchema)}`)
    .sort()
    .join("\u0001");
}
