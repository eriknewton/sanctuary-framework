/**
 * Castle Wall IPC Unix-Domain-Socket path resolver.
 *
 * Linux daemon (root-owned) listens at `/run/sanctuary/<fortress-id>/filter.sock`
 * via a privileged installer. The macOS NEFilterProvider system extension runs
 * unprivileged in user space and cannot bind a socket under `/var/run`; macOS
 * rootless protections block it. The fallback chain below produces the
 * canonical resolution order shared by both the macOS extension and the
 * Sanctuary main client. The Swift mirror at
 * `castle-wall-macos/Sources/CastleWallIPC/SocketPath.swift` MUST resolve to
 * the same path given the same inputs.
 *
 * Source: Castle Wall macOS Phase 1 Foundation spawn prompt (2026-05-11),
 * scope amendment dropping the pf-rule supervisor in favor of direct
 * NEFilterProvider scaffolding.
 */
export interface SocketPathInput {
  /** Detected platform; pass `process.platform`. */
  platform: NodeJS.Platform | string;
  /**
   * Fortress-id used to scope the Linux per-fortress runtime dir. Required
   * on Linux; ignored on macOS where the path is platform-flat.
   */
  fortressId?: string;
  /** Optional override resolved from `SANCTUARY_FORTRESS_PATH`. */
  fortressPath?: string;
  /** Optional override resolved from `os.homedir()`. */
  homeDir?: string;
  /**
   * Optional explicit override resolved from a `SANCTUARY_CASTLE_SOCKET`
   * env var. When set, takes precedence over the fallback chain on either
   * platform.
   */
  explicitOverride?: string;
}

export const CASTLE_WALL_ACTIVE_CONFIG_PATH = "/tmp/sanctuary-castle-active.json";

/** The resolved socket path plus a tag describing which fallback won. */
export interface ResolvedSocketPath {
  path: string;
  source:
    | "explicit_override"
    | "linux_per_fortress"
    | "macos_root_daemon"
    | "macos_per_fortress"
    | "macos_home_default";
}

/**
 * Resolve the UDS socket path the macOS extension or the Linux client
 * should connect to. Pure: no I/O, no syscalls. Path existence is the
 * caller's concern; this helper only chooses the canonical address.
 */
export function resolveCastleWallSocketPath(
  input: SocketPathInput
): ResolvedSocketPath {
  if (input.explicitOverride && input.explicitOverride.length > 0) {
    return { path: input.explicitOverride, source: "explicit_override" };
  }

  if (input.platform === "darwin") {
    if (input.fortressPath && input.fortressPath.length > 0) {
      return {
        path: `${stripTrailingSlash(input.fortressPath)}/castle.sock`,
        source: "macos_per_fortress",
      };
    }
    if (input.homeDir && input.homeDir.length > 0) {
      return {
        path: `${stripTrailingSlash(input.homeDir)}/.sanctuary/castle.sock`,
        source: "macos_home_default",
      };
    }
    return {
      path: "/var/run/sanctuary-castle.sock",
      source: "macos_root_daemon",
    };
  }

  if (input.platform === "linux") {
    const fortressId = input.fortressId ?? "default";
    return {
      path: `/run/sanctuary/${fortressId}/filter.sock`,
      source: "linux_per_fortress",
    };
  }

  if (input.fortressPath && input.fortressPath.length > 0) {
    return {
      path: `${stripTrailingSlash(input.fortressPath)}/castle.sock`,
      source: "macos_per_fortress",
    };
  }
  if (input.homeDir && input.homeDir.length > 0) {
    return {
      path: `${stripTrailingSlash(input.homeDir)}/.sanctuary/castle.sock`,
      source: "macos_home_default",
    };
  }
  return {
    path: "/var/run/sanctuary-castle.sock",
    source: "macos_root_daemon",
  };
}

function stripTrailingSlash(value: string): string {
  if (value.length > 1 && value.endsWith("/")) {
    return value.slice(0, -1);
  }
  return value;
}
