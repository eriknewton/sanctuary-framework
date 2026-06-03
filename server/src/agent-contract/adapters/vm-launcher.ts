/**
 * VM launcher adapter — spawns `sanctuary-vmm guest-exec` to run an agent
 * process inside a no-network Linux VM using Apple's Containerization library.
 *
 * B1 re-platform: the binary is the new Apple Containerization-based launcher
 * (castle-wall-macos/Sources/SanctuaryVMM). It replaces the hand-rolled guest
 * plumbing (sanctuary-init, raw-fd vsock bridge, busybox modprobe).
 *
 * The launcher filters sensitive environment variables before passing them to
 * the subprocess. The VM itself has no network interface; egress flows through
 * a single vsock port to the host-side allowlist proxy (egress-proxy.ts).
 */

import { spawn } from "node:child_process";

export interface VMGuestExecRequest {
  /** Harness identifier (e.g. "claude-code"). */
  harnessId: "claude-code";
  /** Full CLI request JSON for sanctuary-vmm guest-exec. */
  cliRequest: {
    kernelPath: string;
    ociImageReference: string;
    command: string;
    args: string[];
    cwd: string;
    env: Record<string, string>;
    initfsReference?: string;
    rootfsSizeBytes?: number;
    cpuCount?: number;
    memoryBytes?: number;
    egressVsockPort?: number;
    rootfsPins?: Array<{ sha256: string; artifact: string }>;
  };
}

export interface VMRunBoxRequest {
  /** Harness identifier (e.g. "claude-code"). */
  harnessId: "claude-code";
  /** Full CLI request JSON for sanctuary-vmm run-box. */
  cliRequest: {
    kernelPath: string;
    ociImageReference: string;
    command: string;
    args: string[];
    cwd: string;
    env: Record<string, string>;
    initfsReference?: string;
    rootfsSizeBytes?: number;
    cpuCount?: number;
    memoryBytes?: number;
    egressVsockPort?: number;
    /**
     * Host-side Unix socket path the egress allowlist proxy (egress-proxy.ts)
     * listens on. The guest reaches it via Apple's `.into` socket relay
     * (guest UDS -> vsock -> this host UDS); see SanctuaryVsockEgressConfig.
     */
    egressProxyUdsPath: string;
    egressGuestSocketPath?: string;
    rootfsPins?: Array<{ sha256: string; artifact: string }>;
  };
}

export interface VMGuestExecHandle {
  launchId: string;
  pid?: number;
}

export interface VMManagedLauncher {
  launchGuestExec(request: VMGuestExecRequest): Promise<VMGuestExecHandle>;
}

export class SanctuaryVMMCliLauncher implements VMManagedLauncher {
  constructor(
    private readonly options: {
      binary?: string;
      extraArgs?: string[];
    } = {},
  ) {}

  async launchGuestExec(request: VMGuestExecRequest): Promise<VMGuestExecHandle> {
    const binary = this.options.binary ?? "sanctuary-vmm";
    const args = [
      ...(this.options.extraArgs ?? []),
      "guest-exec",
      "--json",
      JSON.stringify(request.cliRequest),
    ];

    const child = spawn(binary, args, {
      stdio: "ignore",
      detached: true,
      env: filterLauncherEnv(process.env),
    });

    return await new Promise<VMGuestExecHandle>((resolve, reject) => {
      child.once("error", reject);
      child.once("spawn", () => {
        child.unref();
        resolve({
          launchId: `sanctuary-vmm:${child.pid ?? "unknown"}`,
          pid: child.pid,
        });
      });
    });
  }

  async launchRunBox(request: VMRunBoxRequest): Promise<VMGuestExecHandle> {
    const binary = this.options.binary ?? "sanctuary-vmm";
    const args = [
      ...(this.options.extraArgs ?? []),
      "run-box",
      "--json",
      JSON.stringify(request.cliRequest),
    ];

    const child = spawn(binary, args, {
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
      env: filterLauncherEnv(process.env),
    });

    return await new Promise<VMGuestExecHandle>((resolve, reject) => {
      child.once("error", reject);
      child.once("spawn", () => {
        child.unref();
        resolve({
          launchId: `sanctuary-vmm:${child.pid ?? "unknown"}`,
          pid: child.pid,
        });
      });
    });
  }
}

function filterLauncherEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const filtered: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    if (isSecretEnvKey(key)) continue;
    filtered[key] = value;
  }
  return filtered;
}

export function isSecretEnvKey(key: string): boolean {
  return (
    key.includes("PRIVATE_KEY") ||
    key.includes("MASTER_SECRET") ||
    key.includes("PASSPHRASE") ||
    key.includes("API_KEY") ||
    key.includes("TOKEN") ||
    key.includes("SECRET") ||
    key.includes("IDENTITY") ||
    key.startsWith("SANCTUARY_KEY_")
  );
}
