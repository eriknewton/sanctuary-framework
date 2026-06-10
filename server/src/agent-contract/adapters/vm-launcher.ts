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

/**
 * B2 inner-confinement guest-jail delivery fields, mirrored from the Swift
 * CLI surface (SanctuaryVMMCLI GuestExecCLIRequest/RunBoxCLIRequest and
 * SanctuaryGuestJail.parseDelivery). Validation here is fail-closed and
 * intentionally consistent with the Swift parser: a partial static-binary
 * config (path without hash, hash without path, static fields under python
 * mode, malformed hash) is rejected host-side BEFORE the launcher is even
 * spawned — it never falls back to a different delivery mode.
 */
export interface GuestJailDeliveryFields {
  /**
   * B2 inner-confinement toggle. Defaults to true in the Swift CLI
   * (production default); set false ONLY for drill baselines.
   */
  applyGuestJail?: boolean;
  /** "python-preamble" (default) or "static-binary". Unknown values fail closed. */
  guestJailDelivery?: "python-preamble" | "static-binary";
  /**
   * TRUSTED-ADMIN TCB INPUT. Host path to the STATIC aarch64 sanctuary-jail
   * binary; required when guestJailDelivery is "static-binary", rejected
   * otherwise. The path alone is NOT trusted: the launcher authenticates
   * the staged copy against staticJailBinarySHA256.
   */
  staticJailBinaryPath?: string;
  /**
   * TRUSTED-ADMIN TCB INPUT. Pinned SHA-256 (64 hex chars) of the
   * sanctuary-jail artifact, sourced from the sanctuary-jail-static CI
   * job's SHA256SUMS manifest. REQUIRED with "static-binary" (no hash, no
   * static delivery); the Swift launcher verifies it against the STAGED
   * copy before boot and refuses to launch on mismatch.
   */
  staticJailBinarySHA256?: string;
}

export interface VMGuestExecRequest {
  /** Harness identifier (e.g. "claude-code"). */
  harnessId: "claude-code";
  /** Full CLI request JSON for sanctuary-vmm guest-exec. */
  cliRequest: GuestJailDeliveryFields & {
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
  cliRequest: GuestJailDeliveryFields & {
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

const SHA256_HEX_RE = /^[0-9a-fA-F]{64}$/;

/**
 * Fail-closed guest-jail delivery validation, mirroring
 * SanctuaryGuestJail.parseDelivery in the Swift CLI. Throws on any partial
 * or inconsistent static-binary configuration so a misconfigured request
 * never reaches the launcher (and can never be silently interpreted as the
 * default python-preamble delivery).
 */
export function assertGuestJailDeliveryConfig(fields: GuestJailDeliveryFields): void {
  const mode = fields.guestJailDelivery;
  const path = fields.staticJailBinaryPath;
  const sha = fields.staticJailBinarySHA256;

  if (mode === undefined || mode === "python-preamble") {
    if (path !== undefined && path !== "") {
      throw new Error(
        "vm-launcher: staticJailBinaryPath provided but guestJailDelivery is not 'static-binary' (fail closed)",
      );
    }
    if (sha !== undefined && sha !== "") {
      throw new Error(
        "vm-launcher: staticJailBinarySHA256 provided but guestJailDelivery is not 'static-binary' (fail closed)",
      );
    }
    return;
  }

  if (mode === "static-binary") {
    if (path === undefined || path === "") {
      throw new Error(
        "vm-launcher: guestJailDelivery 'static-binary' requires staticJailBinaryPath (fail closed)",
      );
    }
    if (sha === undefined || sha === "") {
      throw new Error(
        "vm-launcher: guestJailDelivery 'static-binary' requires staticJailBinarySHA256 " +
          "(64 hex chars, pinned from the sanctuary-jail-static CI SHA256SUMS manifest). " +
          "No hash, no static delivery (fail closed)",
      );
    }
    if (!SHA256_HEX_RE.test(sha)) {
      throw new Error(
        "vm-launcher: staticJailBinarySHA256 is malformed (expected exactly 64 hex characters). " +
          "No hash, no static delivery (fail closed)",
      );
    }
    return;
  }

  throw new Error(
    `vm-launcher: unknown guestJailDelivery '${String(mode)}' (expected 'python-preamble' or 'static-binary'; fail closed)`,
  );
}

/**
 * Build the argv tail for a sanctuary-vmm subcommand: validates the
 * guest-jail delivery config (fail closed) then serializes the full CLI
 * request. Exported for tests — this is the exact serialization path both
 * launch methods use.
 */
export function buildVmmCliArgs(
  subcommand: "guest-exec" | "run-box",
  cliRequest: VMGuestExecRequest["cliRequest"] | VMRunBoxRequest["cliRequest"],
): string[] {
  assertGuestJailDeliveryConfig(cliRequest);
  return [subcommand, "--json", JSON.stringify(cliRequest)];
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
      ...buildVmmCliArgs("guest-exec", request.cliRequest),
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
      ...buildVmmCliArgs("run-box", request.cliRequest),
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
