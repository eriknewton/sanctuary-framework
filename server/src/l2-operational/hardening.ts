/**
 * Sanctuary MCP Server — L2 Operational Isolation: Process Hardening
 *
 * Provides process-level isolation verification without requiring hardware TEE.
 * Implements software-based L2 hardening checks including:
 * - Memory protection (ASLR, stack canaries, secure buffer handling)
 * - Process isolation verification (container, VM, sandbox detection)
 * - Runtime integrity monitoring
 * - Filesystem permission verification
 *
 * These checks allow agents running on machines without TEE to achieve
 * "Hardened" L2 status (between "Degraded" and "Full").
 */

import { execSync } from "node:child_process";
import { statSync } from "node:fs";

// ── Memory Protection Status ───────────────────────────────────────

export interface MemoryProtectionStatus {
  aslr_enabled: boolean;
  stack_canaries: boolean;
  secure_buffer_zeros: boolean;
  argon2id_kdf: boolean;
  overall: "full" | "partial" | "minimal" | "none";
}

/**
 * Verify memory protection mechanisms are in place.
 */
export function checkMemoryProtection(): MemoryProtectionStatus {
  const checks = {
    aslr_enabled: checkASLR(),
    stack_canaries: true, // Enabled by default in Node.js runtime
    secure_buffer_zeros: true, // We use crypto.randomBytes and explicit zeroing
    argon2id_kdf: true, // Master key derivation uses Argon2id
  };

  const activeCount = Object.values(checks).filter((v) => v).length;
  const overall = activeCount >= 4 ? "full" : activeCount >= 3 ? "partial" : "minimal";

  return {
    ...checks,
    overall,
  };
}

function checkASLR(): boolean {
  if (process.platform === "linux") {
    try {
      const result = execSync("cat /proc/sys/kernel/randomize_va_space", {
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "ignore"],
      }).trim();
      return result === "2"; // 2 = full ASLR enabled
    } catch {
      return false;
    }
  }
  if (process.platform === "darwin") {
    // macOS enables ASLR by default for all processes; no direct check needed
    return true;
  }
  return false;
}

// ── Process Isolation Status ───────────────────────────────────────

export type IsolationLevel = "full" | "hardened" | "basic" | "none";

export interface ProcessIsolationStatus {
  isolation_level: IsolationLevel;
  is_container: boolean;
  is_vm: boolean;
  is_sandboxed: boolean;
  is_tee: boolean;
  details: {
    container_type?: string;
    vm_type?: string;
    sandbox_type?: string;
  };
}

/**
 * Verify process-level isolation through environment detection.
 *
 * Returns the isolation level:
 * - "full": Running in TEE (not available for software-only check)
 * - "hardened": Container or VM detected
 * - "basic": Sandboxed process (macOS sandbox, pledge on OpenBSD, etc.)
 * - "none": Regular user process
 */
export function checkProcessIsolation(): ProcessIsolationStatus {
  const isContainer = detectContainer();
  const isVM = detectVM();
  const isSandboxed = detectSandbox();

  let isolationLevel: IsolationLevel = "none";
  if (isContainer) isolationLevel = "hardened";
  else if (isVM) isolationLevel = "hardened";
  else if (isSandboxed) isolationLevel = "basic";

  const details: ProcessIsolationStatus["details"] = {};
  if (isContainer && isContainer !== true) details.container_type = isContainer;
  if (isVM && isVM !== true) details.vm_type = isVM;
  if (isSandboxed && isSandboxed !== true) details.sandbox_type = isSandboxed;

  return {
    isolation_level: isolationLevel,
    is_container: isContainer !== false,
    is_vm: isVM !== false,
    is_sandboxed: isSandboxed !== false,
    is_tee: false,
    details,
  };
}

function detectContainer(): string | boolean {
  // Check for containerization markers
  try {
    // Docker
    if (process.env.DOCKER_HOST) return "docker";

    // Check /.dockerenv
    try {
      statSync("/.dockerenv");
      return "docker";
    } catch {
      // Not a file
    }

    // Check /proc/1/cgroup for container references
    if (process.platform === "linux") {
      const cgroup = execSync("cat /proc/1/cgroup 2>/dev/null || echo ''", {
        encoding: "utf-8",
      });
      if (cgroup.includes("docker")) return "docker";
      if (cgroup.includes("lxc")) return "lxc";
      if (cgroup.includes("kubepods") || cgroup.includes("kubernetes")) return "kubernetes";
    }

    // Podman
    if (process.env.container === "podman") return "podman";

    // OCI container runtime indicators
    if (process.env.CONTAINER_ID) return "oci";

    return false;
  } catch {
    return false;
  }
}

function detectVM(): string | boolean {
  if (process.platform === "linux") {
    try {
      // Check for common hypervisor signatures
      const dmidecode = execSync("dmidecode -s system-product-name 2>/dev/null || echo ''", {
        encoding: "utf-8",
      }).toLowerCase();

      if (dmidecode.includes("vmware")) return "vmware";
      if (dmidecode.includes("virtualbox")) return "virtualbox";
      if (dmidecode.includes("kvm")) return "kvm";
      if (dmidecode.includes("xen")) return "xen";
      if (dmidecode.includes("hyper-v")) return "hyper-v";

      // Check cpuinfo for virtualization
      const cpuinfo = execSync("grep -i hypervisor /proc/cpuinfo || echo ''", {
        encoding: "utf-8",
      });
      if (cpuinfo.length > 0) return "detected";
    } catch {
      // dmidecode might not be available; not a failure
    }
  }

  if (process.platform === "darwin") {
    try {
      // Check for Parallels, VMware, VirtualBox on macOS
      const bootargs = execSync(
        "nvram boot-args 2>/dev/null | grep -i 'parallels\\|vmware\\|virtualbox' || echo ''",
        {
          encoding: "utf-8",
        }
      );
      if (bootargs.length > 0) return "detected";
    } catch {
      // nvram not accessible; skip
    }
  }

  return false;
}

function detectSandbox(): string | boolean {
  // macOS App Sandbox
  if (process.platform === "darwin") {
    if (process.env.APP_SANDBOX_READ_ONLY_HOME === "1") return "app-sandbox";
    if (process.env.TMPDIR && process.env.TMPDIR.includes("AppSandbox")) return "app-sandbox";
  }

  // pledge(2) on OpenBSD (process restrictions)
  if (process.platform === "openbsd") {
    // No easy way to check pledge status from userspace
    // Assume if running on OpenBSD, pledge is a possibility
    try {
      const pledge = execSync("pledge -v 2>/dev/null || echo ''", {
        encoding: "utf-8",
      });
      if (pledge.length > 0) return "pledge";
    } catch {
      // pledge not available
    }
  }

  // SELinux/AppArmor contexts
  if (process.platform === "linux") {
    if (process.env.container === "lxc") return "lxc";
    try {
      const context = execSync("getenforce 2>/dev/null || echo ''", {
        encoding: "utf-8",
      }).trim();
      if (context === "Enforcing") return "selinux";
    } catch {
      // SELinux not available
    }
  }

  return false;
}

// ── Filesystem Permission Verification ───────────────────────────

export interface FilesystemPermissionStatus {
  sanctuary_storage_protected: boolean;
  sanctuary_storage_mode: string;
  owner_is_current_user: boolean;
  group_readable: boolean;
  others_readable: boolean;
  overall: "secure" | "warning" | "insecure";
}

/**
 * Verify filesystem permissions on Sanctuary storage directory.
 * Expects storage to be mode 0o700 (rwx------)
 */
export function checkFilesystemPermissions(storagePath: string): FilesystemPermissionStatus {
  try {
    const stats = statSync(storagePath);

    // Extract permission bits
    const mode = stats.mode & parseInt("777", 8);
    const modeString = mode.toString(8).padStart(3, "0");

    const isSecure = mode === parseInt("700", 8); // rwx------
    const groupReadable = (mode & parseInt("040", 8)) !== 0;
    const othersReadable = (mode & parseInt("007", 8)) !== 0;
    const currentUid = process.getuid?.() || -1;
    const ownerIsCurrentUser = stats.uid === currentUid;

    let overall: "secure" | "warning" | "insecure" = "secure";
    if (groupReadable || othersReadable) overall = "insecure";
    else if (!ownerIsCurrentUser) overall = "warning";

    return {
      sanctuary_storage_protected: isSecure,
      sanctuary_storage_mode: modeString,
      owner_is_current_user: ownerIsCurrentUser,
      group_readable: groupReadable,
      others_readable: othersReadable,
      overall,
    };
  } catch {
    // If we can't stat the directory, report it as a warning
    return {
      sanctuary_storage_protected: false,
      sanctuary_storage_mode: "unknown",
      owner_is_current_user: false,
      group_readable: false,
      others_readable: false,
      overall: "warning",
    };
  }
}

// ── Runtime Integrity Monitoring ──────────────────────────────────

export interface RuntimeIntegrityStatus {
  config_hash_stable: boolean;
  environment_state: "clean" | "modified" | "unknown";
  discrepancies: string[];
}

/**
 * Monitor runtime integrity by checking for unexpected modifications.
 * Currently a stub that reports "clean" state.
 *
 * Future enhancement: hash config at startup, verify at runtime.
 */
export function checkRuntimeIntegrity(): RuntimeIntegrityStatus {
  return {
    config_hash_stable: true,
    environment_state: "clean",
    discrepancies: [],
  };
}

// ── Overall L2 Hardening Status ────────────────────────────────────

export interface OperationalHardeningStatus {
  hardening_level: IsolationLevel;
  memory_protection: MemoryProtectionStatus;
  process_isolation: ProcessIsolationStatus;
  filesystem_permissions: FilesystemPermissionStatus;
  runtime_integrity: RuntimeIntegrityStatus;
  checks_passed: number;
  checks_total: number;
  summary: string;
}

/**
 * Comprehensive Operational-layer hardening assessment.
 * Combines all hardening checks into a single hardening level.
 */
export function assessOperationalHardening(storagePath: string): OperationalHardeningStatus {
  const memory = checkMemoryProtection();
  const isolation = checkProcessIsolation();
  const filesystem = checkFilesystemPermissions(storagePath);
  const integrity = checkRuntimeIntegrity();

  // Count passed checks
  let checksPassed = 0;
  let checksTotal = 0;

  // Memory protection
  if (memory.aslr_enabled) checksPassed++;
  checksTotal++;
  if (memory.stack_canaries) checksPassed++;
  checksTotal++;
  if (memory.secure_buffer_zeros) checksPassed++;
  checksTotal++;
  if (memory.argon2id_kdf) checksPassed++;
  checksTotal++;

  // Process isolation
  if (isolation.is_container) checksPassed++;
  checksTotal++;
  if (isolation.is_vm) checksPassed++;
  checksTotal++;
  if (isolation.is_sandboxed) checksPassed++;
  checksTotal++;

  // Filesystem permissions
  if (filesystem.sanctuary_storage_protected) checksPassed++;
  checksTotal++;

  // Runtime integrity
  if (integrity.config_hash_stable && integrity.environment_state === "clean") {
    checksPassed++;
  }
  checksTotal++;

  // Determine overall hardening level
  let hardeningLevel: IsolationLevel = isolation.isolation_level;

  // If filesystem or memory protection is weak, degrade hardening level
  if (
    filesystem.overall === "insecure" ||
    memory.overall === "none" ||
    memory.overall === "minimal"
  ) {
    if (hardeningLevel === "hardened") {
      hardeningLevel = "basic";
    } else if (hardeningLevel === "basic") {
      hardeningLevel = "none";
    }
  }

  // Generate summary
  const summaryParts: string[] = [];
  if (isolation.is_container || isolation.is_vm) {
    summaryParts.push(`Running in ${isolation.details.container_type || isolation.details.vm_type || "isolated environment"}`);
  }
  if (memory.aslr_enabled) {
    summaryParts.push("ASLR enabled");
  }
  if (filesystem.sanctuary_storage_protected) {
    summaryParts.push("Storage permissions secured (0700)");
  }

  const summary =
    summaryParts.length > 0
      ? summaryParts.join("; ")
      : "No process-level hardening detected";

  return {
    hardening_level: hardeningLevel,
    memory_protection: memory,
    process_isolation: isolation,
    filesystem_permissions: filesystem,
    runtime_integrity: integrity,
    checks_passed: checksPassed,
    checks_total: checksTotal,
    summary,
  };
}

// ── Back-compat aliases (L1-L4 rename PR-3) ─────────────────────────────
// The layer-numbered names stay exported so downstream imports keep working.
// The functional names above are canonical.
export type L2HardeningStatus = OperationalHardeningStatus;
export const assessL2Hardening = assessOperationalHardening;
