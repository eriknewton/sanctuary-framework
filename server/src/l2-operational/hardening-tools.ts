/**
 * Sanctuary MCP Server — L2 Hardening Tools
 *
 * MCP tools for checking and verifying L2 operational isolation hardening.
 * These are Tier 3 tools — always allowed, read-only status checks.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import { assessL2Hardening } from "./hardening.js";
import type { AuditLog } from "./audit-log.js";

export function createL2HardeningTools(
  storagePath: string,
  auditLog: AuditLog
): ToolDefinition[] {
  return [
    {
      name: "l2_hardening_status",
      description:
        "L2 Process Hardening Status — Verify software-based operational isolation. " +
        "Reports memory protection, process isolation level, filesystem permissions, " +
        "and overall hardening assessment. Read-only. Tier 3 — always allowed.",
      inputSchema: {
        type: "object",
        properties: {
          include_details: {
            type: "boolean",
            description:
              "If true, include detailed check results for memory, process, and filesystem. " +
              "If false, show summary only.",
            default: false,
          },
        },
      },
      handler: async (args) => {
        const includeDetails = (args.include_details as boolean) ?? false;
        const status = assessL2Hardening(storagePath);

        auditLog.append(
          "l2",
          "l2_hardening_status",
          "system",
          { include_details: includeDetails }
        );

        if (includeDetails) {
          return toolResult({
            hardening_level: status.hardening_level,
            summary: status.summary,
            checks_passed: status.checks_passed,
            checks_total: status.checks_total,
            memory_protection: {
              aslr_enabled: status.memory_protection.aslr_enabled,
              stack_canaries: status.memory_protection.stack_canaries,
              secure_buffer_zeros: status.memory_protection.secure_buffer_zeros,
              argon2id_kdf: status.memory_protection.argon2id_kdf,
              overall: status.memory_protection.overall,
            },
            process_isolation: {
              isolation_level: status.process_isolation.isolation_level,
              is_container: status.process_isolation.is_container,
              is_vm: status.process_isolation.is_vm,
              is_sandboxed: status.process_isolation.is_sandboxed,
              is_tee: status.process_isolation.is_tee,
              details: status.process_isolation.details,
            },
            filesystem_permissions: {
              sanctuary_storage_protected:
                status.filesystem_permissions.sanctuary_storage_protected,
              sanctuary_storage_mode: status.filesystem_permissions.sanctuary_storage_mode,
              owner_is_current_user: status.filesystem_permissions.owner_is_current_user,
              group_readable: status.filesystem_permissions.group_readable,
              others_readable: status.filesystem_permissions.others_readable,
              overall: status.filesystem_permissions.overall,
            },
            runtime_integrity: {
              config_hash_stable: status.runtime_integrity.config_hash_stable,
              environment_state: status.runtime_integrity.environment_state,
              discrepancies: status.runtime_integrity.discrepancies,
            },
          });
        } else {
          return toolResult({
            hardening_level: status.hardening_level,
            summary: status.summary,
            checks_passed: status.checks_passed,
            checks_total: status.checks_total,
            note:
              "Pass include_details: true to see full breakdown of memory, " +
              "process isolation, and filesystem checks.",
          });
        }
      },
    },

    {
      name: "l2_verify_isolation",
      description:
        "Verify L2 process isolation at runtime. Checks whether the Sanctuary server " +
        "is running in an isolated environment (container, VM, sandbox) and validates " +
        "filesystem and memory protections. Reports isolation level and any issues. " +
        "Read-only. Tier 3 — always allowed.",
      inputSchema: {
        type: "object",
        properties: {
          check_filesystem: {
            type: "boolean",
            description:
              "If true, verify Sanctuary storage directory permissions.",
            default: true,
          },
          check_memory: {
            type: "boolean",
            description:
              "If true, verify memory protection mechanisms (ASLR, etc.).",
            default: true,
          },
          check_process: {
            type: "boolean",
            description:
              "If true, detect container, VM, or sandbox environment.",
            default: true,
          },
        },
      },
      handler: async (args) => {
        const checkFilesystem = (args.check_filesystem as boolean) ?? true;
        const checkMemory = (args.check_memory as boolean) ?? true;
        const checkProcess = (args.check_process as boolean) ?? true;

        const status = assessL2Hardening(storagePath);

        auditLog.append(
          "l2",
          "l2_verify_isolation",
          "system",
          {
            check_filesystem: checkFilesystem,
            check_memory: checkMemory,
            check_process: checkProcess,
          }
        );

        const results: Record<string, unknown> = {
          isolation_level: status.hardening_level,
          timestamp: new Date().toISOString(),
        };

        if (checkFilesystem) {
          const fs = status.filesystem_permissions;
          results.filesystem = {
            sanctuary_storage_protected: fs.sanctuary_storage_protected,
            storage_mode: fs.sanctuary_storage_mode,
            is_secure: fs.overall === "secure",
            issues:
              fs.overall === "insecure"
                ? [
                    "Storage directory is readable by group or others. " +
                    "Recommend: chmod 700 on Sanctuary storage path.",
                  ]
                : fs.overall === "warning"
                  ? [
                      "Storage directory not owned by current user. " +
                      "Verify correct user is running Sanctuary.",
                    ]
                  : [],
          };
        }

        if (checkMemory) {
          const mem = status.memory_protection;
          const issues: string[] = [];
          if (!mem.aslr_enabled) {
            issues.push(
              "ASLR not detected. On Linux, enable with: " +
              "echo 2 | sudo tee /proc/sys/kernel/randomize_va_space"
            );
          }
          results.memory = {
            aslr_enabled: mem.aslr_enabled,
            stack_canaries: mem.stack_canaries,
            secure_buffer_handling: mem.secure_buffer_zeros,
            argon2id_key_derivation: mem.argon2id_kdf,
            protection_level: mem.overall,
            issues,
          };
        }

        if (checkProcess) {
          const iso = status.process_isolation;
          results.process = {
            isolation_level: iso.isolation_level,
            in_container: iso.is_container,
            in_vm: iso.is_vm,
            sandboxed: iso.is_sandboxed,
            has_tee: iso.is_tee,
            environment: iso.details,
            recommendation:
              iso.isolation_level === "none"
                ? "Consider running Sanctuary in a container or VM for improved isolation."
                : iso.isolation_level === "basic"
                  ? "Basic isolation detected. Container or VM would provide stronger guarantees."
                  : "Running in isolated environment — process-level isolation is strong.",
          };
        }

        return toolResult({
          status: "verified",
          results,
        });
      },
    },
  ];
}
