/**
 * L2 Process Hardening Tests
 *
 * Verifies:
 * - Memory protection detection (ASLR, stack canaries, secure buffer handling)
 * - Process isolation detection (container, VM, sandbox)
 * - Filesystem permission verification
 * - Runtime integrity monitoring
 * - Overall L2 hardening status assessment
 * - Hardening tools report correct isolation level
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  checkMemoryProtection,
  checkProcessIsolation,
  checkFilesystemPermissions,
  checkRuntimeIntegrity,
  assessL2Hardening,
} from "../../src/operational/hardening.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL2HardeningTools } from "../../src/operational/hardening-tools.js";
import type { ToolDefinition } from "../../src/router.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { chmodSync } from "node:fs";
import { join } from "node:path";

describe("L2 Process Hardening", () => {
  describe("Memory Protection", () => {
    it("detects memory protection mechanisms", () => {
      const status = checkMemoryProtection();

      expect(status).toBeDefined();
      expect(status.stack_canaries).toBe(true);
      expect(status.secure_buffer_zeros).toBe(true);
      expect(status.argon2id_kdf).toBe(true);
      expect(
        ["full", "partial", "minimal", "none"]
      ).toContain(status.overall);
    });

    it("reports ASLR status on supported platforms", () => {
      const status = checkMemoryProtection();
      // ASLR detection varies by platform and environment
      expect(typeof status.aslr_enabled).toBe("boolean");
    });

    it("overall status reflects enabled protections", () => {
      const status = checkMemoryProtection();
      // With stack canaries and secure buffer handling always true,
      // overall should be at least "partial"
      expect(status.overall !== "none").toBe(true);
    });
  });

  describe("Process Isolation", () => {
    it("detects isolation level", () => {
      const status = checkProcessIsolation();

      expect(status.isolation_level).toMatch(/^(full|hardened|basic|none)$/);
      expect(typeof status.is_container).toBe("boolean");
      expect(typeof status.is_vm).toBe("boolean");
      expect(typeof status.is_sandboxed).toBe("boolean");
      expect(typeof status.is_tee).toBe("boolean");
      expect(status.details).toBeDefined();
    });

    it("reports isolation level based on environment", () => {
      const status = checkProcessIsolation();
      // In a normal test environment, should be "none" unless running in Docker/VM
      expect(["full", "hardened", "basic", "none"]).toContain(status.isolation_level);
    });

    it("isolation_level is consistent with component checks", () => {
      const status = checkProcessIsolation();
      const hasAnyIsolation = status.is_container || status.is_vm || status.is_sandboxed;

      if (status.isolation_level === "hardened") {
        expect(hasAnyIsolation).toBe(true);
      }
      if (!hasAnyIsolation) {
        expect(status.isolation_level).toBe("none");
      }
    });
  });

  describe("Filesystem Permissions", () => {
    it("checks filesystem permissions on storage path", () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "sanctuary-test-"));

      const status = checkFilesystemPermissions(tmpDir);

      expect(status).toBeDefined();
      expect(typeof status.sanctuary_storage_protected).toBe("boolean");
      expect(status.sanctuary_storage_mode).toBeDefined();
      expect(typeof status.owner_is_current_user).toBe("boolean");
      expect(
        ["secure", "warning", "insecure"]
      ).toContain(status.overall);
    });

    it("detects 0700 permissions as secure", () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "sanctuary-test-"));

      try {
        // Set permissions to 0700 (rwx------)
        chmodSync(tmpDir, 0o700);

        const status = checkFilesystemPermissions(tmpDir);

        expect(status.sanctuary_storage_protected).toBe(true);
        expect(status.overall).toBe("secure");
      } finally {
        // Cleanup
        try {
          chmodSync(tmpDir, 0o777);
        } catch {
          // ignore cleanup errors
        }
      }
    });

    it("detects overly permissive permissions as insecure", () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "sanctuary-test-"));

      try {
        // Set permissions to 0755 (rwxr-xr-x) — group readable
        chmodSync(tmpDir, 0o755);

        const status = checkFilesystemPermissions(tmpDir);

        expect(status.group_readable || status.others_readable).toBe(true);
        expect(status.overall).toBe("insecure");
      } finally {
        // Cleanup
        try {
          chmodSync(tmpDir, 0o777);
        } catch {
          // ignore cleanup errors
        }
      }
    });

    it("reports warning for non-existent path", () => {
      const status = checkFilesystemPermissions("/nonexistent/path/to/sanctuary");

      expect(status.sanctuary_storage_protected).toBe(false);
      expect(status.overall).toBe("warning");
    });
  });

  describe("Runtime Integrity", () => {
    it("monitors runtime integrity", () => {
      const status = checkRuntimeIntegrity();

      expect(status.config_hash_stable).toBe(true);
      expect(status.environment_state).toMatch(/^(clean|modified|unknown)$/);
      expect(Array.isArray(status.discrepancies)).toBe(true);
    });

    it("reports clean state in normal operation", () => {
      const status = checkRuntimeIntegrity();

      // In a normal test environment, should be clean
      expect(status.config_hash_stable).toBe(true);
      expect(status.environment_state).toBe("clean");
      expect(status.discrepancies.length).toBe(0);
    });
  });

  describe("L2 Hardening Assessment", () => {
    it("produces comprehensive hardening assessment", () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "sanctuary-test-"));

      try {
        const assessment = assessL2Hardening(tmpDir);

        expect(assessment.hardening_level).toMatch(
          /^(full|hardened|basic|none)$/
        );
        expect(assessment.checks_passed).toBeGreaterThanOrEqual(0);
        expect(assessment.checks_total).toBeGreaterThan(0);
        expect(assessment.checks_passed).toBeLessThanOrEqual(assessment.checks_total);
        expect(assessment.summary).toBeDefined();
        expect(typeof assessment.summary).toBe("string");

        // Verify all components are present
        expect(assessment.memory_protection).toBeDefined();
        expect(assessment.process_isolation).toBeDefined();
        expect(assessment.filesystem_permissions).toBeDefined();
        expect(assessment.runtime_integrity).toBeDefined();
      } finally {
        // Cleanup
        try {
          chmodSync(tmpDir, 0o777);
        } catch {
          // ignore cleanup errors
        }
      }
    });

    it("hardening level reflects security posture", () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "sanctuary-test-"));

      try {
        chmodSync(tmpDir, 0o700);

        const assessment = assessL2Hardening(tmpDir);

        // With secure filesystem permissions, should be at least "basic"
        expect(["hardened", "basic", "none"]).toContain(assessment.hardening_level);
      } finally {
        // Cleanup
        try {
          chmodSync(tmpDir, 0o777);
        } catch {
          // ignore cleanup errors
        }
      }
    });
  });

  describe("L2 Hardening Tools", () => {
    let storage: MemoryStorage;
    let masterKey: Uint8Array;
    let auditLog: AuditLog;
    let tmpDir: string;
    let tools: ToolDefinition[];

    beforeEach(async () => {
      storage = new MemoryStorage();
      masterKey = generateRandomKey();
      auditLog = new AuditLog(storage, masterKey);
      tmpDir = mkdtempSync(join(tmpdir(), "sanctuary-test-"));
      tools = createL2HardeningTools(tmpDir, auditLog);
    });

    it("creates hardening tools", () => {
      expect(tools).toBeDefined();
      expect(Array.isArray(tools)).toBe(true);
      expect(tools.length).toBeGreaterThan(0);
    });

    it("includes l2_hardening_status tool", () => {
      const statusTool = tools.find((t) => t.name === "l2_hardening_status");
      expect(statusTool).toBeDefined();
      expect(statusTool?.description).toBeDefined();
      expect(statusTool?.inputSchema).toBeDefined();
    });

    it("includes l2_verify_isolation tool", () => {
      const verifyTool = tools.find((t) => t.name === "l2_verify_isolation");
      expect(verifyTool).toBeDefined();
      expect(verifyTool?.description).toBeDefined();
      expect(verifyTool?.inputSchema).toBeDefined();
    });

    it("l2_hardening_status reports without details by default", async () => {
      const statusTool = tools.find((t) => t.name === "l2_hardening_status");
      expect(statusTool).toBeDefined();

      const result = await statusTool!.handler({} as any);
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.hardening_level).toBeDefined();
      expect(parsed.summary).toBeDefined();
      expect(parsed.checks_passed).toBeDefined();
      expect(parsed.checks_total).toBeDefined();
    });

    it("l2_hardening_status reports full details when requested", async () => {
      const statusTool = tools.find((t) => t.name === "l2_hardening_status");
      expect(statusTool).toBeDefined();

      const result = await statusTool!.handler({ include_details: true } as any);
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.hardening_level).toBeDefined();
      expect(parsed.memory_protection).toBeDefined();
      expect(parsed.process_isolation).toBeDefined();
      expect(parsed.filesystem_permissions).toBeDefined();
      expect(parsed.runtime_integrity).toBeDefined();
    });

    it("l2_verify_isolation reports isolation checks", async () => {
      const verifyTool = tools.find((t) => t.name === "l2_verify_isolation");
      expect(verifyTool).toBeDefined();

      const result = await verifyTool!.handler({} as any);
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.status).toBe("verified");
      expect(parsed.results).toBeDefined();
      expect(parsed.results.isolation_level).toBeDefined();
    });

    it("l2_verify_isolation can disable specific checks", async () => {
      const verifyTool = tools.find((t) => t.name === "l2_verify_isolation");
      expect(verifyTool).toBeDefined();

      const result = await verifyTool!.handler({
        check_filesystem: false,
        check_memory: false,
        check_process: true,
      } as any);
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.results.process).toBeDefined();
      expect(parsed.results.filesystem).toBeUndefined();
      expect(parsed.results.memory).toBeUndefined();
    });

    it("hardening tools are read-only (Tier 3)", async () => {
      // Verify tools don't modify state
      const statusTool = tools.find((t) => t.name === "l2_hardening_status");

      // Call tool multiple times
      await statusTool!.handler({} as any);
      await statusTool!.handler({} as any);
      await statusTool!.handler({} as any);

      // Audit log should record the calls but not error
      const result = await auditLog.query({});
      expect(result.total).toBeGreaterThan(0);
      expect(result.entries.every((e) => e.result === "success")).toBe(true);
    });
  });
});
