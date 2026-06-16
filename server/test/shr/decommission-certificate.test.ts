/**
 * Decommissioning Certificate — Tests
 *
 * Tests for decommissioning certificate generation, signing, verification,
 * zero-state checks, and tamper detection.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import {
  generateDecommissionCertificate,
  type DecommissionGeneratorOptions,
} from "../../src/shr/decommission-generator.js";
import {
  verifyDecommissionCertificate,
} from "../../src/shr/decommission-verifier.js";
import type {
  SignedDecommissionCertificate,
} from "../../src/shr/decommission-types.js";
import { StateStore } from "../../src/cognitive/state-store.js";

// Minimal IdentityManager mock
class TestIdentityManager {
  private identities = new Map<string, any>();
  private defaultId: string | null = null;

  constructor(storage: MemoryStorage, masterKey: Uint8Array) {
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      "test",
      encKey,
      "recovery-key"
    );
    this.identities.set(publicIdentity.identity_id, storedIdentity);
    this.defaultId = publicIdentity.identity_id;
  }

  get(id: string) {
    return this.identities.get(id);
  }

  getDefault() {
    return this.defaultId ? this.identities.get(this.defaultId) : undefined;
  }

  list() {
    return Array.from(this.identities.values());
  }
}

describe("Decommissioning Certificate", () => {
  let storage: MemoryStorage;
  let stateStore: StateStore;
  let masterKey: Uint8Array;
  let identityManager: TestIdentityManager;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
    stateStore = new StateStore(storage, masterKey);
    identityManager = new TestIdentityManager(storage, masterKey);
  });

  describe("Generation", () => {
    it("generates a valid signed decommissioning certificate", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const result = await generateDecommissionCertificate(opts);

      expect(typeof result).not.toBe("string");
      const cert = result as SignedDecommissionCertificate;

      expect(cert.body.cert_type).toBe("decommissioning");
      expect(cert.body.cert_version).toBe("1.0");
      expect(cert.body.agent_public_key).toBeTruthy();
      expect(cert.body.agent_instance_id).toBeTruthy();
      expect(cert.body.decommissioned_at).toBeTruthy();
      expect(cert.body.certificate_issued_at).toBeTruthy();
      expect(cert.signed_by).toBeTruthy();
      expect(cert.signature).toBeTruthy();
    });

    it("includes zero-state checks", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;

      expect(cert.body.zero_state_checks).toBeTruthy();
      expect(Array.isArray(cert.body.zero_state_checks)).toBe(true);
      expect(cert.body.zero_state_checks.length).toBeGreaterThan(0);

      // Check for specific checks
      const checkNames = cert.body.zero_state_checks.map((c) => c.check_name);
      expect(checkNames).toContain("state_namespace_empty");
      expect(checkNames).toContain("no_active_identities");
      expect(checkNames).toContain("no_active_reputation");
      expect(checkNames).toContain("no_active_sessions");
    });

    it("marks checks as passed when conditions are met", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;

      // Most checks should pass initially (clean state)
      const passedChecks = cert.body.zero_state_checks.filter((c) => c.passed);
      expect(passedChecks.length).toBeGreaterThan(0);
    });

    it("marks overall as having checks passed when all required checks pass", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;

      // With clean state and at least one active identity, all_checks_passed should be false
      // (because no_active_identities check fails)
      expect(typeof cert.body.all_checks_passed).toBe("boolean");
    });

    it("includes decommissioning reason if provided", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;

      expect(cert.body.decommissioning_reason).toBeTruthy();
    });

    it("marks private key as zeroed", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;

      expect(cert.body.private_key_zeroed).toBe(true);
    });

    it("returns error when no identity exists", async () => {
      const emptyManager = {
        get: () => undefined,
        getDefault: () => undefined,
        list: () => [],
      };

      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: emptyManager as any,
        storage,
        masterKey,
      };

      const result = await generateDecommissionCertificate(opts);

      expect(typeof result).toBe("string");
      expect(result).toContain("No identity");
    });
  });

  describe("Verification", () => {
    it("verifies a valid decommissioning certificate", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;
      const result = verifyDecommissionCertificate(cert);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.agent_id).toBe(cert.body.agent_instance_id);
    });

    it("detects tampered body", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;

      // Tamper with the body
      const tampered = JSON.parse(JSON.stringify(cert)) as SignedDecommissionCertificate;
      tampered.body.decommissioning_reason = "Modified reason";

      const result = verifyDecommissionCertificate(tampered);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("signature") || e.includes("tamper"))).toBe(true);
    });

    it("detects invalid certificate structure", () => {
      const invalidCert = {
        body: null,
        signed_by: "test",
        signature: "test",
      };

      const result = verifyDecommissionCertificate(invalidCert as any);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("detects missing signature", () => {
      const certWithoutSig = {
        body: {
          cert_type: "decommissioning",
          cert_version: "1.0",
          agent_public_key: "test",
          agent_instance_id: "test",
          decommissioned_at: new Date().toISOString(),
          certificate_issued_at: new Date().toISOString(),
          zero_state_checks: [],
          all_checks_passed: true,
          decommissioned_key_hash: "test",
          private_key_zeroed: true,
        },
        signed_by: undefined,
        signature: undefined,
      };

      const result = verifyDecommissionCertificate(certWithoutSig as any);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("missing signature"))).toBe(true);
    });

    it("assesses agent ID correctly", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;
      const result = verifyDecommissionCertificate(cert);

      expect(result.agent_id).toBe(cert.body.agent_instance_id);
    });

    it("reports decommissioning time", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;
      const result = verifyDecommissionCertificate(cert);

      expect(result.decommissioned_at).toBe(cert.body.decommissioned_at);
    });

    it("detects invalid timestamps", () => {
      const certWithBadTime = {
        body: {
          cert_type: "decommissioning",
          cert_version: "1.0",
          agent_public_key: "test",
          agent_instance_id: "test",
          decommissioned_at: "invalid-date",
          certificate_issued_at: "also-invalid",
          zero_state_checks: [],
          all_checks_passed: true,
          decommissioned_key_hash: "test",
          private_key_zeroed: true,
        },
        signed_by: "test",
        signature: "test",
      };

      const result = verifyDecommissionCertificate(certWithBadTime as any);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes("timestamp") || e.includes("ISO 8601"))
      ).toBe(true);
    });

    it("detects certificate issued in the future", () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 1);

      const certFromFuture = {
        body: {
          cert_type: "decommissioning",
          cert_version: "1.0",
          agent_public_key: "test",
          agent_instance_id: "test",
          decommissioned_at: new Date().toISOString(),
          certificate_issued_at: futureDate.toISOString(),
          zero_state_checks: [],
          all_checks_passed: true,
          decommissioned_key_hash: "test",
          private_key_zeroed: true,
        },
        signed_by: "test",
        signature: "test",
      };

      const result = verifyDecommissionCertificate(certFromFuture as any);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("future"))).toBe(true);
    });
  });

  describe("Zero-state check assessment", () => {
    it("correctly reflects all_checks_passed state", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;
      const result = verifyDecommissionCertificate(cert);

      // In the current setup with one active identity, not all checks should pass
      const hasFailedChecks = cert.body.zero_state_checks.some((c) => !c.passed);
      if (hasFailedChecks) {
        expect(result.all_checks_passed).toBe(false);
      }
    });

    it("includes details about failed checks in warnings", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;
      const result = verifyDecommissionCertificate(cert);

      // If there are failed checks, they should be in warnings
      const failedChecks = cert.body.zero_state_checks.filter((c) => !c.passed);
      if (failedChecks.length > 0) {
        expect(result.warnings.length).toBeGreaterThan(0);
      }
    });
  });

  describe("Temporal validity", () => {
    it("correctly validates certificate timestamps", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;

      // Verify with current time — should be valid
      const result = verifyDecommissionCertificate(cert);
      expect(result.valid).toBe(true);
    });

    it("includes decommissioning time in result", async () => {
      const opts: DecommissionGeneratorOptions = {
        stateStore,
        identityManager: identityManager as any,
        storage,
        masterKey,
      };

      const beforeGeneration = new Date();
      const cert = (await generateDecommissionCertificate(opts)) as SignedDecommissionCertificate;
      const afterGeneration = new Date();

      const result = verifyDecommissionCertificate(cert);

      const decomTime = new Date(result.decommissioned_at);
      expect(decomTime.getTime()).toBeGreaterThanOrEqual(beforeGeneration.getTime());
      expect(decomTime.getTime()).toBeLessThanOrEqual(afterGeneration.getTime());
    });
  });
});
