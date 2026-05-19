import { CallbackApprovalChannel } from "../../../../server/src/principal-policy/approval-channel.js";
import { ApprovalGate } from "../../../../server/src/principal-policy/gate.js";
import { DEFAULT_POLICY } from "../../../../server/src/principal-policy/loader.js";
import { BaselineTracker } from "../../../../server/src/principal-policy/baseline.js";
import { AuditLog } from "../../../../server/src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../../../server/src/storage/memory.js";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import { fromBase64url, stringToBytes, toBase64url } from "../../../../server/src/core/encoding.js";
import { createIdentity, sign as identitySign, verify as identityVerify } from "../../../../server/src/core/identity.js";
import { derivePurposeKey } from "../../../../server/src/core/key-derivation.js";
import { registerFixture } from "../../registry.js";
import {
  callTool,
  failedSince,
  makeL1Rig,
  passedSince,
  ROW_IDENTITY_SIGNING,
  ROW_IDENTITY_SIGNING_LABEL,
} from "./helpers.js";

// Entrypoints: createL1Tools().identity_sign / identity_verify, ApprovalGate.evaluate,
// and core/identity.sign. Existing mirrors: server/test/identity-signing-helpers.test.ts,
// server/test/principal-policy/approval-gate.test.ts, and
// server/test/security/tool-registry-raw-signing-guard.test.ts.
// ASSURANCE_MATRIX row: 19, Identity signing authority.

registerFixture(
  ROW_IDENTITY_SIGNING,
  ROW_IDENTITY_SIGNING_LABEL,
  "identity tool signing verifies through registry-mediated surface",
  async () => {
    const start = performance.now();
    try {
      const { tools, identityManager } = makeL1Rig();
      await identityManager.load();
      const identity = await callTool(tools, "identity_create", {
        label: "synthetic-registry-mediated",
      });
      const payloadBytes = stringToBytes("synthetic identity signing payload");
      const payload = toBase64url(payloadBytes);
      const signed = await callTool(tools, "identity_sign", {
        identity_id: identity.identity_id,
        payload,
      });
      const verified = await callTool(tools, "identity_verify", {
        public_key: signed.public_key,
        payload,
        signature: signed.signature,
      });

      return passedSince(
        start,
        `signature valid=${verified.valid === true}`,
      );
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_IDENTITY_SIGNING,
  ROW_IDENTITY_SIGNING_LABEL,
  "raw identity_sign is denied without approval",
  async () => {
    const start = performance.now();
    try {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const baseline = new BaselineTracker(storage, masterKey);
      const auditLog = new AuditLog(storage, masterKey);
      const approvals: string[] = [];
      const channel = new CallbackApprovalChannel(async (request) => {
        approvals.push(request.operation);
        return {
          decision: "deny",
          decided_at: new Date().toISOString(),
          decided_by: "human",
        };
      });
      const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);
      const result = await gate.evaluate("identity_sign", {
        payload: "externally meaningful commitment",
      });

      return {
        passed:
          result.allowed === false &&
          result.tier === 1 &&
          result.approval_required === true &&
          approvals[0] === "identity_sign",
        message: `tier=${result.tier}, allowed=${String(result.allowed)}`,
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_IDENTITY_SIGNING,
  ROW_IDENTITY_SIGNING_LABEL,
  "rotated identity key signs under the new public key only",
  async () => {
    const start = performance.now();
    try {
      const { identityManager, masterKey } = makeL1Rig();
      await identityManager.load();
      const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
      const { publicIdentity, storedIdentity } = createIdentity(
        "synthetic-rotated-key",
        identityEncKey,
        "recovery-key",
      );
      await identityManager.save(storedIdentity);
      const identity = publicIdentity;
      const oldPublicKey = fromBase64url(identity.public_key);
      const rotatedResult = await identityManager.rotate(
        identity.identity_id,
        "synthetic boundary rotation",
      );
      if (!rotatedResult) {
        throw new Error("identity rotation returned null");
      }
      const rotated = rotatedResult.updatedIdentity;
      const payloadBytes = stringToBytes("post-rotation payload");
      const signature = identitySign(
        payloadBytes,
        rotated.encrypted_private_key,
        identityEncKey,
      );
      const verifiesWithNew = identityVerify(
        payloadBytes,
        signature,
        fromBase64url(rotated.public_key),
      );
      const verifiesWithOld = identityVerify(payloadBytes, signature, oldPublicKey);

      return {
        passed:
          rotated.public_key !== identity.public_key &&
          verifiesWithNew === true &&
          verifiesWithOld === false,
        message: `new_key=${String(verifiesWithNew)}, old_key=${String(verifiesWithOld)}`,
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);
