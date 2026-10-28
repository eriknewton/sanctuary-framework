/** Ten encrypted data rows, two authenticated _sdw_meta MAC-envelope rows, and ephemeral identities. */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateRandomKey } from "../../src/core/random.js";
import { createIdentity, sign } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { IdentityManager, createInternalIdentitySigningHelpers } from "../../src/cognitive/tools.js";
import { resolveAuthenticatedIdentityWriterPublicKeys } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  SDW_JOURNAL_NAMESPACES, SdwStorageError, sdwCanonicalBytes, sdwSha256,
  sdwSigningReceipt, sdwSigningBytes, type SdwPlan, type SdwPlanBody, type SdwPlanPage,
  type SdwCertificate, type SdwEpochs, type SdwPrimarySigner,
} from "../../src/storage/sdw-journal-contract.js";
import {
  defaultSdwStoreDescriptors, type SdwRecord, type SdwNamespace,
} from "../../src/sdw/records.js";
import {
  mintPersistable, prepareSdwBackendWrite, prepareReplayAnchorWrite, prepareSdwOwnerPinWrite,
  type PreparedSdwWrite,
} from "../../src/sdw/write-gate.js";

export const FIXTURE_TIME = "2026-10-28T00:00:00.000Z";
export const FIXTURE_TRANSACTION = "a".repeat(32); // 16-byte transaction identifier, hex encoded
export const FIXTURE_FORTRESS = "fortress:sdw-schema-test";
export function fixtureEpochs(epoch = 1): SdwEpochs {
  return Object.fromEntries(SDW_JOURNAL_NAMESPACES.map(ns => [ns, epoch])) as SdwEpochs;
}

export async function createSdwSchemaFixture() {
  const root = await mkdtemp(join(tmpdir(), "sdw-schema-"));
  const masterKey = generateRandomKey();
  const storage = new FilesystemStorage(root);
  const identityKey = derivePurposeKey(masterKey, "identity-encryption");
  const manager = new IdentityManager(storage, masterKey);
  const audit = new AuditLog(storage, masterKey);
  try {
    const primary = createIdentity("schema primary", identityKey, "recovery-key").storedIdentity;
    await manager.save(primary);
    await manager.setPrimary(primary.identity_id);
    const storedOnly = createIdentity("stored only", identityKey, "recovery-key").storedIdentity;
    await manager.save(storedOnly);
    const foreign = createIdentity("foreign", identityKey, "recovery-key").storedIdentity;
    const helpers = createInternalIdentitySigningHelpers(manager, masterKey, audit);
    const authority: SdwPrimarySigner = {
      fortress_id: FIXTURE_FORTRESS,
      get identity_id() { return manager.getDefault()!.identity_id; },
      get public_key() { return Buffer.from(manager.getDefault()!.public_key, "base64url"); },
      async assertCurrent() {
        if (manager.getDefault()?.identity_id !== primary.identity_id) throw new SdwStorageError("storage_plan_invalid", "none");
      },
      async assertPlanSigner(id, key) {
        // Test-only primary pin: storage membership never establishes primary authority.
        const current = manager.getDefault();
        if (!current || current.identity_id !== primary.identity_id || id !== primary.identity_id ||
          !resolveAuthenticatedIdentityWriterPublicKeys(current).some(k => !k.compromised && Buffer.from(k.publicKey).equals(key))) {
          throw new SdwStorageError("storage_plan_invalid", "none");
        }
      },
      async signReceipt(payload) {
        const signed = await helpers.internal_receipt_sign(payload, { identity_id: this.identity_id });
        return Buffer.from(signed.signature, "base64url");
      },
    };
    const rows: PreparedSdwWrite[] = [];
    for (const namespace of SDW_JOURNAL_NAMESPACES) {
      // Two rows per namespace: ten encrypted data rows and two authenticated
      // _sdw_meta MAC-envelope rows; all use the existing write gate.
      for (let index = 0; index < 2; index++) {
        let row: PreparedSdwWrite;
        if (namespace === "_sdw_meta") {
          row = index === 0 ? prepareReplayAnchorWrite(masterKey, {
            catalog: 1, chain_head: [], manifests: [], tombstones: [], export_state: 0,
          }) : prepareSdwOwnerPinWrite(masterKey, {
            version: 1, fortress_id: FIXTURE_FORTRESS, owner_ref: "owner-test", agent_id: "agent-test", pinned_at: FIXTURE_TIME,
          });
        } else {
          const descriptor = defaultSdwStoreDescriptors().find(d => d.namespace === namespace)!;
          row = prepareSdwBackendWrite(
            mintPersistable({ value: fixtureRecord(namespace, index), taint: "user_content" }, namespace, `row-${index}`, FIXTURE_FORTRESS),
            derivePurposeKey(masterKey, descriptor.hkdf_info), FIXTURE_FORTRESS,
          );
        }
        await storage.write(row.namespace, row.storageKey, row.data);
        rows.push(row);
      }
    }
    rows.sort((a, b) => a.namespace < b.namespace ? -1 : a.namespace > b.namespace ? 1 : a.storageKey < b.storageKey ? -1 : 1);
    const page: SdwPlanPage = {
      version: 1, transaction_id: FIXTURE_TRANSACTION, page: 0,
      entries: rows.map((row, ordinal) => ({ ordinal, namespace: row.namespace, key: row.storageKey,
        target_ciphertext_sha256: sdwSha256(row.data), byte_length: row.data.length })),
    };
    const pages = [sdwCanonicalBytes(page)];
    const receipt = Buffer.from("fixture receipt: encrypted rows selected");
    const body: SdwPlanBody = {
      version: 1, fortress_id: FIXTURE_FORTRESS, identity_id: primary.identity_id,
      signer_public_key: primary.public_key, transaction_id: FIXTURE_TRANSACTION, created_at: FIXTURE_TIME,
      namespaces: [...SDW_JOURNAL_NAMESPACES], record_count: rows.length,
      staged_bytes: rows.reduce((n, row) => n + row.data.length, 0),
      receipt_sha256: sdwSha256(receipt), receipt_byte_length: receipt.length,
      pages: [{ page: 0, record_count: rows.length, byte_length: pages[0]!.length, sha256: sdwSha256(pages[0]!) }],
    };
    async function signPlan(body: SdwPlanBody): Promise<SdwPlan> {
      const attestation = sdwSigningReceipt(body, body.created_at);
      const signed = await helpers.internal_receipt_sign(attestation, { identity_id: body.identity_id });
      return { body, attestation, signature: signed.signature };
    }
    const plan = await signPlan(body);
    async function certificate(state: SdwCertificate["body"]["state"], rootPlan = plan): Promise<SdwCertificate> {
      const body: SdwCertificate["body"] = {
        version: 1, state, transaction_id: rootPlan.body.transaction_id, plan_sha256: sdwSha256(sdwCanonicalBytes(rootPlan)),
        fortress_id: FIXTURE_FORTRESS, identity_id: authority.identity_id,
        signer_public_key: Buffer.from(authority.public_key).toString("base64url"), epochs: fixtureEpochs(),
        receipt_sha256: rootPlan.body.receipt_sha256, receipt_byte_length: rootPlan.body.receipt_byte_length,
      };
      const attestation = sdwSigningReceipt(body, FIXTURE_TIME);
      return { body, attestation, signature: Buffer.from(await authority.signReceipt(attestation)).toString("base64url") };
    }
    return {
      root, storage, manager, primary, storedOnly, foreign, authority, helpers, audit,
      plan, page, pages, receipt, rows, signPlan, certificate, masterKey,
      signForeign(body: SdwPlanBody): SdwPlan {
        const attestation = sdwSigningReceipt(body, body.created_at);
        return { body, attestation, signature: Buffer.from(sign(sdwSigningBytes(attestation), foreign.encrypted_private_key, identityKey)).toString("base64url") };
      },
      async dispose() { masterKey.fill(0); identityKey.fill(0); await rm(root, { recursive: true, force: true }); },
    };
  } catch (error) {
    masterKey.fill(0); identityKey.fill(0);
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

function fixtureRecord(namespace: Exclude<SdwNamespace, "_sdw_meta">, index: number): SdwRecord {
  switch (namespace) {
    case "_sdw_catalog": return {
      kind: "catalog", version: 1, fortress_id: FIXTURE_FORTRESS, environment_id: `environment-${index}`,
      created_at: FIXTURE_TIME, replay_anchor_seq: 1, stores: defaultSdwStoreDescriptors(),
    };
    case "_sdw_document_corpus": return {
      kind: "document", version: 1, document_id: `document-${index}`, source: { kind: "paste" },
      content_hash: sdwSha256(Buffer.from("schema fixture note")), chunk_count: 0,
      created_at: FIXTURE_TIME, updated_at: FIXTURE_TIME,
    };
    case "_sdw_query_history": return {
      kind: "query_history", version: 1, query_id: `query-${index}`, sequence: 1,
      previous_record_hash: null, previous_query_key: null, record_hash: "b".repeat(64),
      audit_event_id: `event-${index}`, occurred_at: FIXTURE_TIME, actor: { kind: "operator" }, channel: "internal",
      operation: "schema-test", prompt_or_query: "schema fixture note", policy_visibility: "not_included", created_at: FIXTURE_TIME,
    };
    case "_sdw_vector_memory": return {
      kind: "vector_record", version: 1, vector_id: `vector-${index}`, source: { kind: "manual", ref: `source-${index}` },
      segment_id: "segment-test", hnsw_label: index, vector: [0, 1], created_at: FIXTURE_TIME,
    };
    case "_sdw_working_state": return {
      kind: "working_state", version: 1, state_id: `state-${index}`, scope: "task", owner_ref: "owner-test", status: "active",
      created_at: FIXTURE_TIME, updated_at: FIXTURE_TIME, content_type: "application/json",
      state: { kind: "task_checkpoint", task_ref: "task-test", summary: "schema fixture note" },
    };
  }
}
