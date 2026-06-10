/**
 * SDW D2 — MCP tool surface: `sdw_export`, `sdw_import`, `sdw_export_delete`.
 *
 * Option A+ wiring (Erik-ratified 2026-06-09) — entirely inside existing
 * machinery; NO changes to gate.ts / router.ts / approval-channel.ts /
 * core/identity.ts:
 *
 * - Each tool's `approvalTargetArgs` runs at GATE time (before the human is
 *   asked) and returns metadata only: namespaces, counts, sizes, digests.
 *   Constraint #1 holds — the approval context can travel to a dashboard or
 *   webhook before approval, so it never carries record bodies, ciphertext,
 *   bundles, or key material.
 * - For `sdw_export`/`sdw_export_delete`, the gate-time ciphertext inventory
 *   is frozen in a short-TTL stash keyed by the normalized args hash. The
 *   handler consumes the stash and ships EXACTLY the approved snapshot after
 *   a fail-closed drift recheck. A handler invocation with no stashed
 *   approval-bound inventory (gate not configured, stash expired) fails
 *   closed.
 * - Because the scope digest lives in the gate-time args, the
 *   `ApprovalProofStore` envelope binds it automatically: a stored approval
 *   proof for one vault state cannot be replayed after the vault mutates
 *   (args-hash mismatch at `verifyApprovalProof`).
 * - `sdw_import` verifies the manifest signature inside `approvalTargetArgs`
 *   — i.e. BEFORE any approval prompt. A bundle that fails verification
 *   throws, the router returns the fixed denial without prompting, and the
 *   audit log records digest + category only (never the body).
 * - Drift/denial responses to the agent use the fixed denial schema only —
 *   no digests, no policy detail (invariant #7). Details go to audit.
 */

import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import { fixedDenial, normalizedArgsHash } from "../agent-native/safety-base.js";
import {
  buildSignedSdwExportBundle,
  enumerateSdwExportInventory,
  sdwExportApprovalContext,
  sdwManifestBodyDigest,
  sdwManifestCanonicalBytes,
  writeSdwExportBundleAtomic,
  computeSdwExportRecordHash,
  isSdwExportableNamespace,
  SdwExportScopeDriftError,
  type SdwExportFs,
  type SdwExportInventory,
  type SdwExportInventorySource,
  type SdwExportSigningKey,
  type SdwSignedExportManifest,
  type SdwStateExportBundle,
} from "./export.js";
import {
  decodeSdwExportBundle,
  importSdwExportBundle,
  verifySdwExportManifest,
  SdwImportVerificationError,
} from "./import.js";
import { verify } from "../core/identity.js";
import { bytesToString, fromBase64url } from "../core/encoding.js";
import { isSdwIdentifier } from "./grammar.js";
import { SdwValidationError } from "./errors.js";

const EXPORT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_MANIFEST_ARG_BYTES = 1_048_576;
/**
 * Approved gate-time inventory is held briefly between gate evaluation and
 * handler execution. Interactive approvals can take minutes (human-speed);
 * proofs expire at 5 minutes — 15 minutes comfortably bounds both while
 * keeping a stale snapshot from being consumable indefinitely.
 */
const APPROVED_SCOPE_TTL_MS = 15 * 60_000;
const APPROVED_SCOPE_MAX_ENTRIES = 16;

export interface SdwToolsOptions {
  readonly storage: StorageBackend;
  readonly inventory: SdwExportInventorySource;
  readonly auditLog: AuditLog;
  readonly fortressId: string;
  /** Operator-configured directory for export bundles. Tool args choose only a filename. */
  readonly exportDir: string;
  readonly signingKey: SdwExportSigningKey;
  readonly resolvePublicKey: (keyRef: string) => Uint8Array | null;
  /**
   * Resolve operator-configured source key material by opaque reference.
   * Raw key bytes never transit tool arguments or the approval channel.
   */
  readonly resolveSourceMasterKey: (ref: string) => Uint8Array | null;
  readonly targetMasterKey: Uint8Array;
  readonly fs?: SdwExportFs;
  readonly now?: () => string;
}

interface ApprovedScopeEntry {
  readonly inventory: SdwExportInventory;
  storedAt: number;
}

const APPROVED_SCOPE_MAX_PER_KEY = 4;

/**
 * Gate-time → handler-time inventory hand-off. Keyed by the normalized hash
 * of the ORIGINAL tool args (both `approvalTargetArgs` and the handler see
 * them), so the handler can only consume an inventory that was computed for
 * this exact call shape.
 *
 * Semantics: FIFO per key, deduplicated by scope digest, consumed strictly
 * oldest-first. This is the fail-closed answer to the overlapping-identical-
 * calls TOCTOU: if call A's prompt shows digest D1, the agent mutates the
 * vault, and an overlapping call B enqueues digest D2, then A's approval
 * consumes the OLDEST entry (D1) and the assembly-time drift recheck against
 * the live store (now D2) fails closed — the unapproved state can never ride
 * out under A's approval. Digest-dedup keeps the legitimate proof flow
 * (preflight + execution both run `approvalTargetArgs` over an unchanged
 * vault) at a single entry. A stale leftover entry (abandoned proof, denied
 * call) costs at most one extra fail-closed round before a retry succeeds —
 * safety over convenience (constraint #5 posture).
 */
class ApprovedScopeStash {
  private readonly queues = new Map<string, ApprovedScopeEntry[]>();

  set(key: string, inventory: SdwExportInventory, nowMs: number): void {
    this.prune(nowMs);
    const queue = this.queues.get(key) ?? [];
    const existing = queue.find(
      (entry) => entry.inventory.scope_digest === inventory.scope_digest,
    );
    if (existing !== undefined) {
      existing.storedAt = nowMs;
    } else {
      queue.push({ inventory, storedAt: nowMs });
      while (queue.length > APPROVED_SCOPE_MAX_PER_KEY) queue.shift();
    }
    if (!this.queues.has(key)) {
      if (this.queues.size >= APPROVED_SCOPE_MAX_ENTRIES) {
        const oldestKey = this.queues.keys().next().value;
        if (oldestKey !== undefined) this.queues.delete(oldestKey);
      }
      this.queues.set(key, queue);
    }
  }

  /** Strictly oldest-first; never skips entries (see class doc). */
  consumeOldest(key: string, nowMs: number): SdwExportInventory | null {
    this.prune(nowMs);
    const queue = this.queues.get(key);
    if (queue === undefined || queue.length === 0) return null;
    const entry = queue.shift()!;
    if (queue.length === 0) this.queues.delete(key);
    return entry.inventory;
  }

  private prune(nowMs: number): void {
    for (const [key, queue] of this.queues) {
      const fresh = queue.filter((entry) => nowMs - entry.storedAt <= APPROVED_SCOPE_TTL_MS);
      if (fresh.length === 0) {
        this.queues.delete(key);
      } else if (fresh.length !== queue.length) {
        queue.length = 0;
        queue.push(...fresh);
      }
    }
  }
}

export function createSdwTools(options: SdwToolsOptions): ToolDefinition[] {
  const exportStash = new ApprovedScopeStash();
  const deleteStash = new ApprovedScopeStash();
  const now = options.now ?? (() => new Date().toISOString());

  const auditFailure = (
    operation: string,
    details: Record<string, unknown>,
  ): Promise<void> =>
    options.auditLog.appendCritical({
      layer: "l1",
      operation,
      identity_id: "system",
      result: "failure",
      details,
    });

  const auditSuccess = (
    operation: string,
    details: Record<string, unknown>,
  ): Promise<void> =>
    options.auditLog.appendCritical({
      layer: "l1",
      operation,
      identity_id: "principal",
      result: "success",
      details,
    });

  const genericDeny = (operation: string) =>
    toolResult(fixedDenial(`audit:${operation}`, "request_review", null));

  // Fail closed on a malformed namespaces argument: silently treating it as
  // "no filter" would WIDEN the export scope past what the caller asked for.
  const requestedNamespaces = (args: Record<string, unknown>): string[] | undefined => {
    if (args.namespaces === undefined || args.namespaces === null) return undefined;
    if (
      !Array.isArray(args.namespaces) ||
      !args.namespaces.every((item): item is string => typeof item === "string")
    ) {
      throw new SdwValidationError("invalid_identifier", "Invalid SDW namespaces argument");
    }
    return args.namespaces as string[];
  };

  // ── sdw_export ─────────────────────────────────────────────────────────────
  const sdwExport: ToolDefinition = {
    name: "sdw_export",
    description:
      "Export the Sovereign Data Warehouse as a signed, encrypted, portable bundle. " +
      "Tier 1: the approval freezes a ciphertext-inventory fingerprint of exactly " +
      "what will ship; any vault change before packaging aborts the export.",
    tool_class: "write",
    inputSchema: {
      type: "object",
      properties: {
        export_name: {
          type: "string",
          description: "Bundle filename stem inside the operator-configured export directory",
        },
        namespaces: {
          type: "array",
          items: { type: "string" },
          description: "Optional subset of exportable SDW namespaces (default: all)",
        },
      },
      required: ["export_name"],
    },
    // Gate-time inventory freeze. Synchronous, decryption-free, metadata-only
    // output. Throwing here makes the router deny without prompting.
    approvalTargetArgs: (args) => {
      const exportName = args.export_name;
      if (
        typeof exportName !== "string" ||
        !EXPORT_NAME_PATTERN.test(exportName) ||
        exportName.includes("..")
      ) {
        throw new SdwValidationError("invalid_identifier", "Invalid SDW export name");
      }
      const inventory = enumerateSdwExportInventory(
        options.inventory,
        requestedNamespaces(args),
      );
      exportStash.set(normalizedArgsHash(args), inventory, Date.now());
      return {
        export_name: exportName,
        ...sdwExportApprovalContext(inventory),
      };
    },
    handler: async (args) => {
      const exportName = args.export_name as string;
      if (
        typeof exportName !== "string" ||
        !EXPORT_NAME_PATTERN.test(exportName) ||
        exportName.includes("..")
      ) {
        await auditFailure("sdw_export_denied", { denial_class: "invalid_export_name" });
        return genericDeny("sdw_export");
      }

      // Fail closed when no gate-time approved inventory exists for this call
      // (gate not configured, stash expired, or approvalTargetArgs never ran).
      const approved = exportStash.consumeOldest(normalizedArgsHash(args), Date.now());
      if (approved === null) {
        await auditFailure("sdw_export_denied", {
          denial_class: "approval_scope_binding_missing",
        });
        return genericDeny("sdw_export");
      }

      const exportAuditEventId = `sdw-export:${Date.now()}:${randomBytes(6).toString("hex")}`;

      // Audit anchor: ties the gate_approve event (adjacent in the
      // tamper-evident chain) to the exact approved fingerprint and to the
      // manifest's export_audit_event_id.
      await auditSuccess("sdw_export_scope_approved", {
        export_audit_event_id: exportAuditEventId,
        export_name: exportName,
        scope_digest: approved.scope_digest,
        namespaces: approved.namespaces,
        record_count: approved.record_count,
        total_bytes: approved.total_bytes,
      });

      let built: { bundle: SdwStateExportBundle; manifestBodyDigest: string };
      try {
        built = buildSignedSdwExportBundle({
          inventory: approved,
          source: options.inventory,
          fortressId: options.fortressId,
          exportAuditEventId,
          signingKey: options.signingKey,
          now: now(),
        });
      } catch (error) {
        if (error instanceof SdwExportScopeDriftError) {
          // Honest audit event with both digests; agent sees only the fixed
          // denial (invariant #7 — no drift detail leaks).
          await auditFailure("sdw_export_scope_drift", {
            export_audit_event_id: exportAuditEventId,
            approved_scope_digest: error.approvedDigest,
            current_scope_digest: error.currentDigest,
          });
          return genericDeny("sdw_export");
        }
        // Signing/enumeration failure: never degrade to an unsigned export
        // (constraint #5). Category only — no error text that could carry
        // key-adjacent detail.
        await auditFailure("sdw_export_failed", {
          export_audit_event_id: exportAuditEventId,
          category: "sign_failed",
        });
        return genericDeny("sdw_export");
      }

      const destinationPath = join(options.exportDir, `${exportName}.sdw-export.json`);
      try {
        await writeSdwExportBundleAtomic(built.bundle, destinationPath, options.fs);
      } catch {
        await auditFailure("sdw_export_failed", {
          export_audit_event_id: exportAuditEventId,
          category: "write_failed",
        });
        return genericDeny("sdw_export");
      }

      await auditSuccess("sdw_export_completed", {
        export_audit_event_id: exportAuditEventId,
        export_name: exportName,
        manifest_body_digest: built.manifestBodyDigest,
        scope_digest: approved.scope_digest,
        namespaces: approved.namespaces,
        record_count: approved.record_count,
      });

      return toolResult({
        exported: true,
        export_name: exportName,
        destination_path: destinationPath,
        export_audit_event_id: exportAuditEventId,
        scope_digest: approved.scope_digest,
        manifest_body_digest: built.manifestBodyDigest,
        namespaces: approved.namespaces,
        record_count: approved.record_count,
        total_bytes: approved.total_bytes,
      });
    },
  };

  // ── sdw_import ─────────────────────────────────────────────────────────────
  const sdwImport: ToolDefinition = {
    name: "sdw_import",
    description:
      "Import a signed SDW export bundle. The manifest signature is verified " +
      "before any approval prompt; records are decrypted only inside the " +
      "approved flow and re-encrypted under this fortress.",
    tool_class: "write",
    inputSchema: {
      type: "object",
      properties: {
        bundle: { type: "string", description: "Base64url-encoded SDW export bundle" },
        source_key_ref: {
          type: "string",
          description: "Opaque reference to operator-configured source key material",
        },
        conflict_resolution: {
          type: "string",
          enum: ["skip", "overwrite"],
          default: "skip",
        },
      },
      required: ["bundle", "source_key_ref"],
    },
    // Verify-before-prompt. On failure: digest+category audit (async,
    // fire-and-forget — appendCritical chains onto the audit queue) and a
    // throw, which the router converts to a fixed denial WITHOUT prompting.
    // On success the gate context carries metadata only — the bundle string
    // itself is deliberately absent (constraint #1); the manifest digest
    // binds it into the approval and into any approval proof.
    approvalTargetArgs: (args) => {
      try {
        const bundle = decodeSdwExportBundle(args.bundle as string);
        const summary = verifySdwExportManifest(bundle, options.resolvePublicKey);
        return {
          source_key_ref: args.source_key_ref,
          conflict_resolution: args.conflict_resolution ?? "skip",
          signature_verified: true,
          manifest_body_digest: summary.manifest_body_digest,
          source_fortress_id: summary.source_fortress_id,
          export_audit_event_id: summary.export_audit_event_id,
          namespaces: [...summary.namespaces],
          record_count: summary.record_count,
        };
      } catch (error) {
        const category =
          error instanceof SdwImportVerificationError ? error.category : "malformed_bundle";
        const digest =
          error instanceof SdwImportVerificationError ? error.manifestBodyDigest : null;
        void options.auditLog.appendCritical({
          layer: "l1",
          operation: "sdw_import_manifest_rejected",
          identity_id: "system",
          result: "failure",
          details: { category, manifest_body_digest: digest },
        });
        throw error;
      }
    },
    handler: async (args) => {
      // Verify again on the exact bytes the handler received (ratified import
      // flow step 2), independent of the gate-time check.
      let bundle;
      let summary;
      try {
        bundle = decodeSdwExportBundle(args.bundle as string);
        summary = verifySdwExportManifest(bundle, options.resolvePublicKey);
      } catch (error) {
        const category =
          error instanceof SdwImportVerificationError ? error.category : "malformed_bundle";
        const digest =
          error instanceof SdwImportVerificationError ? error.manifestBodyDigest : null;
        await auditFailure("sdw_import_manifest_rejected", {
          category,
          manifest_body_digest: digest,
        });
        return genericDeny("sdw_import");
      }

      const sourceKeyRef = args.source_key_ref;
      const sourceMasterKey =
        typeof sourceKeyRef === "string"
          ? options.resolveSourceMasterKey(sourceKeyRef)
          : null;
      if (sourceMasterKey === null) {
        await auditFailure("sdw_import_failed", {
          category: "source_key_unavailable",
          manifest_body_digest: summary.manifest_body_digest,
        });
        return genericDeny("sdw_import");
      }

      let result;
      try {
        result = await importSdwExportBundle({
          bundle,
          storage: options.storage,
          resolvePublicKey: options.resolvePublicKey,
          sourceMasterKey,
          targetMasterKey: options.targetMasterKey,
          targetFortressId: options.fortressId,
          conflictResolution:
            args.conflict_resolution === "overwrite" ? "overwrite" : "skip",
        });
      } catch (error) {
        const category =
          error instanceof SdwImportVerificationError ? error.category : "schema_invalid";
        await auditFailure("sdw_import_failed", {
          category,
          manifest_body_digest: summary.manifest_body_digest,
        });
        return genericDeny("sdw_import");
      }

      await auditSuccess("sdw_import_completed", {
        manifest_body_digest: result.manifest_body_digest,
        source_fortress_id: result.source_fortress_id,
        imported: result.imported,
        skipped_existing: result.skipped_existing,
        overwritten: result.overwritten,
        namespaces: result.namespaces,
      });

      return toolResult({
        imported: result.imported,
        skipped_existing: result.skipped_existing,
        overwritten: result.overwritten,
        namespaces: result.namespaces,
        source_fortress_id: result.source_fortress_id,
        manifest_body_digest: result.manifest_body_digest,
      });
    },
  };

  // ── sdw_export_delete ──────────────────────────────────────────────────────
  const sdwExportDelete: ToolDefinition = {
    name: "sdw_export_delete",
    description:
      "Post-export local-state delete: removes exactly the records listed in a " +
      "signed export manifest, and only while their stored ciphertext still " +
      "matches the manifest. Tier 1.",
    tool_class: "write",
    inputSchema: {
      type: "object",
      properties: {
        manifest: {
          type: "string",
          description: "Base64url-encoded signed export manifest from a completed sdw_export",
        },
      },
      required: ["manifest"],
    },
    approvalTargetArgs: (args) => {
      const manifest = decodeSignedManifestArg(args.manifest);
      const summary = verifyManifestSignatureOnly(manifest, options.resolvePublicKey);
      // Freeze the CURRENT inventory of the manifest's namespaces so the
      // handler deletes only what the human saw — and only if nothing moved.
      const namespaces = [
        ...new Set(manifest.body.records.map((record) => record.namespace)),
      ].sort();
      for (const namespace of namespaces) {
        if (!isSdwExportableNamespace(namespace)) {
          throw new SdwImportVerificationError("schema_invalid", summary.digest);
        }
      }
      const inventory = enumerateSdwExportInventory(options.inventory, namespaces);
      assertManifestMatchesInventory(manifest, inventory, summary.digest);
      deleteStash.set(normalizedArgsHash(args), inventory, Date.now());
      return {
        manifest_body_digest: summary.digest,
        scope_digest: inventory.scope_digest,
        namespaces,
        record_count: manifest.body.records.length,
        source_fortress_id: manifest.body.source_fortress_id,
      };
    },
    handler: async (args) => {
      let manifest: SdwSignedExportManifest;
      let digest: string;
      try {
        manifest = decodeSignedManifestArg(args.manifest);
        ({ digest } = verifyManifestSignatureOnly(manifest, options.resolvePublicKey));
      } catch (error) {
        const category =
          error instanceof SdwImportVerificationError ? error.category : "malformed_bundle";
        await auditFailure("sdw_export_delete_denied", { category });
        return genericDeny("sdw_export_delete");
      }

      const approved = deleteStash.consumeOldest(normalizedArgsHash(args), Date.now());
      if (approved === null) {
        await auditFailure("sdw_export_delete_denied", {
          denial_class: "approval_scope_binding_missing",
          manifest_body_digest: digest,
        });
        return genericDeny("sdw_export_delete");
      }

      // Fail-closed drift recheck: every listed record must STILL exist with
      // exactly the exported ciphertext. Any mismatch aborts with zero deletes
      // (no partial deletion of records the human did not see).
      const live = enumerateSdwExportInventory(options.inventory, approved.namespaces);
      if (live.scope_digest !== approved.scope_digest) {
        await auditFailure("sdw_export_delete_drift", {
          manifest_body_digest: digest,
          approved_scope_digest: approved.scope_digest,
          current_scope_digest: live.scope_digest,
        });
        return genericDeny("sdw_export_delete");
      }
      try {
        assertManifestMatchesInventory(manifest, live, digest);
      } catch {
        await auditFailure("sdw_export_delete_drift", {
          manifest_body_digest: digest,
          approved_scope_digest: approved.scope_digest,
          current_scope_digest: live.scope_digest,
        });
        return genericDeny("sdw_export_delete");
      }

      // Defense-in-depth against a write racing the recheck above: re-read
      // each record and verify its ciphertext hash IMMEDIATELY before its
      // delete. A mismatch aborts the loop (deletes so far were all verified;
      // the abort is honestly audited with the partial count).
      let deleted = 0;
      for (const record of manifest.body.records) {
        const raw = await options.storage.read(record.namespace, record.key);
        const liveHash = raw === null ? null : recordHashOfRawEnvelope(raw);
        if (liveHash !== record.record_hash) {
          await auditFailure("sdw_export_delete_drift", {
            manifest_body_digest: digest,
            approved_scope_digest: approved.scope_digest,
            denial_class: "record_changed_mid_delete",
            deleted_before_abort: deleted,
          });
          return genericDeny("sdw_export_delete");
        }
        if (await options.storage.delete(record.namespace, record.key)) {
          deleted += 1;
        }
      }

      await auditSuccess("sdw_export_delete_completed", {
        manifest_body_digest: digest,
        deleted_count: deleted,
        record_count: manifest.body.records.length,
        namespaces: approved.namespaces,
      });

      return toolResult({
        deleted: deleted,
        record_count: manifest.body.records.length,
        namespaces: approved.namespaces,
        manifest_body_digest: digest,
      });
    },
  };

  return [sdwExport, sdwImport, sdwExportDelete];
}

// ── Manifest-arg helpers (sdw_export_delete) ─────────────────────────────────

/** Hash a stored ciphertext envelope (raw bytes form) — no decryption. */
function recordHashOfRawEnvelope(raw: Uint8Array): string | null {
  try {
    return computeSdwExportRecordHash(
      JSON.parse(bytesToString(raw)) as Parameters<typeof computeSdwExportRecordHash>[0],
    );
  } catch {
    return null;
  }
}

function decodeSignedManifestArg(value: unknown): SdwSignedExportManifest {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_MANIFEST_ARG_BYTES) {
    throw new SdwImportVerificationError("malformed_bundle");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(fromBase64url(value)));
  } catch {
    throw new SdwImportVerificationError("malformed_bundle");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    (parsed as SdwSignedExportManifest).body === null ||
    typeof (parsed as SdwSignedExportManifest).body !== "object" ||
    typeof (parsed as SdwSignedExportManifest).signature !== "object"
  ) {
    throw new SdwImportVerificationError("malformed_bundle");
  }
  const manifest = parsed as SdwSignedExportManifest;
  if (
    manifest.body.version !== 1 ||
    !Array.isArray(manifest.body.records) ||
    typeof manifest.body.source_fortress_id !== "string" ||
    !isSdwIdentifier(manifest.body.source_fortress_id) ||
    typeof manifest.signature.key_ref !== "string" ||
    typeof manifest.signature.value !== "string" ||
    manifest.signature.alg !== "ed25519"
  ) {
    throw new SdwImportVerificationError("malformed_bundle");
  }
  for (const record of manifest.body.records) {
    if (
      record === null ||
      typeof record !== "object" ||
      typeof record.namespace !== "string" ||
      typeof record.key !== "string" ||
      typeof record.record_hash !== "string"
    ) {
      throw new SdwImportVerificationError("malformed_bundle");
    }
  }
  return manifest;
}

function verifyManifestSignatureOnly(
  manifest: SdwSignedExportManifest,
  resolvePublicKey: (keyRef: string) => Uint8Array | null,
): { digest: string } {
  const digest = sdwManifestBodyDigest(manifest.body);
  const publicKey = resolvePublicKey(manifest.signature.key_ref);
  if (publicKey === null) {
    throw new SdwImportVerificationError("key_unknown", digest);
  }
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64url(manifest.signature.value);
  } catch {
    throw new SdwImportVerificationError("signature_invalid", digest);
  }
  if (!verify(sdwManifestCanonicalBytes(manifest.body), signatureBytes, publicKey)) {
    throw new SdwImportVerificationError("signature_invalid", digest);
  }
  return { digest };
}

/**
 * Every record listed in the manifest must currently exist in the inventory
 * with EXACTLY the exported ciphertext hash. Records not listed are ignored
 * (they survive a post-export delete untouched).
 */
function assertManifestMatchesInventory(
  manifest: SdwSignedExportManifest,
  inventory: SdwExportInventory,
  digest: string,
): void {
  const current = new Map<string, string>();
  for (const record of inventory.records) {
    current.set(`${record.namespace}\u0000${record.key}`, record.record_hash);
  }
  for (const listed of manifest.body.records) {
    const liveHash = current.get(`${listed.namespace}\u0000${listed.key}`);
    if (liveHash === undefined) {
      throw new SdwImportVerificationError("manifest_mismatch", digest);
    }
    if (liveHash !== listed.record_hash) {
      throw new SdwImportVerificationError("record_hash_mismatch", digest);
    }
  }
}
