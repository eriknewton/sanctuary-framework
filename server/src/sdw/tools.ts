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
 * - EXACT consent binding (gate → handler): `approvalTargetArgs` attaches the
 *   approval-bound payload (the frozen ciphertext inventory for
 *   `sdw_export`/`sdw_export_delete`; the verified manifest summary for
 *   `sdw_import`) to the per-call args object under a private Symbol key. The
 *   router passes the SAME object to the handler, so the handler consumes the
 *   binding computed for THIS call's gate evaluation — the inventory/manifest
 *   the human's approval was shown — never a stale entry from an earlier,
 *   abandoned call. Agent-supplied args arrive as JSON (no Symbol keys can be
 *   forged) and schema validation rejects unknown string fields, so the
 *   binding channel is unforgeable. A handler invocation with no binding
 *   (gate not configured, `approvalTargetArgs` never ran, binding expired or
 *   args mutated after gate time) fails closed. The assembly-time live-store
 *   drift recheck remains as defense-in-depth on top of this binding.
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

import { join, relative, resolve, sep } from "node:path";
import { lstat, mkdir, mkdtemp, realpath } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import { fixedDenial, normalizedArgsHash } from "../agent-native/safety-base.js";
import {
  buildSignedSdwExportBundle,
  enumerateSdwExportInventory,
  sdwExportApprovalContext,
  sdwManifestBodyDigest,
  sdwManifestCanonicalBytes,
  writeSdwExportBundleAtomic,
  writeSdwExportBundleInFreshDir,
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
import type { MultiAgentIsolationGuard } from "./memory-isolation.js";
import { SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS } from "./memory-tools.js";

const EXPORT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_MANIFEST_ARG_BYTES = 1_048_576;
/**
 * The approval binding lives only between gate evaluation and handler
 * execution of a single call. Interactive approvals can take minutes
 * (human-speed); proofs expire at 5 minutes — 15 minutes comfortably bounds
 * both while keeping a stale binding from being consumable indefinitely.
 */
const APPROVAL_BINDING_TTL_MS = 15 * 60_000;

export interface SdwToolsOptions {
  readonly storage: StorageBackend;
  readonly inventory: SdwExportInventorySource;
  readonly auditLog: AuditLog;
  readonly fortressId: string;
  /** Operator-configured directory for export bundles. Tool args choose only a filename. */
  readonly exportDir: string;
  /**
   * The manifest signing key, or a resolver for it. The production composition
   * root passes a resolver because the fortress's primary identity can be
   * created after boot; a resolver returning null fails the export closed
   * (never an unsigned bundle, MUST-NEVER #5).
   */
  readonly signingKey: SdwExportSigningKey | (() => SdwExportSigningKey | null);
  readonly resolvePublicKey: (keyRef: string) => Uint8Array | null;
  /**
   * The SAME multi-agent isolation guard instance the memory tool families
   * share (`memory-isolation.ts`). An export moves, and an import replaces,
   * the whole shared corpus, so they are the same custody question as
   * `memory_emit`; a second wrapped-agent identity reaching THIS process is
   * refused here too (bound: the guard is per server process).
   */
  readonly isolationGuard?: MultiAgentIsolationGuard;
  /**
   * The fortress root the export directory must stay inside. When set, the
   * archive is written into a fresh per-export directory under `exportDir`
   * with the bounded symlink containment described at
   * `prepareExportDestination`. Tests that write to a plain temp dir may
   * omit it.
   */
  readonly fortressRoot?: string;
  /** TEST-ONLY seam: runs after the fresh per-export directory exists, before the bytes are written. */
  readonly __afterExportDirPrepared?: () => Promise<void>;
  /** TEST-ONLY seam: runs after the rename, before the post-rename containment check. */
  readonly __afterExportRenamed?: () => Promise<void>;
  /**
   * Resolve operator-configured source key material by opaque reference.
   * Raw key bytes never transit tool arguments or the approval channel.
   */
  readonly resolveSourceMasterKey: (ref: string) => Uint8Array | null;
  readonly targetMasterKey: Uint8Array;
  readonly fs?: SdwExportFs;
  readonly now?: () => string;
}

/**
 * Private, unforgeable gate→handler channel. The router computes
 * `approvalTargetArgs(handlerArgs)` and later invokes
 * `handler(handlerArgs)` with the SAME object, so a Symbol-keyed property on
 * that object travels from gate evaluation to handler execution of one call
 * and nowhere else:
 *
 * - Agent args arrive as JSON — JSON cannot carry Symbol keys, and schema
 *   validation rejects unknown string fields, so the agent cannot inject or
 *   forge a binding.
 * - Symbol keys are invisible to `JSON.stringify`/`Object.keys`, so the
 *   binding never leaks into approval-channel payloads, audit details, or
 *   `normalizedArgsHash` (which canonicalizes string-keyed JSON only).
 * - No cross-call state exists: an abandoned gate evaluation (denied prompt,
 *   never-executed preflight) leaves nothing behind that a later call could
 *   consume. This is what closes the FIFO-stash cycle-back hole — the
 *   handler provably consumes the exact inventory/manifest that THIS call's
 *   approval was shown, not "the oldest entry for these args".
 */
const SDW_APPROVAL_BINDING = Symbol("sanctuary.sdw.approval-binding");

interface SdwExportScopeBinding {
  readonly kind: "export_scope";
  readonly toolName: "sdw_export" | "sdw_export_delete";
  /** Normalized hash of the gate-time args — the handler re-derives and compares. */
  readonly argsHash: string;
  /** The frozen ciphertext inventory the approval prompt displayed. */
  readonly inventory: SdwExportInventory;
  readonly storedAtMs: number;
}

interface SdwImportApprovalBinding {
  readonly kind: "import_manifest";
  readonly toolName: "sdw_import";
  readonly argsHash: string;
  /** Digest of the verified manifest the approval prompt displayed. */
  readonly manifestBodyDigest: string;
  readonly sourceKeyRef: string;
  readonly conflictResolution: "skip" | "overwrite";
  readonly storedAtMs: number;
}

type SdwApprovalBinding = SdwExportScopeBinding | SdwImportApprovalBinding;

interface BindableArgs extends Record<string, unknown> {
  [SDW_APPROVAL_BINDING]?: SdwApprovalBinding;
}

function attachApprovalBinding(
  args: Record<string, unknown>,
  binding: SdwApprovalBinding,
): void {
  Object.defineProperty(args, SDW_APPROVAL_BINDING, {
    value: binding,
    enumerable: false,
    configurable: true,
    writable: false,
  });
}

/**
 * Consume (single-use) the approval binding for this call. Returns null —
 * the caller MUST fail closed — when no binding exists (gate not configured
 * or `approvalTargetArgs` never ran), the binding belongs to a different
 * tool, it exceeded the freshness window, or the args object changed after
 * gate time (hash mismatch).
 */
function takeApprovalBinding(
  args: Record<string, unknown>,
  toolName: SdwApprovalBinding["toolName"],
  nowMs: number,
): SdwApprovalBinding | null {
  const bindable = args as BindableArgs;
  const binding = bindable[SDW_APPROVAL_BINDING];
  if (binding === undefined) return null;
  delete bindable[SDW_APPROVAL_BINDING];
  if (binding.toolName !== toolName) return null;
  if (nowMs - binding.storedAtMs > APPROVAL_BINDING_TTL_MS) return null;
  if (binding.argsHash !== normalizedArgsHash(args)) return null;
  return binding;
}

/**
 * NOT WIRED IN PRODUCTION. `sdw_export_delete` stays unregistered: the
 * backend-wide serialization boundary a verify-then-delete needs is not
 * designed yet. It is built here, unchanged from its pre-wiring form, only for
 * the D2 test suite.
 */
export function createSdwExportDeleteTool(options: SdwToolsOptions): ToolDefinition {
  return buildSdwTools(options, { includeExportDelete: true }).find(
    (tool) => tool.name === "sdw_export_delete",
  )!;
}

/** The shipped vault surface: `sdw_export` and `sdw_import`. */
export function createSdwTools(options: SdwToolsOptions): ToolDefinition[] {
  return buildSdwTools(options, { includeExportDelete: false });
}

function buildSdwTools(
  options: SdwToolsOptions,
  build: { includeExportDelete: boolean },
): ToolDefinition[] {
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

  const resolveSigningKey = (): SdwExportSigningKey | null =>
    typeof options.signingKey === "function" ? options.signingKey() : options.signingKey;

  // Every enumeration re-reads the live store first when the source can (the
  // shipped filesystem fortress is async): gate-time freeze and assembly-time
  // drift recheck both go through here so the scope digest is never computed
  // over a stale snapshot.
  const refreshInventory = (): Promise<void> | undefined => options.inventory.refresh?.();

  // Shared-scope custody: export moves and import replaces the whole
  // `fleet-self` corpus, so both sit behind the SAME pinned-identity guard as
  // memory_get/memory_emit; a second identity reaching this process is
  // refused with the fixed denial and an audit record.
  const refusedForeignIdentity = async (operation: string): Promise<boolean> => {
    if (options.isolationGuard === undefined) return false;
    if (options.isolationGuard(operation).allowed) return false;
    // Same denial class as the memory families (must match
    // SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS in memory-tools.ts).
    await auditFailure(`${operation}_denied`, { denial_class: SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS });
    return true;
  };

  /**
   * Gate-time wrapper for sdw_export: the isolation guard runs FIRST, before
   * any enumeration, so a foreign identity never sees the vault's inventory
   * and never raises a Tier-1 prompt (the throw makes the router deny without
   * prompting). Then the live re-read, then the synchronous gate body. Stays
   * synchronous when neither a guard nor a refresh is wired, so the existing
   * synchronous gate contract (and its tests) is unchanged.
   */
  const gateWithGuard = (
    toolName: "sdw_export",
    gate: () => Record<string, unknown>,
  ): Record<string, unknown> | Promise<Record<string, unknown>> => {
    if (options.isolationGuard === undefined && options.inventory.refresh === undefined) {
      return gate();
    }
    return (async () => {
      if (await refusedForeignIdentity(toolName)) {
        throw new SdwValidationError(
          "owner_scope_conflict",
          "SDW vault tool refused for a second wrapped-agent identity",
        );
      }
      await refreshInventory();
      return gate();
    })();
  };

  const storageIsTransactional = (): boolean =>
    typeof (options.storage as { sdwTransaction?: unknown }).sdwTransaction === "function";

  /**
   * Archive destination with BOUNDED symlink containment (fortressRoot set).
   * Node has no openat/renameat, so every check here is path-based:
   *   1. walk every component of exportDir below the root, refusing any
   *      symlink and creating missing ones;
   *   2. require realpath(exportDir) under realpath(root);
   *   3. mkdtemp a fresh per-export directory inside it (unpredictable name,
   *      so nothing can be pre-planted there), capture its inode and realpath.
   * `verifyFreshDirUnchanged` then re-runs the component walk and asserts the
   * inode and realpath are unchanged; the writer calls it immediately before
   * the O_EXCL open and immediately after the rename, unlinking what it
   * wrote on any mismatch.
   * RESIDUAL (stated, not closed): a swap inside the window between the last
   * check and the following syscall is not detected; that window is the
   * microseconds between `lstat`/`realpath` returning and `open`/`rename`
   * being issued. Closing it needs openat-style fd-relative syscalls Node
   * does not expose.
   * Without fortressRoot (test harnesses writing to a plain temp dir) the
   * legacy path-based atomic write is used.
   */
  interface FreshExportDir {
    readonly destinationPath: string;
    readonly freshDir: string;
    readonly verify: () => Promise<void>;
  }
  const prepareExportDestination = async (
    exportName: string,
  ): Promise<{ destinationPath: string; fresh: FreshExportDir | null }> => {
    if (options.fortressRoot === undefined) {
      await mkdir(options.exportDir, { recursive: true, mode: 0o700 });
      return { destinationPath: join(options.exportDir, `${exportName}.sdw-export.json`), fresh: null };
    }
    const root = resolve(options.fortressRoot);
    const dir = resolve(options.exportDir);
    const rel = relative(root, dir);
    if (rel === "" || rel.startsWith("..") || rel.includes(`..${sep}`)) {
      throw new Error("export directory is outside the fortress root");
    }
    const walkRefusingSymlinks = async (target: string, create: boolean): Promise<void> => {
      let current = root;
      for (const component of relative(root, target).split(sep)) {
        current = join(current, component);
        try {
          if ((await lstat(current)).isSymbolicLink()) {
            throw new Error("export directory path contains a symlink");
          }
        } catch (error) {
          if (!create || (error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          await mkdir(current, { mode: 0o700 });
        }
      }
    };
    await walkRefusingSymlinks(dir, true);
    const realRoot = await realpath(root);
    if (!(await realpath(dir)).startsWith(realRoot + sep)) {
      throw new Error("export directory resolved outside the fortress root");
    }
    const freshDir = await mkdtemp(join(dir, `${exportName}.`));
    const freshReal = await realpath(freshDir);
    const freshInode = (await lstat(freshDir, { bigint: true })).ino;
    if (!freshReal.startsWith(realRoot + sep)) {
      throw new Error("export directory resolved outside the fortress root");
    }
    const verify = async (): Promise<void> => {
      await walkRefusingSymlinks(freshDir, false);
      if ((await lstat(freshDir, { bigint: true })).ino !== freshInode) {
        throw new Error("export directory changed identity after validation");
      }
      if ((await realpath(freshDir)) !== freshReal) {
        throw new Error("export directory resolved elsewhere after validation");
      }
    };
    return {
      destinationPath: join(freshDir, `${exportName}.sdw-export.json`),
      fresh: { destinationPath: join(freshDir, `${exportName}.sdw-export.json`), freshDir, verify },
    };
  };

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
      "Export the Sovereign Data Warehouse (working state, query history, document " +
      "corpus, vector memory) as a signed, still-encrypted bundle written into a fresh " +
      "per-export directory under the operator-configured export directory on this " +
      "machine. Nothing is decrypted and nothing leaves the host; this is an " +
      "operator-directed archive, not a carriage path, and unsealed memory is never " +
      "carried by participant Exit. Tier 1: the approval freezes a " +
      "ciphertext-inventory fingerprint of exactly what will ship; any vault change " +
      "before packaging aborts the export.",
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
    // Gate-time inventory freeze. Decryption-free, metadata-only output
    // (synchronous once the live store has been re-read). Throwing here makes
    // the router deny without prompting.
    approvalTargetArgs: (args) =>
      gateWithGuard("sdw_export", () => {
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
        // Bind THIS call's approval target to THIS call's handler execution —
        // the handler can only ship the inventory whose digest the approval
        // prompt displayed (see SDW_APPROVAL_BINDING).
        attachApprovalBinding(args, {
          kind: "export_scope",
          toolName: "sdw_export",
          argsHash: normalizedArgsHash(args),
          inventory,
          storedAtMs: Date.now(),
        });
        return {
          export_name: exportName,
          ...sdwExportApprovalContext(inventory),
        };
      }),
    handler: async (args) => {
      if (await refusedForeignIdentity("sdw_export")) return genericDeny("sdw_export");
      const exportName = args.export_name as string;
      if (
        typeof exportName !== "string" ||
        !EXPORT_NAME_PATTERN.test(exportName) ||
        exportName.includes("..")
      ) {
        await auditFailure("sdw_export_denied", { denial_class: "invalid_export_name" });
        return genericDeny("sdw_export");
      }

      // Fail closed when this call carries no gate-time approval binding
      // (gate not configured, approvalTargetArgs never ran, binding expired,
      // or args changed after gate time). The consumed inventory is by
      // construction the one THIS call's approval prompt displayed.
      const binding = takeApprovalBinding(args, "sdw_export", Date.now());
      if (binding === null || binding.kind !== "export_scope") {
        await auditFailure("sdw_export_denied", {
          denial_class: "approval_scope_binding_missing",
        });
        return genericDeny("sdw_export");
      }
      const approved = binding.inventory;

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

      // Never degrade to an unsigned export: no resolvable signing identity
      // fails the export closed before anything is assembled (MUST-NEVER #5).
      const signingKey = resolveSigningKey();
      if (signingKey === null) {
        await auditFailure("sdw_export_failed", {
          export_audit_event_id: exportAuditEventId,
          category: "signing_identity_unavailable",
        });
        return genericDeny("sdw_export");
      }

      let built: { bundle: SdwStateExportBundle; manifestBodyDigest: string };
      try {
        // Re-read the live store so the assembly-time drift recheck inside
        // buildSignedSdwExportBundle compares against current bytes.
        await refreshInventory();
        built = buildSignedSdwExportBundle({
          inventory: approved,
          source: options.inventory,
          fortressId: options.fortressId,
          exportAuditEventId,
          signingKey,
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

      let destinationPath: string;
      try {
        // The export directory is created here, by the first approved export,
        // never at server boot (boot must not add anything to the fortress).
        const destination = await prepareExportDestination(exportName);
        destinationPath = destination.destinationPath;
        await options.__afterExportDirPrepared?.();
        if (destination.fresh === null) {
          await writeSdwExportBundleAtomic(built.bundle, destinationPath, options.fs);
        } else {
          await writeSdwExportBundleInFreshDir(built.bundle, destination.fresh.freshDir, destinationPath, {
            verify: destination.fresh.verify,
            afterRename: options.__afterExportRenamed,
          });
        }
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
      "Import a signed SDW export bundle produced by sdw_export. The manifest " +
      "signature is verified before any approval prompt; records are decrypted " +
      "only inside the approved flow and re-encrypted under this fortress. " +
      "Imports are all-or-nothing: they run inside one storage transaction, and a " +
      "backend without transactions refuses the import outright, before any " +
      "prompt, rather than applying part of it. The shipped filesystem fortress has " +
      "no transaction primitive today, so on that backend this tool refuses; only " +
      "the source key reference `this-fortress` (a bundle this fortress exported) " +
      "resolves, since cross-fortress source key material is not yet " +
      "operator-configurable. Tier 1.",
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
    // Verify-before-prompt. On failure: digest+category audit is awaited before
    // the throw, which the router converts to a fixed denial WITHOUT prompting.
    // On success the gate context carries metadata only — the bundle string
    // itself is deliberately absent (constraint #1); the manifest digest
    // binds it into the approval and into any approval proof.
    approvalTargetArgs: async (args) => {
      // Guard first: a foreign identity never gets as far as manifest parsing
      // or an approval prompt. Only awaited when a guard is wired, so the
      // no-guard path keeps its synchronous binding order.
      if (options.isolationGuard !== undefined && (await refusedForeignIdentity("sdw_import"))) {
        throw new SdwValidationError(
          "owner_scope_conflict",
          "SDW vault tool refused for a second wrapped-agent identity",
        );
      }
      // Never prompt a human for an import the handler will refuse because
      // the backend cannot apply it atomically.
      if (!storageIsTransactional()) {
        await auditFailure("sdw_import_denied", { denial_class: "storage_not_transactional" });
        throw new SdwImportVerificationError("storage_not_transactional");
      }
      const sourceKeyRef = args.source_key_ref;
      if (typeof sourceKeyRef !== "string" || sourceKeyRef.length === 0) {
        // Fail closed pre-prompt; the router converts the throw to the fixed
        // denial without prompting.
        throw new SdwValidationError(
          "invalid_identifier",
          "Invalid SDW import source key reference",
        );
      }
      const conflictResolution =
        args.conflict_resolution === "overwrite" ? "overwrite" : "skip";
      try {
        const bundle = decodeSdwExportBundle(args.bundle as string);
        const summary = verifySdwExportManifest(bundle, options.resolvePublicKey);
        // Bind THIS call's verified manifest summary to THIS call's handler
        // execution. The handler refuses to resolve key material, decrypt,
        // or write unless it consumes exactly this approved binding —
        // mirroring the export/delete fail-closed posture.
        attachApprovalBinding(args, {
          kind: "import_manifest",
          toolName: "sdw_import",
          argsHash: normalizedArgsHash(args),
          manifestBodyDigest: summary.manifest_body_digest,
          sourceKeyRef,
          conflictResolution,
          storedAtMs: Date.now(),
        });
        return {
          source_key_ref: sourceKeyRef,
          conflict_resolution: conflictResolution,
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
        await options.auditLog.appendCritical({
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
      if (await refusedForeignIdentity("sdw_import")) return genericDeny("sdw_import");
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

      // Fail closed when this call carries no gate-time approval binding —
      // a missing/bypassed gate must NOT leave sdw_import as a decrypt+write
      // primitive. This check runs BEFORE any key material is resolved and
      // before anything is decrypted.
      const binding = takeApprovalBinding(args, "sdw_import", Date.now());
      if (binding === null || binding.kind !== "import_manifest") {
        await auditFailure("sdw_import_denied", {
          denial_class: "approval_binding_missing",
          manifest_body_digest: summary.manifest_body_digest,
        });
        return genericDeny("sdw_import");
      }
      // The manifest digest the handler verified on ITS bytes must equal the
      // digest the approval prompt displayed; ditto the key slot and conflict
      // policy. Defense-in-depth on top of the args-hash binding.
      if (
        binding.manifestBodyDigest !== summary.manifest_body_digest ||
        binding.sourceKeyRef !== args.source_key_ref ||
        binding.conflictResolution !==
          (args.conflict_resolution === "overwrite" ? "overwrite" : "skip")
      ) {
        await auditFailure("sdw_import_denied", {
          denial_class: "approval_binding_mismatch",
          manifest_body_digest: summary.manifest_body_digest,
        });
        return genericDeny("sdw_import");
      }

      const sourceMasterKey = options.resolveSourceMasterKey(binding.sourceKeyRef);
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
          conflictResolution: binding.conflictResolution,
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
      // Bind THIS call's frozen inventory to THIS call's handler execution
      // (see SDW_APPROVAL_BINDING): the handler deletes only against the
      // snapshot the approval prompt displayed.
      attachApprovalBinding(args, {
        kind: "export_scope",
        toolName: "sdw_export_delete",
        argsHash: normalizedArgsHash(args),
        inventory,
        storedAtMs: Date.now(),
      });
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

      // Fail closed when this call carries no gate-time approval binding —
      // the consumed inventory is the one THIS call's approval displayed.
      const binding = takeApprovalBinding(args, "sdw_export_delete", Date.now());
      if (binding === null || binding.kind !== "export_scope") {
        await auditFailure("sdw_export_delete_denied", {
          denial_class: "approval_scope_binding_missing",
          manifest_body_digest: digest,
        });
        return genericDeny("sdw_export_delete");
      }
      const approved = binding.inventory;

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

  return build.includeExportDelete ? [sdwExport, sdwImport, sdwExportDelete] : [sdwExport, sdwImport];
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
