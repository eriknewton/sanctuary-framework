/**
 * Shared PUBLIC-SURFACE extractors for the PR-0 snapshot harness.
 *
 * Step 0 of the l1-l4 -> named-layer rename: this module is the SINGLE SOURCE
 * of the four "public surface" artifacts that every later rename PR must leave
 * byte-for-byte unchanged. The snapshot test (public-surface-snapshot.test.ts)
 * and the fixture generator (gen-public-surface-snapshot.ts) BOTH call these
 * functions, so the committed fixtures and the live comparison can never drift
 * out of step (the same lesson the em-dash baseline + its generator learned).
 *
 * The four artifacts (deliberately reconciled against the EXISTING Phase-0
 * guards in this directory so PR-0 adds coverage rather than duplicating it):
 *
 *   1. MCP tool catalog ({name, description, inputSchema}, sorted by name) —
 *      the full agent-facing tool set: the main createSanctuaryServer catalog
 *      PLUS the standalone broker MCP server's four broker/* tools (which the
 *      existing reorg-surface golden does NOT cover — that golden is registration
 *      ORDER of the main catalog only and excludes descriptions). Here the layer
 *      rename target is explicit: the wire tool NAMES + SCHEMAS + the agent-facing
 *      DESCRIPTION prose all live on the public surface a rename must not touch.
 *
 *   2. SHR JSON SHAPE — the structural key paths of a signed SHR body's
 *      `layers.*` plus the sorted set of `degradations[].layer` field VALUES
 *      (l1..l4). Values like generated_at / signature are non-deterministic, so
 *      we snapshot the SHAPE (the l1..l4 layer keys + per-layer field names),
 *      which is exactly the surface a rename would corrupt.
 *
 *   3. Sovereignty-audit JSON SHAPE — the `layers.*` keys, the `gaps[].id` +
 *      `gaps[].layer` value sets from analyzeSovereignty(), and the
 *      gateway-adapter `layer_scores.*` / `layer_status.*` keys from
 *      transformSHRForGateway(). Deterministic via a fixed fingerprint + config.
 *
 *   4. Exported package API — the sorted list of NAMES re-exported from
 *      src/index.ts (what becomes dist/index.d.ts). Resolved with the TypeScript
 *      compiler's type checker so `export *` re-exports are included.
 */

import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { Broker } from "../../src/l3-disclosure/broker/broker.js";
import type { Backend } from "../../src/l3-disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../src/l3-disclosure/broker/backend-interface.js";
import { createBrokerMcpServer } from "../../src/broker-mcp/broker-server.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { generateSHR } from "../../src/shr/generator.js";
import type { SignedSHR } from "../../src/shr/types.js";
import { transformSHRForGateway } from "../../src/shr/gateway-adapter.js";
import { analyzeSovereignty } from "../../src/audit/analyzer.js";
import type { EnvironmentFingerprint } from "../../src/audit/types.js";
import { defaultConfig } from "../../src/config.js";

/** Deterministic passphrase for the snapshot harness's in-memory fortress. */
const SNAPSHOT_PASSPHRASE = "public-surface-snapshot-deterministic-v1";

/** server/test/structure/<file> is two levels below server/. */
const SERVER_DIR = join(fileURLToPath(import.meta.url), "..", "..", "..");
const INDEX_TS = join(SERVER_DIR, "src", "index.ts");
const TSCONFIG = join(SERVER_DIR, "tsconfig.json");

// ── Artifact types ────────────────────────────────────────────────────────

/** The frozen public contract per MCP tool: name + agent-facing prose + schema. */
export interface ToolSurfaceEntry {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface ShrShape {
  /** Sorted top-level keys under body.layers (the l1..l4 layer names). */
  layer_keys: string[];
  /** Per-layer sorted field-name lists, keyed by layer name. */
  layer_field_names: Record<string, string[]>;
  /** Sorted DISTINCT degradations[].layer field VALUES present in the body. */
  degradation_layer_values: string[];
}

export interface SovereigntyAuditShape {
  /** Sorted keys under result.layers (l1_cognitive .. l4_reputation). */
  layer_keys: string[];
  /** Sorted DISTINCT gaps[].id values for the fixed fingerprint. */
  gap_ids: string[];
  /** Sorted DISTINCT gaps[].layer field VALUES (L1..L4 / cross-cutting). */
  gap_layer_values: string[];
  /** Sorted keys of the gateway-adapter layer_scores object. */
  gateway_layer_score_keys: string[];
  /** Sorted keys of the gateway-adapter layer_status object. */
  gateway_layer_status_keys: string[];
}

// ── Helpers ─────────────────────────────────────────────────────────────

/** Reach into the MCP SDK Server's private request-handler map (test-only). */
function requestHandler(
  server: unknown,
  method: string,
): (req: unknown, extra: unknown) => unknown {
  const handler = (
    server as { _requestHandlers: Map<string, (...a: unknown[]) => unknown> }
  )._requestHandlers.get(method);
  if (!handler) throw new Error(`${method} handler not registered`);
  return handler as (req: unknown, extra: unknown) => unknown;
}

async function listTools(
  server: unknown,
): Promise<Array<{ name: string; description?: unknown; inputSchema?: unknown }>> {
  const handler = requestHandler(server, "tools/list");
  const result = (await handler({ method: "tools/list", params: {} }, {})) as {
    tools: Array<{ name: string; description?: unknown; inputSchema?: unknown }>;
  };
  return result.tools;
}

/** Minimal in-memory backend mirroring the broker-server test harness. */
function makeFakeBackend(seed: Record<string, string> = {}): Backend {
  const store = new Map(Object.entries(seed));
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() {
      return true;
    },
    async addSecret(n, v) {
      if (store.has(n)) throw new Error("exists");
      store.set(n, v);
    },
    async readSecret(n) {
      const v = store.get(n);
      if (v === undefined) throw new SecretNotFoundError(n);
      return v;
    },
    async rotateSecret(n, v) {
      if (!store.has(n)) throw new SecretNotFoundError(n);
      store.set(n, v);
    },
    async deleteSecret(n) {
      if (!store.delete(n)) throw new SecretNotFoundError(n);
    },
    async listSecretNames() {
      return Array.from(store.keys());
    },
  };
}

/** Minimal IdentityManager mock — mirrors shr.test.ts / gateway-adapter.test.ts. */
class SnapshotIdentityManager {
  private identities = new Map<string, unknown>();
  private defaultId: string | null = null;

  constructor(masterKey: Uint8Array) {
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      "snapshot",
      encKey,
      "recovery-key",
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

/** The fixed environment fingerprint used for the audit-shape snapshot. */
function snapshotFingerprint(): EnvironmentFingerprint {
  return {
    sanctuary_installed: true,
    sanctuary_version: "0.3.0",
    openclaw_detected: false,
    openclaw_version: null,
    openclaw_config: null,
    node_version: "v20.0.0",
    platform: "linux-x64",
  };
}

// ── Artifact #1: MCP tool catalog ───────────────────────────────────────

/**
 * The FULL agent-facing MCP tool catalog: the main createSanctuaryServer
 * tools + the standalone broker MCP server's broker/* tools, serialized as
 * {name, description, inputSchema} and SORTED BY NAME. Deterministic
 * (in-memory fortress, fixed passphrase, no network).
 */
export async function extractToolSurface(): Promise<ToolSurfaceEntry[]> {
  const { server } = await createSanctuaryServer({
    storage: new MemoryStorage(),
    passphrase: SNAPSHOT_PASSPHRASE,
  });
  const mainTools = await listTools(server);

  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(new MemoryStorage(), masterKey);
  const broker = new Broker({
    backend: makeFakeBackend({ snapshot_secret: "x" }),
    auditLog,
    grants: [{ skill: "snapshot-skill", secret: "snapshot_secret", scope: "read" }],
    principalIdentityId: "did:sanctuary:snapshot",
  });
  const brokerServer = createBrokerMcpServer(broker, {
    skill: "snapshot-skill",
    agentId: "snapshot",
    identityId: "did:sanctuary:snapshot",
    tenantId: "tenant-snapshot",
    fortressId: "fortress-snapshot",
    audience: "sanctuary-broker",
  });
  const brokerTools = await listTools(brokerServer);

  return [...mainTools, ...brokerTools]
    .map((t) => ({
      name: t.name,
      description: typeof t.description === "string" ? t.description : "",
      inputSchema: (t.inputSchema ?? {}) as Record<string, unknown>,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

// ── Artifact #2: SHR JSON shape ─────────────────────────────────────────

function sortedKeys(o: unknown): string[] {
  if (o === null || typeof o !== "object") return [];
  return Object.keys(o as Record<string, unknown>).sort();
}

export function extractShrShape(): ShrShape {
  const masterKey = generateRandomKey();
  const identityManager = new SnapshotIdentityManager(masterKey);
  const config = defaultConfig();
  const shr = generateSHR(undefined, {
    config,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    identityManager: identityManager as any,
    masterKey,
    // Force every L4 degradation code so the degradation layer-value surface is
    // populated for l4 too, not just the always-present l2 PROCESS_ISOLATION_ONLY.
    l4Evidence: {
      attestation_count: 0,
      tier_distribution: {
        "verified-sovereign": 0,
        "verified-degraded": 0,
        "self-attested": 0,
        unverified: 0,
      },
      most_recent_attestation_at: null,
      dispute_count: 0,
      context_breakdown: {},
      verascore_linked: false,
    },
  }) as SignedSHR;

  const layers = shr.body.layers as unknown as Record<string, unknown>;
  const layerKeys = sortedKeys(layers);
  const layerFieldNames: Record<string, string[]> = {};
  for (const k of layerKeys) {
    layerFieldNames[k] = sortedKeys(layers[k]);
  }
  const degradationLayerValues = [
    ...new Set(shr.body.degradations.map((d) => d.layer)),
  ].sort();

  return {
    layer_keys: layerKeys,
    layer_field_names: layerFieldNames,
    degradation_layer_values: degradationLayerValues,
  };
}

// ── Artifact #3: sovereignty-audit JSON shape ───────────────────────────

export function extractSovereigntyAuditShape(): SovereigntyAuditShape {
  const config = defaultConfig();
  const result = analyzeSovereignty(snapshotFingerprint(), config);

  // Gaps for the ALL-CLEAN fingerprint are empty by design; use a degraded
  // fingerprint so the gap id/layer value surface is non-empty and stable.
  const degraded = analyzeSovereignty(
    {
      ...snapshotFingerprint(),
      sanctuary_installed: false,
      sanctuary_version: null,
      openclaw_detected: true,
      openclaw_config: {
        config_path: "/home/snapshot/.openclaw/openclaw.json",
        require_approval_enabled: false,
        sandbox_policy_active: false,
        sandbox_allow_list: [],
        sandbox_deny_list: [],
        memory_encrypted: false,
        env_file_exposed: true,
        gateway_token_set: false,
        dm_pairing_enabled: false,
        mcp_bridge_active: false,
      },
    },
    config,
  );

  const gapIds = [...new Set(degraded.gaps.map((g) => g.id))].sort();
  const gapLayerValues = [
    ...new Set(degraded.gaps.map((g) => g.layer)),
  ].sort();

  // Gateway adapter layer_scores / layer_status keys (deterministic shape).
  const masterKey = generateRandomKey();
  const identityManager = new SnapshotIdentityManager(masterKey);
  const shr = generateSHR(undefined, {
    config,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    identityManager: identityManager as any,
    masterKey,
  }) as SignedSHR;
  const gateway = transformSHRForGateway(shr);

  return {
    layer_keys: sortedKeys(result.layers),
    gap_ids: gapIds,
    gap_layer_values: gapLayerValues,
    gateway_layer_score_keys: sortedKeys(gateway.layer_scores),
    gateway_layer_status_keys: sortedKeys(gateway.layer_status),
  };
}

// ── Artifact #4: exported package API ───────────────────────────────────

/**
 * Sorted list of NAMES exported from src/index.ts (the public barrel that
 * becomes dist/index.d.ts). Uses the TypeScript type checker so `export *`
 * re-exports are resolved into their concrete names.
 */
export function extractExportedNames(): string[] {
  const configFile = ts.readConfigFile(TSCONFIG, ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(
    configFile.config,
    ts.sys,
    SERVER_DIR,
  );
  const program = ts.createProgram({
    rootNames: [INDEX_TS],
    options: { ...parsed.options, noEmit: true },
  });
  const checker = program.getTypeChecker();
  const source = program.getSourceFile(INDEX_TS);
  if (!source) throw new Error(`could not load source file: ${INDEX_TS}`);
  const moduleSymbol = checker.getSymbolAtLocation(source);
  if (!moduleSymbol) throw new Error("index.ts is not a module (no exports)");
  const exported = checker.getExportsOfModule(moduleSymbol);
  return [...new Set(exported.map((s) => s.getName()))].sort();
}
