import { registerFixture } from "../../registry.js";
import { SentinelRegistry } from "../../../../server/src/sentinel/sentinel-registry.js";
import {
  PHI1_BASELINE_CATALOG,
  EGRESS_VOLUME_SENTINEL_ID,
  EBPF_SYSCALL_SENTINEL_ID,
  AUDITD_TAIL_SENTINEL_ID,
} from "../../../../server/src/sentinel/sentinels/index.js";

// Recon: canonical sentinel registration surface is SentinelRegistry.register()
// with PHI1_BASELINE_CATALOG, mirrored by sentinel-framework.test.ts. Maps to row 8.
const CLAIM_ID = "8";
const CLAIM_LABEL = "Health and attestation evidence-based";

function makeRegistry(): SentinelRegistry {
  const registry = new SentinelRegistry();
  for (const entry of PHI1_BASELINE_CATALOG) {
    registry.register(entry);
  }
  return registry;
}

function catalogContains(sentinelId: string): boolean {
  return makeRegistry().listCatalog().some((entry) => entry.sentinelId === sentinelId);
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "sentinel-registration: register baseline sentinel", async () => {
  const start = performance.now();
  return {
    passed: catalogContains(EGRESS_VOLUME_SENTINEL_ID),
    durationMs: performance.now() - start,
  };
});

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "sentinel-registration: register observation sentinel eBPF",
  async () => {
    const start = performance.now();
    return {
      passed: catalogContains(EBPF_SYSCALL_SENTINEL_ID),
      durationMs: performance.now() - start,
    };
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "sentinel-registration: register observation sentinel auditd",
  async () => {
    const start = performance.now();
    return {
      passed: catalogContains(AUDITD_TAIL_SENTINEL_ID),
      durationMs: performance.now() - start,
    };
  },
);
