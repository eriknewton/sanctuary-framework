import type { AuditChainVerdictStatus } from "../operational/audit-log.js";
import type { FeatureHealthPanel } from "../principal-policy/feature-health.js";
import type { CustodyExitPanel } from "../principal-policy/posture.js";

/** A layer's observed state; unknown includes unavailable or inconclusive evidence. */
export type ProtectionLayerStatus = "on" | "off" | "not_built" | "unknown";

/** Public layer inventory shared by the cooperative tool and posture home. */
export interface ProtectionLayerRow {
  id: string;
  name: string;
  status: ProtectionLayerStatus;
  basis: string;
}

/** Observations from existing consumers, never policy intent or enabled flags. */
export interface ProtectionEvidence {
  identityLoaded?: boolean;
  encryptedStateStoreConstructed?: boolean;
  auditChain?: AuditChainVerdictStatus;
  featureHealth?: Pick<FeatureHealthPanel, "rows" | "audit_integrity_ok">;
  custodyExit?: CustodyExitPanel;
  toolOutputScreenReady?: boolean;
}

const NO_SOURCE = "no evidence source wired";

/** Compose all layers without I/O. Missing evidence never earns an on state. */
export function composeProtectionLayers(evidence: ProtectionEvidence): ProtectionLayerRow[] {
  function row(id: string, name: string, status: ProtectionLayerStatus = "unknown", basis = NO_SOURCE): ProtectionLayerRow {
    return { id, name, status, basis };
  }
  function observed(value: boolean | undefined): ProtectionLayerStatus {
    return value === undefined ? "unknown" : value ? "on" : "off";
  }
  function feature(id: string, name: string, featureId: string): ProtectionLayerRow {
    const health = evidence.featureHealth;
    const source = health?.rows.find(r => r.feature_id === featureId);
    if (!source) return row(id, name);
    // Feature-health verifies the observed feature's evidence; a tainted read cannot support any verdict.
    const status: ProtectionLayerStatus = !health?.audit_integrity_ok || !source.audit_integrity_ok
      ? "unknown"
      : source.status === "active" ? "on"
      : source.status === "fault" || source.basis === "intentionally_stopped" ? "off" : "unknown";
    return row(id, name, status, `feature health: ${featureId}`);
  }
  const privacy = row("query_privacy", "Query privacy");
  const headers = feature("header_strip", "Headers", "header_strip");
  const rewrites = feature("privacy_strips", "Rewrites", "privacy_strips");
  if (headers.basis !== NO_SOURCE || rewrites.basis !== NO_SOURCE) {
    // Header and rewrite observations do not establish timestamp blurring for the combined layer.
    privacy.basis = `feature health: header_strip ${headers.status}, privacy_strips ${rewrites.status}; timestamp blurring: ${NO_SOURCE}`;
  }
  const broker = feature("credential_stand_ins", "Credential stand-ins", "secret_broker");
  const daemon = feature("secret_broker_daemon", "Broker daemon", "secret_broker_daemon");
  if (daemon.basis !== NO_SOURCE) {
    // Daemon liveness is separate from the broker's observed token decisions.
    broker.basis += `; feature health: secret_broker_daemon ${daemon.status}`;
  }
  return [
    row("identity", "Identity", observed(evidence.identityLoaded), evidence.identityLoaded === undefined ? NO_SOURCE : "identity manager: session keys"),
    row("encrypted_vault", "Encrypted vault", observed(evidence.encryptedStateStoreConstructed),
      evidence.encryptedStateStoreConstructed === undefined ? NO_SOURCE : "runtime: encrypted StateStore"),
    row("mantle_binding", "Mantle binding"),
    feature("approval_gates", "Approval gates", "approval_gates"),
    // Chain integrity alone does not attest that a signed checkpoint has been observed.
    row("signed_record", "Signed record", "unknown", evidence.auditChain === undefined ? NO_SOURCE : `audit chain: ${evidence.auditChain}; signed checkpoint: ${NO_SOURCE}`),
    feature("castle_wall", "Castle Wall", "castle_wall_egress"),
    row("context_gate", "Context gate"),
    row("local_model_routing", "Local model routing"),
    row("sentinels", "Sentinels"),
    privacy,
    broker,
    // Export availability describes the gated export capability, never a clean-exit guarantee.
    row("exit", "Exit", evidence.custodyExit?.exit_state === "export_available" ? "on" : "unknown",
      evidence.custodyExit ? "custody exit: gated export available" : NO_SOURCE),
    row("inbound_protection", "Inbound protection", "not_built", evidence.toolOutputScreenReady === undefined
      ? "capability: not built"
      : `capability: not built; tool-output screening readiness: ${observed(evidence.toolOutputScreenReady)}`),
  ];
}

/** One plain-English line per row, preserving the inventory's order. */
export function summarizeProtectionLayers(rows: readonly ProtectionLayerRow[]): string {
  return rows.map(r => `${r.name}: ${r.status.replace("_", " ")}`).join("\n");
}
