import type { AuditChainVerdictStatus } from "../operational/audit-log.js";
import { parseIsoInstantWithOffset } from "../core/time.js";
import type { FeatureHealthPanel } from "../principal-policy/feature-health.js";
import { DEFAULT_ENFORCEMENT_FRESHNESS_MS, ENFORCEMENT_FUTURE_SKEW_MS, type CustodyExitPanel } from "../principal-policy/posture.js";
import type { PosturePanelStatus } from "../principal-policy/panel-producer.js";

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
  featureHealth?: Pick<FeatureHealthPanel, "rows" | "audit_integrity_ok" | "window_end">;
  custodyExit?: CustodyExitPanel;
  /** Must match the custody producer observation in cooperative-surface.ts and posture-routes.ts. */
  custodyObservation?: Pick<PosturePanelStatus, "state" | "completed_at">;
  /** Evaluation time for current evidence, injectable for deterministic consumers. */
  now?: number;
  toolOutputScreenReady?: boolean;
}

const NO_SOURCE = "no evidence source wired";

/** Compose all layers without I/O. Missing evidence never earns an on state. */
export function composeProtectionLayers(evidence: ProtectionEvidence): ProtectionLayerRow[] {
  const now = evidence.now ?? Date.now();
  function current(timestamp: string | null | undefined, windowMs = DEFAULT_ENFORCEMENT_FRESHNESS_MS): boolean {
    const at = timestamp ? parseIsoInstantWithOffset(timestamp) : undefined;
    // Explicit offsets make the feature-health age and skew bounds independent of the reader's timezone.
    return at !== undefined && Number.isFinite(windowMs) && windowMs > 0 &&
      at <= now + ENFORCEMENT_FUTURE_SKEW_MS && now - at <= Math.min(windowMs, DEFAULT_ENFORCEMENT_FRESHNESS_MS);
  }
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
    const basis = `feature health: ${featureId}`;
    // Feature-health verifies this feature's evidence; unreadable or stale panels cannot support a current verdict.
    if (!health?.audit_integrity_ok || !source.audit_integrity_ok) return row(id, name, "unknown", `${basis}; integrity not verified`);
    if (!current(health.window_end)) return row(id, name, "unknown", `${basis}; stale observation`);
    if (source.status === "fault" || source.basis === "intentionally_stopped") return row(id, name, "off", basis);
    if (source.status === "active" && !current(source.last_evidence_at, source.freshness_window_ms)) {
      return row(id, name, "unknown", `${basis}; ${source.liveness === "event_driven"
        ? "activity in the last 24 hours, not current" : "stale evidence"}`);
    }
    return row(id, name, source.status === "active" ? "on" : "unknown", basis);
  }
  function exit(): ProtectionLayerRow {
    const panel = evidence.custodyExit;
    const observation = evidence.custodyObservation;
    if (!panel) return row("exit", "Exit", "unknown", observation ? "custody exit: audit read unavailable" : NO_SOURCE);
    if (!observation || observation.state === "unavailable") return row("exit", "Exit", "unknown", "custody exit: fallback or unavailable observation");
    if (observation.state !== "fresh" || !current(observation.completed_at, panel.freshness_window_ms)) {
      return row("exit", "Exit", "unknown", "custody exit: stale observation");
    }
    // The custody read's integrity and producer freshness qualify availability; the capability label alone does not.
    if (!panel.audit_integrity_ok) return row("exit", "Exit", "unknown", "custody exit: audit read unavailable or integrity not verified");
    return row("exit", "Exit", panel.exit_state === "export_available" ? "on" : "unknown", "custody exit: gated export available");
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
    // Daemon liveness never earns active; fresh token evidence qualifies on unless the daemon is reported down.
    if (daemon.status === "off") broker.status = "off";
    const daemonSource = evidence.featureHealth?.rows.find(r => r.feature_id === "secret_broker_daemon");
    // Unavailable authenticity evidence cannot establish daemon availability on either surface.
    if (broker.status === "on" && (daemonSource?.basis === "integrity_tainted" || daemonSource?.audit_integrity_ok === false)) {
      broker.status = "unknown";
    }
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
    exit(),
    row("inbound_protection", "Inbound protection", "not_built", evidence.toolOutputScreenReady === undefined
      ? "capability: not built"
      : `capability: not built; tool-output screening readiness: ${observed(evidence.toolOutputScreenReady)}`),
  ];
}

/** One plain-English line per row, preserving the inventory's order. */
export function summarizeProtectionLayers(rows: readonly ProtectionLayerRow[]): string {
  return rows.map(r => `${r.name}: ${r.status.replace("_", " ")}`).join("\n");
}
