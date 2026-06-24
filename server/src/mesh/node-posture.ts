import type { NodeMode } from "./constants.js";

export const NODE_TRUST_BOUNDARY_VERSION = "operator-cloud-trust-boundary-v1";

export const OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL =
  "provider in trust boundary, not TEE";

export const OPERATOR_CLOUD_DISCLOSURE =
  "This node runs in your cloud account. Until sovereign TEE mode is enabled and attested, provider is in this node's trust boundary: it can technically read this node's memory while the node is running. Treat this as operator-controlled cloud deployment, not full sovereign isolation.";

export type NodeModeForPosture = NodeMode | "unknown";

export type NodeTrustBoundaryPosture =
  | "local_operator_host"
  | "provider_in_trust_boundary_not_tee"
  | "sovereign_tee_unverified"
  | "sovereign_tee_attested"
  | "unknown";

export type NodeDrillStatus =
  | "not_applicable"
  | "unproven"
  | "verified"
  | "unknown";

export interface NodeTrustBoundary {
  version: typeof NODE_TRUST_BOUNDARY_VERSION;
  posture: NodeTrustBoundaryPosture;
  label: string;
  provider_in_trust_boundary: boolean;
  tee_attested: boolean;
  disclosure: string | null;
}

export interface NodePosture {
  node_mode: NodeModeForPosture;
  host_provider: string | null;
  trust_boundary: NodeTrustBoundary;
  tee_attested: boolean;
  disclosure_acknowledged_at: string | null;
  drill_status: NodeDrillStatus;
}

export function deriveNodePosture(params: {
  nodeMode: NodeModeForPosture | null | undefined;
  hostProvider?: string | null;
  verifiedTeeEvidence?: boolean;
  disclosureAcknowledgedAt?: string | null;
}): NodePosture {
  const nodeMode = params.nodeMode ?? "unknown";
  const verifiedTeeEvidence =
    nodeMode === "sovereign_tee" && params.verifiedTeeEvidence === true;

  if (nodeMode === "operator_cloud") {
    return {
      node_mode: nodeMode,
      host_provider: params.hostProvider ?? "provider",
      trust_boundary: {
        version: NODE_TRUST_BOUNDARY_VERSION,
        posture: "provider_in_trust_boundary_not_tee",
        label: OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL,
        provider_in_trust_boundary: true,
        tee_attested: false,
        disclosure: OPERATOR_CLOUD_DISCLOSURE,
      },
      tee_attested: false,
      disclosure_acknowledged_at: params.disclosureAcknowledgedAt ?? null,
      drill_status: "unproven",
    };
  }

  if (nodeMode === "sovereign_tee") {
    return {
      node_mode: nodeMode,
      host_provider: params.hostProvider ?? null,
      trust_boundary: {
        version: NODE_TRUST_BOUNDARY_VERSION,
        posture: verifiedTeeEvidence
          ? "sovereign_tee_attested"
          : "sovereign_tee_unverified",
        label: verifiedTeeEvidence
          ? "sovereign TEE attested"
          : "sovereign TEE evidence unavailable",
        provider_in_trust_boundary: !verifiedTeeEvidence,
        tee_attested: verifiedTeeEvidence,
        disclosure: verifiedTeeEvidence
          ? null
          : "TEE posture is unverified until real hardware attestation evidence is validated.",
      },
      tee_attested: verifiedTeeEvidence,
      disclosure_acknowledged_at: params.disclosureAcknowledgedAt ?? null,
      drill_status: verifiedTeeEvidence ? "verified" : "unproven",
    };
  }

  if (nodeMode === "local") {
    return {
      node_mode: nodeMode,
      host_provider: null,
      trust_boundary: {
        version: NODE_TRUST_BOUNDARY_VERSION,
        posture: "local_operator_host",
        label: "local operator host",
        provider_in_trust_boundary: false,
        tee_attested: false,
        disclosure: null,
      },
      tee_attested: false,
      disclosure_acknowledged_at: params.disclosureAcknowledgedAt ?? null,
      drill_status: "not_applicable",
    };
  }

  return {
    node_mode: "unknown",
    host_provider: params.hostProvider ?? null,
    trust_boundary: {
      version: NODE_TRUST_BOUNDARY_VERSION,
      posture: "unknown",
      label: "unknown",
      provider_in_trust_boundary: false,
      tee_attested: false,
      disclosure: null,
    },
    tee_attested: false,
    disclosure_acknowledged_at: params.disclosureAcknowledgedAt ?? null,
    drill_status: "unknown",
  };
}
