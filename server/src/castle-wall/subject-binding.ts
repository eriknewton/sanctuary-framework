import { join } from "node:path";

import { readFileCustody } from "../storage/custody-fs.js";
import { validateAgentOrigin } from "./allowlist/agent-origin.js";

const MACOS_AUDIT_TOKEN_HEX_RE = /^[0-9a-fA-F]{64}$/;

export type ProtectionSubjectMatchReason =
  | "matched"
  | "subject_unresolvable"
  | "missing_evidence_subject"
  | "legacy_macos_audit_token"
  | "subject_mismatch";

export type ProtectionSubjectMatch =
  | { matches: true; reason: Extract<ProtectionSubjectMatchReason, "matched"> }
  | {
      matches: false;
      reason: Extract<
        ProtectionSubjectMatchReason,
        | "subject_unresolvable"
        | "missing_evidence_subject"
        | "legacy_macos_audit_token"
        | "subject_mismatch"
      >;
      evidenceSubject: string | null;
    };

/**
 * Subject matching mode for Castle Wall protection evidence.
 *
 * `exact_subject` is the per-agent protection-claim rule: "this agent is
 * protected" requires evidence bound to this exact confined-agent subject.
 *
 * `fortress_scoped` is reserved for daemon/coarse-wall facts that are
 * machine-wide for a fortress. Evidence from any canonical subject within that
 * fortress can prove a daemon heartbeat or coarse wall exists on this machine,
 * but it does NOT prove any particular agent's fine-grained protection claim.
 * Per-agent enforcement callers must keep `exact_subject`.
 */
export type ProtectionSubjectMatchMode =
  | { readonly mode: "exact_subject" }
  | { readonly mode: "fortress_scoped"; readonly fortressId: string };

export type ProtectionSubjectResolutionStatus =
  | "resolved"
  | "absent"
  | "non_uid_mode"
  | "invalid_descriptor"
  | "malformed_json"
  | "unreadable";

export type ProtectionSubjectResolution =
  | {
      status: "resolved";
      subject: string;
      message: string;
    }
  | {
      status: Exclude<ProtectionSubjectResolutionStatus, "resolved">;
      subject: null;
      message: string;
    };

export function isLegacyMacOSAuditTokenHex(value: unknown): value is string {
  return typeof value === "string" && MACOS_AUDIT_TOKEN_HEX_RE.test(value);
}

export function protectionSubjectForUid(
  fortressId: string,
  uid: number,
): string | null {
  if (
    typeof fortressId !== "string" ||
    fortressId.length === 0 ||
    !Number.isInteger(uid) ||
    uid < 1 ||
    uid > 0xffffffff
  ) {
    return null;
  }
  return `${fortressId}/uid-${uid}`;
}

export function fortressIdFromProtectionSubject(
  subject: string | null | undefined,
): string | null {
  if (typeof subject !== "string" || subject.length === 0) return null;
  const match = /^(.*)\/uid-([1-9][0-9]*)$/.exec(subject);
  if (match === null) return null;
  const [, fortressId, rawUid] = match;
  if (fortressId.length === 0) return null;
  const uid = Number(rawUid);
  if (!Number.isInteger(uid)) return null;
  return protectionSubjectForUid(fortressId, uid) === subject
    ? fortressId
    : null;
}

export function ruidFromMacOSAuditTokenHex(agentId: string): number | null {
  if (!isLegacyMacOSAuditTokenHex(agentId)) return null;
  const bytes = [
    Number.parseInt(agentId.slice(24, 26), 16),
    Number.parseInt(agentId.slice(26, 28), 16),
    Number.parseInt(agentId.slice(28, 30), 16),
    Number.parseInt(agentId.slice(30, 32), 16),
  ];
  if (bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) {
    return null;
  }
  return (
    (bytes[0] |
      (bytes[1] << 8) |
      (bytes[2] << 16) |
      (bytes[3] << 24)) >>>
    0
  );
}

export function protectionSubjectFromMacOSAuditToken(
  fortressId: string,
  agentId: string,
): string | null {
  const ruid = ruidFromMacOSAuditTokenHex(agentId);
  return ruid === null ? null : protectionSubjectForUid(fortressId, ruid);
}

function evidenceSubjectBelongsToFortress(
  fortressId: string,
  evidenceSubject: string,
): boolean {
  if (evidenceSubject === fortressId) return true;
  const prefix = `${fortressId}/uid-`;
  if (!evidenceSubject.startsWith(prefix)) return false;
  const rawUid = evidenceSubject.slice(prefix.length);
  if (!/^[1-9][0-9]*$/.test(rawUid)) return false;
  const uid = Number(rawUid);
  return protectionSubjectForUid(fortressId, uid) === evidenceSubject;
}

export function protectionSubjectFromAgentOrigin(
  fortressId: string,
  candidate: unknown,
): string | null {
  const result = resolveProtectionSubjectFromAgentOrigin(fortressId, candidate);
  return result.subject;
}

export function resolveProtectionSubjectFromAgentOrigin(
  fortressId: string,
  candidate: unknown,
): ProtectionSubjectResolution {
  const origin = validateAgentOrigin(candidate);
  if (origin === null) {
    return {
      status: "invalid_descriptor",
      subject: null,
      message:
        "agent-origin.json is present but does not contain a valid confined uid descriptor",
    };
  }
  if (origin.mode !== "uid") {
    return {
      status: "non_uid_mode",
      subject: null,
      message:
        "agent-origin.json is not uid mode, so no per-uid confined agent subject can be derived",
    };
  }
  if (typeof origin.agent_uid !== "number") {
    return {
      status: "invalid_descriptor",
      subject: null,
      message:
        "agent-origin.json uid mode does not contain a usable confined agent uid",
    };
  }
  const subject = protectionSubjectForUid(fortressId, origin.agent_uid);
  if (subject === null) {
    return {
      status: "invalid_descriptor",
      subject: null,
      message:
        "agent-origin.json names a confined agent uid that cannot be used as a protection subject",
    };
  }
  return {
    status: "resolved",
    subject,
    message: "agent-origin.json resolved a confined agent subject",
  };
}

export async function resolveProtectionSubjectFromFortressPath(
  fortressPath: string,
  fortressId: string,
): Promise<ProtectionSubjectResolution> {
  const filePath = join(fortressPath, "policy", "egress", "agent-origin.json");
  try {
    const raw = await readFileCustody(filePath, {
      encoding: "utf8",
      verifyPathIdentity: true,
    });
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return {
        status: "malformed_json",
        subject: null,
        message:
          "agent-origin.json is present but cannot be parsed, so the agent's confinement identity could not be read",
      };
    }
    return resolveProtectionSubjectFromAgentOrigin(fortressId, parsed);
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") {
      return {
        status: "absent",
        subject: null,
        message:
          "agent-origin.json is absent, so the agent's confinement identity could not be read",
      };
    }
    return {
      status: "unreadable",
      subject: null,
      message:
        "agent-origin.json could not be read with custody verification, so the agent's confinement identity could not be read",
    };
  }
}

export function castleWallEvidenceMatchesProtectionSubject(
  claimSubject: string | null | undefined,
  evidence: { identity_id?: unknown } | null | undefined,
  matchMode: ProtectionSubjectMatchMode = { mode: "exact_subject" },
): ProtectionSubjectMatch {
  const evidenceSubject =
    evidence !== null &&
    evidence !== undefined &&
    typeof evidence.identity_id === "string" &&
    evidence.identity_id.length > 0
      ? evidence.identity_id
      : null;
  if (
    matchMode.mode === "exact_subject" &&
    (claimSubject === null ||
      claimSubject === undefined ||
      claimSubject.length === 0)
  ) {
    return {
      matches: false,
      reason: "subject_unresolvable",
      evidenceSubject,
    };
  }
  if (evidenceSubject === null) {
    return {
      matches: false,
      reason: "missing_evidence_subject",
      evidenceSubject,
    };
  }
  if (isLegacyMacOSAuditTokenHex(evidenceSubject)) {
    return {
      matches: false,
      reason: "legacy_macos_audit_token",
      evidenceSubject,
    };
  }
  if (matchMode.mode === "fortress_scoped") {
    if (matchMode.fortressId.length === 0) {
      return {
        matches: false,
        reason: "subject_unresolvable",
        evidenceSubject,
      };
    }
    if (evidenceSubjectBelongsToFortress(matchMode.fortressId, evidenceSubject)) {
      return { matches: true, reason: "matched" };
    }
    return {
      matches: false,
      reason: "subject_mismatch",
      evidenceSubject,
    };
  }
  if (evidenceSubject === claimSubject) {
    return { matches: true, reason: "matched" };
  }
  return {
    matches: false,
    reason: "subject_mismatch",
    evidenceSubject,
  };
}
