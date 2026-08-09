/**
 * Per-agent network stop for Castle Wall confined agents.
 *
 * This is the first dashboard-originated enforcement mutation. The dashboard
 * still writes only operator-owned rule files; the root daemon remains the
 * signer and system-extension publisher.
 */

import { createHash } from "node:crypto";
import {
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";

import {
  egressRulesDir,
  restoreProvisionedEgressRules,
  scrubProvisionedEgressRules,
  snapshotProvisionedEgressRules,
  type PolicyReloadTrigger,
  type ProvisionedEgressRuleFile,
} from "./egress.js";
import { egressPolicyWriterLock } from "./lockfile.js";
import { loadExclusiveRoutingMarker } from "../allowlist/routing-marker.js";
import { validateAgentOrigin } from "../allowlist/agent-origin.js";
import { isAgentMatchableAllowRuleFile } from "../allowlist/agent-matchable.js";
import { resolveCastleWallSocketPath } from "../runtime/socket-path.js";
import {
  queryMacOSEnforcementAvailability,
  type ResolvedEnforcementAvailability,
} from "../runtime/enforcement-availability.js";
import { requestPolicyReload } from "../runtime/policy-reload-client.js";
import { protectionSubjectForUid } from "../subject-binding.js";

export const AGENT_STOP_REASON_CODES = [
  "stop_unsupported_platform",
  "stop_agent_not_confined",
  "stop_uid_binding_mismatch",
  "stop_enforcement_not_verified",
  "stop_policy_writer_busy",
  "stop_residual_allow_rules",
  "stop_reload_unconfirmed",
] as const;

export type AgentStopReasonCode = (typeof AGENT_STOP_REASON_CODES)[number];

export class AgentEgressStopError extends Error {
  readonly reasonCode: AgentStopReasonCode;

  constructor(reasonCode: AgentStopReasonCode, message?: string) {
    super(message ?? reasonCode);
    this.reasonCode = reasonCode;
    this.name = "AgentEgressStopError";
  }
}

export interface StopAgentEgressObservation {
  outcome: "engaged" | "partial";
  agent_uid: number;
  revoked_rule_ids: string[];
  residual_allow_count: number;
  reload_confirmed: boolean;
  snapshot_path: string;
  reason_code?: AgentStopReasonCode;
}

export interface LiftAgentEgressStopObservation {
  restored_rule_ids: string[];
  removed_rule_ids: string[];
  reload_confirmed: boolean;
  snapshot_path: string;
}

export interface StopAgentEgressInput {
  agentId: string;
  protectionSubject?: string;
  fortressId: string;
  fortressPath: string;
  storagePath: string;
  platform?: NodeJS.Platform;
  now?: () => Date;
  queryEnforcement?: (
    socketPath: string,
  ) => Promise<ResolvedEnforcementAvailability>;
  reloadPolicy?: PolicyReloadTrigger;
  afterScrub?: () => Promise<void>;
}

export interface LiftAgentEgressStopInput {
  agentId: string;
  fortressPath: string;
  storagePath: string;
  reloadPolicy?: PolicyReloadTrigger;
}

function stopSnapshotPath(storagePath: string, agentId: string): string {
  const digest = createHash("sha256").update(agentId).digest("hex").slice(0, 24);
  return join(storagePath, "state", "_hub", "stop-snapshots", `${digest}.json`);
}

function agentMatchableSelector(fortressPath: string) {
  const rulesDir = egressRulesDir(fortressPath);
  return (filename: string): Promise<boolean> =>
    isAgentMatchableAllowRuleFile(join(rulesDir, filename));
}

async function readAgentOriginUid(fortressPath: string): Promise<number> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      await readFile(
        join(fortressPath, "policy", "egress", "agent-origin.json"),
        "utf8",
      ),
    );
  } catch {
    throw new AgentEgressStopError("stop_agent_not_confined");
  }
  const origin = validateAgentOrigin(parsed);
  if (origin === null || origin.mode !== "uid") {
    throw new AgentEgressStopError("stop_agent_not_confined");
  }
  const agentUid = origin.agent_uid;
  if (typeof agentUid !== "number" || !Number.isInteger(agentUid)) {
    throw new AgentEgressStopError("stop_agent_not_confined");
  }
  return agentUid;
}

async function resolveConfinedUid(input: StopAgentEgressInput): Promise<number> {
  let marker;
  try {
    marker = await loadExclusiveRoutingMarker(input.fortressPath);
  } catch {
    throw new AgentEgressStopError("stop_agent_not_confined");
  }
  if (marker === null || marker.agent_id !== input.agentId) {
    throw new AgentEgressStopError("stop_agent_not_confined");
  }
  const agentOriginUid = await readAgentOriginUid(input.fortressPath);
  if (agentOriginUid !== marker.agent_uid) {
    throw new AgentEgressStopError("stop_uid_binding_mismatch");
  }
  const expectedSubject = protectionSubjectForUid(input.fortressId, marker.agent_uid);
  if (
    expectedSubject === null ||
    input.protectionSubject === undefined ||
    input.protectionSubject !== expectedSubject
  ) {
    throw new AgentEgressStopError("stop_uid_binding_mismatch");
  }
  return marker.agent_uid;
}

async function writeStopSnapshot(
  path: string,
  input: {
    agentId: string;
    agentUid: number;
    capturedAt: string;
    files: readonly ProvisionedEgressRuleFile[];
  },
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp-${process.pid}`;
  await writeFile(
    tmp,
    JSON.stringify(
      {
        version: 1,
        agent_id: input.agentId,
        agent_uid: input.agentUid,
        captured_at: input.capturedAt,
        files: input.files,
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  await rename(tmp, path);
}

async function readStopSnapshot(
  path: string,
): Promise<ReadonlyArray<ProvisionedEgressRuleFile>> {
  const parsed = JSON.parse(await readFile(path, "utf8")) as {
    files?: unknown;
  };
  if (!Array.isArray(parsed.files)) {
    throw new AgentEgressStopError("stop_agent_not_confined");
  }
  return parsed.files as ProvisionedEgressRuleFile[];
}

async function defaultReloadPolicy(
  fortressPath: string,
): Promise<{ ok: boolean; error?: string }> {
  return requestPolicyReload(fortressPath, "darwin");
}

async function verifyGreenEnforcement(input: StopAgentEgressInput): Promise<void> {
  const socketPath = resolveCastleWallSocketPath({
    platform: "darwin",
    fortressPath: input.fortressPath,
  }).path;
  const query = input.queryEnforcement ?? queryMacOSEnforcementAvailability;
  let resolved: ResolvedEnforcementAvailability;
  try {
    resolved = await query(socketPath);
  } catch (err) {
    throw new AgentEgressStopError(
      "stop_enforcement_not_verified",
      err instanceof Error ? err.message : String(err),
    );
  }
  // A stop reported without a verified-green enforcement probe would claim an
  // effect the kernel never applied.
  if (resolved.status !== "live") {
    throw new AgentEgressStopError(
      "stop_enforcement_not_verified",
      resolved.reason,
    );
  }
}

export async function stopAgentEgress(
  input: StopAgentEgressInput,
): Promise<StopAgentEgressObservation> {
  const platform = input.platform ?? process.platform;
  if (platform !== "darwin") {
    throw new AgentEgressStopError("stop_unsupported_platform");
  }
  const agentUid = await resolveConfinedUid(input);
  await verifyGreenEnforcement(input);

  let holderDescription = "";
  const lock = egressPolicyWriterLock(input.fortressPath, (holder) => {
    holderDescription = holder;
  });
  const release = await lock.acquire();
  if (release === null) {
    throw new AgentEgressStopError(
      "stop_policy_writer_busy",
      holderDescription,
    );
  }

  const select = agentMatchableSelector(input.fortressPath);
  const snapshotPath = stopSnapshotPath(input.storagePath, input.agentId);
  try {
    const snapshot = await snapshotProvisionedEgressRules(
      input.fortressPath,
      input.agentId,
      select,
    );
    await writeStopSnapshot(snapshotPath, {
      agentId: input.agentId,
      agentUid,
      capturedAt: (input.now ?? (() => new Date()))().toISOString(),
      files: snapshot,
    });
    const scrubbed = await scrubProvisionedEgressRules({
      fortressPath: input.fortressPath,
      harnessId: input.agentId,
      select,
      lockAlreadyHeld: true,
    });
    if (input.afterScrub !== undefined) await input.afterScrub();
    const residual = await snapshotProvisionedEgressRules(
      input.fortressPath,
      input.agentId,
      select,
    );
    // The stop is a stop only if nothing the agent could match survives.
    if (residual.length !== 0) {
      await restoreProvisionedEgressRules({
        fortressPath: input.fortressPath,
        harnessId: input.agentId,
        snapshot,
        select,
        lockAlreadyHeld: true,
      });
      throw new AgentEgressStopError("stop_residual_allow_rules");
    }
    const reload = await (input.reloadPolicy ?? (() => defaultReloadPolicy(input.fortressPath)))();
    // An unconfirmed reload means the running filter is still serving the
    // prior composition, so this is partial, not success.
    if (!reload.ok) {
      return {
        outcome: "partial",
        agent_uid: agentUid,
        revoked_rule_ids: scrubbed.removedRuleIds,
        residual_allow_count: 0,
        reload_confirmed: false,
        snapshot_path: snapshotPath,
        reason_code: "stop_reload_unconfirmed",
      };
    }
    return {
      outcome: "engaged",
      agent_uid: agentUid,
      revoked_rule_ids: scrubbed.removedRuleIds,
      residual_allow_count: 0,
      reload_confirmed: true,
      snapshot_path: snapshotPath,
    };
  } finally {
    await release();
  }
}

export async function liftAgentEgressStop(
  input: LiftAgentEgressStopInput,
): Promise<LiftAgentEgressStopObservation> {
  const select = agentMatchableSelector(input.fortressPath);
  const snapshotPath = stopSnapshotPath(input.storagePath, input.agentId);
  const snapshot = await readStopSnapshot(snapshotPath);
  const result = await restoreProvisionedEgressRules({
    fortressPath: input.fortressPath,
    harnessId: input.agentId,
    snapshot,
    select,
    reloadPolicy: input.reloadPolicy ?? (() => defaultReloadPolicy(input.fortressPath)),
  });
  if (!result.restored) {
    throw new AgentEgressStopError(
      "stop_residual_allow_rules",
      result.problems.join("; "),
    );
  }
  if (result.reloadOk) {
    await rm(snapshotPath, { force: true });
  }
  return {
    restored_rule_ids: result.restoredRuleIds,
    removed_rule_ids: result.removedRuleIds,
    reload_confirmed: result.reloadOk,
    snapshot_path: snapshotPath,
  };
}
