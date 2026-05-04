/**
 * Installer pure-logic core: produces the install plan + audit-event shape
 * the installer should emit, given a firewall-detection result and an
 * operator selection of curated allowlist entries.
 *
 * PR 2a does not run the actual install (no privileged syscalls, no systemd
 * unit copy). It produces the plan; PR 2b's installer binary executes it.
 * Splitting it this way means PR 2a tests the decision shape on macOS
 * without root or systemd.
 */

import { CURATED_ALLOWLIST, type CuratedAllowlistEntry } from "./curated-allowlist.js";
import {
  CASTLE_TABLE_NAME,
  type FirewallNamespaceRecommendation,
} from "./detect-firewall.js";

/** A single curated entry the operator chose to enable. */
export interface CuratedSelection {
  rule_id: string;
}

/** A planned step the installer will execute. */
export interface InstallStep {
  kind:
    | "create_sanctuary_group"
    | "create_runtime_dir"
    | "create_state_dir"
    | "place_systemd_unit"
    | "enable_systemd_unit"
    | "place_pinned_public_key"
    | "publish_initial_manifest";
  description: string;
  destination: string;
  side_effects:
    | "filesystem_write"
    | "systemd_call"
    | "user_group_create";
}

/** The full install plan returned by `planInstall`. */
export interface InstallPlan {
  steps: ReadonlyArray<InstallStep>;
  curated_rules_enabled: ReadonlyArray<string>;
  curated_rules_skipped: ReadonlyArray<string>;
  firewall: FirewallNamespaceRecommendation;
  systemd_unit_path: string;
  runtime_dir: string;
  state_dir: string;
  socket_path: string;
}

/** Inputs for the planner. */
export interface PlanInstallInput {
  fortress_id: string;
  firewall: FirewallNamespaceRecommendation;
  curated_selections: ReadonlyArray<CuratedSelection>;
  /** Optional override for the libexec path (tests). */
  libexec_dir?: string;
}

/** Build the install plan. Pure: no I/O, no syscalls. */
export function planInstall(input: PlanInstallInput): InstallPlan {
  const knownIds = new Set(CURATED_ALLOWLIST.map((e) => e.rule_id));
  const enabled: string[] = [];
  const skipped: string[] = [];
  for (const sel of input.curated_selections) {
    if (knownIds.has(sel.rule_id)) {
      enabled.push(sel.rule_id);
    } else {
      skipped.push(sel.rule_id);
    }
  }

  const runtimeDir = `/run/sanctuary/${input.fortress_id}`;
  const stateDir = `/var/lib/sanctuary/${input.fortress_id}`;
  const libexec = input.libexec_dir ?? "/usr/local/libexec/sanctuary";
  const systemdUnitPath = "/etc/systemd/system/sanctuary-castle-wall.service";
  const daemonBinary = `${libexec}/castle-wall-daemon`;

  const steps: InstallStep[] = [
    {
      kind: "create_sanctuary_group",
      description: "Create the sanctuary group and add the operator user to it.",
      destination: "sanctuary",
      side_effects: "user_group_create",
    },
    {
      kind: "create_runtime_dir",
      description: `Create runtime dir for the UDS at ${runtimeDir} (mode 0750, root:sanctuary).`,
      destination: runtimeDir,
      side_effects: "filesystem_write",
    },
    {
      kind: "create_state_dir",
      description: `Create state dir at ${stateDir} (mode 0750, root:sanctuary).`,
      destination: stateDir,
      side_effects: "filesystem_write",
    },
    {
      kind: "place_systemd_unit",
      description: `Place systemd unit at ${systemdUnitPath} (daemon binary: ${daemonBinary}).`,
      destination: systemdUnitPath,
      side_effects: "filesystem_write",
    },
    {
      kind: "place_pinned_public_key",
      description: `Place TOFU-pinned fortress public key at ${stateDir}/policy/egress/pinned.key.`,
      destination: `${stateDir}/policy/egress/pinned.key`,
      side_effects: "filesystem_write",
    },
    {
      kind: "publish_initial_manifest",
      description: `Publish the initial signed manifest with ${enabled.length} curated rule(s) enabled.`,
      destination: `${stateDir}/policy/egress/manifest.json`,
      side_effects: "filesystem_write",
    },
    {
      kind: "enable_systemd_unit",
      description: "Enable + start sanctuary-castle-wall.service.",
      destination: "sanctuary-castle-wall.service",
      side_effects: "systemd_call",
    },
  ];

  return {
    steps,
    curated_rules_enabled: enabled,
    curated_rules_skipped: skipped,
    firewall: input.firewall,
    systemd_unit_path: systemdUnitPath,
    runtime_dir: runtimeDir,
    state_dir: stateDir,
    socket_path: `${runtimeDir}/filter.sock`,
  };
}

/** Render the install plan as the audit-event details payload. */
export function planAsAuditDetails(
  plan: InstallPlan
): Record<string, unknown> {
  return {
    castle_table_name: CASTLE_TABLE_NAME,
    firewall_conflict_class: plan.firewall.conflictClass,
    firewall_note: plan.firewall.note,
    runtime_dir: plan.runtime_dir,
    state_dir: plan.state_dir,
    systemd_unit_path: plan.systemd_unit_path,
    curated_rules_enabled: [...plan.curated_rules_enabled],
    curated_rules_skipped: [...plan.curated_rules_skipped],
    step_count: plan.steps.length,
  };
}

/** Look up curated entries by id; helper for the install UI. */
export function describeCurated(
  ruleIds: ReadonlyArray<string>
): ReadonlyArray<CuratedAllowlistEntry> {
  const idSet = new Set(ruleIds);
  return CURATED_ALLOWLIST.filter((e) => idSet.has(e.rule_id));
}
