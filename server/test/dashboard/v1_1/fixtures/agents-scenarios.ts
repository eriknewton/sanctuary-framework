import type { LocalAgentRecord } from '../../../../src/contracts/v1.1/local-agent-records.js';
import type { HubActivityFeedEntry, HubApprovalPendingItem } from '../../../../src/contracts/v1.1/hub-events.js';
import type { HubPolicySummary } from '../../../../src/hub/types.js';
import { buildPostureAgentRows, buildAgentReach } from '../../../../src/principal-policy/posture.js';
import type { PostureHome } from '../../../../src/principal-policy/posture-home-types.js';

// The capture and wired-client tests consume the same typed, public-metadata fixtures.
export function agentsScenario(name = 'protected', now = Date.now()) {
  const minute = 60 * 1000;
  const at = (ago: number) => new Date(now - ago).toISOString();
  const agent: LocalAgentRecord = {
    version: '1.1', agent_id: 'research-agent', identity_id: 'fixture-operator', harness: 'claude_code',
    model_provider: { vendor: 'local', model_id: 'fixture-model', runs_locally: true },
    policy_id: 'policy-research', channel_template_id: 'request-approve-act', status: name === 'unknown' ? 'unknown' : 'active',
    budget_summary: { daily: { unit: 'USD', used: 4, cap: 10 }, last_refreshed_at: at(minute) },
    last_activity_at: at(minute), wrapped_at: at(60 * minute),
    capabilities: { can_pause: false, can_resume: false, can_restart: false, can_lockdown: true, can_unwrap: false, can_chat: false, can_change_template: true },
  };
  const agents = name === 'empty' ? [] : [agent];
  const home: Partial<PostureHome> = {
    origin_machine: 'fixture-linux',
    agents: buildPostureAgentRows({ originMachine: 'fixture-linux', records: agents }),
    protection_requested_count: agents.length, enforcement_confirmed_count: 0,
    castle_wall: { origin_machine: 'fixture-linux', arm_state: 'unknown', platform: 'linux', evidence_basis: 'no_evidence',
      last_enforcement_evidence_at: null, freshness_window_ms: 5 * minute,
      verdict_counts: { allowed: 0, blocked: 0, operator_decisions: 0 }, audit_integrity_ok: false,
      sealed_region_unverified_at_privilege: false, producer_authenticity: 'not_applicable' },
    digest: { origin_machine: 'fixture-linux', window_start: at(60 * minute), window_end: at(0), total_operations: 1,
      failures: 1, kernel_blocks: 0, kernel_allows: 0, approvals_granted: 0, approvals_denied: 1, by_agent: [],
      chain_verified: false, chain_verdict: 'findings', integrity_finding_count: 1 },
    unwrapped: { origin_machine: 'fixture-linux', detection_method: 'config_file_presence', unwrapped: [] },
  };
  // This additional capture fixture has scoped, current enforcement evidence; roster intent alone stays unknown.
  if (name === 'evidenced-protected') {
    home.agents = home.agents!.map(row => ({ ...row, enforcement_active: 'active', last_enforcement_evidence_at: at(0), freshness_window_ms: 5 * minute }));
    home.enforcement_confirmed_count = agents.length;
  }
  const approval: HubApprovalPendingItem = {
    version: '1.1', item_id: 'held-agent', identity_id: agent.identity_id, agent_id: agent.agent_id,
    kind: 'approval_pending', tier: 'tier1', operation_category: 'lockdown', created_at: at(minute), resolved: false,
    display_template_id: 'approval_pending.tier1.lockdown', display_template_args: [{ kind: 'agent_id', value: agent.agent_id }],
  };
  const activity: HubActivityFeedEntry[] = agents.map(a => ({
    version: '1.1', entry_id: 'entry-1', agent_id: a.agent_id, identity_id: a.identity_id, category: 'denial', emitted_at: at(minute),
    display_template_id: 'activity.denial.egress_policy_deny', display_template_args: [{ kind: 'agent_id', value: a.agent_id }],
  }));
  const policies: HubPolicySummary[] = [{ policy_id: agent.policy_id, display_label: 'Research policy', bound_at: at(60 * minute), agent_count: agents.length, channel_template_id: 'request-approve-act' }];
  const reach = buildAgentReach({ originMachine: 'fixture-linux', agentId: agent.agent_id, harness: agent.harness,
    rules: name === 'unknown' ? [] : [{ rule_id: 'allow-docs', host: 'docs.example.test', disposition: 'allow', enforcing_layer: 'castle_wall' },
      { rule_id: 'prompt-other', host: '*', disposition: 'prompt', enforcing_layer: 'policy' },
      { rule_id: 'deny-private', host: 'private.example.test', disposition: 'deny', enforcing_layer: 'castle_wall' }] });
  return { name, agents, home, activity, policies, reach, inbox: name === 'pending-tier1' ? [approval] : [], approval };
}
