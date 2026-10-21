import { buildFleetRoster } from '../../../../src/principal-policy/fleet-roster.js';
import type { FederationContext, FederationNodeView, V1FederationDeps } from '../../../../src/v1/federation.js';
import { renderPolicyPlainEnglish } from '../../../../src/policy-engine/policy-plain-english.js';
import { DEFAULT_POLICY } from '../../../../src/principal-policy/loader.js';
import type { SentinelFinding } from '../../../../src/sentinel/types.js';
import { agentsScenario } from './agents-scenarios.js';

// Shared with the lane capture: public metadata from the production presenters.
export function mfpScenario(name = 'populated', now = Date.now()) {
  const minute = 60 * 1000;
  const at = (ago: number) => new Date(now - ago).toISOString();
  const node: FederationNodeView = {
    node_id: 'build-box', label: 'Build box', attestation_status: 'verified', node_mode: 'local', host_provider: null,
    trust_boundary: { version: 'operator-cloud-trust-boundary-v1', posture: 'local_operator_host', label: 'Local host', provider_in_trust_boundary: false, tee_attested: false, disclosure: null },
    tee_attested: false, disclosure_acknowledged_at: null, drill_status: 'not_applicable',
    first_seen: at(60 * minute), last_seen: at(minute),
    last_sync: { received_at: at(minute), sent_at: at(minute), last_sequence: 1 },
    applied_policy: { version: null, hash: null, hash_algorithm: null, applied_at: null, source_event_id: null },
  };
  // Only the four read methods are consumed by this presenter; all other access fails.
  const reads = { getContext: () => ({ fortressId: 'fixture-linux', nodeId: node.node_id } as FederationContext),
    isEnabled: () => true, listNodes: () => name === 'empty' ? [] : [node], isNodeRevoked: () => false };
  const deps = new Proxy(reads, { get(target, prop) {
    if (prop in target) return target[prop as keyof typeof target];
    throw new Error('Fixture permits roster reads only');
  } }) as unknown as V1FederationDeps;
  const roster = buildFleetRoster(deps, { now: () => now });
  const findings: SentinelFinding[] = name === 'empty' ? [] : (['info', 'alert', 'warn'] as const).map((severity, i) => ({
    finding_id: 'finding-' + severity, sentinel_id: 'egress-volume', severity,
    agent_id: 'research-agent', summary: severity + ' outbound observation',
    observed_at: at((i + 1) * minute), fortress_id: 'fixture-linux',
    details: { observed: 12, baseline_mean: 3, window: 'one minute' }, evidence_audit_ids: [at(minute) + ':egress_blocked'],
  }));
  const policy = renderPolicyPlainEnglish({ ...DEFAULT_POLICY, version: 7, tier1_always_approve: ['state_export'], tier3_always_allow: ['state_read'] });
  if (name === 'empty') policy.lines = [];
  return { ...agentsScenario(name === 'empty' ? 'empty' : 'protected', now), roster, findings, policy };
}
