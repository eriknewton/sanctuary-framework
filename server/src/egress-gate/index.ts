/**
 * egress-gate: the exclusive-egress enforcement core (Unified Protect
 * Slices 1-4 + 8; drill acceptance PENDING on every slice).
 *
 * The agent's only path off the box is the local policy gate: off-box
 * egress is denied at the kernel (Castle Wall per-uid floor, proven),
 * loopback reach is confined to the gate port by a per-uid pf anchor
 * (mechanism proven on Tahoe 2026-07-02; composed build pending drill), and
 * the gate applies per-destination policy in userspace before egressing as
 * a non-agent uid.
 *
 * Distinct from `proxy/` (the MCP-tool proxy), from
 * `castle-wall/egress-proxy.ts` (the VM/vsock CONNECT evaluator, whose
 * decision logic this module REUSES), and from
 * `policy-engine/egress-gate.ts` (the EXACT-NAME confusable: the
 * compiled-policy per-agent egress allowlist gate inside the policy
 * engine). The manifest-side rule derivation
 * lives in `castle-wall/allowlist/gate-derivation.ts` (single source with
 * the pf anchor here; see `parity.ts`).
 */

export {
  PF_ANCHOR_NAME,
  PF_BASE_CONF_PATH,
  PF_COMMAND_TIMEOUT_MS,
  createExecFilePfRunner,
  renderPfAnchorRules,
  renderPfAnchorRulesForUids,
  renderPfMainRulesetHook,
  checkPfAnchorLiveness,
  checkPfAnchorUnionLiveness,
  findPreemptingQuickPassRules,
  findLoopbackSkipLines,
  armPfAnchor,
  armPfAnchorUnion,
  disarmPfAnchor,
  type PfCommandRunner,
  type PfCommandResult,
  type PfLivenessResult,
  type PfAnchorUnionEntry,
  type ArmPfAnchorOptions,
  type ArmPfAnchorUnionOptions,
  type ArmPfAnchorResult,
  type DisarmPfAnchorOptions,
} from "./pf-anchor.js";

export {
  PF_ANCHOR_REGISTRY_PATH,
  PF_ANCHOR_REGISTRY_LOCK_PATH,
  PF_ANCHOR_REGISTRY_STATE_VERSION,
  PfAnchorRegistry,
  PfAnchorRegistryDirtyError,
  PfAnchorRegistryStateError,
  createFsRegistryStore,
  type PfAnchorRegistryEntry,
  type PfAnchorRegistryState,
  type PfAnchorRegistryStore,
  type PfAnchorRegistryOps,
  type PfAnchorRegistryMutationResult,
} from "./anchor-registry.js";

export {
  GenerationCoordinator,
  GenerationStateError,
  GENERATION_LOCK_PATH_PREFIX,
  bindEphemeralGatePort,
  computeNextGenerationId,
  createFsGenerationStagingStore,
  evaluateGenerationMatch,
  resolveCommittedGeneration,
  resolveGateRestart,
  type GenerationPhase,
  type GateBinding,
  type GenerationBringUpRequest,
  type CommittedGeneration,
  type GenerationStagingRecord,
  type GenerationStagingStore,
  type GenerationRegistryOps,
  type GenerationOps,
  type GenerationRecoveryOutcome,
  type GenerationMatchInput,
  type GateRestartOutcome,
} from "./generation.js";

export {
  checkGatePolicyParity,
  assertGatePolicyParity,
  GatePolicyParityError,
  type GatePolicyParityInput,
} from "./parity.js";

export {
  PEER_LOOKUP_TIMEOUT_MS,
  createExecFilePeerRunner,
  parseLsofPeer,
  resolveLoopbackPeer,
  type LoopbackPeerIdentity,
  type PeerCommandRunner,
  type ResolveLoopbackPeerOptions,
} from "./peer-identity.js";

export {
  GATE_BIND_HOST,
  PEER_LOOKUP_MAX_CONCURRENT,
  createExclusiveEgressGate,
  startExclusiveEgressGate,
  type GateLivenessProbe,
  type EgressGateEvent,
  type ExclusiveEgressGateOptions,
  type ExclusiveEgressGateHandle,
} from "./gate-server.js";

export {
  GATE_ACCOUNT_NAME_PREFIX,
  deriveGateAccountName,
  gateAccountProvisionOptions,
  planGateAccountProvision,
  planAndCreateGateAccount,
  GateUidCollisionError,
  type GateAccountProvisionOptions,
} from "./gate-account.js";

export {
  GATE_CRED_DIR,
  GATE_AUTH_SCHEME,
  GATE_CREDENTIAL_VERSION,
  GATE_CREDENTIAL_SECRET_BYTES,
  GateCredentialAuthority,
  formatGateCredentialHeader,
  parseGateCredentialHeader,
  verifyGateCredential,
  mintGateSecret,
  createFsGateCredentialAuthority,
  createFsGateAcceptSource,
  type GateCredentialToken,
  type GateCredentialAcceptRecord,
  type PresentedGateCredential,
  type GateCredentialDenyReason,
  type GateCredentialVerdict,
  type GateCredentialAuthorityOps,
  type GateAcceptSource,
} from "./gate-credential.js";

export {
  decideGateClientAuth,
  createGateClientAuthenticator,
  type GatePeerResolution,
  type GateClientDenyReason,
  type GateClientAuthDecision,
  type GateClientAuthenticator,
} from "./gate-client-auth.js";

export {
  GATE_LIVENESS_DIR,
  GATE_LIVENESS_TOKEN_VERSION,
  GATE_LIVENESS_DEFAULT_TTL_MS,
  canonicalLivenessPayload,
  GateLivenessOracle,
  verifyLivenessToken,
  createOracleLivenessProbe,
  createFsLivenessOracleOps,
  createFsLivenessTokenSource,
  type LivenessTokenClaims,
  type SignedLivenessToken,
  type LivenessOracleOps,
  type LivenessTokenSource,
  type LivenessProbeBinding,
} from "./liveness-oracle.js";

export {
  AGENT_HARNESS_DAEMON_LABEL,
  AGENT_HARNESS_DAEMON_PLIST_PATH,
  HARNESS_FORBIDDEN_PLIST_ENV,
  renderAgentHarnessDaemonPlist,
  planAgentHarnessDaemonInstall,
  installAgentHarnessDaemon,
  uninstallAgentHarnessDaemon,
  agentHarnessDaemonStatus,
  type AgentHarnessDaemonPlistOptions,
  type HarnessDaemonOps,
  type HarnessDaemonInstallPlan,
  type HarnessDaemonStatus,
} from "./harness-daemon.js";
