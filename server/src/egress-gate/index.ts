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
  observePfEnabled,
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
  type DisarmPfAnchorResult,
  type PfEnabledObservation,
  type PfEnableReferenceDisposition,
} from "./pf-anchor.js";

export {
  PF_ANCHOR_REGISTRY_PATH,
  PF_ANCHOR_REGISTRY_LOCK_PATH,
  PF_ANCHOR_REGISTRY_STATE_VERSION,
  PfAnchorRegistry,
  PfAnchorRegistryDirtyError,
  PfAnchorRegistryStateError,
  createFsRegistryStore,
  createFsQuarantineForensicsWriter,
  hasGenerationHeadroom,
  type PfAnchorRegistryEntry,
  type PfAnchorRegistryState,
  type PfAnchorRegistryStore,
  type PfAnchorRegistryOps,
  type PfAnchorRegistryMutationResult,
  type PfAnchorQuarantineRepairFinding,
  type PfAnchorQuarantineRepairResult,
} from "./anchor-registry.js";

export {
  GenerationCoordinator,
  GenerationStateError,
  GENERATION_LOCK_PATH_PREFIX,
  bindEphemeralGatePort,
  computeNextGenerationId,
  createFsGenerationStagingStore,
  evaluateGenerationMatch,
  parseGenerationStagingRecord,
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
  PEER_RESOLVER_PROTOCOL_VERSION,
  PEER_RESOLVER_MAX_FRAME_BYTES,
  encodePeerResolveRequest,
  encodePeerResolveResponse,
  parsePeerResolveRequest,
  parsePeerResolveResponse,
  type PeerResolveRequest,
  type PeerResolveResponse,
  type PeerResolveOkResponse,
  type PeerResolveErrResponse,
} from "./peer-resolver-protocol.js";

export {
  PEER_RESOLVER_DIR,
  PEER_RESOLVER_DAEMON_LABEL_PREFIX,
  PEER_RESOLVER_MAX_CONCURRENT_LOOKUPS,
  PEER_RESOLVER_LOOKUP_TIMEOUT_MS,
  peerResolverSocketPath,
  peerResolverDaemonLabel,
  peerResolverDaemonPlistPath,
  renderPeerResolverDaemonPlist,
  runPeerResolverDaemon,
  type PeerResolverEvent,
  type PeerResolverDaemonDeps,
  type PeerResolverDaemonHandle,
  type PeerResolverDaemonPlistOptions,
} from "./peer-resolver-daemon.js";

export {
  PRIVILEGED_PEER_RUNNER_TIMEOUT_MS,
  createPrivilegedPeerRunner,
  type PrivilegedPeerRunnerOptions,
} from "./peer-resolver-client.js";

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
  GateAccountVerificationError,
  type GateAccountProvisionOptions,
  type GateAccountProvisionOps,
  type GateAccountRecord,
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
  gateCredentialAcceptPath,
  gateCredentialTokenPath,
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
  gateLivenessTokenPath,
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
  setAgentHarnessJobDisabled,
  kickstartAgentHarnessDaemon,
  agentHarnessDaemonStatus,
  agentHarnessDaemonStableRunning,
  type AgentHarnessDaemonPlistOptions,
  type HarnessDaemonOps,
  type HarnessDaemonInstallPlan,
  type HarnessDaemonStatus,
} from "./harness-daemon.js";

export {
  AGENT_HARNESS_HOLD_DIR,
  AGENT_HARNESS_HOLD_DIR_MODE,
  writeIntoHoldDir,
  HOLD_FILE_HEADER,
  RELEASE_WRAPPER_FILENAME,
  RELEASE_WRAPPER_REFUSAL_EXIT_CODE,
  RELEASE_EXEC_WRAPPER_SCRIPT,
  PARKED_EXPECTED_GENERATION,
  ReleaseBarrierError,
  holdFilePathForUid,
  releaseWrapperPath,
  computeHarnessArgvDigest,
  renderHarnessReleaseHoldFile,
  parseHarnessReleaseHoldFile,
  renderReleaseExecWrapperScript,
  buildBarrierProgramArguments,
  planParkedHarnessInstall,
  executeParkedHarnessInstall,
  runReleaseBarrierSequence,
  type HarnessReleaseHoldRecord,
  type HoldDirWriteOps,
  type BarrierProgramArgumentsInput,
  type ParkedHarnessInstallOptions,
  type ParkedHarnessInstallPlan,
  type ParkedInstallOps,
  type ReleaseBarrierStage,
  type ReleaseBarrierContext,
  type CommittedGenerationIdentity,
  type ReleaseBarrierOps,
  type ReleaseBarrierOutcome,
} from "./release-barrier.js";

export {
  buildExclusiveEgressPosture,
  summarizeExclusiveEgressStatus,
  exclusiveEgressCapsAggregateGreen,
  failedExclusiveEgressStatus,
  type ExclusiveEgressMode,
  type ExclusiveEgressPosture,
  type ExclusiveEgressPostureInput,
  type ExclusiveEgressRegistryEntryView,
  type ExclusiveEgressStatus,
  type GateProcessStatus,
} from "./posture.js";

export {
  GENERIC_UID_CONFINEMENT_REMEDY,
} from "./operator-advice.js";

export {
  protectionObservationFromFeatureHealth,
  protectionStateAdvice,
  protectionStateClaimFromObservation,
  reconcileProtectionClaimWithArmOutcome,
  castleWallDaemonStartFailureHeadline,
  type ProtectionClaimState,
  type ProtectionFeatureStatus,
  type ProtectionStateAdvice,
  type ProtectionStateClaim,
  type ProtectionStateObservation,
} from "./protection-claim.js";

// Unified Protect Slice 5 S5-6: gate daemon + drift guard + production wiring.
export {
  EGRESS_GATE_RUNTIME_DIR,
  EGRESS_GATE_DAEMON_LABEL_PREFIX,
  GATE_ORACLE_PUBLIC_KEY_PATH,
  egressGateDaemonLabel,
  egressGateDaemonLogPaths,
  egressGateDaemonPlistPath,
  egressGatePolicyConfigPath,
  egressGateRulesConfigPath,
  egressGateRuntimeStatePath,
  egressGateRuntimeUidDirPath,
  gateDaemonLogDirForHome,
  parseEgressGateRuntimeState,
  renderEgressGateDaemonPlist,
  runEgressGateDaemon,
  type EgressGateDaemonDeps,
  type EgressGateDaemonHandle,
  type EgressGateDaemonPlistOptions,
  type EgressGateRuntimeState,
} from "./gate-daemon.js";
export {
  diffTransientPfRules,
  type DiffTransientPfRulesOptions,
  type TransientPfRulesDiff,
} from "./drift-guard.js";
export {
  SANCTUARY_VAR_DB_DIR,
  applyGateRuntimeFsPlan,
  createRealGateRuntimeFsOps,
  ensureExclusiveEgressRuntimeFs,
  planExclusiveEgressRuntimeFs,
  type GateRuntimeFsOps,
  type GateRuntimeFsPlanInput,
  type GateRuntimeFsStep,
} from "./runtime-fs-plan.js";
export {
  GATE_ORACLE_PRIVATE_KEY_PATH,
  NON_HERMES_BOOT_PARK_REASON,
  bootstrapGateDaemonForBoot,
  createExclusiveEgressPostureProducer,
  createInstallExclusiveEgressOps,
  createProductionAnchorRegistry,
  createProductionOracle,
  createProductionReleaseBarrierOps,
  createRepairExclusiveEgressOps,
  ensureGateAccountHomeLayout,
  GATE_ACCOUNT_HOME_BASE,
  createUnprotectExclusiveEgressOps,
  ensureAgentHarnessHoldDir,
  ensureSupervisorOracleKeys,
  parkHarnessPersistently,
  realHoldDirWriteOps,
  restoreCoarseCompositionProduction,
  startExclusiveEgressBootSupervisor,
  verifyHarnessJobDisabled,
  verifyHarnessParkedPersistent,
  verifyLoopbackTcpPortOwner,
  PID_START_TOLERANCE_MS,
  type BootAgentResolution,
  type BootRegistryEntry,
  type BootRegistryListing,
  type ExclusiveEgressBootSupervisorHandle,
  type ExclusiveEgressBootSupervisorInternals,
  type ExclusiveEgressWiringInput,
  type GateAccountHomeLayoutOps,
  type PersistentParkContext,
  type PersistentParkDeps,
  type PortOwnerVerdict,
  type QuarantinedBootRegistryEntry,
  type UnprotectWiringDeps,
} from "./arming-wiring.js";
