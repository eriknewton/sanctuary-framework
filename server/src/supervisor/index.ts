/**
 * Phase S1 — Split-process supervised-daemon subsystem (public surface).
 *
 * Make "Protect this agent" actually launch + supervise a wrapped agent, in a
 * SEPARATE process from the dashboard's HTTP surface, holding only a transient
 * key over an authenticated local socket (Tier A custody — the operator
 * unlocks once; survives agent crashes via restart; re-unlock required after a
 * host reboot). Tier A+ (keychain-at-login) and Tier B (headless/unattended)
 * are deferred behind their own Erik sign-off.
 */

export {
  SUPERVISOR_PROTOCOL_VERSION,
  MAX_FRAME_BYTES,
  FRAME_HEADER_BYTES,
  SUPERVISOR_KNOWN_HARNESSES,
  mintAuthSecret,
  encodeFrame,
  FrameDecoder,
  parseRequest,
  type SupervisorRequest,
  type SupervisorResponse,
  type SupervisorErrorReason,
  type SupervisedAgentState,
  type SupervisedAgentStatus,
  type ProtectRequest,
  type DecodeOutcome,
} from "./protocol.js";

export {
  Supervisor,
  DEFAULT_RESTART_POLICY,
  DEFAULT_ENFORCEMENT_FRESHNESS_MS,
  DEFAULT_LAUNCH_TIMEOUT_MS,
  type SupervisorDeps,
  type SupervisionSpec,
  type AgentLauncher,
  type LaunchedChild,
  type RestartPolicy,
  type ProtectResult,
} from "./supervisor.js";

export { SupervisorSocketServer, type SocketServerDeps } from "./socket-server.js";
export { sendSupervisorRequest, type SocketClientOptions } from "./socket-client.js";
export { SupervisorBridge, mapSupervisorResponse, type SupervisorBridgeDeps } from "./dashboard-bridge.js";
export { makeSupervisorHandler, type RequestHandlerDeps } from "./request-handler.js";
export {
  SpawnAgentLauncher,
  SpawnedChild,
  readSupervisorTransientKey,
  SupervisorKeyHandoffError,
  SUPERVISOR_KEY_FD_ENV,
  type SpawnLauncherOptions,
} from "./spawn-launcher.js";
export { isRotationInProgress } from "./rotation-guard.js";
