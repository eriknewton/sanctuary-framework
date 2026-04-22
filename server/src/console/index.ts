/**
 * Sanctuary Operator Console v1.0 — Public surface.
 *
 * The single operator-facing artifact that speaks the federation protocol
 * (v0.1) to every node in an operator's fortress mesh. Browser + thin
 * Electron desktop shell at v1.0; native mobile reserved for v1.x.
 *
 * Spec: Review/Sanctuary/WP_MVP_2_Operator_Console_Spawn_Prompt_2026-04-21.md
 */

export { MeshConsoleClient, sanityCheckReservations } from "./client.js";
export type { MeshConsoleClientParams } from "./client.js";
export {
  handleConsoleRequest,
  type ConsoleAPIDeps,
} from "./api.js";
export {
  startConsoleServer,
  type ConsoleServerHandle,
  type ConsoleServerOptions,
} from "./server.js";
export { renderConsoleHTML, renderConsoleHTMLBytes } from "./html.js";
export {
  badgeClassName,
  custodyProvenanceStub,
  globalBadge,
  perActionBadge,
  perAgentBadge,
  renderBadge,
  rollupGlobal,
} from "./attestation-badge.js";
export {
  CONSOLE_SURFACES,
  CONSOLE_VERSION,
  FEDERATION_NODE_JOIN_OPERATION,
  RESERVED_V1X_SURFACES,
  RESERVED_V1X_SURFACE_LABELS,
  SURFACE_LABELS,
  isReservedMeshSurface,
  type ConsoleSurface,
  type ReservedV1xSurface,
} from "./constants.js";
export {
  MeshConsoleError,
  MeshConsoleJoinDecisionError,
  MeshConsoleReservedSurfaceError,
  MeshConsoleUnknownEventTypeError,
} from "./errors.js";
export type {
  AgentPanelEntryView,
  AgentsPanelView,
  AlertAckInput,
  AlertInboxRow,
  AlertInboxView,
  AttestationBadgeView,
  AttestationState,
  ConsoleSSEEvent,
  FortressOverviewView,
  JoinDecisionInput,
  MeshConsoleClientState,
  PendingJoinView,
  PinnedPolicyView,
  PolicyComposeInput,
  PolicyComposeResult,
  RecoveryEntryView,
  RevokeInput,
  RevokeTargetView,
} from "./types.js";
