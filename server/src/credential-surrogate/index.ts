/**
 * Credential surrogacy: the pure, process-free core.
 *
 * WHAT LIVES HERE: the placeholder grammar and its single mint, the binding
 * shape and the element-level validators every stage shares, the two one-shot
 * wire codecs, and the event redaction function. No sockets, no launchd, no
 * keychain, no filesystem.
 *
 * WHY IT IS ITS OWN MODULE: three processes at three privilege levels read the
 * same grammar (the root helper daemon, root arming, the operator CLI and the
 * broker, and in slice 1b the gate uid). One shared parse function per structure
 * is AGENTS.md rule 11; a second copy of the placeholder regex or the destination
 * rule in any of those would be a way for two stages to disagree about which
 * destination a credential may be written to.
 *
 * WHERE THE PROCESSES LIVE INSTEAD: `egress-gate/` owns the helper daemon, both
 * sockets and every launchd surface; `disclosure/broker/` owns the keychain label
 * and both policy files.
 */

export {
  MAX_PLACEHOLDERS_PER_REQUEST,
  MAX_SURROGATE_BINDINGS_PER_AGENT,
  MAX_SURROGATE_BINDINGS_PER_HOST,
  MAX_SURROGATE_DESTINATIONS_PER_BINDING,
  MAX_SURROGATE_ECHO_SCAN_BYTES,
  MAX_SURROGATE_UNLOCK_SECONDS,
  MAX_SURROGATE_VALUE_BYTES,
  SURROGATE_HELPER_MAX_CONCURRENT_QUERIES,
  SURROGATE_QUERY_TIMEOUT_MS,
  SURROGATE_WIRE_ENVELOPE_BYTES,
  SURROGATE_WIRE_MAX_FRAME_BYTES,
} from "./constants.js";

export {
  SURROGATE_PLACEHOLDER_HEX_LENGTH,
  SURROGATE_PLACEHOLDER_LENGTH,
  SURROGATE_PLACEHOLDER_PREFIX,
  SURROGATE_PLACEHOLDER_RANDOM_BYTES,
  SURROGATE_PLACEHOLDER_RE,
  isSurrogatePlaceholder,
  mintSurrogatePlaceholder,
  surrogatePlaceholderScanRe,
} from "./placeholder.js";

export {
  MAX_SURROGATE_HEADER_NAME_LENGTH,
  MAX_SURROGATE_HOST_LENGTH,
  SURROGATE_BOUND_PORT,
  SURROGATE_RESERVED_ENV_NAMES,
  isLegalHttpFieldValue,
  validateSurrogateAgentId,
  validateSurrogateEnvName,
  validateSurrogateHeaderName,
  validateSurrogateHost,
  validateSurrogatePort,
  validateSurrogateSecretName,
  type MintedSurrogateBinding,
  type SurrogateBinding,
  type SurrogateDestination,
  type SurrogateValidationReason,
} from "./binding.js";

export {
  SURROGATE_ARTIFACT_VERSION,
  SURROGATE_BINDINGS_FILE_KIND,
  SURROGATE_DESTINATIONS_FILE_KIND,
  SURROGATE_PLACEHOLDER_FILE_KIND,
  SURROGATE_PLACEHOLDER_LINE_RE,
  SurrogateArtifactError,
  parseSurrogateBindingsFile,
  parseSurrogateDestinationsFile,
  parseSurrogatePlaceholderFile,
  readSurrogateArtifactGeneration,
  renderSurrogateBindingsFile,
  renderSurrogateDestinationsFile,
  renderSurrogatePlaceholderFile,
  type SurrogateArtifactRefusal,
} from "./artifacts.js";

export {
  SURROGATE_CORRELATION_ID_BYTES,
  SURROGATE_WIRE_VERSION,
  decodeSurrogateFrameRecord,
  encodeSurrogateFrame,
  hasExactKeys,
  isSurrogateCorrelationId,
  newSurrogateCorrelationId,
} from "./wire.js";

export {
  SURROGATE_TARGET_LOCATION,
  encodeSurrogateQueryRequest,
  encodeSurrogateQueryResponse,
  isSurrogateDenyReason,
  isSurrogateQueryLocation,
  parseSurrogateQueryRequest,
  parseSurrogateQueryResponse,
  surrogateHeaderLocation,
  type SurrogateDenyReason,
  type SurrogateQueryDenyResponse,
  type SurrogateQueryLocation,
  type SurrogateQueryRequest,
  type SurrogateQueryResponse,
  type SurrogateQuerySwapResponse,
} from "./query-codec.js";

export {
  encodeSurrogateUnlockSocketRequest,
  encodeSurrogateUnlockSocketResponse,
  isSurrogateUnlockDenyReason,
  parseSurrogateUnlockSocketRequest,
  parseSurrogateUnlockSocketResponse,
  type SurrogateLockRequest,
  type SurrogateOkResponse,
  type SurrogateStatusBinding,
  type SurrogateStatusRequest,
  type SurrogateStatusResponse,
  type SurrogateUnlockDenyReason,
  type SurrogateUnlockDenyResponse,
  type SurrogateUnlockRequest,
  type SurrogateUnlockSocketRequest,
  type SurrogateUnlockSocketResponse,
} from "./unlock-codec.js";

export {
  SURROGATE_PLACEHOLDER_REDACTION,
  redactSurrogatePlaceholders,
  redactSurrogatePlaceholdersInString,
} from "./redaction.js";
