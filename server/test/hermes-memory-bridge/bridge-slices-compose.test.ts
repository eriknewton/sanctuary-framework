import { describe, expect, it } from "vitest";

import * as Bridge from "../../src/hermes-memory-bridge/index.js";
import * as BridgeCore from "../../src/hermes-memory-bridge/bridge-core.js";
import * as Constants from "../../src/hermes-memory-bridge/constants.js";
import * as Envelopes from "../../src/hermes-memory-bridge/envelopes.js";
import * as Framing from "../../src/hermes-memory-bridge/framing.js";
import * as Lifecycle from "../../src/hermes-memory-bridge/connection-lifecycle.js";
import * as ProbeWaiter from "../../src/hermes-memory-bridge/probe-waiter.js";
import * as PublicResults from "../../src/hermes-memory-bridge/public-results.js";
import * as Recall from "../../src/hermes-memory-bridge/recall.js";
import * as StrictJson from "../../src/hermes-memory-bridge/strict-json.js";
import type {
  HermesCallKind,
  HermesCallRecordSnapshot,
  HermesCallRecordState,
  HermesClassifiedPublicFrame,
  HermesConnectionState,
  HermesControlKind,
  HermesFatalReason,
  HermesLifecycleAction,
  HermesLifecycleEvent,
  HermesLifecycleResult,
  HermesMemoryToolArguments,
  HermesMemoryToolName,
  HermesNodeCloseReason,
  HermesProbeEntryRef,
  HermesProbeFatalReason,
  HermesProbeNonceSource,
  HermesProbeStartRefusal,
  HermesProbeTerminalReason,
  HermesProbeWaiterAction,
  HermesProbeWaiterResult,
  HermesProbeWaiterSnapshot,
  HermesProbeWaiterState,
  HermesPublicFrameSummary,
  HermesRefusalReason,
  HermesReleaseResult,
  HermesWireEncodeErrorCode,
  NodeToRelayInput,
  PrivateFrameDecodeResult,
  PrivateFrameErrorCode,
  PublicFrame,
  PublicFrameParseResult,
  RelayToNodeFrame,
  RelayToNodeParseResult,
  StrictJsonErrorCode,
} from "../../src/hermes-memory-bridge/index.js";

type BarrelTypeSurface = [
  HermesCallKind,
  HermesCallRecordSnapshot,
  HermesCallRecordState,
  HermesClassifiedPublicFrame,
  HermesConnectionState,
  HermesControlKind,
  HermesFatalReason,
  HermesLifecycleAction,
  HermesLifecycleEvent,
  HermesLifecycleResult,
  HermesMemoryToolArguments,
  HermesMemoryToolName,
  HermesNodeCloseReason,
  HermesProbeEntryRef,
  HermesProbeFatalReason,
  HermesProbeNonceSource,
  HermesProbeStartRefusal,
  HermesProbeTerminalReason,
  HermesProbeWaiterAction,
  HermesProbeWaiterResult,
  HermesProbeWaiterSnapshot,
  HermesProbeWaiterState,
  HermesPublicFrameSummary,
  HermesRefusalReason,
  HermesReleaseResult,
  HermesWireEncodeErrorCode,
  NodeToRelayInput,
  PrivateFrameDecodeResult,
  PrivateFrameErrorCode,
  PublicFrame,
  PublicFrameParseResult,
  RelayToNodeFrame,
  RelayToNodeParseResult,
  StrictJsonErrorCode,
];

const typeSurfaceCompiles = true satisfies BarrelTypeSurface extends readonly unknown[] ? true : false;

const composedSurfaces = [BridgeCore, Constants, Envelopes, Framing, Lifecycle, ProbeWaiter, PublicResults, Recall, StrictJson] as const;

describe("Hermes memory bridge composition", () => {
  it("publishes the composed module surface", () => {
    expect(typeSurfaceCompiles).toBe(true);

    for (const surface of composedSurfaces) {
      expect(Object.keys(surface).length).toBeGreaterThan(0);
      for (const [name, value] of Object.entries(surface)) {
        expect(Bridge[name as keyof typeof Bridge]).toBe(value);
      }
    }
  });

  it("shares bridge constants through the barrel", () => {
    expect(Bridge.HERMES_MEMORY_DENIAL).toBe(Constants.HERMES_MEMORY_DENIAL);
    expect(Bridge.HERMES_MEMORY_DENIAL_MESSAGE).toBe(Constants.HERMES_MEMORY_DENIAL);
    expect(Lifecycle.HERMES_MEMORY_DENIAL_MESSAGE).toBe(Constants.HERMES_MEMORY_DENIAL);
    expect(Bridge.HERMES_MAX_PUBLIC_CONNECTIONS).toBe(Constants.HERMES_MAX_PUBLIC_CONNECTIONS);
    expect(Bridge.HERMES_SETTLING_RESERVE).toBe(Constants.HERMES_SETTLING_RESERVE);
    expect(Bridge.HERMES_MAX_CALL_RECORDS).toBe(Constants.HERMES_MAX_CALL_RECORDS);
  });
});
