/**
 * Dashboard-fold PR-1 — the ONE AggregatorSources construction site.
 *
 * `composeAggregatorSources` replaced two hand-assembled conditional-spread
 * bundles (`dashboard/index.ts` `startDashboard` and the principal-policy
 * dashboard's private `buildAggregatorSources`). These tests pin the
 * include-or-omit semantics both prior sites relied on, so a future edit to
 * the builder cannot silently change what a snapshot server sees:
 *
 *  - object/function fields: included iff truthy;
 *  - `teeAvailable`: included iff `!= null` (false is a real answer);
 *  - the `...ExpectedButUnavailable` flags: included iff true;
 *  - `platform`: included iff `!== undefined`;
 *  - `activity` / `pendingApprovals`: included iff provided (an empty
 *    array is a real, present value);
 *  - function references pass through by IDENTITY (callers assert exactly
 *    which resolver a server is armed with).
 */

import { describe, it, expect } from "vitest";
import {
  composeAggregatorSources,
  type AggregatorSourcesInput,
} from "../../src/dashboard/aggregator.js";

const BASE: AggregatorSourcesInput = {
  mode: "co-located",
  serverVersion: "9.9.9-test",
};

describe("composeAggregatorSources — include-or-omit semantics", () => {
  it("minimal input yields ONLY mode + server_version (no phantom keys)", () => {
    const sources = composeAggregatorSources(BASE);
    expect(sources).toEqual({
      mode: "co-located",
      server_version: "9.9.9-test",
    });
    expect(Object.keys(sources).sort()).toEqual(["mode", "server_version"]);
  });

  it("omits undefined AND null object fields (both prior sites used truthy checks)", () => {
    const sources = composeAggregatorSources({
      ...BASE,
      identityManager: null,
      auditLog: undefined,
      clientManager: null,
      baseline: undefined,
      policy: null,
      reputation: undefined,
      l4Evidence: null,
    });
    for (const key of [
      "identityManager",
      "auditLog",
      "clientManager",
      "baseline",
      "policy",
      "reputation",
      "l4Evidence",
    ]) {
      expect(key in sources, `${key} must be ABSENT, not undefined`).toBe(false);
    }
  });

  it("teeAvailable: false is included (a real answer); null/undefined are omitted", () => {
    expect(
      composeAggregatorSources({ ...BASE, teeAvailable: false }).teeAvailable,
    ).toBe(false);
    expect(
      "teeAvailable" in composeAggregatorSources({ ...BASE, teeAvailable: null }),
    ).toBe(false);
    expect(
      "teeAvailable" in
        composeAggregatorSources({ ...BASE, teeAvailable: undefined }),
    ).toBe(false);
  });

  it("the two ExpectedButUnavailable flags are included iff true (false means absent)", () => {
    const on = composeAggregatorSources({
      ...BASE,
      producerKeyExpectedButUnavailable: true,
      brokerProducerKeyExpectedButUnavailable: true,
    });
    expect(on.producerKeyExpectedButUnavailable).toBe(true);
    expect(on.brokerProducerKeyExpectedButUnavailable).toBe(true);

    const off = composeAggregatorSources({
      ...BASE,
      producerKeyExpectedButUnavailable: false,
      brokerProducerKeyExpectedButUnavailable: false,
    });
    expect("producerKeyExpectedButUnavailable" in off).toBe(false);
    expect("brokerProducerKeyExpectedButUnavailable" in off).toBe(false);
  });

  it("platform: included iff !== undefined", () => {
    expect(
      composeAggregatorSources({ ...BASE, platform: "linux" }).platform,
    ).toBe("linux");
    expect(
      "platform" in composeAggregatorSources({ ...BASE, platform: undefined }),
    ).toBe(false);
  });

  it("activity/pendingApprovals: an EMPTY array is included (live-buffer identity matters)", () => {
    const activity: never[] = [];
    const pending: never[] = [];
    const sources = composeAggregatorSources({
      ...BASE,
      activity,
      pendingApprovals: pending,
    });
    // Reference identity, not a copy: startDashboard mutates these buffers
    // after construction (publishActivity/publishApproval) and the snapshot
    // must observe the mutation.
    expect(sources.activity).toBe(activity);
    expect(sources.pendingApprovals).toBe(pending);
  });

  it("resolver functions pass through by identity", () => {
    const resolvePinnedProducerKey = (): string | null => null;
    const resolveEnforcementAvailability = (() =>
      Promise.reject(new Error("never called"))) as never;
    const resolveExclusiveEgressPosture = (() =>
      Promise.resolve(null)) as never;
    const resolveProtectionClaimSubject = (): string | null => null;
    const sources = composeAggregatorSources({
      ...BASE,
      resolvePinnedProducerKey,
      resolveEnforcementAvailability,
      resolveExclusiveEgressPosture,
      resolveProtectionClaimSubject,
    });
    expect(sources.resolvePinnedProducerKey).toBe(resolvePinnedProducerKey);
    expect(sources.resolveEnforcementAvailability).toBe(
      resolveEnforcementAvailability,
    );
    expect(sources.resolveExclusiveEgressPosture).toBe(
      resolveExclusiveEgressPosture,
    );
    expect(sources.resolveProtectionClaimSubject).toBe(
      resolveProtectionClaimSubject,
    );
  });

  it("standalone mode + full bundle round-trips every provided field", () => {
    const auditLog = { marker: "audit" } as never;
    const identityManager = { marker: "idm" } as never;
    const sources = composeAggregatorSources({
      mode: "standalone",
      serverVersion: "1.2.3",
      auditLog,
      identityManager,
      teeAvailable: true,
      platform: "darwin",
    });
    expect(sources).toEqual({
      mode: "standalone",
      server_version: "1.2.3",
      auditLog,
      identityManager,
      teeAvailable: true,
      platform: "darwin",
    });
  });
});
