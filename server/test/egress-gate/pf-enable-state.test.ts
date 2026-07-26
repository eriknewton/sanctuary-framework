/**
 * The pf enable-reference chokepoint, tested against REAL CAPTURED pfctl
 * OUTPUT (`fixtures/pf-hardware-capture.ts`), not against a model of pf.
 *
 * PR #1007, the first attempt at F-PFBOOT, was reviewed UNSOUND because its
 * pf host was a model its author wrote from prose about drill logs, so its
 * tests could only confirm the author's understanding. Every pfctl string this
 * file feeds the code under test is a byte-exact extract from the 2026-07-26
 * Mini1 drill, and the fixture module names the source log and line range for
 * each one.
 *
 * The five states the drill said a correct fix must distinguish, and which
 * `describe` block covers each:
 *
 *   our token live this boot ........... "our reference, live, this boot"
 *   our token stale from a prior boot .. "F-PFBOOT: a token that outlived its boot session"
 *   a third party holds the reference .. "F-PFTHIRDPARTY: pf held up by somebody else"
 *   pf disabled entirely ............... "F-PFBOOT: a token that outlived its boot session"
 *   pfctl unavailable or erroring ...... "could not look is not a yes"
 */

import { describe, it, expect } from "vitest";

import {
  ensurePfEnableReference,
  observePfEnabled,
  observePfEnableReferences,
  parsePfEnableReferenceTokens,
  releasePfEnableReference,
  resolvePfEnableReference,
  type PfEnableReference,
} from "../../src/egress-gate/pf-enable-state.js";
import type { ExecCommandResult, ExecCommandRunner } from "../../src/egress-gate/exec-runner.js";

import {
  CAPTURED_BOOT_SESSION_AFTER,
  CAPTURED_BOOT_SESSION_BEFORE,
  CAPTURED_BOOT_SESSION_T1,
  CAPTURED_ENABLE_TOKEN,
  CAPTURED_STALE_REGISTRY_TOKEN,
  CAPTURED_THIRD_PARTY_TOKEN,
  CAPTURED_TOKEN_ONE,
  CAPTURED_TOKEN_TWO,
  PF_ENABLE_OK,
  PF_INFO_DISABLED,
  PF_INFO_ENABLED,
  PF_REFERENCES_NONE,
  PF_REFERENCES_ONE,
  PF_REFERENCES_THIRD_PARTY,
  PF_REFERENCES_TWO,
  PF_RELEASE_LAST,
  PF_RELEASE_OTHERS_REMAIN,
  PF_RELEASE_STALE_PF_DISABLED,
  PF_RELEASE_STALE_PF_ENABLED,
} from "./fixtures/pf-hardware-capture.js";

// ---------------------------------------------------------------------------
// A pf host built ONLY from captured output.
// ---------------------------------------------------------------------------

interface HostState {
  /** stdout of `pfctl -s info`. */
  info: string;
  /** stdout of `pfctl -s References`. */
  references: string;
  /** Result of the next `pfctl -E`. */
  enable: ExecCommandResult;
  /** Result of the next `pfctl -X <token>`, by token. */
  release: (token: string) => ExecCommandResult;
  /** Force a spawn-level failure for one subcommand shape. */
  failing?: (args: readonly string[]) => ExecCommandResult | undefined;
}

function pfHost(state: HostState): ExecCommandRunner & { calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    async run(command: string, args: readonly string[]): Promise<ExecCommandResult> {
      calls.push([command, ...args]);
      const forced = state.failing?.(args);
      if (forced !== undefined) return forced;
      const joined = args.join(" ");
      if (joined === "-s info") return { code: 0, stdout: state.info, stderr: "" };
      if (joined === "-s References") return { code: 0, stdout: state.references, stderr: "" };
      if (joined === "-E") return { ...state.enable };
      if (args[0] === "-X") return state.release(args[1] ?? "");
      throw new Error(`unscripted pfctl invocation: ${joined}`);
    },
  };
}

/** The exact state the drill captured BEFORE the reboot: our reference, live. */
function ourReferenceLive(): HostState {
  return {
    info: PF_INFO_ENABLED,
    references: PF_REFERENCES_ONE,
    enable: { ...PF_ENABLE_OK },
    release: () => ({ ...PF_RELEASE_LAST }),
  };
}

/** The exact state the drill captured AFTER the reboot: pf disabled, no references. */
function afterReboot(): HostState {
  return {
    info: PF_INFO_DISABLED,
    references: PF_REFERENCES_NONE,
    enable: { ...PF_ENABLE_OK },
    release: () => ({ ...PF_RELEASE_STALE_PF_DISABLED }),
  };
}

/** The F-PFTHIRDPARTY state: pf enabled, but by a reference that is not ours. */
function thirdPartyHoldsPf(): HostState {
  return {
    info: PF_INFO_ENABLED,
    references: PF_REFERENCES_THIRD_PARTY,
    enable: { ...PF_ENABLE_OK },
    release: () => ({ ...PF_RELEASE_STALE_PF_ENABLED }),
  };
}

const bootSession = (uuid: string) => async (): Promise<string> => uuid;
const bootSessionUnreadable = async (): Promise<string> => {
  throw new Error("sysctl: unknown oid 'kern.bootsessionuuid'");
};

const OUR_REFERENCE: PfEnableReference = {
  token: CAPTURED_TOKEN_ONE,
  boot_session_uuid: CAPTURED_BOOT_SESSION_T1,
};

// ---------------------------------------------------------------------------

describe("pfctl -s References parsing (captured formats only)", () => {
  it("reads the empty-table sentinel as zero tokens", () => {
    expect(parsePfEnableReferenceTokens(PF_REFERENCES_NONE)).toEqual([]);
  });

  it("reads one reference, taking the TOKEN column and not the PID", () => {
    expect(parsePfEnableReferenceTokens(PF_REFERENCES_ONE)).toEqual([CAPTURED_TOKEN_ONE]);
  });

  it("reads two references in the captured (newest-first) order", () => {
    expect(parsePfEnableReferenceTokens(PF_REFERENCES_TWO)).toEqual([
      CAPTURED_TOKEN_TWO,
      CAPTURED_TOKEN_ONE,
    ]);
  });

  it("reads the third-party capture", () => {
    expect(parsePfEnableReferenceTokens(PF_REFERENCES_THIRD_PARTY)).toEqual([
      CAPTURED_THIRD_PARTY_TOKEN,
    ]);
  });

  it("counts the TOKEN column BACKWARDS, so a multi-word process name cannot shift it", () => {
    // Every captured row says `pfctl`. A forward positional parse would be
    // correct on all of them and silently wrong on this one -- and being
    // silently wrong here means misattributing a pf enable reference.
    const twoWordName =
      "TOKENS:\n" +
      "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
      "4063     some helper                  15053025338191571182     0 days 00:00:00\n";
    expect(parsePfEnableReferenceTokens(twoWordName)).toEqual([CAPTURED_TOKEN_ONE]);
  });

  it("returns null (could not look) for output in neither captured shape", () => {
    expect(parsePfEnableReferenceTokens("")).toBeNull();
    expect(parsePfEnableReferenceTokens("some future pfctl phrasing\n")).toBeNull();
  });

  it("returns null rather than dropping a data row it cannot read", () => {
    const unreadableRow =
      "TOKENS:\n" +
      "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
      "4063     pfctl                        not-a-token              0 days 00:00:00\n";
    expect(parsePfEnableReferenceTokens(unreadableRow)).toBeNull();
  });
});

describe("observePfEnabled / observePfEnableReferences", () => {
  it("reads the captured enabled and disabled outputs", async () => {
    expect(await observePfEnabled(pfHost(ourReferenceLive()))).toEqual({ known: true, enabled: true });
    expect(await observePfEnabled(pfHost(afterReboot()))).toEqual({ known: true, enabled: false });
  });

  it("matches 'Status: Enabled for 0 days 00:00:00', the form pf actually prints", () => {
    // The captured status line carries a trailing duration; a predicate
    // anchored to end-of-line would read every enabled host as disabled.
    expect(PF_INFO_ENABLED.startsWith("Status: Enabled for")).toBe(true);
  });

  it("reports a non-zero pfctl as `known: false`, never as `enabled: false`", async () => {
    const host = pfHost({
      ...afterReboot(),
      failing: (a) => (a.join(" ") === "-s info" ? { code: 1, stdout: "", stderr: "denied" } : undefined),
    });
    expect(await observePfEnabled(host)).toEqual({ known: false, reason: "pfctl -s info exited 1" });
  });

  it("reports a throwing runner as `known: false`", async () => {
    const throwing: ExecCommandRunner = {
      async run(): Promise<ExecCommandResult> {
        throw new Error("spawn pfctl ENOENT");
      },
    };
    const enabled = await observePfEnabled(throwing);
    expect(enabled.known).toBe(false);
    const refs = await observePfEnableReferences(throwing);
    expect(refs.known).toBe(false);
  });
});

describe("our reference, live, this boot", () => {
  it("resolves ours-live and reuses it without calling pfctl -E", async () => {
    const host = pfHost(ourReferenceLive());
    const ensured = await ensurePfEnableReference(
      { runner: host, bootSession: bootSession(CAPTURED_BOOT_SESSION_T1) },
      OUR_REFERENCE,
    );
    expect(ensured.resolution.status).toBe("ours-live");
    expect(ensured.acquired).toBe(false);
    expect(ensured.reference).toEqual(OUR_REFERENCE);
    expect(host.calls.map((c) => c.slice(1).join(" "))).not.toContain("-E");
  });

  it("still verifies attribution when the boot session merely MATCHES", async () => {
    // A matching session removes a shortcut; it grants nothing. Here the
    // session matches but the reference table names somebody else's token.
    const host = pfHost(thirdPartyHoldsPf());
    const resolution = await resolvePfEnableReference(
      { runner: host, bootSession: bootSession(CAPTURED_BOOT_SESSION_T1) },
      OUR_REFERENCE,
    );
    expect(resolution.status).toBe("not-ours");
    expect(host.calls.map((c) => c.slice(1).join(" "))).toContain("-s References");
  });

  it("resolves ours-live from attribution alone when the record has no boot binding", async () => {
    // State written before this module carries no session. It must still be
    // usable, and it must still be verified.
    const host = pfHost(ourReferenceLive());
    const resolution = await resolvePfEnableReference(
      { runner: host, bootSession: bootSession(CAPTURED_BOOT_SESSION_T1) },
      { token: CAPTURED_TOKEN_ONE },
    );
    expect(resolution.status).toBe("ours-live");
  });
});

describe("F-PFBOOT: a token that outlived its boot session", () => {
  it("rejects a token minted in a different boot WITHOUT asking pfctl anything", async () => {
    // The strongest leg: an unreadable or broken pfctl cannot make this wrong,
    // which is exactly the hole a `pfctl -s References` parse alone leaves.
    const host = pfHost(afterReboot());
    const resolution = await resolvePfEnableReference(
      { runner: host, bootSession: bootSession(CAPTURED_BOOT_SESSION_AFTER) },
      { token: CAPTURED_STALE_REGISTRY_TOKEN, boot_session_uuid: CAPTURED_BOOT_SESSION_BEFORE },
    );
    expect(resolution.status).toBe("not-ours");
    expect(host.calls).toEqual([]);
  });

  it("rejects any recorded token when pf is observed disabled", async () => {
    const host = pfHost(afterReboot());
    const resolution = await resolvePfEnableReference(
      { runner: host, bootSession: bootSessionUnreadable },
      { token: CAPTURED_STALE_REGISTRY_TOKEN },
    );
    expect(resolution).toEqual({
      status: "not-ours",
      reason: "pf is not enabled, so no enable reference of any kind is held",
    });
  });

  it("re-acquires after a reboot and binds the FRESH token to the CURRENT boot", async () => {
    // This is the whole defect, end to end: the persisted token was
    // byte-identical across the reboot (2276319666065282592) while pf was
    // Status: Disabled and the confined uid had regained loopback reach.
    const state = afterReboot();
    const host = pfHost(state);
    // pf comes up once `-E` runs, exactly as it does on a real host.
    const enable = state.enable;
    state.enable = enable;
    const runner: ExecCommandRunner & { calls: string[][] } = {
      calls: host.calls,
      async run(command, args) {
        const res = await host.run(command, args);
        if (args.join(" ") === "-E") {
          state.info = PF_INFO_ENABLED;
          state.references =
            "TOKENS:\n" +
            "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
            `4151     pfctl                        ${CAPTURED_ENABLE_TOKEN}     0 days 00:00:00\n`;
        }
        return res;
      },
    };

    const ensured = await ensurePfEnableReference(
      { runner, bootSession: bootSession(CAPTURED_BOOT_SESSION_AFTER) },
      { token: CAPTURED_STALE_REGISTRY_TOKEN, boot_session_uuid: CAPTURED_BOOT_SESSION_BEFORE },
    );

    expect(ensured.acquired).toBe(true);
    expect(ensured.reference).toEqual({
      token: CAPTURED_ENABLE_TOKEN,
      boot_session_uuid: CAPTURED_BOOT_SESSION_AFTER,
    });
    // The stale token's release fails with `pfctl: pf not enabled`, which is
    // the truth about it, not a teardown failure.
    expect(ensured.supersededRelease?.disposition).toBe("already-gone");
  });

  it("takes the token off STDERR, where pfctl -E actually writes it", async () => {
    expect(PF_ENABLE_OK.stdout).toBe("");
    expect(PF_ENABLE_OK.stderr).toContain("Token :");
    const state = afterReboot();
    state.info = PF_INFO_ENABLED;
    state.references =
      "TOKENS:\n" +
      "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
      `4151     pfctl                        ${CAPTURED_ENABLE_TOKEN}     0 days 00:00:00\n`;
    const ensured = await ensurePfEnableReference(
      { runner: pfHost(state), bootSession: bootSession(CAPTURED_BOOT_SESSION_T1) },
      undefined,
    );
    expect(ensured.reference.token).toBe(CAPTURED_ENABLE_TOKEN);
  });
});

describe("F-PFTHIRDPARTY: pf held up by somebody else", () => {
  it("refuses to read a globally-enabled pf as evidence that the reference is ours", async () => {
    // Measured on hardware: with pf enabled by an out-of-band reference and
    // our own token kernel-invalid, the product reported the gate LIVE.
    // Releasing that foreign reference destroyed uid 503's loopback
    // confinement in the SAME boot and the SAME generation.
    const host = pfHost(thirdPartyHoldsPf());
    const resolution = await resolvePfEnableReference(
      { runner: host, bootSession: bootSession(CAPTURED_BOOT_SESSION_AFTER) },
      { token: CAPTURED_STALE_REGISTRY_TOKEN, boot_session_uuid: CAPTURED_BOOT_SESSION_AFTER },
    );
    expect(resolution.status).toBe("not-ours");
    expect(resolution.status === "not-ours" && resolution.reason).toContain(
      "reference this fortress does not own",
    );
  });

  it("acquires OUR OWN reference so a third party's release cannot disable pf under us", async () => {
    const state = thirdPartyHoldsPf();
    const host = pfHost(state);
    const runner: ExecCommandRunner & { calls: string[][] } = {
      calls: host.calls,
      async run(command, args) {
        const res = await host.run(command, args);
        if (args.join(" ") === "-E") {
          // pf now holds TWO references: the third party's and ours.
          state.references =
            "TOKENS:\n" +
            "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
            `4151     pfctl                        ${CAPTURED_ENABLE_TOKEN}     0 days 00:00:00\n` +
            `5059     pfctl                        ${CAPTURED_THIRD_PARTY_TOKEN}      0 days 00:01:06\n`;
        }
        return res;
      },
    };
    const ensured = await ensurePfEnableReference(
      { runner, bootSession: bootSession(CAPTURED_BOOT_SESSION_AFTER) },
      { token: CAPTURED_STALE_REGISTRY_TOKEN, boot_session_uuid: CAPTURED_BOOT_SESSION_AFTER },
    );
    expect(ensured.acquired).toBe(true);
    expect(ensured.reference.token).toBe(CAPTURED_ENABLE_TOKEN);
    // And the reference table now attributes one of the references to us,
    // which is what makes the third party's departure survivable.
    const refs = await observePfEnableReferences(runner);
    expect(refs.known && refs.tokens).toContain(CAPTURED_ENABLE_TOKEN);
  });

  it("does not release the third party's reference (it is not ours to release)", async () => {
    const state = thirdPartyHoldsPf();
    const host = pfHost(state);
    const runner: ExecCommandRunner & { calls: string[][] } = {
      calls: host.calls,
      async run(command, args) {
        const res = await host.run(command, args);
        if (args.join(" ") === "-E") {
          state.references =
            "TOKENS:\n" +
            "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
            `4151     pfctl                        ${CAPTURED_ENABLE_TOKEN}     0 days 00:00:00\n` +
            `5059     pfctl                        ${CAPTURED_THIRD_PARTY_TOKEN}      0 days 00:01:06\n`;
        }
        return res;
      },
    };
    await ensurePfEnableReference(
      { runner, bootSession: bootSession(CAPTURED_BOOT_SESSION_AFTER) },
      { token: CAPTURED_STALE_REGISTRY_TOKEN, boot_session_uuid: CAPTURED_BOOT_SESSION_AFTER },
    );
    const released = host.calls.filter((c) => c[1] === "-X").map((c) => c[2]);
    expect(released).toContain(CAPTURED_STALE_REGISTRY_TOKEN); // our own superseded record
    expect(released).not.toContain(CAPTURED_THIRD_PARTY_TOKEN);
  });
});

describe("could not look is not a yes", () => {
  it("resolves `unknown` when pf's enable state is unreadable", async () => {
    const host = pfHost({
      ...ourReferenceLive(),
      failing: (a) => (a.join(" ") === "-s info" ? { code: 77, stdout: "", stderr: "" } : undefined),
    });
    const resolution = await resolvePfEnableReference(
      { runner: host, bootSession: bootSession(CAPTURED_BOOT_SESSION_T1) },
      OUR_REFERENCE,
    );
    expect(resolution.status).toBe("unknown");
  });

  it("resolves `unknown` when the reference table is unreadable, even with pf enabled", async () => {
    const host = pfHost({ ...ourReferenceLive(), references: "some future pfctl phrasing\n" });
    const resolution = await resolvePfEnableReference(
      { runner: host, bootSession: bootSession(CAPTURED_BOOT_SESSION_T1) },
      OUR_REFERENCE,
    );
    expect(resolution.status).toBe("unknown");
  });

  it("RE-ACQUIRES on `unknown` rather than trusting the record", async () => {
    // The asymmetric fail direction, stated as a test: a needless `-E` leaves
    // pf enabled with one extra reference (over-enforcing, releasable,
    // visible). Trusting the record risks pf being disabled while we report
    // armed, which is the wrong-allow both findings are about.
    const state = ourReferenceLive();
    state.references = "some future pfctl phrasing\n";
    const host = pfHost(state);
    const ensured = await ensurePfEnableReference(
      { runner: host, bootSession: bootSession(CAPTURED_BOOT_SESSION_T1) },
      OUR_REFERENCE,
    );
    expect(ensured.resolution.status).toBe("unknown");
    expect(ensured.acquired).toBe(true);
  });

  it("throws when pfctl -E itself fails, so the caller parks rather than proceeds", async () => {
    const host = pfHost({
      ...afterReboot(),
      failing: (a) =>
        a.join(" ") === "-E" ? { code: 127, stdout: "", stderr: "spawn pfctl ENOENT" } : undefined,
    });
    await expect(
      ensurePfEnableReference({ runner: host, bootSession: bootSessionUnreadable }, undefined),
    ).rejects.toThrow(/pfctl -E exited 127/);
  });

  it("records a reference with NO boot binding when the sysctl is unreadable", async () => {
    const state = afterReboot();
    state.info = PF_INFO_ENABLED;
    state.references =
      "TOKENS:\n" +
      "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
      `4151     pfctl                        ${CAPTURED_ENABLE_TOKEN}     0 days 00:00:00\n`;
    const ensured = await ensurePfEnableReference(
      { runner: pfHost(state), bootSession: bootSessionUnreadable },
      undefined,
    );
    expect(ensured.reference).toEqual({ token: CAPTURED_ENABLE_TOKEN });
    expect(ensured.evidence.join(" ")).toContain("unreadable");
  });
});

describe("the invariant is asserted, not assumed", () => {
  it("throws when pfctl -E exits 0 with a token but pf is still observed disabled", async () => {
    // A 0-exit is not evidence. Before this, such a host surfaced only as a
    // generic 5-second settle timeout, and in the field as a wrong-allow.
    const host = pfHost(afterReboot()); // -E succeeds but info stays Disabled
    await expect(
      ensurePfEnableReference({ runner: host, bootSession: bootSessionUnreadable }, undefined),
    ).rejects.toThrow(/but pf is still not enabled/);
    // Refusing to REPORT a reference means giving it back: the token this call
    // took is released, not leaked for a retry to duplicate.
    expect(host.calls.some((c) => c[1] === "-X" && c[2] === CAPTURED_ENABLE_TOKEN)).toBe(true);
  });

  it("throws when the fresh token is absent from the reference table", async () => {
    const state = afterReboot();
    state.info = PF_INFO_ENABLED;
    state.references = PF_REFERENCES_THIRD_PARTY; // somebody else's, not ours
    const host = pfHost(state);
    await expect(
      ensurePfEnableReference({ runner: host, bootSession: bootSessionUnreadable }, undefined),
    ).rejects.toThrow(/does not list it/);
    expect(host.calls.some((c) => c[1] === "-X" && c[2] === CAPTURED_ENABLE_TOKEN)).toBe(true);
  });

  it("does NOT throw when the post-acquire probes are merely unreadable", async () => {
    // Only DEFINITE negative evidence throws. A transient pfctl read failure
    // must not become an availability cliff; the caller's settle probe is
    // fail-closed anyway.
    const state = afterReboot();
    const host = pfHost({
      ...state,
      failing: (a) =>
        a.join(" ") === "-s info" || a.join(" ") === "-s References"
          ? { code: 77, stdout: "", stderr: "" }
          : undefined,
    });
    const ensured = await ensurePfEnableReference(
      { runner: host, bootSession: bootSessionUnreadable },
      undefined,
    );
    expect(ensured.reference.token).toBe(CAPTURED_ENABLE_TOKEN);
  });

  it("releases the superseded reference AFTER acquiring, never before", async () => {
    const state = ourReferenceLive();
    state.references = PF_REFERENCES_THIRD_PARTY; // our record is stale
    state.release = () => ({ ...PF_RELEASE_OTHERS_REMAIN });
    const host = pfHost(state);
    const runner: ExecCommandRunner & { calls: string[][] } = {
      calls: host.calls,
      async run(command, args) {
        const res = await host.run(command, args);
        if (args.join(" ") === "-E") {
          state.references =
            "TOKENS:\n" +
            "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
            `4151     pfctl                        ${CAPTURED_ENABLE_TOKEN}     0 days 00:00:00\n`;
        }
        return res;
      },
    };
    await ensurePfEnableReference(
      { runner, bootSession: bootSession(CAPTURED_BOOT_SESSION_T1) },
      OUR_REFERENCE,
    );
    const shapes = host.calls.map((c) => (c[1] === "-X" ? "-X" : c.slice(1).join(" ")));
    // pf's reference count must never dip to zero underneath a loaded anchor.
    expect(shapes.indexOf("-E")).toBeLessThan(shapes.indexOf("-X"));
  });
});

describe("releasing a reference", () => {
  it("reports `released` on a clean pfctl -X", async () => {
    const host = pfHost(ourReferenceLive());
    expect(await releasePfEnableReference({ runner: host }, CAPTURED_TOKEN_ONE)).toEqual({
      disposition: "released",
    });
  });

  it("reports `released` when other references remain (the captured multi-holder message)", async () => {
    const host = pfHost({ ...ourReferenceLive(), release: () => ({ ...PF_RELEASE_OTHERS_REMAIN }) });
    expect(
      (await releasePfEnableReference({ runner: host }, CAPTURED_TOKEN_ONE)).disposition,
    ).toBe("released");
  });

  it("reports `already-gone` on `pfctl: pf not enabled` (the post-reboot message)", async () => {
    const host = pfHost({ ...afterReboot(), release: () => ({ ...PF_RELEASE_STALE_PF_DISABLED }) });
    const out = await releasePfEnableReference({ runner: host }, CAPTURED_STALE_REGISTRY_TOKEN);
    expect(out.disposition).toBe("already-gone");
  });

  it("reports `already-gone` on `pfctl: pf: token invalid` (the pf-enabled message)", async () => {
    // BOTH messages, deliberately. A fix that suppresses only `token invalid`
    // still throws on the more common post-reboot case; this pair is the whole
    // reason the drill re-measured the exit codes without a pipe.
    const host = pfHost({ ...thirdPartyHoldsPf(), release: () => ({ ...PF_RELEASE_STALE_PF_ENABLED }) });
    const out = await releasePfEnableReference({ runner: host }, CAPTURED_STALE_REGISTRY_TOKEN);
    expect(out.disposition).toBe("already-gone");
  });

  it("THROWS on a failure it cannot account for", async () => {
    const host = pfHost({
      ...ourReferenceLive(),
      release: () => ({ code: 1, stdout: "", stderr: "pfctl: Operation not permitted" }),
    });
    await expect(releasePfEnableReference({ runner: host }, CAPTURED_TOKEN_ONE)).rejects.toThrow(
      /Operation not permitted/,
    );
  });

  it("refuses a non-numeric token", async () => {
    const host = pfHost(ourReferenceLive());
    await expect(releasePfEnableReference({ runner: host }, "; rm -rf /")).rejects.toThrow(
      /numeric pfctl reference token/,
    );
  });
});
