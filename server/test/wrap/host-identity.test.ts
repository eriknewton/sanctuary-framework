/**
 * The host-fact resolvers behind the machine-local passphrase fallback key.
 *
 * Capability under test: the production resolver in
 * `server/src/wrap/host-identity.ts` extracts a canonical stable host identity
 * from what each platform actually hands it, and reports an honest `null`
 * rather than a plausible-looking string when it cannot.
 *
 * METHOD, stated so the evidence is not overread: the subprocess call itself is
 * deliberately NOT mocked. A mock of `execFileSync` would prove that a mock was
 * called and nothing about the real probe. The evidence is instead (a) the pure
 * parsers, exercised against the shapes a real dump takes, and (b) a real-host
 * witness that runs the shipped resolver on this machine when this machine is a
 * Mac. On a non-darwin runner the witness SKIPS, so it is not counted in the
 * Linux test-baseline floor; the parsers carry the portable coverage.
 *
 * Register id: defect.fallback-passphrase-key-derived-from-volatile-hostname
 */

import { describe, it, expect, afterEach, vi } from "vitest";

import {
  parseDarwinPlatformUuidDump,
  parseLinuxMachineId,
  resolveStableHostId,
} from "../../src/wrap/host-identity.js";

/**
 * The shape `ioreg -rd1 -c IOPlatformExpertDevice` prints, trimmed to the lines
 * that matter plus enough neighbours that a parser keyed to position rather
 * than to the key name would fail here.
 *
 * FAILURE MODE if this drifts from the real tool's output: the parser test
 * keeps passing against a dump no Mac produces, and only the darwin witness
 * below would notice.
 */
const DARWIN_DUMP = `+-o Root  <class IORegistryEntry, id 0x100000100, retain 39>
  +-o MacBookAir10,1  <class IOPlatformExpertDevice, id 0x100000271, registered>
      {
        "IOPlatformSerialNumber" = "C02ZZ0ZZZZZZ"
        "IOPlatformUUID" = "4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4"
        "IOBusyInterest" = "IOCommand is not serializable"
        "model" = <"MacBookAir10,1">
      }
`;

/** The same dump with a truncated, non-canonical value in the UUID slot. */
const DARWIN_DUMP_MALFORMED = DARWIN_DUMP.replace(
  "4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4",
  "4F1D3C2B-9A87-4655-B3E1",
);

/** The same dump with the key absent, as from an unexpected device node. */
const DARWIN_DUMP_WITHOUT_KEY = DARWIN_DUMP.split("\n")
  .filter((line) => !line.includes("IOPlatformUUID"))
  .join("\n");

describe("parseDarwinPlatformUuidDump", () => {
  it("extracts the canonical platform UUID from a device dump", () => {
    expect(parseDarwinPlatformUuidDump(DARWIN_DUMP)).toBe(
      "4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4",
    );
  });

  it("reports absence rather than accepting a malformed UUID", () => {
    // A truncated capture is not a weaker identity, it is a different one: a
    // key derived from it would be stable only until the truncation changed.
    expect(parseDarwinPlatformUuidDump(DARWIN_DUMP_MALFORMED)).toBeNull();
  });

  it("reports absence when the dump carries no platform UUID at all", () => {
    expect(parseDarwinPlatformUuidDump(DARWIN_DUMP_WITHOUT_KEY)).toBeNull();
  });

  it("reports absence for whitespace INSIDE the quoted value", () => {
    // A parser that trimmed inside the quotes would bind the custody key to a
    // value `ioreg` never printed, which is a different identity wearing the
    // right shape.
    const padded = DARWIN_DUMP.replace(
      '"4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4"',
      '" 4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4 "',
    );
    expect(parseDarwinPlatformUuidDump(padded)).toBeNull();
  });

  it("reports absence when the pair is not the whole line", () => {
    // An unanchored expression would accept the pair wherever it appeared,
    // including inside another node's serialized text.
    const trailing = DARWIN_DUMP.replace(
      '"IOPlatformUUID" = "4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4"',
      '"IOPlatformUUID" = "4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4" (stale)',
    );
    expect(parseDarwinPlatformUuidDump(trailing)).toBeNull();
  });
});

describe("parseLinuxMachineId", () => {
  it("accepts a 32-hex machine id with its trailing newline", () => {
    expect(parseLinuxMachineId("9f2c1b7e4a0d4c6fb83e5d17a2c90b64\n")).toBe(
      "9f2c1b7e4a0d4c6fb83e5d17a2c90b64",
    );
  });

  it("reports absence for an uninitialized (empty) machine-id file", () => {
    // Every first-boot host would otherwise share the identity "", which is the
    // opposite of a machine binding.
    expect(parseLinuxMachineId("")).toBeNull();
    expect(parseLinuxMachineId("\n")).toBeNull();
  });

  it("reports absence for contents that are not a machine id", () => {
    expect(parseLinuxMachineId("uninitialized\n")).toBeNull();
    expect(parseLinuxMachineId("9F2C1B7E4A0D4C6FB83E5D17A2C90B64")).toBeNull();
  });

  it("reports absence for leading whitespace", () => {
    // systemd writes the id at offset zero. Contents that need trimming to fit
    // were written by something else, and accepting them widens what counts as
    // this host's identity.
    expect(parseLinuxMachineId(" 9f2c1b7e4a0d4c6fb83e5d17a2c90b64\n")).toBeNull();
    expect(parseLinuxMachineId("\n9f2c1b7e4a0d4c6fb83e5d17a2c90b64")).toBeNull();
  });

  it("reports absence for a second trailing newline", () => {
    // One trailing newline is what systemd writes; anything past it is extra
    // content in a file whose whole contents are supposed to be the id.
    expect(parseLinuxMachineId("9f2c1b7e4a0d4c6fb83e5d17a2c90b64\n\n")).toBeNull();
  });
});

describe("resolveStableHostId caching", () => {
  // METHOD, and why this one file DOES substitute the subprocess where the rest
  // of the file refuses to: the property under test is the CACHE policy, not
  // the probe. Producing a transient probe failure on a healthy host is not
  // otherwise possible, and the shipped probe itself stays witnessed by the
  // real-host assertion below. The module is re-imported per test because the
  // memo has no reset by design.
  afterEach(() => {
    vi.doUnmock("node:child_process");
    vi.resetModules();
  });

  it("retries after a failed probe and caches only the resolved identity", async () => {
    // A probe failure cached as an identity would decide the host fact for
    // every later derivation in the process: a fallback file written in that
    // window is keyed to the hostname, and the next run — whose probe answers —
    // would derive the stable-identity key and strand it.
    let probes = 0;
    vi.doMock("node:child_process", () => ({
      execFileSync: (): string => {
        probes += 1;
        if (probes === 1) throw new Error("ioreg unavailable on this run");
        return DARWIN_DUMP;
      },
    }));
    // Reset BEFORE the dynamic import: the statically imported instance at the
    // top of this file is already in the registry, and without this the import
    // below returns it (real subprocess, real memo) and the test silently
    // measures the host instead of the policy.
    vi.resetModules();
    const mod = await import("../../src/wrap/host-identity.js");

    expect(mod.resolveStableHostId("darwin")).toBeNull();
    expect(mod.resolveStableHostId("darwin")).toBe(
      "4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4",
    );
    expect(probes).toBe(2);

    // The resolved value IS cached: a third call spawns nothing.
    expect(mod.resolveStableHostId("darwin")).toBe(
      "4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4",
    );
    expect(probes).toBe(2);
  });
});

describe("resolveStableHostId on the real host", () => {
  // Real-host witness. This is the only assertion in the file that exercises
  // the shipped probe end to end, including the subprocess. It is gated because
  // there is nothing to witness on a platform that has no platform UUID.
  it.skipIf(process.platform !== "darwin")(
    "returns this Mac's canonical platform UUID, and the same value on a second call",
    () => {
      const first = resolveStableHostId("darwin");
      expect(first).toMatch(
        /^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$/,
      );
      // The resolver memoizes per platform token so a custody read does not
      // spawn a subprocess every time. Identical values across two calls is the
      // observable half of that; a changing value would mean the fallback file
      // could be sealed under one identity and read under another.
      expect(resolveStableHostId("darwin")).toBe(first);
    },
  );
});
