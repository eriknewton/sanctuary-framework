import { describe, expect, it } from "vitest";

import {
  SanctuaryVMMCliLauncher,
  assertGuestJailDeliveryConfig,
  buildVmmCliArgs,
  isSecretEnvKey,
  type VMGuestExecRequest,
  type VMRunBoxRequest,
} from "../../src/agent-contract/adapters/vm-launcher.js";

const VALID_SHA = "a".repeat(64);

function baseGuestExecCliRequest(): VMGuestExecRequest["cliRequest"] {
  return {
    kernelPath: "/k/vmlinux",
    ociImageReference: "img:latest",
    command: "/plugin/run",
    args: ["--flag"],
    cwd: "/work",
    env: { LANG: "C" },
  };
}

function baseRunBoxCliRequest(): VMRunBoxRequest["cliRequest"] {
  return {
    ...baseGuestExecCliRequest(),
    egressProxyUdsPath: "/tmp/egress.sock",
  };
}

describe("agent-contract/adapters/vm-launcher", () => {
  describe("guest-jail delivery fields (codex MEDIUM fix)", () => {
    it("serializes static-binary delivery fields into the guest-exec CLI JSON", () => {
      const cliRequest: VMGuestExecRequest["cliRequest"] = {
        ...baseGuestExecCliRequest(),
        applyGuestJail: true,
        guestJailDelivery: "static-binary",
        staticJailBinaryPath: "/opt/sanctuary/sanctuary-jail",
        staticJailBinarySHA256: VALID_SHA,
      };
      const args = buildVmmCliArgs("guest-exec", cliRequest);
      expect(args[0]).toBe("guest-exec");
      expect(args[1]).toBe("--json");
      const parsed = JSON.parse(args[2]);
      expect(parsed.applyGuestJail).toBe(true);
      expect(parsed.guestJailDelivery).toBe("static-binary");
      expect(parsed.staticJailBinaryPath).toBe("/opt/sanctuary/sanctuary-jail");
      expect(parsed.staticJailBinarySHA256).toBe(VALID_SHA);
    });

    it("serializes static-binary delivery fields into the run-box CLI JSON", () => {
      const cliRequest: VMRunBoxRequest["cliRequest"] = {
        ...baseRunBoxCliRequest(),
        guestJailDelivery: "static-binary",
        staticJailBinaryPath: "/opt/sanctuary/sanctuary-jail",
        staticJailBinarySHA256: VALID_SHA,
      };
      const args = buildVmmCliArgs("run-box", cliRequest);
      expect(args[0]).toBe("run-box");
      const parsed = JSON.parse(args[2]);
      expect(parsed.guestJailDelivery).toBe("static-binary");
      expect(parsed.staticJailBinaryPath).toBe("/opt/sanctuary/sanctuary-jail");
      expect(parsed.staticJailBinarySHA256).toBe(VALID_SHA);
      expect(parsed.egressProxyUdsPath).toBe("/tmp/egress.sock");
    });

    it("accepts the default (python-preamble) config with no static fields", () => {
      expect(() => assertGuestJailDeliveryConfig({})).not.toThrow();
      expect(() =>
        assertGuestJailDeliveryConfig({ guestJailDelivery: "python-preamble" }),
      ).not.toThrow();
      expect(() =>
        assertGuestJailDeliveryConfig({ applyGuestJail: false }),
      ).not.toThrow();
    });

    it("rejects static-binary without a path (fail closed)", () => {
      expect(() =>
        assertGuestJailDeliveryConfig({
          guestJailDelivery: "static-binary",
          staticJailBinarySHA256: VALID_SHA,
        }),
      ).toThrow(/requires staticJailBinaryPath/);
    });

    it("rejects static-binary without a SHA-256 pin (no hash, no static delivery)", () => {
      expect(() =>
        assertGuestJailDeliveryConfig({
          guestJailDelivery: "static-binary",
          staticJailBinaryPath: "/opt/sanctuary/sanctuary-jail",
        }),
      ).toThrow(/No hash, no static delivery/);
      expect(() =>
        assertGuestJailDeliveryConfig({
          guestJailDelivery: "static-binary",
          staticJailBinaryPath: "/opt/sanctuary/sanctuary-jail",
          staticJailBinarySHA256: "",
        }),
      ).toThrow(/No hash, no static delivery/);
    });

    it.each([
      "deadbeef",
      `${"a".repeat(64)}aa`,
      "g".repeat(64),
      `sha256:${"a".repeat(57)}`,
    ])("rejects malformed SHA-256 pin %s (fail closed)", (sha) => {
      expect(() =>
        assertGuestJailDeliveryConfig({
          guestJailDelivery: "static-binary",
          staticJailBinaryPath: "/opt/sanctuary/sanctuary-jail",
          staticJailBinarySHA256: sha,
        }),
      ).toThrow(/malformed/);
    });

    it("rejects static fields under python-preamble mode (no silent mode confusion)", () => {
      expect(() =>
        assertGuestJailDeliveryConfig({
          staticJailBinaryPath: "/opt/sanctuary/sanctuary-jail",
        }),
      ).toThrow(/not 'static-binary'/);
      expect(() =>
        assertGuestJailDeliveryConfig({
          guestJailDelivery: "python-preamble",
          staticJailBinarySHA256: VALID_SHA,
        }),
      ).toThrow(/not 'static-binary'/);
    });

    it("rejects unknown delivery modes smuggled past the type system", () => {
      expect(() =>
        assertGuestJailDeliveryConfig({
          guestJailDelivery: "none" as never,
        }),
      ).toThrow(/unknown guestJailDelivery/);
    });

    it("launchGuestExec rejects a partial static config before spawning anything", async () => {
      const launcher = new SanctuaryVMMCliLauncher({
        binary: "/definitely/not/a/real/sanctuary-vmm",
      });
      await expect(
        launcher.launchGuestExec({
          harnessId: "claude-code",
          cliRequest: {
            ...baseGuestExecCliRequest(),
            guestJailDelivery: "static-binary",
            staticJailBinaryPath: "/opt/sanctuary/sanctuary-jail",
            // no staticJailBinarySHA256 — must be refused host-side
          },
        }),
      ).rejects.toThrow(/No hash, no static delivery/);
    });

    it("launchRunBox rejects a partial static config before spawning anything", async () => {
      const launcher = new SanctuaryVMMCliLauncher({
        binary: "/definitely/not/a/real/sanctuary-vmm",
      });
      await expect(
        launcher.launchRunBox({
          harnessId: "claude-code",
          cliRequest: {
            ...baseRunBoxCliRequest(),
            guestJailDelivery: "static-binary",
            staticJailBinarySHA256: VALID_SHA,
            // no staticJailBinaryPath — must be refused host-side
          },
        }),
      ).rejects.toThrow(/requires staticJailBinaryPath/);
    });
  });

  describe("isSecretEnvKey", () => {
    it.each([
      "PRIVATE_KEY",
      "SSH_PRIVATE_KEY",
      "MASTER_SECRET",
      "SANCTUARY_PASSPHRASE",
      "OPENAI_API_KEY",
      "AUTH_TOKEN",
      "SESSION_SECRET",
      "AWS_SECRET_ACCESS_KEY",
      "SANCTUARY_KEY_MATERIAL",
      "SANCTUARY_IDENTITY",
    ])("filters secret key %s", (key) => {
      expect(isSecretEnvKey(key)).toBe(true);
    });

    it.each([
      "PATH",
      "HOME",
      "USER",
      "SHELL",
      "LANG",
      "TERM",
      "NODE_ENV",
      "SANCTUARY_FORTRESS_PATH",
      "SANCTUARY_LOG_LEVEL",
    ])("allows non-secret key %s", (key) => {
      expect(isSecretEnvKey(key)).toBe(false);
    });
  });
});
