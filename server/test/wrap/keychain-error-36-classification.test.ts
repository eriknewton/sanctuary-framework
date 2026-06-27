/**
 * Keychain error-36 / headless classification tests (element 3).
 *
 * Regression target: `readKey` collapsed ALL non-zero exit codes (macOS error
 * 36 / errSecInteractionNotAllowed over SSH included) to `null`, silently
 * dropping the keychain factor with zero diagnostic. The classifying read now
 * distinguishes "unreachable" (locked / no GUI / not installed) from
 * "not-found" (reachable, item absent) so the unlock path can guide the
 * operator instead of pretending the factor never existed.
 */

import { describe, it, expect } from "vitest";
import {
  readKeychainKeyStatus,
  type KeychainCustodyOptions,
} from "../../src/wrap/keychain-custody.js";

const KEY_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

function backend(
  plat: NodeJS.Platform,
  reply: { stdout?: string; stderr?: string; code: number | null },
): KeychainCustodyOptions {
  return {
    platformOverride: plat,
    exec: async () => ({
      stdout: reply.stdout ?? "",
      stderr: reply.stderr ?? "",
      code: reply.code,
    }),
  };
}

describe("readKeychainKeyStatus — error-36 / headless classification", () => {
  it("macOS error 36 (interaction not allowed) classifies as unreachable, not not-found", async () => {
    const result = await readKeychainKeyStatus(
      "sanctuary-custody-test",
      backend("darwin", { code: 36, stderr: "User interaction is not allowed." }),
    );
    expect(result.status).toBe("unreachable");
    expect(result.detail).toContain("error 36");
  });

  it("macOS errSecInteractionNotAllowed by -25308 marker classifies as unreachable", async () => {
    const result = await readKeychainKeyStatus(
      "sanctuary-custody-test",
      backend("darwin", { code: 1, stderr: "SecKeychainSearchCopyNext: -25308" }),
    );
    expect(result.status).toBe("unreachable");
  });

  it("macOS item-not-found (exit 44) classifies as not-found", async () => {
    const result = await readKeychainKeyStatus(
      "sanctuary-custody-test",
      backend("darwin", { code: 44, stderr: "could not be found" }),
    );
    expect(result.status).toBe("not-found");
  });

  it("a present 32-byte item classifies as found and returns the key", async () => {
    const result = await readKeychainKeyStatus(
      "sanctuary-custody-test",
      backend("darwin", { code: 0, stdout: KEY_B64 + "\n" }),
    );
    expect(result.status).toBe("found");
    expect(result.key).toBeInstanceOf(Uint8Array);
    expect(result.key?.length).toBe(32);
  });

  it("Linux empty-stderr miss classifies as not-found", async () => {
    const result = await readKeychainKeyStatus(
      "sanctuary-custody-test",
      backend("linux", { code: 1, stderr: "" }),
    );
    expect(result.status).toBe("not-found");
  });

  it("Linux D-Bus / locked-collection failure classifies as unreachable", async () => {
    const result = await readKeychainKeyStatus(
      "sanctuary-custody-test",
      backend("linux", {
        code: 1,
        stderr: "Cannot autolaunch D-Bus without X11 $DISPLAY",
      }),
    );
    expect(result.status).toBe("unreachable");
  });

  it("a spawn failure (binary missing) classifies as unreachable, never not-found", async () => {
    const result = await readKeychainKeyStatus("sanctuary-custody-test", {
      platformOverride: "linux",
      exec: async () => {
        throw new Error("ENOENT: secret-tool not found");
      },
    });
    expect(result.status).toBe("unreachable");
  });
});
