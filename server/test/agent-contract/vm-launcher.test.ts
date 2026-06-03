import { describe, expect, it } from "vitest";

import { isSecretEnvKey } from "../../src/agent-contract/adapters/vm-launcher.js";

describe("agent-contract/adapters/vm-launcher", () => {
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
