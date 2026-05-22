import { buildUpstreamStdioEnv } from "../../../../server/src/proxy/client-manager.js";
import { registerFixture } from "../../registry.js";
import { outcome } from "../state-trust/helpers.js";

const CLAIM_ID = "15";
const CLAIM_LABEL = "Proxy isolation: env (PR #267)";

// Entrypoint: buildUpstreamStdioEnv, the stdio env sanitizer used by ClientManager.
// Mirrored tests: server/test/proxy/client-manager.test.ts.
// Matrix claim: Proxy isolation: env (PR #267).

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-env-isolation: default safe env only", async () => {
  const started = performance.now();
  const env = buildUpstreamStdioEnv(undefined, {
    PATH: "/usr/bin",
    HOME: "/home/operator",
    LANG: "C.UTF-8",
    LC_ALL: "C",
    LC_CTYPE: "UTF-8",
    TZ: "UTC",
    TMPDIR: "/tmp",
    SANCTUARY_PASSPHRASE: "do-not-forward",
    OPENAI_API_KEY: "do-not-forward",
    AWS_SECRET_ACCESS_KEY: "do-not-forward",
    NODE_OPTIONS: "--inspect",
  });

  const passed =
    env.PATH === "/usr/bin" &&
    env.HOME === "/home/operator" &&
    env.LANG === "C.UTF-8" &&
    env.LC_ALL === "C" &&
    env.LC_CTYPE === "UTF-8" &&
    env.TZ === "UTC" &&
    env.TMPDIR === "/tmp" &&
    env.SANCTUARY_PASSPHRASE === undefined &&
    env.OPENAI_API_KEY === undefined &&
    env.AWS_SECRET_ACCESS_KEY === undefined &&
    env.NODE_OPTIONS === undefined &&
    Object.keys(env).length === 7;

  return outcome(started, passed, "expected only default allowlisted stdio env to reach upstream");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-env-isolation: secret env denylist", async () => {
  const started = performance.now();
  const env = buildUpstreamStdioEnv(
    {
      SAFE_FEATURE_FLAG: "enabled",
      project_token: "do-not-forward",
      DB_PASSWORD: "do-not-forward",
      ANTHROPIC_API_KEY: "do-not-forward",
      GOOGLE_SECRET: "do-not-forward",
      AZURE_CLIENT_SECRET: "do-not-forward",
      GCP_PROJECT: "do-not-forward",
      SANCTUARY_PROFILE: "do-not-forward",
      "BAD-NAME": "do-not-forward",
    },
    { PATH: "/bin" },
  );

  const passed =
    env.PATH === "/bin" &&
    env.SAFE_FEATURE_FLAG === "enabled" &&
    env.project_token === undefined &&
    env.DB_PASSWORD === undefined &&
    env.ANTHROPIC_API_KEY === undefined &&
    env.GOOGLE_SECRET === undefined &&
    env.AZURE_CLIENT_SECRET === undefined &&
    env.GCP_PROJECT === undefined &&
    env.SANCTUARY_PROFILE === undefined &&
    env["BAD-NAME"] === undefined;

  return outcome(started, passed, "expected configured secret names and invalid env names denied");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-env-isolation: explicit safe env pass-through", async () => {
  const started = performance.now();
  const env = buildUpstreamStdioEnv(
    {
      SAFE_MODE: "true",
      CACHE_DIR: "/tmp/cache",
      _LEADING_UNDERSCORE: "ok",
      FEATURE_FLAG_2: "ok",
    },
    {
      PATH: "/usr/local/bin",
      HOME: "/home/operator",
    },
  );

  const passed =
    env.PATH === "/usr/local/bin" &&
    env.HOME === "/home/operator" &&
    env.SAFE_MODE === "true" &&
    env.CACHE_DIR === "/tmp/cache" &&
    env._LEADING_UNDERSCORE === "ok" &&
    env.FEATURE_FLAG_2 === "ok";

  return outcome(started, passed, "expected non-secret configured env to pass through");
});
