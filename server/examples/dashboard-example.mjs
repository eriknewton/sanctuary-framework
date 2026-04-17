// Dashboard visual-check harness.
//
//   npm run build
//   node examples/dashboard-example.mjs
//
// Boots the Sovereignty Dashboard on http://127.0.0.1:3501 with seed
// data so you can eyeball the hero shield, the four layer cards, and
// the live activity / approval panels without running a full MCP server.

import { startDashboard } from "../dist/index.js";

const MODE = process.env.SANCTUARY_DASHBOARD_MODE === "standalone"
  ? "standalone"
  : "co-located";

const FAKE_IDENTITY = {
  getDefault: () => ({
    identity_id: "demo-1",
    label: "Demo Sovereign Agent",
    public_key: "demo-pk",
    did: "did:key:z6MkvDemoAbcDefGhiJklMnoPqrStuVwxYz1234567890",
    created_at: new Date().toISOString(),
    key_type: "ed25519",
    key_protection: "passphrase",
  }),
  list: () => [
    {
      identity_id: "demo-1",
      label: "Demo Sovereign Agent",
      public_key: "demo-pk",
      did: "did:key:z6MkvDemoAbcDefGhiJklMnoPqrStuVwxYz1234567890",
      created_at: new Date().toISOString(),
      key_type: "ed25519",
      key_protection: "passphrase",
    },
  ],
  getPrimaryIdentityId: () => "demo-1",
  get: () => undefined,
};

const FAKE_AUDIT = {
  query: async () => ({
    entries: [
      { timestamp: new Date().toISOString(), layer: "l1", operation: "identity_create", identity_id: "demo-1", result: "success" },
      { timestamp: new Date().toISOString(), layer: "l3", operation: "proof_generate", identity_id: "demo-1", result: "success" },
      { timestamp: new Date().toISOString(), layer: "l4", operation: "reputation_attest", identity_id: "demo-1", result: "success" },
      { timestamp: new Date().toISOString(), layer: "l2", operation: "injection_blocked_latent", identity_id: "demo-1", result: "failure" },
    ],
    total: 4,
  }),
  append: () => {},
  size: 4,
};

const teeFlag = process.env.SANCTUARY_TEE === "1";
const reputation = process.env.SANCTUARY_NO_REP === "1"
  ? undefined
  : { score: 87, profile_url: "https://verascore.ai/p/demo" };

const handle = await startDashboard({
  mode: MODE,
  serverVersion: "0.9.0-dev",
  identityManager: FAKE_IDENTITY,
  auditLog: FAKE_AUDIT,
  teeAvailable: teeFlag,
  ...(reputation ? { reputation } : {}),
  initialActivity: [
    { timestamp: new Date().toISOString(), tool: "state_write", server: "sanctuary", tier: 3, result: "allowed" },
    { timestamp: new Date().toISOString(), tool: "reputation_attest", server: "sanctuary", tier: 3, result: "allowed" },
  ],
  initialPendingApprovals: [
    {
      id: "demo-req-1",
      operation: "state_export",
      tier: 1,
      reason: "Tier 1 export — human approval required",
      created_at: new Date().toISOString(),
    },
  ],
  approvals: {
    allow: async (id) => { console.error("[demo] allow", id); return true; },
    deny: async (id) => { console.error("[demo] deny", id); return true; },
  },
});

let tick = 0;
setInterval(() => {
  tick++;
  handle.publishActivity({
    timestamp: new Date().toISOString(),
    tool: tick % 2 === 0 ? "state_read" : "sign_challenge",
    server: "sanctuary",
    tier: 3,
    result: "allowed",
  });
}, 3000);

console.error(`Dashboard: ${handle.url}`);
console.error("Hero shield state:", teeFlag ? "green (full)" : "green (L2 degraded — normal)");
console.error("Press Ctrl-C to stop.");

const shutdown = async () => {
  await handle.stop();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
