/**
 * Authenticated config-security baseline — the custody-MAC config-downgrade
 * gate (boot step "5rc"; replaces #791's forgeable adjacent baseline file).
 *
 * Threat under regression: an on-host attacker with disk write but WITHOUT the
 * master key weakens the running config (drops dashboard TLS, disables the
 * approval webhook, downgrades key protection) and tries to make the gate
 * accept it. The baseline is MAC-authenticated with a master-key-derived key,
 * so forging it requires the master key the attacker lacks.
 *
 * Each test closes one leg of the fail-closed contract:
 *   - valid baseline + downgrade  -> THROWS (boot refused).
 *   - valid baseline + no change  -> advances (re-MAC).
 *   - tampered MAC                -> FAILS CLOSED (refuse, never re-MAC).
 *   - stripped marker             -> FAILS CLOSED.
 *   - unparseable / schema bad    -> FAILS CLOSED.
 *   - genuine first run           -> seeds.
 *   - the reused detectConfigDowngrades comparator cases.
 *   - cross-key MAC binding: a baseline keyed by master A is rejected under B.
 */

import { describe, it, expect } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";
import {
  defaultConfig,
  detectConfigDowngrades,
  ConfigDowngradeError,
  type SanctuaryConfig,
} from "../../src/config.js";
import {
  crossCheckConfigBaseline,
  writeAuthenticatedConfigBaseline,
  CONFIG_BASELINE_META_KEY,
} from "../../src/core/config-baseline.js";

const NAMESPACE = "_meta";

/** A config with every security knob at its strongest, for downgrade tests. */
function strongConfig(): SanctuaryConfig {
  const config = defaultConfig();
  config.state.key_protection = "passphrase";
  config.execution.attestation = true;
  config.dashboard.auth_token = "secret-token";
  config.dashboard.tls = { cert_path: "/c.pem", key_path: "/k.pem" };
  config.webhook.enabled = true;
  config.privacy_filter.mode = "local";
  config.privacy_filter.fail_mode = "closed";
  return config;
}

async function readEnvelope(
  storage: MemoryStorage
): Promise<Record<string, unknown>> {
  const raw = await storage.read(NAMESPACE, CONFIG_BASELINE_META_KEY);
  expect(raw).not.toBeNull();
  return JSON.parse(bytesToString(raw!)) as Record<string, unknown>;
}

describe("config-security baseline (custody-MAC downgrade gate)", () => {
  it("seeds on a genuine first run (no prior baseline)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    const outcome = await crossCheckConfigBaseline({
      storage,
      master,
      config: strongConfig(),
    });

    expect(outcome.kind).toBe("seeded");
    // A MAC-authenticated record was written.
    const envelope = await readEnvelope(storage);
    expect(envelope.__sanctuary_config_security_baseline_v1).toBe(true);
    expect(typeof envelope.mac).toBe("string");
  });

  it("advances the baseline when there is no downgrade", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const config = strongConfig();

    await crossCheckConfigBaseline({ storage, master, config });
    const firstObservedAt = (
      (await readEnvelope(storage)).data as Record<string, unknown>
    ).observed_at as string;

    // A real clock tick so observed_at is allowed to differ.
    await new Promise((r) => setTimeout(r, 2));

    const outcome = await crossCheckConfigBaseline({ storage, master, config });
    expect(outcome.kind).toBe("advanced");

    const secondObservedAt = (
      (await readEnvelope(storage)).data as Record<string, unknown>
    ).observed_at as string;
    // Re-MAC'd with a fresh timestamp (>= because the resolution may collide).
    expect(secondObservedAt >= firstObservedAt).toBe(true);
  });

  it("REFUSES boot when a valid baseline records a stronger posture (downgrade)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    // Seed the strong posture.
    await crossCheckConfigBaseline({ storage, master, config: strongConfig() });

    // Now boot with the approval webhook disabled — a security downgrade.
    const weakened = strongConfig();
    weakened.webhook.enabled = false;

    await expect(
      crossCheckConfigBaseline({ storage, master, config: weakened })
    ).rejects.toBeInstanceOf(ConfigDowngradeError);
  });

  it("fails closed on a tampered MAC (never re-MACs a forged record)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await crossCheckConfigBaseline({ storage, master, config: strongConfig() });

    // Attacker flips the MAC. They cannot recompute it without the master.
    const envelope = await readEnvelope(storage);
    envelope.mac = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    await storage.write(
      NAMESPACE,
      CONFIG_BASELINE_META_KEY,
      stringToBytes(JSON.stringify(envelope))
    );

    await expect(
      crossCheckConfigBaseline({ storage, master, config: strongConfig() })
    ).rejects.toBeInstanceOf(ConfigDowngradeError);

    // The forged record must NOT have been silently re-MAC'd into a valid one.
    const after = await readEnvelope(storage);
    expect(after.mac).toBe(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
  });

  it("fails closed when the authentication marker is stripped", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await crossCheckConfigBaseline({ storage, master, config: strongConfig() });

    const envelope = await readEnvelope(storage);
    delete envelope.__sanctuary_config_security_baseline_v1;
    await storage.write(
      NAMESPACE,
      CONFIG_BASELINE_META_KEY,
      stringToBytes(JSON.stringify(envelope))
    );

    await expect(
      crossCheckConfigBaseline({ storage, master, config: strongConfig() })
    ).rejects.toBeInstanceOf(ConfigDowngradeError);
  });

  it("fails closed on an unparseable baseline", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await storage.write(
      NAMESPACE,
      CONFIG_BASELINE_META_KEY,
      stringToBytes("{ not json")
    );

    await expect(
      crossCheckConfigBaseline({ storage, master, config: strongConfig() })
    ).rejects.toBeInstanceOf(ConfigDowngradeError);
  });

  it("fails closed on a schema mismatch (valid JSON, wrong shape)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await storage.write(
      NAMESPACE,
      CONFIG_BASELINE_META_KEY,
      stringToBytes(
        JSON.stringify({
          __sanctuary_config_security_baseline_v1: true,
          data: { schema_version: 99, observed_at: "now", posture: {} },
          mac: "x",
        })
      )
    );

    await expect(
      crossCheckConfigBaseline({ storage, master, config: strongConfig() })
    ).rejects.toBeInstanceOf(ConfigDowngradeError);
  });

  it("rejects a baseline minted under a different master key (MAC key binding)", async () => {
    const storage = new MemoryStorage();
    const masterA = generateRandomKey();
    const masterB = generateRandomKey();

    // Minted under A...
    await writeAuthenticatedConfigBaseline(storage, masterA, strongConfig());

    // ...is unauthenticatable under B.
    await expect(
      crossCheckConfigBaseline({
        storage,
        master: masterB,
        config: strongConfig(),
      })
    ).rejects.toBeInstanceOf(ConfigDowngradeError);
  });
});

describe("detectConfigDowngrades comparator (reused #791 logic)", () => {
  it("flags every security weakening and nothing on an identical config", () => {
    const base = strongConfig();
    expect(detectConfigDowngrades(base, structuredClone(base))).toEqual([]);

    const noWebhook = strongConfig();
    noWebhook.webhook.enabled = false;
    expect(
      detectConfigDowngrades(base, noWebhook).map((d) => d.reason)
    ).toContain("webhook_gate_disabled");

    const noTls = strongConfig();
    delete noTls.dashboard.tls;
    expect(detectConfigDowngrades(base, noTls).map((d) => d.reason)).toContain(
      "dashboard_tls_disabled"
    );

    const noAuth = strongConfig();
    delete noAuth.dashboard.auth_token;
    expect(detectConfigDowngrades(base, noAuth).map((d) => d.reason)).toContain(
      "dashboard_auth_disabled"
    );

    const weakerKey = strongConfig();
    weakerKey.state.key_protection = "none";
    expect(
      detectConfigDowngrades(base, weakerKey).map((d) => d.reason)
    ).toContain("state_key_protection_downgrade");

    const noAttest = strongConfig();
    noAttest.execution.attestation = false;
    expect(
      detectConfigDowngrades(base, noAttest).map((d) => d.reason)
    ).toContain("execution_attestation_disabled");

    const failOpen = strongConfig();
    failOpen.privacy_filter.fail_mode = "fallback";
    expect(
      detectConfigDowngrades(base, failOpen).map((d) => d.reason)
    ).toContain("privacy_fail_mode_downgrade");

    const filterOff = strongConfig();
    filterOff.privacy_filter.mode = "off";
    expect(
      detectConfigDowngrades(base, filterOff).map((d) => d.reason)
    ).toContain("privacy_filter_disabled");
  });

  it("flags a version rollback and never echoes secret values", () => {
    const previous = strongConfig();
    previous.version = "2.0.0";
    const next = strongConfig();
    next.version = "1.0.0";
    const downgrades = detectConfigDowngrades(previous, next);
    expect(downgrades.map((d) => d.reason)).toContain("config_version_rollback");

    // The auth-token downgrade reason must redact the secret, never leak it.
    const noAuth = strongConfig();
    delete noAuth.dashboard.auth_token;
    const authDown = detectConfigDowngrades(strongConfig(), noAuth).find(
      (d) => d.reason === "dashboard_auth_disabled"
    );
    expect(authDown?.previous).toBe("configured");
    expect(JSON.stringify(authDown)).not.toContain("secret-token");
  });
});
