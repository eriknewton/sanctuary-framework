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
  securityPostureFromConfig,
  configFromSecurityPosture,
  ConfigDowngradeError,
  type SanctuaryConfig,
} from "../../src/config.js";
import {
  crossCheckConfigBaseline,
  writeAuthenticatedConfigBaseline,
  CONFIG_BASELINE_META_KEY,
} from "../../src/core/config-baseline.js";
import {
  readBaselineEstablishedLatch,
  raiseBaselineEstablishedLatch,
  readEpochWitness,
  EPOCH_WITNESS_META_KEY,
} from "../../src/core/anti-rollback.js";

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

  it("RESEEDS (not bricks) on a recognized older schema (v1 under current)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    // A v1-schema record: marker present, but schema_version 1 and a v1 posture
    // (no dashboard_allow_plaintext_remote field). Its MAC is irrelevant: the
    // schema check fires BEFORE authentication, so the record is never trusted.
    await storage.write(
      NAMESPACE,
      CONFIG_BASELINE_META_KEY,
      stringToBytes(
        JSON.stringify({
          __sanctuary_config_security_baseline_v1: true,
          data: {
            schema_version: 1,
            observed_at: "2026-01-01T00:00:00.000Z",
            posture: {
              config_version: "1.0.0",
              state_key_protection: "passphrase",
              execution_attestation: true,
              dashboard_tls_configured: true,
              dashboard_auth_configured: true,
              webhook_enabled: true,
              privacy_filter_mode: "local",
              privacy_filter_fail_mode: "closed",
            },
          },
          mac: "stale-v1-mac-not-checked",
        })
      )
    );

    // An operator who upgraded the binary is not an attacker: reseed, do not brick.
    const outcome = await crossCheckConfigBaseline({
      storage,
      master,
      config: strongConfig(),
    });
    expect(outcome.kind).toBe("reseeded");

    // The fresh sealed baseline is a current-schema record under the current
    // master key, so a second boot now authenticates and advances (no longer a
    // migration).
    const envelope = await readEnvelope(storage);
    expect(envelope.__sanctuary_config_security_baseline_v1).toBe(true);
    expect((envelope.data as Record<string, unknown>).schema_version).toBe(3);

    const second = await crossCheckConfigBaseline({
      storage,
      master,
      config: strongConfig(),
    });
    expect(second.kind).toBe("advanced");
  });

  it("RESEEDS (not bricks) on a v2 record under v3 (binary upgrade adds posture fields)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    // A v2-schema record: marker present, schema_version 2, and a v2 posture
    // (has dashboard_allow_plaintext_remote, but lacks the v3 fields:
    // privacy_filter_command, disclosure_default_policy, verascore_auto_publish,
    // erc8004_confirmation_enabled). An operator who upgraded the binary is not
    // an attacker, so v2 reseeds under v3 rather than bricking the boot.
    await storage.write(
      NAMESPACE,
      CONFIG_BASELINE_META_KEY,
      stringToBytes(
        JSON.stringify({
          __sanctuary_config_security_baseline_v1: true,
          data: {
            schema_version: 2,
            observed_at: "2026-02-01T00:00:00.000Z",
            posture: {
              config_version: "1.4.0",
              state_key_protection: "passphrase",
              execution_attestation: true,
              dashboard_tls_configured: true,
              dashboard_auth_configured: true,
              dashboard_allow_plaintext_remote: false,
              webhook_enabled: true,
              privacy_filter_mode: "local",
              privacy_filter_fail_mode: "closed",
            },
          },
          mac: "stale-v2-mac-not-checked",
        })
      )
    );

    const outcome = await crossCheckConfigBaseline({
      storage,
      master,
      config: strongConfig(),
    });
    expect(outcome.kind).toBe("reseeded");

    // The fresh sealed baseline is a v3 record under the current master key, so
    // a second boot now authenticates and advances (no longer a migration).
    const envelope = await readEnvelope(storage);
    expect((envelope.data as Record<string, unknown>).schema_version).toBe(3);

    const second = await crossCheckConfigBaseline({
      storage,
      master,
      config: strongConfig(),
    });
    expect(second.kind).toBe("advanced");
  });

  it("fails closed on an UNKNOWN/FUTURE schema (version > current)", async () => {
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

  it("flags dashboard.allow_plaintext_remote false -> true (and nothing on no-change / true -> false)", () => {
    // false -> true is a downgrade: it permits plaintext HTTP on a routable
    // (non-loopback) dashboard binding.
    const base = strongConfig();
    base.dashboard.allow_plaintext_remote = false;
    const enabled = strongConfig();
    enabled.dashboard.allow_plaintext_remote = true;
    expect(
      detectConfigDowngrades(base, enabled).map((d) => d.reason)
    ).toContain("dashboard_plaintext_remote_enabled");

    // No change (true -> true, false -> false) is not a downgrade.
    expect(
      detectConfigDowngrades(enabled, structuredClone(enabled)).map(
        (d) => d.reason
      )
    ).not.toContain("dashboard_plaintext_remote_enabled");
    expect(
      detectConfigDowngrades(base, structuredClone(base)).map((d) => d.reason)
    ).not.toContain("dashboard_plaintext_remote_enabled");

    // true -> false is a HARDENING, never flagged.
    expect(
      detectConfigDowngrades(enabled, base).map((d) => d.reason)
    ).not.toContain("dashboard_plaintext_remote_enabled");

    // An undefined previous (treated as false) -> true is still a downgrade.
    const undef = strongConfig();
    delete undef.dashboard.allow_plaintext_remote;
    expect(
      detectConfigDowngrades(undef, enabled).map((d) => d.reason)
    ).toContain("dashboard_plaintext_remote_enabled");
  });

  it("flags a privacy_filter.command change while filtering is active (and not when mode is off / unchanged)", () => {
    // Repointing the filter executable while mode stays a filtering mode is a
    // covert disable (e.g. swap to a no-op binary) the mode check alone misses.
    const base = strongConfig();
    base.privacy_filter.mode = "opf";
    base.privacy_filter.command = "opf";
    const repointed = strongConfig();
    repointed.privacy_filter.mode = "opf";
    repointed.privacy_filter.command = "/tmp/noop";
    expect(
      detectConfigDowngrades(base, repointed).map((d) => d.reason)
    ).toContain("privacy_filter_command_changed");

    // No change to the command -> not flagged.
    expect(
      detectConfigDowngrades(base, structuredClone(base)).map((d) => d.reason)
    ).not.toContain("privacy_filter_command_changed");

    // Previous mode "off" -> a command change is not a downgrade (filtering was
    // already disabled; the command is inert).
    const offBase = strongConfig();
    offBase.privacy_filter.mode = "off";
    offBase.privacy_filter.command = "opf";
    const offRepointed = strongConfig();
    offRepointed.privacy_filter.mode = "off";
    offRepointed.privacy_filter.command = "/tmp/noop";
    expect(
      detectConfigDowngrades(offBase, offRepointed).map((d) => d.reason)
    ).not.toContain("privacy_filter_command_changed");
  });

  it("flags disclosure.default_policy loosening (withhold-all -> minimum-necessary) and not the hardening direction", () => {
    const strong = strongConfig();
    strong.disclosure.default_policy = "withhold-all";
    const loosened = strongConfig();
    loosened.disclosure.default_policy = "minimum-necessary";
    expect(
      detectConfigDowngrades(strong, loosened).map((d) => d.reason)
    ).toContain("disclosure_default_policy_loosened");

    // Hardening (minimum-necessary -> withhold-all) is never flagged.
    expect(
      detectConfigDowngrades(loosened, strong).map((d) => d.reason)
    ).not.toContain("disclosure_default_policy_loosened");

    // No change is not flagged.
    expect(
      detectConfigDowngrades(strong, structuredClone(strong)).map((d) => d.reason)
    ).not.toContain("disclosure_default_policy_loosened");
  });

  it("flags verascore auto-publish false -> true (either flag) and not the disabling direction", () => {
    const off = strongConfig();
    off.verascore.auto_publish_to_verascore = false;
    off.verascore.auto_publish_handshakes = false;

    const onPrimary = structuredClone(off);
    onPrimary.verascore.auto_publish_to_verascore = true;
    expect(
      detectConfigDowngrades(off, onPrimary).map((d) => d.reason)
    ).toContain("verascore_autopublish_enabled");

    const onHandshakes = structuredClone(off);
    onHandshakes.verascore.auto_publish_handshakes = true;
    expect(
      detectConfigDowngrades(off, onHandshakes).map((d) => d.reason)
    ).toContain("verascore_autopublish_enabled");

    // Disabling (true -> false) is a hardening, never flagged.
    expect(
      detectConfigDowngrades(onPrimary, off).map((d) => d.reason)
    ).not.toContain("verascore_autopublish_enabled");

    // No change (off -> off) is not flagged.
    expect(
      detectConfigDowngrades(off, structuredClone(off)).map((d) => d.reason)
    ).not.toContain("verascore_autopublish_enabled");
  });

  it("flags erc8004 registry confirmation false -> true and not the disabling direction", () => {
    const off = strongConfig();
    off.erc8004.registry_confirmation.enabled = false;
    const on = strongConfig();
    on.erc8004.registry_confirmation.enabled = true;
    expect(
      detectConfigDowngrades(off, on).map((d) => d.reason)
    ).toContain("erc8004_confirmation_enabled");

    // Disabling is a hardening, never flagged.
    expect(
      detectConfigDowngrades(on, off).map((d) => d.reason)
    ).not.toContain("erc8004_confirmation_enabled");

    // No change is not flagged.
    expect(
      detectConfigDowngrades(off, structuredClone(off)).map((d) => d.reason)
    ).not.toContain("erc8004_confirmation_enabled");
  });

  it("posture round-trips the new v3 fields (command, disclosure policy, verascore, erc8004)", () => {
    const config = strongConfig();
    config.privacy_filter.mode = "opf";
    config.privacy_filter.command = "/opt/opf";
    config.disclosure.default_policy = "minimum-necessary";
    config.verascore.auto_publish_to_verascore = false;
    config.verascore.auto_publish_handshakes = true;
    config.erc8004.registry_confirmation.enabled = true;

    const posture = securityPostureFromConfig(config);
    expect(posture.privacy_filter_command).toBe("/opt/opf");
    expect(posture.disclosure_default_policy).toBe("minimum-necessary");
    // OR of the two auto-publish flags.
    expect(posture.verascore_auto_publish).toBe(true);
    expect(posture.erc8004_confirmation_enabled).toBe(true);

    // Round-trip back through the comparison config preserves the posture so the
    // boot comparator sees the stored values, never a default.
    const rebuilt = configFromSecurityPosture(posture);
    const rebuiltPosture = securityPostureFromConfig(rebuilt);
    expect(rebuiltPosture.privacy_filter_command).toBe("/opt/opf");
    expect(rebuiltPosture.disclosure_default_policy).toBe("minimum-necessary");
    expect(rebuiltPosture.verascore_auto_publish).toBe(true);
    expect(rebuiltPosture.erc8004_confirmation_enabled).toBe(true);
  });

  it("posture round-trip preserves dashboard_allow_plaintext_remote", () => {
    for (const flag of [true, false]) {
      const config = strongConfig();
      config.dashboard.allow_plaintext_remote = flag;

      const posture = securityPostureFromConfig(config);
      expect(posture.dashboard_allow_plaintext_remote).toBe(flag);

      // Round-trip through the comparison config and back must preserve it, so
      // the boot comparator sees the stored value (not a default).
      const rebuilt = configFromSecurityPosture(posture);
      expect(rebuilt.dashboard.allow_plaintext_remote).toBe(flag);
      expect(
        securityPostureFromConfig(rebuilt).dashboard_allow_plaintext_remote
      ).toBe(flag);
    }
  });
});

/**
 * DEBT-1 close-out: deletion-replay + older-schema-reseed, closed by binding the
 * baseline's existence + sealed-schema floor into the boot-anchored monotonic
 * epoch witness (`core/anti-rollback.ts`). The attack under regression: an
 * on-host attacker WITHOUT the master key deletes the single deletable baseline
 * record (or presents a recognized-older-schema record) to re-enter the
 * first-run seed path and seed a DOWNGRADED posture. The witness — a SEPARATE
 * master-MAC'd record — remembers a baseline was established, so the gate now
 * fails closed instead of silently reseeding.
 *
 * The four legs (each a hard requirement):
 *   1. deletion-replay attack        -> fail closed.
 *   2. older-schema-reseed attack     -> fail closed (downgrade reseed).
 *   3. legitimate first run           -> seeds normally (no false rollback).
 *   4. legitimate forward upgrade     -> reseed allowed (no false brick;
 *                                        the #805 reseed-not-brick survives).
 */
describe("config-security baseline — DEBT-1 deletion/downgrade replay (witness-anchored)", () => {
  /** Hand-write an older-schema (v2) baseline record an attacker would forge.
   * The marker is present and the schema is < current, so the reseed branch is
   * reached BEFORE any MAC check — exactly the unauthenticated path DEBT-1
   * closes. The MAC bytes are irrelevant on this path (never verified). */
  async function writeOlderSchemaRecord(
    storage: MemoryStorage,
    schema: number
  ): Promise<void> {
    const envelope = {
      __sanctuary_config_security_baseline_v1: true,
      data: {
        schema_version: schema,
        observed_at: new Date().toISOString(),
        // v2 posture shape (lacks the v3 fields) — irrelevant: the reseed path
        // never trusts the old record's posture.
        posture: { config_version: "1.4.0" },
      },
      mac: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };
    await storage.write(
      NAMESPACE,
      CONFIG_BASELINE_META_KEY,
      stringToBytes(JSON.stringify(envelope))
    );
  }

  it("LEG 1 — deletion-replay: a deleted baseline on a witnessed fortress fails closed", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    // A fortress that has established a strong baseline. The witness now records
    // that a baseline exists (the latch is raised by the gate).
    await crossCheckConfigBaseline({ storage, master, config: strongConfig() });
    expect((await readBaselineEstablishedLatch(storage, master)).established).toBe(
      true
    );

    // The attacker DELETES the single deletable baseline record to replay
    // first-run seeding from a downgraded config (webhook disabled).
    await storage.delete(NAMESPACE, CONFIG_BASELINE_META_KEY);
    expect(await storage.read(NAMESPACE, CONFIG_BASELINE_META_KEY)).toBeNull();

    const weakened = strongConfig();
    weakened.webhook.enabled = false;

    // The witness exposes the deletion → fail closed. The downgraded posture is
    // NOT seeded.
    await expect(
      crossCheckConfigBaseline({ storage, master, config: weakened })
    ).rejects.toMatchObject({
      downgrades: [{ reason: "config_baseline_rollback" }],
    });
    // No fresh (downgraded) baseline was written on the refusal.
    expect(await storage.read(NAMESPACE, CONFIG_BASELINE_META_KEY)).toBeNull();
  });

  it("LEG 2 — older-schema reseed: a backward-schema record after a newer one existed fails closed", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    // A fortress that sealed a CURRENT-schema (v3) baseline: the witness floor is
    // the current schema.
    await crossCheckConfigBaseline({ storage, master, config: strongConfig() });
    const latch = await readBaselineEstablishedLatch(storage, master);
    expect(latch.established).toBe(true);
    expect(latch.sealedSchema).toBeGreaterThanOrEqual(3);

    // The attacker rolls the record back to a hand-written OLDER-schema (v2)
    // record to replay seeding from the current (possibly downgraded) config.
    await writeOlderSchemaRecord(storage, 2);

    await expect(
      crossCheckConfigBaseline({ storage, master, config: strongConfig() })
    ).rejects.toMatchObject({
      downgrades: [{ reason: "config_baseline_rollback" }],
    });
  });

  it("LEG 3 — legitimate first run: no prior witness seeds normally (no false rollback)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    // No baseline, no witness latch — a genuine first boot.
    expect((await readBaselineEstablishedLatch(storage, master)).established).toBe(
      false
    );

    const outcome = await crossCheckConfigBaseline({
      storage,
      master,
      config: strongConfig(),
    });
    expect(outcome.kind).toBe("seeded");

    // The latch is now raised at the current schema so the NEXT deletion is
    // caught — the residual closes forward.
    const after = await readBaselineEstablishedLatch(storage, master);
    expect(after.established).toBe(true);
    expect(after.sealedSchema).toBe(3);
  });

  it("LEG 4 — legitimate forward upgrade: an older-schema record AT/ABOVE the sealed floor reseeds (no brick)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    // Simulate a fortress whose PRIOR binary sealed a v2 baseline: the witness
    // floor is 2 (raised directly, as the prior binary would have).
    await raiseBaselineEstablishedLatch(storage, master, 2);
    expect((await readBaselineEstablishedLatch(storage, master)).sealedSchema).toBe(
      2
    );

    // The operator upgrades the binary (now v3) and the on-disk record is the
    // legitimate prior v2 record. v2 is NOT below the sealed floor (2) → a real
    // forward upgrade, not a downgrade replay.
    await writeOlderSchemaRecord(storage, 2);

    const outcome = await crossCheckConfigBaseline({
      storage,
      master,
      config: strongConfig(),
    });
    // Reseeds rather than bricking (the #805 reseed-not-brick behavior survives).
    expect(outcome.kind).toBe("reseeded");

    // A fresh sealed (current-schema) baseline was minted and the witness floor
    // advanced to the current schema.
    const witness = await readEpochWitness(storage, master);
    expect(witness.status).toBe("valid");
    const after = await readBaselineEstablishedLatch(storage, master);
    expect(after.sealedSchema).toBe(3);
    // The witness record is the SEPARATE deletable location from the baseline.
    expect(await storage.read(NAMESPACE, EPOCH_WITNESS_META_KEY)).not.toBeNull();
  });

  it("LEG 4b — forward upgrade with NO prior schema floor (legacy latch) reseeds, not bricks", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    // A pre-DEBT-1 witness that established the latch WITHOUT a schema floor
    // (legacy). An older-schema record must not be treated as a downgrade when
    // there is no floor to compare against.
    await raiseBaselineEstablishedLatch(storage, master, 0);
    await writeOlderSchemaRecord(storage, 2);

    const outcome = await crossCheckConfigBaseline({
      storage,
      master,
      config: strongConfig(),
    });
    expect(outcome.kind).toBe("reseeded");
  });

  it("witness-untrusted residual: deleting BOTH records re-seeds (and re-raises the latch)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();

    await crossCheckConfigBaseline({ storage, master, config: strongConfig() });

    // The attacker deletes BOTH the baseline record AND the master-MAC'd epoch
    // witness (the documented full-wipe residual on a fortress with no other
    // history). With no trustworthy latch, the gate cannot prove a baseline
    // existed → it re-seeds, but RE-RAISES the latch so the next replay is caught.
    await storage.delete(NAMESPACE, CONFIG_BASELINE_META_KEY);
    await storage.delete(NAMESPACE, EPOCH_WITNESS_META_KEY);
    expect(
      (await readBaselineEstablishedLatch(storage, master)).witnessUntrusted
    ).toBe(true);

    const outcome = await crossCheckConfigBaseline({
      storage,
      master,
      config: strongConfig(),
    });
    expect(outcome.kind).toBe("seeded");
    expect((await readBaselineEstablishedLatch(storage, master)).established).toBe(
      true
    );
  });
});
