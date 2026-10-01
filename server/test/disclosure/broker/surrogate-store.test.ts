/**
 * Capability: surrogate values live under a keychain label the broker never
 * queries, so a broker handed any grant for a bound name reads not-found rather
 * than the value. Covers the label derivation, the shared keychain file, and the
 * old-writer case where a pre-existing `secrets grant` writer has added a `read`
 * entry for a bound name.
 *
 * Host-free: an injected in-memory backend through the keychain chokepoint, so
 * no `security` subprocess runs and no operator keychain is opened. The value is
 * generated in the test.
 *
 * Defect id: SURROGATE-BROKER-REACHABLE.
 */

import { describe, expect, it } from "vitest";
import { join } from "node:path";

import type { Backend } from "../../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../../src/disclosure/broker/backend-interface.js";
import {
  SurrogateValueStore,
  surrogateKeychainIdentityFor,
} from "../../../src/disclosure/broker/surrogate-store.js";
import {
  brokerKeychainIdentityFor,
  legacyBrokerKeychainIdentity,
} from "../../../src/disclosure/broker/keychain-backend.js";
import { Broker } from "../../../src/disclosure/broker/broker.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";

const BOUND_VALUE = Buffer.from(generateRandomKey()).toString("base64url");
const HOME = "/tmp/sanctuary-surrogate-store-home";

/**
 * One in-memory keychain FILE holding items for every service, exactly as the
 * real keychain does. A backend view filters by its own service, which is the
 * property under test: the broker's view and the surrogate view share storage
 * and still cannot see each other's items.
 */
function makeSharedKeychain() {
  const items = new Map<string, string>();
  const viewFor = (service: string): Backend => ({
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() {
      return true;
    },
    async addSecret(name, value) {
      const key = `${service} ${name}`;
      if (items.has(key)) throw new Error(`exists: ${name}`);
      items.set(key, value);
    },
    async readSecret(name) {
      const v = items.get(`${service} ${name}`);
      if (v === undefined) throw new SecretNotFoundError(name);
      return v;
    },
    async rotateSecret(name, value) {
      const key = `${service} ${name}`;
      if (!items.has(key)) throw new SecretNotFoundError(name);
      items.set(key, value);
    },
    async deleteSecret(name) {
      if (!items.delete(`${service} ${name}`)) throw new SecretNotFoundError(name);
    },
    async listSecretNames() {
      const prefix = `${service} `;
      return Array.from(items.keys())
        .filter((k) => k.startsWith(prefix))
        .map((k) => k.slice(prefix.length));
    },
  });
  return { items, viewFor };
}

describe("surrogate keychain identity", () => {
  it("shares the keychain file and account namespace with the broker, and only the service differs", () => {
    const storagePath = join(HOME, "fortress-a");
    const broker = brokerKeychainIdentityFor(storagePath, HOME);
    const surrogate = surrogateKeychainIdentityFor(storagePath, HOME);

    // One file, one passphrase, one unlock for the operator.
    expect(surrogate.keychainPath).toBe(broker.keychainPath);
    expect(surrogate.accountNamespace).toBe(broker.accountNamespace);
    expect(surrogate.service).not.toBe(broker.service);
  });

  it("carries the per-fortress digest the broker derives, so two fortresses keep two labels", () => {
    const a = surrogateKeychainIdentityFor(join(HOME, "fortress-a"), HOME);
    const b = surrogateKeychainIdentityFor(join(HOME, "fortress-b"), HOME);
    expect(a.service).not.toBe(b.service);
    expect(a.service.startsWith("sanctuary-surrogate-")).toBe(true);
    // The digest is the broker's own, not a second derivation.
    const brokerA = brokerKeychainIdentityFor(join(HOME, "fortress-a"), HOME);
    expect(a.service.slice("sanctuary-surrogate-".length)).toBe(
      brokerA.service.slice("sanctuary-broker-".length),
    );
  });

  it("the legacy single-tenant fortress gets the bare prefix, matching the broker's shape", () => {
    const legacyBroker = legacyBrokerKeychainIdentity(HOME);
    expect(legacyBroker.service).toBe("sanctuary-broker");
    const surrogate = surrogateKeychainIdentityFor(join(HOME, ".sanctuary"), HOME);
    expect(surrogate.service).toBe("sanctuary-surrogate");
  });
});

describe("a broker cannot reach a value stored under the surrogate label", () => {
  it("a grant for a bound name reads NOT FOUND, whatever the policy file says", async () => {
    const keychain = makeSharedKeychain();
    const storagePath = join(HOME, "fortress-a");
    const identity = surrogateKeychainIdentityFor(storagePath, HOME);
    const brokerIdentity = brokerKeychainIdentityFor(storagePath, HOME);

    const store = new SurrogateValueStore({
      storagePath,
      home: HOME,
      backend: keychain.viewFor(identity.service),
    });
    await store.bindValue("openai-api-key", BOUND_VALUE);

    // THE OLD-WRITER CASE. A pre-existing `secrets grant` writer has put a
    // `read` entry for the bound name into `broker-policy.json`, and the broker
    // in this test is constructed with that grant and with NO knowledge of the
    // binding: the bound set is empty, so nothing but the label is stopping it.
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const broker = new Broker({
      backend: keychain.viewFor(brokerIdentity.service),
      auditLog,
      surrogateBoundSecrets: new Set<string>(),
      principalIdentityId: "did:sanctuary:principal",
    });
    broker.grant({ skill: "mailer", secret: "openai-api-key", scope: "read" });
    const binding = await broker.issueToken({
      skill: "mailer",
      secret: "openai-api-key",
      caller: {
        identity_id: "did:sanctuary:agent",
        skill: "mailer",
        agent: "hermes",
        tenant_id: "t1",
        fortress_id: "f1",
        audience: "broker",
      },
    });

    await expect(broker.readViaToken(binding.token)).rejects.toBeInstanceOf(
      SecretNotFoundError,
    );
    // And the name is not even visible to the broker's inventory.
    expect(await broker.listSecretNames()).not.toContain("openai-api-key");
    // The value IS there, under the other label.
    expect(await store.readValue("openai-api-key")).toBe(BOUND_VALUE);
  });

  it("an existence check never materializes the value", async () => {
    const keychain = makeSharedKeychain();
    const storagePath = join(HOME, "fortress-a");
    const backend = keychain.viewFor(surrogateKeychainIdentityFor(storagePath, HOME).service);
    let reads = 0;
    const counting: Backend = {
      ...backend,
      async readSecret(name) {
        reads += 1;
        return backend.readSecret(name);
      },
    };
    const store = new SurrogateValueStore({ storagePath, home: HOME, backend: counting });
    await store.bindValue("openai-api-key", BOUND_VALUE);
    expect(await store.hasValue("openai-api-key")).toBe(true);
    expect(await store.hasValue("absent-key")).toBe(false);
    expect(reads).toBe(0);
  });

  it("removing a name that is not bound is reported, never silently successful", async () => {
    const keychain = makeSharedKeychain();
    const storagePath = join(HOME, "fortress-a");
    const store = new SurrogateValueStore({
      storagePath,
      home: HOME,
      backend: keychain.viewFor(surrogateKeychainIdentityFor(storagePath, HOME).service),
    });
    await expect(store.removeValue("never-bound")).rejects.toBeInstanceOf(SecretNotFoundError);
  });

  it("listBoundNames returns surrogate names only, never broker names", async () => {
    const keychain = makeSharedKeychain();
    const storagePath = join(HOME, "fortress-a");
    const brokerView = keychain.viewFor(brokerKeychainIdentityFor(storagePath, HOME).service);
    await brokerView.addSecret("sendgrid-key", BOUND_VALUE);
    const store = new SurrogateValueStore({
      storagePath,
      home: HOME,
      backend: keychain.viewFor(surrogateKeychainIdentityFor(storagePath, HOME).service),
    });
    await store.bindValue("openai-api-key", BOUND_VALUE);

    expect(await store.listBoundNames()).toEqual(["openai-api-key"]);
    expect(await brokerView.listSecretNames()).toEqual(["sendgrid-key"]);
  });
});
