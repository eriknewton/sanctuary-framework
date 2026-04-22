/**
 * Agent Contract v0.1 — Per-agent identity binding tests (§2.2).
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import {
  AGENT_SUBKEY_PURPOSES,
} from "../../src/agent-contract/constants.js";
import {
  bindAgentIdentity,
  deriveAgentKeyWrappingKey,
  deriveAgentSubkey,
  getAgentPublicKey,
  InMemoryAgentKeyStore,
  signWithAgentKey,
  unwrapAgentPrivateKey,
  wrapAgentPrivateKey,
  generateAgentKeypair,
} from "../../src/agent-contract/identity-bind.js";
import { IdentityBindingError } from "../../src/agent-contract/errors.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { buildTestFortress } from "./fixture.js";

describe("Per-agent identity binding (§2.2)", () => {
  it("derives stable wrapping keys for the same (master, agent_id)", () => {
    const f = buildTestFortress();
    const k1 = deriveAgentKeyWrappingKey({
      fortress_master_secret: f.fortressMasterSecret,
      agent_id: "agent-a",
    });
    const k2 = deriveAgentKeyWrappingKey({
      fortress_master_secret: f.fortressMasterSecret,
      agent_id: "agent-a",
    });
    expect(k1).toEqual(k2);
    const k3 = deriveAgentKeyWrappingKey({
      fortress_master_secret: f.fortressMasterSecret,
      agent_id: "agent-b",
    });
    expect(k3).not.toEqual(k1);
  });

  it("derives unrelated subkeys for different purposes", () => {
    const f = buildTestFortress();
    const a = deriveAgentSubkey({
      fortress_master_secret: f.fortressMasterSecret,
      agent_id: "agent-a",
      purpose: "envelope-wrap",
    });
    const b = deriveAgentSubkey({
      fortress_master_secret: f.fortressMasterSecret,
      agent_id: "agent-a",
      purpose: "audit-chain",
    });
    expect(a).not.toEqual(b);
    expect(a.length).toBe(32);
    expect(b.length).toBe(32);
  });

  it("rejects unknown AgentSubkeyPurpose at compile+runtime", () => {
    const f = buildTestFortress();
    expect(() =>
      deriveAgentSubkey({
        fortress_master_secret: f.fortressMasterSecret,
        agent_id: "agent-a",
        purpose: "no-such-purpose" as (typeof AGENT_SUBKEY_PURPOSES)[number],
      })
    ).toThrow(IdentityBindingError);
  });

  it("wraps + unwraps a private seed round-trip under agent:<id> AAD", () => {
    const f = buildTestFortress();
    const { private_key, public_key } = generateAgentKeypair();
    const wrapped = wrapAgentPrivateKey({
      agent_private_key: private_key,
      fortress_master_secret: f.fortressMasterSecret,
      agent_id: "agent-a",
    });
    const unwrapped = unwrapAgentPrivateKey({
      wrapped,
      fortress_master_secret: f.fortressMasterSecret,
      agent_id: "agent-a",
    });
    // Can't compare private_key directly — bindAgentIdentity zeroes it after use,
    // but in this test we generated standalone. Validate via signature round-trip.
    const payload = new TextEncoder().encode("hello");
    const sig = ed25519.sign(payload, unwrapped);
    expect(ed25519.verify(sig, payload, public_key)).toBe(true);
  });

  it("refuses cross-agent AAD substitution", () => {
    const f = buildTestFortress();
    const { private_key } = generateAgentKeypair();
    const wrapped = wrapAgentPrivateKey({
      agent_private_key: private_key,
      fortress_master_secret: f.fortressMasterSecret,
      agent_id: "agent-a",
    });
    expect(() =>
      unwrapAgentPrivateKey({
        wrapped,
        fortress_master_secret: f.fortressMasterSecret,
        agent_id: "agent-b",
      })
    ).toThrow();
  });

  it("bindAgentIdentity produces a binding and signWithAgentKey round-trips", async () => {
    const f = buildTestFortress();
    const store = new InMemoryAgentKeyStore();
    const binding = await bindAgentIdentity({
      agent_id: "agent-a",
      fortress_id: f.master.public.fortress_id,
      fortress_master_secret: f.fortressMasterSecret,
      store,
    });
    expect(binding.agent_pubkey.length).toBeGreaterThan(0);
    expect(await store.list()).toEqual(["agent-a"]);
    const payload = new TextEncoder().encode("hi there");
    const sig = await signWithAgentKey({
      agent_id: "agent-a",
      fortress_master_secret: f.fortressMasterSecret,
      store,
      payload,
    });
    const pub = await getAgentPublicKey({
      agent_id: "agent-a",
      fortress_master_secret: f.fortressMasterSecret,
      store,
    });
    expect(ed25519.verify(sig, payload, pub)).toBe(true);
    // The exported agent_pubkey matches the one we can re-derive.
    expect(fromBase64url(binding.agent_pubkey)).toEqual(pub);
  });

  it("refuses double-binding", async () => {
    const f = buildTestFortress();
    const store = new InMemoryAgentKeyStore();
    await bindAgentIdentity({
      agent_id: "agent-a",
      fortress_id: f.master.public.fortress_id,
      fortress_master_secret: f.fortressMasterSecret,
      store,
    });
    await expect(
      bindAgentIdentity({
        agent_id: "agent-a",
        fortress_id: f.master.public.fortress_id,
        fortress_master_secret: f.fortressMasterSecret,
        store,
      })
    ).rejects.toThrow(IdentityBindingError);
  });

  it("signWithAgentKey throws when agent is not bound", async () => {
    const f = buildTestFortress();
    const store = new InMemoryAgentKeyStore();
    await expect(
      signWithAgentKey({
        agent_id: "nobody",
        fortress_master_secret: f.fortressMasterSecret,
        store,
        payload: new Uint8Array(1),
      })
    ).rejects.toThrow(IdentityBindingError);
  });
});
