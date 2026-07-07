/**
 * Governed File-Grant v1 -- StateStore round-trip (DoD gate 3).
 *
 * Writes a FileGrant to `_file_grants` via `FileGrantStore` (which calls the
 * StateStore's own `write`/`read`/`list`/`delete` methods directly, the
 * exact same encrypted/signed/monotonic-versioned machinery every other
 * piece of Sanctuary state goes through), proving AGENTS.md Invariant #2
 * (inspect/export/delete) over REAL store code with `MemoryStorage`. This
 * deliberately exercises the StateStore methods directly rather than the
 * agent-facing `state_read`/`state_list`/`state_delete` MCP tool handlers in
 * cognitive/tools.ts, which correctly reject any `_`-prefixed namespace
 * (including `_file_grants`) via the reserved-namespace firewall -- the same
 * posture as `_audit`/`_identities`/every other internal namespace. A grant
 * describes exactly what an agent can read; it must not be agent-readable
 * through the generic state tools (that would be a policy-inference leak),
 * so THIS is the correct level to prove the invariant at.
 */

import { describe, expect, it } from "vitest";

import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  FileGrantStore,
  FILE_GRANT_NAMESPACE,
  FILE_GRANT_SCHEMA_VERSION,
  type FileGrant,
} from "../../src/file-grant/index.js";

function makeStore() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("operator", identityEncKey, "passphrase");
  const grantStore = new FileGrantStore(stateStore, {
    identityId: storedIdentity.identity_id,
    encryptedPrivateKey: storedIdentity.encrypted_private_key,
    identityEncryptionKey: identityEncKey,
  });
  return { stateStore, grantStore, identityId: storedIdentity.identity_id };
}

function makeGrant(overrides: Partial<FileGrant> = {}): FileGrant {
  return {
    grant_id: "fg_0123456789abcdef",
    schema_version: FILE_GRANT_SCHEMA_VERSION,
    subject_agent_id: "agent-1",
    scope: { kind: "file", path: "/tmp/example.txt" },
    mode: "read",
    created_by: "operator-identity",
    created_at: "2026-07-07T00:00:00.000Z",
    expires_at: "2026-07-08T00:00:00.000Z",
    status: "active",
    revoked_at: null,
    tree_entry: "agent-1/fg_0123456789abcdef",
    audit_refs: [],
    ...overrides,
  };
}

describe("file-grant StateStore round-trip", () => {
  it("writes, reads, lists, and deletes a grant through real StateStore code", async () => {
    const { stateStore, grantStore } = makeStore();
    const grant = makeGrant();

    await grantStore.put(grant);

    const read = await grantStore.get(grant.grant_id);
    expect(read).toEqual(grant);

    const listed = await grantStore.list();
    expect(listed).toHaveLength(1);
    expect(listed[0]).toEqual(grant);

    // Directly via the StateStore too, proving the namespace + key shape.
    const rawRead = await stateStore.read(FILE_GRANT_NAMESPACE, grant.grant_id);
    expect(rawRead).not.toBeNull();
    expect(JSON.parse(rawRead!.value)).toEqual(grant);

    const rawList = await stateStore.list(FILE_GRANT_NAMESPACE);
    expect(rawList.keys.map((k) => k.key)).toEqual([grant.grant_id]);

    await grantStore.remove(grant.grant_id);
    expect(await grantStore.get(grant.grant_id)).toBeNull();
    const rawAfterDelete = await stateStore.read(FILE_GRANT_NAMESPACE, grant.grant_id);
    expect(rawAfterDelete).toBeNull();
  });

  it("get returns null for an absent grant id", async () => {
    const { grantStore } = makeStore();
    expect(await grantStore.get("fg_doesnotexist000")).toBeNull();
  });
});
