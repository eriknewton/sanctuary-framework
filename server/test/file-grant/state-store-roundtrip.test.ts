/**
 * Governed File-Grant v1 -- inspect / export / delete round-trip (DoD gate 3,
 * AGENTS.md Invariant #2).
 *
 * Proves the operator's HONEST inspect/export/delete story over real store
 * code with `MemoryStorage`:
 *   - the record round-trips through the SAME encrypted/signed/monotonic-
 *     versioned StateStore machinery every other piece of Sanctuary state uses
 *     (write/read/list/delete on the `_file_grants` namespace); and
 *   - the operator inspects grants through the operator-facing `file-grant
 *     list` projection path (`listFileGrants`), not through the agent-facing
 *     `state_*` MCP tools.
 *
 * It does NOT claim the record is reachable through the agent-facing
 * `state_read`/`state_list`/`state_export` MCP tools: those correctly REJECT
 * any `_`-prefixed namespace (including `_file_grants`) via the reserved-
 * namespace firewall in cognitive/tools.ts -- the same posture as
 * `_audit`/`_identities`. A grant describes exactly what an agent may read, so
 * it must not be agent-readable through the generic state tools (that would be
 * a policy-inference leak). Invariant #2 is satisfied by the OPERATOR-facing
 * surfaces exercised here, not by agent reachability.
 */

import { describe, expect, it } from "vitest";

import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";
import {
  FileGrantStore,
  FILE_GRANT_NAMESPACE,
  FILE_GRANT_SCHEMA_VERSION,
  listFileGrants,
  type FileGrant,
} from "../../src/file-grant/index.js";

async function makeStore() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("operator", identityEncKey, "passphrase");
  await persistStoredIdentity(storage, masterKey, storedIdentity);
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
    const { stateStore, grantStore } = await makeStore();
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

  it("the operator inspects a grant through the file-grant list path (not the agent state_* tools)", async () => {
    const { grantStore } = await makeStore();
    const grant = makeGrant();
    await grantStore.put(grant);

    // This is the operator-facing inspection surface `sanctuary file-grant
    // list` renders from -- the honest Invariant #2 read path for grants.
    const projected = await listFileGrants(grantStore, new Date("2026-07-07T12:00:00.000Z"));
    expect(projected).toHaveLength(1);
    expect(projected[0]!.grant_id).toBe(grant.grant_id);
    expect(projected[0]!.projected_status).toBe("active");
  });

  it("get returns null for an absent grant id", async () => {
    const { grantStore } = await makeStore();
    expect(await grantStore.get("fg_doesnotexist000")).toBeNull();
  });

  it("lists ALL grants past the 100-key default page (R2-6)", async () => {
    const { grantStore } = await makeStore();
    // The underlying stateStore.list() caps each call at limit=100. A grant set
    // larger than one page must still be fully listed (and therefore fully
    // reconciled) -- grants 101+ must never be silently dropped.
    const COUNT = 101;
    for (let i = 0; i < COUNT; i++) {
      const id = `fg_${i.toString(16).padStart(16, "0")}`;
      await grantStore.put(makeGrant({ grant_id: id, tree_entry: `agent-1/${id}` }));
    }

    const listed = await grantStore.list();
    expect(listed).toHaveLength(COUNT);
    // No duplicates: every grant_id appears exactly once across the pages.
    expect(new Set(listed.map((g) => g.grant_id)).size).toBe(COUNT);
  });
});
