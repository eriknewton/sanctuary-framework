/**
 * Governed File-Grant v1 -- StateStore persistence (build spec section 3.1).
 *
 * A `FileGrant` is a first-class encrypted state object in the reserved
 * `_file_grants` namespace. This thin wrapper is the ONLY place that knows
 * how a `FileGrant` is serialized into a StateStore entry; `mint.ts` /
 * `revoke.ts` / the CLI all go through it. Because it calls the StateStore's
 * own `write`/`read`/`list`/`delete` methods directly, a grant round-trips
 * through the exact same encrypted, signed, monotonic-versioned, Merkle-
 * verified machinery every other piece of Sanctuary state does (AGENTS.md
 * Invariant #2), even though the reserved `_`-prefix namespace firewall in
 * `cognitive/tools.ts` correctly keeps the agent-facing `state_read`/
 * `state_list`/`state_delete` MCP tools from reaching it directly -- the same
 * posture as `_audit`, `_identities`, and every other internal namespace.
 */

import type { EncryptedPayload } from "../core/encryption.js";
import type { StateStore } from "../cognitive/state-store.js";
import { FILE_GRANT_NAMESPACE, type FileGrant } from "./types.js";

/** The signing identity a `FileGrantStore` writes under. */
export interface FileGrantWriteIdentity {
  identityId: string;
  encryptedPrivateKey: EncryptedPayload;
  identityEncryptionKey: Uint8Array;
}

export class FileGrantStore {
  constructor(
    private readonly stateStore: StateStore,
    private readonly identity: FileGrantWriteIdentity
  ) {}

  async put(grant: FileGrant): Promise<void> {
    await this.stateStore.write(
      FILE_GRANT_NAMESPACE,
      grant.grant_id,
      JSON.stringify(grant),
      this.identity.identityId,
      this.identity.encryptedPrivateKey,
      this.identity.identityEncryptionKey,
      { content_type: "application/json", tags: ["file-grant"] }
    );
  }

  async get(grantId: string): Promise<FileGrant | null> {
    const result = await this.stateStore.read(FILE_GRANT_NAMESPACE, grantId);
    if (!result) return null;
    return JSON.parse(result.value) as FileGrant;
  }

  async list(): Promise<FileGrant[]> {
    const { keys } = await this.stateStore.list(FILE_GRANT_NAMESPACE);
    const grants: FileGrant[] = [];
    for (const { key } of keys) {
      const grant = await this.get(key);
      if (grant) grants.push(grant);
    }
    return grants;
  }

  async remove(grantId: string): Promise<void> {
    await this.stateStore.delete(FILE_GRANT_NAMESPACE, grantId);
  }
}
