/**
 * Task coordination -- a task listing stays available across a row it cannot
 * read (FG-RECONCILE-SIBLINGS-01).
 *
 * CAPABILITY ASSERTED HERE. `TaskService.list` reads its rows through the
 * shared per-entry-tolerant namespace scan, so a stored row that does not read
 * back is skipped and recorded rather than propagated. That listing backs the
 * hub tasks endpoint, the CLI task list, and the concierge's task-state
 * surface, and the concierge fans its six surfaces out through `Promise.all`,
 * so the reach of a propagating row error is all three consumers at once.
 *
 * The paired honesty assertion is that the skipped row is written to the audit
 * trail. A listing that is quietly shorter than the truth reads as a listing
 * with nothing missing, which is the same conflation in the other direction.
 *
 * `get()` is asserted to keep propagating: a caller asking for ONE task by id
 * must never be told it does not exist when it merely did not read.
 *
 * FAULT SCHEDULE EXERCISED (AGENTS.md rule 12): a per-row read rejection inside
 * the listing fan-out, and separately a row whose stored shape does not
 * normalize.
 */

import { describe, expect, it } from "vitest";

import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { createIdentity } from "../../../src/core/identity.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { StateStore } from "../../../src/cognitive/state-store.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import {
  TASK_NAMESPACE,
  TaskService,
} from "../../../src/operational/task-coordination/index.js";
import { SanctuaryContextReader } from "../../../src/concierge/sanctuary-context-reader.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { persistStoredIdentity } from "../../util/persist-stored-identity.js";

const FORTRESS_ID = "fortress-a";

async function makeService() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("operator", identityEncryptionKey, "recovery-key");
  await persistStoredIdentity(storage, masterKey, storedIdentity);
  const service = new TaskService({
    stateStore,
    auditLog,
    fortressId: FORTRESS_ID,
    identityId: storedIdentity.identity_id,
    signingIdentity: storedIdentity,
    identityEncryptionKey,
    now: () => new Date("2026-05-16T12:00:00.000Z"),
  });
  return { service, stateStore, auditLog, storage, masterKey, storedIdentity };
}

/**
 * Make one stored task key's read reject, the way a row whose writer key cannot
 * be resolved does, while every other key still reads. Patching `read` only
 * leaves the key in the enumeration, so the fan-out genuinely has to survive it
 * rather than never seeing it.
 */
function failReadFor(stateStore: StateStore, keySuffix: string, message: string): void {
  const realRead = stateStore.read.bind(stateStore);
  stateStore.read = (async (namespace: string, key: string, ...rest: unknown[]) => {
    if (namespace === TASK_NAMESPACE && key.endsWith(keySuffix)) throw new Error(message);
    return (realRead as (...args: unknown[]) => unknown)(namespace, key, ...rest);
  }) as typeof stateStore.read;
}

describe("TaskService.list: one unread row never empties the listing", () => {
  it("returns every readable task when one row does not read back", async () => {
    const { service, stateStore } = await makeService();

    const readable = await service.create({ title: "Readable", creator: "operator" });
    const broken = await service.create({ title: "Broken", creator: "operator" });

    failReadFor(stateStore, broken.id, "writer key could not be resolved");

    const listed = await service.list();
    expect(listed.map((task) => task.id)).toEqual([readable.id]);
  });

  it("returns every readable task when one row does not normalize", async () => {
    const { service, stateStore, storedIdentity, masterKey } = await makeService();

    const readable = await service.create({ title: "Readable", creator: "operator" });
    // A stored row missing the fields `normalizeTask` requires: present in the
    // enumeration, decodes as JSON, and then rejects during normalization.
    await stateStore.write(
      TASK_NAMESPACE,
      `${FORTRESS_ID}/not-a-task`,
      JSON.stringify({ id: "not-a-task" }),
      storedIdentity.identity_id,
      storedIdentity.encrypted_private_key,
      derivePurposeKey(masterKey, "identity-encryption"),
      { content_type: "application/json", tags: ["task"] },
    );

    const listed = await service.list();
    expect(listed.map((task) => task.id)).toEqual([readable.id]);
  });

  it("records each skipped row in the audit trail rather than dropping it silently", async () => {
    const { service, stateStore, auditLog } = await makeService();

    await service.create({ title: "Readable", creator: "operator" });
    const broken = await service.create({ title: "Broken", creator: "operator" });

    failReadFor(stateStore, broken.id, "writer key could not be resolved");

    await service.list();

    const entries = (await auditLog.query({ limit: 200 })).entries;
    const recorded = entries.filter(
      (entry) => entry.operation === "task.list_row_unreadable",
    );
    expect(recorded).toHaveLength(1);
    expect((recorded[0]!.details as { state_key?: string }).state_key).toContain(broken.id);
    expect(recorded[0]!.result).toBe("failure");
  });

  it("still propagates from get(), so one task by id is never reported as absent", async () => {
    const { service, stateStore } = await makeService();

    const broken = await service.create({ title: "Broken", creator: "operator" });
    failReadFor(stateStore, broken.id, "writer key could not be resolved");

    await expect(service.get(broken.id)).rejects.toThrow(
      /writer key could not be resolved/,
    );
  });

  it("keeps the concierge's whole context bundle intact across an unread task row", async () => {
    const { service, stateStore, auditLog } = await makeService();

    const readable = await service.create({ title: "Readable", creator: "operator" });
    const broken = await service.create({ title: "Broken", creator: "operator" });
    failReadFor(stateStore, broken.id, "writer key could not be resolved");

    // The concierge reads its surfaces through `Promise.all`, so this asserts
    // the blast the tolerance prevents: not just the task surface, but the
    // audit, identity, inbox, profile, and state-store surfaces beside it.
    const reader = new SanctuaryContextReader({
      auditLog,
      identityManager: { listWithRotationCount: () => [] },
      inboxSources: {
        listPendingApprovals: () => [],
        listRecentBlockedEgress: () => [],
        listRecentPrivacyEvents: () => [],
        listActiveBudgetWarnings: () => [],
        listActiveRecoveryPrompts: () => [],
        listRecentAgentErrors: () => [],
      },
      identityId: "operator",
      fortressId: FORTRESS_ID,
      taskService: service,
    } as unknown as ConstructorParameters<typeof SanctuaryContextReader>[0]);

    const bundle = await reader.readContext({ question: "what tasks are open?" });

    expect(bundle.task_state.total).toBe(1);
    expect(bundle.task_state.tasks.map((task) => task.id)).toEqual([readable.id]);
    expect(bundle.read_surfaces.length).toBeGreaterThan(0);
    expect(bundle.identity_registry).toBeDefined();
    expect(bundle.approval_inbox).toBeDefined();
  });
});
