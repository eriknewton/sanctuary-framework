/** Child witness only: real admission/fence locks, injected private observations. */
import { createSdwFenceFixture } from "./sdw-journal-fixtures.js";
import { withExitAdmissionLock, withSdwJournalAdmission, type ExitAdmissionOwner } from "../../src/storage/exit-import-journal.js";
import { SDW_JOURNAL_NAMESPACES } from "../../src/storage/sdw-journal-contract.js";
import { withCustodyWriteLock } from "../../src/core/master-custody.js";

const [root, mode, owner = "import", custody = "no"] = process.argv.slice(2);
const rig = await createSdwFenceFixture(root);
const original = rig.storage.withNamespaceLock.bind(rig.storage);
rig.storage.withNamespaceLock = (namespace, name, operation, options) => original(namespace, name, async lease => {
  process.send?.({ event: "acquired", namespace, name });
  return operation(lease);
}, { ...options, onContended: attempt => process.send?.({ event: "contended", namespace, name, attempt }) });
const operation = async () => {
  if (mode === "engine") {
    return withSdwJournalAdmission(rig.storage, token => {
      process.send?.({ event: "token" });
      return rig.fence.withEngine(token, "new", SDW_JOURNAL_NAMESPACES, undefined, async () => {
      process.send?.({ event: "callback" });
      });
    });
  }
  return withExitAdmissionLock(rig.storage, owner as ExitAdmissionOwner, async () => { process.send?.({ event: "callback" }); });
};
try {
  if (custody === "yes") await withCustodyWriteLock(rig.storage, operation);
  else await operation();
  process.send?.({ event: "result", status: "ok", trace: rig.trace });
} catch (error) {
  process.send?.({ event: "result", status: "error", reason: (error as { reason?: string }).reason,
    kind: (error as { kind?: string }).kind, message: String(error), trace: rig.trace });
} finally { process.disconnect?.(); }
