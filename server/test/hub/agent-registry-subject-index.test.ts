import { describe, expect, it, vi } from "vitest";
import { InMemoryLocalAgentRegistry } from "../../src/hub/agent-registry.js";
import { enrolledAgentBindingForVerifiedSubject } from "../../src/hub/agent-attribution.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { BlockedEgressMetadata } from "../../src/contracts/v1.1/blocked-egress.js";
const OWNER = "operator";
const record = (agent_id: string, protection_subject: string, identity_id = OWNER): LocalAgentRecord => ({
  version: "1.1", agent_id, protection_subject, identity_id, harness: "other", model_provider: { vendor: "local", model_id: "test", runs_locally: true },
  policy_id: "policy", status: "active", budget_summary: { last_refreshed_at: "2026-06-14T00:00:00Z" }, last_activity_at: "2026-06-14T00:00:00Z", wrapped_at: "2026-06-14T00:00:00Z",
  capabilities: { can_pause: false, can_resume: false, can_restart: false, can_unwrap: false, can_lockdown: false, can_chat: false, can_change_template: false },
});
const metadata = (subject = "subject"): BlockedEgressMetadata => ({ subject, attribution: { subject: "castle_wall_producer", evidence_source: "producer_signature", verifier: "castle_wall_audit_consumer", state: "verified" } });
describe("enrolled protection subject binding", () => {
  it("binds only a unique same-owner verified subject without scanning the roster", () => {
    const registry = new InMemoryLocalAgentRegistry([record("agent", "subject")]);
    const list = vi.spyOn(registry, "list").mockImplementation(() => { throw new Error("No roster scan"); });
    const lookup = registry.lookupProtectionSubject.bind(registry);
    expect(enrolledAgentBindingForVerifiedSubject(metadata(), OWNER, lookup)).toEqual({ agent_binding: "bound", agent_id: "agent" });
    expect(enrolledAgentBindingForVerifiedSubject(metadata("missing"), OWNER, lookup)).toEqual({ agent_binding: "unattributed" });
    expect(enrolledAgentBindingForVerifiedSubject(metadata(), "foreign", lookup)).toEqual({ agent_binding: "unattributed" });
    expect(enrolledAgentBindingForVerifiedSubject({ ...metadata(), attribution: { ...metadata().attribution, state: "unverified" } }, OWNER, lookup)).toEqual({ agent_binding: "unattributed" });
    expect(enrolledAgentBindingForVerifiedSubject(metadata(), OWNER)).toEqual({ agent_binding: "unattributed" });
    registry.put(record("second", "subject"));
    expect(lookup("subject")).toEqual({ kind: "ambiguous" });
    expect(enrolledAgentBindingForVerifiedSubject(metadata(), OWNER, lookup)).toEqual({ agent_binding: "unattributed" });
    expect(list).not.toHaveBeenCalled();
  });
  it("moves changed subjects on put and clears uniqueness on remove", () => {
    const registry = new InMemoryLocalAgentRegistry([record("agent", "old"), record("second", "old")]);
    expect(registry.lookupProtectionSubject("old").kind).toBe("ambiguous");
    registry.put(record("agent", "new"));
    expect(registry.lookupProtectionSubject("old")).toEqual({ kind: "unique", record: record("second", "old") });
    expect(registry.lookupProtectionSubject("new")).toEqual({ kind: "unique", record: record("agent", "new") });
    registry.remove("second"); expect(registry.lookupProtectionSubject("old")).toEqual({ kind: "none" });
    registry.remove("agent"); expect(registry.lookupProtectionSubject("new")).toEqual({ kind: "none" });
  });
});
