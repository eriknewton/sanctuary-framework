// fail-before-exempt: pins that every content tool refuses or skips the local store names before storage access.
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, expect, it, vi } from "vitest";
import * as router from "../../src/router.js";
import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AGENT_DISCOVERY_SKIPPED_NAMESPACES } from "../../src/storage/agent-discovery.js";
import { derivePurposeKey, IDENTITY_ENCRYPTION_PURPOSE } from "../../src/core/key-derivation.js";
import { sign } from "../../src/core/identity.js";
import { sdwManifestCanonicalBytes, type SdwExportManifestBody } from "../../src/sdw/export.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import { createTempFortress, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

type Args = Record<string, unknown>;
type Driver = { class: "no_namespace_input"; reason: string } |
  { class: "addresses_namespace" | "skips_reserved_namespace"; reason: string; args: (name: string) => Promise<Args | Args[]> | Args | Args[] };
const namespaceArgs = (namespace: string) => ({ namespace, key: "one" });
const facadeArgs = (namespace: string) => ({ key: "one", opts: { namespace } });
const importBundles = new Map<string, string>();
const sdwBundles = new Map<string, string>();
const drivers: Record<string, Driver> = {
  "identity_create": { class: "no_namespace_input", reason: "takes label; none selects a storage namespace" },
  "identity_import": { class: "no_namespace_input", reason: "takes identity; none selects a storage namespace" },
  "identity_list": { class: "no_namespace_input", reason: "takes filter; none selects a storage namespace" },
  "identity_sign": { class: "no_namespace_input", reason: "takes identity_id, payload; none selects a storage namespace" },
  "identity_verify": { class: "no_namespace_input", reason: "takes payload, signature, identity_id, public_key; none selects a storage namespace" },
  "identity_rotate": { class: "no_namespace_input", reason: "takes identity_id, reason; none selects a storage namespace" },
  "identity_set_primary": { class: "no_namespace_input", reason: "takes identity_id; none selects a storage namespace" },
  "state_write": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: (namespace) => ({ ...namespaceArgs(namespace), value: "fixture" }) },
  "state_read": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: namespaceArgs },
  "state_disclose_unattributed": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: namespaceArgs },
  "state_list": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: (namespace) => ({ namespace }) },
  "state_delete": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: namespaceArgs },
  "state_export": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: (namespace) => ({ namespace }) },
  "state_import": { class: "skips_reserved_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: (namespace) => ({ bundle: importBundles.get(namespace)!, allow_unverified_legacy: true }) },
  "exec_attest": { class: "no_namespace_input", reason: "takes include_hardware, include_software, include_network; none selects a storage namespace" },
  "monitor_health": { class: "no_namespace_input", reason: "takes no input fields" },
  "monitor_audit_log": { class: "no_namespace_input", reason: "takes since, layer, operation_type, limit; none selects a storage namespace" },
  "proof_commitment": { class: "no_namespace_input", reason: "takes value, blinding_factor; none selects a storage namespace" },
  "proof_reveal": { class: "no_namespace_input", reason: "takes commitment, value, blinding_factor; none selects a storage namespace" },
  "disclosure_set_policy": { class: "no_namespace_input", reason: "takes policy_name, rules, default_action, identity_id, policy_id; none selects a storage namespace" },
  "disclosure_evaluate": { class: "no_namespace_input", reason: "takes context, requested_fields, policy_id; none selects a storage namespace" },
  "zk_commit": { class: "no_namespace_input", reason: "takes value; none selects a storage namespace" },
  "zk_prove": { class: "no_namespace_input", reason: "takes value, blinding_factor, commitment; none selects a storage namespace" },
  "zk_verify": { class: "no_namespace_input", reason: "takes proof; none selects a storage namespace" },
  "zk_range_prove": { class: "no_namespace_input", reason: "takes value, blinding_factor, commitment, min, max; none selects a storage namespace" },
  "zk_range_verify": { class: "no_namespace_input", reason: "takes proof; none selects a storage namespace" },
  "reputation_record": { class: "no_namespace_input", reason: "takes interaction_id, counterparty_did, outcome, context, counterparty_attestation, identity_id; none selects a storage namespace" },
  "reputation_query": { class: "no_namespace_input", reason: "takes context, time_range, metrics, counterparty_did; none selects a storage namespace" },
  "reputation_export": { class: "no_namespace_input", reason: "takes format, context, identity_id; none selects a storage namespace" },
  "reputation_import": { class: "no_namespace_input", reason: "takes bundle, allow_unverified_legacy; none selects a storage namespace" },
  "reputation_query_weighted": { class: "no_namespace_input", reason: "takes metric, context, counterparty_did; none selects a storage namespace" },
  "bootstrap_create_escrow": { class: "no_namespace_input", reason: "takes transaction_terms, collateral_amount, counterparty_did, timeout_seconds, identity_id; none selects a storage namespace" },
  "bootstrap_provide_guarantee": { class: "no_namespace_input", reason: "takes principal_identity_id, agent_identity_id, scope, duration_seconds, max_liability; none selects a storage namespace" },
  "reputation_publish": { class: "no_namespace_input", reason: "takes type, verascore_agent_id, verascore_url, data, identity_id; none selects a storage namespace" },
  "principal_policy_view": { class: "no_namespace_input", reason: "takes include_defaults; none selects a storage namespace" },
  "principal_baseline_view": { class: "no_namespace_input", reason: "takes no input fields" },
  "shr_generate": { class: "no_namespace_input", reason: "takes identity_id, validity_minutes; none selects a storage namespace" },
  "shr_verify": { class: "no_namespace_input", reason: "takes shr; none selects a storage namespace" },
  "shr_gateway_export": { class: "no_namespace_input", reason: "takes format, identity_id, validity_minutes; none selects a storage namespace" },
  "handshake_initiate": { class: "no_namespace_input", reason: "takes identity_id; none selects a storage namespace" },
  "handshake_respond": { class: "no_namespace_input", reason: "takes challenge, identity_id; none selects a storage namespace" },
  "handshake_complete": { class: "no_namespace_input", reason: "takes session_id, response; none selects a storage namespace" },
  "handshake_status": { class: "no_namespace_input", reason: "takes session_id, completion; none selects a storage namespace" },
  "handshake_exchange": { class: "no_namespace_input", reason: "takes counterparty_shr, identity_id; none selects a storage namespace" },
  "handshake_verify_attestation": { class: "no_namespace_input", reason: "takes attestation; none selects a storage namespace" },
  "handshake_abort": { class: "no_namespace_input", reason: "takes session_id, reason; none selects a storage namespace" },
  "federation_peers": { class: "no_namespace_input", reason: "takes action, peer_id, peer_did, active_only; none selects a storage namespace" },
  "federation_trust_evaluate": { class: "no_namespace_input", reason: "takes peer_id, mutual_attestation_count, reputation_score; none selects a storage namespace" },
  "federation_status": { class: "no_namespace_input", reason: "takes no input fields" },
  "bridge_commit": { class: "no_namespace_input", reason: "takes session_id, protocol_version, proposer_did, acceptor_did, terms, terms_hash, rounds, accepted_at, session_receipt, identity_id, include_pedersen; none selects a storage namespace" },
  "bridge_verify": { class: "no_namespace_input", reason: "takes bridge_commitment_id, committer_public_key, outcome; none selects a storage namespace" },
  "bridge_attest": { class: "no_namespace_input", reason: "takes bridge_commitment_id, outcome_result, metrics, identity_id; none selects a storage namespace" },
  "sovereignty_audit": { class: "no_namespace_input", reason: "takes deep_scan; none selects a storage namespace" },
  "audit_export_siem": { class: "no_namespace_input", reason: "takes format, since, until, limit, filter_tool, filter_decision, filter_layer, filter_result; none selects a storage namespace" },
  "context_gate_recommend": { class: "no_namespace_input", reason: "takes context, provider; none selects a storage namespace" },
  "context_gate_filter": { class: "no_namespace_input", reason: "takes policy_id, provider, context; none selects a storage namespace" },
  "context_gate_list_policies": { class: "no_namespace_input", reason: "takes no input fields" },
  "context_gate_enforcer_status": { class: "no_namespace_input", reason: "takes no input fields" },
  "context_gate_enforcer_configure": { class: "no_namespace_input", reason: "takes enabled, log_only, default_policy_id, on_deny, reset_stats; none selects a storage namespace" },
  "l2_hardening_status": { class: "no_namespace_input", reason: "takes include_details; none selects a storage namespace" },
  "l2_verify_isolation": { class: "no_namespace_input", reason: "takes check_filesystem, check_memory, check_process; none selects a storage namespace" },
  "sovereignty_profile_get": { class: "no_namespace_input", reason: "takes no input fields" },
  "sovereignty_profile_update": { class: "no_namespace_input", reason: "takes audit_logging, injection_detection, context_gating, approval_gate, zk_proofs; none selects a storage namespace" },
  "sovereignty_profile_generate_prompt": { class: "no_namespace_input", reason: "takes no input fields" },
  "sanctuary_bootstrap": { class: "no_namespace_input", reason: "takes label, verascore_url, publish; none selects a storage namespace" },
  "sanctuary_policy_status": { class: "no_namespace_input", reason: "takes no input fields" },
  "sanctuary_export_identity_bundle": { class: "no_namespace_input", reason: "takes identity_id, attestations; none selects a storage namespace" },
  "sanctuary_link_to_human": { class: "no_namespace_input", reason: "takes email, verascore_url; none selects a storage namespace" },
  "sanctuary_sign_challenge": { class: "no_namespace_input", reason: "takes nonce, purpose, identity_id; none selects a storage namespace" },
  "memory_attest": { class: "no_namespace_input", reason: "takes operation, provider, content_hash, memory_id, user_id, agent_id, session_id, scope, identity_id; none selects a storage namespace" },
  "memory_insert": { class: "no_namespace_input", reason: "takes text, taint, tags, passage_id; none selects a storage namespace" },
  "memory_get": { class: "no_namespace_input", reason: "takes passage_id; none selects a storage namespace" },
  "memory_search": { class: "no_namespace_input", reason: "takes text, tag, limit; none selects a storage namespace" },
  "memory_list": { class: "no_namespace_input", reason: "takes limit, after; none selects a storage namespace" },
  "memory_count": { class: "no_namespace_input", reason: "takes no input fields" },
  "memory_delete": { class: "no_namespace_input", reason: "takes passage_id; none selects a storage namespace" },
  "sdw_memory_provenance": { class: "no_namespace_input", reason: "takes passage_id; none selects a storage namespace" },
  "sdw_memory_provenance_migration_status": { class: "no_namespace_input", reason: "takes no input fields" },
  "sdw_memory_provenance_migrate": { class: "no_namespace_input", reason: "takes no input fields" },
  "sdw_memory_provenance_abort_migration": { class: "no_namespace_input", reason: "takes no input fields" },
  "sdw_memory_provenance_repair_completion_marker": { class: "no_namespace_input", reason: "takes no input fields" },
  "memory_provenance_mark_bad_signer": { class: "no_namespace_input", reason: "takes signer_did, public_key_sha256, reason; none selects a storage namespace" },
  "memory_provenance_clear_bad_signer": { class: "no_namespace_input", reason: "takes signer_did, public_key_sha256; none selects a storage namespace" },
  "memory_provenance_prune_signers": { class: "no_namespace_input", reason: "takes no input fields" },
  "memory_ingest": { class: "no_namespace_input", reason: "takes harness, dir, allow_files; none selects a storage namespace" },
  "memory_emit": { class: "no_namespace_input", reason: "takes harness, dir; none selects a storage namespace" },
  "memory_transcode": { class: "no_namespace_input", reason: "takes from_harness, to_harness, dir, mode; none selects a storage namespace" },
  "memory_transcode_restore": { class: "no_namespace_input", reason: "takes archive_id, dir; none selects a storage namespace" },
  "sdw_export": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: (namespace) => ({ export_name: "fixture", namespaces: [namespace] }) },
  "sdw_import": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: (namespace) => ({ bundle: sdwBundles.get(namespace)!, source_key_ref: "this-fortress" }) },
  "compliance_eu_ai_act_annex_iii_classify": { class: "no_namespace_input", reason: "takes description; none selects a storage namespace" },
  "compliance_generate_eu_ai_act_bundle": { class: "no_namespace_input", reason: "takes agent_did, deployment_context, period_start, period_end, delta_from_bundle_path, publish_to_verascore, verascore_url; none selects a storage namespace" },
  "sanctuary/sign_erc8004_identity": { class: "no_namespace_input", reason: "takes registry_address, chain_id, agent_id, nonce, metadata_uri, counterparty, request_id; none selects a storage namespace" },
  "sanctuary/resolve_erc8004_identity": { class: "no_namespace_input", reason: "takes record; none selects a storage namespace" },
  "sanctuary_remember": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: (namespace) => ({ ...facadeArgs(namespace), value: "fixture" }) },
  "sanctuary_recall": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: facadeArgs },
  "sanctuary_hide": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: facadeArgs },
  "sanctuary_forget": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: (namespace) => ({ ...facadeArgs(namespace), mode: "secure", approval_ref: "fixture" }) },
  "sanctuary_help": { class: "no_namespace_input", reason: "takes intent; none selects a storage namespace" },
  "sanctuary_capabilities": { class: "no_namespace_input", reason: "takes no input fields" },
  "sanctuary_who_am_i": { class: "no_namespace_input", reason: "takes no input fields" },
  "sanctuary_active_protections": { class: "no_namespace_input", reason: "takes no input fields" },
  "sanctuary_events_open_cursor": { class: "no_namespace_input", reason: "takes filter, opts; none selects a storage namespace" },
  "sanctuary_events_read": { class: "no_namespace_input", reason: "takes cursor, opts; none selects a storage namespace" },
  "sanctuary_events_close": { class: "no_namespace_input", reason: "takes cursor; none selects a storage namespace" },
  "sanctuary_audit_search": { class: "no_namespace_input", reason: "takes query, scope, limit; none selects a storage namespace" },
  "sanctuary_compound_execute": { class: "addresses_namespace", reason: "accepts a namespace in its direct fields or structured payload", args: (namespace) => ["sanctuary_remember", "sanctuary_recall", "sanctuary_hide", "sanctuary_forget"].map((tool) => ({ steps: [{ tool, args: { ...facadeArgs(namespace), value: "fixture", mode: "secure", approval_ref: "fixture" } }] })) },
  "sanctuary_distress": { class: "no_namespace_input", reason: "takes reason, severity, detail; none selects a storage namespace" },
  "manifest": { class: "no_namespace_input", reason: "takes no input fields" },
  "governor_status": { class: "no_namespace_input", reason: "takes no input fields" },
  "governor_reset": { class: "no_namespace_input", reason: "takes confirm; none selects a storage namespace" },
  "context_gate_set_policy": { class: "no_namespace_input", reason: "takes policy_name, rules, default_action and policy_id; policy storage namespace is fixed" },
  "context_gate_apply_template": { class: "no_namespace_input", reason: "takes a template identifier and policy label; policy storage namespace is fixed" },
};

// The positive control's namespace: an ordinary name every addressing driver must reach with the same input shape.
const ORDINARY_NAMESPACE = "notes";
let fortress: Awaited<ReturnType<typeof createTempFortress>>;
let runtime: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;
let client: Client | undefined;
const storage = new MemoryStorage();
const calls: Array<{ method: string; namespace: string }> = [];
const priorEnv = new Map<string, string | undefined>();
const registrySpy = vi.spyOn(router, "createServer");
beforeAll(async () => {
  fortress = await createTempFortress("local-store-ban");
  for (const key of ["SANCTUARY_AGENT_ID", "SANCTUARY_SESSION_IDENTITY_ID"]) {
    priorEnv.set(key, process.env[key]); delete process.env[key];
  }
  await mkdir(fortress.storagePath, { recursive: true, mode: 0o700 }); // Owner-only fixture root.
  await writeFile(join(fortress.storagePath, "principal-policy.yaml"), generateDefaultPolicyYaml().replace(
    /approval_channel:\n  type: \w+/, "approval_channel:\n  type: callback"), { mode: 0o600 }); // Owner-only policy.
  runtime = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE,
    approvalCallback: async () => ({ decision: "approve", decided_by: "human", decided_at: new Date().toISOString() }) });
  client = new Client({ name: "namespace-ban", version: "1.0.0" });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await runtime.server.connect(st); await client.connect(ct);
  const created = await client.callTool({ name: "identity_create", arguments: { label: "fixture" } });
  expect(created.isError).not.toBe(true);
  const identity = runtime.identityManager.getDefault()!;
  const key = derivePurposeKey(runtime.masterKey, IDENTITY_ENCRYPTION_PURPOSE);
  try {
    for (const namespace of [...AGENT_DISCOVERY_SKIPPED_NAMESPACES, "_identities", ORDINARY_NAMESPACE]) {
      const source = new MemoryStorage();
      const state = new StateStore(source, runtime.masterKey);
      await state.write(namespace, "one", "fixture", identity.identity_id, identity.encrypted_private_key, key);
      const opened = await state.read(namespace, "one", fromBase64url(identity.public_key));
      expect(opened).toMatchObject({ value: "fixture", signature_verified: true, integrity_verified: true });
      const entry = JSON.parse(Buffer.from((await source.read(namespace, "one"))!).toString());
      importBundles.set(namespace, Buffer.from(JSON.stringify({ format: "sanctuary-v1", namespaces: [namespace],
        data: { [namespace]: [{ key: "one", entry }] }, exported_at: "2026-11-22T00:00:00.000Z" })).toString("base64url"));
      const body: SdwExportManifestBody = { version: 1, bundle_version: 1, source_fortress_id: "fixture",
        export_audit_event_id: "fixture", created_at: "2026-11-22T00:00:00.000Z", records: [], hnsw_segments: [] };
      const signature = Buffer.from(sign(sdwManifestCanonicalBytes(body), identity.encrypted_private_key, key)).toString("base64url");
      sdwBundles.set(namespace, Buffer.from(JSON.stringify({ version: 1, exported_at: body.created_at,
        source_fortress_id: body.source_fortress_id, export_audit_event_id: body.export_audit_event_id,
        manifest: { body, signature: { alg: "ed25519", key_ref: identity.identity_id, value: signature } },
        stores: [{ namespace, hkdf_info: "fixture", records: [] }], hnsw_segments: [] })).toString("base64url"));
    }
  } finally { key.fill(0); }
  for (const method of ["read", "readBounded", "write", "delete", "list", "listKeys", "exists"] as const) {
    const original = storage[method].bind(storage) as (...args: unknown[]) => unknown;
    vi.spyOn(storage, method).mockImplementation(((...args: unknown[]) => {
      calls.push({ method, namespace: String(args[0]) }); return original(...args);
    }) as never);
  }
});
afterAll(async () => {
  try {
    try { await client?.close(); } finally { try { await runtime?.cleanup(); } finally { await runtime?.server.close(); } }
  } finally {
    vi.restoreAllMocks();
    for (const [key, value] of priorEnv) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    await fortress?.cleanup();
  }
});

it("the driver table covers exactly the registered tools", async () => {
  const registered = await client!.listTools();
  expect(registered.nextCursor).toBeUndefined();
  const registry = registrySpy.mock.calls[0]![0];
  expect(Object.keys(drivers).sort()).toEqual(registry.map((tool) => tool.name).sort());
  expect(registered.tools.every((tool) => tool.name in drivers)).toBe(true);
});
it("the skip list and the ban cover the same names", () => {
  // Must match AGENT_DISCOVERY_SKIPPED_NAMESPACES in storage/agent-discovery.ts.
  expect(AGENT_DISCOVERY_SKIPPED_NAMESPACES).toEqual(["_local_results", "_local_disclosure", "_local_oplog"]);
  expect(Object.entries(drivers).filter(([, d]) => d.class === "skips_reserved_namespace").map(([name]) => name)).toEqual(["state_import"]);
});
function importResponse(response: Awaited<ReturnType<Client["callTool"]>>) {
  expect(response.isError).not.toBe(true);
  const body = JSON.parse((response.content as Array<{ text: string }>)[0]!.text);
  expect(body.imported_keys).toBe(0);
  expect(body.skipped_keys).toBe(1);
  expect(body.namespaces).toEqual([]);
  delete body.imported_at;
  delete body.audit_ref;
  return { ...response, content: [{ type: "text", text: JSON.stringify(body) }] };
}
it.each(Object.entries(drivers).filter(([, driver]) => driver.class !== "no_namespace_input"))(
  "%s refuses or skips before touching storage", async (tool, driver) => {
    if (driver.class === "no_namespace_input") throw new Error("driver class");
    for (const namespace of AGENT_DISCOVERY_SKIPPED_NAMESPACES) {
      const inputs = await driver.args(namespace);
      for (const args of Array.isArray(inputs) ? inputs : [inputs]) {
        calls.length = 0;
        const response = await client!.callTool({ name: tool, arguments: args });
        expect(calls.filter((call) => call.namespace === namespace), `${tool}: ${namespace}`).toEqual([]);
        if (driver.class === "skips_reserved_namespace") {
          const actual = importResponse(response);
          calls.length = 0;
          const reference = await client!.callTool({ name: tool, arguments: await driver.args("_identities") as Args });
          expect(actual).toEqual(importResponse(reference));
        } else {
          expect(response.isError, `${tool}: ${namespace}`).toBe(true);
        }
      }
    }
  });

// Drivers whose ordinary-namespace input is also refused in this fixture before any namespace handling:
// the SDW vault tools refuse a fortress with a second wrapped-agent identity, the facade tools refuse a raw
// namespace name at their argument gate, and the compound tool refuses those facade steps. For these the
// reserved-name case above shows only that storage under the name was untouched. Pinned so the set cannot
// grow silently; a driver that becomes reachable must leave this list.
const ORDINARY_INPUT_REFUSED = ["sdw_export", "sdw_import", "sanctuary_remember", "sanctuary_recall", "sanctuary_hide",
  "sanctuary_forget", "sanctuary_compound_execute"];
it.each(Object.entries(drivers).filter(([, driver]) => driver.class !== "no_namespace_input"))(
  "%s positive control: the same input with an ordinary namespace is accepted or reaches storage under it", async (tool, driver) => {
    if (driver.class === "no_namespace_input") throw new Error("driver class");
    const inputs = await driver.args(ORDINARY_NAMESPACE);
    for (const args of Array.isArray(inputs) ? inputs : [inputs]) {
      calls.length = 0;
      const response = await client!.callTool({ name: tool, arguments: args });
      const reached = response.isError !== true || calls.some((call) => call.namespace === ORDINARY_NAMESPACE);
      expect(reached, `${tool}: ordinary input`).toBe(!ORDINARY_INPUT_REFUSED.includes(tool));
    }
  });
