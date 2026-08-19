/**
 * CAPABILITY (STATE-DISCLOSE-UNATTRIB-01), MCP half: the unattributed
 * disclosure is reachable through a WIRED tool built by the production
 * factory, and the copy an agent reads before deciding how to call it says what
 * the tool is and what it is not.
 *
 * The tool `description` is machine-facing product copy, so AGENTS.md assurance
 * rule 9 puts it inside the claim-to-evidence gate rather than outside it. Its
 * assertions here are on the LABELS an agent needs to route correctly - that
 * this is not a verified read, that restoring the writer identity is the real
 * remedy, and that the tool refuses an entry whose writer can be established -
 * because a description that omits any of them invites exactly the misuse the
 * refusal exists to prevent.
 *
 * The handler assertions pin the same structural separation the store-level
 * tests pin, one layer out: what an MCP consumer receives carries neither
 * `value` nor `signature_verified`, so a consumer that treats a tool result as
 * a read result finds no plaintext under the name it expects.
 */
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import {
  generateIdentityId,
  publicKeyToDid,
  type StoredIdentity,
} from "../../src/core/identity.js";
import { hashToString } from "../../src/core/hashing.js";
import {
  deriveNamespaceKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import {
  StateStore,
  UNATTRIBUTED_DISCLOSURE_NOTICE,
  type StateEntry,
} from "../../src/cognitive/state-store.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { UNATTRIBUTED_DISCLOSURE_OPERATION } from "../../src/cognitive/unattributed-disclosure.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const MASTER_KEY = new Uint8Array([
  0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
  0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x10,
  0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
  0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x10,
]);
const WRITER_PRIVATE_KEY = new Uint8Array([
  0x3f, 0x2e, 0x1d, 0x0c, 0x4b, 0x5a, 0x69, 0x78,
  0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
]);

const NAMESPACE = "memories";

interface ToolTextResult {
  content: Array<{ type: string; text: string }>;
}

function parseToolResult(result: unknown): Record<string, unknown> {
  return JSON.parse((result as ToolTextResult).content[0]!.text) as Record<
    string,
    unknown
  >;
}

function makeStoredIdentity(identityEncKey: Uint8Array): StoredIdentity {
  const publicKey = ed25519.getPublicKey(WRITER_PRIVATE_KEY);
  return {
    identity_id: generateIdentityId(publicKey),
    label: "tool-fixture-writer",
    public_key: toBase64url(publicKey),
    did: publicKeyToDid(publicKey),
    created_at: "2026-08-18T00:00:00.000Z",
    key_type: "ed25519",
    key_protection: "recovery-key",
    encrypted_private_key: encrypt(WRITER_PRIVATE_KEY, identityEncKey),
    rotation_history: [],
  };
}

async function makeRig(options?: { withAuditLog?: boolean }) {
  const storage = new MemoryStorage();
  const stateStore = new StateStore(storage, MASTER_KEY);
  const auditLog =
    options?.withAuditLog === false
      ? undefined
      : new AuditLog(storage, MASTER_KEY);
  const identityEncKey = derivePurposeKey(MASTER_KEY, "identity-encryption");
  const identity = makeStoredIdentity(identityEncKey);
  await storage.write(
    "_identities",
    identity.identity_id,
    stringToBytes(
      JSON.stringify(
        encrypt(stringToBytes(JSON.stringify(identity)), identityEncKey)
      )
    )
  );
  const { tools, namespaceRegistry } = createCognitiveTools(
    stateStore,
    storage,
    MASTER_KEY,
    "recovery-key",
    auditLog
  );
  const tool = tools.find(
    (candidate) => candidate.name === UNATTRIBUTED_DISCLOSURE_OPERATION
  );
  return {
    storage,
    stateStore,
    auditLog,
    identity,
    identityEncKey,
    tools,
    tool,
    namespaceRegistry,
  };
}

async function plantUnattributableLegacyEntry(
  storage: MemoryStorage,
  key: string,
  value: string
): Promise<void> {
  const plaintext = stringToBytes(value);
  const entry: StateEntry = {
    v: 1,
    payload: encrypt(plaintext, deriveNamespaceKey(MASTER_KEY, NAMESPACE)),
    ver: 1,
    // ED25519_SIGNATURE_BYTES = 64; the value is irrelevant because no key
    // resolves for `kid`, which is the point of this fixture.
    sig: toBase64url(new Uint8Array(64)),
    kid: "sanctuary-no-such-writer-identity",
    integrity_hash: hashToString(plaintext),
    metadata: { written_at: "2026-08-18T00:00:06.000Z" },
  };
  await storage.write(NAMESPACE, key, stringToBytes(JSON.stringify(entry)));
}

describe("the unattributed-disclosure MCP tool", () => {
  it("is registered by the production factory under the force-pinned operation name", async () => {
    const { tool } = await makeRig();
    // The tier is resolved from the NAME, so a tool registered under any other
    // spelling would classify as unknown rather than as non-relaxable Tier 1.
    expect(tool).toBeDefined();
    expect(tool!.name).toBe("state_disclose_unattributed");
  });

  it("labels itself in the copy an agent routes on", async () => {
    const { tool } = await makeRig();
    const description = tool!.description!;
    expect(description).toMatch(/NOT A VERIFIED READ/i);
    expect(description).toMatch(/writer/i);
    expect(description).toMatch(/RESTORE THE WRITER IDENTITY/i);
    expect(description).toMatch(/Tier 1/i);
    expect(description).toMatch(/REFUSES/);
    // It must not read as a general-purpose read, so the copy names the ordinary
    // path as the one to try first.
    expect(description).toContain("state_read");

    // THE REFUSAL BOUNDS AN AGENT CANNOT DISCOVER BY TRYING CHEAPLY. Reserved
    // `_` namespaces and unowned opaque handles are refused BEFORE the read,
    // but the approval gate runs before that, so an agent that does not know
    // the bound spends a human's Tier-1 approval on a request that could only
    // ever be refused. The copy has to state them, and say to check first.
    expect(description).toContain("_identities");
    expect(description).toContain("mem_*");
    expect(description).toMatch(/reserved namespace/i);
    expect(description).toMatch(/BEFORE asking a human to approve/);

    // And the read-only claim is scoped to the state store, because the CLI
    // transport does deliberately create a disclosure file. A description that
    // said "no durable write other than its own audit record" would be false.
    expect(description).toMatch(/no mutation of the state store/i);
    expect(description).not.toContain("no durable write other than");
  });

  it("returns the distinct shape, not a read result with a flag", async () => {
    const { storage, tool } = await makeRig();
    await plantUnattributableLegacyEntry(storage, "orphaned", "tool-content");

    const payload = parseToolResult(
      await tool!.handler({ namespace: NAMESPACE, key: "orphaned" })
    );
    expect(payload.unattributed_content).toBe("tool-content");
    expect(payload.disclosure_kind).toBe("unattributed_state_content");
    expect(payload.writer).toBe("not_established");
    expect(payload.unattributed_disclosure_notice).toBe(
      UNATTRIBUTED_DISCLOSURE_NOTICE
    );
    // The verified spellings are absent, so a consumer reaching for either gets
    // `undefined` rather than plaintext or a reassuring boolean.
    expect(payload).not.toHaveProperty("value");
    expect(payload).not.toHaveProperty("signature_verified");
  });

  it("refuses through the tool when the writer is establishable", async () => {
    const { tool, stateStore, identity, identityEncKey } = await makeRig();
    await stateStore.write(
      NAMESPACE,
      "attributable",
      "routine-value",
      identity.identity_id,
      identity.encrypted_private_key,
      identityEncKey
    );

    const payload = parseToolResult(
      await tool!.handler({ namespace: NAMESPACE, key: "attributable" })
    );
    expect(payload.error).toBe("writer_is_establishable");
    expect(payload).not.toHaveProperty("unattributed_content");
  });

  it("points an agent at WHICH identity to restore, and labels it a claim", async () => {
    // The description tells an agent the remedy is to restore the writer
    // identity; the result has to name one, or the instruction is not
    // actionable through this surface.
    const { storage, tool } = await makeRig();
    await plantUnattributableLegacyEntry(storage, "orphaned", "tool-content");

    const payload = parseToolResult(
      await tool!.handler({ namespace: NAMESPACE, key: "orphaned" })
    );
    expect(payload.claimed_writer_id).toBe("sanctuary-no-such-writer-identity");
    // Under the `claimed_` spelling only: the attested name stays absent, so a
    // consumer cannot read this as attribution.
    expect(payload).not.toHaveProperty("written_by");
    expect(tool!.description!).toContain("claimed_writer_id");
  });

  it("refuses a reserved namespace, the refusal the CLI verb also makes", async () => {
    // TRANSPORT PARITY. The check lives in the shared operation, so this
    // asserts the tool RENDERS it; the CLI half of the same property is in
    // test/cli/state-disclose-unattributed-cli.test.ts, and the shared-path
    // half is in test/cognitive/state-disclose-unattributed.test.ts.
    const { tool } = await makeRig();
    const payload = parseToolResult(
      await tool!.handler({ namespace: "_reputation", key: "anything" })
    );
    expect(payload.error).toBe("namespace_reserved");
    expect(payload).not.toHaveProperty("unattributed_content");
  });

  it("refuses an opaque memory handle owned by another session", async () => {
    const { tool, namespaceRegistry, auditLog } = await makeRig();
    const someoneElsesHandle =
      namespaceRegistry.issueMemoryHandle("another-identity");

    const payload = parseToolResult(
      await tool!.handler({ namespace: someoneElsesHandle, key: "anything" })
    );
    expect(payload).not.toHaveProperty("unattributed_content");
    // The GENERIC denial, not a specific one: which of "not yours" or "no
    // session" it was is not something the caller is told, so the denial leaks
    // no structure about the fortress.
    expect(payload.denied).toBe(true);
    expect(payload.audit_ref).toBe(`audit:${UNATTRIBUTED_DISCLOSURE_OPERATION}`);

    // And the denial is on the record, written by the shared operation rather
    // than by this transport.
    const denials = await auditLog!.query({
      operation_type: UNATTRIBUTED_DISCLOSURE_OPERATION,
    });
    expect(denials.entries).toHaveLength(1);
    expect(denials.entries[0]!.details).toMatchObject({
      denial_class: "namespace_unavailable",
    });
  });

  it("fails closed when the server has no audit log, rather than disclosing unrecorded", async () => {
    // The audit record is the only trace this hole was used, so an unauditable
    // invocation must not happen at all. `auditLog` is optional on the factory
    // and the shared audit helper no-ops when it is absent, which is why this
    // path needs its own refusal rather than inheriting one.
    const { storage, tool } = await makeRig({ withAuditLog: false });
    await plantUnattributableLegacyEntry(storage, "orphaned", "tool-content");

    const payload = parseToolResult(
      await tool!.handler({ namespace: NAMESPACE, key: "orphaned" })
    );
    expect(payload.error).toBe("unattributed_disclosure_unavailable");
    expect(payload).not.toHaveProperty("unattributed_content");
  });
});
