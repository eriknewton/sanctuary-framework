import { readFile, readdir } from "node:fs/promises";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  SDW_JOURNAL_NAMESPACES, SDW_MAX_KEY_ENCODED_BYTES, SDW_MAX_PAGE_BYTES,
  SDW_MAX_PLAN_BYTES, SDW_MAX_RECEIPT_BYTES, SDW_MAX_RECORDS, SDW_MAX_STAGED_BYTES,
  SDW_MAX_PAGES, SDW_PAGE_RECORDS, SDW_RECORD_BYTE_LIMITS, SdwStorageError,
  parseSdwJournalRecord, sdwCanonicalBytes, sdwSha256, sdwSigningBytes, sdwSigningReceipt,
  validateSdwPlanClosure, verifySdwCertificate, verifySdwSignedRecord, sdwImageName, sdwPageName, sdwApplyTempName,
  type SdwPlan, type SdwPlanPage, type SdwRecordTypes, type SdwPrimaryVerifier,
} from "../../src/storage/sdw-journal-contract.js";
import { createL1Tools, domainSeparatedSigningBytes, INTERNAL_RECEIPT_SIGNING_DOMAIN } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { isSdwNamespace, assertSdwRawWriteAuthorized } from "../../src/sdw/write-gate.js";
import * as locks from "../../src/storage/cross-process-lock.js";
import * as admission from "../../src/storage/exit-import-journal.js";
import * as custody from "../../src/core/master-custody.js";
import { createSdwSchemaFixture, fixtureEpochs, FIXTURE_TIME } from "./sdw-journal-fixtures.js";

type Fixture = Awaited<ReturnType<typeof createSdwSchemaFixture>>;
let rig: Fixture;
beforeAll(async () => { rig = await createSdwSchemaFixture(); });
afterAll(async () => { await rig?.dispose(); });
afterEach(() => vi.restoreAllMocks());

function rebind(plan: SdwPlan): SdwPlan {
  plan.attestation = sdwSigningReceipt(plan.body, plan.body.created_at);
  return plan;
}
function parse<K extends keyof SdwRecordTypes>(kind: K, value: unknown): SdwRecordTypes[K] {
  return parseSdwJournalRecord(kind, sdwCanonicalBytes(value));
}
function updatePage(plan: SdwPlan, page: SdwPlanPage): Uint8Array[] {
  const raw = sdwCanonicalBytes(page);
  plan.body.pages = [{ page: 0, record_count: page.entries.length, byte_length: raw.length, sha256: sdwSha256(raw) }];
  plan.body.record_count = page.entries.length;
  plan.body.staged_bytes = page.entries.reduce((n, e) => n + e.byte_length, 0);
  rebind(plan);
  return [raw];
}

// Enumerate ALL record fields and array elements, so a new nested field cannot
// silently escape the missing/type/unknown-field witnesses.
function malformedVariants(value: unknown, path = "$", root = value): Array<{ path: string; value: unknown }> {
  const result: Array<{ path: string; value: unknown }> = [];
  function visit(current: unknown, parts: Array<string | number>): void {
    if (!current || typeof current !== "object") return;
    for (const key of Object.keys(current)) {
      const part = Array.isArray(current) ? Number(key) : key;
      const location = [...parts, part];
      const mutate = (mode: "missing" | "null") => {
        const copy = structuredClone(root) as any;
        let parent = copy;
        for (const p of parts) parent = parent[p];
        if (mode === "missing") delete parent[part]; else parent[part] = null;
        return copy;
      };
      if (!Array.isArray(current)) result.push({ path: `${path}.${location.join(".")}:missing`, value: mutate("missing") });
      if ((current as any)[part] !== null) result.push({ path: `${path}.${location.join(".")}:null`, value: mutate("null") });
      visit((current as any)[part], location);
    }
    if (!Array.isArray(current)) {
      const copy = structuredClone(root) as any;
      let target = copy;
      for (const p of parts) target = target[p];
      target.unrecognized = true;
      result.push({ path: `${path}.${parts.join(".")}:unknown`, value: copy });
    }
  }
  visit(value, []);
  return result;
}

describe("SDW canonical journal schema", () => {
  it("uses ten encrypted data rows and two authenticated _sdw_meta MAC-envelope rows, all six exact namespaces, and no journal producer", async () => {
    expect(rig.rows).toHaveLength(12); // two selected rows in each of six namespaces
    for (const row of rig.rows) {
      expect(assertSdwRawWriteAuthorized(row.namespace, row.storageKey, row.data)).toEqual(row.data);
      expect(Buffer.from(row.data).toString()).not.toContain("schema fixture note");
      expect(await rig.storage.read(row.namespace, row.storageKey)).toEqual(row.data);
    }
    expect(validateSdwPlanClosure(rig.plan, rig.pages, rig.receipt)).toEqual([rig.page]);
    expect(SDW_JOURNAL_NAMESPACES.every(isSdwNamespace)).toBe(true);
    for (const ns of ["_sdw_memory_bad_signers", "_sdw_journal_v1", "_sdw_catalog_suffix", "_sdw", "memory"]) {
      const page = structuredClone(rig.page);
      page.entries[0]!.namespace = ns as any;
      expect(() => parse("page", page)).toThrow(SdwStorageError);
    }
    expect(await readdir(rig.root)).not.toContain("_sdw_journal_v1");
    expect(rig.storage).not.toHaveProperty("sdwTransaction");
  });

  it("rejects every missing/wrong field, malformed element and unknown field at every nesting level", async () => {
    const records: { [K in keyof SdwRecordTypes]: SdwRecordTypes[K] } = {
      plan: rig.plan, page: rig.page, certificate: await rig.certificate("COMMIT"),
      prepared: { version: 1, state: "PREPARED", transaction_id: rig.plan.body.transaction_id, plan_sha256: sdwSha256(sdwCanonicalBytes(rig.plan)) },
      generation: { version: 1, epochs: fixtureEpochs(), transaction_id: rig.plan.body.transaction_id, affected_mask: 63, phase: "BUSY" },
    };
    let cases = 0;
    for (const kind of Object.keys(records) as Array<keyof SdwRecordTypes>) {
      expect(parse(kind, records[kind])).toEqual(records[kind]);
      for (const variant of malformedVariants(records[kind])) {
        expect(() => parse(kind, variant.value), `${kind}:${variant.path}`).toThrow(SdwStorageError);
        cases++;
      }
      const unknownVersion = structuredClone(records[kind]) as any;
      if (unknownVersion.body) unknownVersion.body.version = 2; else unknownVersion.version = 2;
      expect(() => parse(kind, unknownVersion)).toThrow(SdwStorageError);
    }
    expect(cases).toBeGreaterThan(250); // twelve entry objects alone contribute 12 * (5 * 2 + 1) cases
  });

  it("rejects duplicate JSON keys, noncanonical encodings, bad UTF-8 and deep input before parsing", () => {
    const canonical = Buffer.from(sdwCanonicalBytes(rig.page)).toString();
    const samples = [
      canonical.replace('"version":1', '"version":1,"version":1'),
      canonical.replace('"ordinal":0', '"ordinal":0,"ordinal":1'),
      canonical.replace('"version":1', '"version":1e0'),
      canonical.replace('"version":1', '"version":1.0'),
      canonical.replace('"ordinal":0', '"ordinal":-0'),
      canonical.replace('"page"', '"\\u0070age"'),
      ` ${canonical}`, `${canonical}\n`, `\ufeff${canonical}`,
      `${"[".repeat(1000)}0${"]".repeat(1000)}`,
    ];
    for (const text of samples) expect(() => parseSdwJournalRecord("page", Buffer.from(text))).toThrow(SdwStorageError);
    expect(() => parseSdwJournalRecord("page", Buffer.from([0xff]))).toThrow(SdwStorageError);
    expect(parseSdwJournalRecord("page", Buffer.from(canonical))).toEqual(rig.page);
  });

  it.each([
    ["ordinal", -1], ["ordinal", 0.5], ["ordinal", SDW_MAX_RECORDS], ["ordinal", Number.MAX_SAFE_INTEGER + 1],
    ["byte_length", 0], ["byte_length", -1], ["byte_length", 0.5], ["byte_length", SDW_MAX_STAGED_BYTES + 1],
    ["target_ciphertext_sha256", "A".repeat(64)], ["target_ciphertext_sha256", "a".repeat(63)],
    ["key", ""], ["key", "."], ["key", ".."], ["key", "\0"], ["key", "\u0100"],
    ["key", "x".repeat(SDW_MAX_KEY_ENCODED_BYTES + 1)],
  ])("rejects malformed entry %s=%s", (field, value) => {
    const page = structuredClone(rig.page);
    (page.entries[0] as any)[field] = value;
    expect(() => parse("page", page)).toThrow(SdwStorageError);
  });

  it("enforces encoded key bytes, identifiers, canonical base64url and declared coverage", () => {
    const page = structuredClone(rig.page);
    page.entries[0]!.key = "x".repeat(SDW_MAX_KEY_ENCODED_BYTES);
    expect(parse("page", page)).toEqual(page);
    // Each ! becomes !21 on disk: 83 * 3 + 2 = 251, one more byte refuses.
    page.entries[0]!.key = "!".repeat(83) + "xx";
    expect(parse("page", page)).toEqual(page);
    page.entries[0]!.key += "x";
    expect(() => parse("page", page)).toThrow(SdwStorageError);
    for (const [field, value] of [
      ["identity_id", "é".repeat(129)], ["fortress_id", ""], ["transaction_id", "a".repeat(31)],
      ["created_at", "tomorrow"], ["signer_public_key", rig.primary.public_key + "="],
      ["namespaces", []], ["namespaces", ["_sdw_catalog", "_sdw_catalog"]],
      ["namespaces", [...SDW_JOURNAL_NAMESPACES].reverse()],
    ]) {
      const plan = structuredClone(rig.plan);
      (plan.body as any)[field as string] = value;
      expect(() => parse("plan", rebind(plan))).toThrow(SdwStorageError);
    }
    const plan = structuredClone(rig.plan);
    plan.body.identity_id = "é".repeat(128); // 256 UTF-8 bytes is accepted
    expect(parse("plan", rebind(plan))).toEqual(plan);
    plan.body.namespaces = ["_sdw_catalog"];
    expect(() => validateSdwPlanClosure(rebind(plan), rig.pages, rig.receipt)).toThrow(SdwStorageError);
  });

  it("rejects page numbering, gaps, duplicate targets and mismatched closure hash/length/totals", () => {
    for (const modify of [
      (p: SdwPlanPage) => { p.page = 1; },
      (p: SdwPlanPage) => { p.page = SDW_MAX_PAGES; },
      (p: SdwPlanPage) => { p.entries[1]!.ordinal = 2; },
      (p: SdwPlanPage) => { p.entries[1]!.key = p.entries[0]!.key; },
      (p: SdwPlanPage) => { p.entries = []; },
      (p: SdwPlanPage) => { p.transaction_id = "b".repeat(32); },
    ]) {
      const page = structuredClone(rig.page), plan = structuredClone(rig.plan);
      modify(page);
      expect(() => validateSdwPlanClosure(plan, updatePage(plan, page), rig.receipt)).toThrow(SdwStorageError);
    }
    for (const field of ["sha256", "byte_length", "record_count", "page"] as const) {
      const plan = structuredClone(rig.plan);
      (plan.body.pages[0] as any)[field] = field === "sha256" ? "0".repeat(64) : plan.body.pages[0]![field] as number + 1;
      expect(() => validateSdwPlanClosure(rebind(plan), rig.pages, rig.receipt)).toThrow(SdwStorageError);
    }
    const plan = structuredClone(rig.plan);
    plan.body.staged_bytes++;
    expect(() => validateSdwPlanClosure(rebind(plan), rig.pages, rig.receipt)).toThrow(SdwStorageError);
    expect(() => validateSdwPlanClosure(rig.plan, [], rig.receipt)).toThrow(SdwStorageError);
    expect(() => validateSdwPlanClosure(rig.plan, rig.pages, Buffer.from("wrong receipt"))).toThrow(SdwStorageError);
  });

  it.each(Object.entries(SDW_RECORD_BYTE_LIMITS))("charges exact canonical UTF-8 N/N+1 bytes for %s", (kind, limit) => {
    // Hard byte-cap witness is separate from the fixed field schema: no padding
    // field is invented to make a structurally smaller v1 marker fill its cap.
    const atLimit = "x".repeat(limit - 2); // two JSON string quotes
    const bytes = sdwCanonicalBytes(atLimit, limit);
    expect(bytes.length).toBe(limit);
    expect(() => sdwCanonicalBytes(atLimit + "x", limit)).toThrow(SdwStorageError);
    expect(() => parseSdwJournalRecord(kind as keyof SdwRecordTypes, Buffer.alloc(limit + 1))).toThrow(SdwStorageError);
  });

  it("accepts exact receipt and staged-byte ceilings, refuses N+1, and accepts empty write sets", () => {
    const plan = structuredClone(rig.plan), page = structuredClone(rig.page);
    page.entries = [{ ...page.entries[0]!, byte_length: SDW_MAX_STAGED_BYTES }];
    const pages = updatePage(plan, page);
    const receipt = Buffer.alloc(SDW_MAX_RECEIPT_BYTES);
    plan.body.receipt_byte_length = receipt.length;
    plan.body.receipt_sha256 = sdwSha256(receipt);
    expect(validateSdwPlanClosure(rebind(plan), pages, receipt)).toHaveLength(1);
    plan.body.receipt_byte_length++;
    expect(() => validateSdwPlanClosure(rebind(plan), pages, Buffer.alloc(SDW_MAX_RECEIPT_BYTES + 1))).toThrow(SdwStorageError);
    plan.body.receipt_byte_length = receipt.length;
    page.entries[0]!.byte_length++;
    expect(() => validateSdwPlanClosure(plan, updatePage(plan, page), receipt)).toThrow(SdwStorageError);
    plan.body.pages = []; plan.body.record_count = 0; plan.body.staged_bytes = 0;
    plan.body.receipt_byte_length = 0; plan.body.receipt_sha256 = sdwSha256(new Uint8Array());
    expect(validateSdwPlanClosure(rebind(plan), [], new Uint8Array())).toEqual([]);
  });

  it("bounds adversarial work at 100000 unique records / 391 pages and detects cross-page duplicates", () => {
    const plan = structuredClone(rig.plan);
    const pages: Uint8Array[] = [];
    plan.body.pages = [];
    plan.body.record_count = SDW_MAX_RECORDS;
    plan.body.staged_bytes = SDW_MAX_RECORDS;
    for (let page = 0; page < SDW_MAX_PAGES; page++) {
      const count = Math.min(SDW_PAGE_RECORDS, SDW_MAX_RECORDS - page * SDW_PAGE_RECORDS);
      const raw = sdwCanonicalBytes({ version: 1, transaction_id: plan.body.transaction_id, page,
        entries: Array.from({ length: count }, (_, offset) => {
          const ordinal = page * SDW_PAGE_RECORDS + offset;
          return { ordinal, namespace: "_sdw_catalog", key: `row-${ordinal}`, byte_length: 1, target_ciphertext_sha256: "a".repeat(64) };
        }),
      });
      pages.push(raw);
      plan.body.pages.push({ page, record_count: count, byte_length: raw.length, sha256: sdwSha256(raw) });
    }
    expect(sdwCanonicalBytes(rebind(plan), SDW_MAX_PLAN_BYTES).length).toBeLessThan(SDW_MAX_PLAN_BYTES);
    const parsed = validateSdwPlanClosure(plan, pages, rig.receipt);
    expect(parsed.reduce((sum, p) => sum + p.entries.length, 0)).toBe(SDW_MAX_RECORDS);
    expect(parsed).toHaveLength(SDW_MAX_PAGES);
    plan.body.record_count++;
    expect(() => parse("plan", rebind(plan))).toThrow(SdwStorageError);
    plan.body.record_count--;
    parsed[1]!.entries[0]!.key = parsed[0]!.entries[0]!.key;
    pages[1] = sdwCanonicalBytes(parsed[1]);
    plan.body.pages[1]!.byte_length = pages[1]!.length;
    plan.body.pages[1]!.sha256 = sdwSha256(pages[1]!);
    expect(() => validateSdwPlanClosure(rebind(plan), pages, rig.receipt)).toThrow(SdwStorageError);
  });

  it("uses bounded deterministic file names without accepting path-shaped identifiers", () => {
    expect(sdwImageName(0)).toBe("000000.bin");
    expect(sdwImageName(SDW_MAX_RECORDS - 1)).toBe("099999.bin");
    expect(sdwPageName(SDW_MAX_PAGES - 1)).toBe("0390.json");
    expect(sdwApplyTempName(rig.plan.body.transaction_id, 0)).toBe(`.sdw-${rig.plan.body.transaction_id}-000000.apply`);
    for (const ordinal of [-1, 0.5, SDW_MAX_RECORDS, Number.NaN, Number.POSITIVE_INFINITY]) expect(() => sdwImageName(ordinal)).toThrow(SdwStorageError);
    expect(() => sdwPageName(SDW_MAX_PAGES)).toThrow(SdwStorageError);
    expect(() => sdwApplyTempName("../target", 0)).toThrow(SdwStorageError);
  });

  it("bounds canonical escaping before allocation and rejects sparse/cyclic/non-JSON input", () => {
    for (const value of ["é", "😀", "\ud800", "\udfff", "\u0000", "\b\t\n\f\r", '"\\']) {
      const actual = Buffer.byteLength(JSON.stringify(value));
      expect(sdwCanonicalBytes(value, actual).length).toBe(actual);
      expect(() => sdwCanonicalBytes(value, actual - 1)).toThrow(SdwStorageError);
    }
    const cycle: unknown[] = []; cycle.push(cycle);
    for (const value of [cycle, new Array(2), undefined, new Date(), Number.NaN, Number.POSITIVE_INFINITY, { absent: undefined }]) expect(() => sdwCanonicalBytes(value)).toThrow(SdwStorageError);
  });

  it("preserves typed reason, decision, transaction and cause", () => {
    const cause = new Error("test failure");
    for (const decision of ["none", "unknown", "committed"] as const) {
      expect(new SdwStorageError("storage_io_failed", decision, rig.plan.body.transaction_id, { cause }))
        .toMatchObject({ reason: "storage_io_failed", decision, transaction_id: rig.plan.body.transaction_id, cause });
    }
  });
});

describe("SDW signing evidence", () => {
  it("has exact canonical byte parity with cognitive's encoder and the real signing helper", async () => {
    const certificates = await Promise.all(["COMMIT", "APPLIED", "RETIRED"].map(s => rig.certificate(s as any)));
    for (const record of [rig.plan, ...certificates]) {
      expect(Buffer.from(sdwSigningBytes(record.attestation)).equals(domainSeparatedSigningBytes(INTERNAL_RECEIPT_SIGNING_DOMAIN, record.attestation))).toBe(true);
      const signed = await rig.helpers.internal_receipt_sign(record.attestation);
      expect(Buffer.from(signed.signed_payload, "base64url")).toEqual(sdwSigningBytes(record.attestation));
      expect(signed.signature).toBe(record.signature);
    }
    const samples = [rig.plan, rig.page, ...certificates, { z: [null, true, false, -0, 1.25], a: 'é😀\u0000"\\\ud800\udfff', "\u0301": "e\u0301", nested: { z: 1, a: 2 } }];
    for (const sample of samples) {
      const expected = domainSeparatedSigningBytes(INTERNAL_RECEIPT_SIGNING_DOMAIN, sample);
      expect(Buffer.concat([Buffer.from(`${INTERNAL_RECEIPT_SIGNING_DOMAIN}\n`), sdwCanonicalBytes(sample)]).equals(expected)).toBe(true);
    }
  });

  it("accepts current and authenticated prior-primary keys; refuses foreign, stored-only and missing/corrupt history", async () => {
    const local = await createSdwSchemaFixture();
    try {
      await expect(verifySdwSignedRecord(local.plan, local.authority)).resolves.toBeUndefined();
      for (const identity of [local.storedOnly, local.foreign]) {
        const plan = structuredClone(local.plan);
        plan.body.identity_id = identity.identity_id; plan.body.signer_public_key = identity.public_key;
        if (identity === local.storedOnly) {
          const signed = await local.signPlan(plan.body);
          await expect(verifySdwSignedRecord(signed, local.authority)).rejects.toBeInstanceOf(SdwStorageError);
        } else await expect(verifySdwSignedRecord(local.signForeign(plan.body), local.authority)).rejects.toBeInstanceOf(SdwStorageError);
      }
      await local.manager.rotate(local.primary.identity_id, "scheduled maintenance");
      await expect(verifySdwSignedRecord(local.plan, local.authority)).resolves.toBeUndefined();
      await expect(verifySdwCertificate(await local.certificate("APPLIED"), local.plan, fixtureEpochs(), local.authority)).resolves.toBeUndefined();
      const rotated = local.manager.getDefault()!;
      const history = structuredClone(rotated.rotation_history);
      rotated.rotation_history = [];
      await expect(verifySdwSignedRecord(local.plan, local.authority)).rejects.toBeInstanceOf(SdwStorageError);
      rotated.rotation_history = history;
      rotated.rotation_history[0]!.rotation_event = "broken";
      await expect(verifySdwSignedRecord(local.plan, local.authority)).rejects.toBeInstanceOf(SdwStorageError);
      await expect(verifySdwSignedRecord(local.plan, undefined as unknown as SdwPrimaryVerifier)).rejects.toMatchObject({ reason: "storage_capability_unavailable" });
      await expect(verifySdwSignedRecord(rig.plan, { ...rig.authority, fortress_id: "different" })).rejects.toBeInstanceOf(SdwStorageError);
      await local.manager.setPrimary(local.storedOnly.identity_id);
      await expect(local.authority.assertCurrent()).rejects.toBeInstanceOf(SdwStorageError);
    } finally { await local.dispose(); }
  });

  it.each(["COMMIT", "APPLIED", "RETIRED"] as const)("binds %s to exact root, fortress, epochs and receipt", async state => {
    const certificate = await rig.certificate(state);
    await expect(verifySdwCertificate(certificate, rig.plan, fixtureEpochs(), rig.authority)).resolves.toBeUndefined();
    for (const field of ["plan_sha256", "fortress_id", "transaction_id", "receipt_sha256", "receipt_byte_length", "epochs"] as const) {
      const changed = structuredClone(certificate);
      if (field === "epochs") changed.body.epochs._sdw_catalog++;
      else if (field === "receipt_byte_length") changed.body[field]++;
      else changed.body[field] = field === "fortress_id" ? "foreign" : (field === "transaction_id" ? "b".repeat(32) : "b".repeat(64));
      changed.attestation = sdwSigningReceipt(changed.body, FIXTURE_TIME);
      changed.signature = Buffer.from(await rig.authority.signReceipt(changed.attestation)).toString("base64url");
      await expect(verifySdwCertificate(changed, rig.plan, fixtureEpochs(), rig.authority)).rejects.toBeInstanceOf(SdwStorageError);
    }
    for (const field of ["subject", "status", "receipt_id", "body_hash"] as const) {
      const changed = structuredClone(certificate);
      (changed.attestation as any)[field] = field === "subject" ? "sdw-storage-plan" : field === "status" ? "issued" : "wrong";
      expect(() => parse("certificate", changed)).toThrow(SdwStorageError);
    }
    const changed = structuredClone(certificate);
    changed.signature = Buffer.alloc(64).toString("base64url");
    await expect(verifySdwSignedRecord(changed, rig.authority)).rejects.toBeInstanceOf(SdwStorageError);
  });

  it("snapshots certificate bindings across asynchronous authority checks", async () => {
    const certificate = await rig.certificate("APPLIED");
    const original = structuredClone(certificate);
    const epochs = fixtureEpochs();
    const plan = structuredClone(rig.plan);
    await expect(verifySdwCertificate(certificate, plan, epochs, {
      fortress_id: rig.authority.fortress_id,
      async assertPlanSigner(id, key) {
        await rig.authority.assertPlanSigner(id, key);
        certificate.body.plan_sha256 = "f".repeat(64);
        plan.body.receipt_byte_length++;
        epochs._sdw_catalog++;
        key.fill(0);
      },
    })).resolves.toBeUndefined();
    await expect(verifySdwCertificate(original, rig.plan, fixtureEpochs(), rig.authority)).resolves.toBeUndefined();
  });

  it("actual internal helper audits without acquiring SDW, admission, corpus or master locks", async () => {
    const critical = vi.spyOn(rig.audit, "appendCritical");
    const lockSpies = [
      vi.spyOn(locks, "withCrossProcessLock"), vi.spyOn(locks, "withRequiredCrossProcessLock"),
      vi.spyOn(locks, "withPathLock"), vi.spyOn(admission, "withExitAdmissionLock"),
      vi.spyOn(custody, "withCustodyWriteLock"), vi.spyOn(rig.storage, "withNamespaceLock"),
    ];
    const read = vi.spyOn(rig.storage, "read"), write = vi.spyOn(rig.storage, "write");
    const durable = vi.spyOn(rig.storage, "writeDurable");
    await rig.helpers.internal_receipt_sign(rig.plan.attestation);
    expect(critical).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ operation: "internal_receipt_sign", identity_id: rig.primary.identity_id }));
    for (const spy of lockSpies) expect(spy).not.toHaveBeenCalled();
    for (const [namespace] of [...read.mock.calls, ...write.mock.calls, ...durable.mock.calls]) expect(isSdwNamespace(namespace)).toBe(false);
    expect([...write.mock.calls, ...durable.mock.calls].some(([namespace]) => namespace === "_audit")).toBe(true);
    critical.mockRejectedValueOnce(new Error("audit unavailable"));
    await expect(rig.helpers.internal_receipt_sign(rig.plan.attestation)).rejects.toThrow("audit unavailable");
  });

  it("keeps raw identity_sign receipt-domain refusal and ordinary signing counterpart", async () => {
    const l1 = createL1Tools(new StateStore(rig.storage, rig.masterKey), rig.storage, rig.masterKey, "recovery-key", rig.audit);
    await l1.identityManager.load();
    const tool = l1.tools.find(t => t.name === "identity_sign")!;
    const invoke = async (payload: Uint8Array) => {
      const response = await tool.handler({ payload: Buffer.from(payload).toString("base64url"), identity_id: rig.primary.identity_id });
      return JSON.parse((response.content as Array<{ text: string }>)[0]!.text);
    };
    expect(await invoke(sdwSigningBytes(rig.plan.attestation))).not.toHaveProperty("signature");
    expect(await invoke(Buffer.from("ordinary operator-authorized message"))).toHaveProperty("signature");
    const source = await readFile("src/cognitive/tools.ts", "utf8");
    expect(source).toContain("startsWithInternalSigningDomain(payload)");
  });
});
