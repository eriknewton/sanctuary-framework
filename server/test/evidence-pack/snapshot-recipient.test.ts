import { it, expect } from "vitest";
import { SNAPSHOT_RECIPIENT } from "../../src/evidence-pack/snapshot-recipient.js";
import { renderSnapshot } from "../../src/evidence-pack/snapshot-generate.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
it("recipient procedure requires independent full pins and positive acceptance", () => {
  for (const token of ["PACK_KEY_FINGERPRINT", "key file merely copied", "fresh extraction before browsing it in Finder", "--expect-manifest-digest", "--trust-descriptor-file", "Exit 10/PARTIAL is not acceptance", 'status:"PASS"', 'accepted:true', "expected export id", "--ignore-scripts", "tarball hash"]) expect(SNAPSHOT_RECIPIENT).toContain(token);
});
it("report and recipient use the identical procedure and PDF carries export id", () => {
  const id = "12345678-1234-4123-8123-123456789012";
  const files = renderSnapshot(id, "2026-01-01T00:00:00.000Z", { audit: { state: "empty_verified", reason: "no_records" }, transparency: { state: "read_failed", reason: "pin_unavailable" } }, C.utf8("{}"));
  expect(Buffer.from(files.get(C.RECIPIENT_FILENAME)!).toString()).toBe(SNAPSHOT_RECIPIENT);
  expect(Buffer.from(files.get(C.REPORT_FILENAME)!).toString()).toContain(SNAPSHOT_RECIPIENT);
  const pdf = Buffer.from(files.get(C.PDF_FILENAME)!).toString(); expect(pdf).toContain(id); expect(pdf).toContain("Export id");
});
