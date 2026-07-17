/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: C3 daemon-store read-error
 * classification (dry-bar regression).
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * The evidence pack tells an auditor whether a present-but-unreadable daemon
 * enforcement store's omission is a PRIVILEGE limitation (re-run as root reads
 * it) or an I/O/generic error (root will NOT resolve it). Misclassifying either
 * direction misdirects the auditor. This pins:
 *   - a genuine tamper finding -> present_tampered (never a privilege excuse);
 *   - an access-only error -> `privilege` ONLY when a finding message reveals a
 *     permission errno (EACCES/EPERM); every other access error (EIO, a
 *     disappeared/null read, a generic storage failure) -> the claim-less `io`,
 *     which never advises the futile "re-run as root";
 *   - the errno-chain classifier walks nested `cause`;
 *   - the CLI stderr warning scopes the covered-window/shortfall assessment too.
 */

import { describe, it, expect } from "vitest";
import {
  classifyDaemonIntegrityError,
  daemonStoreCliWarning,
  daemonUnreadableReason,
} from "../../src/evidence-pack/cli.js";
import {
  AuditIntegrityError,
  type AuditIntegrityFinding,
} from "../../src/operational/audit-log.js";

function finding(
  kind: AuditIntegrityFinding["kind"],
  message = ""
): AuditIntegrityFinding {
  return { kind, message };
}

describe("C3: classifyDaemonIntegrityError", () => {
  it("a genuine tamper finding is present_tampered, never a privilege excuse", () => {
    const e = new AuditIntegrityError([
      finding("entry_hash_mismatch", "entry hash did not match"),
    ]);
    expect(classifyDaemonIntegrityError(e).status).toBe("present_tampered");
  });

  it("tamper mixed with access findings is still present_tampered", () => {
    const e = new AuditIntegrityError([
      finding("entry_unreadable"),
      finding("prev_hash_mismatch", "chain link broken"),
    ]);
    expect(classifyDaemonIntegrityError(e).status).toBe("present_tampered");
  });

  it("an entry_unreadable whose message shows EACCES is a PRIVILEGE limitation (root clears it)", () => {
    const e = new AuditIntegrityError([
      finding("entry_unreadable", "entry-0001 could not be read: EACCES: permission denied"),
    ]);
    expect(classifyDaemonIntegrityError(e)).toEqual({
      status: "present_unreadable",
      unreadable_reason: "privilege",
    });
  });

  it("an entry_unreadable with a NON-permission errno (EIO) is classified io, NOT privilege", () => {
    // Both families' residual: a per-file EIO or disappearance is NOT a
    // privilege limit, so it must never advise the futile "re-run as root".
    const e = new AuditIntegrityError([
      finding("entry_unreadable", "entry-0001 could not be read: EIO: i/o error, read"),
    ]);
    expect(classifyDaemonIntegrityError(e)).toEqual({
      status: "present_unreadable",
      unreadable_reason: "io",
    });
  });

  it("an entry_unreadable with no errno in the message defaults to the claim-less io", () => {
    const e = new AuditIntegrityError([finding("entry_unreadable", "unreadable")]);
    expect(classifyDaemonIntegrityError(e)).toEqual({
      status: "present_unreadable",
      unreadable_reason: "io",
    });
  });

  it("a storage_unavailable (generic storage failure) is classified io, NOT privilege", () => {
    // Pre-fix, storage_unavailable was lumped with entry_unreadable -> privilege,
    // producing futile "re-run as root" advice for a non-permission storage error.
    const e = new AuditIntegrityError([
      finding("storage_unavailable", "audit checkpoints could not be listed: EIO"),
    ]);
    const r = classifyDaemonIntegrityError(e);
    expect(r).toEqual({
      status: "present_unreadable",
      unreadable_reason: "io",
    });
  });

  it("a storage_unavailable whose message reveals EACCES stays privilege (root clears it)", () => {
    const e = new AuditIntegrityError([
      finding(
        "storage_unavailable",
        "audit persistence write failed: EACCES: permission denied, scandir '/x'"
      ),
    ]);
    const r = classifyDaemonIntegrityError(e);
    expect(r).toEqual({
      status: "present_unreadable",
      unreadable_reason: "privilege",
    });
  });
});

describe("C3: daemonUnreadableReason (shared errno-chain classifier)", () => {
  it("EACCES at the top level -> privilege", () => {
    const e = Object.assign(new Error("denied"), { code: "EACCES" });
    expect(daemonUnreadableReason(e)).toBe("privilege");
  });

  it("EPERM nested on the cause chain -> privilege", () => {
    const inner = Object.assign(new Error("op not permitted"), { code: "EPERM" });
    const outer = Object.assign(new Error("wrap"), { cause: inner });
    expect(daemonUnreadableReason(outer)).toBe("privilege");
  });

  it("a non-permission errno (EIO) -> io", () => {
    const e = Object.assign(new Error("i/o error"), { code: "EIO" });
    expect(daemonUnreadableReason(e)).toBe("io");
  });

  it("no errno at all -> io (claim-less default)", () => {
    expect(daemonUnreadableReason(new Error("mystery"))).toBe("io");
  });
});

describe("Fix 2: daemonStoreCliWarning scopes the coverage/shortfall assessment too", () => {
  for (const status of ["present_unreadable", "present_tampered", "missing"] as const) {
    it(`${status}: the stderr warning scopes covered-window / shortfall, not just the count`, () => {
      const lines = daemonStoreCliWarning({ status, included_entry_count: 0 }).join(
        "\n"
      );
      expect(lines).toMatch(/covered-window|shortfall/i);
      expect(lines).toMatch(/OPERATOR/);
    });
  }

  it("absent / included add no warning", () => {
    expect(daemonStoreCliWarning({ status: "absent", included_entry_count: 0 })).toEqual(
      []
    );
    expect(
      daemonStoreCliWarning({ status: "included", included_entry_count: 3 })
    ).toEqual([]);
    expect(daemonStoreCliWarning(undefined)).toEqual([]);
  });
});
