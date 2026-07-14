/**
 * F2 BLOCKER-2 (adversarial gate 2026-07-14): the daemon migration-marker
 * namespace literals are DUPLICATED in two places that cannot import each other
 * (audit-store-split.ts imports FROM audit-log.ts, so audit-log.ts cannot import
 * back — that would be a dependency cycle). This structural test asserts they
 * stay in lockstep, so a rename in one file that is not mirrored in the other
 * fails loudly rather than silently breaking the "migration happened but
 * boundary gone" detection (`daemonMigrationMarkerExists`).
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  AUDIT_DAEMON_NAMESPACE,
  AUDIT_DAEMON_CHECKPOINT_NAMESPACE,
  AUDIT_DAEMON_META_NAMESPACE,
} from "../../src/operational/audit-store-split.js";

const SRC = join(process.cwd(), "src");

describe("F2 audit-store-split marker namespaces stay in lockstep", () => {
  it("the exported daemon namespaces are the frozen literals", () => {
    expect(AUDIT_DAEMON_NAMESPACE).toBe("_audit-daemon");
    expect(AUDIT_DAEMON_CHECKPOINT_NAMESPACE).toBe("_audit-daemon_checkpoints");
    expect(AUDIT_DAEMON_META_NAMESPACE).toBe("_audit-daemon_meta");
  });

  it("audit-log.ts's private marker list matches the exported daemon namespaces", () => {
    const src = readFileSync(join(SRC, "operational", "audit-log.ts"), "utf8");
    const match = /AUDIT_DAEMON_MIGRATION_MARKER_NAMESPACES\s*=\s*\[([^\]]*)\]/s.exec(src);
    expect(match, "AUDIT_DAEMON_MIGRATION_MARKER_NAMESPACES array not found in audit-log.ts").toBeTruthy();
    const listed = [...match![1]!.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    expect(new Set(listed)).toEqual(
      new Set([
        AUDIT_DAEMON_NAMESPACE,
        AUDIT_DAEMON_CHECKPOINT_NAMESPACE,
        AUDIT_DAEMON_META_NAMESPACE,
      ]),
    );
  });

  it("audit-chain-export.ts's daemon-namespace literal matches too", () => {
    const src = readFileSync(join(SRC, "cli", "audit-chain-export.ts"), "utf8");
    expect(src).toContain(`AUDIT_EXPORT_DAEMON_NAMESPACE = "${AUDIT_DAEMON_NAMESPACE}"`);
  });

  // BLOCKER-R2: the `_meta` migration-established marker key is ALSO duplicated
  // across audit-log.ts (write/read), master-rotation.ts (refusal), and
  // audit-chain-export.ts (presence probe). It cannot drift, or the boundary-loss
  // fail-closed / rotation refusal / export refusal silently break.
  it("the F2 _meta established-marker key literal is in lockstep across all four files", () => {
    const KEY = "audit-store-split-established-v1";
    for (const rel of [
      ["operational", "audit-log.ts"],
      ["core", "master-rotation.ts"],
      ["cli", "audit-chain-export.ts"],
    ] as const) {
      const src = readFileSync(join(SRC, ...rel), "utf8");
      expect(src, `${rel.join("/")} must reference the established-marker key`).toContain(
        `"${KEY}"`,
      );
    }
  });
});
