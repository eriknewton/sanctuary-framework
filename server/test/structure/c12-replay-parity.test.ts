/**
 * C12-REPLAY T9 — cross-stage parity structure guards (rules 5/11).
 *
 * These are source-text/structure assertions, not runtime behavior: they pin
 * that the retired hand-mirror stays retired and that the shared module is the
 * SOLE constructor of the quorum input, the SOLE freshness-assertion, and that
 * only applySync passes the weaker `sync_anchored` mode.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const MESH_SRC = join(REPO_ROOT, "server/src/mesh");
// The scans walk ALL of server/src, not a hand-picked file list: a single-file
// substring pin cannot see a new caller added elsewhere (the J5 lesson — no
// single-file substring pins).
const SERVER_SRC = join(REPO_ROOT, "server/src");

function read(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), "utf8");
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

describe("C12-REPLAY parity structure (T9)", () => {
  it("the retired v1 builders and their must-match pin comments are gone", () => {
    const nodeRevoke = read("server/src/mesh/recovery-flows/node-revoke.ts");
    const meshNode = read("server/src/mesh/lifecycle/mesh-node.ts");
    // The exported v1 builder is deleted.
    expect(nodeRevoke).not.toMatch(/export function revokeQuorumInput/);
    // The hand-mirror method is deleted.
    expect(meshNode).not.toMatch(/private nodeRevokeQuorumInput/);
    // Neither v1 Math.random ceremony-id generator survives.
    expect(nodeRevoke).not.toMatch(/Math\.random/);
    expect(read("server/src/mesh/recovery-flows/device-recovery.ts")).not.toMatch(
      /Math\.random/
    );
  });

  it("the shared module is the ONLY constructor of the v2 revoke input shape", () => {
    // The schema literal is defined once (in the shared module) and otherwise
    // only referenced (type positions / wire echoes), never re-built by hand.
    const files = walk(SERVER_SRC);
    const sharedModule = join(MESH_SRC, "guardian", "revoke-quorum-input.ts");
    // A hand-built input assigns the `schema` key (NOT the `input_schema` wire
    // echo, which legitimately rides NodeRevokePayload) to the v2 value.
    const handBuilt = /(?<![\w])schema:\s*(?:"sanctuary\.guardian-revoke-quorum\.v2"|GUARDIAN_REVOKE_QUORUM_SCHEMA_V2)/;
    for (const file of files) {
      if (file === sharedModule) continue;
      const src = readFileSync(file, "utf8");
      expect(
        handBuilt.test(src),
        `unexpected hand-built v2 input in ${file}`
      ).toBe(false);
    }
  });

  it("only applySync passes mode: \"sync_anchored\" — sole-caller scan over ALL of server/src", () => {
    // A VALUE-position use is `mode: "sync_anchored"` followed by `,` or `}`
    // (an object literal being passed); the shared module's FreshnessMode TYPE
    // member is followed by `;` and is the one legitimate non-call occurrence.
    const callSite = /mode:\s*"sync_anchored"\s*[,}]/g;
    const meshNodePath = join(MESH_SRC, "lifecycle", "mesh-node.ts");
    let totalCallSites = 0;
    for (const file of walk(SERVER_SRC)) {
      const matches = readFileSync(file, "utf8").match(callSite) ?? [];
      if (matches.length > 0) {
        expect(
          file,
          `sync_anchored passed outside mesh-node.ts: ${file}`
        ).toBe(meshNodePath);
        totalCallSites += matches.length;
      }
    }
    // Exactly one sync_anchored call site in ALL production code.
    expect(totalCallSites).toBe(1);
    // And it is inside applySync (the anchored call references effective_at).
    const meshNode = read("server/src/mesh/lifecycle/mesh-node.ts");
    const applySyncStart = meshNode.indexOf("async applySync(");
    const applySyncEnd = meshNode.indexOf("private admitRevoke(");
    expect(applySyncStart).toBeGreaterThan(0);
    expect(applySyncEnd).toBeGreaterThan(applySyncStart);
    const applySyncBody = meshNode.slice(applySyncStart, applySyncEnd);
    expect(applySyncBody).toMatch(/mode:\s*"sync_anchored"/);
  });

  it("no second freshness-assertion or ceremony-id generator exists under server/src", () => {
    const files = walk(SERVER_SRC);
    const sharedModule = join(MESH_SRC, "guardian", "revoke-quorum-input.ts");
    for (const file of files) {
      if (file === sharedModule) continue;
      const src = readFileSync(file, "utf8");
      // The relying-side freshness logic is defined once.
      expect(
        src.includes("export function assertQuorumContextFresh"),
        `duplicate freshness assertion in ${file}`
      ).toBe(false);
      // The CSPRNG ceremony-id minting is defined once.
      expect(
        src.includes("export function mintRevokeCollectionContext"),
        `duplicate ceremony-id minting in ${file}`
      ).toBe(false);
    }
  });
});
