/**
 * Observe/Learn promote -> LIVE ENFORCEMENT reach (2026-07-27 fix, Option A).
 *
 * THE DEFECT THIS GUARDS AGAINST: promote published rule files BESIDE
 * `policy/egress/manifest.json`, a location no enforcement path reads -- the
 * macOS signing daemon's composer scans the `policy/egress/rules/`
 * subdirectory and the Linux enforcer resolves every manifest entry as
 * `policy_dir/rules/<entry.file>` -- so approved destinations stayed denied
 * while the CLI reported success, and the refresh suppression then hid the
 * miss from `observe candidates`. It shipped because the only round-trip test
 * paired the promote writer with the promote module's OWN reader
 * (`readVerifiedManifest`), which passed while connected to nothing.
 *
 * THE RULE THIS FILE EXISTS TO UPHOLD: the far side of the round trip is the
 * REAL consumer. Every reach assertion here runs the promoted output through
 * `loadManifestState` -- the daemon's actual, only manifest production path
 * (initial load AND every reload) -- never through a reimplementation of its
 * read half. The near side mirrors `runObservePromote`'s production wiring
 * (promoteCandidates + readVerifiedManifest + publishSignedManifest +
 * FilesystemManifestStorage + resolvePromoteRouting) dependency-for-
 * dependency.
 *
 * ALSO COVERED (the trap that made the one-line writer repoint unshippable
 * alone): promoted rules carried template/agent scope and no uid axis, so the
 * moment they reach the composer on an EXCLUSIVE-routing fortress each is an
 * agent-reachable direct off-box allow that
 * `assertExclusiveRoutingComposition` rejects by THROWING -- no manifest, no
 * arm, a bricked policy reload. The fix scopes promoted rules to the gate
 * principal whenever the exclusive-routing marker is present; the exclusive
 * tests below prove the reload SUCCEEDS with the rule correctly gate-scoped,
 * and that the unscoped legacy shape is indeed refused fail-closed.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import {
  FilesystemManifestStorage,
  readVerifiedManifest,
  resolvePromoteRouting,
} from "../../../src/cli/castle-wall-observe.js";
import {
  localManifestSigner,
  publishSignedManifest,
} from "../../../src/castle-wall/runtime/manifest-publisher.js";
import {
  loadManifestState,
  type DaemonSigner,
} from "../../../src/castle-wall/runtime/macos-daemon.js";
import {
  exclusiveRoutingMarkerPath,
  renderExclusiveRoutingMarker,
} from "../../../src/castle-wall/allowlist/index.js";
import { ExclusiveRoutingViolationError } from "../../../src/castle-wall/allowlist/exclusive-routing.js";
import type { ExclusiveEgressGatePolicy } from "../../../src/castle-wall/allowlist/gate-derivation.js";
import { promoteCandidates } from "../../../src/castle-wall/observe/promote.js";
import { OBSERVE_PROMOTED_RULE_ID_PREFIX } from "../../../src/castle-wall/observe/synthesize.js";
import type { CandidateObservation } from "../../../src/castle-wall/observe/types.js";
import type { SignedManifest } from "../../../src/castle-wall/allowlist/manifest.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { encrypt } from "../../../src/core/encryption.js";

const AGENT_UID = 601;
const GATE_UID = 602;
const GATE_PORT = 48620;

const gatePolicy: ExclusiveEgressGatePolicy = { agent_uid: AGENT_UID, gate_port: GATE_PORT };

function candidate(host: string): CandidateObservation {
  return {
    agent_id: "agent-1",
    agent_template: "claude-code",
    host,
    ip: "93.184.216.34",
    port: 443,
    protocol: "tcp",
    hostname_source: "sni",
    times_seen: 3,
    first_seen: "2026-07-27T00:00:00Z",
    last_seen: "2026-07-27T01:00:00Z",
    would_be_disposition: "denied",
    exfil_risk: false,
  };
}

describe("observe promote reaches live enforcement (the real composer, not promote's own reader)", () => {
  let fortressPath: string;
  let egressDir: string;
  let publicKey: Uint8Array;
  let signer: ReturnType<typeof localManifestSigner>;
  let daemonSigner: DaemonSigner;

  beforeEach(async () => {
    fortressPath = await mkdtemp(join(tmpdir(), "cw-promote-reach-"));
    egressDir = join(fortressPath, "policy", "egress");
    await mkdir(egressDir, { recursive: true, mode: 0o700 });
    const privateSeed = generateRandomKey();
    publicKey = ed25519.getPublicKey(privateSeed);
    const encryptionKey = generateRandomKey();
    const encryptedPrivateKey = encrypt(privateSeed, encryptionKey);
    signer = localManifestSigner({ signingKeyId: "test-key", encryptedPrivateKey, encryptionKey });
    // mode "local": the daemon's dev/test signing path (the helper path's
    // global-pin cross-check needs a root-owned system file no test may own).
    daemonSigner = {
      mode: "local",
      signingKeyId: "test-key",
      publicKey,
      signManifest: async (bytes) => signer.sign(bytes),
      signNonce: async (bytes) => signer.sign(bytes),
    };
  });

  afterEach(async () => {
    await rm(fortressPath, { recursive: true, force: true });
  });

  /**
   * Promote exactly as `runObservePromote` wires it in production: the same
   * verified-manifest reader, the same publisher, the same storage rooted at
   * the fortress egress dir, and the ROUTING RESOLVED FROM THE FORTRESS via
   * the CLI's own `resolvePromoteRouting` (marker present => gate-scoped).
   */
  async function promoteViaProductionWiring(row: CandidateObservation): Promise<string> {
    const routing = await resolvePromoteRouting(fortressPath);
    const candidatesByKey = new Map([["k1", row]]);
    const storage = new FilesystemManifestStorage(egressDir);
    const outcome = await promoteCandidates([{ key: "k1" }], candidatesByKey, {
      readVerifiedManifest: () => readVerifiedManifest(egressDir, publicKey),
      approve: async () => ({ allowed: true }),
      publish: (rules, descriptors) =>
        publishSignedManifest(
          {
            fortressId: "fortress-test",
            issuedAt: new Date().toISOString(),
            rules,
            signer,
            ...(descriptors.agentOrigin !== undefined ? { agentOrigin: descriptors.agentOrigin } : {}),
            ...(descriptors.operatorBaseline !== undefined
              ? { operatorBaseline: descriptors.operatorBaseline }
              : {}),
          },
          storage,
        ),
      now: new Date(),
      routing,
    });
    expect(outcome.status).toBe("promoted");
    if (outcome.status !== "promoted") throw new Error("unreachable");
    expect(outcome.addedRules).toHaveLength(1);
    return outcome.addedRules[0]!.id;
  }

  it("FAIL-WITHOUT-FIX: a promoted rule is present in the REAL daemon composer's output (coarse mode)", async () => {
    const ruleId = await promoteViaProductionWiring(candidate("api.newlyapproved.example"));
    expect(ruleId.startsWith(OBSERVE_PROMOTED_RULE_ID_PREFIX)).toBe(true);

    // THE REAL CONSUMER: the daemon's one and only manifest production path.
    const state = await loadManifestState({
      fortressPath,
      fortressId: "fortress-test",
      signer: daemonSigner,
    });

    const composed = state.rules.find((rule) => rule.id === ruleId);
    expect(composed).toBeDefined();
    expect(composed!.match.host).toEqual(["api.newlyapproved.example"]);
    expect(composed!.disposition).toBe("allow");
    // The SIGNED manifest the daemon broadcasts carries it too.
    expect(state.signed.manifest.rules.some((entry) => entry.rule_id === ruleId)).toBe(true);
  });

  it("FAIL-WITHOUT-FIX: the published tree matches the Linux enforcer's resolution contract (manifest beside, rules under rules/, digests intact)", async () => {
    // The Rust store (castle-wall-daemon/src/manifest/store.rs) reads
    // `<policy_dir>/manifest.json` and resolves every entry as
    // `<policy_dir>/rules/<entry.file>`, verifying each file's sha256 against
    // the signed entry. This asserts the SAME resolution in TS so the layout
    // contract is pinned on every CI run; the Rust binary itself is exercised
    // by its own store tests over this exact layout.
    const ruleId = await promoteViaProductionWiring(candidate("api.newlyapproved.example"));

    const signed = JSON.parse(
      await readFile(join(egressDir, "manifest.json"), "utf8"),
    ) as SignedManifest;
    expect(signed.manifest.rules.length).toBeGreaterThan(0);
    expect(signed.manifest.rules.some((entry) => entry.rule_id === ruleId)).toBe(true);
    for (const entry of signed.manifest.rules) {
      const bytes = await readFile(join(egressDir, "rules", entry.file));
      const digest = createHash("sha256").update(bytes).digest("hex");
      expect(digest).toBe(entry.sha256);
    }
    // And NO rule file sits beside the manifest (the legacy dead-drop): the
    // egress dir holds only the manifest itself here.
    const besideManifest = (await readdir(egressDir)).filter(
      (name) => name.endsWith(".json") && name !== "manifest.json",
    );
    expect(besideManifest).toEqual([]);
  });

  it("promote NEVER orphan-cleans rule files it does not own (provisioned/operator files survive)", async () => {
    // A provisioned endpoint rule file and an operator-authored rule file
    // already live in the shared rules/ source. Neither is referenced by
    // promote's manifest; the publisher's orphan-cleanup must not touch them
    // (deleting the provisioned egress rules would sever a confined agent's
    // own endpoints -- the F-REVOKE blanket-scrub class).
    const rulesDir = join(egressDir, "rules");
    await mkdir(rulesDir, { recursive: true, mode: 0o700 });
    const foreign = ["provisioned-hermes-abc123.json", "operator-handwritten.json"];
    for (const name of foreign) {
      await writeFile(
        join(rulesDir, name),
        JSON.stringify({
          id: name.replace(/\.json$/, ""),
          schema_version: 1,
          created_at: "2026-07-27T00:00:00Z",
          match: { host: ["kept.example.com"], port: [443], protocol: "tcp" },
          scope: {},
          disposition: "allow",
        }),
      );
    }

    await promoteViaProductionWiring(candidate("api.newlyapproved.example"));

    const survivors = await readdir(rulesDir);
    for (const name of foreign) {
      expect(survivors).toContain(name);
    }
  });

  it("FAIL-WITHOUT-FIX: exclusive-mode reload SUCCEEDS with the promoted rule bound to the gate principal", async () => {
    // The exclusive-routing fortress: marker present, gate policy live. This
    // is the configuration the naive writer repoint would have bricked.
    await writeFile(
      exclusiveRoutingMarkerPath(fortressPath),
      renderExclusiveRoutingMarker({
        agent_uid: AGENT_UID,
        gate_uid: GATE_UID,
        agent_id: "agent-1",
        agent_template: "claude-code",
      }),
    );

    const ruleId = await promoteViaProductionWiring(candidate("api.newlyapproved.example"));

    // The REAL reload path: routing marker present routes the compose through
    // composeExclusiveRoutingRules, whose assertion throws on any
    // agent-reachable direct off-box allow. It must NOT throw here.
    const state = await loadManifestState({
      fortressPath,
      fortressId: "fortress-test",
      signer: daemonSigner,
      exclusiveEgressGate: gatePolicy,
    });

    const composed = state.rules.find((rule) => rule.id === ruleId);
    expect(composed).toBeDefined();
    // Correctly scoped: bound to the gate principal ONLY (the same
    // scope.uids axis the provisioned endpoint rules use), never to the
    // agent's template/id (the axes compose as an OR, so carrying either
    // would keep the rule agent-reachable).
    expect(composed!.scope).toEqual({ uids: [GATE_UID] });
  });

  it("the legacy template-scoped promoted shape on an exclusive fortress is refused FAIL-CLOSED, never silently widened", async () => {
    // Promote in coarse mode (no marker yet): the rule lands in rules/ with
    // template scope -- agent-reachable by construction.
    const ruleId = await promoteViaProductionWiring(candidate("api.newlyapproved.example"));
    // The fortress then declares exclusive routing.
    await writeFile(
      exclusiveRoutingMarkerPath(fortressPath),
      renderExclusiveRoutingMarker({
        agent_uid: AGENT_UID,
        gate_uid: GATE_UID,
        agent_id: "agent-1",
        agent_template: "claude-code",
      }),
    );

    // The compose-time assertion must reject the agent-reachable allow: no
    // manifest, no arm, and the violation names the offending rule so the
    // operator knows exactly what to discard or re-promote.
    await expect(
      loadManifestState({
        fortressPath,
        fortressId: "fortress-test",
        signer: daemonSigner,
        exclusiveEgressGate: gatePolicy,
      }),
    ).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(ExclusiveRoutingViolationError);
      const violation = error as ExclusiveRoutingViolationError;
      expect(violation.violations.some((v) => v.rule_id === ruleId)).toBe(true);
      return true;
    });
  });
});
