/**
 * Observe/Learn promote -> LIVE ENFORCEMENT reach (2026-07-27 fix, Option A,
 * plus the two-family-gate fix round F2-F7).
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
 * FilesystemManifestStorage + resolvePromoteRouting, including the F5
 * post-approval re-resolve) dependency-for-dependency.
 *
 * FIX-ROUND COVERAGE (2026-07-27 two-family gate on PR #1031):
 *   - F2: a gate-scoped (uids-only) rule must never suppress a candidate --
 *     the agent's path stays denied until the gate re-arms, and suppression
 *     hid exactly that (the third recurrence of the self-masking shape).
 *   - F3: a same-id rule promoted under the OTHER routing mode is REWRITTEN
 *     to the current-mode scope on re-promote (both transition directions),
 *     never silently carried forward under a success message.
 *   - F4: orphan-cleanup owns files by MEMBERSHIP in the previous
 *     promote-signed manifest -- an operator-authored file named
 *     `derived-observe-*.json` survives a promote.
 *   - F5: the routing marker is re-resolved after the (possibly minutes-long)
 *     Tier-1 approval wait; a mode flip aborts with `routing_changed`.
 *   - F6: marker removed after an exclusive promote => the gate-scoped rule's
 *     candidate stays VISIBLE (F2) and the next promote REPAIRS the rule to
 *     coarse scope (F3's reverse direction) -- the exclusive->coarse
 *     transition test below.
 *   - F7: a malformed marker refuses the promote through the REAL CLI verb.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";

import {
  FilesystemManifestStorage,
  readVerifiedManifest,
  resolvePromoteRouting,
  runObservePromote,
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
import { promoteCandidates, type PromoteOutcome } from "../../../src/castle-wall/observe/promote.js";
import { candidateCurrentlyAllowed } from "../../../src/castle-wall/observe/refresh.js";
import { OBSERVE_PROMOTED_RULE_ID_PREFIX } from "../../../src/castle-wall/observe/synthesize.js";
import type { CandidateObservation } from "../../../src/castle-wall/observe/types.js";
import type { SignedManifest } from "../../../src/castle-wall/allowlist/manifest.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import { IdentityManager } from "../../../src/cognitive/tools.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { hashToString } from "../../../src/core/hashing.js";
import { stringToBytes, toBase64url } from "../../../src/core/encoding.js";
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

function exclusiveMarkerDoc(): string {
  return renderExclusiveRoutingMarker({
    agent_uid: AGENT_UID,
    gate_uid: GATE_UID,
    agent_id: "agent-1",
    agent_template: "claude-code",
  });
}

class Capture extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
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
   * the fortress egress dir, the ROUTING RESOLVED FROM THE FORTRESS via the
   * CLI's own `resolvePromoteRouting`, and the same post-approval re-resolve
   * (F5). A FRESH storage per call, as the CLI constructs one per invocation.
   */
  async function promoteViaProductionWiring(row: CandidateObservation): Promise<PromoteOutcome> {
    const routing = await resolvePromoteRouting(fortressPath);
    const candidatesByKey = new Map([["k1", row]]);
    const storage = new FilesystemManifestStorage(egressDir);
    return promoteCandidates([{ key: "k1" }], candidatesByKey, {
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
      reresolveRouting: () => resolvePromoteRouting(fortressPath),
    });
  }

  async function promoteExpectPromoted(
    row: CandidateObservation,
  ): Promise<{ ruleId: string; outcome: Extract<PromoteOutcome, { status: "promoted" }> }> {
    const outcome = await promoteViaProductionWiring(row);
    expect(outcome.status).toBe("promoted");
    if (outcome.status !== "promoted") throw new Error("unreachable");
    const rule = outcome.addedRules[0] ?? outcome.rewrittenRules[0];
    expect(rule).toBeDefined();
    return { ruleId: rule!.id, outcome };
  }

  it("FAIL-WITHOUT-FIX: a promoted rule is present in the REAL daemon composer's output (coarse mode)", async () => {
    const { ruleId } = await promoteExpectPromoted(candidate("api.newlyapproved.example"));
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
    const { ruleId } = await promoteExpectPromoted(candidate("api.newlyapproved.example"));

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

  it("FAIL-WITHOUT-FIX (F4): promote NEVER deletes rule files it did not publish, even ones named derived-observe-*", async () => {
    // The shared rules/ source holds a provisioned endpoint rule, an
    // operator-authored rule, AND an operator-authored file that happens to
    // carry the observe id prefix. None is referenced by the promote-owned
    // manifest; ownership is by MEMBERSHIP in that manifest, never by name,
    // so all three must survive the publish's orphan-cleanup (deleting the
    // provisioned egress rules would sever a confined agent's own endpoints,
    // the F-REVOKE blanket-scrub class; deleting the prefix-named operator
    // file is the F4 collision).
    const rulesDir = join(egressDir, "rules");
    await mkdir(rulesDir, { recursive: true, mode: 0o700 });
    const foreign = [
      "provisioned-hermes-abc123.json",
      "operator-handwritten.json",
      "derived-observe-operatorhand.json",
    ];
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

    await promoteExpectPromoted(candidate("api.newlyapproved.example"));

    const survivors = await readdir(rulesDir);
    for (const name of foreign) {
      expect(survivors).toContain(name);
    }
  });

  it("FAIL-WITHOUT-FIX: exclusive-mode reload SUCCEEDS with the promoted rule bound to the gate principal", async () => {
    // The exclusive-routing fortress: marker present, gate policy live. This
    // is the configuration the naive writer repoint would have bricked.
    await writeFile(exclusiveRoutingMarkerPath(fortressPath), exclusiveMarkerDoc());

    const { ruleId } = await promoteExpectPromoted(candidate("api.newlyapproved.example"));

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
    const { ruleId } = await promoteExpectPromoted(candidate("api.newlyapproved.example"));
    // The fortress then declares exclusive routing.
    await writeFile(exclusiveRoutingMarkerPath(fortressPath), exclusiveMarkerDoc());

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

  it("FAIL-WITHOUT-FIX (F3, coarse->exclusive): re-promote REWRITES the stale template-scoped rule to gate scope, and the exclusive reload composes", async () => {
    // 1. Promote under coarse: template-scoped rule in rules/.
    const row = candidate("api.newlyapproved.example");
    const first = await promoteExpectPromoted(row);
    expect(first.outcome.rewrittenRules).toEqual([]);

    // 2. The fortress arms exclusive routing (marker written at G4).
    await writeFile(exclusiveRoutingMarkerPath(fortressPath), exclusiveMarkerDoc());

    // 3. The destination is still denied for the agent, so the operator
    //    re-promotes. The synthesized id collides with the stale rule; the
    //    scope disagrees with the CURRENT routing resolution, so the rule is
    //    REWRITTEN, never silently carried forward under a success message.
    const second = await promoteExpectPromoted(row);
    expect(second.outcome.rewrittenRules).toHaveLength(1);
    expect(second.outcome.rewrittenRules[0]!.id).toBe(first.ruleId);
    expect(second.outcome.addedRules).toEqual([]);

    // 4. The REAL exclusive reload now composes (the stale shape would throw)
    //    with the rule bound to the gate principal.
    const state = await loadManifestState({
      fortressPath,
      fortressId: "fortress-test",
      signer: daemonSigner,
      exclusiveEgressGate: gatePolicy,
    });
    const composed = state.rules.find((rule) => rule.id === first.ruleId);
    expect(composed).toBeDefined();
    expect(composed!.scope).toEqual({ uids: [GATE_UID] });
  });

  it("FAIL-WITHOUT-FIX (F3+F6, exclusive->coarse): the dead gate-scoped rule stays VISIBLE and the next promote repairs it to coarse scope", async () => {
    // 1. Promote under exclusive routing: gate-scoped rule.
    await writeFile(exclusiveRoutingMarkerPath(fortressPath), exclusiveMarkerDoc());
    const row = candidate("api.newlyapproved.example");
    const first = await promoteExpectPromoted(row);

    // 2. The marker is removed (coarse restore / unprotect). The gate-scoped
    //    rule is now DEAD: agent-unreachable at the kernel, no gate to honor
    //    it. F2's scope-aware suppression must keep the candidate VISIBLE --
    //    the pre-fix ruleScopeCoversAgent read uids-only as "all agents" and
    //    suppressed it, hiding the miss (the self-masking shape again).
    await rm(exclusiveRoutingMarkerPath(fortressPath));
    const verified = await readVerifiedManifest(egressDir, publicKey);
    expect(verified.status).toBe("ok");
    if (verified.status !== "ok") throw new Error("unreachable");
    expect(candidateCurrentlyAllowed(verified.rules, row)).toBe(false);

    // 3. Re-promote: the stale gate-scoped rule is rewritten to the coarse
    //    (template) scope, and the REAL coarse compose serves it.
    const second = await promoteExpectPromoted(row);
    expect(second.outcome.rewrittenRules).toHaveLength(1);
    const state = await loadManifestState({
      fortressPath,
      fortressId: "fortress-test",
      signer: daemonSigner,
    });
    const composed = state.rules.find((rule) => rule.id === first.ruleId);
    expect(composed).toBeDefined();
    expect(composed!.scope).toEqual({ template_ids: ["claude-code"] });
  });
});

describe("F2: gate-scoped rules never suppress a candidate (scope-aware conservative suppression)", () => {
  const row = candidate("api.newlyapproved.example");

  function allowRule(scope: AllowlistRule["scope"]): AllowlistRule {
    return {
      id: "r-scope-test",
      schema_version: 1,
      created_at: "2026-07-27T00:00:00Z",
      match: { host: ["api.newlyapproved.example"], port: [443], protocol: "tcp" },
      scope,
      disposition: "allow",
      derived: true,
    };
  }

  it("FAIL-WITHOUT-FIX: a uids-only (gate-scoped) allow does NOT suppress -- the agent's path is still denied", () => {
    expect(candidateCurrentlyAllowed([allowRule({ uids: [GATE_UID] })], row)).toBe(false);
  });

  it("a template-scoped allow naming the agent's template still suppresses (the kernel honors that axis)", () => {
    expect(candidateCurrentlyAllowed([allowRule({ template_ids: ["claude-code"] })], row)).toBe(true);
  });

  it("a mixed scope that names the agent's template alongside uids still suppresses via the template axis", () => {
    expect(
      candidateCurrentlyAllowed([allowRule({ template_ids: ["claude-code"], uids: [GATE_UID] })], row),
    ).toBe(true);
  });
});

describe("F5: the routing marker is re-resolved after the Tier-1 approval wait", () => {
  const row = candidate("api.newlyapproved.example");
  const OK_EMPTY = { status: "ok" as const, rules: [], digest: "digest-empty" };

  it("FAIL-WITHOUT-FIX: a mode flip during the approval window aborts with routing_changed and publishes NOTHING", async () => {
    let published = false;
    const outcome = await promoteCandidates([{ key: "k1" }], new Map([["k1", row]]), {
      readVerifiedManifest: async () => OK_EMPTY,
      approve: async () => ({ allowed: true }),
      publish: async () => {
        published = true;
        return { written_rule_filenames: [], removed_rule_filenames: [] };
      },
      now: new Date(),
      routing: { mode: "coarse" },
      // The fortress armed exclusive while the human was reading the prompt.
      reresolveRouting: async () => ({ mode: "exclusive", gate_uid: GATE_UID }),
    });
    expect(outcome.status).toBe("routing_changed");
    expect(published).toBe(false);
  });

  it("a marker that became MALFORMED during the window also aborts (fail closed, nothing published)", async () => {
    let published = false;
    const outcome = await promoteCandidates([{ key: "k1" }], new Map([["k1", row]]), {
      readVerifiedManifest: async () => OK_EMPTY,
      approve: async () => ({ allowed: true }),
      publish: async () => {
        published = true;
        return { written_rule_filenames: [], removed_rule_filenames: [] };
      },
      now: new Date(),
      routing: { mode: "exclusive", gate_uid: GATE_UID },
      reresolveRouting: async () => {
        throw new Error("exclusive-routing marker: not valid JSON");
      },
    });
    expect(outcome.status).toBe("routing_changed");
    if (outcome.status !== "routing_changed") throw new Error("unreachable");
    expect(outcome.reason).toContain("not valid JSON");
    expect(published).toBe(false);
  });

  it("an unchanged routing proceeds to publish (the recheck is a guard, not a blocker)", async () => {
    let published = false;
    const outcome = await promoteCandidates([{ key: "k1" }], new Map([["k1", row]]), {
      readVerifiedManifest: async () => OK_EMPTY,
      approve: async () => ({ allowed: true }),
      publish: async () => {
        published = true;
        return { written_rule_filenames: [], removed_rule_filenames: [] };
      },
      now: new Date(),
      routing: { mode: "exclusive", gate_uid: GATE_UID },
      reresolveRouting: async () => ({ mode: "exclusive", gate_uid: GATE_UID }),
    });
    expect(outcome.status).toBe("promoted");
    expect(published).toBe(true);
  });
});

describe("F7: a malformed exclusive-routing marker refuses the promote through the REAL CLI verb", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("runObservePromote exits 1 with the routing-mode refusal, before touching any policy state", async () => {
    // A REAL bootstrap-able fortress: recovery-key custody + one identity,
    // exactly what the observe CLI's shared bootstrap requires.
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-observe-cli-marker-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const recoveryKey = toBase64url(masterKey);
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    await storage.write("_meta", "recovery-key-hash", stringToBytes(hashToString(masterKey)));
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const manager = new IdentityManager(storage, masterKey);
    const { storedIdentity } = createIdentity("test-agent", identityEncKey, "passphrase");
    await manager.save(storedIdentity);

    // A PRESENT-but-malformed marker: the loader's contract is to throw, and
    // the promote must refuse rather than guess a mode.
    await mkdir(join(fortressPath, "policy", "egress"), { recursive: true, mode: 0o700 });
    await writeFile(exclusiveRoutingMarkerPath(fortressPath), "{ this is not json", {
      mode: 0o600,
    });

    const out = new Capture();
    const err = new Capture();
    const code = await runObservePromote(
      ["--destination", "api.newlyapproved.example:443", "--fortress", fortressPath],
      { out, err, env: { SANCTUARY_RECOVERY_KEY: recoveryKey } },
    );

    expect(code).toBe(1);
    expect(err.text()).toContain("could not resolve this fortress's egress routing mode");
    expect(err.text()).toContain("Nothing was changed");
  });
});
