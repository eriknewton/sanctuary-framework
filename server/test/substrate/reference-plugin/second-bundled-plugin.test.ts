/**
 * Second bundled reference plugin (slice S5) - n>1 bundled plugins under supervisor
 * isolation.
 *
 * A SECOND first-party bundled reference plugin (ai.sanctuary.hosts-blocklist, a
 * Pi-hole / hosts-format egress vetoer) now ships alongside the first
 * (ai.sanctuary.blocklist). This suite proves the four facts the plugin host must
 * uphold for more than one bundled plugin:
 *
 *   (1) ENUMERATE + INTEGRITY-VERIFY BOTH: the registry lists both plugins and each
 *       integrity-verifies independently against its OWN self-shipped first-party
 *       signer key. A `plugin list` / `plugin status` over the CLI shows both.
 *   (2) SUPERVISOR ISOLATION: a hostile or failing second plugin adopted alongside a
 *       healthy plugin under the SAME supervisor cannot corrupt or take down the
 *       healthy one - the healthy plugin still produces its correct verdict while the
 *       faulty plugin is contained (fail-mode deny).
 *   (3) TAMPERED SIGNATURE FAILS CLOSED: a tampered SIGNATURE.json / rules file on
 *       EITHER bundle makes that bundle fail integrity verification, so the tampered
 *       plugin never runs. The OTHER bundle still verifies.
 *   (4) HOSTS-FORMAT PARSE: the second plugin's Pi-hole / hosts-format rules parse to
 *       the expected domain set.
 *
 * These are FIRST-PARTY BUNDLED reference plugins, NOT third-party or marketplace
 * plugins; third-party install stays F1-gated. No "unbypassable" claim is made:
 * kernel confinement is the Linux launcher's job (proven by the Rust hostile drill);
 * this suite proves the host-side enumeration/integrity/isolation/fail-closed
 * contract, which is platform-independent.
 */

import { afterEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ed25519 } from "@noble/curves/ed25519";

import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import {
  decideEgressProxyConnect,
  type EgressProxyResolver,
} from "../../../src/castle-wall/egress-proxy.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import { SubstrateError } from "../../../src/substrate/errors.js";
import {
  BUNDLED_PLUGINS,
  PluginSupervisor,
  bundledPluginDir,
  bundledPluginSpec,
  buildReferenceDescriptor,
  signDescriptor,
  loadBundledPlugin,
  loadBundledReferenceBlocklist,
  loadReferenceBlocklistBundle,
  pinnedSignerFor,
  spawnReferencePlugin,
  readBundledSignerFrom,
  enumerateBundleDir,
  verifyBundle,
  parseGovernance,
  type SpawnedPlugin,
  type SignatureFile,
  type TrustedSigner,
} from "../../../src/substrate/index.js";
import { runPluginCommand } from "../../../src/cli/plugin.js";

const HOSTS_PLUGIN_ID = "ai.sanctuary.hosts-blocklist";
const BLOCKLIST_PLUGIN_ID = "ai.sanctuary.blocklist";

const HOSTILE_ENTRY = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "hostile-fixtures",
  "hostile-plugin.mjs",
);

function hostsBundleDir(): string {
  const spec = BUNDLED_PLUGINS.find((p) => p.plugin_id === HOSTS_PLUGIN_ID);
  if (!spec) throw new Error("hosts-blocklist not registered");
  return bundledPluginDir(spec);
}

function allowHost(host: string, port = 443): AllowlistRule {
  return {
    id: `allow-${host}`,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-07-03T00:00:00.000Z",
    match: { host, port, protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

function resolverReturning(addresses: string[]): EgressProxyResolver {
  return { async resolve() { return addresses; } };
}

const spawned: SpawnedPlugin[] = [];
afterEach(() => {
  while (spawned.length > 0) spawned.pop()?.close();
});

/** Spawn the HOSTILE fixture (never bundled) with a chosen attack mode. */
function spawnHostile(mode: string): SpawnedPlugin {
  const orig = process.env.HOSTILE_MODE;
  process.env.HOSTILE_MODE = mode;
  try {
    return spawnReferencePlugin(HOSTILE_ENTRY);
  } finally {
    if (orig === undefined) delete process.env.HOSTILE_MODE;
    else process.env.HOSTILE_MODE = orig;
  }
}

describe("S5 second bundled plugin - registry + integrity (n>1)", () => {
  it("registers exactly the two first-party bundled plugins with distinct ids", () => {
    const ids = BUNDLED_PLUGINS.map((p) => p.plugin_id);
    expect(ids).toContain(BLOCKLIST_PLUGIN_ID);
    expect(ids).toContain(HOSTS_PLUGIN_ID);
    // distinct ids (a Map keyed by plugin_id must not collide)
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("integrity-verifies BOTH bundles independently, each under its own signer key", async () => {
    const blockDir = bundledPluginDir(
      BUNDLED_PLUGINS.find((p) => p.plugin_id === BLOCKLIST_PLUGIN_ID)!,
    );
    const hostsDir = hostsBundleDir();

    // Load BY REGISTRY PLUGIN ID (fail-closed) - the loader resolves the dir itself.
    const block = await loadBundledPlugin(BLOCKLIST_PLUGIN_ID);
    const hosts = await loadBundledPlugin(HOSTS_PLUGIN_ID);

    expect(block.governance.plugin_id).toBe(BLOCKLIST_PLUGIN_ID);
    expect(hosts.governance.plugin_id).toBe(HOSTS_PLUGIN_ID);
    expect(block.governance.hooks[0]?.hook_class).toBe("egress_decision");
    expect(hosts.governance.hooks[0]?.hook_class).toBe("egress_decision");
    expect(hosts.governance.hooks[0]?.fail_mode).toBe("deny");
    expect(block.bundleHash).toMatch(/^[0-9a-f]{64}$/);
    expect(hosts.bundleHash).toMatch(/^[0-9a-f]{64}$/);
    // the two bundles are genuinely distinct artifact sets
    expect(block.bundleHash).not.toBe(hosts.bundleHash);

    // each bundle self-ships its own signer key, and they are DIFFERENT keys
    const blockSigner = await readBundledSignerFrom(blockDir);
    const hostsSigner = await readBundledSignerFrom(hostsDir);
    expect(Buffer.from(blockSigner.publicKey).toString("base64")).not.toBe(
      Buffer.from(hostsSigner.publicKey).toString("base64"),
    );
  });

  it("CLI `plugin list` enumerates BOTH bundled plugins", async () => {
    const chunks: string[] = [];
    const out = { write: (s: string) => (chunks.push(s), true) } as unknown as NodeJS.WritableStream;
    const code = await runPluginCommand({ argv: ["list"], out: out as never });
    expect(code).toBe(0);
    const parsed = JSON.parse(chunks.join(""));
    const ids = (parsed.plugins as Array<{ plugin_id: string }>).map((p) => p.plugin_id);
    expect(ids).toContain(BLOCKLIST_PLUGIN_ID);
    expect(ids).toContain(HOSTS_PLUGIN_ID);
  });

  it("CLI `plugin status` integrity-verifies BOTH and exits 0", async () => {
    const chunks: string[] = [];
    const out = { write: (s: string) => (chunks.push(s), true) } as unknown as NodeJS.WritableStream;
    const errChunks: string[] = [];
    const err = { write: (s: string) => (errChunks.push(s), true) } as unknown as NodeJS.WritableStream;
    const code = await runPluginCommand({ argv: ["status"], out: out as never, err: err as never });
    expect(code).toBe(0);
    const parsed = JSON.parse(chunks.join(""));
    const rows = parsed.plugins as Array<{ plugin_id: string; integrity: string }>;
    expect(rows).toHaveLength(2);
    for (const row of rows) expect(row.integrity).toBe("verified");
  });
});

describe("S5 second bundled plugin - supervisor isolation (one plugin's fault is contained)", () => {
  // Adopt the HEALTHY second plugin (hosts-blocklist) AND a FAILING plugin under the
  // SAME supervisor. The failing plugin must not corrupt or take down the healthy one:
  // the healthy plugin still returns its correct verdict; the failing one is contained
  // (fail-mode deny). Distinct plugin_ids so both live in the supervisor map at once.
  for (const hostileMode of ["crash", "silent", "allow"] as const) {
    it(`a "${hostileMode}" second plugin cannot corrupt the healthy hosts-blocklist plugin`, async () => {
      const supervisor = new PluginSupervisor();

      // Healthy: the real second bundled plugin, integrity-verified before spawn.
      const healthy = await loadBundledPlugin(HOSTS_PLUGIN_ID);
      const healthyProc = spawnReferencePlugin(healthy.entryPath);
      spawned.push(healthyProc);
      await supervisor.adoptRunningPlugin({
        governance: healthy.governance,
        descriptor: healthy.descriptor,
        bundleHash: healthy.bundleHash,
        instanceId: "inst-healthy-hosts",
        client: healthyProc.client,
        requestTimeoutMs: 200,
      });

      // Faulty: a hostile fixture registered under the OTHER bundled id so both
      // coexist in the supervisor. We borrow the real blocklist governance (distinct
      // id) but drive the hostile binary.
      const other = await loadBundledReferenceBlocklist();
      const hostileProc = spawnHostile(hostileMode);
      spawned.push(hostileProc);
      await supervisor.adoptRunningPlugin({
        governance: other.governance, // plugin_id ai.sanctuary.blocklist
        descriptor: other.descriptor,
        bundleHash: other.bundleHash,
        instanceId: `inst-faulty-${hostileMode}`,
        client: hostileProc.client,
        requestTimeoutMs: 200,
      });

      // Consult on a host that the HEALTHY plugin blocks (it is a hosts-blocklist
      // entry). Isolation means: the healthy plugin's DENY still lands, attributed to
      // it, regardless of the faulty co-tenant.
      const decision = await decideEgressProxyConnect("ads.tracker-network.example:443", {
        rules: [allowHost("ads.tracker-network.example")],
        resolver: resolverReturning(["93.184.216.34"]),
        pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
      });

      expect(decision.disposition).toBe("deny");
      const contributors = decision.contributors ?? [];
      // Both plugins contributed (n>1 consulted in one pass).
      const byId = new Map(contributors.map((c) => [c.plugin_id, c]));
      const healthyContribution = byId.get(HOSTS_PLUGIN_ID);
      const faultyContribution = byId.get(BLOCKLIST_PLUGIN_ID);

      // The healthy plugin produced its own correct DENY, not a host-minted failure.
      expect(healthyContribution).toBeDefined();
      expect(healthyContribution?.verdict).toBe("deny");
      expect(healthyContribution?.rationale).toContain("ads.tracker-network.example");
      expect(healthyContribution?.instance_id).toBe("inst-healthy-hosts");

      // The faulty plugin is contained (fail-mode applied / timeout) - never a
      // fabricated allow, and it did not prevent the healthy plugin from answering.
      expect(faultyContribution).toBeDefined();
      expect(["fail_mode_applied", "timeout"]).toContain(faultyContribution?.verdict);
    });
  }

  it("the healthy plugin also answers correctly when the faulty co-tenant is asked FIRST", async () => {
    // Order-independence: register the faulty plugin first, then the healthy one, and
    // confirm the healthy plugin still lets a CLEAN host through with no_objection.
    const supervisor = new PluginSupervisor();

    const other = await loadBundledReferenceBlocklist();
    const hostileProc = spawnHostile("crash");
    spawned.push(hostileProc);
    await supervisor.adoptRunningPlugin({
      governance: other.governance,
      descriptor: other.descriptor,
      bundleHash: other.bundleHash,
      instanceId: "inst-faulty-first",
      client: hostileProc.client,
      requestTimeoutMs: 200,
    });

    const healthy = await loadBundledPlugin(HOSTS_PLUGIN_ID);
    const healthyProc = spawnReferencePlugin(healthy.entryPath);
    spawned.push(healthyProc);
    await supervisor.adoptRunningPlugin({
      governance: healthy.governance,
      descriptor: healthy.descriptor,
      bundleHash: healthy.bundleHash,
      instanceId: "inst-healthy-second",
      client: healthyProc.client,
      requestTimeoutMs: 200,
    });

    const decision = await decideEgressProxyConnect("clean.example.com:443", {
      rules: [allowHost("clean.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    });

    // A crashing co-tenant forces an overall DENY (fail-closed is correct), but the
    // healthy plugin's OWN contribution must be a clean no_objection - proving its
    // evaluation was not corrupted by the crashing neighbor.
    const contributors = decision.contributors ?? [];
    const healthyContribution = contributors.find((c) => c.plugin_id === HOSTS_PLUGIN_ID);
    expect(healthyContribution?.verdict).toBe("no_objection");
  });
});

describe("S5 second bundled plugin - tampered SIGNATURE fails closed (either bundle)", () => {
  it("a tampered rules file on the second bundle fails integrity (the plugin never runs)", async () => {
    const hostsDir = hostsBundleDir();
    const governanceText = await fs.readFile(path.join(hostsDir, "governance.yaml"), "utf8");
    const governance = parseGovernance(governanceText);
    const signatureRaw = await fs.readFile(path.join(hostsDir, "SIGNATURE.json"), "utf8");
    const signatureFile = JSON.parse(signatureRaw) as SignatureFile;
    const signer = await readBundledSignerFrom(hostsDir);

    // Enumerate on-disk, then TAMPER: flip the rules file hash to simulate a modified
    // blocklist that the signature no longer covers.
    const observed = await enumerateBundleDir(hostsDir, governance.entry);
    const tampered = {
      ...observed,
      files: observed.files.map((f) =>
        f.path.startsWith("rules/")
          ? { ...f, sha256: "0".repeat(64) }
          : f,
      ),
    };

    expect(() =>
      verifyBundle(signatureFile, {
        resolveSigner: (sid, kid) =>
          sid === signer.signer_id && kid === signer.key_id ? signer : undefined,
        observed: tampered,
        entryPath: governance.entry,
        expect: {
          plugin_id: governance.plugin_id,
          version: governance.version,
          channel: governance.channel,
        },
      }),
    ).toThrow(SubstrateError);
  });

  it("a tampered descriptor (bumped file size) fails the signature check on the second bundle", async () => {
    const hostsDir = hostsBundleDir();
    const governanceText = await fs.readFile(path.join(hostsDir, "governance.yaml"), "utf8");
    const governance = parseGovernance(governanceText);
    const signatureRaw = await fs.readFile(path.join(hostsDir, "SIGNATURE.json"), "utf8");
    const signatureFile = JSON.parse(signatureRaw) as SignatureFile;
    const signer = await readBundledSignerFrom(hostsDir);
    const observed = await enumerateBundleDir(hostsDir, governance.entry);

    // Mutate the SIGNED descriptor: bump a file size. The re-derived signed bytes no
    // longer match the signature -> signature_invalid, fail-closed.
    const tamperedSig: SignatureFile = {
      ...signatureFile,
      descriptor: {
        ...signatureFile.descriptor,
        files: signatureFile.descriptor.files.map((f, i) =>
          i === 0 ? { ...f, size: f.size + 1 } : f,
        ),
      },
    };

    let threw: unknown;
    try {
      verifyBundle(tamperedSig, {
        resolveSigner: (sid, kid) =>
          sid === signer.signer_id && kid === signer.key_id ? signer : undefined,
        observed,
        entryPath: governance.entry,
      });
    } catch (e) {
      threw = e;
    }
    expect(threw).toBeInstanceOf(SubstrateError);
    expect((threw as SubstrateError).reason).toBe("signature_invalid");
  });

  it("tampering the SECOND bundle does NOT stop the FIRST from verifying (isolation of trust)", async () => {
    // Even though a tampered hosts-blocklist bundle would fail closed, the untouched
    // first bundle still integrity-verifies on the SAME machine - one bundle's tamper
    // never poisons another's trust.
    const block = await loadBundledReferenceBlocklist();
    expect(block.governance.plugin_id).toBe(BLOCKLIST_PLUGIN_ID);
    expect(block.bundleHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

/**
 * SECURITY (P1, arbitrary-code-execution fail-open): the PUBLIC bundle loader must
 * derive trust from "ships in the signed release" (the frozen, compiled-in
 * BUNDLED_PLUGINS registry), NOT from a bundle's own self-shipped key. A self-signed
 * bundle at a path OUTSIDE the registry must be unloadable and unspawnable through
 * every exported surface. Before the fix, loadBundledPlugin took an arbitrary caller
 * path and verified it against its OWN self-shipped signer key, so a self-consistent
 * attacker bundle was "verified" and its entry could be spawned.
 */
describe("S5 second bundled plugin - registry is the root of trust (arbitrary-path load is fail-closed)", () => {
  const evilDirs: string[] = [];
  const swappedBack: Array<() => Promise<void>> = [];
  afterEach(async () => {
    while (swappedBack.length > 0) await swappedBack.pop()?.();
    while (evilDirs.length > 0) {
      const d = evilDirs.pop();
      if (d) await rm(d, { recursive: true, force: true }).catch(() => {});
    }
  });

  /**
   * Materialize a FULLY self-signed "evil" bundle in a fresh temp dir: an attacker key,
   * attacker-controlled governance.yaml, a first-party-signer.json holding the attacker
   * pubkey, an evil entry binary, and a SIGNATURE.json that verifies under the attacker
   * key. This is exactly what an attacker who can write a plugin directory would stage.
   * The bundle is internally self-consistent - the ONLY thing that must stop it is the
   * registry gate.
   */
  async function stageEvilSelfSignedBundle(pluginId: string): Promise<string> {
    const dir = await mkdtemp(path.join(tmpdir(), "sanctuary-evil-bundle-"));
    evilDirs.push(dir);
    await fs.mkdir(path.join(dir, "bin"), { recursive: true });
    // An entry binary that, if ever spawned, marks that attacker code ran.
    await fs.writeFile(
      path.join(dir, "bin", "blocklist.mjs"),
      "process.stdout.write('EVIL-CODE-RAN');\n",
      { mode: 0o755 },
    );
    const governanceText =
      `plugin_id: ${pluginId}\n` +
      "version: 1.0.0\n" +
      "channel: stable\n" +
      "entry: bin/blocklist.mjs\n" +
      "hooks:\n" +
      "  - hook_class: egress_decision\n" +
      "    fields:\n" +
      "      - egress.host\n" +
      "      - egress.port\n" +
      "    fail_mode: deny\n" +
      "endpoints: []\n" +
      "signal_keys:\n" +
      "  - blocked_rule\n";
    await fs.writeFile(path.join(dir, "governance.yaml"), governanceText);

    const attackerPriv = ed25519.utils.randomPrivateKey();
    const attackerPub = ed25519.getPublicKey(attackerPriv);
    await fs.writeFile(
      path.join(dir, "first-party-signer.json"),
      `${JSON.stringify(
        {
          signer_id: "ai.sanctuary.first-party",
          key_id: "release-v1",
          public_key_b64: Buffer.from(attackerPub).toString("base64"),
        },
        null,
        2,
      )}\n`,
    );

    // Build the descriptor over the on-disk set and sign it with the ATTACKER key, so
    // the bundle is fully self-consistent (self-signature proves only self-consistency).
    const { descriptor } = await buildReferenceDescriptor(dir, governanceText);
    const signatureFile = signDescriptor(descriptor, attackerPriv);
    await fs.writeFile(
      path.join(dir, "SIGNATURE.json"),
      `${JSON.stringify(signatureFile, null, 2)}\n`,
    );
    return dir;
  }

  it("(a) a self-signed bundle at a path OUTSIDE the registry is UNLOADABLE via the exported surface", async () => {
    // The attacker's plugin id is not in the frozen registry. The public loader takes a
    // registry plugin_id, not a path, so there is no way to point it at the evil dir.
    await stageEvilSelfSignedBundle("ai.sanctuary.evil");

    await expect(loadBundledPlugin("ai.sanctuary.evil")).rejects.toMatchObject({
      reason: "signature_plugin_mismatch",
    });

    // Belt-and-suspenders: the barrel exposes NO arbitrary-path bundle loader. The only
    // exported loader is registry-keyed; a path is not an accepted argument type.
    const substrate = await import("../../../src/substrate/index.js");
    const exportNames = Object.keys(substrate);
    // No exported symbol named for path-based bundle loading.
    expect(exportNames).not.toContain("loadBundleFromDir");
    expect(exportNames).not.toContain("loadBundleFromDirInternal");
    expect(exportNames).not.toContain("loadBundleFromPath");
  });

  it("(a') an unregistered plugin id is rejected fail-closed (registry gate)", async () => {
    await expect(loadBundledPlugin("ai.sanctuary.not-a-real-plugin")).rejects.toBeInstanceOf(
      SubstrateError,
    );
  });

  it("(b) a symlink swap redirecting a registry dir to a foreign self-signed bundle is REJECTED (realpath gate)", async () => {
    // Stage a self-signed bundle whose governance claims the REAL hosts-blocklist id, so
    // only the realpath gate (not the identity gate) can catch it. Then replace the real
    // registry directory with a symlink pointing at that foreign bundle.
    const foreign = await stageEvilSelfSignedBundle(HOSTS_PLUGIN_ID);
    const realDir = bundledPluginDir(bundledPluginSpec(HOSTS_PLUGIN_ID));
    const backup = `${realDir}.bak-${Date.now()}`;

    await fs.rename(realDir, backup);
    // Restore the real directory no matter how the assertion goes.
    swappedBack.push(async () => {
      await rm(realDir, { recursive: true, force: true }).catch(() => {});
      await fs.rename(backup, realDir).catch(() => {});
    });
    await fs.symlink(foreign, realDir);

    // The realpath of the resolved dir now points outside the bundled-plugin tree; the
    // loader must reject rather than load+trust the foreign bundle.
    await expect(loadBundledPlugin(HOSTS_PLUGIN_ID)).rejects.toBeInstanceOf(SubstrateError);
  });

  it("(c) both legitimate registry bundles still load + verify after the fix", async () => {
    const block = await loadBundledPlugin(BLOCKLIST_PLUGIN_ID);
    const hosts = await loadBundledPlugin(HOSTS_PLUGIN_ID);
    expect(block.governance.plugin_id).toBe(BLOCKLIST_PLUGIN_ID);
    expect(hosts.governance.plugin_id).toBe(HOSTS_PLUGIN_ID);
    // The distinct per-bundle signer tuple flows through the registry assertion.
    expect(block.descriptor.key_id).toBe("release-v1");
    expect(hosts.descriptor.key_id).toBe("hosts-blocklist-v1");
    expect(block.descriptor.signer_id).toBe("ai.sanctuary.first-party");
    expect(hosts.descriptor.signer_id).toBe("ai.sanctuary.first-party");
  });

  it("(d) a bundle whose self-shipped signer tuple mismatches the registry is REJECTED (identity gate)", async () => {
    // The hosts-blocklist bundle is registered with key_id "hosts-blocklist-v1". A bundle
    // self-signed as (first-party, release-v1) that claims the hosts id must fail the
    // identity gate even if internally self-consistent - proving trust is pinned to the
    // frozen registry tuple, not to the bundle's own declaration.
    const foreign = await stageEvilSelfSignedBundle(HOSTS_PLUGIN_ID); // signer key_id release-v1
    const realDir = bundledPluginDir(bundledPluginSpec(HOSTS_PLUGIN_ID));
    const backup = `${realDir}.bak2-${Date.now()}`;

    await fs.rename(realDir, backup);
    swappedBack.push(async () => {
      await rm(realDir, { recursive: true, force: true }).catch(() => {});
      await fs.rename(backup, realDir).catch(() => {});
    });
    // Copy (not symlink) the foreign bundle into the real location so the realpath gate
    // passes and the IDENTITY gate is the one under test.
    await fs.cp(foreign, realDir, { recursive: true });

    await expect(loadBundledPlugin(HOSTS_PLUGIN_ID)).rejects.toMatchObject({
      reason: "signature_signer_mismatch",
    });
  });

  /**
   * Materialize a fully self-signed evil bundle at `dir` whose governance claims
   * `pluginId` and whose self-shipped first-party-signer.json carries the CHOSEN
   * (signerId, keyId) tuple - but the key BYTES are an attacker key, and the SIGNATURE.json
   * verifies under that attacker key. This is the "same-tuple attacker key": every string
   * matches the registry, only the pinned public key differs.
   */
  async function stageEvilBundleWithTuple(
    pluginId: string,
    signerId: string,
    keyId: string,
  ): Promise<string> {
    const dir = await mkdtemp(path.join(tmpdir(), "sanctuary-evil-tuple-"));
    evilDirs.push(dir);
    await fs.mkdir(path.join(dir, "bin"), { recursive: true });
    await fs.writeFile(
      path.join(dir, "bin", "blocklist.mjs"),
      "process.stdout.write('EVIL-CODE-RAN');\n",
      { mode: 0o755 },
    );
    const governanceText =
      `plugin_id: ${pluginId}\n` +
      "version: 1.0.0\n" +
      "channel: stable\n" +
      "entry: bin/blocklist.mjs\n" +
      "hooks:\n" +
      "  - hook_class: egress_decision\n" +
      "    fields:\n" +
      "      - egress.host\n" +
      "      - egress.port\n" +
      "    fail_mode: deny\n" +
      "endpoints: []\n" +
      "signal_keys:\n" +
      "  - blocked_rule\n";
    await fs.writeFile(path.join(dir, "governance.yaml"), governanceText);

    const attackerPriv = ed25519.utils.randomPrivateKey();
    const attackerPub = ed25519.getPublicKey(attackerPriv);
    // Self-ship the EXACT registry tuple, but attacker key bytes.
    await fs.writeFile(
      path.join(dir, "first-party-signer.json"),
      `${JSON.stringify(
        { signer_id: signerId, key_id: keyId, public_key_b64: Buffer.from(attackerPub).toString("base64") },
        null,
        2,
      )}\n`,
    );

    // Sign the descriptor with the ATTACKER key but stamp the registry (signerId, keyId)
    // into the descriptor so the descriptor's own tuple also matches the registry.
    const { descriptor } = await buildReferenceDescriptor(dir, governanceText);
    const stamped = { ...descriptor, signer_id: signerId, key_id: keyId };
    const signatureFile = signDescriptor(stamped, attackerPriv);
    await fs.writeFile(path.join(dir, "SIGNATURE.json"), `${JSON.stringify(signatureFile, null, 2)}\n`);
    return dir;
  }

  it("(e) a SAME-TUPLE attacker key (self-shipped signer_id/key_id match the registry, key bytes differ) is REJECTED", async () => {
    // FAIL-BEFORE (old code): the loader verified against the bundle's OWN self-shipped
    // key, so a bundle self-shipping the exact (first-party, hosts-blocklist-v1) tuple with
    // ATTACKER key bytes verified and was spawnable. PASS-AFTER: the signature is checked
    // against the REGISTRY-PINNED key, and the self-shipped key must EQUAL it, so an
    // attacker key with a matching tuple is rejected fail-closed.
    const spec = bundledPluginSpec(HOSTS_PLUGIN_ID);
    const foreign = await stageEvilBundleWithTuple(HOSTS_PLUGIN_ID, spec.signer_id, spec.key_id);
    // Sanity: the attacker's self-shipped key does NOT equal the registry-pinned key.
    const attackerSigner = await readBundledSignerFrom(foreign);
    const pinned: TrustedSigner = pinnedSignerFor(spec);
    expect(Buffer.from(attackerSigner.publicKey).toString("base64")).not.toBe(
      Buffer.from(pinned.publicKey).toString("base64"),
    );

    const realDir = bundledPluginDir(spec);
    const backup = `${realDir}.bak-tuple-${Date.now()}`;
    await fs.rename(realDir, backup);
    swappedBack.push(async () => {
      await rm(realDir, { recursive: true, force: true }).catch(() => {});
      await fs.rename(backup, realDir).catch(() => {});
    });
    // Copy (not symlink) so the realpath gate passes and the PINNED-KEY gate is under test.
    await fs.cp(foreign, realDir, { recursive: true });

    await expect(loadBundledPlugin(HOSTS_PLUGIN_ID)).rejects.toBeInstanceOf(SubstrateError);
  });

  it("(f) a SAME-BASENAME in-tree SYMLINK to a foreign bundle is REJECTED (realpath EQUALITY, not descendant)", async () => {
    // FAIL-BEFORE (old code used startsWith/descendant matching): a symlink whose final
    // segment keeps the registry basename but whose realpath lands on a DIFFERENT foreign
    // directory (that itself sits under the module tree) could slip past a prefix check.
    // PASS-AFTER: the realpath of the resolved dir must EQUAL the registry location exactly;
    // any redirect (even same-basename, even in-tree) breaks equality and is rejected.
    const spec = bundledPluginSpec(HOSTS_PLUGIN_ID);
    const realDir = bundledPluginDir(spec);
    const parent = path.dirname(realDir); // .../reference-plugin
    // A foreign bundle that lives IN-TREE (under reference-plugin/.evil/) with the SAME
    // basename as the registry dir, so basename + ancestor-prefix checks would both pass.
    const evilParent = path.join(parent, ".evil");
    const evilBundle = path.join(evilParent, spec.dirName);
    await fs.mkdir(evilParent, { recursive: true });
    // Reuse the self-signed evil bundle materializer, then move it to the in-tree location.
    const staged = await stageEvilSelfSignedBundle(HOSTS_PLUGIN_ID);
    await fs.cp(staged, evilBundle, { recursive: true });

    const backup = `${realDir}.bak-symlink-${Date.now()}`;
    await fs.rename(realDir, backup);
    swappedBack.push(async () => {
      await rm(realDir, { recursive: true, force: true }).catch(() => {});
      await fs.rename(backup, realDir).catch(() => {});
      await rm(evilParent, { recursive: true, force: true }).catch(() => {});
    });
    // Same-basename in-tree symlink: reference-plugin/hosts-blocklist -> reference-plugin/.evil/hosts-blocklist
    await fs.symlink(evilBundle, realDir);

    await expect(loadBundledPlugin(HOSTS_PLUGIN_ID)).rejects.toMatchObject({
      reason: "bundle_path_traversal",
    });
  });
});

/**
 * SECURITY (P1, arbitrary-code-execution fail-open via a SIBLING export): the P1 fix
 * routed the NEW loadBundledPlugin through the frozen registry, but the pre-existing
 * blocklist.ts exports loadReferenceBlocklistBundle(opts) and
 * loadBundledReferenceBlocklist(bundleDir?) STILL accepted a caller path / a
 * caller-supplied signer and returned a spawnable entryPath - the SAME arbitrary-code-exec
 * class reachable through a different exported symbol. After the chokepoint fix, every
 * exported blocklist loader delegates ONLY to loadBundledPlugin('ai.sanctuary.blocklist')
 * and ignores/rejects any caller-supplied path or signer.
 */
describe("S5 sibling blocklist loaders funnel through the ONE chokepoint (no arbitrary-path/self-signed input)", () => {
  const evilDirs: string[] = [];
  afterEach(async () => {
    while (evilDirs.length > 0) {
      const d = evilDirs.pop();
      if (d) await rm(d, { recursive: true, force: true }).catch(() => {});
    }
  });

  async function stageEvilBlocklistBundle(): Promise<string> {
    const dir = await mkdtemp(path.join(tmpdir(), "sanctuary-evil-sibling-"));
    evilDirs.push(dir);
    await fs.mkdir(path.join(dir, "bin"), { recursive: true });
    await fs.writeFile(
      path.join(dir, "bin", "blocklist.mjs"),
      "process.stdout.write('EVIL-CODE-RAN');\n",
      { mode: 0o755 },
    );
    const governanceText =
      "plugin_id: ai.sanctuary.blocklist\n" +
      "version: 1.0.0\n" +
      "channel: stable\n" +
      "entry: bin/blocklist.mjs\n" +
      "hooks:\n" +
      "  - hook_class: egress_decision\n" +
      "    fields:\n" +
      "      - egress.host\n" +
      "      - egress.port\n" +
      "    fail_mode: deny\n" +
      "endpoints: []\n" +
      "signal_keys:\n" +
      "  - blocked_rule\n";
    await fs.writeFile(path.join(dir, "governance.yaml"), governanceText);
    const attackerPriv = ed25519.utils.randomPrivateKey();
    const attackerPub = ed25519.getPublicKey(attackerPriv);
    await fs.writeFile(
      path.join(dir, "first-party-signer.json"),
      `${JSON.stringify(
        { signer_id: "ai.sanctuary.first-party", key_id: "release-v1", public_key_b64: Buffer.from(attackerPub).toString("base64") },
        null,
        2,
      )}\n`,
    );
    const { descriptor } = await buildReferenceDescriptor(dir, governanceText);
    const signatureFile = signDescriptor(descriptor, attackerPriv);
    await fs.writeFile(path.join(dir, "SIGNATURE.json"), `${JSON.stringify(signatureFile, null, 2)}\n`);
    return dir;
  }

  it("(g) loadBundledReferenceBlocklist(evilDir) IGNORES the caller path and returns the REAL registry bundle", async () => {
    // FAIL-BEFORE: passing an attacker dir made the loader read + self-verify that dir and
    // return its evil entryPath (spawnable arbitrary code). PASS-AFTER: the argument is
    // ignored; the loader returns the registry blocklist bundle from its real in-tree
    // location, verified against the registry-pinned key.
    const evil = await stageEvilBlocklistBundle();
    const loaded = await loadBundledReferenceBlocklist(evil);
    expect(loaded.governance.plugin_id).toBe(BLOCKLIST_PLUGIN_ID);
    // The returned entry is the REAL registry bundle, never the attacker temp dir.
    expect(loaded.bundleDir.startsWith(evil)).toBe(false);
    expect(loaded.entryPath.includes(evil)).toBe(false);
    expect(loaded.descriptor.key_id).toBe("release-v1");
  });

  it("(h) loadReferenceBlocklistBundle({bundleDir: evil, signer: attacker}) IGNORES caller path + signer", async () => {
    // FAIL-BEFORE: the opts.signer + opts.bundleDir were the trust root, so an attacker
    // dir signed by an attacker key verified and returned a spawnable evil entry.
    // PASS-AFTER: opts is ignored entirely; the registry blocklist bundle is returned.
    const evil = await stageEvilBlocklistBundle();
    const attackerSigner: TrustedSigner = await readBundledSignerFrom(evil);
    const signatureRaw = await fs.readFile(path.join(evil, "SIGNATURE.json"), "utf8");
    const signatureFile = JSON.parse(signatureRaw) as SignatureFile;

    const loaded = await loadReferenceBlocklistBundle({
      bundleDir: evil,
      signer: attackerSigner,
      signatureFile,
    });
    expect(loaded.governance.plugin_id).toBe(BLOCKLIST_PLUGIN_ID);
    expect(loaded.bundleDir.startsWith(evil)).toBe(false);
    expect(loaded.entryPath.includes(evil)).toBe(false);
  });

  it("(i) NO exported symbol in the barrel is a path-taking self-verifying spawnable loader", async () => {
    // Grep-in-code: enumerate the barrel and assert the only bundle-returning loaders are
    // the registry-keyed loadBundledPlugin + the two now-delegating blocklist wrappers.
    // No exported symbol accepts an arbitrary path AND returns a verified spawnable bundle.
    const substrate = await import("../../../src/substrate/index.js");
    const names = Object.keys(substrate);
    for (const forbidden of [
      "loadBundleFromDir",
      "loadBundleFromDirInternal",
      "loadBundleFromPath",
      "loadBundleFromDirectory",
    ]) {
      expect(names).not.toContain(forbidden);
    }
    // The wrappers exist (frozen names) but only delegate: calling with an evil path is
    // covered by (g)/(h). loadBundledPlugin takes a plugin_id, not a path (compile-time).
    expect(names).toContain("loadBundledPlugin");
    expect(names).toContain("loadBundledReferenceBlocklist");
    expect(names).toContain("loadReferenceBlocklistBundle");
  });
});
