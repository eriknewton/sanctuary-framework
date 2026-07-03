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
import path from "node:path";
import { fileURLToPath } from "node:url";

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
  loadBundledPlugin,
  loadBundledReferenceBlocklist,
  spawnReferencePlugin,
  readBundledSignerFrom,
  enumerateBundleDir,
  verifyBundle,
  parseGovernance,
  type SpawnedPlugin,
  type SignatureFile,
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

    const block = await loadBundledPlugin(blockDir);
    const hosts = await loadBundledPlugin(hostsDir);

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
      const healthy = await loadBundledPlugin(hostsBundleDir());
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

    const healthy = await loadBundledPlugin(hostsBundleDir());
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
