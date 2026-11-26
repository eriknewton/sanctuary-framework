/**
 * Synthetic releases for the verify-release orchestration and CLI tests: a
 * tarball built in memory, its version document and test-key manifest, routes
 * for a modelled requester, an install of its files, and an injected
 * provenance stub whose subject digest is the synthetic tarball's sha512.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { manifestArtifactName, manifestUrl, tarballUrl, versionDocumentUrl, attestationsUrl } from "../../src/verify-release/constants.js";
import { passed, type CertificateView } from "../../src/verify-release/evidence.js";
import type { ProvenanceSteps, VerifyReleaseDeps } from "../../src/verify-release/run.js";
import { state_BUNDLE_SELECT } from "../../src/verify-release/sigstore.js";
import type { RawResponse } from "../../src/verify-release/transport.js";
import { ManualClock, attestations184, modelledRequester, response, sha256Hex, sha512, signManifest, tgz, verifyWithTestKey } from "./helpers.js";

const roots: string[] = [];
/** Remove every temp root made since the last call; call from afterEach. */
export function cleanupTempRoots(): void {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
}
export function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "vr-run-"));
  roots.push(root);
  return root;
}

export const NAME = "@sanctuary-framework/mcp-server";
export const VERSION = "3.1.0";
const SLSA = "https://slsa.dev/provenance/v1";


export interface Release {
  version: string;
  files: Record<string, string>;
  tarball: Buffer;
  versionDocument: unknown;
  manifest: unknown;
}

export function release(version = VERSION, extra: Record<string, string> = {}): Release {
  const files = { "package.json": JSON.stringify({ name: NAME, version }), "README.md": "synthetic", "dist/cli.js": "#!/usr/bin/env node\n", ...extra };
  const tarball = tgz(Object.entries(files).map(([path, body]) => ({ path: `package/${path}`, body })));
  return {
    version,
    files,
    tarball,
    versionDocument: { name: NAME, version, dist: { tarball: tarballUrl(version), integrity: `sha512-${sha512(tarball).toString("base64")}` } },
    manifest: signManifest({ version, artifact_hashes: { [manifestArtifactName(version)]: sha256Hex(tarball) } }),
  };
}

export function install(files: Record<string, string>): string {
  const root = tempRoot();
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return root;
}

/** A DSSE-shaped attestation whose SIGNED predicateType is SLSA; the stub's sigstore state does not verify it. */
const slsaAttestation = () => ({ predicateType: SLSA, bundle: { dsseEnvelope: { payload: Buffer.from(JSON.stringify({ predicateType: SLSA })).toString("base64") } } });

export const routesFor = (r: Release, options: { hops?: number; withPublish?: boolean; attestations?: unknown } = {}) => {
  const hops = options.hops ?? 1;
  const assetUrl = (n: number) => `https://release-assets.githubusercontent.com/asset/${n}?sig=x`;
  const routes: Record<string, () => RawResponse> = {
    [versionDocumentUrl(r.version)]: () => response(200, JSON.stringify(r.versionDocument)),
    [attestationsUrl(r.version)]: () => response(200, JSON.stringify(options.attestations ?? {
      attestations: options.withPublish ? [attestations184().attestations[0], slsaAttestation()] : [slsaAttestation()],
    })),
    [tarballUrl(r.version)]: () => response(200, r.tarball, { "content-length": String(r.tarball.length) }),
  };
  if (hops === 0) {
    routes[manifestUrl(r.version)] = () => response(200, JSON.stringify(r.manifest));
  } else {
    routes[manifestUrl(r.version)] = () => response(302, "", { location: assetUrl(1) });
    for (let n = 1; n < hops; n++) routes[assetUrl(n)] = () => response(302, "", { location: assetUrl(n + 1) });
    routes[assetUrl(hops)] = () => response(200, JSON.stringify(r.manifest));
  }
  return routes;
};

/** Injected provenance stub: real bundle selection, stubbed Sigstore, identity and statement evidence. */
export function stubProvenance(r: Release, subjectHex = sha512(r.tarball).toString("hex")): ProvenanceSteps {
  const certificate: CertificateView = { sanUri: undefined, extensions: [] };
  return {
    bundleSelect: state_BUNDLE_SELECT,
    sigstore: async () => passed({ state: "state_SIGSTORE", payload: Buffer.alloc(0), payloadType: "application/vnd.in-toto+json", certificate, integratedTime: 1 }),
    identity: () => passed({ state: "state_IDENTITY", repositoryUri: "r", repositoryId: "1", repositoryOwnerId: "2", ref: "refs/heads/main", trigger: "workflow_dispatch" }),
    statement: () => passed({ state: "state_STATEMENT", subjects: [{ name: `pkg:npm/%40sanctuary-framework/mcp-server@${r.version}`, sha512: subjectHex }] }),
  };
}

export function deps(r: Release, overrides: Partial<VerifyReleaseDeps> = {}, routeOptions: Parameters<typeof routesFor>[1] = {}): VerifyReleaseDeps {
  return {
    requester: modelledRequester(routesFor(r, routeOptions)),
    clock: new ManualClock(),
    nodeVersion: "22.23.3",
    runningVersion: r.version,
    selfRoot: "/nonexistent-self-root",
    verifyManifest: verifyWithTestKey,
    provenance: stubProvenance(r),
    ...overrides,
  };
}

