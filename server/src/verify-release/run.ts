/**
 * The strictly ordered run of `sanctuary verify-release`.
 *
 * state_RUNTIME -> state_TARGET -> state_FETCH -> state_BUNDLE_SELECT ->
 * state_SIGSTORE -> state_IDENTITY -> state_STATEMENT -> state_SUBJECT ->
 * state_MANIFEST -> state_ARCHIVE -> state_INSTALLED -> state_VERDICT.
 *
 * The first refusal stops the run and later steps report `not-run`. There is
 * no partial pass: `verified` comes only from `constructVerifiedVerdict`, with
 * one evidence object from every state. Each step's evidence is accepted only
 * if the run deadline has not passed when the step returns. Nothing is carried
 * between runs: every run builds its own deadline, map and evidence.
 */

import { RUN_DEADLINE_MS, tarballUrl } from "./constants.js";
import { Deadline, type Clock } from "./deadline.js";
import {
  STEP_NAMES,
  constructVerifiedVerdict,
  passed,
  type BundleSelectEvidence,
  type FetchEvidence,
  type IdentityEvidence,
  type RuntimeEvidence,
  type SigstoreEvidence,
  type StatementEvidence,
  type StepName,
} from "./evidence.js";
import { refuse, type FetchResource, type RefusalReason, type StepOutcome } from "./reasons.js";
import { satisfiesEngineRange } from "./runtime.js";
import { state_ARCHIVE } from "./archive.js";
import { state_IDENTITY } from "./identity.js";
import { state_INSTALLED } from "./installed.js";
import { state_BUNDLE_SELECT, state_SIGSTORE } from "./sigstore.js";
import { state_STATEMENT } from "./statement.js";
import { state_MANIFEST, state_SUBJECT } from "./subject.js";
import { readTrustedRootBytes } from "./trust-root.js";
import { fetchResource, resourcePolicies, type HttpRequester } from "./transport.js";
import { state_TARGET, type TargetRequest } from "./target.js";
import type { ManifestVerificationResult } from "../release-manifest.js";

export type StepResult = "passed" | "refused" | "not-run";

export interface RunReport {
  verdict: "verified" | "refused";
  /** null when the run stopped before the version was known. */
  version: string | null;
  /** null when the run stopped before the target was resolved. */
  target: string | null;
  steps: Array<{ step: StepName; result: StepResult }>;
  reason?: RefusalReason;
}

/** The four provenance states. Production wires the real Sigstore pipeline; a test may inject a stub. */
export interface ProvenanceSteps {
  bundleSelect(document: unknown): StepOutcome<BundleSelectEvidence>;
  sigstore(selection: BundleSelectEvidence): Promise<StepOutcome<SigstoreEvidence>>;
  identity(sigstore: SigstoreEvidence): StepOutcome<IdentityEvidence>;
  statement(sigstore: SigstoreEvidence, identity: IdentityEvidence): StepOutcome<StatementEvidence>;
}

/** The production provenance states: the committed root, the real verifier, the identity adapter, the shared schema. */
export const PRODUCTION_PROVENANCE: ProvenanceSteps = {
  bundleSelect: state_BUNDLE_SELECT,
  sigstore: async selection => state_SIGSTORE(selection, await readTrustedRootBytes()),
  identity: sigstore => state_IDENTITY(sigstore.certificate),
  statement: (sigstore, identity) => state_STATEMENT(sigstore.payloadType, sigstore.payload, identity),
};

export interface VerifyReleaseDeps {
  requester: HttpRequester;
  clock: Clock;
  /** `process.versions.node` in production. */
  nodeVersion: string;
  /** The running copy's version, `getSanctuaryVersion()`. */
  runningVersion: string;
  /** The running package root (self mode): `hermesPackageRootFromEntry(<cli.ts module URL>)`. */
  selfRoot: string;
  /** `verifyReleaseManifest` (pinned key) in production. */
  verifyManifest: (value: unknown) => ManifestVerificationResult;
  provenance: ProvenanceSteps;
}

function parseJson(bytes: Buffer): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) };
  } catch {
    return { ok: false };
  }
}

/** state_FETCH: the four resources, in order; the tarball URL is compared before the tarball is fetched. */
async function state_FETCH(version: string, requester: HttpRequester, deadline: Deadline): Promise<StepOutcome<FetchEvidence>> {
  const policies = resourcePolicies(version);
  const document = async (resource: FetchResource): Promise<StepOutcome<unknown>> => {
    const fetched = await fetchResource(policies[resource], requester, deadline);
    if (!fetched.ok) return fetched;
    const parsed = parseJson(fetched.evidence);
    return parsed.ok ? { ok: true, evidence: parsed.value } : refuse(`fetch-failed:${resource}`);
  };
  const versionDocument = await document("version-document");
  if (!versionDocument.ok) return versionDocument;
  const distTarball = ((versionDocument.evidence as { dist?: unknown } | null)?.dist as { tarball?: unknown } | null)?.tarball;
  // The document may only confirm the composed URL; it never chooses where the tarball comes from.
  if (distTarball !== tarballUrl(version)) return refuse("tarball-url-mismatch");
  const attestations = await document("attestations");
  if (!attestations.ok) return attestations;
  const tarball = await fetchResource(policies.tarball, requester, deadline);
  if (!tarball.ok) return tarball;
  const manifest = await document("manifest");
  if (!manifest.ok) return manifest;
  return passed({
    state: "state_FETCH",
    versionDocument: versionDocument.evidence,
    attestations: attestations.evidence,
    tarball: tarball.evidence,
    manifest: manifest.evidence,
  });
}

export async function runVerifyRelease(request: TargetRequest, deps: VerifyReleaseDeps): Promise<RunReport> {
  const results = new Map<StepName, StepResult>(STEP_NAMES.map(name => [name, "not-run"]));
  let version: string | null = null;
  let target: string | null = null;
  const report = (verdict: RunReport["verdict"], reason?: RefusalReason): RunReport => ({
    verdict,
    version,
    target,
    steps: STEP_NAMES.map(step => ({ step, result: results.get(step)! })),
    ...(reason === undefined ? {} : { reason }),
  });

  const deadline = new Deadline(deps.clock, RUN_DEADLINE_MS);
  class Stop extends Error {
    constructor(readonly reason: RefusalReason) {
      super(reason);
    }
  }
  /** Accept a step's evidence only if it passed and the deadline still holds when it returns. */
  const accept = <E>(step: StepName, outcome: StepOutcome<E>): E => {
    const reason = !outcome.ok ? outcome.reason : deadline.expired() ? "deadline-exceeded" : null;
    if (reason !== null) {
      results.set(step, "refused");
      throw new Stop(reason);
    }
    results.set(step, "passed");
    return (outcome as { evidence: E }).evidence;
  };

  try {
    // state_RUNTIME: before anything imports a Sigstore module.
    const runtime = accept("runtime", satisfiesEngineRange(deps.nodeVersion)
      ? passed<RuntimeEvidence>({ state: "state_RUNTIME", nodeVersion: deps.nodeVersion })
      : refuse("runtime-unsupported"));
    const targetEvidence = accept("target", await state_TARGET(request, deps.selfRoot, deps.runningVersion));
    target = targetEvidence.root;
    version = targetEvidence.version;
    const fetched = accept("fetch", await state_FETCH(targetEvidence.version, deps.requester, deadline));
    const bundle = accept("bundle-select", deps.provenance.bundleSelect(fetched.attestations));
    const sigstore = accept("sigstore", await deps.provenance.sigstore(bundle));
    const identity = accept("identity", deps.provenance.identity(sigstore));
    const statement = accept("statement", deps.provenance.statement(sigstore, identity));
    const subject = accept("subject", state_SUBJECT(statement, fetched.versionDocument, fetched.tarball, targetEvidence.version));
    const manifest = accept("manifest", state_MANIFEST(fetched.manifest, fetched.tarball, targetEvidence.version, deps.verifyManifest));
    const archive = accept("archive", await state_ARCHIVE(fetched.tarball, deadline));
    const installed = accept("installed", await state_INSTALLED(targetEvidence.root, archive, deadline));
    // state_VERDICT
    const verdict = constructVerifiedVerdict(
      { runtime, target: targetEvidence, fetch: fetched, bundle, sigstore, identity, statement, subject, manifest, archive, installed },
      deadline,
    );
    return verdict.ok ? report("verified") : report("refused", verdict.reason);
  } catch (error) {
    if (error instanceof Stop) return report("refused", error.reason);
    throw error;
  } finally {
    deadline.dispose();
  }
}
