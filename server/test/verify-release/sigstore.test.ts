/**
 * The Sigstore step over the real 1.8.4 provenance bundle, offline, against
 * the committed trusted root: the success witness for the provenance half, the
 * foreign-package refusal, and every tampering and proof-shape refusal.
 */
import { describe, expect, it } from "vitest";
import { state_BUNDLE_SELECT, state_SIGSTORE, rootIsStaleAt, VERIFIER_THRESHOLDS } from "../../src/verify-release/sigstore.js";
import { state_IDENTITY } from "../../src/verify-release/identity.js";
import { state_STATEMENT } from "../../src/verify-release/statement.js";
import type { BundleSelectEvidence, SigstoreEvidence } from "../../src/verify-release/evidence.js";
import { attestations184, denyAllNetwork, foreignSlsaBundle, slsaBundle184, trustedRootBytes } from "./helpers.js";

denyAllNetwork();

/** The 1.8.4 entry's integratedTime, seconds; read from the fixture, restated so a fixture swap is visible. */
const INTEGRATED_TIME_184 = 1788678487;

function select(bundle: unknown): BundleSelectEvidence {
  const selected = state_BUNDLE_SELECT({ attestations: [{ predicateType: "https://slsa.dev/provenance/v1", bundle }] });
  if (!selected.ok) throw new Error(`fixture bundle not selectable: ${selected.reason}`);
  return selected.evidence;
}

async function verify(bundle: unknown, root: Buffer | null = trustedRootBytes()) {
  return state_SIGSTORE(select(bundle), root);
}

function rootWith(edit: (root: any) => void): Buffer {
  const root = JSON.parse(trustedRootBytes().toString("utf8"));
  edit(root);
  return Buffer.from(JSON.stringify(root), "utf8");
}

function flipBase64Char(text: string, index: number): string {
  const replacement = text[index] === "A" ? "B" : "A";
  return text.slice(0, index) + replacement + text.slice(index + 1);
}

describe("real 1.8.4 SLSA bundle, offline", () => {
  it("passes the Sigstore, identity and statement steps with the committed root and no network", async () => {
    const sigstore = await verify(slsaBundle184());
    expect(sigstore.ok).toBe(true);
    const evidence = (sigstore as { evidence: SigstoreEvidence }).evidence;
    expect(evidence.integratedTime).toBe(INTEGRATED_TIME_184);
    expect(evidence.payloadType).toBe("application/vnd.in-toto+json");
    const identity = state_IDENTITY(evidence.certificate);
    expect(identity).toMatchObject({ ok: true, evidence: { repositoryId: "1188932575", repositoryOwnerId: "38265121", ref: "refs/heads/main", trigger: "workflow_dispatch" } });
    const statement = state_STATEMENT(evidence.payloadType, evidence.payload, (identity as any).evidence);
    expect(statement.ok).toBe(true);
    expect((statement as any).evidence.subjects).toEqual([{
      name: "pkg:npm/%40sanctuary-framework/mcp-server@1.8.4",
      sha512: "27f1761dffda369ef8a450a5e2b2241c6889d53f3689f623235b2029fe84f187a35afa35a75f116888dd41835691ebeca757db5316c7f326055c502ce68fa33c",
    }]);
  });

  it("pins one tlog entry, one SCT and one timestamp as the library thresholds", () => {
    expect(VERIFIER_THRESHOLDS).toEqual({ tlogThreshold: 1, ctlogThreshold: 1, timestampThreshold: 1 });
  });
});

describe("foreign provenance", () => {
  it("passes the generic cryptographic check, then refuses at identity naming the SAN", async () => {
    const sigstore = await verify(foreignSlsaBundle());
    expect(sigstore.ok).toBe(true);
    const identity = state_IDENTITY((sigstore as { evidence: SigstoreEvidence }).evidence.certificate);
    expect(identity).toEqual({ ok: false, reason: "identity-mismatch:san" });
  });
});

describe("tampering", () => {
  it("one byte changed in the DSSE payload refuses", async () => {
    const bundle = slsaBundle184();
    const statement = Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8");
    bundle.dsseEnvelope.payload = Buffer.from(statement.replace("attempts/1", "attempts/2"), "utf8").toString("base64");
    const result = await verify(bundle);
    expect(result).toMatchObject({ ok: false });
    expect((result as { reason: string }).reason).toMatch(/^sigstore-invalid:[A-Z_]+$/);
  });

  it("one byte changed in the DSSE signature refuses", async () => {
    const bundle = slsaBundle184();
    const signature = Buffer.from(bundle.dsseEnvelope.signatures[0].sig, "base64");
    signature[signature.length - 1] ^= 0x01;
    bundle.dsseEnvelope.signatures[0].sig = signature.toString("base64");
    const result = await verify(bundle);
    expect((result as { reason: string }).reason).toMatch(/^sigstore-invalid:[A-Z_]+$/);
  });
});

describe("transparency-log evidence", () => {
  const entryOf = (bundle: any) => bundle.verificationMaterial.tlogEntries[0];

  it("the real entry carries both an inclusion proof with checkpoint and an inclusion promise", () => {
    const entry = entryOf(slsaBundle184());
    expect(entry.inclusionProof.checkpoint.envelope.length).toBeGreaterThan(0);
    expect(entry.inclusionPromise.signedEntryTimestamp.length).toBeGreaterThan(0);
  });

  it("an inclusion promise alone (proof removed) refuses proof-required", async () => {
    const bundle = slsaBundle184();
    delete entryOf(bundle).inclusionProof;
    expect(await verify(bundle)).toEqual({ ok: false, reason: "sigstore-invalid:proof-required" });
  });

  it("a proof without its checkpoint refuses proof-required", async () => {
    const bundle = slsaBundle184();
    entryOf(bundle).inclusionProof.checkpoint = { envelope: "" };
    expect(await verify(bundle)).toEqual({ ok: false, reason: "sigstore-invalid:proof-required" });
  });

  it("the proof kept with the SET removed refuses set-required", async () => {
    const bundle = slsaBundle184();
    delete entryOf(bundle).inclusionPromise;
    expect(await verify(bundle)).toEqual({ ok: false, reason: "sigstore-invalid:set-required" });
  });

  it("an altered checkpoint refuses", async () => {
    const bundle = slsaBundle184();
    const proof = entryOf(bundle).inclusionProof;
    proof.checkpoint.envelope = proof.checkpoint.envelope.replace(/\n(\d+)\n/, (_: string, size: string) => `\n${Number(size) + 1}\n`);
    expect(await verify(bundle)).toEqual({ ok: false, reason: "sigstore-invalid:TLOG_INCLUSION_PROOF_ERROR" });
  });

  it("an altered Merkle path refuses", async () => {
    const bundle = slsaBundle184();
    const proof = entryOf(bundle).inclusionProof;
    proof.hashes[0] = flipBase64Char(proof.hashes[0], 0);
    expect(await verify(bundle)).toEqual({ ok: false, reason: "sigstore-invalid:TLOG_INCLUSION_PROOF_ERROR" });
  });

  it("an altered integratedTime refuses (the SET covers it)", async () => {
    const bundle = slsaBundle184();
    entryOf(bundle).integratedTime = String(INTEGRATED_TIME_184 + 1);
    expect(await verify(bundle)).toEqual({ ok: false, reason: "sigstore-invalid:TLOG_INCLUSION_PROMISE_ERROR" });
  });

  it("an altered logId refuses", async () => {
    const bundle = slsaBundle184();
    entryOf(bundle).logId.keyId = flipBase64Char(entryOf(bundle).logId.keyId, 2);
    const result = await verify(bundle);
    expect((result as { reason: string }).reason).toMatch(/^sigstore-invalid:TLOG_INCLUSION_(PROMISE|PROOF)_ERROR$/);
  });

  it("a second tlog entry refuses, since which entry authenticated the time would be ambiguous", async () => {
    const bundle = slsaBundle184();
    bundle.verificationMaterial.tlogEntries.push(structuredClone(entryOf(bundle)));
    expect(await verify(bundle)).toEqual({ ok: false, reason: "sigstore-invalid:TLOG_ENTRY_COUNT" });
  });

  it("an integratedTime that is not a positive integer refuses before the library runs", async () => {
    const bundle = slsaBundle184();
    entryOf(bundle).integratedTime = "0";
    expect(await verify(bundle)).toEqual({ ok: false, reason: "sigstore-invalid:INTEGRATED_TIME" });
  });
});

describe("trust material", () => {
  it("a chain to a root that does not hold the issuing Fulcio CA refuses", async () => {
    const root = rootWith(r => { r.certificateAuthorities = r.certificateAuthorities.filter((ca: any) => ca.validFor.end !== undefined); });
    expect(await verify(slsaBundle184(), root)).toEqual({ ok: false, reason: "sigstore-invalid:CERTIFICATE_ERROR" });
  });

  it("a one-byte change to the committed root's log key refuses the real bundle", async () => {
    const root = rootWith(r => {
      const log = r.tlogs.find((t: any) => t.baseUrl === "https://rekor.sigstore.dev");
      log.publicKey.rawBytes = flipBase64Char(log.publicKey.rawBytes, 60);
    });
    const result = await verify(slsaBundle184(), root);
    expect((result as { reason: string }).reason).toMatch(/^sigstore-invalid:/);
  });

  it("an unreadable or invalid root refuses", async () => {
    expect(await verify(slsaBundle184(), null)).toEqual({ ok: false, reason: "sigstore-invalid:TRUSTED_ROOT_UNAVAILABLE" });
    expect(await verify(slsaBundle184(), Buffer.from("{", "utf8"))).toEqual({ ok: false, reason: "sigstore-invalid:TRUSTED_ROOT_INVALID" });
  });

  it("a message-signature bundle refuses DSSE_REQUIRED", async () => {
    const bundle = slsaBundle184();
    const signature = bundle.dsseEnvelope.signatures[0].sig;
    delete bundle.dsseEnvelope;
    bundle.messageSignature = { messageDigest: { algorithm: "SHA2_256", digest: Buffer.alloc(32, 1).toString("base64") }, signature };
    expect(await state_SIGSTORE({ state: "state_BUNDLE_SELECT", bundle } as BundleSelectEvidence, trustedRootBytes())).toEqual({ ok: false, reason: "sigstore-invalid:DSSE_REQUIRED" });
  });

  it("a bundle signed by a bare public key, like npm's publish attestation, refuses CERTIFICATE_REQUIRED", async () => {
    const publish = attestations184().attestations.find(a => a.predicateType !== "https://slsa.dev/provenance/v1")!.bundle;
    expect(await state_SIGSTORE({ state: "state_BUNDLE_SELECT", bundle: publish } as BundleSelectEvidence, trustedRootBytes())).toEqual({ ok: false, reason: "sigstore-invalid:CERTIFICATE_REQUIRED" });
  });

  it("a bundle the library cannot parse refuses", async () => {
    const bundle = slsaBundle184();
    bundle.mediaType = "application/vnd.dev.sigstore.bundle.v9+json";
    expect(await verify(bundle)).toEqual({ ok: false, reason: "sigstore-invalid:BUNDLE_INVALID" });
  });
});

describe("validity windows over the real bundle", () => {
  const T = INTEGRATED_TIME_184;
  const iso = (seconds: number) => new Date(seconds * 1000).toISOString();
  /** Every CA and every log key window set to one window. */
  const windowed = (start: number | undefined, end: number | undefined) => rootWith(r => {
    const window = { ...(start === undefined ? { start: iso(0) } : { start: iso(start) }), ...(end === undefined ? {} : { end: iso(end) }) };
    for (const ca of r.certificateAuthorities) ca.validFor = window;
    for (const log of r.tlogs) log.publicKey.validFor = window;
  });

  it("a window ending one second before the log time refuses trusted-root-stale", async () => {
    expect(await verify(slsaBundle184(), windowed(undefined, T - 1))).toEqual({ ok: false, reason: "trusted-root-stale" });
  });
  it("a window ending exactly at the log time verifies", async () => {
    expect((await verify(slsaBundle184(), windowed(undefined, T))).ok).toBe(true);
  });
  it("a window starting one second after the log time refuses trusted-root-stale", async () => {
    expect(await verify(slsaBundle184(), windowed(T + 1, undefined))).toEqual({ ok: false, reason: "trusted-root-stale" });
  });
  it("a window starting exactly at the log time verifies", async () => {
    expect((await verify(slsaBundle184(), windowed(T, undefined))).ok).toBe(true);
  });

  it("stale needs both sides uncovered: a covering log key alone keeps the failure a library refusal", () => {
    const at = new Date(T * 1000);
    const before = { start: new Date(0), end: new Date((T - 1) * 1000) };
    const covering = { start: new Date(0) };
    expect(rootIsStaleAt({ certificateAuthorities: [before], tlogs: [before] }, at)).toBe(true);
    expect(rootIsStaleAt({ certificateAuthorities: [before], tlogs: [covering] }, at)).toBe(false);
    expect(rootIsStaleAt({ certificateAuthorities: [covering], tlogs: [before] }, at)).toBe(false);
    expect(rootIsStaleAt({ certificateAuthorities: [{}], tlogs: [{}] }, at)).toBe(true);
  });
});
