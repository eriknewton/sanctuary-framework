/**
 * The subject, integrity and manifest bindings of the fetched tarball bytes.
 * The manifest is signed with a generated test key and checked through
 * `verifyReleaseManifestWithKey`; the pinned-key path is checked against the
 * real 1.8.4 manifest.
 */
import { describe, expect, it } from "vitest";
import { mint, type StatementEvidence } from "../../src/verify-release/evidence.js";
import { decodeSriSha512, state_MANIFEST, state_SUBJECT } from "../../src/verify-release/subject.js";
import { verifyReleaseManifest } from "../../src/release-manifest.js";
import { generateKeypair } from "../../src/core/identity.js";
import { denyAllNetwork, fixtureJson, sha256Hex, sha512, signManifest, verifyWithTestKey } from "./helpers.js";

denyAllNetwork();

const VERSION = "2.0.0-rc.1";
const NAME = `pkg:npm/%40sanctuary-framework/mcp-server@${VERSION}`;
const TARBALL = Buffer.from("synthetic tarball bytes");
const HEX = sha512(TARBALL).toString("hex");
const SRI = `sha512-${sha512(TARBALL).toString("base64")}`;
const ARTIFACT = `sanctuary-framework-mcp-server-${VERSION}.tgz`;

const statement = (subjects: Array<{ name: string; sha512: string | undefined }>): StatementEvidence =>
  mint({ state: "state_STATEMENT", subjects });
const versionDocument = (integrity: unknown) => ({ dist: { integrity } });

describe("subject", () => {
  it("one subject naming this version with the tarball's sha512, and a matching SRI, passes", () => {
    const result = state_SUBJECT(statement([{ name: NAME, sha512: HEX }]), versionDocument(SRI), TARBALL, VERSION);
    expect(result).toMatchObject({ ok: true });
    expect((result as any).evidence.sha512.equals(sha512(TARBALL))).toBe(true);
  });

  it("two subjects refuse subject-invalid", () => {
    expect(state_SUBJECT(statement([{ name: NAME, sha512: HEX }, { name: NAME, sha512: HEX }]), versionDocument(SRI), TARBALL, VERSION)).toEqual({ ok: false, reason: "subject-invalid" });
  });
  it("no subject refuses subject-invalid", () => {
    expect(state_SUBJECT(statement([]), versionDocument(SRI), TARBALL, VERSION)).toEqual({ ok: false, reason: "subject-invalid" });
  });
  it.each([
    ["another version", "pkg:npm/%40sanctuary-framework/mcp-server@2.0.0"],
    ["another package", "pkg:npm/%40sanctuary-framework/other@2.0.0-rc.1"],
    ["an unencoded scope", "pkg:npm/@sanctuary-framework/mcp-server@2.0.0-rc.1"],
  ])("a subject naming %s refuses subject-invalid", (_label, name) => {
    expect(state_SUBJECT(statement([{ name, sha512: HEX }]), versionDocument(SRI), TARBALL, VERSION)).toEqual({ ok: false, reason: "subject-invalid" });
  });
  it.each([
    ["missing", undefined],
    ["one character short", HEX.slice(1)],
    ["one character long", `${HEX}0`],
    ["uppercase", HEX.toUpperCase()],
    ["not hex", `${HEX.slice(1)}g`],
  ])("a subject sha512 that is %s refuses digest-malformed", (_label, digest) => {
    expect(state_SUBJECT(statement([{ name: NAME, sha512: digest }]), versionDocument(SRI), TARBALL, VERSION)).toEqual({ ok: false, reason: "digest-malformed" });
  });
  it.each([
    ["two tokens", `${SRI} ${SRI}`],
    ["a sha256 token", `sha256-${Buffer.alloc(32).toString("base64")}`],
    ["unpadded base64", SRI.replace(/==$/, "")],
    ["a non-canonical last character", `${SRI.slice(0, -3)}B==`],
    ["missing", undefined],
    ["not a string", 7],
  ])("an SRI with %s refuses digest-malformed", (_label, integrity) => {
    expect(state_SUBJECT(statement([{ name: NAME, sha512: HEX }]), versionDocument(integrity), TARBALL, VERSION)).toEqual({ ok: false, reason: "digest-malformed" });
  });
  it("a subject digest that is not the tarball's refuses subject-digest-mismatch", () => {
    const other = sha512(Buffer.from("other")).toString("hex");
    expect(state_SUBJECT(statement([{ name: NAME, sha512: other }]), versionDocument(SRI), TARBALL, VERSION)).toEqual({ ok: false, reason: "subject-digest-mismatch" });
  });
  it("an SRI that is not the tarball's refuses packument-integrity-mismatch", () => {
    const other = `sha512-${sha512(Buffer.from("other")).toString("base64")}`;
    expect(state_SUBJECT(statement([{ name: NAME, sha512: HEX }]), versionDocument(other), TARBALL, VERSION)).toEqual({ ok: false, reason: "packument-integrity-mismatch" });
  });
  it("the real 1.8.4 SRI decodes to the real subject digest", () => {
    const document = fixtureJson<{ dist: { integrity: string } }>("version-1.8.4.json");
    expect(decodeSriSha512(document.dist.integrity)!.toString("hex")).toBe("27f1761dffda369ef8a450a5e2b2241c6889d53f3689f623235b2029fe84f187a35afa35a75f116888dd41835691ebeca757db5316c7f326055c502ce68fa33c");
  });
});

describe("release manifest", () => {
  const good = () => signManifest({ version: VERSION, artifact_hashes: { [ARTIFACT]: sha256Hex(TARBALL) } });

  it("a test-key manifest for this version listing exactly the tarball with its sha256 passes", () => {
    expect(state_MANIFEST(good(), TARBALL, VERSION, verifyWithTestKey)).toEqual({ ok: true, evidence: { state: "state_MANIFEST", sha256: sha256Hex(TARBALL) } });
  });
  it("a manifest signed by a key other than the one verified against refuses manifest-invalid", () => {
    const other = signManifest(good().body, generateKeypair().privateKey);
    expect(state_MANIFEST(other, TARBALL, VERSION, verifyWithTestKey)).toEqual({ ok: false, reason: "manifest-invalid" });
  });
  it("the production pinned key refuses a test-key manifest", () => {
    expect(state_MANIFEST(good(), TARBALL, VERSION, verifyReleaseManifest)).toEqual({ ok: false, reason: "manifest-invalid" });
  });
  it("the production pinned key accepts the real 1.8.4 manifest's signature and version", () => {
    const manifest = fixtureJson("release-manifest-1.8.4.json");
    // The real tarball is not committed, so the digest step refuses; reaching it proves signature and shape passed.
    expect(state_MANIFEST(manifest, TARBALL, "1.8.4", verifyReleaseManifest)).toEqual({ ok: false, reason: "manifest-digest-mismatch" });
  });
  it("another version refuses manifest-version-mismatch", () => {
    const other = signManifest({ version: "2.0.0", artifact_hashes: { [ARTIFACT]: sha256Hex(TARBALL) } });
    expect(state_MANIFEST(other, TARBALL, VERSION, verifyWithTestKey)).toEqual({ ok: false, reason: "manifest-version-mismatch" });
  });
  it("two artifacts refuse manifest-invalid", () => {
    const two = signManifest({ version: VERSION, artifact_hashes: { [ARTIFACT]: sha256Hex(TARBALL), "checksums.txt": sha256Hex(TARBALL) } });
    expect(state_MANIFEST(two, TARBALL, VERSION, verifyWithTestKey)).toEqual({ ok: false, reason: "manifest-invalid" });
  });
  it("one artifact under another name refuses manifest-invalid", () => {
    const renamed = signManifest({ version: VERSION, artifact_hashes: { "mcp-server.tgz": sha256Hex(TARBALL) } });
    expect(state_MANIFEST(renamed, TARBALL, VERSION, verifyWithTestKey)).toEqual({ ok: false, reason: "manifest-invalid" });
  });
  it("a malformed artifact hash refuses manifest-invalid", () => {
    const upper = signManifest({ version: VERSION, artifact_hashes: { [ARTIFACT]: sha256Hex(TARBALL).toUpperCase() } });
    expect(state_MANIFEST(upper, TARBALL, VERSION, verifyWithTestKey)).toEqual({ ok: false, reason: "manifest-invalid" });
  });
  it("a digest mismatch refuses manifest-digest-mismatch", () => {
    expect(state_MANIFEST(good(), Buffer.from("other bytes"), VERSION, verifyWithTestKey)).toEqual({ ok: false, reason: "manifest-digest-mismatch" });
  });
});
