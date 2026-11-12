/// <reference types="node" />
/** Must match artifact-policy.mjs; runtime parsers, not casts, establish these result types. */
export type ArtifactMode = "release" | "fixture";
export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };
export interface Member { path: string; type: "file"; size_bytes: number; sha256: string }
export interface ArtifactManifest { format: "SANCTUARY_EVIDENCE_ARTIFACT_V1"; mode: ArtifactMode; package_name: string; package_version: string; source_revision: string; source_archive_sha256: string; tarball_sha256: string; members: Member[] }
export interface Candidate { format: "SANCTUARY_EVIDENCE_CANDIDATE_V1"; mode: ArtifactMode; source_revision: string; tarball: "candidate.tgz"; manifest: "artifact-manifest.json"; tarball_sha256: string; manifest_sha256: string }
export interface Pins { mode: ArtifactMode; source_revision: string; tarball_sha256: string; manifest_sha256: string; dependency_lock_sha256?: string }
export interface Archive { members: (Member & { bytes: Buffer })[]; expanded_bytes: number }
export const MAX_ARTIFACT_BYTES: number, MAX_TAR_BYTES: number, MAX_MANIFEST_BYTES: number, MAX_MEMBERS: number;
export const NON_RELEASE_MARKER: "NON_RELEASE", NON_RELEASE_TEXT: string;
export const ARTIFACT_FORMAT: ArtifactManifest["format"], CANDIDATE_FORMAT: Candidate["format"];
export const BIN: Readonly<Record<"verify-evidence-pack" | "check-evidence-pack-artifact", string>>;
export const ARTIFACT_FILES: Readonly<{ tarball: "candidate.tgz"; manifest: "artifact-manifest.json"; receipt: "candidate.json" }>;
export const CHECK_FLAGS: readonly string[];
export const ARTIFACT_HELP: string, ARTIFACT_REFUSED: string, ARTIFACT_USAGE: string;
export function artifactSuccess(mode: ArtifactMode): string;
export function digest(bytes: Uint8Array | string): string;
export function requireValid<T>(parsed: Parsed<T>): T;
export function registry(mode: ArtifactMode): string[];
export function memberMode(path: string): number;
export function readBounded(path: string, limit: number): Buffer;
export function parseJson(bytes: Uint8Array): unknown;
export function parseManifest(bytes: Uint8Array): Parsed<ArtifactManifest>;
export function parseCandidate(bytes: Uint8Array): Parsed<Candidate>;
export function parsePackage(bytes: Uint8Array): { name: string; version: string };
export function parseArchive(bytes: Buffer, mode: ArtifactMode): Parsed<Archive>;
export function memberRows(members: readonly Member[]): Member[];
export function checkArtifact(tarball: Buffer, manifestBytes: Uint8Array, pins: Pins): Parsed<Archive & { manifest: ArtifactManifest }>;
