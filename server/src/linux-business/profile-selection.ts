import fs from "node:fs";
import {isAbsolute, relative, join} from "node:path";
import {jcs} from "../smb/jcs.js";

// Must match config.rs and the complete inventory in profile_selector_vectors.json.
export const BUSINESS_PROFILE_SELECTOR = "/etc/sanctuary/business-profile.json";
export const BUSINESS_SIGNER_CONFIG = "/etc/sanctuary/business-signer.json";
export const BUSINESS_SIGNER_PEER_POLICY = "/etc/sanctuary/business-signer-peer.json";
export const BUSINESS_SIGNER_CONTROLLER_POLICY = "/etc/sanctuary/business-signer-controller.json";
export const BUSINESS_WRITER_CONFIG = "/etc/sanctuary/business-writer.json";
export const BUSINESS_CUSTODY_ROOT = "/var/lib/sanctuary-business-signer";
export const BUSINESS_DRAIN_ROOT = "/var/lib/sanctuary-business-drain";
export const BUSINESS_EVIDENCE = Object.freeze([BUSINESS_PROFILE_SELECTOR, BUSINESS_SIGNER_CONFIG,
  BUSINESS_SIGNER_PEER_POLICY, BUSINESS_SIGNER_CONTROLLER_POLICY, BUSINESS_WRITER_CONFIG,
  BUSINESS_CUSTODY_ROOT, BUSINESS_DRAIN_ROOT]);
export const RAW_STATE_ROOT = "/var/lib/sanctuary";
export const RAW_RUNTIME_ROOT = "/run/sanctuary";
export const RAW_STATE_RELATIVE = "policy/egress/audit-producer.key";
export const RAW_RUNTIME_RELATIVE = "audit-producer.pub";
export const RAW_INVENTORY_MAX_ENTRIES = 64; // Policy bound on unexplained legacy fortress accumulation.
export const SELECTOR_ID_HEX_LENGTH = 16 * 2; // Sixteen-byte enrollment ids as hex pairs.
export const SELECTOR_MAX_BYTES = 512; // Next power of two above the maximal 463-byte selector.
export const SELECTOR_MODE = 0o600; // Owner-only selection.
export const CANDIDATE_MAX_BYTES = 4096 - 1; // Linux PATH_MAX includes NUL.
export const CANDIDATE_MAX_COMPONENTS = (CANDIDATE_MAX_BYTES + 1) / 2;
export const MAX_RAW_CANDIDATES = 2; // One private and one public producer path.
const UNTRUSTED_WRITE_BITS = 0o022; // Group or other write lets another principal hide evidence.
const DIRECTORY_FLAGS = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
const TEST_ROOTS = Symbol.for("sanctuary.test.selector-roots");

export interface SelectorRoots {
  readonly anchor: string;
  readonly expectedOwner: number;
  readonly owners?: Readonly<Record<string, number>>;
  readonly deniedLookup?: readonly string[];
  readonly deniedOpen?: readonly string[];
}
export interface IsolatedSelectorRoots extends SelectorRoots {
  expectOwnerAt(path: string, uid: number): IsolatedSelectorRoots;
  denyLookup(path: string): IsolatedSelectorRoots;
  denyOpen(path: string): IsolatedSelectorRoots;
}
/** Production selection trusts only uid zero under the real root, without test seams. */
export const PRODUCTION_SELECTOR_ROOTS: SelectorRoots = Object.freeze({anchor: "/", expectedOwner: 0});

/** Tests supply an existing owned anchor; fixed inventory paths are relative to it. */
export function isolatedSelectorRoots(root: string): IsolatedSelectorRoots {
  const make = (owners: Readonly<Record<string, number>>, deniedLookup: readonly string[], deniedOpen: readonly string[]): IsolatedSelectorRoots => Object.freeze({
    anchor: root, expectedOwner: process.geteuid!(), owners: Object.freeze(owners),
    deniedLookup: Object.freeze(deniedLookup), deniedOpen: Object.freeze(deniedOpen),
    expectOwnerAt: (path: string, uid: number) => make({...owners, [path]: uid}, deniedLookup, deniedOpen),
    denyLookup: (path: string) => make(owners, [...deniedLookup, path], deniedOpen),
    denyOpen: (path: string) => make(owners, deniedLookup, [...deniedOpen, path]),
  });
  return make({}, [], []);
}
/** The single worker setup installs this reset-stable test state. */
export function installSelectorRootsForTest(roots: SelectorRoots): void {
  (globalThis as Record<symbol, unknown>)[TEST_ROOTS] = roots;
}
/** Callers forward explicit fixtures or use the process-wide worker fixture, otherwise production. */
export function defaultSelectorRoots(): SelectorRoots {
  return (globalThis as Record<symbol, SelectorRoots | undefined>)[TEST_ROOTS] ?? PRODUCTION_SELECTOR_ROOTS;
}
export type ProfileRefusal = "SelectorInvalid" | "InventoryAmbiguous" | "LegacyWithEnrollment" | "RawInventoryPresent";
export type LinuxProfileSelection = {kind: "LegacyV1"; reason: "Explicit" | "NoBusinessEvidence"}
  | {kind: "Business"; reason: null} | {kind: "Refused"; reason: ProfileRefusal};
/** These are the TS legacy producer paths; must match the runtime's storage-path contract. */
export function rawCandidates(storagePath: string): string[] {
  return [join(storagePath, "policy/egress/audit-producer.key"), join(storagePath, "policy/egress/audit-producer.pub")];
}
/** Both operator entrypoints use one fixed refusal without exposing inventory paths. */
export function profileRefusalText(selection: LinuxProfileSelection): string {
  return `sanctuary castle-wall: Linux business profile selected or refused (${selection.reason ?? selection.kind}); installed business signing is not enabled in this build`;
}
const exact = (v: unknown, names: string[]): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v)
  && Object.keys(v).length === names.length && names.every(name => Object.hasOwn(v, name));
function validSelector(v: unknown): v is Record<string, unknown> {
  if (!exact(v, ["version", "profile", "fortress_id", "machine_id", "enrollment_revision", "digests"])) return false;
  const hex = (value: unknown, length: number, prefix = "") => typeof value === "string" && new RegExp(`^${prefix}[a-f0-9]{${length}}$`).test(value);
  const digests = ["custody_envelope_digest", "roster_digest", "anchor_digest"];
  return v.version === 1 && ["business", "legacy-v1"].includes(v.profile as string)
    && hex(v.fortress_id, SELECTOR_ID_HEX_LENGTH) && hex(v.machine_id, SELECTOR_ID_HEX_LENGTH)
    && Number.isSafeInteger(v.enrollment_revision) && (v.enrollment_revision as number) >= 1
    && exact(v.digests, digests) && digests.every(key => hex((v.digests as Record<string, unknown>)[key], 32 * 2, "sha256:"));
}
const code = (error: unknown): string | undefined => (error as NodeJS.ErrnoException)?.code;

/** Profile selection reads only root-owned on-disk evidence; an absent or false environment opt-in never selects legacy on a host with business evidence, and a caller-supplied path can only add refusal. */
export function selectLinuxProfile(roots: SelectorRoots, candidates: readonly string[]): LinuxProfileSelection {
  const held: number[] = [];
  const refused = (reason: ProfileRefusal): LinuxProfileSelection => ({kind: "Refused", reason});
  const seam = (path: string, opening: boolean) => {
    if (roots.deniedLookup?.includes(path) || opening && roots.deniedOpen?.includes(path)) {
      throw Object.assign(new Error("selection denied"), {code: "EACCES"});
    }
  };
  const owner = (path: string) => roots.owners?.[path] ?? roots.expectedOwner;
  const trust = (fd: number, path: string) => {
    const stat = fs.fstatSync(fd);
    // Every held parent must retain exclusive ownership of names before absence can be evidence.
    if (!stat.isDirectory() || stat.uid !== owner(path) || (stat.mode & UNTRUSTED_WRITE_BITS) !== 0) {
      throw Object.assign(new Error("selection parent"), {code: "EACCES"});
    }
  };
  const directory = (path: string) => {
    let parent = held[0], current = "";
    for (const component of path.split("/").filter(Boolean)) {
      current = current ? `${current}/${component}` : component;
      seam(current, true);
      // Node/libuv opens with close-on-exec; the kernel magic link names the held parent only.
      const fd = fs.openSync(`/proc/self/fd/${parent}/${component}`, DIRECTORY_FLAGS);
      held.push(fd);
      trust(fd, current);
      parent = fd;
    }
    return parent;
  };
  const present = (path: string) => {
    seam(path, false);
    const components = path.split("/");
    const leaf = components.pop()!;
    const fd = directory(components.join("/"));
    fs.lstatSync(`/proc/self/fd/${fd}/${leaf}`);
    return true;
  };
  try {
    seam("", true);
    held.push(fs.openSync(roots.anchor, DIRECTORY_FLAGS));
    trust(held[0], "");
    // A missing proc transport must not masquerade as an absent selector.
    const transport = fs.statSync(`/proc/self/fd/${held[0]}`);
    const anchor = fs.fstatSync(held[0]);
    if (transport.dev !== anchor.dev || transport.ino !== anchor.ino) return refused("InventoryAmbiguous");
    let selector: "business" | "legacy-v1" | undefined;
    const path = BUSINESS_PROFILE_SELECTOR.slice(1);
    try {
      seam(path, true);
      const parent = directory("etc/sanctuary");
      let fd: number;
      try { fd = fs.openSync(`/proc/self/fd/${parent}/business-profile.json`, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
      catch (error) { if (code(error) === "ELOOP") return refused("SelectorInvalid"); throw error; }
      held.push(fd);
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== owner(path) || (stat.mode & 0o7777) !== SELECTOR_MODE || stat.size > SELECTOR_MAX_BYTES) return refused("SelectorInvalid");
      const bytes = Buffer.alloc(SELECTOR_MAX_BYTES + 1);
      let size = 0;
      while (size < bytes.length) {
        const read = fs.readSync(fd, bytes, size, bytes.length - size, null);
        if (read === 0) break;
        size += read;
      }
      if (size > SELECTOR_MAX_BYTES) return refused("SelectorInvalid");
      try {
        // The selector names the profile and its enrollment; it grants nothing, and its digests are compared with custody and the drain before any key is opened.
        const value: unknown = JSON.parse(bytes.subarray(0, size).toString("utf8"));
        if (!validSelector(value) || !Buffer.from(jcs(value)).equals(bytes.subarray(0, size))) return refused("SelectorInvalid");
        selector = value.profile as "business" | "legacy-v1";
      } catch { return refused("SelectorInvalid"); }
    } catch (error) { if (code(error) !== "ENOENT") return refused("InventoryAmbiguous"); }
    let evidence = false;
    for (const path of BUSINESS_EVIDENCE.slice(1)) {
      try { evidence = present(path.slice(1)) || evidence; }
      catch (error) { if (code(error) !== "ENOENT") return refused("InventoryAmbiguous"); }
    }
    if (selector === "legacy-v1") return evidence ? refused("LegacyWithEnrollment") : {kind: "LegacyV1", reason: "Explicit"};
    if (selector === undefined && !evidence) return {kind: "LegacyV1", reason: "NoBusinessEvidence"};
    for (const [root, suffix] of [[RAW_STATE_ROOT, RAW_STATE_RELATIVE], [RAW_RUNTIME_ROOT, RAW_RUNTIME_RELATIVE]]) {
      let fd: number;
      try { fd = directory(root.slice(1)); }
      catch (error) { if (code(error) === "ENOENT") continue; return refused("InventoryAmbiguous"); }
      let dir: fs.Dir;
      try { dir = fs.opendirSync(`/proc/self/fd/${fd}/.`, {bufferSize: 1}); }
      catch { return refused("RawInventoryPresent"); }
      try {
        let count = 0;
        for (;;) {
          const entry = dir.readSync();
          if (!entry) break;
          if (entry.name === "." || entry.name === "..") continue;
          if (++count > RAW_INVENTORY_MAX_ENTRIES) return refused("RawInventoryPresent");
          try { if (present(`${root.slice(1)}/${entry.name}/${suffix}`)) return refused("RawInventoryPresent"); }
          catch (error) { if (code(error) !== "ENOENT") return refused("RawInventoryPresent"); }
        }
      } catch { return refused("RawInventoryPresent"); }
      finally { dir.closeSync(); }
    }
    // The common byte/component caps bound held fds and syscalls as in config.rs.
    if (candidates.length > MAX_RAW_CANDIDATES) return refused("RawInventoryPresent");
    for (const candidate of candidates) {
      if (!isAbsolute(candidate) || Buffer.byteLength(candidate) > CANDIDATE_MAX_BYTES || candidate.includes("\0") || candidate.split("/").some(p => p === "." || p === "..")) return refused("RawInventoryPresent");
      const path = relative(roots.anchor, candidate);
      if (!path || path.startsWith("../") || path === ".." || isAbsolute(path) || path.split("/").length > CANDIDATE_MAX_COMPONENTS) return refused("RawInventoryPresent");
      try { if (present(path)) return refused("RawInventoryPresent"); }
      catch (error) { if (code(error) !== "ENOENT") return refused("RawInventoryPresent"); }
    }
    return {kind: "Business", reason: null};
  } catch { return refused("InventoryAmbiguous"); }
  finally { for (const fd of held.reverse()) fs.closeSync(fd); }
}
