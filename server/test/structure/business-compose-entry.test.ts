// fail-before-exempt: isolated native Business constructors and complete unprivileged delivery selections read workflows outside server/src.
// W-COMPOSE-ENTRY
import {it, expect} from "vitest";
import {readFileSync, mkdtempSync, mkdirSync, writeFileSync, unlinkSync, rmdirSync, chmodSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";
import {spawnSync, execFileSync} from "node:child_process";
import {nativeBinary} from "../fixtures/k1-service.js";
const root = resolve("..");
const read = (path: string) => readFileSync(join(root, path), "utf8");
const main = () => read("castle-wall-daemon/src/main.rs");
function fixture(business: boolean, run: (root: string) => void): void {
  const path = mkdtempSync(join(tmpdir(), "compose-")); chmodSync(path, 0o700);
  if (business) {
    mkdirSync(join(path, "etc")); mkdirSync(join(path, "etc/sanctuary"));
    const digest = "sha256:" + "a".repeat(64);
    writeFileSync(join(path, "etc/sanctuary/business-profile.json"), JSON.stringify({digests:{anchor_digest:digest,custody_envelope_digest:digest,roster_digest:digest},enrollment_revision:1,fortress_id:"a".repeat(32),machine_id:"a".repeat(32),profile:"business",version:1}), {mode:0o600});
  }
  try { run(path); } finally {
    if (business) { unlinkSync(join(path, "etc/sanctuary/business-profile.json")); rmdirSync(join(path, "etc/sanctuary")); rmdirSync(join(path, "etc")); }
    rmdirSync(path);
  }
}
function invoke(path: string, args: string[]): number | null {
  const result = spawnSync(nativeBinary("debug", "wall"), ["--test-profile-root", path, ...args], {encoding:"utf8", timeout:5000, env:{VITEST:"true"}});
  expect(result.error).toBeUndefined(); expect(result.signal).toBeNull(); return result.status;
}
it("Consumes the selected business capability W-COMPOSE-ENTRY", () => {
  const source = main();
  const arm = source.slice(source.indexOf("ProfileSelection::Business(selection)"), source.indexOf("ProfileSelection::Refused(reason)"));
  expect(arm).toMatch(/castle_wall_daemon::compose_for_test\(\s*selection,/);
  expect(read("castle-wall-daemon/src/business_profile/compose.rs")).toContain("_selection: crate::config::BusinessSelection");
  expect(read("castle-wall-daemon/src/lib.rs")).toContain('#[cfg(all(target_os = "linux", feature = "test-isolation"))]\npub use business_profile::compose::compose_for_test;');
});
it("Requires the explicit composition argument W-COMPOSE-ENTRY", () => {
  fixture(true, path => expect(invoke(path, ["--test-business-compose"])).toBe(2));
});
it("Rejects composition on a legacy selection W-COMPOSE-ENTRY", () => {
  fixture(false, path => expect(invoke(path, ["--test-business-compose", path])).toBe(2));
});
it("Keeps business selection closed without composition W-COMPOSE-ENTRY", () => {
  fixture(true, path => expect(invoke(path, [])).toBe(78));
});
it("Omits composition from release artifacts W-COMPOSE-ENTRY", () => {
  const release = readFileSync(nativeBinary("release", "wall"));
  expect(release.includes(Buffer.from("--test-business-compose"))).toBe(false);
  expect(release.includes(Buffer.from("compose_for_test"))).toBe(false);
  expect(Buffer.from(main()).includes(Buffer.from("--test-business-compose"))).toBe(true);
});
it("Requires all composition dependencies W-COMPOSE-ENTRY", () => {
  fixture(true, path => expect(invoke(path, ["--test-business-compose", path])).toBe(78));
  const actor = read("castle-wall-daemon/src/business_profile/append_actor.rs");
  const dependencies = actor.slice(actor.indexOf("pub struct Dependencies {"), actor.indexOf("/// Owns one append"));
  for (const name of ["writer", "drain", "store", "clock", "evidence", "sink", "fortress", "revision"]) expect(dependencies).toContain(`pub ${name}:`);
  expect(dependencies).not.toContain("Option<");
});
it("Pins the complete value flag registries W-COMPOSE-ENTRY", () => {
  const script = join(root, "castle-wall-daemon/packaging/ubuntu/assert-install-runtime.py");
  expect(() => execFileSync("python3", ["-c", "import runpy,sys; runpy.run_path(sys.argv[1])['check_seam_parity']()", script], {stdio:"pipe"})).not.toThrow();
  expect(main()).toContain('value_options.push("--test-business-compose")');
  expect(main()).toMatch(/position\(\|a\| a == "--test-business-compose"\)[\s\S]{0,250}args.get\(index \+ 1\)/);
});
it("Registers and executes the isolated append target W-COMPOSE-ENTRY", () => {
  const cargo = read("castle-wall-daemon/Cargo.toml");
  expect(cargo).toMatch(/name = "linux_business_signed_append"\s+path = "tests\/linux_business_signed_append.rs"\s+required-features = \["test-isolation"\]/);
  const workflow = read(".github/workflows/castle-wall-linux.yml");
  expect(workflow).toContain("linux_business_append_foundations linux_business_signed_append linux_business_signer_client");
  expect(workflow).toContain("--test linux_business_signed_append real_wall_writer_drain_commit_and_original_with_synthetic_signer 2>&1 | tee /dev/stderr | grep -Eq '^test result. ok. 1 passed; 0 failed; 0 ignored;'");
});

it("pins Business construction, installed Legacy mode and the complete delivery capability extension",()=>{
  const server=read("castle-wall-daemon/src/ipc/server.rs");
  expect(read("castle-wall-daemon/src/daemon.rs")).not.toContain("start_business");
  const config=server.slice(server.indexOf("pub struct BusinessIpcConfig"),server.indexOf("impl BusinessIpcConfig"));
  expect(config).not.toMatch(/wal_writer|producer_signer/);
  expect(server).toContain("Self::start_composed(");
  expect(read("server/src/castle-wall/runtime/linux-activation-gate.ts")).toContain('mode: {kind:"Legacy"}');
  const native=read("castle-wall-daemon/src/ipc/messages.rs");
  const ts=read("server/src/castle-wall/ipc/messages.ts");
  const names=[...native.matchAll(/CAP_BUSINESS_DELIVERY: &str = "([^"]+)"/g)].map(m=>m[1]);
  expect(names).toEqual([...ts.matchAll(/CAP_BUSINESS_DELIVERY = "([^"]+)"/g)].map(m=>m[1]));
  expect(names).toEqual(["business_delivery_v1"]);
  const workflow=read(".github/workflows/castle-wall-linux.yml");
  expect(workflow).toContain("--test linux_business_signed_append signed_append::business_ -- --ignored --test-threads=1 2>&1 | tee /dev/stderr | grep -Eq '^test result. ok. 7 passed; 0 failed; 0 ignored;'");
  expect(workflow).toContain("--test linux_business_signed_append signed_append::delivery_ -- --include-ignored --test-threads=1 2>&1 | tee /dev/stderr | grep -Eq '^test result. ok. 4 passed; 0 failed; 0 ignored;'");
  for(const selection of ["--lib business_peer_gate_precedes_challenge_and_equal_uid_reaches_status", "--test linux_business_signed_append business_ipc_durable_ts_fact_after_real_d_original"]) {
    expect(workflow).toContain(selection+" -- --ignored 2>&1 | tee /dev/stderr | grep -Eq '^test result. ok. 1 passed; 0 failed; 0 ignored;'");
  }
});
