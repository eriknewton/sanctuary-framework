import { it, expect } from "vitest";
import { readFileSync } from "node:fs";
const read=(path:string)=>readFileSync(`../${path}`,"utf8");
it("every supervisor fault arm uses sticky settlement and one deadline writer",()=>{
  const source=read("castle-wall-daemon/src/business_profile/signer_service.rs");
  expect(source.match(/self\.deadline = /g)).toHaveLength(1);
  expect(source).not.toContain("locking_deadline =");
  expect(source).toContain("current.min(proposed)");
  expect(source).toContain("self.cleanup && !self.faulted && success");
  expect(source).toContain("lease.reaped(w.settlement.cooperative(status.success()))");
  expect(source).toContain("w.error.as_raw_fd()");
  const faultArms = ["input write", "stderr bytes", "stderr read", "accumulated size", "declared size", "signature", "unsolicited signature", "protocol", "stdout read", "truncated output"];
  expect(source.match(/w\.settlement\.fault\(now\)/g)).toHaveLength(faultArms.length);
});
it("release trust checks precede the native toolchain and inventory its locked inputs",()=>{
  const workflow=read(".github/workflows/publish-on-tag.yml");
  const toolchain=workflow.indexOf("- name: Install pinned Rust");
  expect(toolchain).toBeGreaterThan(workflow.indexOf("- name: Release trust checks"));
  expect(workflow.slice(toolchain,workflow.indexOf("- name: Run tests"))).not.toMatch(/- name: (?!Install pinned Rust)/);
  expect(workflow).not.toContain('echo "SANCTUARY_K1_TEST_BINARIES=$SANCTUARY_K1_TEST_BINARIES"');
  expect(read("scripts/check-release-dependency-pins.mjs")).toContain('"castle-wall-daemon/Cargo.lock"');
  expect(read(".github/workflows/test-baseline-guard.yml")).toContain("# castle-wall-daemon/Cargo.lock, build scripts and proc-macros;");
});
it("worker acknowledgement follows finally and the storage refusal matches the contract",()=>{
  const worker=readFileSync("src/signing/worker.ts","utf8");
  expect(worker.slice(worker.indexOf('request.header.op === "LOCK"'),worker.indexOf('const {header, preimage}'))).not.toContain('publicFrame({op: "WIPED"})');
  expect(worker).toContain("void main().then(acknowledgeWipe, acknowledgeWipe)");
  expect(worker).toMatch(/must match refuse\(\) in contract.ts\.[\s\n]*async write\(\): Promise<void> \{ throw new Error\("K1_REFUSED"\); \}/);
});
it("root receive witnesses require the named refusal or a mismatched packet",()=>{
  const source=read("castle-wall-daemon/tests/linux_business_signer_peer.rs");
  const witnesses=source.slice(source.indexOf("fn root_real_uid_refuses"),source.indexOf("fn message_pidfd_refuses"));
  expect(witnesses).not.toContain("if let Ok(packet)");
  expect(witnesses.match(/Err\(error\) => assert_eq!\(error.to_string\(\), "K1_REFUSED"\)/g)).toHaveLength(2);
  expect(witnesses.match(/assert_eq!\(status, 0\)/g)).toHaveLength(2);
});

it("source pins remain platform independent while native probes are Linux gated",()=>{
  const source=readFileSync("test/structure/k1-release-closure.test.ts","utf8");
  expect(source).toContain('test("worker closure');
  expect(source).toContain('test("frame constants');
  expect(source).toContain('it("Linux only: pinned runtime');
});

it("both service listeners require the fixture-tested capability parser",()=>{
  const peer=read("castle-wall-daemon/src/business_profile/signer_peer.rs");
  const service=read("castle-wall-daemon/src/business_profile/signer_service.rs");
  expect(peer).toContain("validate_capability_status(&status, bounding)");
  expect(service).toContain("signer_peer::empty_capabilities(peer.pid, paths.owner == ROOT_UID)");
  expect(service).toContain("if lifecycle_sealed || !readable(listener)");
});
