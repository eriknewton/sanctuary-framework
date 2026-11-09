import { it, expect } from "vitest";
import { readFileSync } from "node:fs";
const read=(path:string)=>readFileSync(`../${path}`,"utf8");
it("every supervisor fault arm uses sticky settlement and one deadline writer",()=>{
  const source=read("castle-wall-daemon/src/business_profile/signer_service.rs");
  expect(source.match(/self\.deadline = /g)).toHaveLength(1);
  expect(source).not.toContain("locking_deadline =");
  expect(source).toContain("mod settlement {");
  const helper=source.slice(source.indexOf("mod settlement {"),source.indexOf("pub use settlement::Settlement"));
  expect(helper).not.toMatch(/pub(?:\([^)]*\))?\s+(?:deadline|cleanup|faulted):/);
  expect(source).not.toMatch(/w\.settlement\.(?:deadline|cleanup|faulted)\s*=/);
  expect(source).toContain("!w.settlement.acknowledged()");
  expect(source).toContain("current.min(proposed)");
  expect(source).toContain("self.cleanup && !self.faulted && success");
  expect(source).toContain("lease.reaped(w.settlement.cooperative(status.success()))");
  expect(source).toContain("w.error.as_raw_fd()");
  const faultArms = ["input write", "stderr bytes", "stderr read", "accumulated size", "declared size", "signature", "unsolicited signature", "unsolicited revoked signature", "protocol", "stdout read", "truncated output"];
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
it("live peer witnesses require successful receipt and isolate the UID comparison",()=>{
  const source=read("castle-wall-daemon/tests/linux_business_signer_peer.rs");
  const witness=source.slice(source.indexOf("fn live_sender_packet"),source.indexOf("fn message_pidfd_refuses"));
  expect(witness).toContain("libc::pipe2");
  expect(witness.indexOf("let packet = receive")).toBeLessThan(witness.indexOf("libc::waitpid"));
  expect(witness).toContain("packet.unwrap()");
  expect(witness).toContain("peer.test_identity_refusal(packet)");
  expect(witness).not.toContain('error.to_string(), "K1_REFUSED"');
  const peer=read("castle-wall-daemon/src/business_profile/signer_peer.rs");
  expect(peer).toContain("Some(IdentityRefusal::Uid)");
  expect(peer).toContain("fn uid_refusal_is_distinct_from_receive_and_process_faults");
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

it("fail-before markers describe only the current native enforcement change",()=>{
  // The SMB marker may only state why this change sits outside the server/src revert, never an older change's reason.
  const smb=readFileSync("test/smb/contracts.test.ts","utf8").split("\n").slice(0,30).filter(line=>line.includes("fail-before-exempt:"));
  expect(smb).toHaveLength(1);
  expect(smb[0]).toContain("read castle-wall-daemon Rust sources and this file's own violation scanner, which verify-fail-before does not revert");
  const attendance=readFileSync("test/signing/attendance.test.ts","utf8").split("\n")[0];
  expect(attendance).toContain("This change exercises Rust settlement through rebuilt native binaries");
  expect(attendance).toContain("fixture additions only observe the marker and coordinate worker frames");
});
