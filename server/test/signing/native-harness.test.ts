// fail-before-exempt: This change checks missing harness artifacts and test fixture discovery outside the server source delta, so reverting server source cannot break these absence guards.
import {it,expect} from "vitest";
import {mkdtempSync,rmdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {nativeBinary} from "../fixtures/k1-service.js";

it("missing native harness root fails with a named message",()=>{
  const saved=process.env.SANCTUARY_K1_TEST_BINARIES;
  try{delete process.env.SANCTUARY_K1_TEST_BINARIES;expect(()=>nativeBinary("debug","signer")).toThrow("K1_NATIVE_BINARIES_REQUIRED");}
  finally{if(saved===undefined)delete process.env.SANCTUARY_K1_TEST_BINARIES;else process.env.SANCTUARY_K1_TEST_BINARIES=saved;}
});
it("unbuilt native artifact fails with a named message",()=>{
  const saved=process.env.SANCTUARY_K1_TEST_BINARIES;const root=mkdtempSync(join(tmpdir(),"k1-empty-"));
  try{process.env.SANCTUARY_K1_TEST_BINARIES=root;expect(()=>nativeBinary("release","unlock")).toThrow("K1_NATIVE_BINARY_UNBUILT: release/unlock");}
  finally{rmdirSync(root);if(saved===undefined)delete process.env.SANCTUARY_K1_TEST_BINARIES;else process.env.SANCTUARY_K1_TEST_BINARIES=saved;}
});
it.skipIf(process.platform!=="linux")("Linux harness contains both signer and unlock in both profiles",()=>{
  for(const profile of ["debug","release"] as const)for(const name of ["signer","unlock"] as const)expect(nativeBinary(profile,name)).toContain(`/${profile}/sanctuary-business-${name}`);
});

import {serviceFixture} from "../fixtures/k1-service.js";
import {canonicalBytes} from "../../src/signing/contract.js";
import {LENGTH_BYTES, parsePublicFrame} from "../../src/signing/service.js";
it.skipIf(process.platform !== "linux")("relay readiness is the authenticated reply to its initial STATUS", async () => {
  const fixture = await serviceFixture();
  try {
    const first = fixture.frames[0];
    expect(first.readUInt32BE()).toBe(first.length - LENGTH_BYTES);
    expect(first.subarray(LENGTH_BYTES)).toEqual(Buffer.from(canonicalBytes({op:"STATUS"})));
    const reply = fixture.frames[1];
    expect(reply.readUInt32BE()).toBe(reply.length - LENGTH_BYTES);
    expect(parsePublicFrame(reply.subarray(LENGTH_BYTES)).op).toBe("STATUS");
    expect((await fixture.client.status()).state).toBe("LOCKED");
  } finally { await fixture.close(); }
});

import {readFileSync} from "node:fs";
it.skipIf(process.platform !== "linux")("fresh signer reports the complete typed STATUS identity", async () => {
  const fixture = await serviceFixture();
  try {
    const status = await fixture.client.status();
    expect(Object.keys(status).sort()).toEqual(["anchor_digest","anchor_revision","boot_id","expires_boottime_ns","grant","op","started_boottime_ns","state"]);
    expect(status.anchor_digest).toBeNull(); expect(status.anchor_revision).toBeNull();
    expect(status.boot_id).toBe(readFileSync("/proc/sys/kernel/random/boot_id","utf8").trim().replaceAll("-",""));
    expect(status.started_boottime_ns).toBe("0"); expect(status.expires_boottime_ns).toBe("0"); expect(status.state).toBe("LOCKED");
  } finally {await fixture.close();}
});
it.skipIf(process.platform !== "linux").each([
  ["short", "short"], ["malformed", "01234567-89ab-cdef-0123-456789abcdeg\n"],
  ["overlong", "01234567-89ab-cdef-0123-456789abcdef\nextra"],
])("startup with a %s boot id refuses before READY", async (_name, text) => {
  const fixture = await serviceFixture();
  try {
    const observation = await fixture.probeBootId(text);
    expect(observation.ready).toBe(0);
    expect(observation.code).toBe(1); expect(observation.stderr).toBe("K1_REFUSED\n");
  } finally {await fixture.close();}
});
it.skipIf(process.platform !== "linux")("startup with a valid boot id reaches READY", async () => {
  const fixture = await serviceFixture();
  try {expect((await fixture.probeBootId("01234567-89ab-cdef-0123-456789abcdef\n")).ready).toBe(1);}
  finally {await fixture.close();}
});
