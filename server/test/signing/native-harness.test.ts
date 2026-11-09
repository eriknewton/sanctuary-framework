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
