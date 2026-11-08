import {it,expect} from "vitest";
import {readFileSync} from "node:fs";
import {execFileSync} from "node:child_process";
it("worker closure excludes secret observers and credential injection",()=>{
  const worker=readFileSync("dist/k1/signing-worker.cjs","utf8");
  expect(worker.includes("__testObserveSecretBuffer")).toBe(false);expect(worker).not.toContain("--test-service");
  const imports=[...new Set([...worker.matchAll(/require\(["']([^"']+)["']\)/g)].map(match=>match[1]))].sort();
  expect(imports).toEqual(["node:async_hooks","node:crypto","node:fs","node:tty"]);
  const source=readFileSync("src/signing/worker.ts","utf8");expect(source).not.toContain("process.env");expect(source).not.toContain("process.argv");
});
it("pinned runtime disables SIGUSR1 inspector",()=>{expect(()=>execFileSync(process.execPath,["--disable-sigusr1","--no-addons","-e","process.kill(process.pid, 'SIGUSR1'); setTimeout(() => process.exit(require('node:inspector').url() ? 1 : 0), 25)"],{env:{},timeout:2000})).not.toThrow();});
it("frame constants and service installation paths agree on both sides",()=>{
  const rust=readFileSync("../castle-wall-daemon/src/business_profile/signer_service.rs","utf8"),custody=readFileSync("../castle-wall-daemon/src/business_profile/custody.rs","utf8"),unit=readFileSync("../castle-wall-daemon/systemd/sanctuary-business-signer.service","utf8");
  expect(rust).toContain("pub const LENGTH_BYTES: usize = 4;");expect(custody).toContain('"/usr/libexec/sanctuary-business-signer"');expect(unit).toContain("ExecStart=/usr/libexec/sanctuary-business-signer");
  expect(custody).toContain('"/var/lib/sanctuary-business-signer"');expect(unit).toContain("ReadWritePaths=/var/lib/sanctuary-business-signer /run/sanctuary/business-signer");
  for(const pin of ["Type=notify","Restart=no","PrivateDevices=yes","MemorySwapMax=0","KillMode=control-group","RestrictAddressFamilies=AF_UNIX"])expect(unit).toContain(pin);
});

import {spawnSync} from "node:child_process";
import {releaseIsolationProbe} from "../fixtures/k1-service.js";
it("default native release contains no isolation entrypoint and refuses injection",async()=>{
  const path="/tmp/c99-target/release/sanctuary-business-signer";
  const artifact=readFileSync(path);
  for(const hook of ["--test-service","--test-bridge","k1-test-frames.bin"])expect(artifact.includes(Buffer.from(hook))).toBe(false);
  const result=spawnSync(path,["--test-service"],{env:{K1_FACTOR:"synthetic-unlock-attempt",NODE_OPTIONS:"--inspect"},encoding:"utf8",timeout:2000});
  expect(await releaseIsolationProbe(path)).toBe(false);
  expect(result.status).toBe(1);expect(result.stdout).toBe("");expect(result.stderr).toBe("K1_REFUSED\n");
});
