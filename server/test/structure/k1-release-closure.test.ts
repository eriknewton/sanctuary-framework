// fail-before-exempt: Marker propagation and platform independent source pins preserve existing absence properties; native entrypoint refusal is also checked with the marker present.
import {it as test,expect} from "vitest";
const it = process.platform === "linux" ? test : test.skip;
import {readFileSync, mkdtempSync, rmdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {execFileSync} from "node:child_process";
test("worker closure excludes secret observers and credential injection",()=>{
  const worker=readFileSync("dist/k1/signing-worker.cjs","utf8");
  expect(worker.includes("__testObserveSecretBuffer")).toBe(false);expect(worker).not.toContain("--test-service");
  const imports=[...new Set([...worker.matchAll(/require\(["']([^"']+)["']\)/g)].map(match=>match[1]))].sort();
  expect(imports).toEqual(["node:async_hooks","node:crypto","node:fs","node:tty"]);
  const source=readFileSync("src/signing/worker.ts","utf8");expect(source).not.toContain("process.env");expect(source).not.toContain("process.argv");
});
it("Linux only: pinned runtime disables SIGUSR1 inspector",()=>{expect(()=>execFileSync(process.execPath,["--disable-sigusr1","--no-addons","-e","process.kill(process.pid, 'SIGUSR1'); setTimeout(() => process.exit(require('node:inspector').url() ? 1 : 0), 25)"],{env:{VITEST:"true"},timeout:2000})).not.toThrow();});
test("frame constants and service installation paths agree on both sides",()=>{
  const rust=readFileSync("../castle-wall-daemon/src/business_profile/signer_service.rs","utf8"),custody=readFileSync("../castle-wall-daemon/src/business_profile/custody.rs","utf8"),unit=readFileSync("../castle-wall-daemon/systemd/sanctuary-business-signer.service","utf8");
  expect(rust).toContain(`pub const LENGTH_BYTES: usize = ${LENGTH_BYTES};`);
  expect(RESPONSE_MAX_BYTES).toBe(SIGNER_HEADER_MAX_BYTES);
  expect(rust).toContain("pub const RESPONSE_MAX_BYTES: usize = SIGNER_HEADER_MAX_BYTES;");
  const worker=readFileSync("src/signing/worker.ts","utf8");
  const tty=worker.match(/const TTY_FD = (\d+);/)?.[1]; expect(tty).toBe("3");
  expect(custody).toContain(`pub const TTY_FD: i32 = ${tty};`);expect(custody).toContain('"/usr/libexec/sanctuary-business-signer"');expect(unit).toContain("ExecStart=/usr/libexec/sanctuary-business-signer");
  expect(custody).toContain('"/var/lib/sanctuary-business-signer"');expect(unit).toContain("ReadWritePaths=/var/lib/sanctuary-business-signer /run/sanctuary-business-signer");
  for(const pin of ["Type=notify","Restart=no","PrivateDevices=yes","MemorySwapMax=0","KillMode=control-group","RestrictAddressFamilies=AF_UNIX"])expect(unit).toContain(pin);
});

import {RESPONSE_MAX_BYTES,LENGTH_BYTES} from "../../src/signing/service.js";
import {SIGNER_HEADER_MAX_BYTES} from "../../src/signing/contract.js";
import {spawnSync} from "node:child_process";
import {releaseIsolationProbe,nativeBinary} from "../fixtures/k1-service.js";
test.skipIf(process.platform !== "linux")("Linux only: default native release contains no isolation entrypoint and refuses injection",async()=>{
  const path=nativeBinary("release", "signer");
  const unlock=nativeBinary("release","unlock");
  expect(readFileSync(unlock).includes(Buffer.from("--test-ceremony"))).toBe(false);
  const refused=spawnSync(unlock,["--test-ceremony"],{env:{VITEST:"true"},encoding:"utf8",timeout:2000});
  expect(refused.status).toBe(1);expect(refused.stderr).toBe("K1_REFUSED\n");
  const artifact=readFileSync(path);
  for(const hook of ["--test-service","--test-bridge","--test-relay","--test-client","--test-boot-id","k1-test-frames.bin"])expect(artifact.includes(Buffer.from(hook))).toBe(false);
  const result=spawnSync(path,["--test-service"],{env:{VITEST:"true",K1_FACTOR:"synthetic-unlock-attempt",NODE_OPTIONS:"--inspect"},encoding:"utf8",timeout:2000});
  expect(await releaseIsolationProbe(path)).toBe(false);
  expect(result.status).toBe(1);expect(result.stdout).toBe("");expect(result.stderr).toBe("K1_REFUSED\n");
});

test("release argument refusal precedes every production path read", () => {
  const source = readFileSync("../castle-wall-daemon/src/bin/sanctuary-business-signer.rs", "utf8");
  const production = source.slice(source.indexOf("if !args.is_empty()"));
  expect(production.indexOf("return Err(refused())")).toBeLessThan(production.indexOf("read_pinned("));
});
it("Linux only: release refuses retired transport and complete relay arguments", () => {
  const root = mkdtempSync(join(tmpdir(), "k1-release-argv-"));
  const socket = join(root, "sign.sock");
  try {
  for (const args of [["--bridge"], ["--test-relay", socket, "{}"], ["--test-client", socket, "{}"],
    ["--test-service", join(root,"config"), join(root,"control"), join(root,"custody"), join(root,"node"), join(root,"worker"), "--test-boot-id", join(root,"boot-id")]]) {
    const result = spawnSync(nativeBinary("release", "signer"), args, {env:{VITEST:"true"}, encoding:"utf8", timeout:2000});
    expect(result.status).toBe(1); expect(result.stdout).toBe(""); expect(result.stderr).toBe("K1_REFUSED\n");
  }
  } finally { rmdirSync(root); }
});
