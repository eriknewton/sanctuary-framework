import { copyFileSync, accessSync, constants, mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync, readdirSync, unlinkSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { MemoryStorage } from "../../src/storage/memory.js";
import { establishMaster, verifyRecoveryWrapByReentry } from "../../src/core/master-custody.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { encrypt, decrypt } from "../../src/core/encryption.js";
import { encryptBinding } from "../../src/signing/binding-store.js";
import { prepareRoleIdentity } from "../../src/signing/provision.js";
import { canonicalBytes, ROLE_REGISTRY, ROLE_SIGNATURE_SCHEME } from "../../src/signing/contract.js";
import { RelayClient } from "./k1-relay-client.js";
import type { SigningGrant } from "../../src/signing/record-signer.js";
// Must match the Linux workflow build steps: one target root contains debug and release artifacts.
export function nativeBinary(profile: "debug" | "release", name: "signer" | "unlock"): string {
  const root = process.env.SANCTUARY_K1_TEST_BINARIES;
  if (!root) throw new Error("K1_NATIVE_BINARIES_REQUIRED: set SANCTUARY_K1_TEST_BINARIES to the harness target directory");
  const path = join(root, profile, `sanctuary-business-${name}`);
  try { accessSync(path, constants.X_OK); } catch { throw new Error(`K1_NATIVE_BINARY_UNBUILT: ${profile}/${name}`); }
  return path;
}
// Must match the root-owned interpreter provisioning steps in all three Linux full-suite workflows.
const fixtureNode = "/usr/bin/node";
const digest = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
const pause = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
async function reap(child: ChildProcess): Promise<void> { if (child.exitCode !== null || child.signalCode !== null) return; await new Promise<void>(resolve => { child.once("exit", () => resolve()); child.kill("SIGTERM"); }); }
// Must match custody.rs UNCLEAN_MARKER so fixture teardown removes the nonsecret recovery marker.
function cleanup(root: string, files: string[], directories: string[]): void {
  for (const name of [...files,join(root,"control/sign.sock"),join(root,"control/lifecycle.sock"),join(root,"control/k1-test-frames.bin"),join(root,"custody/worker-unclean")]) {try {unlinkSync(name);}catch{}}
  for (const name of directories.reverse()) {try {rmdirSync(name);}catch{}}
  rmdirSync(root);
}
export function deadline(): bigint { return BigInt(execFileSync("python3",["-c","import time; print(time.clock_gettime_ns(time.CLOCK_BOOTTIME))"],{encoding:"utf8"}).trim()) + 900_000_000n; }
export async function serviceFixture(passphrasePrefix = "fixture ", rootUnit = false, workerSource?: string) {
  const binary = nativeBinary("debug", "signer"), launcher = nativeBinary("debug", "unlock");
  const root = mkdtempSync(join(tmpdir(),"k1-")); chmodSync(root,0o700);
  const files:string[]=[],directories:string[]=[];
  const control=join(root,"control"),custody=join(root,"custody");directories.push(control,custody);mkdirSync(control,{mode:0o700});mkdirSync(custody,{mode:0o700});
  let unitName: string | undefined;
  const children: ChildProcess[]=[];const secrets: Uint8Array[]=[];const frames: Buffer[]=[];const logs: Buffer[]=[];
  let releaseSecrets: (()=>Promise<void>) | undefined;
  try {
  const storage=new MemoryStorage();const passphrase=passphrasePrefix+randomBytes(32).toString("base64url");
  const master=await establishMaster({storage,passphrase,firstRun:{installMode:"interactive",mintRecoveryKey:true}});
  await verifyRecoveryWrapByReentry(storage,master.envelope!,master.mintedRecoveryKey!);
  const key=derivePurposeKey(master.masterKey,"identity-encryption");
  releaseSecrets=async()=>{master.masterKey.fill(0);key.fill(0);await master.masterWriteBarrier?.release();};
  const prepared=prepareRoleIdentity(ROLE_REGISTRY[0].role,1,"a".repeat(32),key,[],[]);
  secrets.push(new Uint8Array(master.masterKey),new Uint8Array(key),decrypt(prepared.storedIdentity.encrypted_private_key,key),Buffer.from(passphrase),Buffer.from(master.mintedRecoveryKey!));
  const grant:SigningGrant={...prepared.pin,activation_id:"b".repeat(32),lease_id:"c".repeat(32),generation:0};
  const roster="sha256:"+"d".repeat(64),fortress="e".repeat(32);
  const binding=encryptBinding({identity_id:grant.identity_id,role:grant.role,machine_id:grant.machine_id,epoch:1,kid:grant.kid,roster_digest:roster,high_water:0,transaction_state:"LOCKED"},master.masterKey,{fortress_id:fortress,machine_id:grant.machine_id,role:grant.role});
  await storage.write("_producer_custody","binding",canonicalBytes(binding));
  await storage.write("_identities",grant.identity_id,canonicalBytes(encrypt(canonicalBytes(prepared.storedIdentity),key)));
  for(const namespace of await storage.listNamespaces()) {const dir=join(custody,namespace);directories.push(dir);mkdirSync(dir,{mode:0o700});for(const entry of await storage.list(namespace)){files.push(join(dir,entry.key+".enc"));writeFileSync(join(dir,entry.key+".enc"),(await storage.read(namespace,entry.key))!,{mode:0o600});}}
  master.masterKey.fill(0);key.fill(0);await master.masterWriteBarrier?.release();
  const uid=process.getuid!(),cgroup=readFileSync("/proc/self/cgroup","utf8").trim();
  const peer={uid,gid:process.getegid!(),executable_sha256:digest(binary),cgroup};
  const workerPath=(rootUnit || workerSource !== undefined)?join(root,"signing-worker.cjs"):resolve("dist/k1/signing-worker.cjs");
  if(rootUnit){if(uid!==0)throw new Error("K1_ROOT_UNIT_REQUIRES_ROOT");copyFileSync(resolve("dist/k1/signing-worker.cjs"),workerPath);chmodSync(workerPath,0o600);files.push(workerPath);unitName=`sanctuary-k1-drill-${process.pid}-${randomBytes(4).toString("hex")}.service`;}
  const servicePeer=rootUnit?{...peer,gid:Number(execFileSync("getent",["group","sanctuary"],{encoding:"utf8"}).trim().split(":")[2]),cgroup:`0::/system.slice/${unitName}`} : peer;
  if(workerSource !== undefined){writeFileSync(workerPath,workerSource,{mode:0o600});files.push(workerPath);}
  const config={controller:peer,launcher:{uid,gid:process.getegid!(),executable_sha256:digest(launcher),cgroup},node_sha256:digest(fixtureNode),worker_sha256:digest(workerPath),grant,fortress_id:fortress,roster_digest:roster,binding_high_water:0,runtime:(JSON.parse(execFileSync(fixtureNode,["-e","process.stdout.write(JSON.stringify(process.report.getReport().sharedObjects.filter(p=>p!=='linux-vdso.so.1').map(p=>require('node:fs').realpathSync(p))))"],{env:{VITEST:"true"},encoding:"utf8"})) as string[]).map(path=>({path,sha256:digest(path)}))};
  const configPath=join(root,"config.json"),peerPath=join(root,"peer.json");files.push(configPath,peerPath);writeFileSync(configPath,canonicalBytes(config),{mode:0o600});writeFileSync(peerPath,canonicalBytes(servicePeer),{mode:0o644});
  const serviceArgs=["--test-service",configPath,control,custody,fixtureNode,workerPath];
  if(rootUnit){
    const unitPath=join(root,unitName!);files.push(unitPath,join(control,"write-control"));
    const probe=join(root,"probe.py");files.push(probe);
    writeFileSync(probe,`import socket,ctypes,errno\nopen(${JSON.stringify(join(control,"write-control"))},"w").close()\ntry:\n open(${JSON.stringify(join(root,"forbidden"))},"w").close()\n raise AssertionError("outside write admitted")\nexcept OSError as e:\n assert e.errno in (errno.EROFS,errno.EACCES,errno.EPERM)\ntry:\n socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n raise AssertionError("network admitted")\nexcept OSError as e:\n assert e.errno in (errno.EAFNOSUPPORT,errno.EPERM)\nlibc=ctypes.CDLL(None,use_errno=True)\nassert libc.swapon(b"/dev/null",0)==-1 and ctypes.get_errno()==errno.EPERM\n`,{mode:0o600});
    // The complete shipped unit supplies confinement; only isolated paths, executable and barrier are overridden for this inert drill.
    const shipped=readFileSync("../castle-wall-daemon/systemd/sanctuary-business-signer.service","utf8");
    const quoted=[binary,...serviceArgs].map(value=>JSON.stringify(value)).join(" ");
    writeFileSync(unitPath,shipped+`\n[Unit]\nRequires=\nAfter=\n[Service]\nExecStart=\nExecStart=${quoted}\nExecStartPre=/usr/bin/python3 ${probe}\nReadWritePaths=\nReadWritePaths=${control} ${custody}\nRuntimeDirectory=\n`,{mode:0o644});
    execFileSync("systemctl",["link","--runtime",unitPath]);execFileSync("systemctl",["daemon-reload"]);
  }
  const startService=()=>rootUnit?spawn("systemctl",["start",unitName!],{env:{VITEST:"true"},stdio:["ignore","pipe","pipe"]}):spawn(binary,serviceArgs,{env:{VITEST:"true"},stdio:["ignore","pipe","pipe"]});let service=startService();children.push(service);service.stdout.on("data",b=>logs.push(b));service.stderr.on("data",b=>logs.push(b));
  // Must match require_unix_socket in signer_peer.rs and k1-relay-client.ts: the relay stdin must be an AF_UNIX socket.
  const clientChild=()=>{const child=spawn(binary,["--test-relay",join(control,"sign.sock"),JSON.stringify(servicePeer)],{env:{VITEST:"true"},stdio:"pipe"});children.push(child);child.stdout.on("data",b=>frames.push(Buffer.from(b)));child.stderr.on("data",b=>logs.push(Buffer.from(b)));const write=child.stdin.write.bind(child.stdin);child.stdin.write=((chunk:Uint8Array,...args:unknown[])=>{frames.push(Buffer.from(chunk));return (write as Function)(chunk,...args);}) as typeof child.stdin.write;return child;};
  for(let i=0;i<500;i++){try{readFileSync(configPath);if(readdirSync(control).includes("sign.sock"))break;}catch{} await pause(20);}
  const child=clientChild(); let client=new RelayClient(child);
  try {await client.status();}catch(e){await client.close();await reap(service);throw new Error("fixture service not ready: "+Buffer.concat(logs).toString(),{cause:e});}
  const trace = {promptSeen:false,workerBytes:0,echoed:false,terminalRestored:false};
  const ceremony=async(lock: boolean | "extra" | "non-tty" | "foreign" = false, factor=passphrase, recovery=false, held=false, settle=true)=>{
    const args=["--test-ceremony",join(control,"lifecycle.sock"),peerPath,typeof lock==="string"?lock:lock?"lock":"unlock"];
    const launcherCommand=[launcher,...args].map(value=>"'"+value.replaceAll("'","'\\''")+"'").join(" ");
    // Compare terminal state after the launcher returns so reap must finish before restoration is judged.
    const command = `before=$(stty -g); ${launcherCommand}; result=$?; after=$(stty -g); if [ "$before" = "$after" ]; then echo K1_TERMINAL_RESTORED; fi; exit "$result"`;
    const child=lock===true?spawn(launcher,args,{env:{VITEST:"true"},stdio:"pipe"}):spawn("script",["-q","-e","-c",command,"/dev/null"],{env:{VITEST:"true"},stdio:"pipe"});children.push(child);
    const outcome=await new Promise<number|null>((resolve,reject)=>{let sent=false;let modeSent=false;let echoTail="";
      let heartbeatRequest:Promise<unknown>=Promise.resolve();
      const heartbeat=setInterval(()=>{heartbeatRequest=client.status().catch(()=>undefined);},400);
      const timeout=setTimeout(()=>{clearInterval(heartbeat);child.kill("SIGKILL");reject(new Error("ceremony timeout"));},35_000);
      child.stdout.on("data",(chunk:Buffer)=>{echoTail=(echoTail+chunk.toString()).slice(-factor.length*2);trace.echoed ||= echoTail.includes(factor);trace.terminalRestored ||= echoTail.includes("K1_TERMINAL_RESTORED");if(!modeSent&&chunk.toString().includes("K1 factor mode")){modeSent=true;child.stdin.write(recovery?"r\n":"p\n");}if(!sent&&(chunk.toString().includes("K1 passphrase:")||chunk.toString().includes("K1 recovery key:"))){sent=true;trace.promptSeen=true;if(!held)child.stdin.write(factor+"\n");}});
      child.stderr.on("data",b=>logs.push(Buffer.from(b)));child.once("error",reject);child.once("exit",code=>{clearTimeout(timeout);clearInterval(heartbeat);try{trace.workerBytes=readFileSync(join(control,"k1-test-frames.bin")).length;}catch{}void heartbeatRequest.then(()=>resolve(code));});});
    if(lock===true&&outcome===0&&settle){
      let closed=false;
      for(let i=0;i<100;i++){const state=(await client.status()).state;if(state==="LOCKED"||state==="WIPE_UNCONFIRMED"){closed=true;break;}await pause(10);}
      if(!closed)throw new Error("worker did not settle after lock");
    }
    return outcome;
  };
  // Must match attendance.test.ts: the marker survives every noncooperative settlement.
  return {trace,markerPresent:()=>existsSync(join(custody,"worker-unclean")),workerPid(){return Number(readFileSync(`/proc/${service.pid}/task/${service.pid}/children`,"utf8").trim());},get client(){return client;},get service(){return service;},grant,
    async probeClient() {
      await client.close();
      return JSON.parse(execFileSync(binary,["--test-client",join(control,"sign.sock"),JSON.stringify(servicePeer)],{env:{VITEST:"true"},encoding:"utf8",timeout:5_000})) as unknown;
    },
    async killController() {const relay=children.find(c => c.pid === child.pid)!; relay.kill("SIGKILL");await reap(relay);},
    async freshClient() {client=new RelayClient(clientChild());return client.status();},
    async probeBootId(text: string, bootIdPath?: string) {
      await client.close(); await reap(service);
      for (const socket of ["sign.sock", "lifecycle.sock"]) {const path=join(control,socket);if(existsSync(path))unlinkSync(path);}
      const boot=join(root,"boot-id"),notify=join(root,"notify.sock"); files.push(boot,notify);
      writeFileSync(boot,text,{mode:0o600});
      // A real datagram observer distinguishes startup refusal from merely refusing later client traffic.
      const script = `import ctypes,json,os,socket,subprocess,sys,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
s.bind(sys.argv[1])
s.settimeout(0.05)
# Linux prctl option 1 is PR_SET_PDEATHSIG; signal 9 is SIGKILL, so observer timeout death also kills S.
p=subprocess.Popen(sys.argv[2:],preexec_fn=lambda: ctypes.CDLL(None).prctl(1, 9),env={"NOTIFY_SOCKET":sys.argv[1],"VITEST":"true"},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
ready=0
started=time.monotonic()
end=started+2
try:
 while time.monotonic()<end:
  try:
   data=s.recv(1024)
   ready+=int(b"READY=1" in data)
  except socket.timeout: pass
  if ready or p.poll() is not None: break
finally:
 if p.poll() is None: p.terminate()
 try: out,err=p.communicate(timeout=2)
 except subprocess.TimeoutExpired:
  p.kill();out,err=p.communicate()
 s.close()
print(json.dumps({"ready":ready,"code":p.returncode,"stderr":err.decode(),"elapsedMs":(time.monotonic()-started)*1000}))`;
      return JSON.parse(execFileSync("python3",["-c",script,notify,binary,...serviceArgs,"--test-boot-id",bootIdPath ?? boot],{encoding:"utf8",timeout:10_000})) as {ready:number;code:number;stderr:string;elapsedMs:number};
    },
    lockImmediate:()=>ceremony(true,passphrase,false,false,false),
    ceremonyHeld:()=>ceremony(false,passphrase,false,true),
    ceremonyEdited:()=>ceremony(false,passphrase+"x\x7f"),
    async restart(){await client.close();await reap(service);for(const socket of ["sign.sock","lifecycle.sock"])unlinkSync(join(control,socket));service=startService();children.push(service);service.stdout!.on("data",b=>logs.push(b));service.stderr!.on("data",b=>logs.push(b));for(let i=0;i<500&&!readdirSync(control).includes("sign.sock");i++)await pause(20);client=new RelayClient(clientChild());await client.status();},
ceremonyRecovery:()=>ceremony(false,master.mintedRecoveryKey!,true),secrets,frames,logs,ceremony,privateFrames(){return readFileSync(join(control,"k1-test-frames.bin"));},async body(){const status=await client.status();const g=status.grant;return {g,bytes:canonicalBytes({signature_scheme:ROLE_SIGNATURE_SCHEME,...{role:g.role,epoch:g.epoch,kid:g.kid,identity_id:g.identity_id,machine_id:g.machine_id},record_kind:"counter",activation_id:g.activation_id,lease_id:g.lease_id,generation:g.generation,boot_id:"f".repeat(32),sequence:1,prior_commitment:"GENESIS",captured_at_unix_ms:1,captured_at_boottime_ns:"1",policy_digest:roster,runtime_digest:roster,config_digest:roster,payload:{count:1}})};},async close(){await client.close();if(unitName){execFileSync("systemctl",["stop",unitName]);unlinkSync(join("/run/systemd/system",unitName));execFileSync("systemctl",["daemon-reload"]);unitName=undefined;}for(const c of children.reverse())await reap(c);for(const s of secrets)s.fill(0);cleanup(root,files,directories);}};
  } catch(error) {if(unitName){try{execFileSync("systemctl",["stop",unitName]);}catch{}try{unlinkSync(join("/run/systemd/system",unitName));execFileSync("systemctl",["daemon-reload"]);}catch{}}await releaseSecrets?.();for(const child of children.reverse())await reap(child);for(const secret of secrets)secret.fill(0);cleanup(root,files,directories);throw error;}
}

/** Public-only executable probe: accepting fixture paths must be impossible in the default release. */
export async function releaseIsolationProbe(executable: string): Promise<boolean> {
  const root=mkdtempSync(join(tmpdir(),"k1-release-"));chmodSync(root,0o700);
  const control=join(root,"control"),custody=join(root,"custody"),configPath=join(root,"config.json");
  mkdirSync(control,{mode:0o700});mkdirSync(custody,{mode:0o700});
  const peer={uid:process.getuid!(),gid:process.getegid!(),executable_sha256:digest(executable),cgroup:readFileSync("/proc/self/cgroup","utf8").trim()};
  const runtime=(JSON.parse(execFileSync(fixtureNode,["-e","process.stdout.write(JSON.stringify(process.report.getReport().sharedObjects.filter(p=>p!=='linux-vdso.so.1').map(p=>require('node:fs').realpathSync(p))))"],{env:{VITEST:"true"},encoding:"utf8"})) as string[]).map(path=>({path,sha256:digest(path)}));
  const worker=resolve("dist/k1/signing-worker.cjs");
  writeFileSync(configPath,canonicalBytes({controller:peer,launcher:peer,node_sha256:digest(fixtureNode),worker_sha256:digest(worker),grant:{},fortress_id:"a".repeat(32),roster_digest:"sha256:"+"b".repeat(64),binding_high_water:0,runtime}),{mode:0o600});
  const child=spawn(executable,["--test-service",configPath,control,custody,fixtureNode,worker],{env:{VITEST:"true",K1_FACTOR:"synthetic-unlock-attempt"},stdio:"ignore"});
  try {
    for(let i=0;i<200;i++){
      if(readdirSync(control).includes("sign.sock"))return true;
      if(child.exitCode!==null)return false;
      await pause(10);
    }
    throw new Error("release probe did not settle or expose a socket");
  }finally{await reap(child);cleanup(root,[configPath],[control,custody]);}
}

import businessSchema from "../../src/signing/linux-business-records.schema.json";
type SchemaNode = {type: string; value?: unknown; values?: string[]; min?: number; name?: string; encoding?: string; fields?: Record<string, SchemaNode>; branches?: SchemaNode[]};
/** Synthetic public records exercise each strict branch without invoking a provider or operator store. */
export function businessBodies(): Record<string, unknown>[] {
  const definitions = businessSchema.definitions as unknown as Record<string, SchemaNode>;
  const sample = (node: SchemaNode): unknown => {
    switch (node.type) {
      case "ref": return sample(definitions[node.name!]);
      case "literal": return node.value;
      case "enum": return node.values![0];
      case "integer": return node.min!;
      case "union": return sample(node.branches![0]);
      case "object": return Object.fromEntries(Object.entries(node.fields!).map(([key, value]) => [key, sample(value)]));
      case "string": return ({id: "a".repeat(32), digest: "sha256:" + "b".repeat(64), kid: "k1:sha256:" + "b".repeat(64), u64: "1", ipv4: "192.0.2.1", ipv6: "2001:db8::1"})[node.encoding!];
      default: throw new Error("UNKNOWN_SCHEMA_NODE");
    }
  };
  // Must match records_schema.rs and linux_business_schema.rs: every root branch supplies one positive fixture.
  return businessSchema.record.branches.map(branch => sample(branch as unknown as SchemaNode) as Record<string, unknown>);
}
