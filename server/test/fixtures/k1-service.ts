import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, chmodSync, readdirSync, unlinkSync, rmdirSync } from "node:fs";
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
import { SigningServiceClient } from "../../src/signing/service.js";
import type { SigningGrant } from "../../src/signing/record-signer.js";
const binary = "/tmp/c99-target/debug/sanctuary-business-signer";
const launcher = "/tmp/c99-target/debug/sanctuary-business-unlock";
const digest = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
const pause = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
async function reap(child: ChildProcess): Promise<void> { if (child.exitCode !== null || child.signalCode !== null) return; await new Promise<void>(resolve => { child.once("exit", () => resolve()); child.kill("SIGTERM"); }); }
function cleanup(root: string, files: string[], directories: string[]): void {
  for (const name of [...files,join(root,"control/sign.sock"),join(root,"control/lifecycle.sock"),join(root,"control/k1-test-frames.bin")]) {try {unlinkSync(name);}catch{}}
  for (const name of directories.reverse()) {try {rmdirSync(name);}catch{}}
  rmdirSync(root);
}
export function deadline(): bigint { return BigInt(execFileSync("python3",["-c","import time; print(time.clock_gettime_ns(time.CLOCK_BOOTTIME))"],{encoding:"utf8"}).trim()) + 900_000_000n; }
export async function serviceFixture() {
  const root = mkdtempSync(join(tmpdir(),"k1-")); chmodSync(root,0o700);
  const files:string[]=[],directories:string[]=[];
  const control=join(root,"control"),custody=join(root,"custody");directories.push(control,custody);mkdirSync(control,{mode:0o700});mkdirSync(custody,{mode:0o700});
  const children: ChildProcess[]=[];const secrets: Uint8Array[]=[];const frames: Buffer[]=[];const logs: Buffer[]=[];
  let releaseSecrets: (()=>Promise<void>) | undefined;
  try {
  const storage=new MemoryStorage();const passphrase="fixture "+randomBytes(32).toString("base64url");
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
  const peer={uid,executable_sha256:digest(binary),cgroup};
  const config={controller:peer,launcher:{uid,executable_sha256:digest(launcher),cgroup},node_sha256:digest(process.execPath),worker_sha256:digest(resolve("dist/k1/signing-worker.cjs")),grant,fortress_id:fortress,roster_digest:roster,binding_high_water:0,runtime:(JSON.parse(execFileSync(process.execPath,["-e","process.stdout.write(JSON.stringify(process.report.getReport().sharedObjects.filter(p=>p!=='linux-vdso.so.1').map(p=>require('node:fs').realpathSync(p))))"],{env:{},encoding:"utf8"})) as string[]).map(path=>({path,sha256:digest(path)}))};
  const configPath=join(root,"config.json"),peerPath=join(root,"peer.json");files.push(configPath,peerPath);writeFileSync(configPath,canonicalBytes(config),{mode:0o600});writeFileSync(peerPath,canonicalBytes(peer),{mode:0o644});
  const service=spawn(binary,["--test-service",configPath,control,custody,process.execPath,resolve("dist/k1/signing-worker.cjs")],{env:{},stdio:["ignore","pipe","pipe"]});children.push(service);service.stdout.on("data",b=>logs.push(b));service.stderr.on("data",b=>logs.push(b));
  const clientChild=()=>{const child=spawn(binary,["--test-bridge",join(control,"sign.sock"),JSON.stringify(peer),JSON.stringify({...peer,executable_sha256:digest(process.execPath)})],{env:{},stdio:"pipe"});children.push(child);child.stdout.on("data",b=>frames.push(Buffer.from(b)));child.stderr.on("data",b=>logs.push(Buffer.from(b)));const write=child.stdin.write.bind(child.stdin);child.stdin.write=((chunk:Uint8Array,...args:unknown[])=>{frames.push(Buffer.from(chunk));return (write as Function)(chunk,...args);}) as typeof child.stdin.write;return child;};
  for(let i=0;i<500;i++){try{readFileSync(configPath);if(readdirSync(control).includes("sign.sock"))break;}catch{} await pause(20);}
  const child=clientChild(); const client=new SigningServiceClient(child);
  try {await client.status();}catch(e){await client.close();await reap(service);throw new Error("fixture service not ready: "+Buffer.concat(logs).toString(),{cause:e});}
  const trace = {promptSeen:false,workerBytes:0,echoed:false};
  const ceremony=async(lock: boolean | "extra" | "non-tty" | "foreign" = false, factor=passphrase)=>{
    const args=["--test-ceremony",join(control,"lifecycle.sock"),peerPath,typeof lock==="string"?lock:lock?"lock":"unlock"];
    const command=[launcher,...args].map(value=>"'"+value.replaceAll("'","'\\''")+"'").join(" ");
    const child=lock===true?spawn(launcher,args,{env:{},stdio:"pipe"}):spawn("script",["-q","-e","-c",command,"/dev/null"],{env:{},stdio:"pipe"});children.push(child);
    const outcome=await new Promise<number|null>((resolve,reject)=>{let sent=false;let echoTail="";
      const heartbeat=setInterval(()=>{void client.status().catch(()=>undefined);},400);
      const timeout=setTimeout(()=>{clearInterval(heartbeat);child.kill("SIGKILL");reject(new Error("ceremony timeout"));},35_000);
      child.stdout.on("data",(chunk:Buffer)=>{echoTail=(echoTail+chunk.toString()).slice(-factor.length*2);trace.echoed ||= echoTail.includes(factor);if(!sent&&chunk.toString().includes("K1 passphrase:")){sent=true;trace.promptSeen=true;child.stdin.write(factor+"\n");}});
      child.stderr.on("data",b=>logs.push(Buffer.from(b)));child.once("error",reject);child.once("exit",code=>{clearTimeout(timeout);clearInterval(heartbeat);try{trace.workerBytes=readFileSync(join(control,"k1-test-frames.bin")).length;}catch{}resolve(code);});});
    if(lock===true&&outcome===0){
      let closed=false;
      for(let i=0;i<100;i++){const state=(await client.status()).state;if(state==="LOCKED"||state==="WIPE_UNCONFIRMED"){closed=true;break;}await pause(10);}
      if(!closed)throw new Error("worker did not settle after lock");
    }
    return outcome;
  };
  return {trace,client,service,grant,ceremonyRecovery:()=>ceremony(false,"recovery:"+master.mintedRecoveryKey!),async foreignWrite(){
    const before=frames.length;
    const writer=spawn("python3",["-c", "import os; os.write(0, bytes.fromhex('0000000f7b226f70223a22535441545553227d'))"],{env:{},stdio:[child.stdin,"ignore","ignore"]});children.push(writer);
    await new Promise<void>(resolve=>writer.once("exit",()=>resolve()));await pause(100);
    return {responded:frames.length>before,bridgeExit:child.exitCode};
  },secrets,frames,logs,ceremony,privateFrames(){return readFileSync(join(control,"k1-test-frames.bin"));},async body(){const status=await client.status();const g=status.grant;return {g,bytes:canonicalBytes({signature_scheme:ROLE_SIGNATURE_SCHEME,...{role:g.role,epoch:g.epoch,kid:g.kid,identity_id:g.identity_id,machine_id:g.machine_id},record_kind:"counter",activation_id:g.activation_id,lease_id:g.lease_id,generation:g.generation,boot_id:"f".repeat(32),sequence:1,prior_commitment:"GENESIS",captured_at_unix_ms:1,captured_at_boottime_ns:"1",policy_digest:roster,runtime_digest:roster,config_digest:roster,payload:{count:1}})};},async close(){await client.close();for(const c of children.reverse())await reap(c);for(const s of secrets)s.fill(0);cleanup(root,files,directories);}};
  } catch(error) {await releaseSecrets?.();for(const child of children.reverse())await reap(child);for(const secret of secrets)secret.fill(0);cleanup(root,files,directories);throw error;}
}

/** Public-only executable probe: accepting fixture paths must be impossible in the default release. */
export async function releaseIsolationProbe(executable: string): Promise<boolean> {
  const root=mkdtempSync(join(tmpdir(),"k1-release-"));chmodSync(root,0o700);
  const control=join(root,"control"),custody=join(root,"custody"),configPath=join(root,"config.json");
  mkdirSync(control,{mode:0o700});mkdirSync(custody,{mode:0o700});
  const peer={uid:process.getuid!(),executable_sha256:digest(executable),cgroup:readFileSync("/proc/self/cgroup","utf8").trim()};
  const runtime=(JSON.parse(execFileSync(process.execPath,["-e","process.stdout.write(JSON.stringify(process.report.getReport().sharedObjects.filter(p=>p!=='linux-vdso.so.1').map(p=>require('node:fs').realpathSync(p))))"],{env:{},encoding:"utf8"})) as string[]).map(path=>({path,sha256:digest(path)}));
  const worker=resolve("dist/k1/signing-worker.cjs");
  writeFileSync(configPath,canonicalBytes({controller:peer,launcher:peer,node_sha256:digest(process.execPath),worker_sha256:digest(worker),grant:{},fortress_id:"a".repeat(32),roster_digest:"sha256:"+"b".repeat(64),binding_high_water:0,runtime}),{mode:0o600});
  const child=spawn(executable,["--test-service",configPath,control,custody,process.execPath,worker],{env:{K1_FACTOR:"synthetic-unlock-attempt"},stdio:"ignore"});
  try {
    for(let i=0;i<200;i++){
      if(readdirSync(control).includes("sign.sock"))return true;
      if(child.exitCode!==null)return false;
      await pause(10);
    }
    throw new Error("release probe did not settle or expose a socket");
  }finally{await reap(child);cleanup(root,[configPath],[control,custody]);}
}
