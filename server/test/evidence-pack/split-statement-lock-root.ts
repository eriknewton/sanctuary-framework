import {afterAll} from "vitest";
import {mkdtemp,readdir,lstat,unlink,rmdir} from "node:fs/promises";
import {join} from "node:path";
import * as locks from "../../src/storage/cross-process-lock.js";
const pending=new Set<string>();
// Source reversal uses the base resolver, which calls the same custodyLockRootFits with the same producer constants.
function fits(root:string):boolean {
 if(typeof locks.custodyLockRootFits==="function")return locks.custodyLockRootFits(root);
 try{return locks.resolveCustodyLockRoot(process.getuid?.()??0,{platform:process.platform,env:{SANCTUARY_CUSTODY_LOCK_ROOT:root}})===root;}catch{return false;}
}
/** Keep work beneath the checkout while reserving socket paths using the producer's own length computation. */
export function fixtureRootPlan(checkout:string){
 const suffix="XXXXXX"; // mkdtemp appends six random characters.
 const lockPrefix=["/tmp/evidence-pack-","/tmp/ep-"].find(prefix=>fits(prefix+suffix));
 if(!lockPrefix)throw new Error("synthetic socket root cannot fit");
 return {scratch:join(checkout,".scratch"),lockPrefix,reservedLockRoot:lockPrefix+suffix};
}
/** Track the rendezvous root before returning it, including fixtures that fail or time out before returning their cleanup. */
export async function createFixtureLockRoot(checkout:string){
 const root=await mkdtemp(fixtureRootPlan(checkout).lockPrefix);pending.add(root);
 if(!fits(root)){await disposeFixtureLockRoot(root);throw new Error("synthetic socket root cannot fit");}
 return root;
}
/** Inventory only this run's known socket leaves, then remove empty directories. */
export async function disposeFixtureLockRoot(root:string){
 const directories=[root],files:string[]=[];
 try{
  for(let i=0;i<directories.length;i++)for(const name of await readdir(directories[i])){const path=join(directories[i],name),stat=await lstat(path);if(stat.isDirectory()&&!stat.isSymbolicLink())directories.push(path);else files.push(path);}
  for(const path of files)await unlink(path);for(const path of directories.reverse())await rmdir(path);
  pending.delete(root);
 }catch(error){if((error as NodeJS.ErrnoException).code==="ENOENT")pending.delete(root);else throw error;}
}
afterAll(async()=>{for(const root of pending)await disposeFixtureLockRoot(root);});
/** Observe the daemon's actual signal registration without polling or substituting its production stop handler. */
export function daemonStopRegistration(){
 let stop:(()=>void)|undefined,ready!:(stop:()=>void)=>void;
 const registered=new Promise<()=>void>(resolve=>{ready=resolve;});
 const observe=(event:string|symbol,listener:(...args:any[])=>void)=>{if(event==="SIGTERM"&&String(listener).includes("Stopping Castle Wall daemon")){stop=listener;ready(listener);}};
 process.on("newListener",observe);
 return {registered,close:()=>{process.removeListener("newListener",observe);stop?.();}};
}
