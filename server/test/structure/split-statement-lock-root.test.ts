import {expect,it} from "vitest";
import {resolve,join} from "node:path";
import * as locks from "../../src/storage/cross-process-lock.js";
import {fixtureRootPlan,createFixtureLockRoot,disposeFixtureLockRoot} from "../evidence-pack/split-statement-lock-root.js";
it.each([resolve(import.meta.dirname,"../../../"),"/home/runner/work/sanctuary-framework/sanctuary-framework"])("fits socket rendezvous independently of checkout %s",async checkout=>{
 const plan=fixtureRootPlan(checkout);
 expect(typeof locks.custodyLockRootFits,"producer fit computation exported").toBe("function");
 expect(locks.custodyLockRootFits(plan.reservedLockRoot),"planned socket root fits").toBe(true);
 expect(plan.scratch,"work stays in checkout scratch").toBe(join(checkout,".scratch"));
 const root=await createFixtureLockRoot(checkout);try{expect(locks.custodyLockRootFits(root),"allocated socket root fits").toBe(true);}finally{await disposeFixtureLockRoot(root);}
});
