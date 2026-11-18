// fail-before-exempt: This row witnesses the test-side fixture helpers split-statement-inventory.ts and split-statement-dispose.ts under server/test, which this gate does not revert, so it passes on reverted server/src by construction; the helper mutation runs that turn it red are recorded with the review.
import {expect,it,vi} from "vitest";
import * as fs from "node:fs/promises";
import {join,resolve} from "node:path";
import {splitFixtureByteInventory} from "./split-statement-inventory.js";
import {disposePhysicalFixture} from "./split-statement-dispose.js";

vi.mock("node:fs/promises",async importOriginal=>{
  const actual=await importOriginal<typeof import("node:fs/promises")>();
  return {...actual,open:vi.fn(actual.open)};
});

it("requires inventory paths to retain descriptor identity",async()=>{
  const scratch=resolve(import.meta.dirname,"../../../.scratch");
  await fs.mkdir(scratch,{recursive:true});
  const root=await fs.mkdtemp(join(scratch,"inventory-")),path=join(root,"member");
  const originalOpen=(await vi.importActual<typeof fs>("node:fs/promises")).open;
  let scheduled=false;
  const openSpy=vi.mocked(fs.open).mockImplementation(async(...args)=>{
    const handle=await originalOpen(...args);
    if(String(args[0])===path) {
      const read=handle.readFile.bind(handle);
      vi.spyOn(handle,"readFile").mockImplementationOnce(async()=>{
        await fs.rename(path,path+".original");
        await fs.writeFile(path,"replacement");
        scheduled=true;
        return read();
      });
    }
    return handle;
  });
  try {
    await fs.writeFile(path,"original");
    await expect(splitFixtureByteInventory(root)).rejects.toThrow("inventory path identity differs");
  } finally {
    openSpy.mockImplementation(originalOpen);
    try {await disposePhysicalFixture(root);} finally {expect(scheduled).toBe(true);}
  }
});
