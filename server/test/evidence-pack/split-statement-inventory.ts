import {createHash} from "node:crypto";
import {constants} from "node:fs";
import {lstat,open,readdir} from "node:fs/promises";
import {join,relative} from "node:path";

// Inventory semantics must match the consumers in split-statement-fixtures.ts and split-statement-failbefore-3.test.ts.
export async function splitFixtureByteInventory(root:string) {
  const directories=[root],files:Record<string,string>={};
  for(const directory of directories)for(const name of await readdir(directory)) {
    const path=join(directory,name);
    const handle=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK).catch((error:NodeJS.ErrnoException)=>{
      if(error.code==="ELOOP"||error.code==="ENXIO"||error.code==="EOPNOTSUPP")return null;
      throw error;
    });
    if(!handle)continue;
    try {
      const meta=await handle.stat();
      if(meta.isDirectory())directories.push(path);
      else if(meta.isFile()) {
        const bytes=await handle.readFile(); // Inventory bytes come from the same no-follow descriptor as the metadata.
        const current=await lstat(path);
        // An inventoried path names the descriptor's file after its read, including device and inode identity.
        if(!current.isFile()||current.dev!==meta.dev||current.ino!==meta.ino)throw new Error("inventory path identity differs: "+path);
        files[relative(root,path)]=createHash("sha256").update(bytes).digest("hex");
      }
    } finally {await handle.close();}
  }
  return Object.fromEntries(Object.entries(files).sort(([a],[b])=>a<b?-1:1));
}
