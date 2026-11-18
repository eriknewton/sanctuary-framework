import {readdir,lstat,unlink,rmdir} from "node:fs/promises";
import {join} from "node:path";
/** Inventory a disposable fixture first, then unlink tracked leaves and remove known empty directories. */
export async function disposePhysicalFixture(root:string):Promise<void> {
  const directories=[root],files:string[]=[];
  for(let i=0;i<directories.length;i++)for(const name of await readdir(directories[i])){const path=join(directories[i],name);const stat=await lstat(path);if(stat.isDirectory()&&!stat.isSymbolicLink())directories.push(path);else files.push(path);}
  for(const file of files)await unlink(file);for(const directory of directories.reverse())await rmdir(directory);
}
