import {mkdtempSync, rmdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";
import {pathToFileURL} from "node:url";
import {registerHooks} from "node:module";

// The compiled CLI keeps its real dispatcher; only its caller dependencies get fixture roots.
const root = mkdtempSync(join(tmpdir(), "k1-cli-selector-"));
const roots = JSON.stringify({anchor: root, expectedOwner: process.geteuid()});
const entry = pathToFileURL(resolve(process.argv[1])).href;
process.once("exit", () => { try { rmdirSync(root); } catch { /* Teardown must not throw from exit. */ } });
registerHooks({
  load(url, context, nextLoad) {
    const loaded = nextLoad(url, context);
    if (url !== entry) return loaded;
    let wrapCalls = 0, daemonCalls = 0;
    const source = String(loaded.source)
      .replace(/await (runWrap\d*)\(opts, \{/g, (_match, call) => {
        wrapCalls++;
        return `await ${call}(opts, {selectorRoots: ${roots},`;
      })
      .replace(/return (runDaemon\d*)\(args\.slice\(1\)\)/g, (_match, call) => {
        daemonCalls++;
        return `return ${call}(args.slice(1), {selectorRoots: ${roots}})`;
      });
    // Refuse drift instead of letting an uninstrumented dispatcher consult host selection roots.
    if (wrapCalls !== 1 || daemonCalls !== 1) throw new Error("CLI selector fixture call sites changed");
    return {...loaded, source};
  },
});
