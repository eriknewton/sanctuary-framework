// Test-only preload for verify-release subprocess witnesses, passed with
// `node --import`. It records every module URL the process resolves, denies
// and records every outbound socket attempt, and can present an older Node
// version to the code under test. It writes its record to
// VR_RECORDER_OUT when the process exits.
import dgram from "node:dgram";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { writeFileSync } from "node:fs";
import { registerHooks, syncBuiltinESMExports } from "node:module";

const record = { modules: [], network: [] };
registerHooks({
  resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context);
    record.modules.push(resolved.url);
    return resolved;
  },
});
for (const [target, key] of [[http, "request"], [http, "get"], [https, "request"], [https, "get"], [net, "connect"], [net, "createConnection"], [tls, "connect"], [dgram, "createSocket"]]) {
  target[key] = () => {
    record.network.push(key);
    throw new Error("network denied by the verify-release test recorder");
  };
}
globalThis.fetch = async () => {
  record.network.push("fetch");
  throw new Error("network denied by the verify-release test recorder");
};
syncBuiltinESMExports();
if (process.env.VR_PRESENT_NODE_VERSION) {
  Object.defineProperty(process.versions, "node", { value: process.env.VR_PRESENT_NODE_VERSION });
}
process.on("exit", () => writeFileSync(process.env.VR_RECORDER_OUT, JSON.stringify(record)));
