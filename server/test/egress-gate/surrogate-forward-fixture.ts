/** Host-free surrogate forward fixtures using real local sockets and a signed oracle. */
import { randomBytes, createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import net, { type Socket } from "node:net";
import https from "node:https";
import { vi } from "vitest";
import {
  mintSurrogatePlaceholder, renderSurrogateBindingsFile, renderSurrogateDestinationsFile,
  encodeSurrogateUnlockSocketRequest, parseSurrogateUnlockSocketResponse, newSurrogateCorrelationId,
  type MintedSurrogateBinding,
} from "../../src/credential-surrogate/index.js";
import { runSurrogateHelperDaemon, surrogateBindingsPath, surrogateDestinationsPath, type SurrogateHelperEvent } from "../../src/egress-gate/surrogate-helper-daemon.js";
import { runEgressGateDaemon, type EgressGateDaemonDeps } from "../../src/egress-gate/gate-daemon.js";
import { createGateClientAuthenticator } from "../../src/egress-gate/gate-client-auth.js";
import { formatGateCredentialHeader } from "../../src/egress-gate/gate-credential.js";
import { canonicalLivenessPayload } from "../../src/egress-gate/liveness-oracle.js";
import { createExclusiveEgressGate, type EgressGateEvent, type ExclusiveEgressGateOptions, type SurrogateUpstreamRequest } from "../../src/egress-gate/gate-server.js";

export const UID = 601;
export const GENERATION = 7;
export const HOST = "api.example.test";
export const cleanup: (() => Promise<unknown>)[] = [];
export async function clean(): Promise<void> { while (cleanup.length) await cleanup.pop()!(); }
export async function directory(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "surr-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
export async function listen(server: net.Server): Promise<number> {
  const sockets = new Set<Socket>();
  server.on("connection", s => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  cleanup.push(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => server.close(() => r())); });
  return (server.address() as net.AddressInfo).port;
}
export async function raw(port: number, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => socket.write(request));
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => socket.destroy(new Error("fixture deadline")), 15_000);
    socket.on("data", c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    socket.on("error", reject);
    socket.on("close", () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString()); });
  });
}
export function binding(ordinal = 1, header = "Authorization"): MintedSurrogateBinding {
  return { ordinal, agent: "hermes", env: `SECRET_${ordinal}`, secret: `secret-${ordinal}`, header, placeholder: mintSurrogatePlaceholder(), destinations: [{ host: HOST, port: 443 }] };
}
export async function helper(dir: string, bindings: MintedSurrogateBinding[]) {
  await writeFile(surrogateBindingsPath(UID, dir), renderSurrogateBindingsFile(GENERATION, bindings));
  const events: SurrogateHelperEvent[] = [];
  const handle = await runSurrogateHelperDaemon({ agentUid: UID, gateUid: UID + 1, operatorUid: UID + 2, generation: GENERATION, surrogateDir: dir,
    fsOps: { mkdir: async () => {}, chmod: async () => {}, chown: async () => {}, rm: path => rm(path, { force: true }), readFile: path => readFile(path, "utf8") },
    onEvent: event => events.push(event),
  });
  cleanup.push(() => handle.close());
  const unlock = async (b: MintedSurrogateBinding, value: string) => {
    const response = await new Promise<string>((resolve, reject) => {
      const s = net.connect(handle.unlockSocketPath, () => s.write(encodeSurrogateUnlockSocketRequest({ v: 1, id: newSurrogateCorrelationId(), kind: "unlock", generation_id: GENERATION, ttl_seconds: 60, secret: b.secret, value })));
      let result = ""; s.on("data", c => result += c.toString()); s.on("end", () => resolve(result.trim())); s.on("error", reject);
    });
    if (parseSurrogateUnlockSocketResponse(response)?.kind !== "ok") throw new Error("fixture unlock refused");
  };
  return { ...handle, events, unlock };
}
export async function tlsUpstream(dir: string, certificateHost = HOST) {
  const keyPath = join(dir, "tls.key"); const certPath = join(dir, "tls.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "1", "-subj", `/CN=${certificateHost}`, "-addext", `subjectAltName=DNS:${certificateHost}`], { stdio: "ignore" });
  const key = await readFile(keyPath); const cert = await readFile(certPath);
  const received: { headers: import("node:http").IncomingHttpHeaders; body: Buffer; url: string }[] = [];
  const server = https.createServer({ key, cert }, (request, response) => {
    const body: Buffer[] = []; request.on("data", c => body.push(c)); request.on("end", () => {
      received.push({ headers: request.headers, body: Buffer.concat(body), url: request.url ?? "" }); response.end("accepted");
    });
  });
  const port = await listen(server);
  const dial = vi.fn<SurrogateUpstreamRequest>((options, listener) => https.request({ ...options, hostname: "127.0.0.1", port, ca: cert }, listener));
  return { server, port, key, cert, received, dial };
}
export function authFixture(port: number) {
  const secret = randomBytes(16).toString("hex");
  const auth = createGateClientAuthenticator({ agentUid: UID, acceptSource: { current: async () => ({ version: 1, generation_id: GENERATION, secret_sha256: createHash("sha256").update(secret).digest("hex") }) } });
  const peerRunner = { run: async (_c: string, args: string[]) => {
    const clientPort = /:(\d+)$/.exec(args[2] ?? "")?.[1];
    return { code: 0, stdout: `p999\nu${UID}\nn127.0.0.1:${clientPort}->127.0.0.1:${port}\n` };
  } };
  const header = formatGateCredentialHeader({ generation_id: GENERATION, secret });
  return { auth, peerRunner, header };
}
export function rule(host = HOST) { return { id: "fixture", schema_version: 1 as const, created_at: "2026-10-01T00:00:00Z", match: { host, port: [443], protocol: "tcp" as const }, scope: {}, disposition: "allow" as const }; }
export function request(header: string, fields = "", target = `http://${HOST}/`): string {
  return `POST ${target} HTTP/1.1\r\nHost: ${HOST}\r\nProxy-Authorization: ${header}\r\nConnection: close\r\n${fields}\r\n`;
}
export async function daemon(dir: string, options: Partial<EgressGateDaemonDeps> = {}, artifactGeneration: number | null = GENERATION) {
  const reserve = net.createServer();
  await new Promise<void>(r => reserve.listen(0, "127.0.0.1", r));
  const port = (reserve.address() as net.AddressInfo).port;
  await new Promise<void>(r => reserve.close(() => r()));
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const claims = { version: 1 as const, agent_uid: UID, gate_port: port, generation_id: GENERATION, live: true, expires_at: Date.now() + 60_000 };
  await writeFile(join(dir, `${UID}.token`), JSON.stringify({ ...claims, sig: sign(null, canonicalLivenessPayload(claims), privateKey).toString("base64") }));
  if (artifactGeneration !== null) await writeFile(surrogateDestinationsPath(UID, dir), renderSurrogateDestinationsFile(artifactGeneration, [binding()]));
  const { auth, peerRunner, header } = authFixture(port);
  const events: EgressGateEvent[] = [];
  const resolver = { resolve: vi.fn(async () => ["203.0.113.1"]) };
  const handle = await runEgressGateDaemon({ agentUid: UID, runtimeDir: dir, livenessDir: dir, credDir: dir, surrogateDir: dir, peerResolverDir: dir,
    loadGatePolicy: async () => JSON.stringify({ agent_uid: UID, gate_port: port, generation_id: GENERATION }), loadRules: async () => [rule(), rule("other.example.test")], loadOraclePublicKey: async () => publicKey,
    upstreamRequest: () => { throw new Error("fixture has no upstream"); }, clientAuth: auth, peerRunner, onEvent: e => events.push(e), resolver, isRoutable: () => true, ...options });
  cleanup.push(() => handle.close());
  return { ...handle, port, header, events, resolver };
}
export async function direct(options: Partial<ExclusiveEgressGateOptions> = {}) {
  const committedPort = 19998;
  const { auth, peerRunner, header } = authFixture(committedPort);
  const events: EgressGateEvent[] = [];
  const resolver = { resolve: vi.fn(async () => ["203.0.113.1"]) };
  const defaults: ExclusiveEgressGateOptions = { policy: { agent_uid: UID, gate_port: committedPort }, rules: [rule()], livenessProbe: { coalescing: "forbidden", binding: { agentUid: UID, gatePort: committedPort }, check: async () => ({ live: true, reasons: [] }) }, upstreamRequest: () => { throw new Error("fixture has no upstream"); }, clientAuth: auth, peerRunner, resolver, isRoutable: () => true, onEvent: e => events.push(e), ...options };
  const server = createExclusiveEgressGate(defaults);
  const port = await listen(server);
  return { server, port, header, events, resolver, defaults };
}
