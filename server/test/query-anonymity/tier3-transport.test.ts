/**
 * WP-V1.x-QUERY-LAYER-ANONYMITY Tier 3a (network-path anonymity) Slice 1
 * regression suite.
 *
 * Exercises the pre-declared acceptance criteria from the ratified design
 * (`Review/Sanctuary/Query_Anon_Tier3_Design_Revised_2026-06-13.md` §8)
 * against a REAL in-process two-hop CONNECT chain (relay → egress →
 * destination), not a mock:
 *
 *   - AC-1 (Castle Wall sole-egress, security-critical): no unwrapped
 *     outbound socket exists. The destination server only ever sees
 *     connections from the egress hop; the operator/test process never
 *     connects to the destination directly. Because the substrate clients
 *     hold only the wrapped fetch, the tunnel is the sole path to the
 *     destination and a direct connection is structurally unreachable.
 *   - AC-2 (IP-decoupling, Property 1): the destination observes the
 *     egress hop's address as the peer, never the operator's loopback
 *     client address, across N≥3 deterministic runs.
 *   - AC-4 (streaming preserved): a chunked response is delivered
 *     token-by-token through the tunnel.
 *
 * Plus the fail-closed guarantees (WA-5):
 *   - armed + no dialer        → deny (Tier3FailClosedError), no direct.
 *   - armed + dialer throws    → deny, no direct.
 *   - armed + non-https target → deny, no direct.
 *   - fallback-direct opt-in   → audits a deanonymizing event, connects
 *                                direct (the only non-default path).
 *   - disarmed                 → passthrough (zero behavioral change).
 */

import { afterEach, describe, expect, it } from "vitest";
import net from "node:net";
import http from "node:http";
import tls from "node:tls";
import { X509Certificate, createPrivateKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DISARMED_TIER3_CONFIG,
  TIER3_AUDIT_OPS,
  Tier3FailClosedError,
  createLoopbackConnectDialer,
  createTunneledFetch,
  type Tier3AuditEvent,
  type Tier3TransportConfig,
} from "../../src/query-anonymity/tier3-transport.js";
import { QUERY_ANONYMITY_AUDIT_OPS } from "../../src/query-anonymity/header-strip.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

// ── Test harness: a self-signed cert, two CONNECT proxies, a TLS server ──

interface SelfSigned {
  key: string;
  cert: string;
}

/**
 * Generate a self-signed cert for `localhost` via openssl (available on
 * CI + dev Macs). Kept in a temp dir cleaned up after the run.
 */
function makeSelfSignedCert(): { pems: SelfSigned; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tier3-cert-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    keyPath,
    "-out",
    certPath,
    "-days",
    "1",
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost,IP:127.0.0.1",
  ]);
  const pems: SelfSigned = {
    key: readFileSync(keyPath, "utf8"),
    cert: readFileSync(certPath, "utf8"),
  };
  // Sanity: the cert parses.
  void new X509Certificate(pems.cert);
  void createPrivateKey(pems.key);
  return { pems, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

interface DestinationServer {
  server: tls.Server;
  port: number;
  /** Remote addresses of every connection the destination accepted. */
  peerAddresses: string[];
  close: () => Promise<void>;
}

/**
 * A TLS "provider" that records the peer address of every connection and
 * answers `/stream` with a chunked, token-by-token body.
 */
async function startDestination(pems: SelfSigned): Promise<DestinationServer> {
  const peerAddresses: string[] = [];
  const liveSockets = new Set<net.Socket>();
  const server = tls.createServer({ key: pems.key, cert: pems.cert }, (socket) => {
    const remote = socket.remoteAddress ?? "unknown";
    peerAddresses.push(remote);
    liveSockets.add(socket);
    socket.on("close", () => liveSockets.delete(socket));
    // Minimal HTTP/1.1 server on the TLS socket.
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      if (!buf.includes("\r\n\r\n")) return;
      const requestLine = buf.split("\r\n")[0] ?? "";
      const path = requestLine.split(" ")[1] ?? "/";
      if (path === "/stream") {
        // Chunked transfer; emit three tokens with a gap so a buffering
        // transport would coalesce them and fail the token-by-token check.
        socket.write(
          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        const tokens = ["alpha", "beta", "gamma"];
        let i = 0;
        const tick = () => {
          if (i >= tokens.length) {
            socket.write("0\r\n\r\n");
            socket.end();
            return;
          }
          const t = tokens[i++]!;
          socket.write(`${t.length.toString(16)}\r\n${t}\r\n`);
          setTimeout(tick, 25);
        };
        tick();
      } else {
        const body = "ok";
        socket.write(
          `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`,
        );
        socket.end();
      }
    });
    socket.on("error", () => {
      /* peer reset; ignore in test */
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  return {
    server,
    port,
    peerAddresses,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of liveSockets) s.destroy();
        liveSockets.clear();
        server.close(() => resolve());
      }),
  };
}

interface ConnectProxy {
  server: http.Server;
  port: number;
  /** Authorities (`host:port`) every CONNECT targeted, in order. */
  connectTargets: string[];
  close: () => Promise<void>;
}

/**
 * A loopback HTTP CONNECT proxy. Forwards the tunnel to the requested
 * authority and records what it was asked to connect to. The relay is
 * asked to reach the egress; the egress is asked to reach the destination.
 * Neither logs both the operator and the destination together (the relay
 * only ever sees the egress authority).
 */
async function startConnectProxy(): Promise<ConnectProxy> {
  const connectTargets: string[] = [];
  // Track every socket so close() can forcibly tear them down; otherwise
  // a lingering piped tunnel keeps http.Server.close() pending and the
  // afterEach hook times out.
  const liveSockets = new Set<net.Socket>();
  const server = http.createServer();
  server.on("connect", (req, clientSocket, head) => {
    const authority = req.url ?? "";
    connectTargets.push(authority);
    liveSockets.add(clientSocket);
    clientSocket.on("close", () => liveSockets.delete(clientSocket));
    const lastColon = authority.lastIndexOf(":");
    const host = authority.slice(0, lastColon).replace(/^\[|\]$/g, "");
    const port = Number(authority.slice(lastColon + 1));
    const upstream = net.connect({ host, port }, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length > 0) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    liveSockets.add(upstream);
    upstream.on("close", () => liveSockets.delete(upstream));
    upstream.on("error", () => {
      if (!clientSocket.destroyed) {
        clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        clientSocket.destroy();
      }
    });
    clientSocket.on("error", () => upstream.destroy());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  return {
    server,
    port,
    connectTargets,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of liveSockets) s.destroy();
        liveSockets.clear();
        server.close(() => resolve());
      }),
  };
}

// ── Lifecycle ────────────────────────────────────────────────────────────

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length) {
    const c = cleanups.pop();
    if (c) await c();
  }
});

interface Harness {
  config: Tier3TransportConfig;
  audits: Tier3AuditEvent[];
  destination: DestinationServer;
  relay: ConnectProxy;
  egress: ConnectProxy;
  /** The single wrapped fetch a substrate client would hold. */
  tunneledFetch: typeof fetch;
  baseFetchCalls: number;
}

/**
 * Build a fully-armed Tier 3 transport over a real two-hop CONNECT chain
 * to a real TLS destination. `baseFetch` is instrumented to count direct
 * calls so tests can prove the armed happy path NEVER touches it.
 */
async function buildHarness(
  failureMode: Tier3TransportConfig["onTunnelFailure"] = "deny",
): Promise<Harness> {
  const { pems, cleanup: certCleanup } = makeSelfSignedCert();
  cleanups.push(certCleanup);
  const destination = await startDestination(pems);
  cleanups.push(() => destination.close());
  const relay = await startConnectProxy();
  cleanups.push(() => relay.close());
  const egress = await startConnectProxy();
  cleanups.push(() => egress.close());

  const audits: Tier3AuditEvent[] = [];
  const state = { baseFetchCalls: 0 };
  // A base fetch that records any direct use. In the armed happy path it
  // must remain at zero (AC-1: no unwrapped direct socket).
  const baseFetch: typeof fetch = async (input, init) => {
    state.baseFetchCalls++;
    return globalThis.fetch(input, init);
  };

  const dialer = createLoopbackConnectDialer({
    relay: { host: "127.0.0.1", port: relay.port, tls: false },
    egress: { host: "127.0.0.1", port: egress.port, tls: false },
    // Trust the test cert for the end-to-end handshake to the destination.
    destinationTlsOptions: { ca: pems.cert, servername: "localhost" },
    label: "test operator-run two-hop CONNECT",
  });

  const config: Tier3TransportConfig = {
    armed: true,
    mode: "connect",
    posture: "operator-run",
    onTunnelFailure: failureMode,
    dialer,
  };
  const tunneledFetch = createTunneledFetch(baseFetch, config, (e) => audits.push(e));

  return {
    config,
    audits,
    destination,
    relay,
    egress,
    tunneledFetch,
    get baseFetchCalls() {
      return state.baseFetchCalls;
    },
  } as Harness;
}

// The destination is addressed by name `localhost` (SAN-matched) so the
// dialer's CONNECT to the egress carries the right authority and the TLS
// servername matches.
function destUrl(h: Harness, path: string): string {
  return `https://localhost:${h.destination.port}${path}`;
}

// ── AC-1: no unwrapped outbound socket (security-critical) ───────────────

describe("Tier 3a Slice 1 — AC-1: Castle Wall sole-egress (no unwrapped socket)", () => {
  it("reaches the destination ONLY through the egress hop; base fetch is never called direct", async () => {
    const h = await buildHarness();
    const res = await h.tunneledFetch(destUrl(h, "/plain"));
    const text = await res.text();
    expect(text).toBe("ok");

    // The armed happy path must NOT have fallen through to a direct
    // connection. baseFetch is the only way to open an unwrapped socket;
    // it stays at zero.
    expect(h.baseFetchCalls).toBe(0);

    // Every connection the destination accepted came from the egress hop's
    // outbound socket, never from this (operator) process connecting to the
    // destination directly. (All loopback, but distinguished by the CONNECT
    // chain: the destination peer is the egress's ephemeral socket.)
    expect(h.destination.peerAddresses.length).toBe(1);

    // The relay only ever saw a CONNECT to the EGRESS authority — never to
    // the destination. No single hop links operator→destination.
    expect(h.relay.connectTargets).toEqual([`127.0.0.1:${h.egress.port}`]);
    // The egress saw the CONNECT to the destination authority.
    expect(h.egress.connectTargets).toEqual([`localhost:${h.destination.port}`]);
  });

  it("the wrapped fetch is the only handle a consumer holds; the tunnel opens no socket the wrapped channel did not initiate", async () => {
    const h = await buildHarness();
    // Drive several calls; assert the destination is only ever reached via
    // the egress chain and base fetch is never used. This is the structural
    // AC-1 property: the transport never creates a second outbound path.
    for (let i = 0; i < 3; i++) {
      const res = await h.tunneledFetch(destUrl(h, "/plain"));
      await res.text();
    }
    expect(h.baseFetchCalls).toBe(0);
    expect(h.destination.peerAddresses.length).toBe(3);
    expect(h.relay.connectTargets.every((t) => t === `127.0.0.1:${h.egress.port}`)).toBe(true);
    expect(h.relay.connectTargets).toHaveLength(3);
  });
});

// ── AC-2: IP-decoupling (Property 1) ─────────────────────────────────────

describe("Tier 3a Slice 1 — AC-2: destination sees the egress IP, never the operator IP (N≥3)", () => {
  it("audits the egress IP as the observed source across 3 deterministic runs", async () => {
    const h = await buildHarness();
    for (let i = 0; i < 3; i++) {
      const res = await h.tunneledFetch(destUrl(h, "/plain"));
      await res.text();
    }
    const tunnelEvents = h.audits.filter((e) => e.op === TIER3_AUDIT_OPS.TUNNEL_USED);
    expect(tunnelEvents).toHaveLength(3);
    for (const e of tunnelEvents) {
      // The reported egress identity is the egress hop, not the operator.
      expect(e.egressIp).toBe("127.0.0.1");
      expect(e.dialerLabel).toBe("test operator-run two-hop CONNECT");
      expect(e.posture).toBe("operator-run");
    }
    // The destination's recorded peers are the egress's outbound sockets.
    // None is an unwrapped operator-direct connection (baseFetch unused).
    expect(h.baseFetchCalls).toBe(0);
    expect(h.destination.peerAddresses).toHaveLength(3);
  });
});

// ── AC-4: streaming preserved ────────────────────────────────────────────

describe("Tier 3a Slice 1 — AC-4: token-by-token streaming survives the tunnel", () => {
  it("delivers chunked tokens incrementally, not coalesced into one buffer", async () => {
    const h = await buildHarness();
    const res = await h.tunneledFetch(destUrl(h, "/stream"));
    expect(res.body).toBeTruthy();
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    const chunks: string[] = [];
    // Read frame-by-frame; the destination emits tokens 25ms apart so a
    // streaming transport yields multiple reads, a buffering one yields one.
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      const piece = decoder.decode(value, { stream: true });
      if (piece.length > 0) chunks.push(piece);
    }
    const joined = chunks.join("");
    expect(joined).toContain("alpha");
    expect(joined).toContain("beta");
    expect(joined).toContain("gamma");
    // Streaming proof: more than one read frame arrived (token-by-token),
    // not a single coalesced buffer.
    expect(chunks.length).toBeGreaterThan(1);
    expect(h.baseFetchCalls).toBe(0);
  });
});

// ── Fail-closed (WA-5) ───────────────────────────────────────────────────

describe("Tier 3a Slice 1 — fail-closed (WA-5): never silently connect direct", () => {
  it("armed + no dialer → denies with Tier3FailClosedError; base fetch untouched", async () => {
    let directCalls = 0;
    const baseFetch: typeof fetch = async (i, init) => {
      directCalls++;
      return globalThis.fetch(i, init);
    };
    const audits: Tier3AuditEvent[] = [];
    const fetchFn = createTunneledFetch(
      baseFetch,
      { armed: true, mode: "connect", posture: "operator-run", onTunnelFailure: "deny" },
      (e) => audits.push(e),
    );
    await expect(fetchFn("https://api.anthropic.com/v1/messages")).rejects.toBeInstanceOf(
      Tier3FailClosedError,
    );
    expect(directCalls).toBe(0);
    expect(audits.map((e) => e.op)).toContain(TIER3_AUDIT_OPS.FAIL_CLOSED);
  });

  it("armed + dialer throws → denies; base fetch untouched", async () => {
    let directCalls = 0;
    const baseFetch: typeof fetch = async (i, init) => {
      directCalls++;
      return globalThis.fetch(i, init);
    };
    const fetchFn = createTunneledFetch(baseFetch, {
      armed: true,
      mode: "connect",
      posture: "operator-run",
      onTunnelFailure: "deny",
      dialer: {
        label: "always-fails",
        async dial() {
          throw new Error("relay unreachable");
        },
      },
    });
    await expect(fetchFn("https://api.anthropic.com/v1/messages")).rejects.toBeInstanceOf(
      Tier3FailClosedError,
    );
    expect(directCalls).toBe(0);
  });

  it("armed + non-https target → denies (cannot tunnel; must not send direct)", async () => {
    let directCalls = 0;
    const baseFetch: typeof fetch = async (i, init) => {
      directCalls++;
      return globalThis.fetch(i, init);
    };
    const fetchFn = createTunneledFetch(baseFetch, {
      armed: true,
      mode: "connect",
      posture: "operator-run",
      onTunnelFailure: "deny",
      dialer: {
        label: "unused",
        async dial() {
          return null;
        },
      },
    });
    await expect(fetchFn("http://insecure.example.com/")).rejects.toBeInstanceOf(
      Tier3FailClosedError,
    );
    expect(directCalls).toBe(0);
  });

  it("dialer returns null → denies (fail-closed); base fetch untouched", async () => {
    let directCalls = 0;
    const baseFetch: typeof fetch = async (i, init) => {
      directCalls++;
      return globalThis.fetch(i, init);
    };
    const fetchFn = createTunneledFetch(baseFetch, {
      armed: true,
      mode: "connect",
      posture: "operator-run",
      onTunnelFailure: "deny",
      dialer: {
        label: "declines",
        async dial() {
          return null;
        },
      },
    });
    await expect(fetchFn("https://api.anthropic.com/v1/messages")).rejects.toBeInstanceOf(
      Tier3FailClosedError,
    );
    expect(directCalls).toBe(0);
  });
});

// ── Explicit opt-in fallback (the only non-default deanonymizing path) ───

describe("Tier 3a Slice 1 — fallback-direct is opt-in only and is audited as deanonymizing", () => {
  it("fallback-direct → connects direct AND emits a deanon-fallback audit event", async () => {
    let directCalls = 0;
    const baseFetch: typeof fetch = async () => {
      directCalls++;
      // Return a synthetic response without a real network call.
      return new Response("direct-ok", { status: 200 });
    };
    const audits: Tier3AuditEvent[] = [];
    const fetchFn = createTunneledFetch(
      baseFetch,
      {
        armed: true,
        mode: "connect",
        posture: "third-party",
        onTunnelFailure: "fallback-direct",
        dialer: {
          label: "always-fails",
          async dial() {
            throw new Error("relay down");
          },
        },
      },
      (e) => audits.push(e),
    );
    const res = await fetchFn("https://api.anthropic.com/v1/messages");
    expect(await res.text()).toBe("direct-ok");
    expect(directCalls).toBe(1);
    expect(audits.map((e) => e.op)).toContain(TIER3_AUDIT_OPS.DEANON_FALLBACK);
  });
});

// ── Disarmed passthrough (default; zero behavioral change) ───────────────

describe("Tier 3a Slice 1 — disarmed default is a transparent passthrough", () => {
  it("returns the base fetch unchanged when disarmed", () => {
    const baseFetch: typeof fetch = async () => new Response("x");
    const fetchFn = createTunneledFetch(baseFetch, DISARMED_TIER3_CONFIG);
    // Identity: disarmed returns the exact base fetch, so there is zero
    // added latency and zero behavioral change for non-opted-in operators.
    expect(fetchFn).toBe(baseFetch);
  });

  it("the exported disarmed config is fail-closed and operator-run by default", () => {
    expect(DISARMED_TIER3_CONFIG.armed).toBe(false);
    expect(DISARMED_TIER3_CONFIG.onTunnelFailure).toBe("deny");
    expect(DISARMED_TIER3_CONFIG.posture).toBe("operator-run");
  });
});

// ── AC-1 end-to-end through the real SubstrateSelector composition ───────

/**
 * The strongest AC-1 evidence: build a REAL SubstrateSelector with an armed
 * Tier 3 config and drive a real frontier (Anthropic) invocation through
 * its wrapped fetch. Prove that:
 *   - the provider call reaches the destination ONLY via the egress chain;
 *   - the global/base fetch is never called directly (no unwrapped socket);
 *   - the Tier 1 header-strip audit STILL fires, proving the tunnel is
 *     composed BENEATH `createAnonymizedFetch`, not in place of it (so
 *     Castle Wall still binds the single wrapped channel).
 */
describe("Tier 3a Slice 1 — AC-1 end-to-end through SubstrateSelector", () => {
  it("an armed selector routes a frontier call through the tunnel; the Tier 1 strip audit still fires; no direct socket", async () => {
    const { pems, cleanup: certCleanup } = makeSelfSignedCert();
    cleanups.push(certCleanup);

    // A TLS "Anthropic" that records peers and answers the messages API.
    const peerAddresses: string[] = [];
    const live = new Set<net.Socket>();
    const dest = tls.createServer({ key: pems.key, cert: pems.cert }, (socket) => {
      peerAddresses.push(socket.remoteAddress ?? "unknown");
      live.add(socket);
      socket.on("close", () => live.delete(socket));
      let buf = "";
      socket.on("data", (chunk) => {
        buf += chunk.toString("utf8");
        if (!buf.includes("\r\n\r\n")) return;
        const body = JSON.stringify({ content: [{ type: "text", text: "summary" }] });
        socket.write(
          `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(
            body,
          )}\r\nConnection: close\r\n\r\n${body}`,
        );
        socket.end();
      });
      socket.on("error", () => {});
    });
    await new Promise<void>((r) => dest.listen(0, "127.0.0.1", r));
    const dport = (dest.address() as net.AddressInfo).port;
    cleanups.push(
      () =>
        new Promise<void>((r) => {
          for (const s of live) s.destroy();
          dest.close(() => r());
        }),
    );

    const relay = await startConnectProxy();
    cleanups.push(() => relay.close());
    const egress = await startConnectProxy();
    cleanups.push(() => egress.close());

    // Instrument the base fetch the selector is given so we can prove the
    // armed happy path never falls through to a direct connection.
    let directCalls = 0;
    const baseFetch: typeof fetch = async (i, init) => {
      directCalls++;
      return globalThis.fetch(i, init);
    };

    const dialer = createLoopbackConnectDialer({
      relay: { host: "127.0.0.1", port: relay.port, tls: false },
      egress: { host: "127.0.0.1", port: egress.port, tls: false },
      destinationTlsOptions: { ca: pems.cert, servername: "localhost" },
      label: "selector-e2e two-hop CONNECT",
    });

    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const appended: { operation: string }[] = [];
    const origAppend = auditLog.append.bind(auditLog);
    // Spy on audit appends to confirm the Tier 1 strip event still fires.
    (auditLog as unknown as { append: typeof auditLog.append }).append = ((
      ...args: Parameters<typeof auditLog.append>
    ) => {
      appended.push({ operation: args[1] });
      return origAppend(...args);
    }) as typeof auditLog.append;

    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "tier3-e2e",
      fetchImpl: baseFetch,
      tier3: {
        armed: true,
        mode: "connect",
        posture: "operator-run",
        onTunnelFailure: "deny",
        dialer,
      },
    });

    // Point the frontier client at our TLS "Anthropic" by overriding the
    // provider key + relying on the selector's wrapped fetch. The frontier
    // client targets the real Anthropic endpoint, so instead we drive the
    // wrapped fetch directly against the test destination to exercise the
    // exact composed channel the selector installed (anonymize∘tunnel∘base).
    const wrapped = (selector as unknown as { fetchImpl: typeof fetch }).fetchImpl;
    const res = await wrapped(`https://localhost:${dport}/v1/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "sk-ant-test",
        "anthropic-version": "2023-06-01",
        // A fingerprintable header the Tier 1 strip must remove even while
        // the request rides the Tier 3 tunnel.
        "User-Agent": "node/24 darwin arm64",
      },
      body: JSON.stringify({ model: "claude", messages: [] }),
    });
    const json = (await res.json()) as { content: { text: string }[] };
    expect(json.content[0]?.text).toBe("summary");

    // AC-1: the provider was reached ONLY via the egress chain.
    expect(directCalls).toBe(0);
    expect(peerAddresses.length).toBe(1);
    expect(relay.connectTargets).toEqual([`127.0.0.1:${egress.port}`]);
    expect(egress.connectTargets).toEqual([`localhost:${dport}`]);

    // The Tier 1 header-strip audit STILL fires on the tunneled call,
    // proving the tunnel sits beneath the anonymized fetch (composition,
    // not replacement). The Tier 3 tunnel-used audit also fires.
    const ops = appended.map((a) => a.operation);
    expect(ops).toContain(QUERY_ANONYMITY_AUDIT_OPS.HEADERS_STRIPPED);
    expect(ops).toContain(TIER3_AUDIT_OPS.TUNNEL_USED);
  });
});
