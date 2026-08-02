/**
 * Dashboard server lifecycle tests that need access to the real Server object.
 *
 * The public handles intentionally do not expose Node's Server, so these tests
 * mock node:http.createServer before importing the SUT and capture the returned
 * server object without widening the production handle shape.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { Server } from "node:http";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";

let capturedServers: Server[] = [];

async function importWithCapturedHttp<T>(importer: () => Promise<T>): Promise<T> {
  vi.resetModules();
  capturedServers = [];
  vi.doMock("node:http", async (importOriginal) => {
    const actual = await importOriginal<typeof import("node:http")>();
    return {
      ...actual,
      createServer: ((...args: Parameters<typeof actual.createServer>) => {
        const server = actual.createServer(...args);
        capturedServers.push(server);
        return server;
      }) as typeof actual.createServer,
    };
  });
  return importer();
}

function captureStderr(): { chunks: string[]; restore: () => void } {
  const chunks: string[] = [];
  const original = process.stderr.write;
  process.stderr.write = ((chunk: unknown) => {
    chunks.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  return {
    chunks,
    restore: () => {
      process.stderr.write = original;
    },
  };
}

async function closeCapturedServers(): Promise<void> {
  for (const server of capturedServers) {
    server.closeAllConnections?.();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    }).catch(() => undefined);
  }
  capturedServers = [];
}

afterEach(async () => {
  await closeCapturedServers();
  vi.doUnmock("node:http");
  vi.restoreAllMocks();
  vi.resetModules();
});

describe("dashboard server post-listen errors", () => {
  it("startDashboardServer logs post-listen server errors without throwing", async () => {
    const { startDashboardServer } = await importWithCapturedHttp(() =>
      import("../../src/dashboard/server.js"),
    );
    const sources: AggregatorSources = {
      mode: "co-located",
      server_version: "lifecycle-test",
      activity: [],
      pendingApprovals: [],
    };
    const options: Parameters<typeof startDashboardServer>[0] & {
      shutdownGraceMs: number;
    } = {
      mode: "co-located",
      port: 0,
      sources,
      shutdownGraceMs: 25,
    };
    const handle = await startDashboardServer(options);
    const server = capturedServers[0];
    expect(server).toBeDefined();

    const captured = captureStderr();
    try {
      expect(() =>
        server!.emit("error", new Error("synthetic dashboard server failure")),
      ).not.toThrow();
    } finally {
      captured.restore();
    }

    expect(captured.chunks.join("")).toContain(
      "synthetic dashboard server failure",
    );
    expect(captured.chunks.join("")).toContain("SAFETY:");
    await handle.stop();
  });

  it("startMultiDashboardServer logs post-listen server errors without throwing", async () => {
    const { startMultiDashboardServer } = await importWithCapturedHttp(() =>
      import("../../src/dashboard/multi-server.js"),
    );
    const options: Parameters<typeof startMultiDashboardServer>[0] & {
      shutdownGraceMs: number;
    } = {
      port: 0,
      host: "127.0.0.1",
      shutdownGraceMs: 25,
    };
    const handle = await startMultiDashboardServer(options);
    const server = capturedServers[0];
    expect(server).toBeDefined();

    const captured = captureStderr();
    try {
      expect(() =>
        server!.emit("error", new Error("synthetic multi dashboard failure")),
      ).not.toThrow();
    } finally {
      captured.restore();
    }

    expect(captured.chunks.join("")).toContain(
      "synthetic multi dashboard failure",
    );
    expect(captured.chunks.join("")).toContain("SAFETY:");
    await handle.stop();
  });
});
