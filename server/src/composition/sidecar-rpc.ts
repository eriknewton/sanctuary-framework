/**
 * Sanctuary Composition v1.0 -- Sidecar JSON-RPC Client
 *
 * JSON-RPC 2.0 client over stdio for communicating with the Concordia
 * Python sidecar. Request/response correlation via numeric IDs.
 * Timeout handling ensures no hung calls.
 */

import type { ChildProcess } from "node:child_process";
import { SidecarTimeoutError } from "./errors.js";
import type { SidecarRequest, SidecarResponse } from "./types.js";

/**
 * JSON-RPC client for sidecar communication over stdio.
 */
export class SidecarRpcClient {
  private nextId = 1;
  private pending = new Map<
    number,
    {
      resolve: (value: SidecarResponse) => void;
      reject: (err: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private buffer = "";

  constructor(
    private process: ChildProcess,
    private defaultTimeoutMs: number
  ) {
    this.setupStdoutListener();
  }

  private setupStdoutListener(): void {
    if (!this.process.stdout) return;

    this.process.stdout.on("data", (chunk: Buffer) => {
      this.buffer += chunk.toString("utf-8");
      this.processBuffer();
    });
  }

  private processBuffer(): void {
    // Split on newlines; each line is a complete JSON-RPC response.
    const lines = this.buffer.split("\n");
    // Keep the incomplete last line in the buffer.
    this.buffer = lines.pop() ?? "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const response = JSON.parse(trimmed) as SidecarResponse;
        const entry = this.pending.get(response.id);
        if (entry) {
          clearTimeout(entry.timer);
          this.pending.delete(response.id);
          entry.resolve(response);
        }
      } catch {
        // Malformed JSON from sidecar; skip silently.
        // Non-JSON output (e.g. Python startup warnings) is expected.
      }
    }
  }

  /**
   * Send a JSON-RPC request to the sidecar and wait for the response.
   *
   * @param method RPC method name
   * @param params Method parameters
   * @param timeoutMs Optional per-call timeout override
   * @returns The JSON-RPC response
   * @throws SidecarTimeoutError if the call times out
   */
  async call(
    method: string,
    params: Record<string, unknown> = {},
    timeoutMs?: number
  ): Promise<SidecarResponse> {
    const id = this.nextId++;
    const timeout = timeoutMs ?? this.defaultTimeoutMs;

    const request: SidecarRequest = {
      jsonrpc: "2.0",
      id,
      method,
      params,
    };

    return new Promise<SidecarResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new SidecarTimeoutError(method, timeout));
      }, timeout);

      this.pending.set(id, { resolve, reject, timer });

      // Write to sidecar stdin
      const stdin = this.process.stdin;
      if (!stdin || stdin.destroyed) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error("Sidecar stdin is not available or destroyed"));
        return;
      }

      const payload = JSON.stringify(request) + "\n";
      stdin.write(payload, "utf-8", (err) => {
        if (err) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  /**
   * Cancel all pending requests. Called on sidecar crash/shutdown.
   */
  cancelAll(reason: string): void {
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.reject(new Error(`Sidecar RPC cancelled: ${reason}`));
    }
    this.pending.clear();
    this.buffer = "";
  }

  /**
   * Number of pending requests.
   */
  get pendingCount(): number {
    return this.pending.size;
  }
}
