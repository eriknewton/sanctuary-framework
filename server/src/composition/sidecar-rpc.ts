/**
 * Sanctuary Composition v1.0 -- Sidecar JSON-RPC Client
 *
 * JSON-RPC 2.0 client over stdio for communicating with the Concordia
 * Python sidecar. Request/response correlation via numeric IDs.
 * Timeout handling ensures no hung calls.
 *
 * WP-MVP-10 Follow-up #1 hardening: per-message size cap.
 * A single JSON-RPC frame (newline-terminated) may not exceed
 * MAX_SIDECAR_MESSAGE_BYTES. A buggy or malicious sidecar that emits
 * a multi-GB response is rejected before the full frame accumulates
 * in memory, closing an OOM vector.
 */

import type { ChildProcess } from "node:child_process";
import { MAX_SIDECAR_MESSAGE_BYTES } from "./constants.js";
import { SidecarMessageSizeCapExceededError, SidecarTimeoutError } from "./errors.js";
import type { SidecarRequest, SidecarResponse } from "./types.js";

/**
 * Callback fired when the read loop rejects an oversized frame. The owner
 * (SidecarManager) wires this to kill the sidecar process and emit an audit
 * entry. Optional for callers that do not need the hook.
 */
export type SidecarSizeCapListener = (
  err: SidecarMessageSizeCapExceededError
) => void;

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
  private bufferedByteLength = 0;
  private sizeCapTripped = false;

  constructor(
    private process: ChildProcess,
    private defaultTimeoutMs: number,
    private onSizeCapExceeded?: SidecarSizeCapListener,
    private maxMessageBytes: number = MAX_SIDECAR_MESSAGE_BYTES
  ) {
    this.setupStdoutListener();
  }

  private setupStdoutListener(): void {
    if (!this.process.stdout) return;

    this.process.stdout.on("data", (chunk: Buffer) => {
      if (this.sizeCapTripped) return;
      this.buffer += chunk.toString("utf-8");
      this.bufferedByteLength += chunk.byteLength;
      // Enforce the size cap BEFORE processing the buffer: a malformed
      // sidecar that never emits a newline must not be allowed to grow
      // the buffer unbounded.
      if (this.enforceSizeCap()) {
        return;
      }
      this.processBuffer();
    });
  }

  /**
   * Reject the current buffered frame if it exceeds the per-message size cap
   * and no newline boundary has been seen. Returns true if the cap tripped
   * (caller must short-circuit further processing on this chunk).
   */
  private enforceSizeCap(): boolean {
    // If a newline is present anywhere in the buffer, the frame is still
    // bounded by its first newline. Only the length of the prefix up to
    // the first newline matters for a single frame. But the total buffer
    // length is the right comparand: if no newline has been seen and the
    // buffer exceeds the cap, at least one frame alone exceeds the cap.
    if (this.bufferedByteLength <= this.maxMessageBytes) {
      return false;
    }
    const firstNewline = this.buffer.indexOf("\n");
    if (firstNewline >= 0) {
      // There is at least one complete frame. Check whether that frame
      // alone exceeds the cap; if not, let processBuffer handle it.
      // We measure the UTF-8 byte length of the prefix, not the char length.
      const prefixBytes = Buffer.byteLength(
        this.buffer.slice(0, firstNewline),
        "utf-8"
      );
      if (prefixBytes <= this.maxMessageBytes) return false;
    }
    // Either there is no newline at all, or the first frame alone exceeds
    // the cap. Either way, reject and stop accumulating.
    this.sizeCapTripped = true;
    const err = new SidecarMessageSizeCapExceededError(
      this.bufferedByteLength,
      this.maxMessageBytes
    );
    this.buffer = "";
    this.bufferedByteLength = 0;
    this.cancelAll(err.message);
    try {
      this.onSizeCapExceeded?.(err);
    } catch {
      // Listener errors must not propagate into the stdout-data callback.
    }
    return true;
  }

  private processBuffer(): void {
    // Split on newlines; each line is a complete JSON-RPC response.
    const lines = this.buffer.split("\n");
    // Keep the incomplete last line in the buffer.
    this.buffer = lines.pop() ?? "";
    this.bufferedByteLength = Buffer.byteLength(this.buffer, "utf-8");

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
    this.bufferedByteLength = 0;
  }

  /**
   * Number of pending requests.
   */
  get pendingCount(): number {
    return this.pending.size;
  }

  /**
   * Bytes currently buffered from stdout, awaiting a frame boundary.
   * Test-only.
   */
  get bufferedBytesForTest(): number {
    return this.bufferedByteLength;
  }

  /**
   * True once the size cap has tripped and further stdout chunks are
   * being ignored. Test-only.
   */
  get sizeCapTrippedForTest(): boolean {
    return this.sizeCapTripped;
  }
}
