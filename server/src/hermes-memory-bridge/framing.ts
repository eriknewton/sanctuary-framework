import { Buffer } from "node:buffer";

import { LENGTH_PREFIX_BYTES, MAX_PRIVATE_FRAME_BYTES } from "./constants.js";

export type PrivateFrameErrorCode = "frame_over_cap" | "zero_length" | "invalid_state";

export class PrivateFrameError extends Error {
  constructor(
    readonly code: PrivateFrameErrorCode,
    message: string = code,
  ) {
    super(message);
    this.name = "PrivateFrameError";
  }
}

export type PrivateFrameDecodeResult =
  | { readonly kind: "frame"; readonly body: Uint8Array }
  | { readonly kind: "need_more" }
  | { readonly kind: "fatal"; readonly error: PrivateFrameError };

export class PrivateFrameDecoder {
  private buffered = Buffer.alloc(0);
  private fatalError: PrivateFrameError | undefined;

  push(bytes: Uint8Array): void {
    if (this.fatalError !== undefined) return;
    if (bytes.byteLength === 0) return;
    this.buffered = Buffer.concat([this.buffered, Buffer.from(bytes)]);
  }

  next(): PrivateFrameDecodeResult {
    if (this.fatalError !== undefined) {
      return { kind: "fatal", error: this.fatalError };
    }
    if (this.buffered.byteLength < LENGTH_PREFIX_BYTES) {
      return { kind: "need_more" };
    }
    const length = this.buffered.readUInt32BE(0);
    // The length is rejected before slicing a body, matching the relay allocation boundary.
    if (length > MAX_PRIVATE_FRAME_BYTES) {
      return this.fail(new PrivateFrameError("frame_over_cap", "private frame length exceeds cap"));
    }
    if (length === 0) {
      return this.fail(new PrivateFrameError("zero_length", "private frame payload is empty"));
    }
    const total = LENGTH_PREFIX_BYTES + length;
    if (this.buffered.byteLength < total) {
      return { kind: "need_more" };
    }
    const body = this.buffered.subarray(LENGTH_PREFIX_BYTES, total);
    this.buffered = this.buffered.subarray(total);
    return { kind: "frame", body };
  }

  bufferedBytes(): number {
    return this.buffered.byteLength;
  }

  private fail(error: PrivateFrameError): PrivateFrameDecodeResult {
    this.fatalError = error;
    this.buffered = Buffer.alloc(0);
    return { kind: "fatal", error };
  }
}

export function encodePrivateFramePayload(body: Uint8Array): Uint8Array {
  if (body.byteLength > MAX_PRIVATE_FRAME_BYTES) {
    throw new PrivateFrameError("frame_over_cap", "private frame payload exceeds cap");
  }
  if (body.byteLength === 0) {
    throw new PrivateFrameError("zero_length", "private frame payload is empty");
  }
  return body;
}

export function encodePrivateFrame(body: Uint8Array): Buffer {
  const payload = encodePrivateFramePayload(body);
  const out = Buffer.allocUnsafe(LENGTH_PREFIX_BYTES + payload.byteLength);
  out.writeUInt32BE(payload.byteLength, 0);
  Buffer.from(payload).copy(out, LENGTH_PREFIX_BYTES);
  return out;
}
