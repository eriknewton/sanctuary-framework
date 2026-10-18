import { bound } from './constants.js';
import { jcs } from './jcs.js';
import { validate, validateBytes } from './wire.js';

/** Build one schema-checked frame; maximum is the selected edge's payload bound. */
export function encodeFrame(value: unknown, schema: string, maximum: number): Buffer {
  if (!validate(schema, value)) throw new Error('SMB schema');
  const body = Buffer.from(jcs(value));
  // Must match frame.rs and vectors/frame.json: reject before allocating the framed copy.
  if (body.length > maximum) throw new Error('SMB frame length');
  const header = Buffer.alloc(bound('FRAME_HEADER'));
  header.writeUInt32BE(body.length);
  return Buffer.concat([header, body]);
}

/** Read exactly one whole frame; callers close without replying on any error. */
export function decodeFrame(bytes: Uint8Array, schema: string, maximum: number): unknown {
  const header = bound('FRAME_HEADER');
  if (bytes.length < header) throw new Error('SMB short frame');
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const length = buffer.readUInt32BE(0);
  // No payload is parsed until both the declared bound and EOF accounting agree.
  if (length > maximum || bytes.length !== header + length) throw new Error('SMB frame length');
  return validateBytes(schema, bytes.subarray(header), maximum);
}

/** Read one frame from a paused byte stream, destroying it without a reply on any refusal. */
export function readFrame(stream: import('node:stream').Readable, schema: string, maximum: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let length: number | undefined;
    let settled = false;
    const cleanup = (): void => {
      stream.off('readable', advance); stream.off('end', eof); stream.off('error', fail); stream.off('close', eof);
    };
    const fail = (): void => {
      if (settled) return;
      settled = true; cleanup();
      // Refusal consumes the connection, so no caller can reuse a partial or schema-invalid frame.
      stream.destroy(); reject(new Error('SMB frame refused'));
    };
    const advance = (): void => {
      if (settled) return;
      try {
        if (length === undefined) {
          const header: Buffer | null = stream.read(bound('FRAME_HEADER'));
          if (header === null) return;
          if (!Buffer.isBuffer(header) || header.length !== bound('FRAME_HEADER')) return fail();
          length = header.readUInt32BE();
          if (length > maximum) return fail();
        }
        const body: Buffer | null = length === 0 ? Buffer.alloc(0) : stream.read(length);
        if (body === null) return;
        if (!Buffer.isBuffer(body) || body.length !== length) return fail();
        const value = validateBytes(schema, body, maximum);
        settled = true; cleanup(); resolve(value);
      } catch { fail(); }
    };
    const eof = (): void => { advance(); if (!settled) fail(); };
    stream.on('readable', advance); stream.on('end', eof); stream.on('error', fail); stream.on('close', eof);
    advance();
    if (stream.destroyed || stream.readableEnded) eof();
  });
}
