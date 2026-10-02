/** One query per connection; a response becomes usable only when its stream ends. */
import { connect } from "node:net";
import {
  SURROGATE_QUERY_TIMEOUT_MS, SURROGATE_WIRE_MAX_FRAME_BYTES, SURROGATE_WIRE_VERSION,
  encodeSurrogateQueryRequest, newSurrogateCorrelationId, parseSurrogateQueryResponse,
  surrogateCorrelationId,
  type SurrogateCorrelationId, type SurrogateFailureCode, type SurrogateQueryRequest,
  type SurrogateQueryResponse,
} from "../credential-surrogate/index.js";
import { surrogateQuerySocketPath } from "./surrogate-helper-daemon.js";

export type SurrogateHelperResult =
  | { kind: "response"; correlationId: SurrogateCorrelationId; response: SurrogateQueryResponse }
  | { kind: "failure"; code: SurrogateFailureCode };
export interface SurrogateHelperClient {
  query(input: Omit<SurrogateQueryRequest, "v" | "id" | "kind">): Promise<SurrogateHelperResult>;
}
/** Parent-directory injection is for isolated sockets; production uses the uid path. */
export function createSurrogateHelperClient(agentUid: number, surrogateDir?: string): SurrogateHelperClient {
  const socketPath = surrogateQuerySocketPath(agentUid, surrogateDir);
  return Object.freeze({
    query(input: Omit<SurrogateQueryRequest, "v" | "id" | "kind">): Promise<SurrogateHelperResult> {
      const id = surrogateCorrelationId(newSurrogateCorrelationId())!;
      return new Promise((resolve) => {
        let state: "CONNECTING" | "READING" | "FRAME" | "SETTLED" = "CONNECTING";
        let bytes = Buffer.alloc(0);
        let answer: SurrogateQueryResponse | null = null;
        const socket = connect(socketPath);
        const state_SETTLED = (result: SurrogateHelperResult): void => {
          if (state === "SETTLED") return;
          state = "SETTLED";
          clearTimeout(timer);
          bytes = Buffer.alloc(0);
          socket.destroy();
          resolve(result);
        };
        const fail = (code: SurrogateFailureCode): void => state_SETTLED({ kind: "failure", code });
        const timer = setTimeout(() => fail("helper_timeout"), SURROGATE_QUERY_TIMEOUT_MS);
        socket.on("connect", () => {
          if (state === "SETTLED") return;
          state = "READING";
          try { socket.write(encodeSurrogateQueryRequest({ ...input, v: SURROGATE_WIRE_VERSION, id, kind: "resolve" })); }
          catch { fail("helper_malformed"); }
        });
        socket.on("data", (chunk: Buffer) => {
          if (state === "SETTLED") return;
          // EOF, not the first newline, proves there is no second frame on this connection.
          if (state === "FRAME" || bytes.length + chunk.length > SURROGATE_WIRE_MAX_FRAME_BYTES) return fail("helper_malformed");
          bytes = Buffer.concat([bytes, chunk]);
          const newline = bytes.indexOf("\n");
          if (newline < 0) return;
          if (newline !== bytes.length - 1) return fail("helper_malformed");
          answer = parseSurrogateQueryResponse(bytes.subarray(0, newline).toString("utf8"));
          if (!answer) return fail("helper_malformed");
          if (answer.id !== id) return fail("helper_id_mismatch");
          state = "FRAME";
        });
        socket.on("end", () => {
          if (state === "FRAME" && answer) state_SETTLED({ kind: "response", correlationId: id, response: answer });
          else if (state !== "SETTLED") fail("helper_malformed");
        });
        socket.on("error", () => fail(state === "CONNECTING" ? "helper_connect_failed" : "helper_malformed"));
        socket.on("close", () => { if (state !== "SETTLED") fail("helper_malformed"); });
      });
    },
  });
}
