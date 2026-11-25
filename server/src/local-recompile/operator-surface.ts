/**
 * Operator-side access to the local results and the operator log, shared by
 * the CLI and the dashboard. Nothing here is reachable from an agent-facing
 * path: the MCP server lists no tool that calls into this file.
 *
 * Every export, view and delete writes its operator-log row before the
 * effect, and when the row fails the effect does not happen.
 */
import { LocalOplog, OPLOG_MAX_ROWS, type OplogRow, type OplogStatus, type OplogVerification } from "./oplog.js";
import { LocalResultsStore, type LocalResultObject } from "./results-store.js";
import { copyStoreKey, isRequestId, type LocalStoreBackend } from "./store-record.js";
import type { LocalStoreKeys } from "./store-keys.js";

/** One page of operator-log rows for a read; an export walks the whole log in pages of this size. */
export const OPERATOR_LOG_PAGE_ROWS = 1_000;

/** The replacement for a control character in model text shown on a terminal or a page. */
export const CONTROL_REPLACEMENT = "�";

/**
 * Replace every C0 and C1 control character other than newline and tab, and
 * DEL, so model output cannot drive a terminal.
 */
export function neutralizeControlText(text: string): string {
  // eslint-disable-next-line no-control-regex -- the class names exactly the characters being removed
  return text.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, CONTROL_REPLACEMENT);
}

export interface LocalResultSummary {
  request_id: string;
  kind: string;
  state: string;
  created_at: number;
  /** UTF-8 bytes of the summary text; 0 while pending or indeterminate. */
  summary_bytes: number;
}

export type OperatorLogRead =
  | { ok: true; status: OplogStatus; rows: OplogRow[] }
  | { ok: false; break: Exclude<OplogVerification, { ok: true }> };

function summaryText(object: LocalResultObject): string {
  const summary = object.body?.summary;
  return typeof summary === "string" ? summary : "";
}

export function summarizeResult(object: LocalResultObject): LocalResultSummary {
  return {
    request_id: object.request_id,
    kind: object.kind,
    state: object.state,
    created_at: object.created_at,
    summary_bytes: Buffer.byteLength(summaryText(object), "utf8"),
  };
}

export interface LocalOperatorStoresOptions {
  /** The custody lock root the server and the worker use; all three must agree. */
  runtimeRoot: string;
  now?: () => number;
}

/** A log export's outcome: the chain's verification, or a destination that could not be created after the row. */
export type LogExportOutcome = OplogVerification | { ok: false; seq: number; reason: "export_file_unavailable" };

/** Both local stores opened for the operator; the caller closes it. */
export class LocalOperatorStores {
  private readonly oplog: LocalOplog;
  private readonly results: LocalResultsStore;

  constructor(storage: LocalStoreBackend, keys: LocalStoreKeys, options: LocalOperatorStoresOptions) {
    const lock = { runtimeRoot: options.runtimeRoot, ...(options.now ? { now: options.now } : {}) };
    this.oplog = new LocalOplog(storage, copyStoreKey(keys.oplogKey), lock);
    this.results = new LocalResultsStore(storage, copyStoreKey(keys.resultsKey), this.oplog, lock);
  }

  close(): void {
    this.results.close();
    this.oplog.close();
  }

  /** Newest first; the store's object cap bounds the list, so there is no paging. */
  async listResults(): Promise<LocalResultSummary[]> {
    const objects = await this.results.list({ includeUncommitted: true });
    return objects.map(summarizeResult).sort((a, b) => b.created_at - a.created_at || (a.request_id < b.request_id ? 1 : -1));
  }

  /** Open one result for the operator; the render row is written first. */
  async viewResult(requestId: string): Promise<LocalResultObject | null> {
    if (!isRequestId(requestId)) return null;
    if ((await this.results.get(requestId, { includeUncommitted: true })) === null) return null;
    await this.oplog.append("operator_render", { request_id: requestId });
    return this.results.get(requestId, { includeUncommitted: true });
  }

  /** Read one result for export; the export row is written first. */
  async exportResult(requestId: string): Promise<LocalResultObject | null> {
    if (!isRequestId(requestId)) return null;
    if ((await this.results.get(requestId, { includeUncommitted: true })) === null) return null;
    await this.oplog.append("operator_export", { request_id: requestId });
    return this.results.get(requestId, { includeUncommitted: true });
  }

  /** The store writes the delete row before removing the object. */
  async deleteResult(requestId: string): Promise<boolean> {
    if (!isRequestId(requestId)) return false;
    return this.results.delete(requestId);
  }

  async deleteAllResults(): Promise<number> {
    let deleted = 0;
    for (const entry of await this.results.list({ includeUncommitted: true })) {
      if (await this.results.delete(entry.request_id)) deleted += 1;
    }
    return deleted;
  }

  /** Verify the chain, then read one page; a broken chain is reported, never read past. */
  async readLog(sinceSeq: number, limit: number): Promise<OperatorLogRead> {
    const verification = await this.oplog.verifyChain();
    if (!verification.ok) return { ok: false, break: verification };
    const status = await this.oplog.status();
    const rows = await this.oplog.readRows(sinceSeq, Math.min(Math.max(1, limit), OPLOG_MAX_ROWS));
    return { ok: true, status, rows };
  }

  /**
   * Verify the chain, write the export row, then call `begin` for the sink and hand it every retained
   * row in pages. The export row is the last row the export covers, and it is written before `begin`
   * runs, so the destination never exists without its row. `begin` answering null (the destination
   * could not be created) ends the export after the row: a row with no file, the safe direction.
   */
  async exportLog(begin: () => Promise<((rows: OplogRow[]) => Promise<void>) | null>): Promise<LogExportOutcome> {
    const verification = await this.oplog.verifyChain();
    if (!verification.ok) return verification;
    const marker = await this.oplog.append("oplog_exported", { head_seq: verification.head_seq });
    const sink = await begin();
    if (sink === null) return { ok: false, seq: marker.seq, reason: "export_file_unavailable" };
    const status = await this.oplog.status();
    for (let seq = status.base_seq; seq <= marker.seq; ) {
      const rows = await this.oplog.readRows(seq, OPERATOR_LOG_PAGE_ROWS);
      const page = rows.filter((row) => row.seq <= marker.seq);
      if (page.length === 0) break;
      await sink(page);
      seq = page[page.length - 1]!.seq + 1;
    }
    return { ok: true, base_seq: status.base_seq, head_seq: marker.seq };
  }
}
