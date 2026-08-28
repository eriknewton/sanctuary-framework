/**
 * Sanctuary MCP Server -- `sanctuary state_disclose_unattributed` CLI subcommand.
 *
 * Operator surface for reaching the content of ONE state entry whose writer the
 * fortress cannot establish. It is the shipped route for an owner who no longer
 * holds the writer identity; an owner who still holds it recovers by importing
 * that identity instead, which restores verification rather than stepping
 * around it, and this command says so on every path including the successful
 * one.
 *
 * Tier 1 FORCED. Approval fires through the same non-relaxable classification
 * the MCP tool uses (`NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS` in
 * `src/principal-policy/loader.ts`), resolved here through an interactive stdin
 * prompt because the CLI is the operator's own out-of-band presence rather than
 * an MCP agent session. A non-interactive invocation (no TTY) fails CLOSED to
 * denial: a piped stdin or a CI job cannot supply informed consent, and the
 * failure mode if this were the other way round is invisible from the outside -
 * the command succeeds, the operator sees output, and nobody approved anything.
 *
 * The disclosure itself, its namespace firewall and its audit record are all
 * performed by the shared `discloseUnattributedState` so this file and the MCP
 * tool cannot implement the obligation two different ways. This file renders
 * refusals; it does not decide them.
 *
 * THE TERMINAL SHOWS A RECEIPT; THE DATA GOES TO A FILE. Earlier versions of
 * this file rendered the disclosed content to the terminal and tried to make
 * that rendering safe: escaping enumerated character sets, then a category
 * allowlist, then a gutter frame around the content block. Five independent
 * adversarial reviews each found the property still not held, because the
 * property "arbitrary attacker-chosen Unicode rendered faithfully inside a
 * framed region of a terminal" is not reachable: category tests do not separate
 * visible from invisible, escaping wide enough to be safe destroys the text an
 * owner came to read, and a terminal WRAPS, so content long enough to fill a
 * row lands attacker-chosen text at column zero of the next visual row with no
 * newline involved, defeating any line-oriented frame. So the content block is
 * gone, by owner decision (register id STATE-DISCLOSE-UNATTRIB-01): the human
 * path writes the stored value verbatim to a file this code names, and prints
 * only a bounded, printable-ASCII receipt naming that file. Nothing an entry's
 * author wrote is ever rendered to a terminal, and nothing the terminal does to
 * a byte can change what the owner reads back out of the file.
 */

import { randomBytes } from "node:crypto";
import { chmod, mkdir, open, realpath, unlink } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  UNATTRIBUTED_DISCLOSURE_NOTICE,
  StateStore,
} from "../cognitive/state-store.js";
import {
  discloseUnattributedState,
  UNATTRIBUTED_DISCLOSURE_DELIVERY_OPERATION,
  UNATTRIBUTED_DISCLOSURE_OPERATION,
} from "../cognitive/unattributed-disclosure.js";
import { IdentityManager } from "../cognitive/tools.js";
import { OpaqueNamespaceRegistry } from "../agent-native/safety-base.js";
import { loadConfig } from "../config.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { AuditLog } from "../operational/audit-log.js";
import type { ApprovalChannel } from "../principal-policy/approval-channel.js";
import { BaselineTracker } from "../principal-policy/baseline.js";
import { ApprovalGate } from "../principal-policy/gate.js";
import { loadPrincipalPolicy } from "../principal-policy/loader.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
} from "../principal-policy/types.js";
import { verifyDirectoryCustodyWithinBase } from "../storage/custody-fs.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { consumeFlagValue, flagValue } from "./argv.js";

/**
 * Maximum RENDERED length of one untrusted metadata value on the receipt, in
 * code points, all of which are printable ASCII after escaping.
 *
 * Derivation: the receipt's metadata values are attacker-chosen (they come out
 * of an entry whose signature did not verify, or from the caller), and a long
 * enough value wraps the terminal row, landing lookalike text at column zero of
 * the next visual row where it reads as a new line this command printed.
 * Truncation bounds that spoof surface to one value's worth of visible ASCII;
 * 120 covers every legitimate identifier and timestamp this surface renders
 * (the longest code-chosen label plus a UUID-sized value is under 90) while
 * staying under the 32 rows a 4-row-per-value wrap would need to bury the
 * notice on an 80-column terminal. The full value is always available
 * untruncated in the content file / `--json` channel.
 *
 * HONEST RESIDUAL BOUND, recorded here because withdrawing a claim is not the
 * same as fixing it: a value at or under this limit can still wrap on a
 * terminal narrower than the limit, so a lookalike line at column zero is
 * bounded, not impossible. What truncation plus the ASCII-only escaping DOES
 * guarantee: the spoof is at most this many visible characters, it cannot move
 * the cursor, and it cannot be invisible.
 */
const METADATA_VALUE_MAX_RENDERED_CODE_POINTS = 120;

/** Appended (by this code, never by a value) when truncation was applied. */
const METADATA_TRUNCATION_MARKER = "...(truncated)";

/**
 * ASCII-ONLY, AND COMPLETE BY CONSTRUCTION. Every string this command prints
 * except its own labels is chosen by whoever wrote a record whose signature did
 * not verify, or supplied by the caller. Written raw to a terminal such a
 * string does not display as itself: some code points move the cursor over
 * lines already printed, some reorder the display of surrounding text, and
 * thousands render as nothing at all. Earlier rounds tried a denylist, then a
 * Unicode-category allowlist; independent reviews found thousands of uncovered
 * code points in the first and invisible non-`C`-category code points
 * (variation selectors, fillers, combining marks) in the second. A category
 * test does not separate visible from invisible, so no category test appears
 * here: the emitted set is printable ASCII 0x20-0x7E and nothing else, a set
 * that does not grow when Unicode does.
 */

/** Space through `~`: the printable ASCII range. */
function isPrintableAscii(code: number): boolean {
  return code >= 0x20 && code <= 0x7e;
}

/**
 * The escape for a single code point of untrusted input. INJECTIVITY INVARIANT
 * (enforced by the backslash arm): every escape sequence begins with a
 * backslash and no literal backslash survives unescaped, so a rendering
 * decodes to exactly one input - a stored ESC (`\x1b`) and the four literal
 * characters `\`, `x`, `1`, `b` (`\\x1b`) render differently. Without the
 * self-escape the two were identical on screen, and the display could not say
 * which was stored.
 */
function escapeUntrustedCodePoint(ch: string, code: number): string {
  if (ch === "\\") return "\\\\";
  if (isPrintableAscii(code)) return ch;
  return code <= 0xff
    ? `\\x${code.toString(16).padStart(2, "0")}`
    : `\\u{${code.toString(16)}}`;
}

/**
 * Emit `raw` with every code point escaped into the printable-ASCII set,
 * unbounded. Used only where the input is OS- or code-originated text that is
 * not attacker metadata (a filesystem error message) but must still never
 * carry a non-ASCII byte to the terminal; attacker-influenced values go
 * through `renderUntrustedMetadata`, which also truncates.
 */
function renderUntrusted(raw: string): string {
  let rendered = "";
  for (const ch of raw) {
    rendered += escapeUntrustedCodePoint(ch, ch.codePointAt(0) ?? 0);
  }
  return rendered;
}

/**
 * The faithful display string for a metadata value of unknown runtime type.
 * Stored records are parsed from JSON and CAST without runtime field
 * validation, so a field typed `string` or `number` can arrive as an object or
 * an array; `String()` on those prints `[object Object]` and discards the
 * value, which an independent review flagged as lossy on the one surface whose
 * job is fidelity. JSON serialization carries the actual value instead. The
 * `undefined` fallback exists because `JSON.stringify` returns `undefined` for
 * values JSON cannot represent; `String()` is then the last resort and is
 * labelled honest by being reachable only off the JSON path.
 */
function metadataDisplayString(value: unknown): string {
  if (typeof value === "string") return value;
  const json = JSON.stringify(value);
  return json === undefined ? String(value) : json;
}

/** Code-chosen placeholder for a stored value no renderer can display. */
const UNRENDERABLE_VALUE_PLACEHOLDER = "(unrenderable value)";

/**
 * Render one untrusted metadata VALUE for the receipt: faithful display
 * string, ASCII-only injective escaping, then truncation at
 * `METADATA_VALUE_MAX_RENDERED_CODE_POINTS` with an explicit marker.
 * Truncation cuts only at whole-escape-sequence boundaries (the loop appends
 * per-code-point chunks), so what IS shown still decodes unambiguously.
 *
 * TOTALITY INVARIANT: this function must return for ARBITRARY stored JSON and
 * never throw. `JSON.stringify` recurses, so a deeply nested but valid stored
 * value throws RangeError before any truncation can bound it; uncaught, that
 * throw escaped mid-receipt, suppressed the file-path line, and was
 * misreported as a fortress unlock failure. A value that defeats
 * serialization renders as a code-chosen placeholder instead.
 */
function renderUntrustedMetadata(value: unknown): string {
  let raw: string;
  try {
    raw = metadataDisplayString(value);
  } catch {
    return UNRENDERABLE_VALUE_PLACEHOLDER;
  }
  let rendered = "";
  let emitted = 0;
  for (const ch of raw) {
    const chunk = escapeUntrustedCodePoint(ch, ch.codePointAt(0) ?? 0);
    // Chunks are pure ASCII, so `.length` is the emitted code-point count.
    if (emitted + chunk.length > METADATA_VALUE_MAX_RENDERED_CODE_POINTS) {
      return rendered + METADATA_TRUNCATION_MARKER;
    }
    rendered += chunk;
    emitted += chunk.length;
  }
  return rendered;
}

/**
 * The exact bytes the disclosure content file carries, exported for direct
 * test coverage of the non-string arm, which no currently persisted shape
 * reaches end to end (the store decodes content through `bytesToString`, so it
 * arrives as a string today; the arm guards the same cast-without-validation
 * class every other field on the record has already exhibited).
 *
 * FIDELITY INVARIANT: the file carries the stored value byte-for-byte when it
 * is a string, or its exact `JSON.stringify(value, null, 2)` serialization
 * when it is not; no display encoding, escaping, or truncation is ever applied
 * to it. A non-string value with no JSON serialization throws rather than
 * degrading to a lossy `String()` coercion - failing loudly is the safe
 * direction, printing something that is not the value is not.
 */
export function disclosureFileBody(content: unknown): {
  body: string;
  storedValueWasString: boolean;
} {
  if (typeof content === "string") {
    return { body: content, storedValueWasString: true };
  }
  const json = JSON.stringify(content, null, 2);
  if (json === undefined) {
    throw new Error(
      "the stored value is not a string and has no JSON serialization; refusing to write a lossy coercion"
    );
  }
  return { body: json, storedValueWasString: false };
}

export interface StateDiscloseCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  /** Test seam. Absent uses the interactive terminal prompt. */
  approvalChannel?: ApprovalChannel;
  /**
   * Test seam for the content-file name derivation. Absent uses the host
   * clock and fresh randomness; the derivation itself never changes.
   */
  fileNameSeam?: { readonly now: Date; readonly randomHex: string };
  /**
   * Test seam for the FILL step only, after the content file has been
   * created. Absent writes through the real handle.
   *
   * It exists because the behaviour that matters here cannot be produced in
   * process: a genuine ENOSPC, EIO, or late close failure arrives after the
   * advertised path is already created, and the property to prove is that the
   * path never keeps partial plaintext. The seam replaces one call and
   * nothing else, so the creation, the removal, and the reporting under test
   * are all the shipped ones.
   */
  contentWriteSeam?: (body: string) => Promise<void>;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

/**
 * Write `text` and WAIT for the stream to say whether it worked.
 *
 * A bare `stream.write(text)` inside a `try` observes only a SYNCHRONOUS
 * throw, which is the failure mode a real stdout almost never has. A broken
 * pipe (the operator closes the pager, the consumer exits) surfaces through
 * the write CALLBACK or as an `error` EVENT, both after `write()` has already
 * returned, so a synchronous guard reports success on a receipt nobody
 * received. Both asynchronous routes are observed here because the caller's
 * rollback decision depends on knowing the receipt was delivered.
 *
 * The error listener is detached one turn LATE, on purpose: Node commonly
 * delivers the callback error first and then emits `error` on the same
 * stream, and a stream with no `error` listener throws that as an uncaught
 * exception. Staying attached through the following immediate absorbs the
 * duplicate without permanently muting the stream.
 *
 * HONEST BOUND: this observes a synchronous throw, a callback error, and an
 * `error` event raised while the write is in flight. A failure the OS reports
 * only after the callback has already succeeded cannot be seen from here; in
 * that case the receipt did reach the stream and retaining the file is the
 * correct outcome anyway.
 */
async function writeAwaitingCompletion(
  stream: Writable,
  text: string,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const onError = (error: Error): void => {
      if (settled) return;
      settled = true;
      setImmediate(() => stream.off("error", onError));
      reject(error);
    };
    const settle = (error?: Error | null): void => {
      if (settled) return;
      settled = true;
      setImmediate(() => stream.off("error", onError));
      if (error) reject(error);
      else resolve();
    };
    stream.on("error", onError);
    try {
      stream.write(text, settle);
    } catch (error) {
      settle(error as Error);
    }
  });
}

/**
 * Interactive approval channel for a Tier-1 disclosure run from the operator's
 * own terminal. Mirrors `CliPromptApprovalChannel` in `cli/file-grant.ts`; the
 * duplication is two short classes over one shared `ApprovalChannel` interface,
 * and both fail closed to denial off a TTY.
 *
 * The streams are injectable (defaulting to the process's own stdin/stderr)
 * and the class is exported, so the REAL prompt path - including the escaping
 * of the context values the operator reads before approving - has an
 * executing test rather than being replaced by a test double everywhere.
 */
export class CliPromptApprovalChannel implements ApprovalChannel {
  private readonly input: NodeJS.ReadableStream & { isTTY?: boolean };
  private readonly output: Writable;

  constructor(io?: {
    readonly input?: NodeJS.ReadableStream & { isTTY?: boolean };
    readonly output?: Writable;
  }) {
    this.input = io?.input ?? process.stdin;
    this.output = io?.output ?? process.stderr;
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    // THE PROMPT IS THE MOST IMPORTANT SURFACE HERE, not the least. `context`
    // carries the namespace and key the caller asked for, and this text is what
    // the operator reads before granting a Tier-1 approval that no policy file
    // can waive. A value that drives the cursor could rewrite the operation
    // name or the notice printed below, so the human approves one thing while
    // reading another. Every context key and value therefore goes through the
    // bounded ASCII-only metadata renderer.
    const contextLines = Object.entries(request.context)
      .map(
        ([k, v]) =>
          `  ${renderUntrustedMetadata(k)}: ${renderUntrustedMetadata(v)}`,
      )
      .join("\n");
    write(
      this.output,
      "\nSanctuary: Tier-1 approval required\n" +
        `  Operation: ${request.operation}\n` +
        `  Reason:    ${request.reason}\n` +
        "  Details:\n" +
        contextLines +
        "\n\n" +
        UNATTRIBUTED_DISCLOSURE_NOTICE +
        "\n",
    );

    if (!this.input.isTTY) {
      return {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "stderr:non-interactive",
      };
    }

    const rl = createInterface({ input: this.input, output: this.output });
    try {
      const answer = await rl.question(
        "Disclose this entry WITHOUT attribution? [y/N] ",
      );
      const approved = /^y(es)?$/i.test(answer.trim());
      return {
        decision: approved ? "approve" : "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };
    } finally {
      rl.close();
    }
  }
}

function printHelp(out: Writable): void {
  write(
    out,
    "Usage: sanctuary state_disclose_unattributed --namespace <ns> --key <key> [options]\n\n" +
      "Discloses the content of one state entry whose writer this fortress cannot\n" +
      "establish. Tier 1: requires an interactive approval that no policy file can\n" +
      "waive, and every invocation that reaches the disclosure operation is audited\n" +
      "with the namespace and the key. A request refused on its arguments before the\n" +
      "fortress is opened (--json to a terminal, a missing flag) is refused before any\n" +
      "audit log exists; a declined approval is recorded by the approval gate under its\n" +
      "own operation, which binds an arguments hash rather than the namespace and key.\n\n" +
      "The content is never written to the terminal. It is written verbatim to a\n" +
      "new file under <fortress>/disclosures/ and the terminal prints a receipt\n" +
      "naming that file.\n\n" +
      "This is NOT a verified read. If the writer CAN be established the command\n" +
      "refuses and points you at `sanctuary state read`-equivalent surfaces, because\n" +
      "restoring the writer identity is the real remedy and it restores verification\n" +
      "instead of stepping around it.\n\n" +
      "Options:\n" +
      "  --namespace <ns>   Required. Namespace of the entry.\n" +
      "  --key <key>        Required. Key within the namespace.\n" +
      "  --fortress <path>  Fortress path (default: the configured storage path).\n" +
      "  --passphrase <p>   Custody material; SANCTUARY_PASSPHRASE or\n" +
      "                     SANCTUARY_RECOVERY_KEY are the preferred sources.\n" +
      "  --json             Emit the disclosure verbatim as JSON. Refused when\n" +
      "                     stdout is a terminal; redirect to a file or pipe it.\n" +
      "  --help, -h         Show this help.\n",
  );
}

export async function runStateDiscloseUnattributedCommand(
  args: StateDiscloseCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  const argv = args.argv;

  if (argv.includes("--help") || argv.includes("-h")) {
    printHelp(out);
    return 0;
  }

  const namespace = flagValue(argv, "--namespace");
  const key = flagValue(argv, "--key");
  if (!namespace || !key) {
    write(err, "Error: --namespace and --key are required.\n");
    return 2;
  }
  const json = argv.includes("--json");
  // `--json` IS a data channel: its payload goes out verbatim, because
  // escaping serialized JSON corrupts it for the program reading it (an
  // earlier round ran the terminal encoder over it and produced escape forms
  // `JSON.parse` rejects). Verbatim bytes must therefore never reach a
  // terminal, so a TTY stdout refuses HERE, before the Tier-1 prompt, rather
  // than choosing between an unsafe write and a corrupted one afterwards.
  if (json && (out as { isTTY?: boolean }).isTTY === true) {
    write(
      err,
      "Error: --json emits the disclosure verbatim and stdout is a terminal; redirect to a file or pipe it.\n",
    );
    return 2;
  }

  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // disclosure runs are a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `Error: ${consumedFortress.error}\n`);
    return 2;
  }
  if (consumedFortress.value !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = consumedFortress.value;
  }
  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: sanctuary state_disclose_unattributed requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n",
    );
    return 1;
  }

  let masterKey: Uint8Array | undefined;
  let identityEncKey: Uint8Array | undefined;
  try {
    const config = await loadConfig();
    await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
    const storage = new FilesystemStorage(join(config.storage_path, "state"));
    masterKey = await resolveCliMasterKey(storage, {
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      storagePathHint: config.storage_path,
    });

    const identityManager = new IdentityManager(storage, masterKey);
    const loadResult = await identityManager.load();
    const primary = identityManager.getDefault();
    if (loadResult.loaded === 0 || !primary) {
      write(err, "Error: no usable identity in this fortress.\n");
      return 1;
    }
    identityEncKey = derivePurposeKey(masterKey, "identity-encryption");

    const stateStore = new StateStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);
    const gate = new ApprovalGate(
      await loadPrincipalPolicy(config.storage_path),
      new BaselineTracker(storage, masterKey),
      args.approvalChannel ?? new CliPromptApprovalChannel(),
      auditLog,
    );

    // The gate resolves Tier 1 from the operation NAME against the same
    // non-relaxable set the MCP router uses, so a hand-authored policy that
    // lists this operation under tier3_always_allow still lands here.
    const decision = await gate.evaluate(UNATTRIBUTED_DISCLOSURE_OPERATION, {
      // This operator-only CLI has no acting agent principal. Keeping the field
      // explicit prevents a missing value from being mistaken for an inferred one.
      agent_id: null,
      namespace,
      key,
    });
    if (!decision.allowed) {
      write(err, "Denied: unattributed disclosure was not approved.\n");
      return 1;
    }

    const outcome = await discloseUnattributedState({
      auditLog,
      stateStore,
      // A FRESH, EMPTY REGISTRY AND NO SESSION BINDING, on purpose. An opaque
      // `mem_*` handle is issued to a live agent session inside a running MCP
      // server; this process is the operator's own out-of-band presence and
      // holds no such session, so it owns no handle and every `mem_*` namespace
      // refuses here. Fail-closed, and the same code path the MCP tool takes
      // rather than a CLI-shaped approximation of it.
      namespaceRegistry: new OpaqueNamespaceRegistry(),
      namespace,
      key,
      identityId: primary.identity_id,
      ...(decision.approval_audit_id
        ? { approvalAuditId: decision.approval_audit_id }
        : {}),
    });

    if (outcome.status === "refused_namespace_reserved") {
      write(
        err,
        `Refused: namespace "${renderUntrustedMetadata(namespace)}" is reserved for internal ` +
          `use (prefix: ${renderUntrustedMetadata(outcome.reservedPrefix)}). This surface\n` +
          "does not disclose from reserved namespaces.\n",
      );
      return 1;
    }
    if (outcome.status === "refused_namespace_unavailable") {
      write(
        err,
        `Refused: namespace "${renderUntrustedMetadata(namespace)}" is not available here.\n`,
      );
      return 1;
    }
    if (outcome.status === "not_found") {
      write(
        err,
        `Not found: ${renderUntrustedMetadata(namespace)}/${renderUntrustedMetadata(key)}\n`,
      );
      return 1;
    }
    if (outcome.status === "refused_writer_is_establishable") {
      write(
        err,
        "Refused: the writer of this entry CAN be established, so the ordinary\n" +
          "verified read returns it and this surface does not apply. Read it normally.\n",
      );
      return 1;
    }
    if (outcome.status === "refused_verification") {
      write(
        err,
        `Refused: state verification failed (${renderUntrustedMetadata(outcome.classification)}).\n`,
      );
      return 1;
    }

    const disclosure = outcome.disclosure;

    /**
     * Record what happened to the DELIVERY of this disclosure.
     *
     * The shared operation's terminal row says an entry was read. It cannot
     * say whether the operator received it, because the transport is what
     * delivers: a file that cannot be written, a receipt that never reaches
     * the terminal, and a rollback that could not remove the plaintext are all
     * outcomes that happen after the read succeeded. Without a row here the
     * durable history reads success while the command told the operator it
     * failed, and, worse, while plaintext may still be sitting on their disk.
     * Critical because it is the only durable answer to "did this content
     * actually leave the fortress".
     */
    const auditDelivery = async (
      deliveryOutcome: string,
      result: "success" | "failure",
      extra?: Record<string, unknown>,
    ): Promise<void> => {
      try {
        await auditLog.appendCritical({
          layer: "l1",
          operation: UNATTRIBUTED_DISCLOSURE_DELIVERY_OPERATION,
          identity_id: primary.identity_id,
          result,
          details: {
            namespace,
            key,
            delivery_outcome: deliveryOutcome,
            ...extra,
          },
        });
      } catch {
        // The delivery row itself could not be persisted. Say so here rather
        // than letting it fall to the outer handler, which would report a
        // storage fault as a fortress unlock failure: a false explanation of a
        // real fault, on the one surface whose job is telling the truth.
        write(
          err,
          "Warning: the disclosure delivery audit record could not be written.\n",
        );
      }
    };

    if (json) {
      // Verbatim, and only here: the TTY refusal above already established
      // that a program, not a terminal, is reading this stream. The
      // serialization can itself fail on a deeply nested stored value, and
      // that failure must be named as what it is rather than falling through
      // to the generic unlock diagnosis below.
      let payload: string;
      try {
        payload = JSON.stringify(disclosure);
      } catch {
        await auditDelivery("json_serialization_failed", "failure");
        write(
          err,
          "Error: could not serialize the disclosure as JSON; a stored field defeats serialization. Use the human path, which writes the content to a file.\n",
        );
        return 1;
      }
      // THE SAME COMPLETION-OBSERVING WRITE THE RECEIPT USES, and for a
      // sharper reason: `--json` writes to a redirected file or a pipe, which
      // is precisely where a broken pipe happens. A bare `write()` followed by
      // an unconditional success row records "delivered" for bytes the
      // consumer never received, which is the one thing an audit log must not
      // do. The terminal row is derived from the write's OUTCOME, never
      // assumed from having called it.
      try {
        await writeAwaitingCompletion(out, payload + "\n");
      } catch {
        // INCOMPLETE, NOT EMPTY, and the distinction is the whole report. A
        // pipe accepts bytes and then breaks, so a rejected write proves the
        // stream stopped part way; it never proves the consumer got nothing.
        // Saying "nothing was received" would point the operator away from a
        // truncated fragment that is really sitting in their file or their
        // consumer's buffer, which is the thing they have to go and check.
        await auditDelivery("json_delivery_incomplete", "failure");
        write(
          err,
          "Error: the disclosure was not fully delivered to stdout; the stream failed part way, " +
            "so any output that did arrive is an incomplete fragment and must not be parsed or " +
            "trusted as a complete document. Discard it and re-run with a writable destination.\n",
        );
        return 3;
      }
      await auditDelivery("delivered_json", "success");
    } else {
      // ORDER OF OPERATIONS, and why: the receipt is composed IN FULL before
      // the content file is written and before any byte reaches the terminal,
      // and it is then emitted as one write. Receipt rendering must be TOTAL
      // over arbitrary stored JSON (every untrusted field goes through the
      // total metadata renderer), and composing first makes the failure
      // geometry safe in both directions: a render fault can never leave a
      // partial receipt with the file already on disk and no line saying
      // where, and a file-write fault fails the command loudly before the
      // terminal has claimed anything happened. Printing the content as a
      // fallback in either case would be the silent downgrade to the exact
      // behavior this design removed (AGENTS.md MUST-NEVER #5).
      let contentFilePath: string;
      let fileBody: { body: string; storedValueWasString: boolean };
      try {
        // THE STORAGE ROOT IS CANONICALIZED FIRST, and everything downstream
        // uses the canonical path. An operator whose fortress path is itself a
        // symlink (a fortress on another volume reached through a link in the
        // home directory) is an ordinary, legitimate setup, and the no-follow
        // verifier below includes its BASE in the chain it refuses symlinks
        // on. Verifying against the un-resolved root would therefore lock that
        // operator out of their own data, which is a worse outcome than the
        // attack being defended against. Resolving once and using the result
        // everywhere also means the custody check and the write are provably
        // about the same directory rather than two spellings of it.
        const canonicalStoragePath = await realpath(config.storage_path);
        const disclosuresDir = join(canonicalStoragePath, "disclosures");
        await mkdir(disclosuresDir, { recursive: true, mode: 0o700 });
        // NO-FOLLOW CUSTODY BEFORE ANY MODE CHANGE OR WRITE: `chmod` and a
        // path-based file write both FOLLOW a symlink, so a pre-positioned
        // `disclosures -> elsewhere` link would redirect the mode change and
        // the plaintext disclosure onto an external target. The shared
        // custody verifier (`storage/custody-fs`, the same machinery the
        // fortress custody paths use) lstats the leaf and refuses a symlink
        // or non-directory; the refusal is loud with no fallback.
        //
        // HONEST BOUND, recorded because the verifier documents it
        // (`custody-fs.ts`, `openDirectoryCustodyWithinBase`): the check and
        // the use are two path-based syscalls, and Node exposes no
        // `openat`-bound write to fuse them. This refuses a PRE-POSITIONED
        // link and any statically hostile shape; it does not prevent a
        // concurrent same-uid swap of `disclosures` between this check and
        // the write below. That residual is inside the operator's own storage
        // path, where a same-uid attacker already holds the fortress.
        await verifyDirectoryCustodyWithinBase(
          disclosuresDir,
          canonicalStoragePath,
        );
        // `mkdir`'s mode applies only when it CREATES the directory; a
        // pre-existing disclosures directory keeps whatever mode it had, so
        // operator-only access is ENFORCED on every run rather than assumed
        // from creation.
        await chmod(disclosuresDir, 0o700);
        // The filename is derived by THIS CODE alone. `namespace` and `key`
        // are attacker-influenced and never reach the path: a stored or
        // caller-chosen string in a filename is filesystem injection
        // (separators, `..`, device names), so the name is a timestamp plus
        // randomness, both chosen here.
        const now = args.fileNameSeam?.now ?? new Date();
        // 3 random bytes hex-encoded = the 6 hex characters in the name.
        const randomHex =
          args.fileNameSeam?.randomHex ?? randomBytes(3).toString("hex");
        // ISO-8601 basic form: strip `-`/`:` and fractional seconds from the
        // extended form, e.g. 20260819T031500Z.
        const timestamp = now
          .toISOString()
          .replace(/[-:]/g, "")
          .replace(/\.\d+/, "");
        contentFilePath = join(
          disclosuresDir,
          `disclosure-${timestamp}-${randomHex}.txt`,
        );
        fileBody = disclosureFileBody(disclosure.unattributed_content);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        await auditDelivery("prepare_failed", "failure");
        write(
          err,
          "Error: could not prepare the disclosure content file: " +
            `${renderUntrusted(message)}\n` +
            "The disclosure was not completed and no content was printed.\n",
        );
        return 1;
      }

      // THE RECEIPT, composed whole. The banner leads and repeats at the end,
      // so an operator who scrolls still sees it. Every value on it is either
      // a label this code chose, an attacker-influenced value rendered through
      // the bounded, total, ASCII-only metadata encoder, or the content-file
      // path. The path is operator-config-derived plus the code-chosen
      // filename, so it is escaped (the whole receipt stays printable ASCII
      // even under a non-ASCII storage path) but deliberately never
      // truncated: a shortened path names no file. TOTALITY INVARIANT: no
      // expression below may throw on any stored value; a render failure may
      // never suppress the file-path line or misreport the disclosure.
      const receipt =
        `\n${UNATTRIBUTED_DISCLOSURE_NOTICE}\n\n` +
        `namespace: ${renderUntrustedMetadata(disclosure.namespace)}\n` +
        `key:       ${renderUntrustedMetadata(disclosure.key)}\n` +
        // `version` IS attacker-controlled, despite its `number` type. The
        // stored entry is parsed from legacy JSON and cast to `StateEntry`
        // without runtime field validation, so `ver` can be any JSON value a
        // writer put there. The metadata renderer encodes it, carries a
        // faithful JSON display of a non-primitive, and is total, so nothing
        // here trusts the type.
        `version:   ${renderUntrustedMetadata(disclosure.version)}\n` +
        // `writer` is the one field this code chooses rather than reads: a
        // single-inhabitant literal set by the disclosure path itself.
        `writer:    ${disclosure.writer}\n` +
        `claimed_written_at: ${
          disclosure.claimed_written_at === undefined
            ? "(none recorded)"
            : renderUntrustedMetadata(disclosure.claimed_written_at)
        }\n` +
        // The identity to restore, printed so the remedy this command
        // advertises on every path names something the operator can act on.
        // Labelled UNVERIFIED at the point of display, not only in the field
        // name: this string comes out of an entry whose signature did not
        // verify, so whoever wrote the entry chose it. It is a lead to check,
        // never attribution.
        "claimed writer id (UNVERIFIED, from the entry itself): " +
        `${
          disclosure.claimed_writer_id === undefined
            ? "(none recorded)"
            : renderUntrustedMetadata(disclosure.claimed_writer_id)
        }\n` +
        `\ncontent written to: ${renderUntrusted(contentFilePath)}\n` +
        (fileBody.storedValueWasString
          ? ""
          : "note: the stored value was not a string; the file carries its exact JSON serialization.\n") +
        `\n${UNATTRIBUTED_DISCLOSURE_NOTICE}\n`;

      // CLAIMING THE PATH AND FILLING IT ARE TWO STEPS, on purpose. A single
      // `writeFile(path, {flag:"wx"})` conflates two failures that call for
      // opposite responses: a refusal to CLAIM the pathname (something is
      // already there, and that something is an earlier disclosure this run
      // must never delete) and a failure while FILLING the file this run just
      // created (which can leave partial plaintext at the advertised path and
      // must be cleaned up). Opening first makes `created` the discriminator.
      //
      // `wx` still carries the no-overwrite guarantee: the open refuses an
      // existing file rather than truncating it.
      let handle: FileHandle | undefined;
      let created = false;
      try {
        handle = await open(contentFilePath, "wx", 0o600);
        created = true;
        // FIDELITY INVARIANT AT THE WRITE SITE: the file carries the stored
        // value byte-for-byte (or its exact JSON serialization when the stored
        // value was not a string); no display encoding is ever applied to it.
        await (args.contentWriteSeam
          ? args.contentWriteSeam(fileBody.body)
          : handle.writeFile(fileBody.body));
        // Closed explicitly rather than left to the runtime, because a close
        // is where a deferred write error surfaces; awaiting it here puts that
        // failure inside this handler instead of after the receipt is printed.
        await handle.close();
        handle = undefined;
      } catch (error) {
        // The OS/error message is code- or kernel-originated, not attacker
        // metadata, but it still goes through the unbounded ASCII escape so
        // no path this command prints can carry a raw non-ASCII byte.
        const message = error instanceof Error ? error.message : String(error);
        await handle?.close().catch(() => undefined);
        if (!created) {
          // This run never owned that pathname. Whatever occupies it belongs
          // to an earlier disclosure, so it is reported and left alone;
          // removing it here would destroy content the operator has not read.
          await auditDelivery("file_write_failed", "failure", {
            content_file: contentFilePath,
          });
          write(
            err,
            "Error: could not write the disclosure content file: " +
              `${renderUntrusted(message)}\n` +
              "The disclosure was not completed and no content was printed.\n",
          );
          return 1;
        }
        // This run created the file, so it may now hold a PARTIAL copy of the
        // plaintext under the advertised name. Same rollback contract the
        // receipt path uses: remove it, and report removal and residue
        // differently, because only one of those two is something the
        // operator has to go and act on.
        let removed = true;
        try {
          await unlink(contentFilePath);
        } catch {
          removed = false;
        }
        await auditDelivery(
          removed
            ? "file_write_failed_partial_removed"
            : "file_write_failed_file_may_remain",
          "failure",
          { content_file: contentFilePath },
        );
        write(
          err,
          "Error: could not write the disclosure content file: " +
            `${renderUntrusted(message)}\n` +
            (removed
              ? "The partially written file was removed, no content was printed, and the disclosure was not completed.\n"
              : "The partially written file could NOT be removed. It remains at " +
                `${renderUntrusted(contentFilePath)} and may contain unattributed plaintext; ` +
                "remove it manually. The disclosure was not completed and no content was printed.\n"),
        );
        return 1;
      }
      // One write, after the file exists: the receipt the operator sees always
      // names a file that is really there.
      try {
        await writeAwaitingCompletion(out, receipt);
      } catch {
        // ROLLBACK INVARIANT: no disclosure file may outlive a run whose
        // receipt never named it; the operator either gets both or neither. A
        // receipt that failed to reach the terminal leaves a plaintext file on
        // disk the operator does not know exists, so the file is removed and
        // the failure is reported on stderr with its own exit status, distinct
        // from the unlock-failure (1) and usage (2) paths, so a wrapper can
        // tell "re-run" from "wrong credentials".
        let removed = true;
        try {
          await unlink(contentFilePath);
        } catch {
          removed = false;
        }
        // THE TWO OUTCOMES ARE REPORTED DIFFERENTLY, and that is the point. A
        // swallowed unlink failure under a message saying the file "was
        // removed" tells the operator the opposite of the truth about a
        // plaintext file on their disk, and it is the one case where they
        // must act. When the removal fails the path is named (escaped, like
        // every other path this command prints) and the message says so.
        // The rollback outcome is part of the durable record, not only of the
        // message: "the plaintext may still be there, at this path" is the one
        // fact an operator reading the log later has to be able to find.
        await auditDelivery(
          removed
            ? "receipt_undelivered_file_removed"
            : "receipt_undelivered_file_may_remain",
          "failure",
          { content_file: contentFilePath },
        );
        write(
          err,
          removed
            ? "Error: the receipt could not be delivered; the disclosure file was removed; re-run the command.\n"
            : "Error: the receipt could not be delivered and the disclosure file could NOT be removed. " +
                `It remains at ${renderUntrusted(contentFilePath)} and contains unattributed plaintext; ` +
                "remove it manually, then re-run the command.\n",
        );
        return 3;
      }
      await auditDelivery("delivered", "success", {
        content_file: contentFilePath,
      });
    }
    await auditLog.flush().catch(() => undefined);
    return 0;
  } catch {
    write(err, "Error: could not open or unlock the fortress.\n");
    return 1;
  } finally {
    identityEncKey?.fill(0);
    masterKey?.fill(0);
  }
}
