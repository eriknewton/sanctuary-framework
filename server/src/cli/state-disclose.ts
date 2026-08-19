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
 */

import { mkdir } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  UNATTRIBUTED_DISCLOSURE_NOTICE,
  StateStore,
} from "../cognitive/state-store.js";
import {
  discloseUnattributedState,
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
import { FilesystemStorage } from "../storage/filesystem.js";
import { flagValue } from "./argv.js";

/**
 * ALLOWLIST, NOT A DENYLIST, and the switch is the point.
 *
 * Every string this command prints except its own labels is chosen by whoever
 * wrote a record whose signature did not verify, or supplied by the caller.
 * Written raw to a terminal such a string does not display as itself: some code
 * points move the cursor over lines already printed, some reorder the display
 * of surrounding text without changing the bytes, and thousands render as
 * nothing at all.
 *
 * An earlier version escaped an ENUMERATED set: C0, DEL, C1, the bidi
 * formatting characters, the separators, a handful of default-ignorables. A
 * review enumerated what that missed and found 4,157 uncovered
 * `Default_Ignorable_Code_Point` values, 153 uncovered format characters, and a
 * bidi control the list had simply not named. That is the predictable outcome:
 * a denylist over Unicode is a list someone maintains against a standard that
 * keeps growing, and it is wrong the day a new format character is assigned.
 *
 * So the rule is inverted. A code point is emitted only if it is in a set we
 * can defend; everything else becomes a visible escape. Complete by
 * construction rather than by diligence.
 *
 * WHAT IS NOT SOLVED BY THIS, stated because a previous round claimed a
 * property it did not have: a terminal WRAPS. Content long enough to fill a row
 * continues at column zero on the next visual row, so text can appear where a
 * line-oriented frame did not put it, with no newline involved. Nothing this
 * function does prevents that, and the gutter below does not either. The
 * defended property is narrower: the entry's author cannot move the cursor,
 * cannot reorder the display, and cannot emit an invisible character. They can
 * still write something that LOOKS like a label if a row happens to wrap.
 */

/** Space through `~`: the printable ASCII range, minus nothing. */
function isPrintableAscii(code: number): boolean {
  return code >= 0x20 && code <= 0x7e;
}

/**
 * Emit `raw` with every code point outside the safe set replaced by a visible
 * escape.
 *
 * `allowLetters` widens the set to any code point a terminal renders as an
 * ordinary visible glyph, which is what the content block needs: an owner
 * reading their own notes in Japanese or Arabic must see them, not a wall of
 * escapes. It is implemented as a category test rather than a range list, and
 * it deliberately excludes the format (`Cf`), control (`Cc`), unassigned (`Cn`)
 * and private-use (`Co`) categories, which is where every invisible and
 * display-reordering character lives.
 *
 * `allowLineBreaks` permits LF alone, for the content block. TAB is NOT
 * permitted even there: it advances to the next tab stop rather than occupying
 * one cell, so it moves text horizontally by an amount the content chooses.
 */
function renderUntrusted(
  raw: string,
  options?: { readonly allowLineBreaks?: boolean; readonly allowLetters?: boolean },
): string {
  let rendered = "";
  for (const ch of raw) {
    const code = ch.codePointAt(0) ?? 0;
    if (options?.allowLineBreaks === true && ch === "\n") {
      rendered += ch;
      continue;
    }
    if (isPrintableAscii(code)) {
      rendered += ch;
      continue;
    }
    if (options?.allowLetters === true && isOrdinaryVisibleGlyph(ch)) {
      rendered += ch;
      continue;
    }
    rendered +=
      code <= 0xff
        ? `\\x${code.toString(16).padStart(2, "0")}`
        : `\\u{${code.toString(16)}}`;
  }
  return rendered;
}

/**
 * Whether a code point is an ordinary visible glyph: a letter, a mark, a
 * number, a punctuation mark, a symbol, or an ordinary space.
 *
 * Defined by what it EXCLUDES, which is the part that matters. `\p{C}` covers
 * control, format, unassigned, private-use and surrogate code points, and that
 * single category is where the entire class of invisible and
 * display-reordering characters lives. `\p{Zl}` and `\p{Zp}` are the line and
 * paragraph separators. `\p{Zs}` is allowed but normalised below, because a
 * space of a different width is still a space an operator cannot measure.
 */
function isOrdinaryVisibleGlyph(ch: string): boolean {
  if (/\p{C}|\p{Zl}|\p{Zp}/u.test(ch)) return false;
  // Any space separator other than U+0020 is rendered as an escape rather than
  // passed through: a narrow or ideographic space is invisible as a difference
  // and is one of the ways two visibly identical values differ in bytes.
  if (/\p{Zs}/u.test(ch)) return ch === " ";
  return true;
}

export interface StateDiscloseCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  /** Test seam. Absent uses the interactive terminal prompt. */
  approvalChannel?: ApprovalChannel;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

/**
 * Interactive approval channel for a Tier-1 disclosure run from the operator's
 * own terminal. Mirrors `CliPromptApprovalChannel` in `cli/file-grant.ts`; the
 * duplication is two short classes over one shared `ApprovalChannel` interface,
 * and both fail closed to denial off a TTY.
 */
class CliPromptApprovalChannel implements ApprovalChannel {
  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    // THE PROMPT IS THE MOST IMPORTANT SURFACE HERE, not the least. `context`
    // carries the namespace and key the caller asked for, and this text is what
    // the operator reads before granting a Tier-1 approval that no policy file
    // can waive. A value that drives the cursor could rewrite the operation
    // name or the notice printed below, so the human approves one thing while
    // reading another. `JSON.stringify` is not sufficient on its own: it
    // escapes C0 controls but passes bidi formatting and U+2028/U+2029 through
    // unchanged.
    const contextLines = Object.entries(request.context)
      .map(
        ([k, v]) =>
          `  ${renderUntrusted(k)}: ` +
          renderUntrusted(typeof v === "string" ? v : JSON.stringify(v)),
      )
      .join("\n");
    write(
      process.stderr,
      "\nSanctuary: Tier-1 approval required\n" +
        `  Operation: ${request.operation}\n` +
        `  Reason:    ${request.reason}\n` +
        "  Details:\n" +
        contextLines +
        "\n\n" +
        UNATTRIBUTED_DISCLOSURE_NOTICE +
        "\n",
    );

    if (!process.stdin.isTTY) {
      return {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "stderr:non-interactive",
      };
    }

    const rl = createInterface({ input: process.stdin, output: process.stderr });
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
      "waive, and every invocation is audited with the namespace and the key.\n\n" +
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
      "  --json             Emit the disclosure as JSON.\n" +
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

  const fortressFlag = flagValue(argv, "--fortress");
  if (fortressFlag) {
    process.env.SANCTUARY_STORAGE_PATH = fortressFlag;
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
        `Refused: namespace "${renderUntrusted(namespace)}" is reserved for internal ` +
          `use (prefix: ${renderUntrusted(outcome.reservedPrefix)}). This surface\n` +
          "does not disclose from reserved namespaces.\n",
      );
      return 1;
    }
    if (outcome.status === "refused_namespace_unavailable") {
      write(
        err,
        `Refused: namespace "${renderUntrusted(namespace)}" is not available here.\n`,
      );
      return 1;
    }
    if (outcome.status === "not_found") {
      write(
        err,
        `Not found: ${renderUntrusted(namespace)}/${renderUntrusted(key)}\n`,
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
        `Refused: state verification failed (${outcome.classification}).\n`,
      );
      return 1;
    }

    const disclosure = outcome.disclosure;
    if (json) {
      // `--json` IS a data channel, and treating it as one was defensible only
      // while nobody checked where it points. It writes to stdout, and stdout
      // is frequently a terminal, so the same values that cannot be trusted in
      // the human path arrive at the same terminal with only
      // `JSON.stringify`'s escaping, which covers C0 and lone surrogates and
      // passes every display-affecting format character through.
      //
      // Resolved by asking rather than assuming: piped or redirected, the
      // bytes are data and go out verbatim, because escaping them would
      // corrupt the value for the program reading it. Attached to a terminal,
      // a human is reading, and the encoder applies.
      const toTerminal = (out as { isTTY?: boolean }).isTTY === true;
      const payload = JSON.stringify(disclosure);
      write(out, (toTerminal ? renderUntrusted(payload) : payload) + "\n");
    } else {
      // The banner is printed BEFORE the content and repeated after it. An
      // operator who scrolls a long value away from the top of the terminal is
      // the ordinary case, and a warning that only the first line carries is a
      // warning most readers of a long entry never see.
      write(out, `\n${UNATTRIBUTED_DISCLOSURE_NOTICE}\n\n`);
      // `namespace` and `key` are caller-chosen; the three `claimed_*`-class
      // fields and the content are chosen by whoever wrote the unverified
      // entry. All of them go through renderUntrusted; see its header for why
      // a raw write here lets the entry's author forge the `writer:` line.
      write(out, `namespace: ${renderUntrusted(String(disclosure.namespace))}\n`);
      write(out, `key:       ${renderUntrusted(String(disclosure.key))}\n`);
      // `version` IS attacker-controlled, despite its `number` type. The stored
      // entry is parsed from legacy JSON and cast to `StateEntry` without
      // runtime field validation, so `ver` can be any JSON value a writer put
      // there, including a string carrying escape sequences. An earlier comment
      // here asserted the opposite and was wrong: the type describes what the
      // code expects, never what the bytes contain. Encode it like any other
      // stored value, and read `String(...)` as the reminder that it may not be
      // a number.
      write(out, `version:   ${renderUntrusted(String(disclosure.version))}\n`);
      // `writer` is the one field this code chooses rather than reads: a
      // single-inhabitant literal set by the disclosure path itself.
      write(out, `writer:    ${disclosure.writer}\n`);
      write(
        out,
        `claimed_written_at: ${
          disclosure.claimed_written_at === undefined
            ? "(none recorded)"
            : renderUntrusted(String(disclosure.claimed_written_at))
        }\n`,
      );
      // The identity to restore, printed so the remedy this command advertises
      // on every path names something the operator can act on. Labelled
      // UNVERIFIED at the point of display, not only in the field name: this
      // string comes out of an entry whose signature did not verify, so whoever
      // wrote the entry chose it. It is a lead to check, never attribution.
      write(
        out,
        "claimed writer id (UNVERIFIED, from the entry itself): " +
          `${
            disclosure.claimed_writer_id === undefined
              ? "(none recorded)"
              : renderUntrusted(String(disclosure.claimed_writer_id))
          }\n`,
      );
      write(out, "\n--- unattributed content ---\n");
      // EVERY CONTENT LINE IS GUTTERED, and the gutter is the delimiter's only
      // defence. Line breaks survive here because this is the text the operator
      // asked to read, and that exemption is exactly what let the content print
      // its own `--- end unattributed content ---` line followed by a forged
      // header: the real delimiter arriving later does not undo what was read.
      // Prefixing each line means anything the content emits appears INSIDE the
      // block, so a forged delimiter reads as `| --- end unattributed content
      // ---` and the ungutted delimiters are unreachable from the content.
      // Escaping LF instead would make ordinary multi-line values unreadable,
      // which is the thing this command exists to provide.
      // The gutter's honest bound, recorded where it is applied: it prefixes
      // LOGICAL lines. A terminal WRAPS, so content long enough to fill a row
      // continues at column zero on the next visual row with no newline
      // involved, and text can appear where a line-oriented frame did not put
      // it. Nothing in-band fixes that. What the encoder above still
      // guarantees is that the content cannot move the cursor, cannot reorder
      // the display, and cannot emit an invisible character; it can only
      // produce visible text that may land in an unexpected column.
      const gutter = "| ";
      // `allowLetters` here and nowhere else: this is the owner's own data and
      // must be readable in any script. The header fields above are
      // identifiers and timestamps, so printable ASCII is the whole of what
      // they legitimately contain.
      //
      // `String(...)` on every stored field, for the same reason `version`
      // needed it: the record is cast from stored JSON with no runtime
      // validation, so a field typed `string` can arrive as a number, an
      // object, or an array. Passing one to a string-only encoder threw, and
      // the throw was caught by the outer handler and reported to the operator
      // as a fortress unlock failure, which is a false explanation of a real
      // fault.
      const body = renderUntrusted(String(disclosure.unattributed_content), {
        allowLineBreaks: true,
        allowLetters: true,
      });
      for (const line of body.split("\n")) {
        write(out, `${gutter}${line}\n`);
      }
      write(out, "--- end unattributed content ---\n\n");
      write(out, `${UNATTRIBUTED_DISCLOSURE_NOTICE}\n`);
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
