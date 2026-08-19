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
 * Every string this command prints except its own notice is chosen by whoever
 * wrote the entry, and that entry's signature did NOT verify - which is the
 * entire premise of the command. Written raw to a terminal those bytes are not
 * text: a carriage return followed by `ESC [ 2 A` and `ESC [ 2 K` walks the
 * cursor back over the header and erases it, so the entry's author can replace
 * `writer:    not_established` on the operator's screen with
 * `writer:    established`. The one security statement this surface exists to
 * make would then be made BY the attacker, to the human it is meant to warn.
 *
 * So no untrusted string reaches `out` except through here.
 *
 * Controls become VISIBLE `\xNN` escapes rather than being dropped. An operator
 * must be able to see that a field carried something strange; silently deleting
 * it trades one presentation lie for a quieter one.
 *
 * `allowLineBreaks` is for the content block alone, where `\n` and `\t` are
 * ordinary text the operator asked to read. ESC and CR stay escaped even there:
 * neither is needed to display text, and both are what drive a cursor.
 *
 * C1 (0x80-0x9f) is escaped too. 0x9b is CSI, and a terminal that is not in
 * UTF-8 mode will act on it exactly as it acts on `ESC [`.
 *
 * The `--json` path needs none of this and must NOT be routed through here:
 * `JSON.stringify` already escapes every C0 control, so passing it through
 * would double-escape. Verified against the MCP transport, which renders the
 * same way.
 */
function renderUntrusted(
  raw: string,
  options?: { readonly allowLineBreaks?: boolean },
): string {
  const keepBreaks = options?.allowLineBreaks === true;
  let rendered = "";
  for (const ch of raw) {
    if (keepBreaks && (ch === "\n" || ch === "\t")) {
      rendered += ch;
      continue;
    }
    const code = ch.codePointAt(0) ?? 0;
    // 0x20 = space, the lowest printable; 0x7f = DEL; 0x80-0x9f = C1.
    if (code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f)) {
      rendered += `\\x${code.toString(16).padStart(2, "0")}`;
      continue;
    }
    rendered += ch;
  }
  return rendered;
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
    const contextLines = Object.entries(request.context)
      .map(([k, v]) => `  ${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
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
        `Refused: namespace "${namespace}" is reserved for internal use ` +
          `(prefix: ${outcome.reservedPrefix}). This surface does not disclose\n` +
          "from reserved namespaces.\n",
      );
      return 1;
    }
    if (outcome.status === "refused_namespace_unavailable") {
      write(err, `Refused: namespace "${namespace}" is not available here.\n`);
      return 1;
    }
    if (outcome.status === "not_found") {
      write(err, `Not found: ${namespace}/${key}\n`);
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
      write(out, JSON.stringify(disclosure) + "\n");
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
      write(out, `namespace: ${renderUntrusted(disclosure.namespace)}\n`);
      write(out, `key:       ${renderUntrusted(disclosure.key)}\n`);
      // `version` is a number and `writer` is a single-inhabitant literal we
      // choose, so neither is attacker-controlled.
      write(out, `version:   ${disclosure.version}\n`);
      write(out, `writer:    ${disclosure.writer}\n`);
      write(
        out,
        `claimed_written_at: ${
          disclosure.claimed_written_at === undefined
            ? "(none recorded)"
            : renderUntrusted(disclosure.claimed_written_at)
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
              : renderUntrusted(disclosure.claimed_writer_id)
          }\n`,
      );
      write(out, "\n--- unattributed content ---\n");
      // Line breaks and tabs survive because this is the text the operator
      // asked to read; ESC, CR and the rest do not, because the content sits
      // BETWEEN the two notices and an unescaped cursor sequence here erases
      // the closing one as easily as it erases the header.
      write(
        out,
        `${renderUntrusted(disclosure.unattributed_content, { allowLineBreaks: true })}\n`,
      );
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
