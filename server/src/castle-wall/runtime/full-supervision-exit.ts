/** Inputs recorded by a future supervisor before observing the named attempt's exit. */
export interface FullSupervisionExitInput {
  attemptId: string;
  exit: { code: number } | { signal: NodeJS.Signals };
  stopIntent: { kind: "none" } | { kind: "operator" | "lifecycle"; attemptId: string };
  readinessCommitted: boolean;
  completion?: { attemptId: string; cleanup: "ok" | "failed" };
}

/** Integration supplies PR-A's eventual code; this library reserves no new exit code. */
export interface FullSupervisionCodeTable {
  restartable: readonly number[];
  terminal: readonly { code: number; reason: string }[];
  retryable: readonly { code: number; reason: string }[];
}

/** Base daemon parse refusal; must match runDaemon in server/src/cli/castle-wall.ts. */
export const FULL_SUPERVISION_DEFAULT_CODES: FullSupervisionCodeTable = Object.freeze({
  restartable: Object.freeze([]),
  terminal: Object.freeze([Object.freeze({ code: 2, reason: "parse_refusal" })]),
  retryable: Object.freeze([]),
});

/** Completion return codes; must match releaseDaemonMasterSession return in server/src/cli/castle-wall.ts. */
export const FULL_SUPERVISION_COMPLETION_CODES = Object.freeze({ ok: 0, failed: 1 });

/** Each decision retains the evidence supplied by its caller, including readiness. */
export type FullSupervisionExitClassification =
  | { kind: "uncharged_clean" | "uncharged_stop" | "charged_unverified_exit"; decidedBy: FullSupervisionExitInput }
  | { kind: "charged_restart"; reason?: string; decidedBy: FullSupervisionExitInput }
  | { kind: "terminal"; reason: string; decidedBy: FullSupervisionExitInput };

const SIGTERM_NUMBER = 15; // POSIX SIGTERM.
const SIGNAL_EXIT_OFFSET = 128; // Shell convention: signal status = 128 + signal number.

/**
 * Classify an observed exit without IO. Stop intent must have been recorded before
 * exit, and completion must describe this attempt's cleanup. Readiness is evidence,
 * never a prerequisite for an operator's startup stop. Unknown codes are charged.
 * Conflicting injected tables resolve conservatively: terminal precedes restartable.
 */
export function classifyFullSupervisionExit(
  input: FullSupervisionExitInput,
  table: FullSupervisionCodeTable = FULL_SUPERVISION_DEFAULT_CODES,
): FullSupervisionExitClassification {
  const intent = input.stopIntent;
  let stop: "none" | "operator" | "lifecycle";
  switch (intent.kind) {
    case "none": stop = "none"; break;
    case "operator":
    case "lifecycle": stop = intent.attemptId === input.attemptId ? intent.kind : "none"; break;
    default: {
      const unreachable: never = intent;
      void unreachable;
      // Durable caller input can violate the static union; unknown intent never exempts an exit.
      return { kind: "charged_unverified_exit", decidedBy: input };
    }
  }
  const exit = input.exit;
  // A stop request cannot hide a crash; only the enumerated stop shapes qualify.
  const stopShaped = "code" in exit
    ? exit.code === FULL_SUPERVISION_COMPLETION_CODES.ok || exit.code === SIGNAL_EXIT_OFFSET + SIGTERM_NUMBER
    : exit.signal === "SIGTERM" || (exit.signal === "SIGKILL" && stop === "lifecycle");
  // A deterministic non-stop refusal remains terminal even when a stop races it.
  if ("code" in exit && !stopShaped) {
    const terminal = table.terminal.find((row) => row.code === exit.code);
    if (terminal) return { kind: "terminal", reason: terminal.reason, decidedBy: input };
  }
  if (stop !== "none") {
    const matchedCompletion = input.completion?.attemptId === input.attemptId;
    // Status-shaped stops require ok cleanup evidence; signals can precede handler installation.
    const verified = "code" in exit
      ? matchedCompletion && input.completion?.cleanup === "ok"
      : !(matchedCompletion && input.completion?.cleanup === "failed");
    return { kind: stopShaped && verified ? "uncharged_stop" : "charged_unverified_exit", decidedBy: input };
  }
  if ("code" in exit) {
    if (exit.code === FULL_SUPERVISION_COMPLETION_CODES.ok) {
      // Zero alone proves no cleanup: only this attempt's explicit ok completion exempts it.
      const clean = input.completion?.attemptId === input.attemptId && input.completion.cleanup === "ok";
      return { kind: clean ? "uncharged_clean" : "charged_unverified_exit", decidedBy: input };
    }
    const terminal = table.terminal.find((row) => row.code === exit.code);
    if (terminal) return { kind: "terminal", reason: terminal.reason, decidedBy: input };
    const retryable = table.retryable.find((row) => row.code === exit.code);
    if (retryable) return { kind: "charged_restart", reason: retryable.reason, decidedBy: input };
    if (table.restartable.includes(exit.code)) return { kind: "charged_restart", decidedBy: input };
  }
  return { kind: "charged_unverified_exit", decidedBy: input };
}
