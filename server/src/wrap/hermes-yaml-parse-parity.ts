/**
 * Sanctuary Wrap - Hermes config.yaml parse-parity guard
 *
 * The wrap-time Hermes injection edits `~/.hermes/config.yaml` with a
 * hand-rolled LINE-SCANNER (hermes-yaml.ts). A line scanner cannot fully
 * replicate PyYAML, the parser Hermes itself uses, and every fidelity gap
 * is a chance to mis-read the file and edit the wrong thing while wrap
 * reports success (a silent stale-config / secret-drop class; see
 * Review/Sanctuary/PR849_Hermes_YAML_ParseParity_Decision_2026-07-03.md).
 *
 * This module is the safety net. Before the scanner's plan is written, it
 * validates the scanner's VIEW of the file (does a top-level `mcp_servers`
 * block exist, and which entry names live under it) against a REAL parse
 * of the same bytes through PyYAML, run as a one-shot subprocess. If the
 * two disagree on anything the edit depends on, the guard REFUSES and the
 * caller aborts with the file untouched.
 *
 * Ratified posture (Erik, 2026-07-03, Option A): fail CLOSED. If the
 * PyYAML sidecar cannot run at all (python absent, PyYAML not importable,
 * crash, timeout, malformed output), the guard REFUSES to wrap rather than
 * falling through to the un-validated scanner. The guard does NOT claim
 * the scanner is correct; it claims only that the scanner and a real
 * parser agree on the facts this edit depends on, or the edit does not
 * happen.
 *
 * The parser here is deliberately the SAME family Hermes runs: PyYAML in
 * the host's python3, invoked with `yaml.safe_load`. It is NOT the
 * Concordia composition sidecar (that is a long-lived JSON-RPC negotiation
 * process gated on its own venv); this is a stateless, dependency-light
 * one-shot parse.
 *
 * This is a wrap-internal config-injection helper, in the same category as
 * hermes-yaml.ts and claude-code-allowlist.ts, and is likewise not
 * re-exported from wrap/index.ts (see that barrel's header).
 */

import { spawn } from "node:child_process";

import { scannerMcpServersView } from "./hermes-yaml.js";

// -- Types ----------------------------------------------------------------

/**
 * Structured result of a one-shot PyYAML parse of a config.yaml, reduced
 * to the facts the injection edit depends on. Mirrors ScannerMcpServersView
 * so the two can be compared field-by-field.
 */
export interface PyYamlMcpServersView {
  /** True when the real parse found a top-level `mcp_servers` mapping. */
  hasBlock: boolean;
  /**
   * Entry names PyYAML resolves under `mcp_servers`, in the order the real
   * parser yields them (last-wins already applied for duplicate keys, which
   * is exactly the semantic the line scanner cannot see). Empty when the
   * key is absent or maps to an empty/null value.
   */
  entryNames: string[];
}

/**
 * Injectable one-shot command executor, matching the wrap keyring executor
 * shape (exec-result.ts style). Production uses the default python3 runner;
 * tests inject a mock to simulate agreement, disagreement, and the sidecar
 * being unavailable without touching a real interpreter.
 */
export interface SidecarExecResult {
  stdout: string;
  stderr: string;
  /** Process exit code, or null when the process was killed / never ran. */
  code: number | null;
}

export type SidecarExec = (
  command: string,
  args: string[],
  input: string,
  timeoutMs: number
) => Promise<SidecarExecResult>;

export interface ParseParityOptions {
  /** Override the python interpreter (for tests / operator config). */
  pythonPath?: string;
  /** Injectable executor; defaults to a real python3 subprocess runner. */
  exec?: SidecarExec;
  /** Sidecar timeout in ms (default 5000). */
  timeoutMs?: number;
}

/** Why the parity guard refused. Distinguishes the two refusal classes. */
export type ParityRefusalReason =
  /** The scanner's view and the PyYAML parse disagree on the edit facts. */
  | "disagreement"
  /** The PyYAML sidecar could not run / produce a trustworthy parse. */
  | "sidecar-unavailable";

/**
 * Raised when the parse-parity guard refuses to let the scanner edit the
 * file. Callers MUST abort the wrap with the file untouched (never fall
 * through to the un-validated scanner). Carries a `reason` so the caller
 * can print the right operator guidance, and `detail` with a
 * non-secret-bearing explanation (config.yaml carries no secret material,
 * but we still keep the message to structural facts, not file contents).
 */
export class HermesYamlParityRefusedError extends Error {
  readonly reason: ParityRefusalReason;
  readonly detail: string;
  constructor(reason: ParityRefusalReason, detail: string) {
    super(
      reason === "disagreement"
        ? `Hermes config.yaml parse-parity check FAILED: the line-scanner's view ` +
            `disagrees with a real PyYAML parse (${detail}). Refusing to edit so a ` +
            `mis-read cannot silently rewrite the wrong entry.`
        : `Hermes config.yaml parse-parity check could not run its PyYAML validator ` +
            `(${detail}). Refusing to edit: wrap will not rewrite the file without a ` +
            `real parse to check the line-scanner against (fail-closed).`
    );
    this.name = "HermesYamlParityRefusedError";
    this.reason = reason;
    this.detail = detail;
  }
}

// -- PyYAML one-shot parse ------------------------------------------------

/**
 * Python program (stdin -> stdout) that parses the config with PyYAML and
 * prints a canonical JSON summary of the top-level `mcp_servers` mapping.
 *
 * Fail-closed contract encoded here, not just in the TS wrapper:
 *   - PyYAML missing            -> exit 20 (import error)
 *   - unparseable YAML          -> exit 21 (a real parser rejects the file;
 *                                  the scanner must not edit what Hermes
 *                                  itself would refuse to load)
 *   - top-level doc empty/null  -> {"hasBlock": false, "entryNames": []}
 *                                  (an empty, whitespace-only, or
 *                                  comment-only file: the plan's add-key
 *                                  appends a fresh top-level mcp_servers
 *                                  mapping, which is valid; the scanner also
 *                                  sees no block, so they agree and proceed)
 *   - top-level doc not a map   -> exit 23 (a sequence or scalar document:
 *                                  the scanner also sees no top-level
 *                                  mcp_servers block, so it would collapse to
 *                                  hasBlock=false and AGREE, then add-key
 *                                  would append a top-level mcp_servers
 *                                  mapping onto a sequence/scalar document,
 *                                  producing mixed types PyYAML rejects. This
 *                                  distinct signal makes the guard refuse
 *                                  fail-closed instead of silently agreeing)
 *   - mcp_servers absent/null   -> {"hasBlock": false, "entryNames": []}
 *   - mcp_servers not a mapping -> exit 22 (scalar/sequence: a shape the
 *                                  scanner also refuses; surface as a hard
 *                                  parser signal rather than silent block=false)
 *   - ok                        -> exit 0 with the JSON summary
 *
 * Keys are stringified with str() so non-string YAML keys (e.g. an
 * accidental integer key) still surface as names the TS side can compare;
 * PyYAML's last-wins duplicate-key resolution is inherent to the dict it
 * builds, which is precisely the semantic the line scanner cannot see.
 */
const PYYAML_PARSE_PROGRAM = [
  "import sys, json",
  "try:",
  "    import yaml",
  "except Exception:",
  "    sys.exit(20)",
  "raw = sys.stdin.read()",
  "try:",
  "    doc = yaml.safe_load(raw)",
  "except Exception:",
  "    sys.exit(21)",
  "if doc is None:",
  '    print(json.dumps({"hasBlock": False, "entryNames": []}))',
  "    sys.exit(0)",
  "if not isinstance(doc, dict):",
  "    sys.exit(23)",
  '"""find the mcp_servers key exactly (top-level, case-sensitive)"""',
  'block = doc.get("mcp_servers", None)',
  "if block is None:",
  '    print(json.dumps({"hasBlock": False, "entryNames": []}))',
  "    sys.exit(0)",
  "if not isinstance(block, dict):",
  "    sys.exit(22)",
  "names = [str(k) for k in block.keys()]",
  'print(json.dumps({"hasBlock": True, "entryNames": names}))',
  "sys.exit(0)",
].join("\n");

/**
 * Default executor: run python3 with the parse program on stdin, capturing
 * stdout/stderr/exit-code. A spawn failure (ENOENT for a missing
 * interpreter) resolves as code null so the caller treats it as
 * sidecar-unavailable, never as agreement. A timeout kills the process and
 * resolves code null for the same reason.
 */
const defaultSidecarExec: SidecarExec = (command, args, input, timeoutMs) =>
  new Promise<SidecarExecResult>((resolve) => {
    let settled = false;
    const finish = (r: SidecarExecResult) => {
      if (settled) return;
      settled = true;
      resolve(r);
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
    } catch {
      // Synchronous spawn throw (rare): treat as unavailable, fail-closed.
      finish({ stdout: "", stderr: "spawn threw", code: null });
      return;
    }

    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already gone.
      }
      finish({ stdout, stderr: `${stderr}\n[timeout]`, code: null });
    }, timeoutMs);
    // Do not keep the event loop alive on the timer alone.
    if (typeof timer.unref === "function") timer.unref();

    child.stdout?.on("data", (d: Buffer) => {
      stdout += d.toString("utf-8");
    });
    child.stderr?.on("data", (d: Buffer) => {
      stderr += d.toString("utf-8");
    });
    child.on("error", () => {
      clearTimeout(timer);
      // ENOENT (no python) and friends land here: unavailable, fail-closed.
      finish({ stdout, stderr: `${stderr}\n[spawn error]`, code: null });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      finish({ stdout, stderr, code });
    });

    // Feed the config bytes and close stdin.
    try {
      child.stdin?.write(input);
      child.stdin?.end();
    } catch {
      // If stdin already errored, the error/close handler settles it.
    }
  });

/**
 * Distinct exit codes the parse program uses to signal "a real parser
 * refuses this file" versus "the parser could not run at all". Both are
 * fail-closed from wrap's perspective, but the codes let tests and the
 * error detail distinguish them.
 */
const PYYAML_EXIT = {
  IMPORT_MISSING: 20,
  UNPARSEABLE: 21,
  MCP_SERVERS_NOT_A_MAP: 22,
  TOP_LEVEL_NOT_A_MAP: 23,
} as const;

/**
 * Run the PyYAML parse and return its view, or throw
 * HermesYamlParityRefusedError("sidecar-unavailable", ...) when a real,
 * trustworthy parse could not be produced.
 */
async function pyYamlView(
  existingContent: string,
  options: ParseParityOptions
): Promise<PyYamlMcpServersView> {
  const python = options.pythonPath ?? "python3";
  const exec = options.exec ?? defaultSidecarExec;
  const timeoutMs = options.timeoutMs ?? 5000;

  const result = await exec(
    python,
    ["-c", PYYAML_PARSE_PROGRAM],
    existingContent,
    timeoutMs
  );

  if (result.code === null) {
    throw new HermesYamlParityRefusedError(
      "sidecar-unavailable",
      `python3 parser did not run (interpreter '${python}' absent, killed, or timed out)`
    );
  }
  if (result.code === PYYAML_EXIT.IMPORT_MISSING) {
    throw new HermesYamlParityRefusedError(
      "sidecar-unavailable",
      "PyYAML is not importable in the resolved python3; install PyYAML or point wrap at the interpreter Hermes uses"
    );
  }
  if (result.code === PYYAML_EXIT.UNPARSEABLE) {
    throw new HermesYamlParityRefusedError(
      "sidecar-unavailable",
      "PyYAML could not parse config.yaml (a real parser rejects the file); fix the YAML and re-run wrap"
    );
  }
  if (result.code === PYYAML_EXIT.MCP_SERVERS_NOT_A_MAP) {
    // A real parser sees mcp_servers as a scalar/sequence: not a block
    // mapping the scanner may append an entry to. Refuse (fail-closed);
    // the scanner would also refuse these, but we do not trust that here.
    throw new HermesYamlParityRefusedError(
      "sidecar-unavailable",
      "PyYAML reads mcp_servers as a non-mapping value (scalar or sequence); wrap only edits a block mapping"
    );
  }
  if (result.code === PYYAML_EXIT.TOP_LEVEL_NOT_A_MAP) {
    // A real parser sees the WHOLE document as a sequence or scalar (not a
    // mapping). The line scanner sees no top-level mcp_servers block and
    // would collapse to hasBlock=false, AGREEING with the naive block=false
    // this case used to emit; the plan's add-key would then append a
    // top-level `mcp_servers:` mapping onto a sequence/scalar document,
    // producing mixed types PyYAML then rejects (Hermes fails to load) while
    // the same-family post-write scanner check falsely reports success.
    // Surface it as a distinct hard signal and refuse (fail-closed).
    throw new HermesYamlParityRefusedError(
      "sidecar-unavailable",
      "PyYAML reads the whole config.yaml document as a non-mapping value (a top-level sequence or scalar); wrap can only add mcp_servers to a mapping document"
    );
  }
  if (result.code !== 0) {
    throw new HermesYamlParityRefusedError(
      "sidecar-unavailable",
      `python3 parser exited with unexpected code ${result.code}`
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout.trim());
  } catch {
    throw new HermesYamlParityRefusedError(
      "sidecar-unavailable",
      "python3 parser produced output that was not valid JSON"
    );
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof (parsed as { hasBlock?: unknown }).hasBlock !== "boolean" ||
    !Array.isArray((parsed as { entryNames?: unknown }).entryNames) ||
    (parsed as { entryNames: unknown[] }).entryNames.some(
      (n) => typeof n !== "string"
    )
  ) {
    throw new HermesYamlParityRefusedError(
      "sidecar-unavailable",
      "python3 parser output did not match the expected {hasBlock, entryNames} shape"
    );
  }
  const view = parsed as PyYamlMcpServersView;
  return { hasBlock: view.hasBlock, entryNames: view.entryNames };
}

// -- Parity check ---------------------------------------------------------

/**
 * Case-insensitive multiset equality on entry names. The injection keys
 * `sanctuary` case-insensitively (planHermesYamlInjection lowercases before
 * comparing), so parity is about the same NAME SET the edit reasons over,
 * independent of ordering of unrelated keys. We compare as sorted,
 * lowercased multisets: a duplicate the scanner missed (PyYAML last-wins)
 * shows up as a length/multiset mismatch and trips the refusal.
 */
function entryNamesAgree(scanner: string[], real: string[]): boolean {
  if (scanner.length !== real.length) return false;
  const norm = (xs: string[]) =>
    xs.map((x) => x.toLowerCase()).sort();
  const a = norm(scanner);
  const b = norm(real);
  return a.every((x, i) => x === b[i]);
}

/**
 * Validate the line-scanner's view of `existingContent` against a real
 * PyYAML parse. Resolves when they AGREE on the facts the injection edit
 * depends on. Throws HermesYamlParityRefusedError otherwise:
 *
 *   - reason "disagreement"        when the scanner and PyYAML see a
 *                                  different `mcp_servers` presence or a
 *                                  different set of entry names (this is
 *                                  the whole class the guard closes: any
 *                                  YAML form the scanner mis-reads relative
 *                                  to the real parser).
 *   - reason "sidecar-unavailable" when a trustworthy PyYAML parse could
 *                                  not be produced at all (fail-closed).
 *
 * A null `existingContent` (file absent) short-circuits to agreement
 * WITHOUT invoking the sidecar: there are no bytes to mis-parse, the plan
 * only creates a fresh file, and requiring python3 to create a brand-new
 * config would be a needless new dependency on the happy path. The guard's
 * job is to catch mis-reads of EXISTING operator content.
 */
export async function assertHermesYamlParseParity(
  existingContent: string | null,
  options: ParseParityOptions = {}
): Promise<void> {
  if (existingContent === null) return;

  const scanner = scannerMcpServersView(existingContent);

  // An unsupported shape (duplicate key / block sequence / inline flow) is
  // already a hard refusal in planHermesYamlInjection; the parity guard
  // still cross-checks against PyYAML so a shape the scanner FAILED to flag
  // as unsupported (but PyYAML reads differently) also refuses. When the
  // scanner itself flags unsupported, the plan throws first; we let that
  // stand and do not spend a sidecar call.
  if (scanner.unsupported) return;

  const real = await pyYamlView(existingContent, options);

  if (scanner.hasBlock !== real.hasBlock) {
    throw new HermesYamlParityRefusedError(
      "disagreement",
      `line-scanner ${scanner.hasBlock ? "sees" : "does not see"} a top-level ` +
        `mcp_servers block but PyYAML ${real.hasBlock ? "does" : "does not"}`
    );
  }

  if (!entryNamesAgree(scanner.entryNames, real.entryNames)) {
    throw new HermesYamlParityRefusedError(
      "disagreement",
      `line-scanner sees ${scanner.entryNames.length} entr${
        scanner.entryNames.length === 1 ? "y" : "ies"
      } under mcp_servers but PyYAML sees ${real.entryNames.length}`
    );
  }

  // Case-insensitive `sanctuary` collision (P1 fail-open closed 2026-07-03):
  // planHermesYamlInjection matches the existing sanctuary entry
  // case-INSENSITIVELY (name.toLowerCase() === "sanctuary") and replaces only
  // the FIRST match. PyYAML keeps DISTINCT keys for `Sanctuary` and
  // `sanctuary` (they differ as exact-case dict keys), and entryNamesAgree
  // lowercases before comparing, so a config carrying both passes the
  // multiset check above. Wrap would then rewrite only the first and leave a
  // stale UNWRAPPED sibling that Hermes routes to, while the same-family
  // post-write scanner check reports success (a silent no-wrap: the agent is
  // not actually behind the proxy). Count sanctuary-collisions in the REAL
  // parse (the authority for what keys exist) and refuse fail-closed when the
  // target is ambiguous.
  const realSanctuaryCount = real.entryNames.filter(
    (n) => n.toLowerCase() === "sanctuary"
  ).length;
  if (realSanctuaryCount > 1) {
    throw new HermesYamlParityRefusedError(
      "disagreement",
      `config.yaml has ${realSanctuaryCount} mcp_servers entries whose name ` +
        `matches "sanctuary" case-insensitively (e.g. Sanctuary and sanctuary); ` +
        `wrap replaces only one and would leave the other stale and unwrapped. ` +
        `Consolidate them to a single "sanctuary" entry and re-run wrap`
    );
  }
}
