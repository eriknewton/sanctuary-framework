/**
 * Top-level `--fortress` flag extraction.
 *
 * Fixes drill finding F-1.3.2-N-001 (v1.3.2 Mini1 drill, 2026-05-23):
 * `sanctuary --fortress <path> <subcommand>` silently ignored BOTH the
 * flag and the subcommand. The argv scanner in `cli.ts` dispatched on
 * `args[0]`, so a leading flag fell through every subcommand check and
 * booted the MCP server against the home fortress (`~/.sanctuary`)
 * instead of the operator-named path. That is a "never silently degrade"
 * violation: operators who set `--fortress` expecting isolation got
 * home-fortress access patterns, and audit writes landed in the wrong
 * storage path on multi-fortress hosts.
 *
 * The fix direction is "honor the flag, or fail loud": a well-formed
 * leading `--fortress <path>` is extracted here and promoted to
 * `SANCTUARY_STORAGE_PATH` semantics by the caller (which every state
 * I/O path already honors end-to-end via `config.ts`); a malformed flag
 * (missing value) produces an error the caller must surface and exit on,
 * never ignore.
 *
 * Scope: only the LEADING flag region is scanned, i.e. tokens before the
 * first non-flag token. Subcommands that accept their own `--fortress`
 * after the subcommand word (`init`, `protect`/`wrap`, `reset-passphrase`,
 * `audit-chain export`) keep ownership of those occurrences; this module
 * never touches argv past the subcommand boundary.
 *
 * That scope has a cost: a subcommand that does NOT parse the flag receives it
 * as an ordinary argv token and drops it, running against the ambient fortress.
 * `secrets` is the case where that was demonstrated to write a credential to
 * the wrong fortress while reporting success, and it refuses the flag itself
 * (`assertNoFortressFlag` in `secrets.ts`, whose accepted spellings must match
 * the two accepted below; adding a third spelling here without adding it there
 * reopens the silent-drop path). Other non-parsing subcommands are still
 * exposed; the general fix is one shared flag parser, not a list here.
 */

export interface TopLevelFortressResult {
  /** argv with the global --fortress flag (and its value) removed. */
  args: string[];
  /** The path supplied to --fortress, when present and well-formed. */
  fortressPath?: string;
  /** Operator-facing error when the flag is present but malformed. */
  error?: string;
}

/**
 * Scan the leading flag region of argv for a global `--fortress <path>`
 * (or `--fortress=<path>`) and extract it.
 *
 * Returns the remaining argv (subcommand dispatch sees it exactly as if
 * the flag had never been typed), the extracted path when present, or an
 * error when the flag is present but has no usable value. On error the
 * original argv is returned untouched; the caller must fail loud rather
 * than continue.
 */
export function extractTopLevelFortressFlag(
  argv: string[]
): TopLevelFortressResult {
  const out: string[] = [];
  let fortressPath: string | undefined;
  let i = 0;

  while (i < argv.length) {
    const tok = argv[i]!;

    if (!tok.startsWith("-")) {
      // Subcommand boundary: everything from here on belongs to the
      // subcommand's own parser (including any --fortress it defines).
      out.push(...argv.slice(i));
      break;
    }

    if (tok === "--fortress") {
      const val = argv[i + 1];
      if (val === undefined || val.startsWith("-")) {
        return {
          args: argv,
          error:
            "--fortress requires a path argument (usage: sanctuary --fortress <path> <subcommand>)",
        };
      }
      fortressPath = val;
      i += 2;
      continue;
    }

    if (tok.startsWith("--fortress=")) {
      const val = tok.slice("--fortress=".length);
      if (val === "") {
        return {
          args: argv,
          error:
            "--fortress requires a path argument (usage: sanctuary --fortress <path> <subcommand>)",
        };
      }
      fortressPath = val;
      i += 1;
      continue;
    }

    if (tok === "--passphrase" && argv[i + 1] !== undefined) {
      // --passphrase takes a value; skip it so a passphrase value is not
      // mistaken for the subcommand boundary.
      out.push(tok, argv[i + 1]!);
      i += 2;
      continue;
    }

    out.push(tok);
    i += 1;
  }

  return {
    args: out,
    ...(fortressPath !== undefined ? { fortressPath } : {}),
  };
}
