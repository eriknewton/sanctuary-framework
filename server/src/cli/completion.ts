/**
 * sanctuary completion
 *
 * Pure shell-completion generator. Does not read or write Sanctuary state.
 */

import { Writable } from "node:stream";
import { TOP_LEVEL_SUBCOMMANDS } from "./subcommands.js";

export interface CompletionCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  commands?: readonly string[];
}

type Shell = "bash" | "zsh" | "fish";

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runCompletionCommand(
  args: CompletionCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const shell = args.argv[0];

  if (!shell || shell === "--help" || shell === "-h") {
    printUsage(shell ? out : err);
    return shell ? 0 : 2;
  }

  if (shell !== "bash" && shell !== "zsh" && shell !== "fish") {
    write(err, `Unknown shell: ${shell}\n`);
    printUsage(err);
    return 2;
  }

  const commands = [...(args.commands ?? TOP_LEVEL_SUBCOMMANDS)].sort();
  write(out, completionFor(shell, commands));
  return 0;
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary completion <bash|zsh|fish>

Emit a shell completion script for the sanctuary CLI.
`,
  );
}

function completionFor(shell: Shell, commands: readonly string[]): string {
  const words = commands.join(" ");
  if (shell === "bash") {
    return `# sanctuary bash completion
_sanctuary_completion() {
  local cur
  cur="\${COMP_WORDS[COMP_CWORD]}"
  if [[ \${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "${words}" -- "\${cur}") )
  else
    COMPREPLY=()
  fi
}
complete -F _sanctuary_completion sanctuary sanctuary-mcp-server
`;
  }

  if (shell === "zsh") {
    const zshWords = commands.map((command) => `'${command}:sanctuary ${command}'`).join(" ");
    return `#compdef sanctuary sanctuary-mcp-server
# sanctuary zsh completion
_sanctuary() {
  local -a commands
  commands=(${zshWords})
  _describe 'sanctuary command' commands
}
compdef _sanctuary sanctuary sanctuary-mcp-server
`;
  }

  return `# sanctuary fish completion
set -l sanctuary_commands ${words}
complete -c sanctuary -f -n "__fish_use_subcommand" -a "$sanctuary_commands"
complete -c sanctuary-mcp-server -f -n "__fish_use_subcommand" -a "$sanctuary_commands"
`;
}
