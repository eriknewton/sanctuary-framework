export function flagValue(argv: string[], name: string): string | undefined {
  const prefix = `${name}=`;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === name) return argv[i + 1];
    if (arg.startsWith(prefix)) return arg.slice(prefix.length);
  }
  return undefined;
}

export function flagValues(argv: string[], name: string): string[] {
  const values: string[] = [];
  const prefix = `${name}=`;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === name) {
      if (argv[i + 1] !== undefined) values.push(argv[++i]!);
      continue;
    }
    if (arg.startsWith(prefix)) values.push(arg.slice(prefix.length));
  }
  return values;
}

export function hasFlag(argv: string[], name: string): boolean {
  const prefix = `${name}=`;
  return argv.some((arg) => arg === name || arg.startsWith(prefix));
}
