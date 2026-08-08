export function flagValue(argv: string[], name: string): string | undefined {
  const prefix = `${name}=`;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === name) return argv[i + 1];
    if (arg.startsWith(prefix)) return arg.slice(prefix.length);
  }
  return undefined;
}

export interface ConsumedFlagValue {
  argv: string[];
  value?: string;
  error?: string;
}

export function consumeFlagValue(argv: string[], name: string): ConsumedFlagValue {
  const prefix = `${name}=`;
  const filtered: string[] = [];
  let value: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === name) {
      const next = argv[i + 1];
      if (next === undefined || next.length === 0 || next.startsWith("--")) {
        return { argv: filtered, error: `${name} requires a value` };
      }
      if (value !== undefined) {
        return { argv: filtered, error: `${name} may only be provided once` };
      }
      value = next;
      i += 1;
      continue;
    }
    if (arg.startsWith(prefix)) {
      const next = arg.slice(prefix.length);
      if (next.length === 0) {
        return { argv: filtered, error: `${name} requires a value` };
      }
      if (value !== undefined) {
        return { argv: filtered, error: `${name} may only be provided once` };
      }
      value = next;
      continue;
    }
    filtered.push(arg);
  }

  return value === undefined ? { argv: filtered } : { argv: filtered, value };
}

export function unknownFlagWithPrefix(
  argv: string[],
  name: string,
  allowedRelatedFlags: string[] = [],
): string | undefined {
  const allowed = new Set([name, ...allowedRelatedFlags]);
  for (const arg of argv) {
    if (!arg.startsWith(name)) continue;
    const flagName = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
    if (!allowed.has(flagName)) return flagName;
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
