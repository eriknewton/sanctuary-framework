import type { FixtureOutcome } from "../../registry.js";

export function outcome(started: number, passed: boolean, message?: string): FixtureOutcome {
  return {
    passed,
    message: passed ? undefined : message,
    durationMs: Math.round(performance.now() - started),
  };
}

export async function captureError(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
    return null;
  } catch (err) {
    return err;
  }
}

export function hasMessage(err: unknown, pattern: RegExp): boolean {
  return err instanceof Error && pattern.test(err.message);
}
