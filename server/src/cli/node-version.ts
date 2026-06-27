import type { Writable } from "node:stream";

export const MIN_NODE_VERSION = "22.0.0";

const parsedMinNodeMajor = parseNodeMajor(MIN_NODE_VERSION);
if (parsedMinNodeMajor === null) {
  throw new Error(`Invalid MIN_NODE_VERSION: ${MIN_NODE_VERSION}`);
}

export const MIN_NODE_MAJOR = parsedMinNodeMajor;

interface NodeVersionPreflightOptions {
  err?: Pick<Writable, "write">;
  exit?: (code: number) => never;
}

export interface NodeVersionCheckResult {
  supported: boolean;
  requiredVersion: string;
  requiredMajor: number;
  actualVersion: string;
  message: string;
}

export function assertSupportedNodeVersion(
  version = process.versions.node,
  options: NodeVersionPreflightOptions = {},
): void {
  const result = checkNodeVersion(version);
  if (result.supported) return;
  const err = options.err ?? process.stderr;
  err.write(`${result.message}\n`);
  const exit = options.exit ?? ((code: number): never => process.exit(code));
  exit(1);
}

export function checkNodeVersion(
  version = process.versions.node,
): NodeVersionCheckResult {
  const actualVersion = normalizeNodeVersion(version);
  const actualMajor = parseNodeMajor(actualVersion);
  const supported = actualMajor !== null && actualMajor >= MIN_NODE_MAJOR;
  return {
    supported,
    requiredVersion: MIN_NODE_VERSION,
    requiredMajor: MIN_NODE_MAJOR,
    actualVersion,
    message: formatUnsupportedNodeVersionMessage(actualVersion),
  };
}

export function formatUnsupportedNodeVersionMessage(actualVersion: string): string {
  return `Sanctuary requires Node.js ${MIN_NODE_MAJOR}.x or later. You are running Node.js ${normalizeNodeVersion(actualVersion)}. Please upgrade Node.js and run the command again.`;
}

export function parseNodeMajor(version: string): number | null {
  const [major] = normalizeNodeVersion(version).split(".");
  if (!major || !/^\d+$/.test(major)) return null;
  return Number.parseInt(major, 10);
}

function normalizeNodeVersion(version: string): string {
  return version.trim().replace(/^v/i, "");
}
