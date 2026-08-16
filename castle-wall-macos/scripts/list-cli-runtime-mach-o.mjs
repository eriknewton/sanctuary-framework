#!/usr/bin/env node

// Emit every Mach-O regular file below a sealed CLI runtime as a NUL-delimited
// absolute path. Signing and every verification phase call this same scanner;
// suffixes are not security boundaries and are deliberately ignored.

import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readdirSync,
  readSync,
} from "node:fs";
import { join, resolve } from "node:path";

const runtime = process.argv[2];
if (!runtime) throw new Error("usage: list-cli-runtime-mach-o.mjs <cli-runtime-directory>");

const magicValues = new Set([
  0xfeedface,
  0xcefaedfe,
  0xfeedfacf,
  0xcffaedfe,
  0xcafebabe,
  0xbebafeca,
  0xcafebabf,
  0xbfbafeca,
]);

function walk(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (stat.isDirectory()) {
      closeSync(fd);
      for (const name of readdirSync(path).sort()) walk(join(path, name));
      return;
    }
    if (!stat.isFile() || stat.size < 4) return;
    const header = Buffer.allocUnsafe(4);
    if (readSync(fd, header, 0, 4, 0) !== 4) return;
    if (magicValues.has(header.readUInt32BE(0))) {
      process.stdout.write(`${resolve(path)}\0`);
    }
  } finally {
    try { closeSync(fd); } catch { /* directory branch already closed */ }
  }
}

walk(resolve(runtime));
