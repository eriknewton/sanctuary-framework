import { describe, expect, it } from "vitest";

import { isBenignDirectoryFsyncError } from "../../src/storage/directory-fsync.js";

function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

describe("directory fsync capability contract", () => {
  it.each(["EINVAL", "ENOTSUP", "EOPNOTSUPP"])(
    "treats supported filesystem capability code %s as benign",
    (code) => expect(isBenignDirectoryFsyncError(errno(code))).toBe(true),
  );

  it.each(["EIO", "EPERM", "EACCES", "EBADF", "EISDIR", "ENOENT"])(
    "propagates real durability failure %s",
    (code) => expect(isBenignDirectoryFsyncError(errno(code))).toBe(false),
  );

  it.each(["EISDIR", "EPERM"])(
    "tolerates Windows directory-descriptor limitation %s only on win32",
    (code) => {
      expect(isBenignDirectoryFsyncError(errno(code), "win32")).toBe(true);
      expect(isBenignDirectoryFsyncError(errno(code), "darwin")).toBe(false);
      expect(isBenignDirectoryFsyncError(errno(code), "linux")).toBe(false);
    },
  );

  it("does not swallow unclassified errors", () => {
    expect(isBenignDirectoryFsyncError(new Error("unclassified"))).toBe(false);
  });
});
