/**
 * A Hermes config path that never exists, so a doctor run under test reads no
 * operator Hermes file and creates nothing. Doctor reads the Hermes entry from
 * the path it is given (must match the hermesConfigPath option of
 * runDoctorChecks in src/cli/doctor.ts).
 */
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

// 8 random bytes = 16 hex characters, so concurrent runs never share the directory name.
const SUFFIX_BYTES = 8;
export const ABSENT_HERMES_CONFIG = join(
  tmpdir(),
  `sanctuary-absent-hermes-${process.pid}-${randomBytes(SUFFIX_BYTES).toString("hex")}`,
  "config.yaml",
);
