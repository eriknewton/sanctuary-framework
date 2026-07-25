/**
 * REAL pfctl OUTPUT, CAPTURED ON HARDWARE. Not a model of what pf prints.
 *
 * PROVENANCE. Every string below was extracted verbatim from the logs of the
 * Mini1 drill of 2026-07-26 (macOS 26.5.2 build 25F84, arm64), which ran
 * unattended against merged main `ed7722ce`. Each constant names its source
 * log and line range. Nothing here was typed from memory or reconstructed from
 * a man page, INCLUDING the trailing whitespace inside the `pfctl -s info`
 * column output, which is preserved exactly as captured.
 *
 * WHY THIS FILE EXISTS AT ALL. The first attempt at this fix (PR #1007) was
 * reviewed UNSOUND for one reason: its test's pf host was a MODEL its author
 * wrote from prose descriptions of drill logs, so the tests could only ever
 * confirm the author's own understanding of pf. The reviewer's verdict was
 * that a correct re-fix "needs hardware, not a better model." The hardware run
 * happened; these are its bytes. Any future edit that makes a constant here
 * diverge from the named log line is a defect in the test, not in the code
 * under test.
 *
 * TWO CAPTURED FACTS THAT ARE EASY TO GET WRONG AND ARE LOAD-BEARING:
 *
 *  1. `pfctl -E` writes BOTH `pf enabled` AND the `Token : <n>` line to
 *     STDERR, and exits 0. A parser reading stdout gets an empty string.
 *  2. A stale `pfctl -X` exits 1 with TWO DIFFERENT messages depending on
 *     pf's state: `pfctl: pf not enabled` when pf is disabled (the common
 *     post-reboot shape) and `pfctl: pf: token invalid` when it is enabled.
 *
 * A CORRECTION THE DRILL ITSELF DECLARED, carried here so it cannot be
 * re-introduced: the drill's FIRST exit-code pass (`T1`) captured `rc` after
 * piping pfctl into `grep`, so every `rc` in that log is grep's status and it
 * reported `rc=0` for a FAILING `pfctl -X`. The exit codes below come from the
 * re-measured, un-piped `T2` log. T1 is used here only for its stdout text,
 * never for an exit code.
 */

/* eslint-disable no-irregular-whitespace */

// ---------------------------------------------------------------------------
// `pfctl -s info`
// ---------------------------------------------------------------------------

/**
 * pf DISABLED. `T1-pf-reference-observation.log:6-30` (step 1, baseline,
 * nothing touched). This is the post-reboot shape F-PFBOOT leaves behind.
 */
export const PF_INFO_DISABLED =
  "Status: Disabled                              Debug: Urgent\n" +
  "\n" +
  "State Table                          Total             Rate\n" +
  "  current entries                        0               \n" +
  "  searches                               0            0.0/s\n" +
  "  inserts                                0            0.0/s\n" +
  "  removals                               0            0.0/s\n" +
  "Counters\n" +
  "  match                                  0            0.0/s\n" +
  "  bad-offset                             0            0.0/s\n" +
  "  fragment                               0            0.0/s\n" +
  "  short                                  0            0.0/s\n" +
  "  normalize                              0            0.0/s\n" +
  "  memory                                 0            0.0/s\n" +
  "  bad-timestamp                          0            0.0/s\n" +
  "  congestion                             0            0.0/s\n" +
  "  ip-option                              0            0.0/s\n" +
  "  proto-cksum                            0            0.0/s\n" +
  "  state-mismatch                         0            0.0/s\n" +
  "  state-insert                           0            0.0/s\n" +
  "  state-limit                            0            0.0/s\n" +
  "  src-limit                              0            0.0/s\n" +
  "  synproxy                               0            0.0/s\n" +
  "  dummynet                               0            0.0/s\n" +
  "  invalid-port                           0            0.0/s\n";

/**
 * pf ENABLED. `T1-pf-reference-observation.log:59-83` (step 2, immediately
 * after `pfctl -E`). Note the status line is `Status: Enabled for 0 days
 * 00:00:00`, not a bare `Status: Enabled` -- the trailing duration is why the
 * predicate matches on a word boundary rather than a line end.
 */
export const PF_INFO_ENABLED =
  "Status: Enabled for 0 days 00:00:00           Debug: Urgent\n" +
  "\n" +
  "State Table                          Total             Rate\n" +
  "  current entries                        0               \n" +
  "  searches                               0               \n" +
  "  inserts                                0               \n" +
  "  removals                               0               \n" +
  "Counters\n" +
  "  match                                  0               \n" +
  "  bad-offset                             0               \n" +
  "  fragment                               0               \n" +
  "  short                                  0               \n" +
  "  normalize                              0               \n" +
  "  memory                                 0               \n" +
  "  bad-timestamp                          0               \n" +
  "  congestion                             0               \n" +
  "  ip-option                              0               \n" +
  "  proto-cksum                            0               \n" +
  "  state-mismatch                         0               \n" +
  "  state-insert                           0               \n" +
  "  state-limit                            0               \n" +
  "  src-limit                              0               \n" +
  "  synproxy                               0               \n" +
  "  dummynet                               0               \n" +
  "  invalid-port                           0               \n";

// ---------------------------------------------------------------------------
// `pfctl -s References`
// ---------------------------------------------------------------------------

/**
 * NOTHING HELD. `T1-pf-reference-observation.log:33`. A distinct sentinel, not
 * an empty string, which is why an unrecognized/empty table is treated as
 * "could not look" rather than "no references".
 */
export const PF_REFERENCES_NONE = "No pf starter references held\n";

/**
 * ONE reference held. `T1-pf-reference-observation.log:87-89`.
 *
 * The token this names, `15053025338191571182`, is the value `pfctl -E`
 * returned four lines earlier in the same log. That correspondence is the
 * entire basis for attribution by token.
 */
export const PF_REFERENCES_ONE =
  "TOKENS:\n" +
  "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
  "4063     pfctl                        15053025338191571182     0 days 00:00:00\n";

/** The token named in {@link PF_REFERENCES_ONE}. */
export const CAPTURED_TOKEN_ONE = "15053025338191571182";

/**
 * TWO independent references held. `T1-pf-reference-observation.log:100-103`.
 * Newest first. Both rows say `pfctl` under `Process Name` and both PIDs have
 * exited, which is the captured evidence that the TOKEN column is the only
 * usable discriminator on this surface.
 */
export const PF_REFERENCES_TWO =
  "TOKENS:\n" +
  "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
  "4077     pfctl                        9084387343160548126      0 days 00:00:00\n" +
  "4063     pfctl                        15053025338191571182     0 days 00:00:00\n";

/** The second token named in {@link PF_REFERENCES_TWO}. */
export const CAPTURED_TOKEN_TWO = "9084387343160548126";

/**
 * THE F-PFTHIRDPARTY STATE, captured.
 * `T3-thirdparty-release-wrongallow.log:8-10`: pf held enabled by an
 * out-of-band reference (PID 5059, token `3557565746035151565`) while the
 * registry's own `enable_token` was the kernel-invalid `2276319666065282592`
 * and the product reported the gate LIVE. Releasing this reference destroyed
 * uid 503's loopback confinement in the same boot and the same generation.
 */
export const PF_REFERENCES_THIRD_PARTY =
  "TOKENS:\n" +
  "PID      Process Name                 TOKEN                    TIMESTAMP\n" +
  "5059     pfctl                        3557565746035151565      0 days 00:01:06\n";

/** The out-of-band holder's token in {@link PF_REFERENCES_THIRD_PARTY}. */
export const CAPTURED_THIRD_PARTY_TOKEN = "3557565746035151565";

/**
 * The registry's persisted `enable_token` on the drilled host, byte-identical
 * before and after the reboot that invalidated it
 * (`RESULTS.md` section 2.2, `T3-thirdparty-release-wrongallow.log:12`).
 */
export const CAPTURED_STALE_REGISTRY_TOKEN = "2276319666065282592";

// ---------------------------------------------------------------------------
// `pfctl -E` and `pfctl -X`: exit codes and streams (T2, re-measured, no pipe)
// ---------------------------------------------------------------------------

/**
 * `pfctl -E`. `T2-pf-exitcodes-corrected.log:14-17`: exit 0, stdout EMPTY,
 * stderr carries both lines. The log renders newlines as `|`; they are restored
 * here.
 */
export const PF_ENABLE_OK = {
  code: 0,
  stdout: "",
  stderr: "pf enabled\nToken : 11012949885072952621\n",
} as const;

/** The token {@link PF_ENABLE_OK} returns. `T2-pf-exitcodes-corrected.log:17`. */
export const CAPTURED_ENABLE_TOKEN = "11012949885072952621";

/**
 * `pfctl -X <stale>` while pf is DISABLED.
 * `T2-pf-exitcodes-corrected.log:9-11`: exit 1, stderr `pfctl: pf not enabled`.
 * THE COMMON POST-REBOOT SHAPE.
 */
export const PF_RELEASE_STALE_PF_DISABLED = {
  code: 1,
  stdout: "",
  stderr: "pfctl: pf not enabled\n",
} as const;

/**
 * `pfctl -X <stale>` while pf IS enabled.
 * `T2-pf-exitcodes-corrected.log:24-26`: exit 1, stderr `pfctl: pf: token
 * invalid`. A DIFFERENT message from the one above, which is why suppressing
 * only this one still leaves the post-reboot path throwing.
 */
export const PF_RELEASE_STALE_PF_ENABLED = {
  code: 1,
  stdout: "",
  stderr: "pfctl: pf: token invalid\n",
} as const;

/**
 * `pfctl -X <valid>` releasing the LAST reference.
 * `T2-pf-exitcodes-corrected.log:34-36`: exit 0, stderr `pf disabled`.
 */
export const PF_RELEASE_LAST = {
  code: 0,
  stdout: "",
  stderr: "pf disabled\n",
} as const;

/**
 * `pfctl -X <valid>` with other references remaining.
 * `T1-pf-reference-observation.log:107-108` (stdout text; the exit code is the
 * re-measured 0 from T2's success branch, since T1's own `rc` is grep's).
 */
export const PF_RELEASE_OTHERS_REMAIN = {
  code: 0,
  stdout: "",
  stderr:
    "disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.\n",
} as const;

// ---------------------------------------------------------------------------
// Boot sessions
// ---------------------------------------------------------------------------

/**
 * The two boot sessions the drill spanned, proving the reboot really happened
 * (`RESULTS.md` criterion P5.3; the full second value is the header of
 * `T3-thirdparty-release-wrongallow.log:2`). The first is recorded truncated in
 * the RESULTS table, so only its captured prefix is used as an opaque token
 * here -- the resolver compares for equality and never parses a UUID.
 */
export const CAPTURED_BOOT_SESSION_BEFORE = "F779C81A";
export const CAPTURED_BOOT_SESSION_AFTER = "4E4A2428-2FBD-4164-B6B6-B1FDA7DA43BD";

/**
 * The boot session the pf reference-format observations (T1/T2) were made in.
 * `T1-pf-reference-observation.log:2`.
 */
export const CAPTURED_BOOT_SESSION_T1 = "992E1A78-7407-4391-B320-E2FC59685EC8";
