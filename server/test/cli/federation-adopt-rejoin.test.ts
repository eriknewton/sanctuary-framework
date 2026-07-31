/**
 * `sanctuary federation adopt` (planned auto-adopt) + `federation rejoin`
 * (compromise manual re-join) CLI tests (Slice 3c-2).
 *
 * Host-free: the custody-unlocking + adopt-core and the join ceremony are
 * injected seams, so these tests assert the CLI SURFACE -- flag parsing, the
 * fail-closed usage refusals, the catalog exit-code mapping, that only PUBLIC
 * material is printed, and that `rejoin` delegates to `join --persist` while
 * recording the dead old root -- without opening a real fortress or a socket.
 * The adopt/rejoin cryptography itself is covered by the store-level suite in
 * test/v1/federation-joiner-trust-root-store.test.ts.
 */

import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { Writable } from "node:stream";
import { toBase64url } from "../../src/core/encoding.js";
import {
  runFederationAdopt,
  runFederationRejoin,
  runFederationCommand,
  type performPlannedAdoptFromCli,
  type persistRejoinedJoinerTrustRootFromJoin,
  type runFederationJoin,
} from "../../src/cli/federation.js";
import type { FederationJoinerPlannedRootAdoptResult } from "../../src/mesh/federation-joiner-trust-root-store.js";

function collector(): { stream: Writable; text: () => string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      chunks.push(chunk.toString());
      cb();
    },
  });
  return { stream, text: () => chunks.join("") };
}

const K1_PUB = toBase64url(randomBytes(32));
const K2_PUB = toBase64url(randomBytes(32));
const PINNED_K2 = JSON.stringify({
  public_key: K2_PUB,
  fortress_id: "fortress-1",
  created_at: "2026-07-24T00:00:00.000Z",
});
const ROTATION_CERT = JSON.stringify({
  kind: "federation-root-rotation",
  fortress_id: "fortress-1",
  old_master_pubkey: K1_PUB,
  new_master: {
    public_key: K2_PUB,
    fortress_id: "fortress-1",
    created_at: "2026-07-24T00:00:00.000Z",
  },
  rotation_serial: 3,
  rotated_at: "2026-07-24T00:00:00.000Z",
  old_master_signature: toBase64url(randomBytes(64)),
});

describe("sanctuary federation adopt (planned auto-adopt CLI)", () => {
  it("refuses without --renew (exit 1)", async () => {
    const out = collector();
    const err = collector();
    const code = await runFederationAdopt({
      argv: ["--fortress-url", "http://x", "--rotation-cert", ROTATION_CERT],
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: out.stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("--renew is required");
  });

  it("refuses a missing --fortress-url (exit 1)", async () => {
    const err = collector();
    const code = await runFederationAdopt({
      argv: ["--renew", "--rotation-cert", ROTATION_CERT],
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("--fortress-url");
  });

  it("refuses a missing --rotation-cert (exit 1)", async () => {
    const err = collector();
    const code = await runFederationAdopt({
      argv: ["--renew", "--fortress-url", "http://x"],
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("--rotation-cert");
  });

  it("refuses a malformed --rotation-cert (exit 1)", async () => {
    const err = collector();
    const code = await runFederationAdopt({
      argv: ["--renew", "--fortress-url", "http://x", "--rotation-cert", "{not json"],
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("not a valid federation");
  });

  it("refuses a missing --pinned-master (A-full, exit 1)", async () => {
    const err = collector();
    const code = await runFederationAdopt({
      argv: ["--renew", "--fortress-url", "http://x", "--rotation-cert", ROTATION_CERT],
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("--pinned-master");
  });

  it("refuses when no operator credential is present (exit 1)", async () => {
    const err = collector();
    const code = await runFederationAdopt({
      argv: [
        "--renew",
        "--fortress-url",
        "http://x",
        "--rotation-cert",
        ROTATION_CERT,
        "--pinned-master",
        PINNED_K2,
      ],
      env: {},
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("unlocked operator identity");
  });

  it("adopts and prints only PUBLIC material (exit 0, no private key)", async () => {
    const out = collector();
    const nodePriv = randomBytes(32);
    const adoptSeam: typeof performPlannedAdoptFromCli = async () =>
      ({
        adopted: true,
        state: "adopted",
        previousPinnedMaster: {
          public_key: K1_PUB,
          fortress_id: "fortress-1",
          created_at: "t",
        },
        pinnedMaster: {
          public_key: K2_PUB,
          fortress_id: "fortress-1",
          created_at: "t",
        },
        rotationSerial: 3,
        record: {
          fortress_id: "fortress-1",
          node_id: "joiner-linux",
          pinned_master_pubkey: {
            public_key: K2_PUB,
            fortress_id: "fortress-1",
            created_at: "t",
          },
          issuing_principal_cert: { principal_id: "p" },
          local_node_cert: { node_id: "joiner-linux", node_pubkey: "NPUB" },
          local_node_private_key: nodePriv,
        },
        context: {},
      }) as unknown as FederationJoinerPlannedRootAdoptResult;

    const code = await runFederationAdopt({
      argv: [
        "--renew",
        "--fortress-url",
        "http://x",
        "--rotation-cert",
        ROTATION_CERT,
        "--pinned-master",
        PINNED_K2,
      ],
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: out.stream,
      err: collector().stream,
      performPlannedAdopt: adoptSeam,
    });

    expect(code).toBe(0);
    const printed = out.text();
    expect(printed).toContain('"adopted": true');
    expect(printed).toContain(K2_PUB);
    expect(printed).toContain('"rotation_serial": 3');
    // Never leaks the node private key.
    expect(printed).not.toContain(toBase64url(nodePriv));
    // LOW (re-gate 2026-07-30): the value check above is weakly formed on its
    // own (a re-serialized leak might not contain the base64url form), so ALSO
    // assert the private-key FIELD NAME never appears in the printed JSON: the
    // print enumerates public fields and must never grow the private one.
    expect(printed).not.toContain("local_node_private_key");
  });

  it("maps a held-old-trust result to exit 3, an unreachable to exit 2", async () => {
    const heldSeam: typeof performPlannedAdoptFromCli = async () =>
      ({
        adopted: false,
        state: "held_old_trust",
        reason: "rotation_cert_invalid",
        currentPinnedMaster: {
          public_key: K1_PUB,
          fortress_id: "fortress-1",
          created_at: "t",
        },
      }) as unknown as FederationJoinerPlannedRootAdoptResult;
    const heldErr = collector();
    const held = await runFederationAdopt({
      argv: [
        "--renew",
        "--fortress-url",
        "http://x",
        "--rotation-cert",
        ROTATION_CERT,
        "--pinned-master",
        PINNED_K2,
      ],
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: collector().stream,
      err: heldErr.stream,
      performPlannedAdopt: heldSeam,
    });
    expect(held).toBe(3);
    expect(heldErr.text()).toContain("held the old trust anchor");

    const unreachableSeam: typeof performPlannedAdoptFromCli = async () =>
      ({
        adopted: false,
        state: "held_old_trust",
        reason: "reissue_unreachable",
        currentPinnedMaster: null,
      }) as unknown as FederationJoinerPlannedRootAdoptResult;
    const unreachable = await runFederationAdopt({
      argv: [
        "--renew",
        "--fortress-url",
        "http://x",
        "--rotation-cert",
        ROTATION_CERT,
        "--pinned-master",
        PINNED_K2,
      ],
      env: { SANCTUARY_PASSPHRASE: "pw" },
      out: collector().stream,
      err: collector().stream,
      performPlannedAdopt: unreachableSeam,
    });
    expect(unreachable).toBe(2);
  });
});

describe("sanctuary federation rejoin (compromise manual re-join CLI)", () => {
  const validArgv = (): string[] => [
    "--fortress-url",
    "http://issuer",
    "--pinned-master",
    PINNED_K2,
    "--bootstrap-token",
    JSON.stringify({
      intended_node_id: "joiner-linux",
      intended_node_mode: "local",
      signature: "sig",
    }),
    "--master-secret",
    toBase64url(randomBytes(32)),
    "--revoked-old-master",
    K1_PUB,
    "--revocation-serial",
    "5",
    "--passphrase",
    "pw",
  ];

  it("refuses any old-key-signed artifact flag outright (exit 1)", async () => {
    const err = collector();
    const code = await runFederationRejoin({
      argv: [...validArgv(), "--rotation-cert", ROTATION_CERT],
      env: {},
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("NEVER accepts");
    expect(err.text()).toContain("--rotation-cert");
  });

  it("refuses a missing --pinned-master (exit 1)", async () => {
    const argv = validArgv().filter(
      (_, i, a) => a[i] !== "--pinned-master" && a[i - 1] !== "--pinned-master",
    );
    const err = collector();
    const code = await runFederationRejoin({
      argv,
      env: {},
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("--pinned-master");
  });

  it("refuses a missing --bootstrap-token (exit 1)", async () => {
    const argv = validArgv().filter(
      (_, i, a) => a[i] !== "--bootstrap-token" && a[i - 1] !== "--bootstrap-token",
    );
    const err = collector();
    const code = await runFederationRejoin({
      argv,
      env: {},
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("FRESH --bootstrap-token");
  });

  it("refuses a missing --revoked-old-master (exit 1)", async () => {
    const argv = validArgv().filter(
      (_, i, a) =>
        a[i] !== "--revoked-old-master" && a[i - 1] !== "--revoked-old-master",
    );
    const err = collector();
    const code = await runFederationRejoin({
      argv,
      env: {},
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("--revoked-old-master");
  });

  it("refuses an invalid --revocation-serial (exit 1)", async () => {
    const argv = validArgv();
    argv[argv.indexOf("--revocation-serial") + 1] = "0";
    const err = collector();
    const code = await runFederationRejoin({
      argv,
      env: {},
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("--revocation-serial");
  });

  it("L3: refuses a --revoked-old-master that is not a base64url Ed25519 pubkey (exit 1)", async () => {
    // Garbage charset: would be persisted as a revocation that can never match.
    const garbage = validArgv();
    garbage[garbage.indexOf("--revoked-old-master") + 1] = "not a key!!";
    const garbageErr = collector();
    const garbageCode = await runFederationRejoin({
      argv: garbage,
      env: {},
      out: collector().stream,
      err: garbageErr.stream,
    });
    expect(garbageCode).toBe(1);
    expect(garbageErr.text()).toContain(
      "--revoked-old-master is not a base64url",
    );

    // Valid base64url charset but the WRONG key length (a truncated paste).
    const truncated = validArgv();
    truncated[truncated.indexOf("--revoked-old-master") + 1] = toBase64url(
      randomBytes(16),
    );
    const truncatedErr = collector();
    const truncatedCode = await runFederationRejoin({
      argv: truncated,
      env: {},
      out: collector().stream,
      err: truncatedErr.stream,
    });
    expect(truncatedCode).toBe(1);
    expect(truncatedErr.text()).toContain(
      "--revoked-old-master is not a base64url",
    );

    // NON-CANONICAL spelling (codex gate 2026-07-31): 43 chars, valid charset,
    // decodes to the same 32 bytes as a canonical key under a LENIENT decoder,
    // but round-trips to a DIFFERENT string. Persisting it would record a
    // revocation that never string-matches a canonical cert pubkey. The strict
    // validator must refuse it.
    const canonical = toBase64url(randomBytes(32));
    const lastChar = canonical[canonical.length - 1]!;
    const alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    // Flip a low-order bit of the final character's 6-bit group: the two
    // discarded trailing bits differ, so a lenient decode yields the same 32
    // bytes while the string is non-canonical.
    const flipped = alphabet[alphabet.indexOf(lastChar) ^ 1]!;
    const nonCanonical = canonical.slice(0, -1) + flipped;
    expect(nonCanonical).not.toBe(canonical);
    const nonCanonicalArgv = validArgv();
    nonCanonicalArgv[nonCanonicalArgv.indexOf("--revoked-old-master") + 1] =
      nonCanonical;
    const nonCanonicalErr = collector();
    const nonCanonicalCode = await runFederationRejoin({
      argv: nonCanonicalArgv,
      env: {},
      out: collector().stream,
      err: nonCanonicalErr.stream,
    });
    expect(nonCanonicalCode).toBe(1);
    expect(nonCanonicalErr.text()).toContain(
      "--revoked-old-master is not a base64url",
    );
  });

  it("refuses --revoked-old-master equal to the new --pinned-master (exit 1)", async () => {
    const argv = validArgv();
    argv[argv.indexOf("--revoked-old-master") + 1] = K2_PUB;
    const err = collector();
    const code = await runFederationRejoin({
      argv,
      env: {},
      out: collector().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("must not equal");
  });

  it("delegates to join --persist and records the dead old root", async () => {
    let capturedArgv: string[] | undefined;
    let persistArgs:
      | { revokedOldMasterPubkey: string; revocationSerial: number }
      | undefined;

    const persistSeam: typeof persistRejoinedJoinerTrustRootFromJoin = async (o) => {
      persistArgs = {
        revokedOldMasterPubkey: o.revokedOldMasterPubkey,
        revocationSerial: o.revocationSerial,
      };
    };
    const joinSeam: typeof runFederationJoin = async (a) => {
      capturedArgv = a.argv;
      // Exercise the injected persist to confirm it carries the revocation.
      await a.persistJoinerTrustRoot!({
        pinnedMaster: {
          public_key: K2_PUB,
          fortress_id: "fortress-1",
          created_at: "t",
        },
        issuingPrincipalCert: {} as never,
        localNodeCert: {} as never,
        localNodePrivateKey: new Uint8Array(32),
      });
      return 0;
    };

    const out = collector();
    const code = await runFederationRejoin({
      argv: validArgv(),
      env: {},
      out: out.stream,
      err: collector().stream,
      join: joinSeam,
      persistRejoinedJoinerTrustRoot: persistSeam,
    });

    expect(code).toBe(0);
    expect(capturedArgv).toContain("--persist");
    expect(capturedArgv).toContain("--pinned-master");
    expect(capturedArgv).toContain("--bootstrap-token");
    expect(persistArgs?.revokedOldMasterPubkey).toBe(K1_PUB);
    expect(persistArgs?.revocationSerial).toBe(5);
    // LOW-2: reports the recorded revocation (observation-shaped, public only).
    const printed = out.text();
    expect(printed).toContain('"rejoined": true');
    expect(printed).toContain(K1_PUB);
    expect(printed).toContain('"revocation_serial": 5');
  });
});

describe("federation dispatcher wires the new verbs", () => {
  it("routes `adopt` and `rejoin` (usage refusal, not unknown-subcommand)", async () => {
    const adoptErr = collector();
    const adoptCode = await runFederationCommand({
      argv: ["adopt"],
      out: collector().stream,
      err: adoptErr.stream,
    });
    expect(adoptCode).toBe(1);
    expect(adoptErr.text()).not.toContain("unknown subcommand");
    expect(adoptErr.text()).toContain("--renew");

    const rejoinErr = collector();
    const rejoinCode = await runFederationCommand({
      argv: ["rejoin"],
      out: collector().stream,
      err: rejoinErr.stream,
    });
    expect(rejoinCode).toBe(1);
    expect(rejoinErr.text()).not.toContain("unknown subcommand");
  });

  it("`federation --help` lists the adopt + rejoin verbs", async () => {
    const out = collector();
    const code = await runFederationCommand({
      argv: ["--help"],
      out: out.stream,
      err: collector().stream,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("adopt");
    expect(out.text()).toContain("rejoin");
  });
});
