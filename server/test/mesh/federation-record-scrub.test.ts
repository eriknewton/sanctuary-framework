import { describe, expect, it } from "vitest";
import { mintFederationTrustRootRecord, mintHybridFederationMaterial, zeroRecordSecrets } from "../../src/mesh/federation-trust-root-store.js";

describe("federation record disposal", () => {
  it.each(["ed25519-v1", "ed25519+ml-dsa-v1"] as const)("scrubs private %s material and retains public records", async (issuanceSuite) => {
    const record = mintFederationTrustRootRecord({ nodeId: "scrub-home" });
    if (issuanceSuite === "ed25519+ml-dsa-v1") record.hybrid = await mintHybridFederationMaterial({
      fortressId: record.fortress_id, nodeId: record.node_id, nodeMode: "local", principalId: "scrub-principal",
    });
    const publicRecord = JSON.stringify([record.pinned_master_pubkey, record.local_node_cert, record.issuing_principal_cert]);
    const privateBytes = [record.master_secret, record.master_private_key!, record.issuing_principal_private_key,
      record.local_node_private_key];
    if (record.hybrid) {
      for (const keys of [record.hybrid.master_private_keys, record.hybrid.issuing_principal_private_keys,
        record.hybrid.local_node_private_keys]) privateBytes.push(keys.ed25519.private_key, keys.ml_dsa_65.secret_key);
    }
    expect(privateBytes.every((key) => key.some((byte) => byte !== 0))).toBe(true);
    zeroRecordSecrets(record); zeroRecordSecrets(record);
    expect(privateBytes.every((key) => key.every((byte) => byte === 0))).toBe(true);
    expect(JSON.stringify([record.pinned_master_pubkey, record.local_node_cert, record.issuing_principal_cert])).toBe(publicRecord);
  });
});
