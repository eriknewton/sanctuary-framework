/** Recipient instructions share the recomputed basis, counts and coverage used by every B surface. */
import * as B from "./split-statement-contract.js";
/** Render an archival acceptance procedure from the same typed chain results as the receipt. */
export function splitRecipient(chains:readonly B.ChainResult[]):string {
  const rendered=B.renderChains(chains);
  return `## Verify the expected split-host statement\n\nObtain the approved installed verifier, full pack key, split trust descriptor, export id and manifest digest through an independently authenticated channel. Confirm every signing role and fingerprint. A descriptor copied from this delivery remains an unauthenticated candidate. Keep pins outside the pack and verify a fresh extraction before browsing it.\n\nRun the installed verify-evidence-pack command with --pack, --public-key-file, --trust-descriptor-file and --expect-manifest-digest. Use --json to retain the full result. Accept only exit 0, status PASS, accepted true and the expected export id. Exit 10 means incomplete evidence and is not acceptance, even when a pack was delivered. Exit 1 rejects the delivery; exit 2 requires correcting the invocation. An old pack requires its own independently supplied expected digest and establishes no freshness.\n\n${rendered.historical_signatures}\n${rendered.coverage.join("\n")}\n\n${rendered.sentences.join("\n\n")}\n`;
}
