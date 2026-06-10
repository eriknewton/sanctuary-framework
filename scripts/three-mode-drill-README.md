# Three-Mode Drill, Pilot Operator Onboarding

A one-command demonstration of the Sanctuary Federation Protocol v0.1 running three nodes on one machine. After you run the script, you can inspect the resulting fortress to see that the mesh protocol is doing exactly what the product page promises: three nodes, each in a different mode, agreeing on the same roster, the same policy set, and the same canonical audit log, all cryptographically anchored to a fortress-master that only you hold.

## What this drill proves

The drill brings up three processes on your laptop, each acting as a Sanctuary node inside one fortress:

- **Node A, local mode.** The "always-on host" role. Your laptop, your Mac Studio, the mini in your closet. This node is the canonical audit node: the authoritative record of what every agent in the fortress has done.
- **Node B, operator cloud mode.** The "sovereign-managed" role. In production this would be a Confidential VM in a cloud region of your choosing, attesting to the fortress-master before it joins. The drill simulates the deployment shape with a loopback process; the cryptographic posture is identical.
- **Node C, sovereign TEE mode.** The "sealed hardware" role. In production, this runs inside a TEE (GCP Confidential VMs, Azure Confidential Computing, or similar) and carries a measured-attestation hash on its certificate. The drill uses a mock attestation so the chain of trust is demonstrable without TEE hardware.

All three are members of the same fortress, all three certificates chain back to one fortress-master that never leaves your encrypted state store. When the drill reports steady state, every node has:

- Verified every other node's certificate chain against the pinned fortress-master.
- Joined the shared gossipsub channel used for broadcast federation.
- Settled into an active presence that the other two nodes have confirmed.

## Requirements

- Node.js 22 or newer.
- Server dependencies installed: `cd server && npm install` once, before the first drill run.
- About 300 MB of free disk, mostly for `node_modules`. The drill state itself is less than 1 MB.

## Run the drill

From the repository root:

```bash
./scripts/three-mode-drill-onboard.sh
```

Typical output:

```
three-mode-drill: seeding fortress materials...
seed: fortress_id=7ad3887af47fabb6bea407c5bf3d9191
three-mode-drill: node A started (pid=..., log=.sanctuary-drill/logs/nodeA.log)
three-mode-drill: node B started (pid=..., log=.sanctuary-drill/logs/nodeB.log)
three-mode-drill: node C started (pid=..., log=.sanctuary-drill/logs/nodeC.log)
three-mode-drill: all three nodes listening. Waiting for steady state...
three-mode-drill: STEADY STATE ACHIEVED (elapsed ~2s)
  node A (local)          roster_size=3 | all peers active
  node B (operator_cloud) roster_size=3 | all peers active
  node C (sovereign_tee)  roster_size=3 | all peers active
```

Steady state on a modern Mac is about two seconds. The script then tears down the three processes and exits cleanly.

## What to look at

Before the script exits, everything is in the `.sanctuary-drill/` directory at the repo root. You can run the script once, Ctrl+C the orchestrator after it reaches steady state, and then poke around. (The processes will already be shutting down, so you are looking at the on-disk artifacts, not live state.)

```
.sanctuary-drill/
  fortress/
    public.json       Fortress-master public key, fortress-id, creation timestamp
    root-cert.json    Root principal certificate (signed by the master)
  peers.json          All three per-node certificates
  nodeA/
    node.json         Node A's id, mode, certificate
    multiaddr.txt     libp2p multiaddr A was listening on
    nodekeys/         FileNodeKeyStore (master-key-wrapped private key)
    counters/         FileCounterStore (monotonic counters)
  nodeB/ (same shape, operator_cloud mode)
  nodeC/ (same shape, sovereign_tee mode)
  logs/
    nodeA.log, nodeB.log, nodeC.log
  status/
    A.json, B.json, C.json (per-node roster snapshot the orchestrator polls)
```

A few things worth inspecting:

- Each `node.json` declares a different `mode`, but every certificate's `parent_chain.fortress_master_pubkey` matches the public key in `fortress/public.json`. That is the "all three nodes anchored to one fortress" property the protocol guarantees.
- Node C's certificate carries a `tee_attestation_hash`, nodes A and B do not. A real TEE integration replaces the mock hash with a live attestation report; the drill keeps the certificate shape intact.
- The `status/*.json` files show each node's view of the other peers. Every entry should read `active` when the drill is at steady state.

## Tear down

Everything the drill writes lives under `.sanctuary-drill/`. To clean up:

```bash
rm -rf .sanctuary-drill
```

The drill script does this automatically on each run, so a fresh invocation always starts from a clean slate.

## Known limitations of this drill

The goal is to prove the protocol on one host so an operator can see it work without spinning up real infrastructure. The drill deliberately cuts several corners that do not appear in a production Sanctuary fortress:

1. **All three processes run on 127.0.0.1.** Production places node B in a cloud region and node C on TEE hardware. The drill uses loopback so a pilot operator can run it on a laptop without provisioning any infrastructure. The wire protocol, the certificates, and the peer-id pinning are identical either way.
2. **The TEE attestation is mocked.** Node C presents a constant `tee_attestation_hash` seeded from a well-known string. Real TEE integration (GCP Confidential VMs AMD SEV-SNP, Azure Confidential Computing, or similar) produces a live measurement that a verifier rejects if the node is running tampered code. That hardware integration is Phase 2 on the product roadmap.
3. **The fortress-master and per-node seeds are written to disk unencrypted.** A production pilot generates the master inside the encrypted state store and never writes it to the filesystem; the drill writes `fortress/master.bin` and `nodeX/seed.bin` so the per-node runtime can pick them up without a passphrase prompt. Treat `.sanctuary-drill/` as ephemeral demo material, not a fortress you would actually run agents in.
4. **mDNS and the Kademlia DHT are disabled.** The drill uses static-peer discovery only. mDNS works on a real LAN and is exercised by the underlying transport tests; the drill sequences bring-up deterministically to keep the onboarding reliable.
5. **No agents are launched.** The drill proves the federation layer (nodes, certificates, roster convergence). Launching a Tier-A harness on top of the fortress is a separate WP-MVP scope.

## What to do after the drill

If this worked and you want to see the full acceptance-drill regression suite:

```bash
cd server
npx vitest run test/acceptance/three-mode-drill
```

That runs the vitest suite that powers this drill: consistency, cert-chain anchoring, policy fan-out latency, audit batch continuity across emitters, receipt replication, agent migration with locator updates, and revoke propagation. Each test boots the same three-mode mesh this script does and asserts on a specific spec property.

If you want to try a sovereign pilot on real infrastructure, the next conversation is with the Sanctuary team directly. Mention that you ran the drill.

## Troubleshooting

- **`npm install` in `server/` fails.** Make sure you are on Node 22 or newer; Node 18 is past end-of-life and some libp2p transitive deps expect newer APIs.
- **"Cannot find module tsx".** The orchestrator uses `npx tsx`; if your `npx` is configured to skip downloads, run `npm install tsx` once in `server/`.
- **Steady state never reports.** Check `.sanctuary-drill/logs/nodeA.log` and `nodeB.log` first. The most common cause is a firewall that blocks loopback TCP; on macOS, check System Settings for application-specific firewall rules and allow Node.
- **Port collisions.** The drill uses `tcp/0` so the kernel picks ephemeral ports. Real port collisions are very rare; if you see one, run the drill again.
