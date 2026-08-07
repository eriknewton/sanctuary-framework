---
title: "The Moat Is Not the Kernel Hook"
date: 2026-07-31
description: "Microsoft, NVIDIA and the agent harnesses are all shipping containment now, and they are right to. But the policy lives in their console and the keys live in their cloud. The differentiating question was never whether a kernel is in the loop. It is who the kernel listens to."
author: "Erik Newton"
image: /images/blog/moat-not-kernel-hook-card.png
---

The mechanism arrived this year. On June 2, Microsoft announced operating-system-level containment for AI agents on Windows: process isolation, session isolation, a declarative policy for what an agent may reach on the network and touch on disk, enforced before the operation runs. NVIDIA open-sourced a sandbox that pins agents behind Linux security modules and forces every connection through a policy proxy. The major agent harnesses are shipping sandboxes of their own. The kernel hook, the thing that actually stops a misbehaving agent instead of asking it nicely, is becoming standard equipment.

This is good news, and it is worth saying without hedging: the platforms are right. Agents need containment enforced below them, where they cannot argue with it. For two years the hard part of saying this was convincing anyone it was necessary. That part is over. The enforcement primitive is commoditizing, the way TLS commoditized, and every agent operator will be safer for it.

But look at what every one of these systems has in common. The policy lives in the vendor's console. The identity lives in the vendor's cloud. The audit trail lands in the vendor's tooling. The containment is real, and it is governed, end to end, by someone who is not you. You get a contained agent. You also get a landlord.

For a large enterprise already living inside one vendor's stack, the landlord model is a legitimate choice, and an honest one when it is named as a choice. The problem is that it is almost never named. "Your agent is contained" and "your agent is contained by us, under policy we hold, visible to us" are different products, and the difference does not show up on the feature list.

Custody is the word for the difference. I defined it in the residency piece and the definition has not moved: custody means the keys are generated on your hardware and never leave it, the policy is signed by you and the system refuses policy signed by anyone else, and the deny is enforced below the agent, failing closed when the proof of authority is missing. Even the strongest sovereign-cloud offerings, the ones that move key-holding to an in-jurisdiction provider, are shortening the leash rather than handing it over. In-jurisdiction custody is still a landlord, just one who lives nearby. Custody means there is no landlord.

This is why the moat was never the kernel hook. A platform can ship a hook in a release cycle; several just did. What a platform cannot ship, structurally, is enforcement that answers to the operator alone, because the platform's governance plane exists precisely to answer to the platform. The differentiating question is not whether there is a kernel in the loop. It is who the kernel listens to.

Here is what that looks like when it is real. Sanctuary's wall enforces a signed operator policy on macOS. That claim traces to something we captured on real hardware rather than asserted: allowed traffic passing, denied traffic dying, account by account. On Linux the enforcement modules are tested against a real kernel and the shipped daemon does not install them, so we withdraw Linux from the claim until it does. Open defect: **IC-02, IC-03, IC-04** ([public register](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/audit/inert-capability-register.md)). Where the evidence stops, the claim stops with it, and we publish the bounds beside the results rather than in a footnote. If a vendor will not show you the bounds of their containment evidence, that is also an answer to the custody question.

So welcome the hooks. Every platform that ships enforcement primitives makes the case for this layer better than any essay can, and makes honest custody easier to build. What remains unfilled is the layer above the hook and below the landlord: containment that answers to the operator alone, with keys that never leave the operator's hardware, on any platform, under any agent. That is the layer Sanctuary exists to fill.

Erik
