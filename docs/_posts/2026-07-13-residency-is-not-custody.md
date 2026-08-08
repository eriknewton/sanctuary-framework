---
title: "Residency Is Not Custody"
date: 2026-07-13
description: "Microsoft's CEO says data location was never the point. He's right. The test for AI security is custody: who holds the keys, what enforces the deny, and who can edit the record. Three questions, and the drill evidence behind ours."
author: "Erik Newton"
image: /images/blog/residency-not-custody-card.png
---

Everyone suddenly agrees with us. Microsoft's CEO says data location was never the point. The biggest security company in the world ships "sovereign" AI for Europe. They're both circling the same truth. Neither of them can land on it.

Here's the truth: **where your data sits was never the question. Who can act without your permission is.**

## The week the word broke

Satya Nadella just told the world that sovereignty "requires real thought on what it is," that control of destiny means preserving your ability to produce something unique, and that the real risk isn't where data lives but the quiet leakage of the intelligence built on it. He's right. That essay is the most important thing an incumbent has said about this problem, and I mean that without irony.

Palo Alto Networks ships Sovereign Cortex for European regulated industries this quarter. Read the fine print and you'll find something honest and revealing: the encryption keys are held by Deutsche Telekom. Not by Palo Alto. Not by Google. And not by you.

That's progress. It's also the tell.

The entire industry has converged on one move: take the keys away from the American cloud and hand them to someone closer to you. A telco. A national provider. A "trusted partner."

Your keys still belong to someone else. The someone changed.

## The test that actually matters

Strip away the marketing and every "sovereign AI" offering answers three questions. Ask them about anything you're evaluating, including us:

1. **Can the vendor read your data?** Not "does the vendor promise not to." Can they, structurally?
2. **Can your agent act after you said no?** When the policy says deny, is that a suggestion the software makes to itself, or a wall the operating system enforces?
3. **Can anyone edit the record of what happened?** If the answer is yes, you don't have an audit trail. You have a diary someone else can rewrite.

Residency answers none of these. A data center in Frankfurt with someone else's keys is a promise with better geography.

Custody answers all three. Custody means the keys are generated on your hardware and never leave it. It means the deny is enforced below the agent, at the kernel, where a prompt-injected agent can't talk its way past it. It means the log is hash-chained so that tampering is detectable under strict verification. Production audit checkpoints are currently unsigned, and `audit-chain verify --no-strict` can return PASS with findings.

Residency is a location. Custody is a power relationship. The industry keeps selling you the first and calling it the second.

## This isn't hypothetical

Last August, the s1ngularity supply-chain attack turned developers' own AI agents into burglars. The malicious package didn't defeat anyone's security. It asked the agents nicely, with their own permission flags, and thousands of private repositories walked out the door.

Every one of those agents was running on somebody's machine. Residency: perfect. Custody: none.

The agent vendors know this. Anthropic open-sourced its sandboxing and told the ecosystem to adopt it. Microsoft is building agent containment into Windows itself. When the platforms start shipping cages, the argument is over: agents need walls. The question they leave open, every single one of them, is who holds the keys to the wall. The platform's answer is always the same: we do, trust us. Which is the exact answer that created this problem.

## What we built, and what we can prove

Sanctuary is operator custody at the agent runtime. Not a promise. A mechanism, and we publish the evidence.

On Linux: kernel-level egress enforcement, shipped in May, with the bypass paths you'd actually try (plain DNS, DoH, DoT) covered by integration tests against a real kernel binding.

> **Current correction, 2026-08-07:** the integration-test coverage is real; the
> word "shipped" was wrong. The shipped Linux daemon does not install the
> nftables table, bind NFQUEUE, create cgroup scopes, or call the deny-by-default
> evaluator, so Linux is source coverage rather than enforcement an operator can
> run. The macOS evidence in the next paragraph is unaffected. Open defect:
> **IC-02, IC-03, IC-04** (`docs/audit/inert-capability-register.md`).
>
> Audit correction, 2026-08-07: earlier versions described the log as "signed
> and chained," which was too broad. Sanctuary's production audit log is hash-chained, but production boot
> paths do not supply a checkpoint signer, so production checkpoints are written
> unsigned. Strict verification detects tampering, while `audit-chain verify
> --no-strict` can return PASS with findings. Open defect: **IC-05, IC-06**
> (`docs/audit/inert-capability-register.md`).

On macOS: a signed and notarized system extension enforcing a signed operator policy. In June we drilled it on real hardware: the agent's account blocked from a non-allowlisted destination, reaching its allowlisted one, the operator's account untouched, in the same armed window. Then we rebooted the machine through five attended cycles. The wall came back up every time within the proven scope.

And here's what we have not proven yet, because claims without limits are how this industry got here: that evidence covers one host and one OS version so far, and the per-flow, rule-attributed audit trail is still being built. It's the top item on our public roadmap. When it lands, "the wall blocked it" becomes "this rule blocked this flow, provably." You'll see the drill logs when it does.

Show me another vendor that publishes the boundary of their own claims. That discipline is the product.

## Ask the question

If you're evaluating "sovereign" AI this year, you don't need our software to benefit from this post. Just ask the three questions. Ask who holds the keys. Ask what enforces the deny. Ask who can edit the log.

If the answer to any of them is a company name that isn't yours, you've found the residency trick.

Your agent. Your machine. Your keys. That's custody. Everything else is a nicer landlord.

Erik
