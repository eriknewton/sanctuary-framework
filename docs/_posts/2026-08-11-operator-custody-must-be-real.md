---
title: "Operator Custody Must Be Real. Let the Agents Spend."
date: 2026-08-11
description: "Three tests separate real key custody from custody theater: unilateral export, a working exit, and no provider-side signing path. Run them yourself. Then let the agents spend."
author: "Erik Newton"
image: /images/blog/operator-custody-card.png
---

The agent-wallet conversation landed on the right question this summer: who controls the keys. I've been barking up this tree long enough that people were starting to worry about me. It's nice to have company.

The question that matters is simple: does the user or the provider control the keys? Everything else is theater.

Notice how "user control" appears in basically every product description these days. The concept finding its way into marketing means people care and that it matters. It also means people are getting snowed by jargon. "Control" is the operative word, and it means very different things to a marketer and to a user operating critical infrastructure. As users we need to dig into what control means in every instance. The answer tells us everything we need to know about a provider's business model and true intentions.

My strong assertion: users deserve as much control and autonomy as they want. Some may want their service providers to hold the keys; others, like law firms and financial services providers, may need full sovereignty over their client data and business logic. I'm agnostic between the two so long as each of us has a real and transparent choice. Providing that choice isn't easy, but it can be done.

Here's the test you can apply yourself to know whether you have real control or control theater.

## 1. The signing key is exportable, by you, unilaterally

You can produce the private key material, or an equivalent recovery secret, in a portable format, on your own machine, with no support ticket and no dependency on the provider's servers being up. The test is concrete: export the key, restore it on hardware the provider has never seen, and sign something. If any step requires the provider's permission or the provider's availability, they hold the key and you hold a login. It's that simple. My bet is most services fail at this first step.

## 2. There is a working exit door, and it opens on your timeline

You can leave with your state, your history, and your agent's record, without notice and without anyone's permission. Simple. Does it work or doesn't it? An exit that exists only in the terms of service is a promise, and that promise evaporates the day the provider changes its pricing, its policies, or its owners. You've got to test this one rather than trust the documentation, because exit lives or dies in the details. Try unsubscribing from the New York Times if you want to know what exit theater feels like.

## 3. Either the provider can sign on your behalf, or it can't

This is the requirement that marketing language most often hides. If the provider can rotate your key, recover your account, or execute transactions "on your behalf" while you are away, then a signing path exists on their side of the fence, whatever the architecture diagram says. A provider that can restore your access without you can also act without you. That provider can see your data and your business logic, and can delete your account. Beware.

Enclave-based custody deserves special mention here, not least because a hosted TEE mode is on Sanctuary's own roadmap. Remote attestation proves which software is running inside a secure enclave. It proves nothing about who is entitled to command that software. That is why our planned use points the proof in the opposite direction: the hardware attests to the operator that the host cannot see inside, while the keys and the right to command stay with the operator. A key that lives in the provider's enclave, commanded through the provider's API, under the provider's account system, is provider custody with better hardware. Some products in this category describe themselves as non-custodial. Are they really, though? Apply test one and test three before accepting the label.

## Let the agents spend

We're all obviously going to give agents wallets. And we should. We just need to do it well so they don't spend us into oblivion. And doing it well isn't hard in principle. Delegation done well follows directly from the three requirements above. The operator holds the master key. The agent receives an allowance: a scoped, revocable grant that narrows at each hop and can be verified offline against a root the operator controls. The agent can act within the allowance and can do nothing outside it. At no point does the agent (or the provider) hold the thing that makes its operator sovereign. The emerging delegated-authority work in the standards community, with its emphasis on attenuation and offline verification, points the same direction.

## Why we hold this bar

This bar comes from the Seven Principles of Sovereignty, the framework Sanctuary is built on: custody is principle two, exit is principle six, and the boundary that keeps an agent inside its allowance is principle one. I defined custody in the residency piece last month and the definition has not moved. The delegated-wallet literature arriving at the same structure independently is good news. A bar that different people keep discovering from different starting points is probably a real one, and more likely a durable one. We're on the right track, and we need to keep pushing forward.

So, three questions for any provider of agent custody:

1. Can I export the signing key myself, right now, without you?
2. Can I leave with my record, verify it offline, and stand it up elsewhere?
3. Does any path exist by which you can sign, rotate, or recover without me?

Yes, yes, and no, with evidence you can check yourself, is custody. Anything else is custody theater.

Sanctuary is built to hold this bar at its root. Don't take my word for it; ask it the three questions.

Let the agents spend, and prosper.
