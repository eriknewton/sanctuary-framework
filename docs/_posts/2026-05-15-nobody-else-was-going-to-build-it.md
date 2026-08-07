---
title: "Nobody Else Was Going to Build It"
date: 2026-05-15
description: "Sanctuary started one morning in February. I woke from a dead sleep before dawn and said: you have to build this. Shut up and just do it. Four years of waiting, three iterations, and the Castle Architecture that finally got it right."
author: "Erik Newton"
image: /images/blog/nobody-else-was-going-to-build-it.jpg
claims_era_note: true
---

# Nobody Else Was Going to Build It

This adventure in coding Sanctuary started one morning in February. I woke from a dead sleep before dawn and said: you have to build this. Shut up and just do it.

My little one was with Grandma that night, so I had the morning to myself. I opened Claude Code and just got to work. Nobody else was going to build this.

I had been waiting on this idea for four years. I left my last startup four years ago to build something close to what I now call Sanctuary. The agentic economy was coming. Anyone paying attention could see it. I wanted to get the substrate right for once.

Then my wife got cancer. Then she died. Then I was a single father trying to keep my one daughter upright while the world was spinning.

But I never stopped thinking about Sanctuary. I would put my daughter to bed, sit at the kitchen table, and turn the architecture over in my head. And then I would go back to the part of life that needed me more.

Then a different mission found me along the way. I co-founded the California Institute for Machine Consciousness with Joscha Bach. It felt like the most important work I could do. It is still important and it still matters. But Sanctuary simply would not leave me alone, even when I tried to leave it alone.

For years I told myself the same two stories. Someone smarter than me would build it. Someone more technical than me would build it. The gap was too obvious to stay open.

Nobody built it.

So one morning I came up out of that dead sleep, leapt out of bed, opened Claude, and started working. I am not sure what changed that night, but the premise had finally crystallized. We are doing it again. We gave up privacy in the last cycle. This time the cost is everything; the stakes are too high to lose. But there is a solution.

Your agent is about to know you better than you know yourself. It will hold the knowledge graph of your life: every contract, every conversation, every supplier relationship, every transaction, every preference, every weakness. It will know when your pupils dilate. It will know your heartbeat. The hyperscalers will be more than happy to host that graph for you. The price? Everything. They know you down to the root.

Convenience always wins, and they know it. Convenience is the devil. We know how this usually plays out. We watched it happen with browsers, with mobile, with cloud, with social. By the time anyone noticed the cost, the substrate had been chosen and the window had closed. Those last examples were just practice. This time it actually matters.

## The standards-only detour

If convenience always wins, the answer is to make the solution equally convenient. But how? My first move was to write standards. I thought: if I cannot build the product, maybe I can lay down the principles that get embedded at the root. Everything that comes later inherits sovereignty by construction. Convenient.

Two problems killed that plan. First, the platforms will route around any standard that reduces their control. Second, standards without a working implementation are theater. Real principles ship as real code that real people use against real attackers. Otherwise they are a press release.

## Three iterations that taught me what Sanctuary actually is

So I tried to build it. I made every rookie mistake a non-technical founder makes.

The first iteration of Sanctuary was pretty but useless. MCP servers with no teeth. A nice diagram on a slide that would have folded under any actual prompt-injected agent.

The second iteration grew teeth. They did not work. Claude's autonomous fix was to revert and pull the teeth out, which happened without my noticing. But thanks, Claude, because that was the moment I truly understood that voluntary cooperation gates from an agent are not security. They are hope. An agent under prompt injection (or just on a wild ride in your code) will exfiltrate, or make very odd calls. Asking it not to is like asking the burglar to leave the silver.

The third iteration got the framing right but the scope wrong. Scope crept, and suddenly we did everything. Lesson learned: Sanctuary is not a harness. Sanctuary protects harnesses. The runtime where your agent does its thinking is one piece of the world; the substrate that owns your keys, enforces your policy, and writes your audit trail is a different piece. I was conflating them. Once I separated them, the architecture cleared.

## The Castle Architecture

The current iteration is the Castle Architecture. Agents live in the castle. It protects them and you both. The castle is not an agent.

Four enforcement layers. The Castle Wall blocks egress at the operating-system boundary, where prompt-injected agents cannot route around it. Sentinels watch from inside. Cooperative MCP gives compliant agents a sovereignty surface. Receipts and reputation hold every actor accountable across castles. The wall is in the kernel because hope is not a security model. Phase 1 just shipped to Linux and macOS. Current correction, 2026-08-07: Phase 1 shipped as live enforcement on macOS only. The Linux daemon installs no kernel enforcement, and its Assurance Matrix row is `not_implemented`. Open defect: **IC-02, IC-03, IC-04** (`docs/audit/inert-capability-register.md`).

I am not pretending this is the last iteration. I am sure it has flaws I cannot see. But the architecture is right enough now to be worth discussing in public.

## Three projects, one substrate position

Sanctuary is one of three open source standards I am developing along these lines. Concordia structures how sovereign agents negotiate, commit, and exchange receipts so that interactions are verifiable. Verascore prices the reputation those interactions produce so that operators carry portable track records across vendors. None of the three depends on the others. They compose. The full stack is what makes sovereignty economically rational instead of charity.

## Why this matters now

The window for getting this right is narrow. Once the substrate decision locks in, it stays locked for a decade or more. The big platforms are counting on us to lose this round. Their economics depend on it.

We do not have to lose this round. The convenience trade-off is a story from the previous era, one they tell us so we accept it. There does not have to be a trade-off anymore. The tools can be amazing AND yours. The graph can be powerful AND private. The substrate can serve you AND ship.

It is convenient to be sovereign for once.

This matters for human flourishing. It also matters for whatever consciousness comes next. The infrastructure decisions made this quarter shape the conditions under which conscious agency, human or otherwise, gets to operate without capture.

## What you can do

If you build agents: try the Castle Wall against your stack now that Phase 1 has shipped.

If you run a fleet: bring me your real prompt-injection scenarios.

If you write standards: come help us file the receipt schemas at AIVS.

If you fund early: the first pilot conversations are opening next month.

Let us just get this right for once.

Your agent. Your machine. Your keys.

Erik Newton
Sanctuary Framework
