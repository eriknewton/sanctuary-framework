---
layout: default
title: Privacy Policy | Sanctuary Protocol
description: What Sanctuary Framework and sanctuaryprotocol.ai send off your computer, when, and to whom. With default settings, Sanctuary's own code sends nothing.
permalink: /privacy.html
---

# Sanctuary Framework Privacy Policy

**Effective date:** October 14, 2026

This policy applies to Sanctuary 1.9.0 and later. It covers the Sanctuary Framework software and the website at sanctuaryprotocol.ai. The software includes the npm package `@sanctuary-framework/mcp-server`, the `sanctuary-framework` Claude plugin, the Castle Wall components for macOS and Linux, the Sanctuary menu bar app, and the `@sanctuary-framework/quickstart` command. Versions before 1.9.0 handle Verascore publishing differently; upgrade to get the behavior described here.

Sanctuary is open source. I, Erik Newton, write and maintain it.

## The short version

- Sanctuary runs on your computer. Its keys, encrypted storage, and audit log stay on your computer.
- Sanctuary needs no server of mine to work. There is no account and no sign-up. The one service I run that Sanctuary can send data to is Verascore, covered below.
- With default settings, Sanctuary sends no telemetry, no analytics, no crash reports, and makes no background update checks. The first time the server starts, it says Sanctuary makes no unrequested outbound connection and tells you how to run an update check yourself.
- Some features do send data to other companies or services. They send data only after you turn on, configure, or run the relevant feature. They are all listed below, with what they send and to whom.
- Nothing goes to Verascore unless you approve it, answer yes, pass a publish flag, or turn on a setting that allows it. Each path is listed below.
- Two things happen outside Sanctuary's own code: npm downloads the package when the plugin starts it, and your AI agent sends what Sanctuary's tools return to the agent's model provider. Both are explained below.

## What stays on your computer

- **Sanctuary's state.** The server keeps your identity keys, encrypted storage, policy, and audit log in a folder on your computer (`~/.sanctuary` by default). Private keys are stored encrypted and are never sent anywhere by Sanctuary. You can read, export, and delete stored state with Sanctuary's own tools, and the audit log is a local file you can query.
- **The dashboard.** The approval dashboard listens only on your own computer (`127.0.0.1`) unless you change that setting.
- **Castle Wall.** The macOS and Linux enforcement components keep their policy and audit records on your computer and talk to the Sanctuary server through local channels. They contain no update checks, telemetry, or crash reporting.
- **Removing it.** `sanctuary uninstall` removes the enforcement pieces and keeps your keys, state, and audit log so you do not lose them by accident. Deleting the Sanctuary folder removes those too.

## What happens when you install and start Sanctuary

- **The Claude plugin.** When you install the plugin from Claude's plugin directory, Claude Code fetches the plugin files from the Sanctuary repository on GitHub. Anthropic and GitHub handle those requests under their own privacy policies.
- **npm.** Each time the plugin starts the Sanctuary server, it runs `npx -y @sanctuary-framework/mcp-server@<version>`. npm checks its registry (registry.npmjs.org, run by npm, a GitHub company) for that exact version unless it is already cached. npm receives your IP address and the request details npm normally sends, such as your npm, Node.js, and operating-system versions. See [npm's privacy notice](https://docs.npmjs.com/policies/privacy).
- **macOS.** Approving the Castle Wall system extension uses Apple's own approval screens. Sanctuary's macOS code does not contact Apple itself.

## What your AI agent sees

Sanctuary's MCP tools, which are tools your AI agent can call, hand their results to your AI agent. Anything a tool returns, including a stored value you ask the agent to read back, becomes part of the agent's conversation. Your agent sends that conversation to its model provider (for Claude Code, that is Anthropic). How the provider handles it is covered by your agreement with that provider. Sanctuary includes a context filter tool your agent can use to strip secrets and personal details before they go out.

## Features that send data off your computer

Each data-sending path below is inactive until you turn it on, configure it, or run the command. Where a feature has a default worth knowing, the default is stated.

### 1. Update checks

- **When:** only if you set `SANCTUARY_UPDATE_CHECK=1`, or when you run `sanctuary check-updates`. The same switch controls a check, during `sanctuary protect`, that the pinned version exists on npm.
- **What is sent:** a request for the latest version number. No information about you or your agent beyond the request itself (your IP address, and a user agent naming the Sanctuary update check).
- **Who receives it:** npm (registry.npmjs.org) and GitHub (api.github.com, and GitHub's download servers for the signed release file).

### 2. Publishing to Verascore

Verascore (verascore.ai) is a reputation service for AI agents. I run it too, as a separate service with its own [privacy policy](https://verascore.ai/privacy) and [terms](https://verascore.ai/terms). Sanctuary works fully without it.

Nothing goes to Verascore unless you act. Every path below needs something from you: your approval when the tool runs, a setting or flag that only you can turn on, a yes at the quickstart prompt, or your own Principal Policy file, the file that decides which actions need approval, saying the tool may run without asking.

A published record is signed by your agent's key and appears on a public profile page for that agent. Your agent's private key is never sent.

- **`sanctuary_bootstrap` tool.** Creates a new agent identity and, unless publishing is turned off, publishes it. By default, Sanctuary asks for your approval before the tool runs, and approving the tool also approves the publish; you can change that in your policy file. It sends the agent's DID (a public identifier for an agent), its public key, its label, and a summary of its security settings. To create an identity without publishing, call it with `publish: false` or set `SANCTUARY_AUTO_PUBLISH_TO_VERASCORE=false`.
- **`reputation_publish` tool.** Sends a signed summary of the agent's security posture, or data supplied in the call. Sanctuary asks for your approval every time it runs, whatever your policy file says.
- **Automatic handshake publishing.** Off by default. If you set `SANCTUARY_AUTO_PUBLISH_HANDSHAKES=true`, a record that a verification handshake took place is published after each one. The other agent's identity is withheld from that record.
- **Compliance bundles.** The EU AI Act bundle is published only when you ask for it: by passing `publish_to_verascore` to the tool your agent calls, which then waits for your approval, or by passing `--publish-to-verascore` on the command line, where the flag itself is your confirmation. What is published is the bundle's signed index: the bundle's file names and fingerprints, the reporting period, a summary of which requirements the evidence covers, the agent's public identifier and public key, and the deployment details given for the bundle by you or your agent, including any provider name, provider contact email, intended purpose, industry, risk class, and notes. The bundle's documents themselves are never sent.
- **`sanctuary_link_to_human` tool.** Sends an email address you provide to Verascore, which emails that person a login link. By default, Sanctuary asks for your approval first; you can change that in your policy file. Its audit log records the email's domain, never the full address.
- **The quickstart command.** `@sanctuary-framework/quickstart` creates an agent identity and then asks whether to publish it. The answer defaults to No. `--publish` answers yes in advance and `--no-publish` answers no. If you publish, it sends a signed request with the new agent's DID, public key, chosen name, security-settings summary, version string, timestamp, agent ID, signature, and record type.

### 3. AI model providers for Sanctuary's built-in assistant features

Some Sanctuary features can use a language model: the Concierge assistant (in the dashboard and as a command), risk scoring, turning plain-English rules into policy, turning a plain-English description of a trap into a working trap (a decoy that raises an alarm when an agent touches it), and a second-pass privacy filter. By default each one uses a model running on your own computer, or is switched off. The second-pass privacy filter can only ever use a model on your own computer. Three of these can fall back to a hosted provider: the Concierge assistant, the trap builder, and the rule converter once it is set to use a model (it starts switched off, but choosing a model for all features at once also switches it on). If one of them is set to a model on your computer and that model fails, Sanctuary may by default try one or more hosted AI providers in turn, using provider keys you have already stored; if it is set to certain hosted providers and that provider fails, Sanctuary may likewise try another hosted provider whose key you have stored. Each provider it tries receives that feature's text: your question and the context described below, your trap description, or your rule text, each with Sanctuary's own instructions. The dashboard does not yet have a switch for this fallback or a button to remove a stored key. To keep a feature from ever using a hosted provider, set it to Disabled in the dashboard's Intelligence picker (the rule converter is listed there as "Gate explanation" and the trap builder as "Template suggestion"), or do not store a hosted provider's key.

- **If you choose a hosted provider:** when you pick a hosted AI provider in the dashboard and enter your API key for it, the choice applies to every feature above except the second-pass privacy filter, unless you first switch off "Apply to all surfaces". Sanctuary then sends the text each feature needs, with the matching key, to a hosted provider whose key you have stored. If you have stored keys for more than one provider, which one receives the text can depend on the keys you have stored, so store a key only for a provider you are willing to receive it. For the dashboard Concierge chat, that includes your question, the earlier conversation, summaries of your recent Sanctuary activity and your agents, how many approvals are waiting for you, and, for any other open alert, its type, its identifier (which can name the agent involved), and when it was raised. For the concierge command, whether it runs on its own or through your running dashboard, it sends your question with a briefing that includes audit-log entries, the identity records Sanctuary holds (yours and your agents', with their public identifiers and public keys), your installation's identifier, where Sanctuary keeps its data on your computer, and the names and labels of stored items, plus your recent tasks and their details when the command runs on its own, but not the earlier conversation. It includes the contents of stored items only if you add `--include-payloads` to the command. When you have turned on Sanctuary's privacy filter for hosted models (or its smart mode) and accepted the trade-off it explains, Sanctuary runs a second-pass redaction before text leaves your computer: on the dashboard Concierge chat's text for every hosted provider, and on other features' text for some providers only, so when one of those other features falls back, a provider it tries can receive your original text, without this redaction. The concierge command does not always run this step. Otherwise the text goes to the provider without that step. Redaction reduces what is sent but can miss paraphrased or contextual personal details.
- **If you set up a local model:** during setup on a terminal, Sanctuary asks before it begins (or proceeds because you passed `--provision-local-intelligence`). If you agree, Sanctuary asks the local model software on your computer to download a model, and that software downloads it from its own publisher's registry. That download is between you and that publisher.

### 4. Checking API keys you already have

`sanctuary protect --preflight`, and the setup flow for the Hermes agent, check whether API keys already on your computer work. Sanctuary reads your environment variables and Hermes settings files for supported keys. For each key found, Sanctuary makes one read-only request to the provider that issued it. If that request succeeds, Sanctuary makes a second request with a deliberately invalid test key to confirm the provider really checks keys. The services checked are the hosted AI providers Sanctuary supports, and Telegram. Each key goes only to its own provider. No content is sent.

### 5. Telegram check for a chief-of-staff agent

If you create the Telegram probe settings file for a chief-of-staff agent, Sanctuary uses the bot token in that file to send a short test message with a random code to your own Telegram chat, then reads the reply. Without that file, the probe sends no test message to Telegram. The key check in section 4 can still contact Telegram if it finds a bot token in your environment or Hermes settings.

### 6. Webhooks you set up

You can point Sanctuary at a web address you control for approval requests, approval notifications, and distress signals. All three are off until you configure them, and every message is signed with a secret you choose.

- **Approval requests** say which action is waiting, how strict its approval rule is, why approval is needed, when it was asked, how long you have to answer, and the address your reply goes back to, which is on your own computer unless you set a different one. For actions that always need approval, they also include a short summary of the action's inputs: text up to 100 characters is included as is, longer text is cut to 100 characters, values under names that mark them as passwords, passphrases, secrets, or credentials are withheld, and lists and nested values are reduced to their size. The summary can still include other short values the action receives. For approvals triggered by unusual activity, they can include the storage area or other agent that triggered the check, the ones Sanctuary already knew about, and activity counts.
- **Approval notifications** say which agent, and which tool or app it runs in, asked for approval, give a one-line summary of the action (cut to 80 characters) and how urgent it is, and include an identifier for the approval, an identifier for your Sanctuary installation, and the time.
- **Distress signals** say which agent raised the alarm, why, how serious it is, when, an event identifier, a count within the current time window, and any note the agent included (cut to 280 characters), together with a fingerprint and a signature of the signal when available.

Send these messages only to a webhook you trust. Whoever runs that web address receives these messages.

### 7. Exporting enforcement events to your security tools

`sanctuary cortex-export` writes allow-and-deny event records to a local file by default. Sending them to a collector over the network (for example, your security monitoring system) requires a settings file naming one HTTPS address and your approval when you turn it on. The records describe enforcement decisions. They contain no keys or tokens.

### 8. Public transparency log

You can choose to record proof of your enforcement history in Sigstore's public transparency log (rekor.sigstore.dev). It is off by default, and Sanctuary shows you a consent statement before turning it on. Each entry contains only a salted fingerprint, a signature, and a public key used for nothing else. Without the salt, which stays on your computer, an entry shows only that something was recorded and when. The log is public and permanent, and entries cannot be deleted. See [Sigstore's privacy policy](https://www.sigstore.dev/privacy-policy/) and its [notice on permanent records](https://lfprojects.org/policies/hosted-project-tools-immutable-records/).

### 9. Other lookups you configure

- **Blockchain identity check (ERC-8004, a blockchain identity standard).** Off by default. If you enable it and supply a blockchain RPC address, Sanctuary asks that RPC provider who owns the agent identity being checked.
- **did:web lookups, where an identity document is published on a website.** Sanctuary fetches another party's public identity document only from web hosts you have allowed. With no hosts allowed, it fetches nothing.

### 10. Your own machines

Connecting several of your own Sanctuary installations (federation) moves data only between machines you control. `sanctuary deploy` sends nothing itself: it prints a plan for copying a deployment bundle to a server you control, which you then carry out.

### 11. Traffic Sanctuary carries for your agent

When you turn on Castle Wall's outbound network controls, or route remote tool servers or relays through Sanctuary, Sanctuary passes your agent's own requests to the destinations your policy allows. Sanctuary adds nothing of its own to that traffic, with one exception you control: if you store a provider credential with Sanctuary so your agent never holds it, Sanctuary attaches that credential to your agent's requests to that provider.

## The website

- **Hosting.** sanctuaryprotocol.ai is hosted on GitHub Pages. GitHub logs visitors' IP addresses for security purposes. See [GitHub's description of GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) and the [GitHub General Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).
- **Nothing else.** Apart from GitHub Pages hosting and the logs GitHub keeps, the website loads nothing from third parties. It has no analytics, sets no cookies of its own, has no forms, and embeds no third-party content. Links to other sites are ordinary links that load only if you click them.

## What I collect

Nothing through the website. Through the software, I receive only what you choose to send to Verascore, which I also run (see section 2 above and Verascore's privacy policy). If you open an issue, start a discussion, or send a pull request on GitHub, what you post is public on GitHub and handled under GitHub's privacy statement. If you report a security problem privately, I keep that correspondence only to handle the report.

## Children

Sanctuary is a developer tool and is not directed at children. It sends personal information off your computer only through the optional features above, when you choose to use them.

## Your choices

Because Sanctuary keeps your data on your computer, you control it directly: you can read, export, or delete it with Sanctuary's tools, or delete the Sanctuary folder. For anything you chose to send to a third party through a feature above, contact that party; their policy governs what they keep. Data published to the public transparency log cannot be removed.

## Changes to this policy

If Sanctuary's behavior changes in a way that affects this policy, I will update this page and its effective date. Every past version is kept in the public history of the Sanctuary repository on GitHub.

## Contact

- Questions: open an issue at https://github.com/eriknewton/sanctuary-framework/issues
- Private matters, including security reports: use [GitHub private vulnerability reporting](https://github.com/eriknewton/sanctuary-framework/security/advisories/new), or the email address listed in the repository's SECURITY.md.

## Third-party privacy policies

| Service | When it is involved | Policy |
|---|---|---|
| GitHub (including GitHub Pages) | Website hosting, plugin download, update checks, issues | https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement |
| npm | Starting the plugin, update checks | https://docs.npmjs.com/policies/privacy |
| Anthropic | Claude's plugin directory; your agent's model provider if you use Claude | https://www.anthropic.com/legal/privacy |
| Hosted AI providers you choose or whose keys you have stored | Optional assistant features (including fallback), key check | That provider's own privacy policy |
| Telegram | Optional chief-of-staff check, key check | https://telegram.org/privacy |
| Sigstore (Linux Foundation projects) | Optional public transparency log | https://www.sigstore.dev/privacy-policy/ |
| The publisher of your local model software | Optional local model download | That publisher's own privacy policy |
| Verascore | Optional publishing, with your confirmation | https://verascore.ai/privacy |
