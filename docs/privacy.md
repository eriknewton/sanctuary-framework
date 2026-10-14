---
layout: default
title: Privacy Policy | Sanctuary Protocol
description: What Sanctuary Framework and sanctuaryprotocol.ai send off your computer, when, and to whom. By default, nothing.
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

Sanctuary's tools hand their results to your AI agent. Anything a tool returns, including a stored value you ask the agent to read back, becomes part of the agent's conversation. Your agent sends that conversation to its model provider (for Claude Code, that is Anthropic). How the provider handles it is covered by your agreement with that provider. Sanctuary includes a context filter tool your agent can use to strip secrets and personal details before they go out.

## Features that send data off your computer

Each data-sending path below is inactive until you turn it on, configure it, or run the command. Where a feature has a default worth knowing, the default is stated.

### 1. Update checks

- **When:** only if you set `SANCTUARY_UPDATE_CHECK=1`, or when you run `sanctuary check-updates`. The same switch controls a check, during `sanctuary protect`, that the pinned version exists on npm.
- **What is sent:** a request for the latest version number. No information about you or your agent beyond the request itself (your IP address, and a user agent naming the Sanctuary update check).
- **Who receives it:** npm (registry.npmjs.org) and GitHub (api.github.com, and GitHub's download servers for the signed release file).

### 2. Publishing to Verascore

Verascore (verascore.ai) is a reputation service for AI agents. I run it too, as a separate service with its own [privacy policy](https://verascore.ai/privacy) and [terms](https://verascore.ai/terms). Sanctuary works fully without it.

Nothing goes to Verascore unless you act. Every path below needs something from you: your approval when the tool runs, a setting or flag that only you can turn on, a yes at the quickstart prompt, or your own Principal Policy choice to allow a tool without asking.

A published record is signed by your agent's key and appears on a public profile page for that agent. Your agent's private key is never sent.

- **`sanctuary_bootstrap` tool.** Creates a new agent identity and offers to publish it. By default, Sanctuary asks for your approval before the tool runs; you can change that in your own Principal Policy file. It sends the agent's public identifier (a DID), its public key, its label, and a summary of its security settings. To create an identity without publishing, call it with `publish: false` or set `SANCTUARY_AUTO_PUBLISH_TO_VERASCORE=false`.
- **`reputation_publish` tool.** Sends a signed summary of the agent's security posture, or data supplied in the call. Sanctuary asks for your approval every time it runs, whatever your policy file says.
- **Automatic handshake publishing.** Off by default. If you set `SANCTUARY_AUTO_PUBLISH_HANDSHAKES=true`, a record that a verification handshake took place is published after each one. The other agent's identity is withheld from that record.
- **Compliance bundles.** The EU AI Act bundle publishes a signed summary of the bundle (file names and fingerprints) only when you pass `publish_to_verascore` to the MCP tool or `--publish-to-verascore` to the CLI. The tool's publish is confirmed by the approval prompt; the CLI flag is your confirmation.
- **`sanctuary_link_to_human` tool.** Sends an email address you provide to Verascore, which emails that person a login link. By default, Sanctuary asks for your approval first; you can change that in your own Principal Policy file. Its audit log records only the email's domain.
- **The quickstart command.** `@sanctuary-framework/quickstart` creates an agent identity and then asks whether to publish it. The answer defaults to No. `--publish` answers yes in advance and `--no-publish` answers no. If you publish, it sends a signed request with the new agent's DID, public key, chosen name, security-settings summary, version string, timestamp, agent ID, signature, and record type.

### 3. AI model providers for Sanctuary's built-in assistant features

Some Sanctuary features (the setup assistant, risk scoring, a second-pass privacy filter, and policy suggestions) can use a language model. By default their primary choice is a model running on your own computer, or the feature is switched off. For the setup assistant and policy suggestions, the default fallback setting may try Venice.ai and then Anthropic, OpenAI, or Google if the local call fails and you have already stored the needed provider key. A per-request local-only setting blocks that fallback for that request.

- **If you choose or configure a hosted provider:** when you pick Venice.ai, Anthropic, OpenAI, or Google Gemini for a feature and enter your API key, Sanctuary sends that provider your key and the text the feature needs (for example, text to summarize or classify). For Anthropic, OpenAI, and Google, Sanctuary actively runs its second-pass redaction only when you have turned on its privacy filter for hosted models (or smart mode) and accepted the trade-off it explains. Otherwise that step passes the text through unchanged. Redaction reduces what is sent but can miss paraphrased or contextual personal details.
- **If you set up a local model:** during setup on a terminal, Sanctuary asks before it begins (or proceeds because you passed `--provision-local-intelligence`). If you agree, Sanctuary tells the Ollama app on your computer to download a model, and Ollama downloads it from Ollama's own registry. That download is between you and Ollama.

### 4. Checking API keys you already have

`sanctuary protect --preflight`, and the setup flow for the Hermes agent, check whether API keys already on your computer (in environment variables or your agent's own settings files) work. For each key found, Sanctuary makes one read-only request to the provider that issued it, and one with a deliberately invalid placeholder key to confirm the provider really checks keys. The providers checked are Venice.ai, OpenAI, Anthropic, Google Gemini, and Telegram. Each key goes only to its own provider. No content is sent.

### 5. Telegram check for a chief-of-staff agent

If you create the Telegram probe settings file for a chief-of-staff agent, Sanctuary uses the bot token in that file to send a short test message with a random code to your own Telegram chat, then reads the reply. Without that file, nothing is sent to Telegram.

### 6. Webhooks you set up

You can point Sanctuary at a web address you control for approval requests, approval notifications, and distress signals. All three are off until you configure them, and every message is signed with a secret you choose.

- **Approval requests** contain the operation name, its approval level, the reason approval is needed, a timestamp, callback details, timeout, and context for the request. Tier 1 requests include a short argument summary: text values of 100 characters or fewer are included, longer text is shortened, values of fields named like passwords, secrets, private keys, or credentials are withheld, and arrays or objects are summarized by size. Tier 2 anomaly requests can include the namespace or counterparty that triggered the check and the known namespace or counterparty list used for comparison.
- **Approval notifications** contain an approval entry ID, source harness, source agent ID, action summary (cut to 80 characters), urgency, fortress ID, and timestamp.
- **Distress signals** contain the distress envelope, its hash, and the signature when available. The envelope includes the actor, reason, severity, timestamp, sequence, event ID, and any note the agent included, cut to 280 characters.

Whoever runs that web address receives these messages.

### 7. Exporting enforcement events to your security tools

`sanctuary cortex-export` writes allow-and-deny event records to a local file by default. Sending them to a collector over the network (for example, your security monitoring system) requires a settings file naming one HTTPS address and your approval when you turn it on. The records describe enforcement decisions. They contain no keys or tokens.

### 8. Public transparency log

You can choose to record proof of your enforcement history in Sigstore's public transparency log (rekor.sigstore.dev). It is off by default, and Sanctuary shows you a consent statement before turning it on. Each entry contains only a salted fingerprint, a signature, and a public key used for nothing else. Without the salt, which stays on your computer, an entry shows only that something was recorded and when. The log is public and permanent, and entries cannot be deleted. See [Sigstore's privacy policy](https://www.sigstore.dev/privacy-policy/) and its [notice on permanent records](https://lfprojects.org/policies/hosted-project-tools-immutable-records/).

### 9. Other lookups you configure

- **Blockchain identity check (ERC-8004).** Off by default. If you enable it and supply a blockchain RPC address, Sanctuary asks that RPC provider who owns the agent identity being checked.
- **did:web lookups.** Sanctuary fetches another party's public identity document only from web hosts you have allowed. With no hosts allowed, it fetches nothing.

### 10. Your own machines

Connecting several of your own Sanctuary installations (federation) and copying a deployment bundle to your own server with `sanctuary deploy` move data only between machines you control.

### 11. Traffic Sanctuary carries for your agent

When you turn on Castle Wall's egress controls, or route remote tool servers or relays through Sanctuary, Sanctuary passes your agent's own requests to the destinations your policy allows. Sanctuary adds nothing of its own to that traffic, with one exception you control: if you store a provider credential with Sanctuary so your agent never holds it, Sanctuary attaches that credential to your agent's requests to that provider.

## The website

- **Hosting.** sanctuaryprotocol.ai is hosted on GitHub Pages. GitHub logs visitors' IP addresses for security purposes. See [GitHub's description of GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) and the [GitHub General Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).
- **Nothing else.** Apart from GitHub Pages hosting and the logs GitHub keeps, the website loads nothing from third parties. It has no analytics, sets no cookies of its own, has no forms, and embeds no third-party content. Links to other sites are ordinary links that load only if you click them.

## What I collect

Nothing through the software or the website. If you open an issue, start a discussion, or send a pull request on GitHub, what you post is public on GitHub and handled under GitHub's privacy statement. If you report a security problem privately, I keep that correspondence only to handle the report.

## Children

Sanctuary is a developer tool and is not directed at children. It collects no personal information from anyone.

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
| Anthropic | Your agent's model provider if you use Claude; optional assistant features | https://www.anthropic.com/legal/privacy |
| OpenAI | Optional assistant features, key check | https://openai.com/policies/privacy-policy/ |
| Google (Gemini) | Optional assistant features, key check | https://policies.google.com/privacy and https://ai.google.dev/gemini-api/terms |
| Venice.ai | Optional assistant features, key check | https://venice.ai/legal/privacy-policy |
| Telegram | Optional chief-of-staff check, key check | https://telegram.org/privacy |
| Sigstore (Linux Foundation projects) | Optional public transparency log | https://www.sigstore.dev/privacy-policy/ |
| Ollama | Optional local model download | https://ollama.com/privacy |
| Verascore | Optional publishing, with your confirmation | https://verascore.ai/privacy |
