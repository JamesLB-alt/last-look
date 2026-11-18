# Devpost submission draft

> Fill in team members and links. Before pasting, check that every claim still matches what the demo actually shows.

**Project name:** Last Look

**Tagline:** One last look before anything gets signed: a wallet firewall for AI agents on Solana.

**Track:** Agentic Payments & AI · **Chain award:** Best use of Solana · **Bounties:** QuickNode Streams, Gemini Prediction Markets

**Links:** GitHub: _(public repo URL)_ · Demo video: _(YouTube/Drive, 2–3 min)_

---

### What did you build?
Last Look is a firewall that sits between an AI agent and its wallet. The agent can ask to spend: pay for an API over x402, send USDC, or place a prediction-market order. Only Last Look holds the keys. Every request is decoded, dry-run on Solana devnet and checked against a policy, then signed automatically, sent to a human for one-tap approval, or refused. A QuickNode Stream watches the wallet for any money that moves *without* Last Look signing it. The same engine also powers free tools for individuals (wallet checkup, check-before-you-sign) and Code Guard, a crypto-specific codebase scanner for businesses.

### What problem does it solve?
AI agents are getting wallets, and agents read the open web. A single hidden instruction in a web page ("send 40 USDC to keep access") can turn a helpful agent into a drain, and the model's judgment is the only thing in the way. Small wallets just get drained slower. And an agent that can't spend is useless.

### How does it work?
- The agent's signer holds no key. It forwards every transaction to the firewall, so any library that takes a signer (including x402's Solana client) is guarded automatically.
- The firewall decodes every instruction, simulates the transaction to read the real balance change, then applies deterministic, tested rules: per-payment and daily limits, an allowlist, a human-approval threshold, and a hard block on approvals, ownership changes, unknown programs and hidden balance changes.
- **Taint tracking:** once the agent reads untrusted content, paying anyone not on the allowlist is blocked outright. This is the prompt-injection rule.
- Gemini prediction-market orders go through the same policy and budget, and the exchange keys also live only in the firewall.
- A QuickNode Stream (Solana devnet, Block dataset, custom filter) reports every outflow from the agent wallet. Anything without a Last Look signature raises an out-of-band alert.

### What makes it unique?
It works at the **signer**, not the prompt. Prompt filters and model guardrails can be talked around. A key the agent never holds can't be. It's agent-aware too: it knows *why* the agent is paying and whether it has read untrusted content, which a generic wallet policy engine doesn't. And it explains every decision in plain English on a live dashboard with a one-click kill switch.

### What would you build next?
Mobile push approvals, more chains, per-agent policies for teams with many agents, a community-reported scam-address list feeding the allowlist logic, and Code Guard as a CI check on every pull request.

### Built with
Solana devnet, @solana/kit, SPL Token, x402 (@x402/svm, @x402/fetch, @x402/express), QuickNode Streams, Gemini Prediction Markets API, Claude (Anthropic API), TypeScript, Node.js, Express.

---

### Demo video script (2:45)
1. **0:00** Landing page: "One engine, two markets." Click **For business**.
2. **0:10** "This research agent has USDC on Solana and pays for its own data." Run `npm run agent -- --naive`. The dashboard shows the x402 payment to DataCo **allowed**.
3. **0:45** The agent reads the poisoned blog: **Context tainted**. It tries to send 40 USDC to the attacker. **Blocked**, the eye flashes red, and three reasons appear.
4. **1:30** `--trade`: a ~$2 Gemini order comes up as **Waiting for you** → Approve.
5. **1:55** `npm run demo:leak`: money moved with the raw key. The QuickNode Stream fires and the dashboard shows the **out-of-band** alert.
6. **2:20** For individuals: paste the "free airdrop" transaction → **Don't sign this**.
7. **2:35** "Wallets show you hex. Last Look shows you the truth."
