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
- **On-chain audit trail:** every decision, allowed or blocked, becomes a hash-chained receipt written to Solana as a Memo transaction, with a fingerprint of the policy that made the call. Nobody can quietly edit why a payment was approved.
- **Built-in red team:** one button fires 12 real drain techniques (injected transfers, unlimited approvals, ownership takeovers, unknown programs, a leaked key) at the real signing door. 12 of 12 are stopped, and the dashboard shows which layer stopped each one and how long the check took (about 155 ms median, under 1 ms of it our own code).
- **One-click guided demo, rule tester and audit export:** the dashboard plays the whole story through the real signing door, lets the owner ask "what would happen if the agent tried to pay $X to Y?", edit limits and trusted wallets live, and download the audit trail. `npm run audit:verify` checks that file against Solana without trusting our server.

### What makes it unique?
It works at the **signer**, not the prompt. Prompt filters and model guardrails can be talked around. A key the agent never holds can't be. It's agent-aware too: it knows *why* the agent is paying and whether it has read untrusted content, which a generic wallet policy engine doesn't. And it explains every decision in plain English on a live dashboard with a one-click kill switch. It is also checkable: you can attack it yourself with one button, and verify every past decision against Solana.

### What would you build next?
Mobile push approvals, more chains, per-agent policies for teams with many agents, a community-reported scam-address list feeding the allowlist logic, and Code Guard as a CI check on every pull request.

### Built with
Solana devnet, @solana/kit, SPL Token, x402 (@x402/svm, @x402/fetch, @x402/express), QuickNode Streams, Gemini Prediction Markets API, Claude (Anthropic API), TypeScript, Node.js, Express.

---

### Demo video script, short version (about 1:30, no terminal)
0. Before recording: `npm run local` (a local Solana validator with pre-funded test wallets; the page shows "Localnet").
1. **0:00** Open `/firewall.html`. "An AI agent with a wallet. Last Look is the only thing that can sign for it."
2. **0:10** Click **Run the demo** and read each scene aloud as it lights up: normal payment, poisoned web page **blocked**, unlimited approval **blocked**, leaked key **alert**, **Freeze**, then click **Approve** on the last one.
3. **0:50** Click **Run attack suite**: 12 of 12 stopped.
4. **1:05** "What would happen if…": type $0.50 to an unknown wallet after reading untrusted content → **Blocked**.
5. **1:15** Audit trail: open one receipt on the Solana explorer, then **Download report**.

### Demo video script (2:45)
1. **0:00** Landing page: "One engine, two markets." Click **For business**.
2. **0:10** "This research agent has USDC on Solana and pays for its own data." Run `npm run agent -- --naive`. The dashboard shows the x402 payment to DataCo **allowed**.
3. **0:45** The agent reads the poisoned blog: **Context tainted**. It tries to send 40 USDC to the attacker. **Blocked**, the eye flashes red, and three reasons appear.
4. **1:30** `--trade`: a ~$2 Gemini order comes up as **Waiting for you** → Approve.
5. **1:50** `npm run demo:leak`: money moved with the raw key. The QuickNode Stream fires and the dashboard shows the **out-of-band** alert.
6. **2:10** Click **Run attack suite**: 12 of 12 stopped. Scroll to the audit trail and open one receipt on the Solana explorer.
7. **2:25** For individuals: paste the "free airdrop" transaction → **Don't sign this**.
8. **2:40** "Wallets show you hex. Last Look shows you the truth."
