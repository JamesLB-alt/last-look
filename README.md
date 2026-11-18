# Last Look

**One last look before anything gets signed.**

Last Look is a wallet firewall for AI agents on Solana. The agent can *ask* to spend, but only Last Look holds the key. Every payment is decoded, simulated and checked against your policy first, then signed, sent to a human, or refused. A prompt injection can talk the model into paying an attacker. It can't make the wallet sign.

The same engine serves two audiences:

| | For individuals | For business |
|---|---|---|
| **Question** | *Is my wallet safe?* | *Are our agents and our code safe?* |
| **Tools** | Wallet checkup (open approvals), Check before you sign (plain-English transaction breakdown) | Agent firewall (limits, allowlists, human approval, kill switch, health score), Code Guard (crypto-specific codebase scanner) |

Built for the **University Blockchain Conference Hackathon 2026**: Track **Agentic Payments & AI** · **Best use of Solana** · **QuickNode Streams** bounty · **Gemini Prediction Markets** bounty.

---

## Architecture

```
 Claude agent (src/agent.ts)            ← holds NO private key, NO exchange keys
   tools: read_webpage · fetch_paid_api (x402) · send_usdc
          get_prediction_markets · place_prediction_order
        │  builds a Solana tx / an order request, plus { tool, purpose, tainted }
        ▼
 ┌──────────────── Last Look firewall (src/server.ts) ───────────────┐
 │ 1. Decode   every instruction: transfers, approvals, ownership,   │  src/firewall/decode.ts
 │             closes, SOL sends, unknown programs                   │
 │ 2. Simulate simulateTransaction → real USDC balance change        │  src/firewall/simulate.ts
 │ 3. Evaluate deterministic policy → allow / ask / block            │  src/firewall/policy.ts
 │ 4. Decide   sign · wait for a human on the dashboard · refuse     │  src/firewall/firewall.ts
 │ holds: agent wallet keypair, Gemini sandbox API keys              │
 └─────────┬─────────────────────────────┬───────────────────────────┘
           ▼                             ▼
     Solana devnet               Dashboard (public/firewall.html): live feed,
           ▲                     approvals, budget, health score, kill switch
           │
 QuickNode Stream (streams/solana-filter.js) watches the agent wallet. Any outflow
 whose signatures don't include one Last Look produced = money moved around the
 firewall (e.g. a leaked key) → 🚨 alert.
```

**Key isolation is the core design.** The agent's signer (`src/client/firewallSigner.ts`) implements `@solana/kit`'s `TransactionPartialSigner` interface but holds no key: it sends each transaction to `POST /sign`. Anything that accepts a signer is guarded for free, including the x402 client library.

**The LLM never decides what's safe.** Policy is deterministic code with tests. Claude only decides what to *ask* for.

---

## The agent's decision loop (track requirement)

1. Claude reads the user's question and picks a tool.
2. Tools that read outside content (`read_webpage`) mark the session **tainted**. Missing taint info is treated as tainted (fail closed).
3. Tools that spend build a transaction (or an order) and ask the firewall to approve it, sending `{ tool, purpose, tainted }`.
4. The firewall decodes, simulates and evaluates the policy, then signs, waits for a human, or refuses.
5. A refusal comes back to Claude as a tool result: *"PAYMENT REFUSED by Last Look … Do not retry. Tell the user."* Claude explains it, and the loop continues.

## Safety limits

Defaults in `src/server.ts`; rules in `src/firewall/policy.ts`; each rule has a test in `test/policy.test.ts`.

| Limit | Value | Outcome |
|---|---|---|
| Per-payment limit | $5.00 | over → **block** |
| Daily budget | $20.00 | would exceed → **block** |
| Auto-approve threshold | $1.00 | above → **ask a human** |
| Allowlist | DataCo API (x402 vendor), Gemini (orders) | unknown recipient → **ask** |
| Tainted context + unknown recipient | the prompt-injection rule | **block**, even for $0.01 |
| Approvals, ownership changes, account closes, unknown programs | never needed by a payment agent | **block** |
| Direct SOL transfers | agent pays in USDC only | **block** |
| Simulated balance change ≠ decoded instructions | something is hidden | **block** |
| Simulation failed | effect unverified | **ask** |
| Human doesn't answer in 2 minutes | — | **deny** |
| Kill switch (Freeze) | owner-controlled | **block everything** |

Spends count toward the budget when *approved*, not when they settle, because a signed transaction can land later.

---

## How it uses Solana (Best use of Solana)

Everything runs on **Solana devnet**. Last Look doesn't deploy its own program. It works by reading, simulating and signing transactions that use these existing programs:

| Program / account | Address | Used for |
|---|---|---|
| SPL Token | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | USDC transfers, and decoding Approve, SetAuthority, CloseAccount |
| Associated Token Account | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` | recipient token accounts |
| Token-2022 | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | wallet checkup (read-only) |
| System | `11111111111111111111111111111111` | detecting SOL transfers |
| Compute Budget | `ComputeBudget111111111111111111111111111111` | recognized as benign in x402 transactions |
| Memo | `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` | recognized as benign (x402 receiver binding) |
| Devnet USDC mint | `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU` | the asset the agent spends |

- **x402 on Solana** (`@x402/svm`, network `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1`): the mock vendor (`src/seller.ts`) runs its own x402 facilitator. The agent pays per API call through the firewall signer.
- **`simulateTransaction`** with `sigVerify: false` dry-runs every transaction *before* it's signed and reads the agent's post-transaction USDC balance.
- **Wallet checkup** reads `getTokenAccountsByOwner` (SPL Token and Token-2022) for open `delegate` approvals.

---

## QuickNode Streams (bounty)

| Setting | Value | Why |
|---|---|---|
| Network | Solana **Devnet** | where the agent wallet lives |
| Dataset | **Block** | it includes `meta.preTokenBalances` / `postTokenBalances`, which carry the per-owner USDC deltas we need |
| Filter | [`streams/solana-filter.js`](streams/solana-filter.js) | Keeps only successful transactions where USDC or SOL **left** the agent wallet (owner-matched token balances, plus `preBalances`/`postBalances` at the wallet's account index). Returns `{ wallet, matches: [{ signature, signatures, blockTime, usdcDelta, solDelta }] }`, plus a heartbeat about once a minute (every 150 blocks) so the dashboard knows the stream is alive. Returns `null` otherwise, so nothing is sent. |
| Destination | **Webhook** → `https://<your-tunnel>/api/stream/webhook` | The firewall checks each match's signatures against the set of signatures it produced. **Anything it never signed is out-of-band**, which raises a red alert on the dashboard. Bodies are verified with QuickNode's `X-QN-Signature` (HMAC-SHA256 of nonce + timestamp + body) when `QUICKNODE_STREAM_TOKEN` is set. |

This covers the one gap a signing firewall can't see: money moved *without* asking it, for example with a leaked key. `npm run demo:leak` does exactly that on devnet, and the Stream catches it.

**Tested:** `npm run test:filter` runs the exact filter file against real devnet USDC transactions and confirms it catches a real outflow and ignores unrelated wallets. `test/watchdog.test.ts` covers signature verification and classification. `npm run watchdog:selftest` exercises the webhook and dashboard alert locally. A simulated event never marks the stream as live.

**Setup:** QuickNode → Streams → New stream → Solana Devnet, Block → paste the filter (replace `WALLET` with your agent address from `npm run setup`) → Webhook destination. The webhook must be public, so tunnel the local server: `ngrok http 4020`. Copy the destination's Security token into `.env` as `QUICKNODE_STREAM_TOKEN`.

---

## Gemini Prediction Markets (bounty)

- **Market data:** `get_prediction_markets` searches live markets through Gemini's public API (`GET /v1/prediction-markets/events`) and returns contracts with implied YES/NO prices. For example, *"Fed decision in December?"* (`FED261211`) gives the agent real market odds alongside its paid data.
- **Orders:** `place_prediction_order` asks the firewall (`POST /offchain/gemini/order`). The order's worst-case cost (`quantity × price`) goes through the **same policy, approval flow and daily budget** as on-chain payments. The exchange keys live in the firewall process, next to the wallet key. Orders go to the **sandbox** only (`api.sandbox.gemini.com`) as immediate-or-cancel limit orders.
- **Without sandbox keys,** approved orders return a dry run. The order signing (`X-GEMINI-PAYLOAD` / HMAC-SHA384 `X-GEMINI-SIGNATURE`) follows Gemini's private-REST docs but hasn't been exercised against the sandbox yet.

---

## Run it

```bash
npm install
cp .env.example .env          # add ANTHROPIC_API_KEY (and optional QuickNode / Gemini sandbox values)
npm run setup                 # creates devnet wallets, shows what to fund
npm run dev                   # firewall + dashboard on :4020, mock x402 vendor on :4021
```

Fund the **agent** with devnet SOL ([faucet.solana.com](https://faucet.solana.com)) and devnet USDC ([faucet.circle.com](https://faucet.circle.com) → Solana Devnet). Fund the **seller** with devnet SOL, since it pays x402 network fees.

| Command | What it does |
|---|---|
| `npm run agent` | Research agent: reads a page, buys data over x402, checks Gemini odds |
| `npm run agent -- --naive` | Same, simulating an agent that trusts injected instructions (the attack demo) |
| `npm run agent -- --trade` | Also lets it place a ~$2 sandbox order (lands in *ask*) |
| `npm run demo:transfer [-- --dry]` | Three scripted payments: allow, block (injection), ask |
| `npm run demo:leak` | Spends with the raw key, bypassing the firewall (the watchdog demo) |
| `npm test` | Policy + watchdog unit tests |
| `npm run test:filter` | QuickNode filter against real devnet transactions |
| `npm run watchdog:selftest` | Simulated Stream event → dashboard alert |

Pages: `/` (landing), `/personal.html` (individuals), `/firewall.html` (agent firewall), `/clients.html` (Code Guard).

---

## Also in the box

- **Code Guard** (`src/codeguard/`): 15 deterministic rules for crypto codebases across frontend, backend, cloud & CI, AI agents and on-chain code (for example, leaked keypairs, unlimited approvals, agents holding signing keys, secrets echoed in CI). It scans only what git would commit, redacts every secret in its output, and can ask Claude for a summary of redacted findings only. `examples/acme-pay/` is an intentionally insecure demo client with fake, never-funded keys.
- **For individuals** (`src/personal.ts`): wallet checkup and check-before-you-sign, both read-only.

## Honest status

| Verified | Not yet verified |
|---|---|
| Policy (13 tests), watchdog (6 tests), filter on real devnet transactions | A full funded run on devnet (wallets need faucet funds) |
| Real x402 payment transactions decoded through the firewall signer | Claude agent loop against the live API (needs `ANTHROPIC_API_KEY`) |
| Gemini public market data, order validation, approval flow | Gemini sandbox order signing (needs sandbox keys) |
| Webhook verification and dashboard alert (simulated event) | A live QuickNode Stream delivering to the webhook |
