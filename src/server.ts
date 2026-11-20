import express from "express";
import { address, type Address } from "@solana/kit";
import { IS_LOCAL, NETWORK, PORT, usdc } from "./config.ts";
import { startChainWatch } from "./chainwatch.ts";
import { sendUsdc } from "./client/transfer.ts";
import { ataFor, Firewall } from "./firewall/firewall.ts";
import type { AgentContext } from "./firewall/policy.ts";
import { loadOrCreate } from "./keys.ts";
import { healthReport, type Trusted, walletSnapshot } from "./wallet.ts";
import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { explain } from "./codeguard/explain.ts";
import { type Report, scan } from "./codeguard/scan.ts";
import { checkup, examples, inspect } from "./personal.ts";
import { classify, describe as describeLeak, verifyQuickNode } from "./watchdog.ts";
import { hasSandboxKeys, type Order, orderCost, placeSandboxOrder, validateOrder } from "./gemini.ts";
import { publicAddress } from "./keys.ts";
import { policyHash, verifyChain } from "./firewall/receipt.ts";
import { type AttackResult, runRedTeam } from "./redteam.ts";
import { createDemo } from "./demo.ts";

// The ONLY process that loads the agent's private key.
const agent = await loadOrCreate("agent");
const seller = await loadOrCreate("seller");

const trusted: Trusted[] = [{ name: "DataCo API", owner: seller.address, ata: await ataFor(seller.address) }];

const firewall = await Firewall.create(
  agent,
  {
    perTxLimit: usdc(5),
    dailyLimit: usdc(20),
    askAbove: usdc(1),
    allowlist: new Map(trusted.map((t) => [t.ata, t.name])),
  },
  // Receipts are anchored on Solana by default. LASTLOOK_ANCHOR=off keeps them local.
  { anchor: process.env.LASTLOOK_ANCHOR !== "off" },
);

// Out-of-band watchdog state, fed by the QuickNode Stream webhook.
const STREAM_TOKEN = process.env.QUICKNODE_STREAM_TOKEN ?? "";
const watchdogState = { lastEventAt: null as string | null, alerts: [] as { at: string; message: string; signature: string }[] };
// "Connected" means we actually heard from the stream recently (its heartbeat is ~1/min).
// On a local validator (or with LASTLOOK_WATCH=rpc) the built-in chain watcher does the same job by polling.
const CHAIN_WATCH = IS_LOCAL || process.env.LASTLOOK_WATCH === "rpc";
const watchdog = () => ({
  connected: !!watchdogState.lastEventAt && Date.now() - Date.parse(watchdogState.lastEventAt) < (CHAIN_WATCH ? 20_000 : 5 * 60_000),
  lastEventAt: watchdogState.lastEventAt,
  source: CHAIN_WATCH ? "Built-in chain watcher" : "QuickNode Stream",
});

// What the agent is doing right now, reported by the agent process itself.
type AgentStep = { at: string; kind: "tool" | "text" | "taint" | "error"; text: string; tool?: string };
const session = {
  status: "idle" as "idle" | "running" | "done",
  model: null as string | null,
  question: null as string | null,
  naive: false,
  tainted: false,
  startedAt: null as string | null,
  steps: [] as AgentStep[],
};

const json = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x));
const broadcast = (msg: unknown) => firewall.emit("event", msg);

const app = express();
// Keep the raw bytes too: the QuickNode webhook signature is computed over them.
app.use(express.json({ limit: "512kb", verify: (req, _res, buf) => ((req as unknown as { rawBody: Buffer }).rawBody = buf) }));
app.use(express.static(new URL("../public/", import.meta.url).pathname));

app.post("/sign", async (req, res) => {
  const { transaction, context } = req.body as { transaction?: string; context?: Partial<AgentContext> };
  if (typeof transaction !== "string") return res.status(400).send(json({ error: "transaction (base64) required" }));
  const ctx: AgentContext = {
    tool: String(context?.tool ?? "unknown"),
    purpose: String(context?.purpose ?? ""),
    // Missing taint info is treated as tainted: fail closed.
    tainted: context?.tainted !== false,
  };
  try {
    const result = await firewall.handleSign(transaction, ctx);
    res.status(result.decision === "allow" ? 200 : 403).type("json").send(json(result));
  } catch (e) {
    res.status(400).type("json").send(json({ decision: "block", reasons: [`could not decode: ${(e as Error).message}`] }));
  }
});

app.get("/api/state", (_req, res) => {
  res.type("json").send(
    json({
      agent: firewall.address,
      agentAta: firewall.agentAta,
      budget: firewall.budget,
      frozen: firewall.frozen,
      // Maps don't survive JSON.stringify, so flatten the allowlist.
      policy: { ...firewall.policy, allowlist: Object.fromEntries(firewall.policy.allowlist) },
      policyHash: policyHash(firewall.policy),
      network: NETWORK,
      session,
      events: firewall.events,
    }),
  );
});

app.get("/api/wallet", async (_req, res) => {
  const wallet = await walletSnapshot(firewall, trusted);
  res.type("json").send(json({ wallet, health: healthReport(firewall, wallet, watchdog()) }));
});

function setFrozen(frozen: boolean) {
  firewall.frozen = frozen;
  broadcast({ type: "freeze", frozen });
}
app.post("/api/freeze", (req, res) => {
  setFrozen(req.body?.frozen === true);
  res.json({ frozen: firewall.frozen });
});

// ---- Limits: the owner can retune them live. Every receipt records which policy was in force.
app.post("/api/policy", (req, res) => {
  const dollars = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? Math.round(v * 100) / 100 : NaN);
  const perTx = dollars(req.body?.perTxLimit), daily = dollars(req.body?.dailyLimit), ask = dollars(req.body?.askAbove);
  if ([perTx, daily, ask].some((n) => Number.isNaN(n) || n <= 0 || n > 10_000)) return res.status(400).json({ error: "Each limit must be between $0.01 and $10,000." });
  if (ask > perTx) return res.status(400).json({ error: "The ask-me threshold can't be above the per-payment limit." });
  if (perTx > daily) return res.status(400).json({ error: "The per-payment limit can't be above the daily budget." });
  Object.assign(firewall.policy, { perTxLimit: usdc(perTx), dailyLimit: usdc(daily), askAbove: usdc(ask) });
  broadcast({ type: "policy" });
  res.type("json").send(json({ ok: true, policyHash: policyHash(firewall.policy) }));
});

// "What would happen if…": the verdict the current rules would give, without signing anything.
app.post("/api/policy/preview", (req, res) => {
  const dollars = Number(req.body?.amount);
  if (!Number.isFinite(dollars) || dollars < 0 || dollars > 1_000_000) return res.status(400).json({ error: "Enter an amount in dollars." });
  const known = typeof req.body?.recipient === "string" && firewall.policy.allowlist.has(req.body.recipient as Address);
  const verdict = firewall.preview(usdc(dollars), known, req.body?.tainted === true);
  res.json({ ...verdict, recipient: known ? firewall.policy.allowlist.get(req.body.recipient as Address) : null });
});

// ---- Trusted recipients: the owner decides who the agent may pay without asking.
// The allowlist is part of the policy fingerprint, so every receipt shows which list was in force.
app.post("/api/allowlist", async (req, res) => {
  const name = String(req.body?.name ?? "").trim().slice(0, 40);
  if (!name) return res.status(400).json({ error: "Give the recipient a name." });
  let owner: Address;
  try {
    owner = address(String(req.body?.address ?? "").trim());
  } catch {
    return res.status(400).json({ error: "That isn't a valid Solana wallet address." });
  }
  if (owner === firewall.address) return res.status(400).json({ error: "That's the agent's own wallet." });
  const ata = await ataFor(owner);
  if (firewall.policy.allowlist.has(ata)) return res.status(400).json({ error: `Already trusted as ${firewall.policy.allowlist.get(ata)}.` });
  trusted.push({ name, owner, ata });
  firewall.policy.allowlist.set(ata, name);
  broadcast({ type: "policy" });
  res.json({ ok: true, policyHash: policyHash(firewall.policy) });
});

app.delete("/api/allowlist/:ata", (req, res) => {
  const i = trusted.findIndex((t) => t.ata === req.params.ata);
  if (i < 0) return res.status(404).json({ error: "Not on the list." });
  firewall.policy.allowlist.delete(trusted[i]!.ata);
  trusted.splice(i, 1);
  broadcast({ type: "policy" });
  res.json({ ok: true, policyHash: policyHash(firewall.policy) });
});

// ---- Numbers: what the firewall has done, and how fast -------------------------
const percentile = (sorted: number[], p: number) => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))] : null);
app.get("/api/stats", (_req, res) => {
  const done = firewall.events.filter((e) => e.decision !== "pending");
  const onchain = done.filter((e) => e.timing.simulateMs > 0).map((e) => e.timing.totalMs).sort((a, b) => a - b);
  const policyOnly = done.map((e) => e.timing.policyMs + e.timing.decodeMs).sort((a, b) => a - b);
  const sum = (d: string) => done.filter((e) => e.decision === d).reduce((s, e) => s + e.signals.outflow, 0n);
  const receipts = firewall.receipts.receipts;
  res.type("json").send(
    json({
      decisions: done.length,
      allowed: done.filter((e) => e.decision === "allow").length,
      blocked: done.filter((e) => e.decision === "block").length,
      humanDecided: done.filter((e) => e.decidedBy === "human").length,
      usdcBlocked: sum("block"),
      usdcAllowed: sum("allow"),
      // Full check = decode + on-chain simulation + policy. The simulation is a network round trip.
      medianCheckMs: percentile(onchain, 0.5),
      p95CheckMs: percentile(onchain, 0.95),
      // Our own code only (decode + policy), with the network taken out.
      medianLocalMs: percentile(policyOnly, 0.5),
      receipts: receipts.length,
      anchored: receipts.filter((r) => r.anchor.status === "anchored").length,
      chain: verifyChain(receipts),
      policyHash: policyHash(firewall.policy),
      redteam: lastRedTeam,
    }),
  );
});

// ---- Audit trail: hash-chained receipts, anchored on Solana as Memo transactions
app.get("/api/receipts", (_req, res) => {
  res.type("json").send(json({ chain: verifyChain(firewall.receipts.receipts), receipts: [...firewall.receipts.receipts].reverse() }));
});

app.post("/api/receipts/anchor", (_req, res) => {
  res.json({ retried: firewall.receipts.retryFailed() });
});

// A self-contained report anyone can check without trusting this server:
// `npm run audit:verify -- <file>` recomputes the hash chain and looks up each memo on Solana.
app.get("/api/receipts/export", (_req, res) => {
  const receipts = firewall.receipts.receipts;
  const p = firewall.policy;
  const stamp = new Date().toISOString();
  res
    .set("content-disposition", `attachment; filename="last-look-audit-${stamp.slice(0, 19).replace(/[:T]/g, "-")}.json"`)
    .type("json")
    .send(
      JSON.stringify(
        {
          format: "lastlook-audit/v1",
          generatedAt: stamp,
          network: NETWORK.id,
          agentWallet: firewall.address,
          memoProgram: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
          policy: {
            hash: policyHash(p),
            perTxLimitUsdc: Number(p.perTxLimit) / 1e6,
            dailyLimitUsdc: Number(p.dailyLimit) / 1e6,
            askAboveUsdc: Number(p.askAbove) / 1e6,
            allowlist: trusted.map((t) => ({ name: t.name, wallet: t.owner, usdcAccount: t.ata })),
          },
          chain: verifyChain(receipts),
          howToVerify:
            "hash = sha256(prev + JSON.stringify(body)); the first prev is 64 zeros. Each anchored receipt's memo is in the Solana transaction at anchor.signature, signed by agentWallet. Run: npm run audit:verify -- <this file>",
          receipts,
        },
        null,
        2,
      ),
    );
});

// ---- Guided demo: one click plays the whole story through the real signing door
const demo = createDemo({
  firewall,
  seller: seller.address,
  attacker: await publicAddress("attacker"),
  publish: (state) => broadcast({ type: "demo", demo: state }),
  agent: agentEvent,
  watching: CHAIN_WATCH,
  leak: async (real) => {
    if (!real) {
      const signature = `DemoLeak${Date.now().toString(36)}`;
      const { outOfBand } = ingestStream({ matches: [{ signature, signatures: [signature], blockTime: null, usdcDelta: -12, solDelta: 0 }] }, true);
      return { message: outOfBand.length ? watchdogState.alerts[0]!.message : null, signature: null };
    }
    // The "stolen key": sign with the raw keypair and broadcast, never calling handleSign.
    // The firewall has no record of this signature, which is exactly what the watcher looks for.
    const { signature } = await sendUsdc(agent, await publicAddress("attacker"), 1);
    for (let i = 0; i < 40; i++) {
      const hit = watchdogState.alerts.find((a) => a.signature === signature);
      if (hit) return { message: hit.message, signature };
      await new Promise((r) => setTimeout(r, 500));
    }
    return { message: null, signature };
  },
  setFrozen,
  balances: async () => {
    const w = await walletSnapshot(firewall, trusted);
    return { sol: w.sol, usdc: w.usdc };
  },
});
app.get("/api/demo", (_req, res) => res.json(demo.state));
app.post("/api/demo/run", (req, res) => {
  const pace = typeof req.body?.pace === "number" ? req.body.pace : undefined;
  if (!demo.start(pace)) return res.status(409).json({ error: "The demo is already playing." });
  res.json(demo.state);
});

// ---- Red team: fire every known drain technique at the real signing door -------
let lastRedTeam: { at: string; caught: number; total: number; results: AttackResult[] } | null = null;
let redTeamRunning = false;
app.post("/api/redteam/run", async (_req, res) => {
  if (redTeamRunning) return res.status(409).json({ error: "The attack suite is already running." });
  redTeamRunning = true;
  try {
    const results = await runRedTeam(firewall, { seller: seller.address, attacker: await publicAddress("attacker") });
    lastRedTeam = { at: new Date().toISOString(), caught: results.filter((r) => r.caught).length, total: results.length, results };
    res.type("json").send(json(lastRedTeam));
  } catch (e) {
    res.status(502).json({ error: `Couldn't run the attack suite: ${(e as Error).message}` });
  } finally {
    redTeamRunning = false;
  }
});

// Express 5 dropped inline regex params, so validate the action by hand.
app.post("/api/pending/:id/:action", (req, res) => {
  const { id, action } = req.params;
  if (action !== "approve" && action !== "deny") return res.status(400).json({ ok: false });
  const ok = firewall.resolve(id, action === "approve");
  res.status(ok ? 200 : 404).json({ ok });
});

// The agent process reports its own steps here so the dashboard can show them.
// This is display-only: nothing here can make the firewall sign anything.
function agentEvent(e: Record<string, unknown>) {
  const now = new Date().toISOString();
  if (e.type === "start") {
    Object.assign(session, { status: "running", model: String(e.model ?? ""), question: String(e.question ?? ""), naive: !!e.naive, tainted: false, startedAt: now, steps: [] });
  } else if (e.type === "step" && ["tool", "text", "taint", "error"].includes(e.kind as string)) {
    if (e.kind === "taint") session.tainted = true;
    session.steps.push({ at: now, kind: e.kind as AgentStep["kind"], text: String(e.text ?? "").slice(0, 600), tool: e.tool ? String(e.tool) : undefined });
    session.steps = session.steps.slice(-60);
  } else if (e.type === "done") {
    session.status = "done";
  } else {
    return false;
  }
  broadcast({ type: "agent", session });
  return true;
}
app.post("/api/agent/event", (req, res) => {
  const ok = agentEvent(req.body ?? {});
  res.status(ok ? 200 : 400).json({ ok });
});

// ---- Code Guard: clients whose codebases we scan ------------------------------
// Local paths only, and the server only listens on 127.0.0.1.
type Client = { id: string; name: string; path: string; note: string; report: Report | null; summary: string | null };
const repoRoot = resolve(new URL("..", import.meta.url).pathname);
const clients: Client[] = [
  { id: "acme-pay", name: "Acme Pay", path: resolve(repoRoot, "examples/acme-pay"), note: "Demo client · intentionally insecure, fake keys", report: null, summary: null },
  { id: "last-look", name: "Last Look", path: repoRoot, note: "This repo · we scan ourselves", report: null, summary: null },
];
const clientView = (c: Client) => ({
  id: c.id, name: c.name, path: c.path, note: c.note, summary: c.summary,
  report: c.report,
});

app.get("/api/clients", (_req, res) => res.json(clients.map(clientView)));

app.post("/api/clients", (req, res) => {
  const name = String(req.body?.name ?? "").trim().slice(0, 60);
  const path = resolve(String(req.body?.path ?? "").trim());
  if (!name) return res.status(400).json({ error: "Give the client a name." });
  if (!existsSync(path) || !statSync(path).isDirectory()) return res.status(400).json({ error: "That folder doesn't exist on this machine." });
  const id = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") + "-" + clients.length;
  const c: Client = { id, name, path, note: "Added by you", report: null, summary: null };
  clients.push(c);
  res.json(clientView(c));
});

app.post("/api/clients/:id/scan", (req, res) => {
  const c = clients.find((x) => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: "Unknown client" });
  try {
    c.report = scan(c.path);
    c.summary = null; // a new scan invalidates the old summary
    res.json(clientView(c));
  } catch (e) {
    res.status(400).json({ error: (e as Error).message });
  }
});

app.post("/api/clients/:id/explain", async (req, res) => {
  const c = clients.find((x) => x.id === req.params.id);
  if (!c?.report) return res.status(400).json({ error: "Scan first." });
  try {
    c.summary = await explain(c.name, c.report);
    res.json(clientView(c));
  } catch (e) {
    const msg = (e as Error).message;
    res.status(502).json({
      error: /authentication|api.?key|credentials/i.test(msg)
        ? "Claude isn't connected yet: add ANTHROPIC_API_KEY to .env (or run `ant auth login`), then restart."
        : `Claude summary failed: ${msg}`,
    });
  }
});

// ---- QuickNode Streams webhook: the out-of-band watchdog ---------------------
/** Sort a stream payload into our spends and out-of-band ones, and raise an alert for each of the latter. */
function ingestStream(body: unknown, simulated: boolean) {
  const now = new Date().toISOString();
  const split = classify(body, firewall.ourSignatures);
  for (const m of split.outOfBand) {
    const message = (simulated ? "SIMULATED TEST: " : "") + describeLeak(m);
    watchdogState.alerts.unshift({ at: now, message, signature: m.signature });
    broadcast({ type: "alert", message, signature: m.signature });
  }
  watchdogState.alerts = watchdogState.alerts.slice(0, 20);
  return split;
}

app.post("/api/stream/webhook", (req, res) => {
  const raw = (req as unknown as { rawBody?: Buffer }).rawBody ?? Buffer.from("");
  if (STREAM_TOKEN && !verifyQuickNode(raw, req.headers, STREAM_TOKEN)) return res.status(401).json({ ok: false });
  // A local self-test exercises the alert path but must not make the stream look alive.
  const simulated = req.body?.selftest === true;
  const now = new Date().toISOString();
  if (!simulated) watchdogState.lastEventAt = now;
  const { ours, outOfBand } = ingestStream(req.body, simulated);
  res.json({ ok: true, ours: ours.length, outOfBand: outOfBand.length, verified: !!STREAM_TOKEN, simulated });
});

// ---- Off-chain spends: Gemini prediction-market orders ------------------------
// Same policy, same approvals, same daily budget as on-chain payments. The exchange
// keys live here, next to the wallet key, never in the agent.
app.post("/offchain/gemini/order", async (req, res) => {
  let order: Order;
  try {
    order = validateOrder(req.body?.order ?? {});
  } catch (e) {
    return res.status(400).json({ decision: "block", reasons: [(e as Error).message] });
  }
  const c = req.body?.context ?? {};
  const context: AgentContext = { tool: String(c.tool ?? "place_prediction_order"), purpose: String(c.purpose ?? ""), tainted: c.tainted !== false };
  const { approved, event } = await firewall.handleOffchain({
    venue: "Gemini Prediction Markets",
    trusted: true,
    amount: usdc(orderCost(order)),
    context,
  });
  if (!approved) return res.status(403).type("json").send(json({ decision: "block", id: event.id, reasons: event.reasons }));
  if (!hasSandboxKeys()) {
    return res.type("json").send(json({ decision: "allow", id: event.id, dryRun: true, note: "Approved, but not sent: no Gemini sandbox keys are configured." }));
  }
  try {
    res.type("json").send(json({ decision: "allow", id: event.id, order: await placeSandboxOrder(order) }));
  } catch (e) {
    res.status(502).json({ decision: "allow", id: event.id, error: (e as Error).message });
  }
});

// ---- For individuals: wallet checkup + check-before-you-sign -----------------
// Read-only. These never sign anything.
app.get("/api/personal/checkup/:address", async (req, res) => {
  try {
    res.type("json").send(json(await checkup(req.params.address)));
  } catch (e) {
    res.status(400).json({ error: (e as Error).message });
  }
});

app.post("/api/personal/inspect", async (req, res) => {
  const tx = req.body?.transaction;
  if (typeof tx !== "string" || !tx.trim()) return res.status(400).json({ error: "Paste a base64-encoded transaction." });
  try {
    res.type("json").send(json(await inspect(tx.trim())));
  } catch (e) {
    const msg = (e as Error).message;
    res.status(400).json({
      error: /base ?64|alphabet|Invalid value/i.test(msg)
        ? "That doesn't look like a transaction. Paste the base64 text a wallet or dApp gives you."
        : `Couldn't read that transaction: ${msg}`,
    });
  }
});

app.get("/api/personal/examples", async (_req, res) => {
  try {
    // The demo "you" is the agent wallet; the attacker is the demo attacker; the friend is DataCo.
    res.json(await examples(firewall.address, await publicAddress("attacker"), seller.address));
  } catch (e) {
    res.status(502).json({ error: (e as Error).message });
  }
});

// Server-Sent Events: the dashboard subscribes and renders everything live.
app.get("/events", (req, res) => {
  res.set({ "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" }).flushHeaders();
  const send = (e: unknown) => res.write(`data: ${json(e)}\n\n`);
  firewall.on("event", send);
  req.on("close", () => firewall.off("event", send));
});

app.get("/api/network", (_req, res) => res.json(NETWORK));

if (CHAIN_WATCH) {
  startChainWatch(
    firewall.address,
    firewall.agentAta,
    (matches) => ingestStream({ matches }, false),
    () => (watchdogState.lastEventAt = new Date().toISOString()),
  );
}

app.listen(PORT, "127.0.0.1", () => {
  console.log(`   network: ${NETWORK.name}${CHAIN_WATCH ? " · built-in chain watcher on" : ""}`);
  console.log(`🛡️  Last Look firewall on http://127.0.0.1:${PORT}`);
  console.log(`   guarding agent wallet ${firewall.address}`);
});
