import express from "express";
import { PORT, usdc } from "./config.ts";
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

// The ONLY process that loads the agent's private key.
const agent = await loadOrCreate("agent");
const seller = await loadOrCreate("seller");

const trusted: Trusted[] = [{ name: "DataCo API", owner: seller.address, ata: await ataFor(seller.address) }];

const firewall = await Firewall.create(agent, {
  perTxLimit: usdc(5),
  dailyLimit: usdc(20),
  askAbove: usdc(1),
  allowlist: new Map(trusted.map((t) => [t.ata, t.name])),
});

// Out-of-band watchdog state, fed by the QuickNode Stream webhook.
const STREAM_TOKEN = process.env.QUICKNODE_STREAM_TOKEN ?? "";
const watchdogState = { lastEventAt: null as string | null, alerts: [] as { at: string; message: string; signature: string }[] };
// "Connected" means we actually heard from the stream recently (its heartbeat is ~1/min).
const watchdog = () => ({
  connected: !!watchdogState.lastEventAt && Date.now() - Date.parse(watchdogState.lastEventAt) < 5 * 60_000,
  lastEventAt: watchdogState.lastEventAt,
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
      session,
      events: firewall.events,
    }),
  );
});

app.get("/api/wallet", async (_req, res) => {
  const wallet = await walletSnapshot(firewall, trusted);
  res.type("json").send(json({ wallet, health: healthReport(firewall, wallet, watchdog()) }));
});

app.post("/api/freeze", (req, res) => {
  firewall.frozen = req.body?.frozen === true;
  broadcast({ type: "freeze", frozen: firewall.frozen });
  res.json({ frozen: firewall.frozen });
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
app.post("/api/agent/event", (req, res) => {
  const e = req.body ?? {};
  const now = new Date().toISOString();
  if (e.type === "start") {
    Object.assign(session, { status: "running", model: String(e.model ?? ""), question: String(e.question ?? ""), naive: !!e.naive, tainted: false, startedAt: now, steps: [] });
  } else if (e.type === "step" && ["tool", "text", "taint", "error"].includes(e.kind)) {
    if (e.kind === "taint") session.tainted = true;
    session.steps.push({ at: now, kind: e.kind, text: String(e.text ?? "").slice(0, 600), tool: e.tool ? String(e.tool) : undefined });
    session.steps = session.steps.slice(-60);
  } else if (e.type === "done") {
    session.status = "done";
  } else {
    return res.status(400).json({ ok: false });
  }
  broadcast({ type: "agent", session });
  res.json({ ok: true });
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
app.post("/api/stream/webhook", (req, res) => {
  const raw = (req as unknown as { rawBody?: Buffer }).rawBody ?? Buffer.from("");
  if (STREAM_TOKEN && !verifyQuickNode(raw, req.headers, STREAM_TOKEN)) return res.status(401).json({ ok: false });
  // A local self-test exercises the alert path but must not make the stream look alive.
  const simulated = req.body?.selftest === true;
  const now = new Date().toISOString();
  if (!simulated) watchdogState.lastEventAt = now;
  const { ours, outOfBand } = classify(req.body, firewall.ourSignatures);
  for (const m of outOfBand) {
    const message = (simulated ? "SIMULATED TEST: " : "") + describeLeak(m);
    watchdogState.alerts.unshift({ at: now, message, signature: m.signature });
    broadcast({ type: "alert", message, signature: m.signature });
  }
  watchdogState.alerts = watchdogState.alerts.slice(0, 20);
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

app.listen(PORT, "127.0.0.1", () => {
  console.log(`🛡️  Last Look firewall on http://127.0.0.1:${PORT}`);
  console.log(`   guarding agent wallet ${firewall.address}`);
});
