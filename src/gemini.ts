// Gemini Prediction Markets.
//   - Market data: public API, no key. Safe to call from the agent.
//   - Orders: SANDBOX only, signed with keys that live in the firewall process, and only
//     after the same Last Look policy that guards on-chain payments approves the spend.
import { createHmac } from "node:crypto";

const PUBLIC_API = "https://api.gemini.com";
const SANDBOX_API = process.env.GEMINI_SANDBOX_URL ?? "https://api.sandbox.gemini.com";
const ORDER_PATH = "/v1/prediction-markets/order";

export type Market = {
  event: string;
  ticker: string;
  volume: string | null;
  contracts: { label: string; symbol: string; yes: number | null; no: number | null; last: number | null }[];
};

const num = (v: unknown) => (v === undefined || v === null || v === "" ? null : Number(v));

/** Active prediction markets matching a search, with implied YES/NO prices (0–1). */
export async function searchMarkets(query: string, limit = 3): Promise<Market[]> {
  const url = `${PUBLIC_API}/v1/prediction-markets/events?status=active&limit=${limit}&search=${encodeURIComponent(query)}`;
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`Gemini market data returned HTTP ${res.status}`);
  const body = (await res.json()) as { data?: any[] };
  return (body.data ?? []).map((e) => ({
    event: String(e.title),
    ticker: String(e.ticker),
    volume: e.volume ?? null,
    contracts: (e.contracts ?? []).slice(0, 8).map((c: any) => ({
      label: String(c.label),
      symbol: String(c.instrumentSymbol),
      yes: num(c.prices?.buy?.yes),
      no: num(c.prices?.buy?.no),
      last: num(c.prices?.lastTradePrice),
    })),
  }));
}

export const hasSandboxKeys = () => Boolean(process.env.GEMINI_SANDBOX_API_KEY && process.env.GEMINI_SANDBOX_API_SECRET);

export type Order = { symbol: string; outcome: "yes" | "no"; quantity: string; price: string };

export function validateOrder(o: Partial<Order>): Order {
  if (!o.symbol || !/^GEMI-[A-Z0-9-]+$/.test(o.symbol)) throw new Error("symbol must be a Gemini instrumentSymbol like GEMI-FED261211-CUT25");
  if (o.outcome !== "yes" && o.outcome !== "no") throw new Error('outcome must be "yes" or "no"');
  const q = Number(o.quantity), p = Number(o.price);
  if (!(q > 0) || !Number.isFinite(q)) throw new Error("quantity must be a positive number of contracts");
  if (!(p > 0 && p < 1)) throw new Error("price must be between 0 and 1");
  return { symbol: o.symbol, outcome: o.outcome, quantity: String(o.quantity), price: String(o.price) };
}

/** Worst-case cost in dollars: each contract costs at most `price`. */
export const orderCost = (o: Order) => Number(o.quantity) * Number(o.price);

/**
 * Places a limit order on the Gemini SANDBOX using Gemini's private-REST auth:
 * base64(JSON payload) in X-GEMINI-PAYLOAD, HMAC-SHA384 hex of that base64 in X-GEMINI-SIGNATURE.
 * Unverified against the sandbox until keys are configured (see README).
 */
export async function placeSandboxOrder(o: Order) {
  const key = process.env.GEMINI_SANDBOX_API_KEY!;
  const secret = process.env.GEMINI_SANDBOX_API_SECRET!;
  const payload = {
    request: ORDER_PATH,
    nonce: Date.now(), // strictly increasing per key
    symbol: o.symbol,
    orderType: "limit",
    side: "buy",
    quantity: o.quantity,
    price: o.price,
    outcome: o.outcome,
    timeInForce: "immediate-or-cancel", // never leave a resting order behind from a demo
  };
  const b64 = Buffer.from(JSON.stringify(payload)).toString("base64");
  const signature = createHmac("sha384", secret).update(b64).digest("hex");
  const res = await fetch(`${SANDBOX_API}${ORDER_PATH}`, {
    method: "POST",
    headers: {
      "Content-Type": "text/plain",
      "Content-Length": "0",
      "Cache-Control": "no-cache",
      "X-GEMINI-APIKEY": key,
      "X-GEMINI-PAYLOAD": b64,
      "X-GEMINI-SIGNATURE": signature,
    },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Gemini sandbox rejected the order (HTTP ${res.status}): ${JSON.stringify(body).slice(0, 300)}`);
  return body;
}
