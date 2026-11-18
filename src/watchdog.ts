// Out-of-band watchdog: QuickNode Streams tells us whenever money leaves the agent
// wallet. If the transaction doesn't carry a signature Last Look produced, it bypassed
// the firewall (e.g. a leaked key), and the dashboard raises an alert.
import { createHmac, timingSafeEqual } from "node:crypto";

export type StreamMatch = { signature: string; signatures: string[]; blockTime: number | null; usdcDelta: number; solDelta: number };

/**
 * QuickNode signs each webhook: hex HMAC-SHA256 of (nonce + timestamp + body),
 * keyed with the destination's security token, in X-QN-Nonce / X-QN-Timestamp / X-QN-Signature.
 */
export function verifyQuickNode(rawBody: Buffer, headers: Record<string, string | string[] | undefined>, token: string): boolean {
  const h = (name: string) => String(headers[name] ?? "");
  const nonce = h("x-qn-nonce"), timestamp = h("x-qn-timestamp"), given = h("x-qn-signature");
  if (!nonce || !timestamp || !given) return false;
  const expected = createHmac("sha256", token).update(nonce + timestamp + rawBody.toString("utf8")).digest("hex");
  const a = Buffer.from(expected), b = Buffer.from(given);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Sign a body the way QuickNode does (used by the local self-test). */
export function signLikeQuickNode(body: string, token: string) {
  const nonce = Math.random().toString(36).slice(2), timestamp = String(Math.floor(Date.now() / 1000));
  return {
    "x-qn-nonce": nonce,
    "x-qn-timestamp": timestamp,
    "x-qn-signature": createHmac("sha256", token).update(nonce + timestamp + body).digest("hex"),
  };
}

/** Split matches into spends Last Look signed and spends it never saw. */
export function classify(body: unknown, ours: Set<string>) {
  const matches = ((body as { matches?: StreamMatch[] })?.matches ?? []).filter((m) => m && typeof m.signature === "string");
  const isOurs = (m: StreamMatch) => (m.signatures ?? [m.signature]).some((s) => ours.has(s));
  return { ours: matches.filter(isOurs), outOfBand: matches.filter((m) => !isOurs(m)) };
}

export function describe(m: StreamMatch) {
  const parts = [m.usdcDelta < 0 ? `$${(-m.usdcDelta).toFixed(2)} USDC` : "", m.solDelta < -0.00001 ? `${(-m.solDelta).toFixed(4)} SOL` : ""].filter(Boolean);
  return `${parts.join(" and ") || "Funds"} left the agent wallet in ${m.signature.slice(0, 8)}…, which Last Look never signed.`;
}
