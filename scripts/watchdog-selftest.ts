// npm run watchdog:selftest: posts a SIMULATED QuickNode Stream event to the local
// webhook, as if money left the agent wallet without Last Look's signature.
// Checks the webhook, signature verification and the dashboard alert, without
// needing QuickNode, ngrok or funded wallets. It is a wiring test, not the real demo
// (the real one is: npm run demo:leak with the Stream running).
import { randomBytes } from "node:crypto";
import { getBase58Decoder } from "@solana/kit";
import { FIREWALL_URL } from "../src/config.ts";
import { signLikeQuickNode } from "../src/watchdog.ts";
import "dotenv/config";

const fakeSig = getBase58Decoder().decode(randomBytes(64));
const body = JSON.stringify({
  wallet: "simulated",
  selftest: true, // shows the alert, but doesn't count as the real stream being alive
  matches: [{ signature: fakeSig, signatures: [fakeSig], blockTime: Math.floor(Date.now() / 1000), usdcDelta: -25, solDelta: 0 }],
});
const token = process.env.QUICKNODE_STREAM_TOKEN;
const res = await fetch(`${FIREWALL_URL}/api/stream/webhook`, {
  method: "POST",
  headers: { "content-type": "application/json", ...(token ? signLikeQuickNode(body, token) : {}) },
  body,
});
console.log(`HTTP ${res.status}`, await res.text());
console.log(token ? "Signed with QUICKNODE_STREAM_TOKEN." : "No QUICKNODE_STREAM_TOKEN set, so the webhook accepted it unsigned.");
console.log(`Check the dashboard: ${FIREWALL_URL}/firewall.html should show the red out-of-band alert.`);
