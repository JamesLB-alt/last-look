// npm run audit:verify -- <report.json> [--offline] [--rpc <url>]
// Checks a downloaded Last Look audit report WITHOUT trusting the server that made it:
//   1. recomputes every receipt hash and the chain linking them
//   2. checks each memo is the one its receipt commits to
//   3. (unless --offline) fetches each anchor transaction from Solana and confirms the
//      memo is really on-chain and was signed by the agent wallet
import { readFileSync } from "node:fs";
import { createSolanaRpc, type Signature } from "@solana/kit";
import { RPC_URL } from "../src/config.ts";
import { memoFor, type Receipt, verifyChain } from "../src/firewall/receipt.ts";

const args = process.argv.slice(2);
const rpcFlag = args.includes("--rpc") ? args[args.indexOf("--rpc") + 1] : undefined;
const file = args.find((a) => !a.startsWith("--") && a !== rpcFlag);
const offline = process.argv.includes("--offline");
if (!file) {
  console.error("Usage: npm run audit:verify -- <report.json> [--offline]");
  process.exit(2);
}

const report = JSON.parse(readFileSync(file, "utf8")) as { format?: string; network?: string; agentWallet: string; receipts: Receipt[] };
if (report.format !== "lastlook-audit/v1" || !Array.isArray(report.receipts)) {
  console.error("That isn't a Last Look audit report (expected format lastlook-audit/v1).");
  process.exit(2);
}

const receipts = report.receipts;
let failed = 0;
const bad = (msg: string) => {
  failed++;
  console.log(`  ✗ ${msg}`);
};

console.log(`\nLast Look audit report: ${receipts.length} receipt${receipts.length === 1 ? "" : "s"} for agent ${report.agentWallet}\n`);

// 1. The hash chain. Editing, dropping or reordering any receipt breaks it.
const chain = verifyChain(receipts);
if (chain.ok) console.log(`  ✓ hash chain intact (${chain.count} receipts)`);
else bad(`hash chain is broken at receipt #${chain.brokenAt}`);

// 2. Each memo must be exactly what its receipt says should go on-chain.
const wrongMemo = receipts.filter((r) => r.memo !== memoFor(r.body, r.hash, r.prev));
if (wrongMemo.length) bad(`memo doesn't match its receipt: ${wrongMemo.map((r) => `#${r.body.seq}`).join(", ")}`);
else console.log("  ✓ every memo matches its receipt");

// 3. The memos on Solana.
const anchored = receipts.filter((r): r is Receipt & { anchor: { status: "anchored"; signature: string } } => r.anchor.status === "anchored");
if (offline) {
  console.log(`  · skipped the on-chain check (--offline); ${anchored.length} receipts claim an anchor`);
} else if (!anchored.length) {
  console.log("  · no receipts are anchored on Solana yet, so there is nothing to look up");
} else {
  // Look where the report says its receipts live: a local-validator report can't be found on devnet.
  const url = rpcFlag ?? process.env.SOLANA_RPC_URL ?? (report.network === "solana-localnet" ? "http://127.0.0.1:8899" : RPC_URL);
  console.log(`  · looking up anchors on ${report.network ?? "solana"} via ${new URL(url).host}`);
  const rpc = createSolanaRpc(url);
  let found = 0;
  for (const r of anchored) {
    try {
      const tx = await rpc.getTransaction(r.anchor.signature as Signature, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0, commitment: "confirmed" }).send();
      const text = JSON.stringify(tx, (_k, v) => (typeof v === "bigint" ? v.toString() : v)) ?? "";
      if (!tx) bad(`#${r.body.seq}: transaction ${r.anchor.signature.slice(0, 12)}… not found on Solana`);
      else if (tx.meta?.err) bad(`#${r.body.seq}: the anchor transaction failed on-chain`);
      else if (!text.includes(r.memo)) bad(`#${r.body.seq}: the on-chain memo is not this receipt's memo`);
      else if (!text.includes(report.agentWallet)) bad(`#${r.body.seq}: the anchor wasn't signed by the agent wallet`);
      else found++;
    } catch (e) {
      bad(`#${r.body.seq}: couldn't fetch the anchor (${(e as Error).message.slice(0, 80)})`);
    }
    await new Promise((res) => setTimeout(res, 250)); // stay under public RPC rate limits
  }
  if (found) console.log(`  ✓ ${found} of ${anchored.length} anchored memos confirmed on Solana`);
}

const unanchored = receipts.length - anchored.length;
if (unanchored) console.log(`  · ${unanchored} receipt${unanchored === 1 ? " is" : "s are"} not anchored on-chain (still covered by the hash chain)`);

console.log(failed ? `\nFAILED: ${failed} problem${failed === 1 ? "" : "s"} found.\n` : "\nVERIFIED: this report has not been altered.\n");
process.exit(failed ? 1 : 0);
