// npm run test:filter: runs streams/solana-filter.js (the exact file you paste into
// QuickNode) against REAL recent devnet blocks, the same getBlock shape Streams delivers.
// It points the filter at a wallet whose token balance dropped in that block and checks
// the filter catches it.
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { RPC_URL } from "../src/config.ts";

const rpc = async (method: string, params: unknown[]) => {
  const r = await fetch(RPC_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = (await r.json()) as { result?: any; error?: any };
  if (j.error) throw new Error(JSON.stringify(j.error));
  return j.result;
};

const source = readFileSync(new URL("../streams/solana-filter.js", import.meta.url), "utf8");
const loadFilter = (wallet: string, mint: string) => {
  const code = source
    .replace(/const WALLET = "[^"]+";/, `const WALLET = ${JSON.stringify(wallet)};`)
    .replace(/const USDC = "[^"]+";/, `const USDC = ${JSON.stringify(mint)};`);
  const ctx: { main?: (s: unknown) => any } = {};
  vm.runInNewContext(`${code}\nthis.main = main;`, ctx); // same sandbox idea as QuickNode: no imports
  return ctx.main!;
};


const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** getBlock is heavy; public RPCs throttle it. Back off instead of treating 429 as "no block". */
async function getBlockWithBackoff(slot: number) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await rpc("getBlock", [slot, { encoding: "json", maxSupportedTransactionVersion: 0, transactionDetails: "full", rewards: false }]);
    } catch (e) {
      if (!String(e).includes("429") || attempt >= 4) throw e;
      await sleep(1500 * 2 ** attempt);
    }
  }
}

// getBlock is heavily rate-limited on the public devnet RPC, so by default we fetch recent
// real USDC transactions with getTransaction (same per-tx meta/transaction shape that sits
// inside a Streams block) and wrap them as a block. Set SOLANA_RPC_URL to QuickNode to use
// full blocks instead: FULL_BLOCKS=1 npm run test:filter
const USDC_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

async function* candidateBlocks() {
  if (process.env.FULL_BLOCKS) {
    let slot = (await rpc("getSlot", [{ commitment: "finalized" }])) as number;
    for (let i = 0; i < 40; i++, slot--) {
      try {
        const b = await getBlockWithBackoff(slot);
        if (b) yield { label: `block ${slot}`, block: b };
      } catch (e) {
        if (String(e).includes("429")) throw new Error("rate-limited: set SOLANA_RPC_URL to your QuickNode devnet endpoint");
      }
    }
    return;
  }
  const sigs = (await rpc("getSignaturesForAddress", [USDC_MINT, { limit: 25, commitment: "finalized" }])) as { signature: string; err: unknown }[];
  for (const s of sigs.filter((x) => !x.err)) {
    const tx = await rpc("getTransaction", [s.signature, { encoding: "json", maxSupportedTransactionVersion: 0, commitment: "finalized" }]).catch(() => null);
    if (tx) yield { label: `tx ${s.signature.slice(0, 10)}… (slot ${tx.slot})`, block: { blockHeight: 150, blockTime: tx.blockTime, transactions: [{ meta: tx.meta, transaction: tx.transaction, version: tx.version }] } };
    await sleep(250);
  }
}

for await (const { label, block } of candidateBlocks()) {
  for (const tx of block.transactions) {
    if (tx.meta?.err) continue;
    for (const pre of tx.meta?.preTokenBalances ?? []) {
      const post = (tx.meta.postTokenBalances ?? []).find((p: any) => p.accountIndex === pre.accountIndex);
      if (!post || !pre.owner || BigInt(post.uiTokenAmount.amount) >= BigInt(pre.uiTokenAmount.amount)) continue;

      const out = loadFilter(pre.owner, pre.mint)({ data: [block], metadata: { network: "solana-devnet", dataset: "block" } });
      const hit = out?.matches?.find((m: any) => m.signature === tx.transaction.signatures[0]);
      console.log(`${label}: watching ${pre.owner.slice(0, 6)}… whose ${pre.mint.slice(0, 6)}… balance dropped`);
      if (!hit) {
        console.error("❌ filter missed a real outflow:", JSON.stringify(out)?.slice(0, 300));
        process.exit(1);
      }
      console.log(`✅ filter caught it: ${hit.signature.slice(0, 12)}…  tokenDelta=${hit.usdcDelta}  solDelta=${hit.solDelta}`);
      const quiet = loadFilter("11111111111111111111111111111111", pre.mint)({ data: [{ ...block, blockHeight: 151 }] });
      console.log(`✅ unrelated wallet → ${quiet === null ? "null (nothing sent)" : JSON.stringify(quiet)}`);
      process.exit(0);
    }
  }
}
console.error("No token outflow found in recent devnet activity; try again in a minute.");
process.exit(2);
