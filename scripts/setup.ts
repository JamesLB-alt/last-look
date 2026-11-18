// npm run setup: create the devnet wallets and show what still needs funding.
import { address } from "@solana/kit";
import { explorerAddr, fmtUsdc, RPC_URL } from "../src/config.ts";
import { ataFor } from "../src/firewall/firewall.ts";
import { rpc } from "../src/firewall/simulate.ts";
import { loadOrCreate, type KeyName } from "../src/keys.ts";

console.log(`RPC: ${RPC_URL}\n`);
const needs: string[] = [];

for (const name of ["agent", "seller", "attacker"] as KeyName[]) {
  const { address: addr } = await loadOrCreate(name);
  const sol = Number((await rpc.getBalance(address(addr)).send()).value) / 1e9;
  const usdcUnits = await rpc
    .getTokenAccountBalance(await ataFor(addr))
    .send()
    .then((r) => BigInt(r.value.amount))
    .catch(() => 0n);
  console.log(`${name.padEnd(9)} ${addr}`);
  console.log(`          ${sol.toFixed(3)} SOL · ${fmtUsdc(usdcUnits)} USDC · ${explorerAddr(addr)}`);
  if (name === "agent" && sol < 0.05) needs.push(`devnet SOL → agent (fees + rent)   https://faucet.solana.com  → ${addr}`);
  if (name === "agent" && usdcUnits < 10_000_000n) needs.push(`devnet USDC → agent (≥ $10)         https://faucet.circle.com  → Solana Devnet → ${addr}`);
  // The vendor runs its own x402 facilitator and pays the network fee for each payment.
  if (name === "seller" && sol < 0.05) needs.push(`devnet SOL → seller (x402 fees)    https://faucet.solana.com  → ${addr}`);
}

console.log(needs.length ? `\nTo do (faucets have captchas, so do these in your browser):\n  - ${needs.join("\n  - ")}` : "\n✅ Agent wallet is funded.");
