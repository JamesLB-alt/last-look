import "dotenv/config";
import { address } from "@solana/kit";

export const RPC_URL = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
/** True when pointed at a validator on this machine (`npm run local`). */
export const IS_LOCAL = /^https?:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(RPC_URL);
// A local validator serves websockets one port above its RPC port.
export const WS_URL =
  process.env.SOLANA_WS_URL ?? (IS_LOCAL ? RPC_URL.replace(/^http/, "ws").replace(/:(\d+)/, (_m, p) => `:${Number(p) + 1}`) : RPC_URL.replace(/^http/, "ws"));

/** Which Solana network this process talks to, and how to link to it in the explorer. */
export const NETWORK = IS_LOCAL
  ? { id: "solana-localnet", name: "Local Solana validator", short: "Localnet", explorerQuery: `cluster=custom&customUrl=${encodeURIComponent(RPC_URL)}` }
  : { id: "solana-devnet", name: "Solana Devnet", short: "Devnet", explorerQuery: "cluster=devnet" };

// Circle's devnet USDC. Verified on-chain: classic SPL Token program, 6 decimals.
// On a local validator, `npm run local` preloads a test mint at this same address.
export const USDC_MINT = address("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
export const USDC_DECIMALS = 6;

export const PORT = Number(process.env.PORT ?? 4020);
export const FIREWALL_URL = process.env.FIREWALL_URL ?? `http://127.0.0.1:${PORT}`;

/** USDC amounts in base units (6 decimals). `usdc(0.05)` → 50_000n */
export const usdc = (dollars: number) => BigInt(Math.round(dollars * 10 ** USDC_DECIMALS));
export const fmtUsdc = (units: bigint) => `$${(Number(units) / 10 ** USDC_DECIMALS).toFixed(2)}`;

export const explorerTx = (sig: string) => `https://explorer.solana.com/tx/${sig}?${NETWORK.explorerQuery}`;
export const explorerAddr = (a: string) => `https://explorer.solana.com/address/${a}?${NETWORK.explorerQuery}`;
