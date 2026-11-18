import "dotenv/config";
import { address } from "@solana/kit";

export const RPC_URL = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
export const WS_URL = process.env.SOLANA_WS_URL ?? RPC_URL.replace(/^http/, "ws");

// Circle's devnet USDC. Verified on-chain: classic SPL Token program, 6 decimals.
export const USDC_MINT = address("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
export const USDC_DECIMALS = 6;

export const PORT = Number(process.env.PORT ?? 4020);
export const FIREWALL_URL = process.env.FIREWALL_URL ?? `http://127.0.0.1:${PORT}`;

/** USDC amounts in base units (6 decimals). `usdc(0.05)` → 50_000n */
export const usdc = (dollars: number) => BigInt(Math.round(dollars * 10 ** USDC_DECIMALS));
export const fmtUsdc = (units: bigint) => `$${(Number(units) / 10 ** USDC_DECIMALS).toFixed(2)}`;

export const explorerTx = (sig: string) => `https://explorer.solana.com/tx/${sig}?cluster=devnet`;
export const explorerAddr = (a: string) => `https://explorer.solana.com/address/${a}?cluster=devnet`;
