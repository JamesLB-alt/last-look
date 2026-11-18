import { type Address, type Base64EncodedWireTransaction, createSolanaRpc } from "@solana/kit";
import { RPC_URL } from "../config.ts";

export const rpc = createSolanaRpc(RPC_URL);

export type Simulation = {
  ok: boolean;
  error: string | null;
  /** Change in the agent's USDC balance if this tx lands. Negative = money leaves. */
  usdcDelta: bigint | null;
  logs: string[];
};

// SPL token account layout: mint(32) | owner(32) | amount(u64 LE) | ...
const readTokenAmount = (data: Uint8Array) =>
  data.length >= 72 ? new DataView(data.buffer, data.byteOffset).getBigUint64(64, true) : null;

/**
 * Dry-runs the transaction against current devnet state. No signature needed:
 * `sigVerify: false` lets us simulate BEFORE deciding whether to sign.
 */
export async function simulate(wireBase64: string, agentUsdcAta: Address): Promise<Simulation> {
  try {
    const before = await rpc
      .getTokenAccountBalance(agentUsdcAta)
      .send()
      .then((r) => BigInt(r.value.amount))
      .catch(() => null); // ATA may not exist yet

    const { value } = await rpc
      .simulateTransaction(wireBase64 as Base64EncodedWireTransaction, {
        encoding: "base64",
        sigVerify: false,
        replaceRecentBlockhash: true,
        commitment: "confirmed",
        accounts: { addresses: [agentUsdcAta], encoding: "base64" },
      })
      .send();

    const acct = value.accounts?.[0];
    const after = acct ? readTokenAmount(Buffer.from(acct.data[0], "base64")) : null;

    return {
      ok: value.err === null,
      error: value.err === null ? null : JSON.stringify(value.err, (_k, v) => (typeof v === "bigint" ? v.toString() : v)),
      usdcDelta: before !== null && after !== null ? after - before : null,
      logs: [...(value.logs ?? [])],
    };
  } catch (e) {
    return { ok: false, error: `simulation call failed: ${(e as Error).message}`, usdcDelta: null, logs: [] };
  }
}
