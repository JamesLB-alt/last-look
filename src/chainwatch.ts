// Built-in out-of-band watcher. Polls the chain for transactions that moved money out
// of the agent wallet and hands them to the same classifier the QuickNode Stream feeds.
// A QuickNode Stream is the production path (push, no polling, survives restarts);
// this watcher makes the same check work on a local validator, where Streams can't reach.
import type { Address, Signature } from "@solana/kit";
import { USDC_MINT } from "./config.ts";
import { rpc } from "./firewall/simulate.ts";
import type { StreamMatch } from "./watchdog.ts";

type TokenBalance = { owner?: string; mint: string; uiTokenAmount: { amount: string } };

export function startChainWatch(
  agent: Address,
  agentAta: Address,
  onMatches: (matches: StreamMatch[]) => void,
  /** Called after every successful poll, so the dashboard knows the watcher is alive. */
  onBeat: () => void,
  intervalMs = 1500,
) {
  const seen = new Set<string>();
  let primed = false;
  let busy = false;

  const usdcOf = (list: readonly TokenBalance[] | null | undefined) =>
    Number(list?.find((b) => b.owner === agent && b.mint === USDC_MINT)?.uiTokenAmount.amount ?? 0) / 1e6;

  async function tick() {
    if (busy) return;
    busy = true;
    try {
      const lists = await Promise.all([agent, agentAta].map((a) => rpc.getSignaturesForAddress(a, { limit: 25, commitment: "confirmed" }).send()));
      const fresh = [...new Set(lists.flat().filter((s) => !s.err).map((s) => s.signature as string))].filter((s) => !seen.has(s));
      for (const s of fresh) seen.add(s);
      // Whatever happened before we started is history, not an alert.
      if (!primed) {
        primed = true;
        return onBeat();
      }
      const matches: StreamMatch[] = [];
      for (const signature of fresh) {
        const tx = await rpc.getTransaction(signature as Signature, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0, commitment: "confirmed" }).send();
        if (!tx?.meta) {
          seen.delete(signature); // not readable yet: look again next round
          continue;
        }
        const i = tx.transaction.message.accountKeys.findIndex((k) => k.pubkey === agent);
        const solDelta = i < 0 ? 0 : (Number(tx.meta.postBalances[i]) - Number(tx.meta.preBalances[i])) / 1e9;
        const usdcDelta = usdcOf(tx.meta.postTokenBalances as TokenBalance[] | undefined) - usdcOf(tx.meta.preTokenBalances as TokenBalance[] | undefined);
        // Only money LEAVING matters. Network fees alone (a few thousand lamports) don't count.
        if (usdcDelta < 0 || solDelta < -0.00001) {
          matches.push({ signature, signatures: [...tx.transaction.signatures], blockTime: tx.blockTime === null ? null : Number(tx.blockTime), usdcDelta, solDelta });
        }
      }
      if (matches.length) onMatches(matches);
      onBeat();
    } catch {
      // RPC hiccup: skip this round. The dashboard shows the watcher as down if this persists.
    } finally {
      busy = false;
    }
  }

  const timer = setInterval(tick, intervalMs);
  void tick();
  return () => clearInterval(timer);
}
