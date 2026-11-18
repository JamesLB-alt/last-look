// QuickNode Streams filter: Last Look out-of-band watchdog.
//
// Paste this whole file into QuickNode → Streams → your stream → Filter.
//   Network: Solana Devnet · Dataset: Block · Destination: Webhook → <public URL>/api/stream/webhook
// Then replace WALLET with your agent wallet address (npm run setup prints it).
//
// What it sends: only successful transactions where USDC or SOL LEFT the agent wallet.
// Last Look compares each one's signatures with the signatures it produced itself;
// anything it didn't sign is money that moved around the firewall (e.g. a leaked key).
// The filter sandbox has no imports or network, so this is plain JavaScript.

const WALLET = "AGRjLrk81SU78xM9LesYPyvEZjxYG523JGWZdsZTyY1S"; // agent wallet
const USDC = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"; // devnet USDC mint

function main(stream) {
  // A batch can carry several blocks.
  const blocks = Array.isArray(stream.data) ? stream.data : [stream.data];
  const matches = [];

  for (const block of blocks) {
    for (const tx of (block && block.transactions) || []) {
      const meta = tx.meta;
      if (!meta || meta.err) continue; // failed transactions moved nothing

      const message = (tx.transaction && tx.transaction.message) || {};
      const keys = (message.accountKeys || []).map((k) => (typeof k === "string" ? k : k.pubkey));
      const walletIndex = keys.indexOf(WALLET);

      // Sum this wallet's USDC across token accounts it owns, before and after.
      const usdcOf = (balances) =>
        (balances || [])
          .filter((b) => b.owner === WALLET && b.mint === USDC)
          .reduce((sum, b) => sum + Number((b.uiTokenAmount && b.uiTokenAmount.amount) || 0), 0);
      const usdcDelta = usdcOf(meta.postTokenBalances) - usdcOf(meta.preTokenBalances);
      const solDelta = walletIndex >= 0 ? meta.postBalances[walletIndex] - meta.preBalances[walletIndex] : 0;

      if (usdcDelta >= 0 && solDelta >= 0) continue; // only outflows matter

      matches.push({
        signature: tx.transaction.signatures[0],
        signatures: tx.transaction.signatures,
        blockTime: block.blockTime || null,
        usdcDelta: usdcDelta / 1e6,
        solDelta: solDelta / 1e9,
      });
    }
  }
  if (matches.length) return { wallet: WALLET, matches };
  // Heartbeat about once a minute (devnet makes ~2.5 blocks/s), so the dashboard can
  // show the watchdog is alive even when nothing is moving.
  const height = blocks.length && blocks[0] ? blocks[0].blockHeight : 0;
  return height % 150 === 0 ? { wallet: WALLET, heartbeat: height, matches: [] } : null;
}
