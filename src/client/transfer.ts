import {
  type Address,
  appendTransactionMessageInstructions,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  getSignatureFromTransaction,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type TransactionPartialSigner,
} from "@solana/kit";
import { getCreateAssociatedTokenIdempotentInstruction, getTransferCheckedInstruction } from "@solana-program/token";
import { USDC_DECIMALS, USDC_MINT, usdc, WS_URL } from "../config.ts";
import { ataFor } from "../firewall/firewall.ts";
import { rpc } from "../firewall/simulate.ts";

const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions: createSolanaRpcSubscriptions(WS_URL) });

/**
 * Builds a USDC transfer, has `signer` sign it (for the agent that's the firewall,
 * which may refuse by throwing FirewallBlockedError), then optionally broadcasts it.
 */
export async function sendUsdc(signer: TransactionPartialSigner, to: Address, dollars: number, broadcast = true) {
  const [fromAta, toAta] = await Promise.all([ataFor(signer.address), ataFor(to)]);
  const { value: blockhash } = await rpc.getLatestBlockhash().send();
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(signer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
    (m) =>
      appendTransactionMessageInstructions(
        [
          getCreateAssociatedTokenIdempotentInstruction({ payer: signer, ata: toAta, owner: to, mint: USDC_MINT }),
          getTransferCheckedInstruction({
            source: fromAta,
            mint: USDC_MINT,
            destination: toAta,
            authority: signer,
            amount: usdc(dollars),
            decimals: USDC_DECIMALS,
          }),
        ],
        m,
      ),
  );

  const signed = await signTransactionMessageWithSigners(message);
  const signature = getSignatureFromTransaction(signed);
  if (broadcast) await sendAndConfirm(signed as Parameters<typeof sendAndConfirm>[0], { commitment: "confirmed" });
  return { signature, broadcast };
}
