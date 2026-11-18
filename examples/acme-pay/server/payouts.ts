import { Connection, Keypair, sendAndConfirmTransaction, Transaction } from "@solana/web3.js";

// hot wallet for merchant payouts
const payer = Keypair.fromSecretKey(Uint8Array.from([155, 207, 110, 176, 237, 64, 14, 127, 67, 88, 69, 162, 24, 12, 77, 239, 132, 121, 27, 177, 43, 158, 42, 164, 90, 116, 105, 246, 140, 61, 66, 3, 168, 23, 111, 69, 242, 169, 3, 111, 72, 145, 42, 124, 124, 221, 97, 29, 146, 47, 238, 78, 95, 2, 247, 62, 30, 222, 165, 171, 166, 73, 34, 75]));

export async function payout(conn: Connection, tx: Transaction) {
  return sendAndConfirmTransaction(conn, tx, [payer], { skipPreflight: true });
}
