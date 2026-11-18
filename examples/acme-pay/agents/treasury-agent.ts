import Anthropic from "@anthropic-ai/sdk";
import bs58 from "bs58";
import { Connection, Keypair, sendAndConfirmTransaction } from "@solana/web3.js";

// The agent rebalances the treasury on its own.
const treasury = Keypair.fromSecretKey(bs58.decode(process.env.TREASURY_PRIVATE_KEY!));
const client = new Anthropic();

export async function runAgent(conn: Connection, task: string) {
  // tool loop can call send_payment, which uses sendAndConfirmTransaction(conn, tx, [treasury])
  return { client, treasury, task, send: sendAndConfirmTransaction };
}
