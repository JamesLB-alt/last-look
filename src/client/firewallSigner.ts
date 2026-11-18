import {
  type Address,
  getBase64EncodedWireTransaction,
  getBase64Encoder,
  type SignatureBytes,
  type TransactionPartialSigner,
} from "@solana/kit";
import { FIREWALL_URL } from "../config.ts";
import type { AgentContext } from "../firewall/policy.ts";

export class FirewallBlockedError extends Error {
  constructor(
    readonly id: string,
    readonly reasons: string[],
  ) {
    super(`Last Look blocked this payment: ${reasons.join("; ")}`);
  }
}

/**
 * A drop-in Solana signer for the agent process. It holds NO private key.
 * Every transaction is shipped to the firewall, which decides whether to sign.
 *
 * Because it implements kit's TransactionPartialSigner, anything that accepts a
 * signer (x402's Solana client, our own transfers, any SDK) is guarded for free.
 */
export function createFirewallSigner(agent: Address, getContext: () => AgentContext): TransactionPartialSigner {
  return {
    address: agent,
    async signTransactions(transactions) {
      return Promise.all(
        transactions.map(async (tx) => {
          const res = await fetch(`${FIREWALL_URL}/sign`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ transaction: getBase64EncodedWireTransaction(tx), context: getContext() }),
          });
          const body = (await res.json()) as { decision: string; id: string; signature?: string; reasons: string[] };
          if (body.decision !== "allow" || !body.signature) throw new FirewallBlockedError(body.id, body.reasons);
          return { [agent]: getBase64Encoder().encode(body.signature) as SignatureBytes };
        }),
      );
    },
  };
}

export async function fetchAgentAddress(): Promise<Address> {
  const res = await fetch(`${FIREWALL_URL}/api/state`);
  return ((await res.json()) as { agent: Address }).agent;
}
