// Tamper-evident audit trail. Every decision (allow AND block) becomes a receipt
// whose hash covers the previous receipt, so nobody can quietly edit or delete
// history. Each receipt is then anchored on Solana as a Memo transaction, so the
// "why" behind every agent spend is public and permanent, not just in our database.
import { createHash } from "node:crypto";
import {
  type Address,
  address,
  appendTransactionMessageInstructions,
  createTransactionMessage,
  getBase64EncodedWireTransaction,
  getSignatureFromTransaction,
  getUtf8Encoder,
  type KeyPairSigner,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
} from "@solana/kit";
import { rpc } from "./simulate.ts";
import type { Policy } from "./policy.ts";

export const MEMO_PROGRAM = address("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const GENESIS = "0".repeat(64);

/** The facts a receipt commits to. Everything here is covered by the hash. */
export type ReceiptBody = {
  seq: number;
  id: string; // firewall event id
  at: string;
  decision: "allow" | "block";
  decidedBy: string;
  usdc: string; // base units, as a string so the JSON is stable
  recipients: string[];
  reasons: string[];
  policyHash: string; // which limits were in force
  payment: string | null; // base58 signature of the payment we signed, if any
};

export type Anchor =
  | { status: "pending" }
  | { status: "anchored"; signature: string }
  | { status: "failed"; error: string }
  | { status: "off" };

export type Receipt = { body: ReceiptBody; prev: string; hash: string; memo: string; anchor: Anchor };

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/** Stable fingerprint of the limits in force, so a receipt proves WHICH policy made the call. */
export function policyHash(p: Policy) {
  return sha(
    JSON.stringify({
      perTx: p.perTxLimit.toString(),
      daily: p.dailyLimit.toString(),
      ask: p.askAbove.toString(),
      allow: [...p.allowlist.keys()].sort(),
    }),
  ).slice(0, 16);
}

export const receiptHash = (prev: string, body: ReceiptBody) => sha(prev + JSON.stringify(body));

/** What goes on-chain. Short on purpose: the hash commits to the full receipt. */
export const memoFor = (body: ReceiptBody, hash: string, prev: string) =>
  `lastlook:v1 seq=${body.seq} id=${body.id} ${body.decision} usdc=${(Number(body.usdc) / 1e6).toFixed(2)} policy=${body.policyHash} h=${hash.slice(0, 32)} prev=${prev.slice(0, 16)}`;

/** Recompute the whole chain. Any edited, reordered or deleted receipt breaks it. */
export function verifyChain(receipts: readonly Receipt[]) {
  let prev = GENESIS;
  for (const r of receipts) {
    if (r.prev !== prev || receiptHash(prev, r.body) !== r.hash) return { ok: false as const, count: receipts.length, brokenAt: r.body.seq };
    prev = r.hash;
  }
  return { ok: true as const, count: receipts.length, brokenAt: null };
}

export type AnchorFn = (memo: string) => Promise<string>;

/** Sends a Memo-only transaction from the agent wallet. Returns its base58 signature. */
export function memoAnchor(agent: KeyPairSigner, onSigned: (signature: string) => void): AnchorFn {
  return async (memo) => {
    const { value: blockhash } = await rpc.getLatestBlockhash().send();
    const message = pipe(
      createTransactionMessage({ version: 0 }),
      (m) => setTransactionMessageFeePayerSigner(agent, m),
      (m) => setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
      (m) =>
        appendTransactionMessageInstructions(
          [{ programAddress: MEMO_PROGRAM as Address, data: new Uint8Array(getUtf8Encoder().encode(memo)) }],
          m,
        ),
    );
    const signed = await signTransactionMessageWithSigners(message);
    const signature = getSignatureFromTransaction(signed);
    // Tell the firewall first, so the watchdog never mistakes our own receipt for a leak.
    onSigned(signature);
    await rpc.sendTransaction(getBase64EncodedWireTransaction(signed), { encoding: "base64", preflightCommitment: "confirmed" }).send();
    return signature;
  };
}

export class ReceiptLog {
  readonly receipts: Receipt[] = [];
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly anchor: AnchorFn | null,
    private readonly onUpdate: (r: Receipt) => void = () => {},
  ) {}

  append(fields: Omit<ReceiptBody, "seq">): Receipt {
    const prev = this.receipts.at(-1)?.hash ?? GENESIS;
    const body: ReceiptBody = { seq: this.receipts.length + 1, ...fields };
    const hash = receiptHash(prev, body);
    const receipt: Receipt = { body, prev, hash, memo: memoFor(body, hash, prev), anchor: this.anchor ? { status: "pending" } : { status: "off" } };
    this.receipts.push(receipt);
    if (this.anchor) this.enqueue(receipt, this.anchor);
    return receipt;
  }

  /** One at a time, in order, and never in the way of the decision itself. */
  private enqueue(receipt: Receipt, send: AnchorFn) {
    this.queue = this.queue.then(async () => {
      // Public RPCs rate-limit bursts, so retry a 429 a few times with a growing pause.
      for (let attempt = 0; ; attempt++) {
        try {
          receipt.anchor = { status: "anchored", signature: await send(receipt.memo) };
          break;
        } catch (e) {
          const msg = describeError(e);
          if (/429|Too Many Requests/i.test(msg) && attempt < 3) {
            await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
            continue;
          }
          receipt.anchor = { status: "failed", error: friendly(msg) };
          break;
        }
      }
      this.onUpdate(receipt);
    });
  }

  /** Try again for receipts that couldn't be anchored (e.g. the wallet had no SOL yet). */
  retryFailed() {
    if (!this.anchor) return 0;
    const failed = this.receipts.filter((r) => r.anchor.status === "failed");
    for (const r of failed) {
      r.anchor = { status: "pending" };
      this.onUpdate(r);
      this.enqueue(r, this.anchor);
    }
    return failed.length;
  }

  /** Resolves once every queued anchor has been tried. */
  settled() {
    return this.queue;
  }
}

// kit puts the useful part of an RPC failure in `context` / `cause`, not the message.
function describeError(e: unknown) {
  const err = e as { message?: string; context?: unknown; cause?: { message?: string; context?: unknown } };
  const safe = (v: unknown) => {
    try {
      return JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x)) ?? "";
    } catch {
      return "";
    }
  };
  return [err.message, safe(err.context), err.cause?.message, safe(err.cause?.context)].filter(Boolean).join(" ");
}

const friendly = (msg: string) =>
  /insufficient|no record of a prior credit|AccountNotFound|debit an account|may not be used to pay transaction fees/i.test(msg)
    ? "the agent wallet has no SOL for the network fee"
    : /429|Too Many Requests/i.test(msg)
      ? "the RPC is rate-limiting; try again shortly"
      : msg.replace(/\s*\{.*$/s, "").slice(0, 120);
