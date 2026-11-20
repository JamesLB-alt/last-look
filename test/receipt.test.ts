// The audit trail must be tamper-evident: change, drop or reorder a receipt and the chain breaks.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { address } from "@solana/kit";
import { usdc } from "../src/config.ts";
import type { Policy } from "../src/firewall/policy.ts";
import { policyHash, ReceiptLog, verifyChain } from "../src/firewall/receipt.ts";

const policy: Policy = {
  perTxLimit: usdc(5),
  dailyLimit: usdc(20),
  askAbove: usdc(1),
  allowlist: new Map([[address("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"), "DataCo API"]]),
};

const entry = (id: string, decision: "allow" | "block", dollars: number) => ({
  id,
  at: "2026-11-20T00:00:00.000Z",
  decision,
  decidedBy: "policy",
  usdc: usdc(dollars).toString(),
  recipients: ["DataCo API"],
  reasons: ["test"],
  policyHash: policyHash(policy),
  payment: null,
});

const filled = () => {
  const log = new ReceiptLog(null);
  log.append(entry("a", "allow", 0.05));
  log.append(entry("b", "block", 40));
  log.append(entry("c", "allow", 0.05));
  return log;
};

describe("audit receipts", () => {
  it("an untouched chain verifies", () => {
    assert.deepEqual(verifyChain(filled().receipts), { ok: true, count: 3, brokenAt: null });
  });

  it("each receipt commits to the one before it", () => {
    const { receipts } = filled();
    assert.equal(receipts[1].prev, receipts[0].hash);
    assert.equal(receipts[2].prev, receipts[1].hash);
  });

  it("editing a past decision breaks the chain at that receipt", () => {
    const { receipts } = filled();
    receipts[1].body.decision = "allow"; // rewrite history: pretend the $40 was approved
    assert.deepEqual(verifyChain(receipts), { ok: false, count: 3, brokenAt: 2 });
  });

  it("deleting a receipt breaks the chain", () => {
    const { receipts } = filled();
    assert.equal(verifyChain([receipts[0], receipts[2]]).ok, false);
  });

  it("reordering receipts breaks the chain", () => {
    const { receipts } = filled();
    assert.equal(verifyChain([receipts[1], receipts[0], receipts[2]]).ok, false);
  });

  it("the memo fits in one Solana transaction and names the policy", () => {
    const [r] = filled().receipts;
    assert.ok(Buffer.byteLength(r.memo) < 300, "memo should stay well under the transaction size limit");
    assert.match(r.memo, /^lastlook:v1 seq=1 id=a allow usdc=0\.05 policy=[0-9a-f]{16} h=[0-9a-f]{32} prev=0{16}$/);
  });

  it("changing a limit changes the policy fingerprint", () => {
    assert.notEqual(policyHash(policy), policyHash({ ...policy, perTxLimit: usdc(500) }));
  });

  it("anchoring failures never lose the receipt, and can be retried", async () => {
    let fail = true;
    const log = new ReceiptLog(async () => {
      if (fail) throw new Error("Attempt to debit an account but found no record of a prior credit");
      return "sig123";
    });
    const r = log.append(entry("a", "block", 40));
    await log.settled();
    assert.equal(r.anchor.status, "failed");
    assert.equal(verifyChain(log.receipts).ok, true);
    fail = false;
    assert.equal(log.retryFailed(), 1);
    await log.settled();
    assert.deepEqual(r.anchor, { status: "anchored", signature: "sig123" });
  });
});
