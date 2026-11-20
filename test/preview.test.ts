// The rule tester must give the same answers as the real door, and must never change anything.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { address, generateKeyPairSigner } from "@solana/kit";
import { usdc } from "../src/config.ts";
import { Firewall } from "../src/firewall/firewall.ts";

const make = async () =>
  Firewall.create(
    await generateKeyPairSigner(),
    { perTxLimit: usdc(5), dailyLimit: usdc(20), askAbove: usdc(1), allowlist: new Map([[address("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"), "DataCo API"]]) },
    { anchor: false },
  );

describe("policy preview", () => {
  it("small payment to a trusted recipient is allowed", async () => {
    assert.equal((await make()).preview(usdc(0.5), true, false).decision, "allow");
  });

  it("above the ask-me threshold goes to a human", async () => {
    assert.equal((await make()).preview(usdc(3), true, false).decision, "ask");
  });

  it("untrusted content plus an unknown recipient is blocked, even for cents", async () => {
    assert.equal((await make()).preview(usdc(0.01), false, true).decision, "block");
  });

  it("over the per-payment limit is blocked", async () => {
    assert.equal((await make()).preview(usdc(50), true, false).decision, "block");
  });

  it("everything is blocked while frozen", async () => {
    const fw = await make();
    fw.frozen = true;
    assert.equal(fw.preview(usdc(0.05), true, false).decision, "block");
  });

  it("is read-only: no event, no receipt, no budget spent", async () => {
    const fw = await make();
    fw.preview(usdc(0.5), true, false);
    assert.equal(fw.events.length, 0);
    assert.equal(fw.receipts.receipts.length, 0);
    assert.equal(fw.budget.spentToday, 0n);
  });
});
