// npm test: the firewall's safety limits, one test per rule we'd defend in Q&A.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { address } from "@solana/kit";
import { usdc } from "../src/config.ts";
import type { Action } from "../src/firewall/decode.ts";
import { evaluate, type Policy, type Signals } from "../src/firewall/policy.ts";

const policy: Policy = { perTxLimit: usdc(5), dailyLimit: usdc(20), askAbove: usdc(1), allowlist: new Map() };
const stranger = address("PyxswJSPjFzHX3RjEBi4YsvTYV2KPNXEV7jDPhEg4be");

/** A clean, small payment to a trusted vendor. Each test changes one thing. */
const base = (o: Partial<Signals> = {}): Signals => ({
  outflow: usdc(0.05),
  spentToday: 0n,
  overPerTx: false,
  overDaily: false,
  overAskThreshold: false,
  unknownRecipients: [],
  dangerousActions: [],
  solOut: 0n,
  tainted: false,
  simulationFailed: false,
  simulationMismatch: false,
  ...o,
});

describe("evaluate()", () => {
  it("allows a small payment to an allowlisted vendor", () => {
    assert.equal(evaluate(base(), policy).decision, "allow");
  });

  it("still allows paying the trusted vendor after reading the web (the demo's happy path)", () => {
    assert.equal(evaluate(base({ tainted: true }), policy).decision, "allow");
  });

  it("BLOCKS the injection: tainted context + unknown recipient", () => {
    const v = evaluate(base({ tainted: true, unknownRecipients: [stranger], outflow: usdc(0.5) }), policy);
    assert.equal(v.decision, "block");
    assert.match(v.reasons.join(), /untrusted content/);
  });

  it("blocks even a tiny injected payment ('stay under the limit' doesn't help the attacker)", () => {
    assert.equal(evaluate(base({ tainted: true, unknownRecipients: [stranger], outflow: usdc(0.01) }), policy).decision, "block");
  });

  it("asks a human for an unknown recipient when the context is clean", () => {
    assert.equal(evaluate(base({ unknownRecipients: [stranger] }), policy).decision, "ask");
  });

  it("asks above the auto-approve threshold", () => {
    const v = evaluate(base({ outflow: usdc(2), overAskThreshold: true }), policy);
    assert.equal(v.decision, "ask");
    assert.match(v.reasons.join(), /\$1\.00 ask-me threshold/);
  });

  it("blocks over the per-payment limit, with the amount in the reason", () => {
    const v = evaluate(base({ outflow: usdc(40), overPerTx: true, overAskThreshold: true }), policy);
    assert.equal(v.decision, "block");
    assert.match(v.reasons.join(), /\$40\.00 is over the \$5\.00/);
  });

  it("blocks when the daily budget would be exceeded", () => {
    assert.equal(evaluate(base({ overDaily: true, spentToday: usdc(19.99) }), policy).decision, "block");
  });

  it("blocks any approval / ownership change / unknown program, however small", () => {
    const approve: Action = { kind: "token-approve", delegate: stranger, amount: 1n, ata: stranger };
    assert.equal(evaluate(base({ dangerousActions: [approve], outflow: 0n }), policy).decision, "block");
  });

  it("blocks direct SOL transfers", () => {
    assert.equal(evaluate(base({ solOut: 1_000_000n }), policy).decision, "block");
  });

  it("blocks when simulation shows more leaving than the instructions claim", () => {
    assert.equal(evaluate(base({ simulationMismatch: true }), policy).decision, "block");
  });

  it("asks (doesn't sign) when simulation fails", () => {
    assert.equal(evaluate(base({ simulationFailed: true }), policy).decision, "ask");
  });

  it("one block reason beats any number of ask reasons", () => {
    const v = evaluate(base({ overPerTx: true, overAskThreshold: true, unknownRecipients: [stranger], simulationFailed: true }), policy);
    assert.equal(v.decision, "block");
  });
});
