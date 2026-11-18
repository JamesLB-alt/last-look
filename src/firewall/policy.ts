import type { Address } from "@solana/kit";
import { fmtUsdc, USDC_MINT } from "../config.ts";
import type { Action, Decoded } from "./decode.ts";
import type { Simulation } from "./simulate.ts";

export type Decision = "allow" | "ask" | "block";
export type Verdict = { decision: Decision; reasons: string[] };

/** What the agent tells the firewall about WHY it wants to pay. */
export type AgentContext = {
  tool: string; // e.g. "fetch_paid_api", "send_usdc"
  purpose: string; // the agent's own one-line justification
  /** True if the agent read untrusted content (web pages, emails) since its last user instruction. */
  tainted: boolean;
};

export type Policy = {
  perTxLimit: bigint; // never auto-approve a single payment above this
  dailyLimit: bigint; // total USDC the agent can spend per day
  askAbove: bigint; // payments above this need a human, even to known recipients
  /** USDC token account (ATA) → human name of the trusted recipient */
  allowlist: Map<Address, string>;
};

/** Every fact the firewall knows about one signing request. No opinions here. */
export type Signals = {
  outflow: bigint; // total USDC leaving the agent in this tx
  spentToday: bigint; // already approved today, before this tx
  overPerTx: boolean;
  overDaily: boolean;
  overAskThreshold: boolean;
  unknownRecipients: Address[]; // destination ATAs NOT on the allowlist
  dangerousActions: Action[]; // approve / set-authority / close / unknown programs
  solOut: bigint; // lamports sent directly (excluding fees and rent)
  tainted: boolean;
  simulationFailed: boolean;
  simulationMismatch: boolean; // simulated balance change ≠ decoded outflow (something hidden)
};

const DANGEROUS = new Set<Action["kind"]>(["token-approve", "token-set-authority", "token-close", "unknown"]);

export function signals(d: Decoded, sim: Simulation, ctx: AgentContext, policy: Policy, spentToday: bigint): Signals {
  const transfers = d.actions.filter((a) => a.kind === "token-transfer");
  // An unchecked Transfer (mint: null) out of the agent's ATA still moves USDC.
  const outflow = transfers.filter((t) => t.mint === null || t.mint === USDC_MINT).reduce((s, t) => s + t.amount, 0n);
  const unknownRecipients = transfers.map((t) => t.toAta).filter((ata) => !policy.allowlist.has(ata));

  return {
    outflow,
    spentToday,
    overPerTx: outflow > policy.perTxLimit,
    overDaily: spentToday + outflow > policy.dailyLimit,
    overAskThreshold: outflow > policy.askAbove,
    unknownRecipients: [...new Set(unknownRecipients)],
    dangerousActions: d.actions.filter((a) => DANGEROUS.has(a.kind)),
    solOut: d.actions.reduce((s, a) => (a.kind === "sol-transfer" ? s + a.lamports : s), 0n),
    tainted: ctx.tainted,
    simulationFailed: !sim.ok,
    simulationMismatch: sim.usdcDelta !== null && -sim.usdcDelta !== outflow,
  };
}

/**
 * THE decision. Every rule here is a safety limit you'll document in the README
 * (the track requires it) and defend in Q&A.
 *
 * Contract:
 *  - return "block" for anything that must never happen without a code change
 *  - return "ask" for anything a human should glance at
 *  - return "allow" only when you're confident; this gets signed with no human
 *  - every reason is a short FACT shown on the dashboard, e.g. "$40.00 is over the $5.00 per-payment limit"
 *
 * Questions only you can answer:
 *  - Tainted + unknown recipient: block outright, or ask a human?
 *    (Injection attacks live here. Ask = a tired human might click Approve.)
 *  - Tainted + KNOWN recipient (paying the allowlisted data vendor after reading the web): allow?
 *  - Is ANY dangerous action (approve, set-authority, close, unknown program) an instant block?
 *  - Simulation failed: block (fail closed) or ask?
 *  - Does overDaily block, or ask?
 */
export function evaluate(s: Signals, policy: Policy): Verdict {
  const amount = fmtUsdc(s.outflow);
  const unknown = s.unknownRecipients.length > 0;

  // ---- BLOCK: never signed without a code or policy change -------------------
  const block: string[] = [];
  if (s.dangerousActions.length)
    // Approvals, ownership changes, closes and unknown programs are how wallets get drained.
    // A payment agent never needs them, so there's no "ask" path.
    block.push(`Contains ${[...new Set(s.dangerousActions.map((a) => a.kind))].join(", ")}: an agent never needs this`);
  if (s.solOut > 0n) block.push("Sends SOL directly: the agent only pays in USDC");
  if (s.simulationMismatch) block.push("Simulated balance change doesn't match the instructions: something is hidden");
  if (s.overPerTx) block.push(`${amount} is over the ${fmtUsdc(policy.perTxLimit)} per-payment limit`);
  if (s.overDaily) block.push(`${amount} would exceed today's ${fmtUsdc(policy.dailyLimit)} budget (${fmtUsdc(s.spentToday)} already spent)`);
  if (s.tainted && unknown)
    // The prompt-injection rule: the agent read text we don't control, and now wants to
    // pay someone we've never trusted. Blocked, not asked: a tired human clicks Approve.
    block.push("Agent read untrusted content and now wants to pay a recipient that isn't on the allowlist");
  if (block.length) return { decision: "block", reasons: block };

  // ---- ASK: a human glances at it on the dashboard -----------------------------
  const ask: string[] = [];
  if (unknown) ask.push("Recipient isn't on the allowlist");
  if (s.overAskThreshold) ask.push(`${amount} is above your ${fmtUsdc(policy.askAbove)} ask-me threshold`);
  // Fail toward a human, not toward signing: if we couldn't dry-run it, someone should look.
  if (s.simulationFailed) ask.push("Couldn't simulate this transaction, so its real effect is unverified");
  if (ask.length) return { decision: "ask", reasons: ask };

  // ---- ALLOW: small, simulated, to a trusted recipient ------------------------
  return {
    decision: "allow",
    reasons: s.outflow > 0n
      ? [`${amount} to an allowlisted recipient, under the ${fmtUsdc(policy.askAbove)} auto-approve limit`]
      : ["Moves no USDC"],
  };
}

// Re-exported so evaluate() can format reasons without extra imports.
export { fmtUsdc };
