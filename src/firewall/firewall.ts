import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import {
  type Address,
  getBase58Decoder,
  getBase64Decoder,
  type KeyPairSigner,
  partiallySignTransaction,
} from "@solana/kit";
import { findAssociatedTokenPda, TOKEN_PROGRAM_ADDRESS } from "@solana-program/token";
import { USDC_MINT } from "../config.ts";
import { decodeWireTransaction, type Action } from "./decode.ts";
import { evaluate, signals, type AgentContext, type Decision, type Policy, type Signals } from "./policy.ts";
import { simulate, type Simulation } from "./simulate.ts";

export type Event = {
  id: string;
  at: string;
  context: AgentContext;
  actions: Action[];
  /** Who gets paid, resolved for display: allowlist name, or the owner if the tx reveals it. */
  recipients: { ata: Address; name: string | null; owner: Address | null }[];
  signals: Signals;
  simulation: Pick<Simulation, "ok" | "error" | "usdcDelta">;
  decision: Decision | "pending";
  finalDecision?: "allow" | "block";
  reasons: string[];
  decidedBy?: "policy" | "human" | "timeout";
};

export type SignResult =
  | { decision: "allow"; id: string; signature: string; reasons: string[] }
  | { decision: "block"; id: string; reasons: string[] };

const ASK_TIMEOUT_MS = 120_000;

export const ataFor = async (owner: Address) =>
  (await findAssociatedTokenPda({ owner, mint: USDC_MINT, tokenProgram: TOKEN_PROGRAM_ADDRESS }))[0];

export class Firewall extends EventEmitter {
  readonly events: Event[] = [];
  /** Owner's kill switch. While true, nothing is signed, whatever the policy says. */
  frozen = false;
  /** Base58 signatures this firewall produced. Anything else moving our funds is out-of-band. */
  readonly ourSignatures = new Set<string>();
  private spentToday = 0n;
  private day = new Date().toDateString();
  private pending = new Map<string, (approved: boolean) => void>();

  private constructor(
    private readonly agent: KeyPairSigner,
    readonly agentAta: Address,
    readonly policy: Policy,
  ) {
    super();
  }

  static async create(agent: KeyPairSigner, policy: Policy) {
    return new Firewall(agent, await ataFor(agent.address), policy);
  }

  get address() {
    return this.agent.address;
  }

  get budget() {
    this.rollDay();
    return { spentToday: this.spentToday, dailyLimit: this.policy.dailyLimit };
  }

  /** The one door. Decode → simulate → evaluate → (maybe ask a human) → sign or refuse. */
  async handleSign(wireBase64: string, context: AgentContext): Promise<SignResult> {
    this.rollDay();
    const id = randomUUID().slice(0, 8);
    const decoded = decodeWireTransaction(wireBase64);

    // Refuse to sign anything where our key isn't the one being asked for.
    if (!(this.agent.address in decoded.transaction.signatures)) {
      return { decision: "block", id, reasons: ["transaction does not request the agent wallet's signature"] };
    }

    const sim = await simulate(wireBase64, this.agentAta);
    const sig = signals(decoded, sim, context, this.policy, this.spentToday);
    const recipients = [...new Set(decoded.actions.flatMap((a) => (a.kind === "token-transfer" ? [a.toAta] : [])))].map((ata) => ({
      ata,
      name: this.policy.allowlist.get(ata) ?? null,
      owner:
        decoded.actions.find((a): a is Extract<Action, { kind: "create-ata" }> => a.kind === "create-ata" && a.ata === ata)?.owner ??
        null,
    }));
    const { approved, event } = await this.decide(id, context, decoded.actions, recipients, sig, {
      ok: sim.ok,
      error: sim.error,
      usdcDelta: sim.usdcDelta,
    });
    if (!approved) return { decision: "block", id, reasons: event.reasons };

    const signed = await partiallySignTransaction([this.agent.keyPair], decoded.transaction);
    const sigBytes = signed.signatures[this.agent.address]!;
    // Remember every signature we produce, so the watchdog can tell our spends
    // apart from money that moved some other way (a leaked key).
    this.ourSignatures.add(getBase58Decoder().decode(sigBytes));
    return { decision: "allow", id, signature: getBase64Decoder().decode(sigBytes), reasons: event.reasons };
  }

  /**
   * Off-chain spends (e.g. a prediction-market order) go through the SAME policy,
   * approval flow and daily budget as on-chain payments. The venue's API keys live
   * in this process too, so the agent can't place orders around us.
   */
  async handleOffchain(spend: { venue: string; trusted: boolean; amount: bigint; context: AgentContext }) {
    this.rollDay();
    const id = randomUUID().slice(0, 8);
    const venueId = `offchain:${spend.venue}` as Address;
    const p = this.policy;
    const sig: Signals = {
      outflow: spend.amount,
      spentToday: this.spentToday,
      overPerTx: spend.amount > p.perTxLimit,
      overDaily: this.spentToday + spend.amount > p.dailyLimit,
      overAskThreshold: spend.amount > p.askAbove,
      unknownRecipients: spend.trusted ? [] : [venueId],
      dangerousActions: [],
      solOut: 0n,
      tainted: spend.context.tainted,
      simulationFailed: false,
      simulationMismatch: false,
    };
    return this.decide(id, spend.context, [], [{ ata: venueId, name: spend.venue, owner: null }], sig, {
      ok: true,
      error: null,
      usdcDelta: null,
    });
  }

  /** Policy → (maybe a human) → record. Shared by on-chain and off-chain spends. */
  private async decide(
    id: string,
    context: AgentContext,
    actions: Action[],
    recipients: Event["recipients"],
    sig: Signals,
    simulation: Event["simulation"],
  ) {
    const verdict = this.frozen
      ? { decision: "block" as const, reasons: ["Spending is frozen by the owner. Nothing is signed until it's unfrozen."] }
      : evaluate(sig, this.policy);

    const event: Event = {
      id,
      at: new Date().toISOString(),
      context,
      actions,
      recipients,
      signals: sig,
      simulation,
      decision: verdict.decision === "ask" ? "pending" : verdict.decision,
      reasons: verdict.reasons,
      decidedBy: verdict.decision === "ask" ? undefined : "policy",
    };
    this.record(event);

    let approved = verdict.decision === "allow";
    if (verdict.decision === "ask") {
      approved = await this.waitForHuman(id);
      event.decidedBy = this.pending.has(id) ? "timeout" : event.decidedBy ?? "human";
      this.pending.delete(id);
    }
    event.finalDecision = approved ? "allow" : "block";
    if (event.decision === "pending") event.decision = event.finalDecision;
    this.update(event);

    // Count the spend when we APPROVE, not when it settles: a signed tx can land later.
    if (approved) this.spentToday += sig.outflow;
    return { approved, event };
  }

  resolve(id: string, approved: boolean) {
    const done = this.pending.get(id);
    if (!done) return false;
    const ev = this.events.find((e) => e.id === id);
    if (ev) ev.decidedBy = "human";
    this.pending.delete(id);
    done(approved);
    return true;
  }

  private waitForHuman(id: string) {
    return new Promise<boolean>((resolve) => {
      this.pending.set(id, resolve);
      // No answer in time → deny. `pending` keeps the id so the caller can tell it timed out.
      setTimeout(() => this.pending.get(id)?.(false), ASK_TIMEOUT_MS);
    });
  }

  private rollDay() {
    const today = new Date().toDateString();
    if (today !== this.day) [this.day, this.spentToday] = [today, 0n];
  }

  private record(e: Event) {
    this.events.unshift(e);
    this.emit("event", e);
  }

  private update(e: Event) {
    this.emit("event", e);
  }
}
