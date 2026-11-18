// Last Look for individuals: two tools anyone can use without an account.
//   1. checkup(address): live read of a wallet's token accounts, flagging open approvals
//   2. inspect(tx):      what a transaction really does, before you sign it
// Both reuse the firewall's decoder and simulator. Nothing here signs anything.
import {
  type Address,
  address,
  appendTransactionMessageInstructions,
  compileTransaction,
  createNoopSigner,
  createTransactionMessage,
  getBase64EncodedWireTransaction,
  isAddress,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
} from "@solana/kit";
import {
  AuthorityType,
  getApproveCheckedInstruction,
  getSetAuthorityInstruction,
  getTransferCheckedInstruction,
  TOKEN_PROGRAM_ADDRESS,
} from "@solana-program/token";
import { TOKEN_2022_PROGRAM_ADDRESS as TOKEN_2022 } from "@solana-program/token-2022";
import { USDC_DECIMALS, USDC_MINT } from "./config.ts";
import { type Action, decodeWireTransaction } from "./firewall/decode.ts";
import { ataFor } from "./firewall/firewall.ts";
import { rpc, simulate } from "./firewall/simulate.ts";

const U64_MAX = 18446744073709551615n;
const KNOWN_MINTS: Record<string, string> = { [USDC_MINT]: "USDC" };
const short = (a: string) => `${a.slice(0, 4)}…${a.slice(-4)}`;
const symbol = (mint: string | null) => (mint && KNOWN_MINTS[mint]) || (mint ? `token ${short(mint)}` : "tokens");

export type Severity = "critical" | "high" | "medium" | "info";
export type Flag = { severity: Severity; title: string; detail: string; fix?: string };

// ---------------------------------------------------------------- checkup ----
export async function checkup(addr: string) {
  if (!isAddress(addr)) throw new Error("That isn't a valid Solana address.");
  const owner = address(addr);

  const [sol, classic, t22, sigs] = await Promise.all([
    rpc.getBalance(owner).send().then((r) => Number(r.value) / 1e9),
    rpc.getTokenAccountsByOwner(owner, { programId: TOKEN_PROGRAM_ADDRESS }, { encoding: "jsonParsed" }).send(),
    rpc.getTokenAccountsByOwner(owner, { programId: TOKEN_2022 }, { encoding: "jsonParsed" }).send(),
    rpc.getSignaturesForAddress(owner, { limit: 25 }).send().catch(() => []),
  ]);

  const tokens = [...classic.value, ...t22.value].map((acc) => {
    const info = (acc.account.data as any).parsed.info;
    return {
      account: acc.pubkey as string,
      mint: info.mint as string,
      symbol: symbol(info.mint),
      amount: Number(info.tokenAmount.uiAmountString ?? 0),
      delegate: (info.delegate as string | undefined) ?? null,
      delegatedRaw: info.delegatedAmount ? BigInt(info.delegatedAmount.amount) : 0n,
      delegated: info.delegatedAmount ? Number(info.delegatedAmount.uiAmountString) : 0,
      frozen: info.state === "frozen",
    };
  });

  const flags: Flag[] = [];
  for (const t of tokens) {
    if (t.delegate) {
      const unlimited = t.delegatedRaw >= U64_MAX / 2n;
      flags.push({
        severity: unlimited ? "critical" : "high",
        title: unlimited ? `Unlimited ${t.symbol} approval is open` : `${t.symbol} approval is open`,
        detail: `${short(t.delegate)} can move ${unlimited ? "ALL of" : `up to ${t.delegated}`} your ${t.symbol} without asking you again.`,
        fix: `Revoke it in your wallet's approvals screen, or run: spl-token revoke ${t.account}`,
      });
    }
    if (t.frozen) flags.push({ severity: "medium", title: `${t.symbol} account is frozen`, detail: "The token's issuer froze this account. You can't move these tokens." });
  }
  if (sol === 0) flags.push({ severity: "medium", title: "No SOL for fees", detail: "This wallet can't send anything until it holds a little SOL." });
  const failed = sigs.filter((s) => s.err !== null).length;
  if (failed >= 3) flags.push({ severity: "info", title: `${failed} failed transactions recently`, detail: "Repeated failures can mean a dApp is asking for things this wallet can't do." });

  const penalty: Record<Severity, number> = { critical: 45, high: 25, medium: 10, info: 0 };
  const score = Math.max(0, 100 - flags.reduce((s, f) => s + penalty[f.severity], 0));
  return {
    address: owner,
    network: "Solana Devnet",
    sol,
    tokens: tokens.map(({ delegatedRaw, ...t }) => t),
    activity: { recent: sigs.length, failed, last: sigs[0]?.blockTime ? new Date(Number(sigs[0].blockTime) * 1000).toISOString() : null },
    flags,
    score,
  };
}

// ---------------------------------------------------------------- inspect ----
function describe(a: Action, all: Action[], payer: string): { text: string; flag?: Flag } {
  switch (a.kind) {
    case "token-transfer": {
      const amt = a.mint === USDC_MINT ? `$${(Number(a.amount) / 10 ** USDC_DECIMALS).toFixed(2)} USDC` : `${a.amount} units of ${symbol(a.mint)}`;
      const fresh = all.some((x) => x.kind === "create-ata" && x.ata === a.toAta);
      return {
        text: `Sends ${amt} to account ${short(a.toAta)}${fresh ? " (a brand-new account created in this same transaction)" : ""}.`,
        flag: fresh ? { severity: "medium", title: "Recipient has never held this token", detail: "The receiving account is created by this transaction. Double-check the address if you expected someone you've paid before." } : undefined,
      };
    }
    case "token-approve": {
      const unlimited = a.amount >= U64_MAX / 2n;
      return {
        text: `Gives ${short(a.delegate)} permission to spend ${unlimited ? "ALL" : a.amount.toString() + " units"} of the tokens in ${short(a.ata)}, now and later, without asking you again.`,
        flag: {
          severity: unlimited ? "critical" : "high",
          title: unlimited ? "Unlimited spending approval" : "Spending approval",
          detail: "Approvals outlive the transaction. This is the most common way wallets get drained.",
          fix: "Only approve the exact amount needed, and only for apps you trust.",
        },
      };
    }
    case "token-set-authority":
      return {
        text: `Hands control of your token account ${short(a.account)} to ${a.newAuthority ? short(a.newAuthority) : "nobody"}.`,
        flag: { severity: "critical", title: "Gives away ownership of your account", detail: "After this, someone else owns the account and everything in it. No legitimate app needs this.", fix: "Don't sign." },
      };
    case "token-close":
      return {
        text: `Closes token account ${short(a.account)} and sends its rent to ${short(a.rentTo)}.`,
        flag: a.rentTo !== payer ? { severity: "medium", title: "Account rent goes to someone else", detail: "Closing an account normally refunds you, not a third party." } : undefined,
      };
    case "sol-transfer":
      return {
        text: `Sends ${(Number(a.lamports) / 1e9).toFixed(4)} SOL to ${short(a.to)}.`,
        flag: Number(a.lamports) > 1e9 ? { severity: "medium", title: "Large SOL transfer", detail: "Confirm you meant to send more than 1 SOL." } : undefined,
      };
    case "create-ata":
      return { text: `Creates a ${symbol(a.mint)} account for ${short(a.owner)}.` };
    case "benign":
      return { text: a.program === "memo" ? "Attaches a memo (a note)." : "Sets the network fee priority." };
    case "unknown":
      return {
        text: `Calls a program Last Look doesn't recognize (${short(a.program)})${a.note ? `: ${a.note}` : ""}.`,
        flag: { severity: "medium", title: "Unrecognized program", detail: "We can't explain what this step does. Simulation below shows its effect on your balance." },
      };
  }
}

export async function inspect(base64: string) {
  const d = decodeWireTransaction(base64);
  const steps = d.actions.map((a) => describe(a, d.actions, d.feePayer));
  const sim = await simulate(base64, await ataFor(d.feePayer));
  const flags = steps.flatMap((s) => (s.flag ? [s.flag] : []));
  if (!sim.ok) flags.push({ severity: "info", title: "Simulation failed", detail: `The network would reject this right now (${sim.error}). It may still work later, so judge it by the steps above.` });
  const verdict = flags.some((f) => f.severity === "critical") ? "danger" : flags.some((f) => f.severity === "high" || f.severity === "medium") ? "caution" : "normal";
  return { signer: d.feePayer, steps: steps.map((s) => s.text), flags, simulation: { ok: sim.ok, error: sim.error, usdcDelta: sim.usdcDelta?.toString() ?? null }, verdict };
}

// --------------------------------------------------------------- examples ----
/** Unsigned example transactions so anyone can try the inspector without a wallet. */
export async function examples(you: Address, attacker: Address, friend: Address) {
  const signer = createNoopSigner(you);
  const { value: blockhash } = await rpc.getLatestBlockhash().send();
  const [yourUsdc, friendUsdc] = await Promise.all([ataFor(you), ataFor(friend)]);
  const build = (ixs: Parameters<typeof appendTransactionMessageInstructions>[0]) =>
    getBase64EncodedWireTransaction(
      compileTransaction(
        pipe(
          createTransactionMessage({ version: 0 }),
          (m) => setTransactionMessageFeePayerSigner(signer, m),
          (m) => setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
          (m) => appendTransactionMessageInstructions(ixs, m),
        ),
      ),
    );
  return [
    {
      id: "airdrop",
      label: "“Claim your free airdrop”",
      blurb: "A site promises free tokens and asks you to sign.",
      transaction: build([getApproveCheckedInstruction({ source: yourUsdc, mint: USDC_MINT, delegate: attacker, owner: signer, amount: U64_MAX, decimals: USDC_DECIMALS })]),
    },
    {
      id: "upgrade",
      label: "“Upgrade your wallet security”",
      blurb: "A support DM sends you a 'security upgrade' to sign.",
      transaction: build([getSetAuthorityInstruction({ owned: yourUsdc, owner: signer, authorityType: AuthorityType.AccountOwner, newAuthority: attacker })]),
    },
    {
      id: "friend",
      label: "Pay a friend $5",
      blurb: "A normal USDC payment.",
      transaction: build([getTransferCheckedInstruction({ source: yourUsdc, mint: USDC_MINT, destination: friendUsdc, authority: signer, amount: 5_000_000n, decimals: USDC_DECIMALS })]),
    },
  ];
}
