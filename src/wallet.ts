// Live wallet + security-health data for the dashboard. Everything here is read
// from devnet or from the firewall's real state: no placeholder numbers.
import { address, type Address } from "@solana/kit";
import { NETWORK, USDC_DECIMALS } from "./config.ts";
import type { Firewall } from "./firewall/firewall.ts";
import { ataFor } from "./firewall/firewall.ts";
import { rpc } from "./firewall/simulate.ts";

export type Trusted = { name: string; owner: Address; ata: Address };

type TokenAccount = { usdc: number; delegate: string | null; delegatedUsdc: number; frozen: boolean } | null;

async function readUsdcAccount(owner: Address): Promise<TokenAccount> {
  const ata = await ataFor(owner);
  const { value } = await rpc.getAccountInfo(ata, { encoding: "jsonParsed" }).send();
  const info = (value?.data as any)?.parsed?.info;
  if (!info) return null; // no USDC account yet
  return {
    usdc: Number(info.tokenAmount.amount) / 10 ** USDC_DECIMALS,
    delegate: info.delegate ?? null,
    delegatedUsdc: info.delegatedAmount ? Number(info.delegatedAmount.amount) / 10 ** USDC_DECIMALS : 0,
    frozen: info.state === "frozen",
  };
}

const solOf = async (a: Address) => Number((await rpc.getBalance(address(a)).send()).value) / 1e9;

export async function walletSnapshot(fw: Firewall, trusted: Trusted[]) {
  const [sol, acct, trustedBalances] = await Promise.all([
    solOf(fw.address).catch(() => null),
    readUsdcAccount(fw.address).catch(() => null),
    Promise.all(trusted.map((t) => readUsdcAccount(t.owner).catch(() => null))),
  ]);
  return {
    address: fw.address,
    network: NETWORK.name,
    sol,
    usdc: acct?.usdc ?? 0,
    delegate: acct?.delegate ? { address: acct.delegate, usdc: acct.delegatedUsdc } : null,
    tokenAccountFrozen: acct?.frozen ?? false,
    frozen: fw.frozen,
    budget: fw.budget,
    trusted: trusted.map((t, i) => ({ ...t, usdc: trustedBalances[i]?.usdc ?? 0 })),
  };
}

type Check = { id: string; label: string; status: "ok" | "warn" | "fail"; detail: string; weight: number };

export function healthReport(fw: Firewall, w: Awaited<ReturnType<typeof walletSnapshot>>, watchdog: { connected: boolean; lastEventAt: string | null; source?: string }) {
  const p = fw.policy;
  const checks: Check[] = [
    {
      id: "key", weight: 20, status: "ok", label: "Key isolation",
      detail: "Only the firewall holds the signing key. The agent process has none.",
    },
    {
      id: "limits", weight: 15,
      status: p.perTxLimit > 0n && p.dailyLimit > 0n ? "ok" : "fail",
      label: "Spending limits",
      detail: `≤ $${(Number(p.perTxLimit) / 1e6).toFixed(2)} per payment, $${(Number(p.dailyLimit) / 1e6).toFixed(2)} per day`,
    },
    {
      id: "allowlist", weight: 10,
      status: p.allowlist.size > 0 ? "ok" : "warn",
      label: "Trusted recipients",
      detail: p.allowlist.size ? `${p.allowlist.size} allowlisted; everyone else needs approval or is blocked` : "No allowlist: every recipient is unknown",
    },
    {
      id: "delegate", weight: 25,
      status: w.delegate ? "fail" : "ok",
      label: "Open token approvals",
      detail: w.delegate
        ? `${w.delegate.address.slice(0, 4)}…${w.delegate.address.slice(-4)} can spend up to $${w.delegate.usdc.toFixed(2)} without asking`
        : "No one else can spend this wallet's USDC",
    },
    {
      id: "fees", weight: 10,
      // Zero SOL means no payment can land at all: that's a failure, not a nudge.
      status: w.sol === null ? "warn" : w.sol >= 0.01 ? "ok" : w.sol > 0 ? "warn" : "fail",
      label: "Fee balance",
      detail: w.sol === null ? "Couldn't read SOL balance" : w.sol >= 0.01 ? `${w.sol.toFixed(3)} SOL for network fees` : w.sol > 0 ? `Only ${w.sol.toFixed(3)} SOL: payments may fail soon` : "No SOL for network fees: every payment will fail",
    },
    {
      id: "watchdog", weight: 20,
      status: watchdog.connected ? "ok" : "warn",
      label: "Out-of-band watchdog",
      detail: watchdog.connected
        ? `${watchdog.source ?? "QuickNode Stream"} live${watchdog.lastEventAt ? `, last event ${new Date(watchdog.lastEventAt).toLocaleTimeString()}` : ""}`
        : "Not connected: money moved outside the firewall wouldn't be noticed",
    },
  ];
  const earned = checks.reduce((s, c) => s + (c.status === "ok" ? c.weight : c.status === "warn" ? c.weight / 2 : 0), 0);
  const hourAgo = Date.now() - 3600_000;
  // Only count blocks that look like attacks (tainted context, unknown recipient,
  // or a dangerous instruction), not freezes or routine policy refusals.
  const recentBlocks = fw.events.filter(
    (e) =>
      e.decision === "block" &&
      e.decidedBy === "policy" &&
      Date.parse(e.at) > hourAgo &&
      !e.reasons.some((r) => r.startsWith("Spending is frozen")) &&
      (e.context.tainted || e.signals.unknownRecipients.length > 0 || e.signals.dangerousActions.length > 0),
  ).length;
  return { score: Math.round(earned), checks, recentBlocks, frozen: fw.frozen };
}
