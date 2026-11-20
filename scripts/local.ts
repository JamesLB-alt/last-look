// npm run local: the whole demo on a private Solana network on this machine. No faucets.
//
//   1. starts `solana-test-validator` (the real Solana runtime, with the Token and Memo programs)
//   2. preloads a TEST USDC mint at the devnet USDC address, with our own key as mint authority
//   3. gives the agent and the vendor SOL, and the agent $100 of test USDC
//   4. starts the firewall, dashboard and mock vendor against it
//
// Needs the Solana CLI: `brew install solana`. Devnet remains the default for `npm run dev`.
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";

// Must be set before anything imports src/config.ts.
const RPC = "http://127.0.0.1:8899";
process.env.SOLANA_RPC_URL = RPC;
process.env.SOLANA_WS_URL = "ws://127.0.0.1:8900";

const kit = await import("@solana/kit");
const token = await import("@solana-program/token");
const { USDC_DECIMALS, USDC_MINT, usdc } = await import("../src/config.ts");
const { loadOrCreate } = await import("../src/keys.ts");
const { ataFor } = await import("../src/firewall/firewall.ts");
const { rpc } = await import("../src/firewall/simulate.ts");

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const healthy = () => rpc.getHealth().send().then((h) => h === "ok", () => false);

const [agent, seller, faucet] = await Promise.all([loadOrCreate("agent"), loadOrCreate("seller"), loadOrCreate("faucet")]);
await loadOrCreate("attacker");

// ---- 1. the validator ------------------------------------------------------------
if (await healthy()) {
  console.log("⛓  A local validator is already running on :8899; using it.");
} else {
  const dir = new URL("../.local/", import.meta.url).pathname;
  mkdirSync(dir, { recursive: true });
  // An SPL Token mint account, exactly as it sits on-chain, with OUR key as the mint authority.
  const data = token.getMintEncoder().encode({ mintAuthority: kit.some(faucet.address), supply: 0n, decimals: USDC_DECIMALS, isInitialized: true, freezeAuthority: kit.none() });
  writeFileSync(
    `${dir}usdc-mint.json`,
    JSON.stringify({
      pubkey: USDC_MINT,
      account: { lamports: 1_461_600, data: [Buffer.from(data).toString("base64"), "base64"], owner: token.TOKEN_PROGRAM_ADDRESS, executable: false, rentEpoch: 0, space: data.length },
    }),
  );
  console.log("⛓  Starting a local Solana validator…");
  const child = spawn(
    "solana-test-validator",
    ["--reset", "--quiet", "--ledger", `${dir}ledger`, "--bind-address", "127.0.0.1", "--rpc-port", "8899", "--account", USDC_MINT, `${dir}usdc-mint.json`],
    { stdio: "ignore" },
  );
  child.on("error", () => {
    console.error("Couldn't start solana-test-validator. Install the Solana CLI first: brew install solana");
    process.exit(1);
  });
  process.on("exit", () => child.kill());
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(sig, () => process.exit(0));

  for (let i = 0; !(await healthy()); i++) {
    if (i > 120) {
      console.error("The validator didn't come up within a minute.");
      process.exit(1);
    }
    await sleep(500);
  }
}

// ---- 2. is the test USDC ours? -----------------------------------------------------
const mint = await token.fetchMint(rpc, USDC_MINT);
if (kit.unwrapOption(mint.data.mintAuthority) !== faucet.address) {
  console.error("The validator on :8899 wasn't started by `npm run local` (its USDC mint isn't ours). Stop it and run this again.");
  process.exit(1);
}

// ---- 3. funds ---------------------------------------------------------------------
const solOf = async (a: typeof agent.address) => (await rpc.getBalance(a, { commitment: "confirmed" }).send()).value;
for (const who of [agent, seller, faucet]) {
  if ((await solOf(who.address)) >= 1_000_000_000n) continue;
  await rpc.requestAirdrop(who.address, kit.lamports(5_000_000_000n), { commitment: "confirmed" }).send();
  for (let i = 0; (await solOf(who.address)) < 1_000_000_000n && i < 60; i++) await sleep(250);
}

const [agentAta, sellerAta] = await Promise.all([ataFor(agent.address), ataFor(seller.address)]);
const held = await rpc.getTokenAccountBalance(agentAta, { commitment: "confirmed" }).send().then((r) => BigInt(r.value.amount), () => 0n);
const sendAndConfirm = kit.sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions: kit.createSolanaRpcSubscriptions(process.env.SOLANA_WS_URL!) });
const { value: blockhash } = await rpc.getLatestBlockhash().send();
const signed = await kit.signTransactionMessageWithSigners(
  kit.pipe(
    kit.createTransactionMessage({ version: 0 }),
    (m) => kit.setTransactionMessageFeePayerSigner(faucet, m),
    (m) => kit.setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
    (m) =>
      kit.appendTransactionMessageInstructions(
        [
          token.getCreateAssociatedTokenIdempotentInstruction({ payer: faucet, ata: agentAta, owner: agent.address, mint: USDC_MINT }),
          token.getCreateAssociatedTokenIdempotentInstruction({ payer: faucet, ata: sellerAta, owner: seller.address, mint: USDC_MINT }),
          ...(held < usdc(50) ? [token.getMintToInstruction({ mint: USDC_MINT, token: agentAta, mintAuthority: faucet, amount: usdc(100) })] : []),
        ],
        m,
      ),
  ),
);
await sendAndConfirm(signed as Parameters<typeof sendAndConfirm>[0], { commitment: "confirmed" });

const usd = await rpc.getTokenAccountBalance(agentAta, { commitment: "confirmed" }).send();
console.log(`💰 Agent ${agent.address}: ${(Number(await solOf(agent.address)) / 1e9).toFixed(2)} SOL · $${usd.value.uiAmountString} test USDC`);
console.log("   This is a LOCAL network: the USDC is a test mint we control, not Circle's.\n");

// ---- 4. firewall + dashboard + mock vendor ----------------------------------------
await import("../src/dev.ts");
