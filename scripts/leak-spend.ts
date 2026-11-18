// npm run demo:leak: the "leaked key" demo. Sends $1 USDC from the agent wallet to
// the attacker by loading the private key DIRECTLY, bypassing Last Look entirely.
// With the QuickNode Stream running, the dashboard should flash the out-of-band alert
// within a few seconds, because no signature Last Look produced is on this transaction.
//
// Devnet only. Needs a funded agent wallet (npm run setup).
import { explorerTx } from "../src/config.ts";
import { sendUsdc } from "../src/client/transfer.ts";
import { loadOrCreate, publicAddress } from "../src/keys.ts";

const leakedKey = await loadOrCreate("agent"); // pretend this key leaked
const attacker = await publicAddress("attacker");
console.log("🔓 Using the agent's private key directly (simulating a leak). Last Look is NOT asked.");
try {
  const { signature } = await sendUsdc(leakedKey, attacker, 1);
  console.log(`💸 $1.00 USDC sent around the firewall: ${explorerTx(signature)}`);
  console.log("👀 Watch the dashboard: QuickNode should report it as out-of-band.");
} catch (e) {
  console.error(`❌ ${(e as Error).message}\n   Is the agent wallet funded with devnet SOL and USDC? (npm run setup)`);
}
process.exit(0);
