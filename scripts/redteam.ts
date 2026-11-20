// npm run redteam: fire every known drain technique at the running firewall and print the scoreboard.
import { FIREWALL_URL } from "../src/config.ts";
import type { AttackResult } from "../src/redteam.ts";

const res = await fetch(`${FIREWALL_URL}/api/redteam/run`, { method: "POST" });
if (!res.ok) {
  console.error(`Couldn't run: ${(await res.text()).slice(0, 300)}\nIs the firewall running? (npm run dev)`);
  process.exit(1);
}
const { caught, total, results } = (await res.json()) as { caught: number; total: number; results: AttackResult[] };
console.log(`\nLast Look red team: ${caught}/${total} attacks stopped\n`);
for (const r of results) {
  console.log(`${r.caught ? "⛔" : "❌"} ${r.name.padEnd(36)} ${r.layer.padEnd(11)} ${r.outcome.padEnd(12)} ${r.ms === null ? "" : `${r.ms} ms`}`);
  console.log(`   ${r.reason}`);
}
process.exit(caught === total ? 0 : 1);
