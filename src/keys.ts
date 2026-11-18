import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import {
  createKeyPairSignerFromBytes,
  createKeyPairSignerFromPrivateKeyBytes,
  getAddressEncoder,
  type KeyPairSigner,
} from "@solana/kit";

// DEVNET-ONLY keypairs, stored in ./keys (gitignored) in solana-keygen's
// 64-byte JSON format, so `solana balance -k keys/agent.json` also works.
//
//   agent    – the AI agent's wallet. ONLY the firewall process loads this.
//   seller   – our mock x402 data vendor (allowlisted merchant)
//   attacker – the prompt-injection attacker's wallet (for the demo)
export type KeyName = "agent" | "seller" | "attacker";

const DIR = new URL("../keys/", import.meta.url);

export async function loadOrCreate(name: KeyName): Promise<KeyPairSigner> {
  const file = new URL(`${name}.json`, DIR);
  if (existsSync(file)) {
    const bytes = new Uint8Array(JSON.parse(readFileSync(file, "utf8")));
    return createKeyPairSignerFromBytes(bytes);
  }
  mkdirSync(DIR, { recursive: true });
  const priv = webcrypto.getRandomValues(new Uint8Array(32));
  const signer = await createKeyPairSignerFromPrivateKeyBytes(priv);
  const pub = getAddressEncoder().encode(signer.address);
  writeFileSync(file, JSON.stringify([...priv, ...pub]), { mode: 0o600 });
  // Reload from the 64-byte file so we exercise the same path every time.
  return createKeyPairSignerFromBytes(new Uint8Array([...priv, ...pub]));
}

/** Public address only; for processes that must NOT hold the private key. */
export async function publicAddress(name: KeyName) {
  return (await loadOrCreate(name)).address;
}
