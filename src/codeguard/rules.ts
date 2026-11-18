// Code Guard: crypto-specific security rules across a company's whole codebase.
// Deterministic on purpose: every finding points at a real file and line.
// (Claude only summarizes findings afterwards; it never invents them.)

export type Facet = "frontend" | "backend" | "cloud" | "agent" | "onchain";
export type Severity = "critical" | "high" | "medium";

export type SourceFile = { path: string; content: string; lines: string[]; facet: Facet };
export type Hit = { line: number }; // 1-based

export type Rule = {
  id: string;
  title: string;
  severity: Severity;
  /** Force a facet; otherwise the finding inherits the file's facet. */
  facet?: Facet;
  why: string;
  fix: string;
  appliesTo?: (f: SourceFile) => boolean;
  find: (f: SourceFile) => Hit[];
};

const CODE = /\.(m?[jt]sx?|py|rs|go|sol|vue|svelte)$/;
const isCode = (f: SourceFile) => CODE.test(f.path);
const isFrontend = (f: SourceFile) => f.facet === "frontend";

/** Every line (1-based) whose text matches `re`. */
const lines = (f: SourceFile, re: RegExp): Hit[] =>
  f.lines.flatMap((l, i) => (re.test(l) ? [{ line: i + 1 }] : []));

/** Whole-file regex → line numbers of each match start. */
const matches = (f: SourceFile, re: RegExp): Hit[] => {
  const out: Hit[] = [];
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  for (const m of f.content.matchAll(g)) out.push({ line: f.content.slice(0, m.index).split("\n").length });
  return out;
};

export const LLM_SDK =/from\s+["'](@anthropic-ai\/sdk|openai|@ai-sdk\/[\w-]+|ai|langchain[\w/-]*|@langchain\/[\w-]+)["']|import\s+(anthropic|openai)\b|require\(["'](@anthropic-ai\/sdk|openai)["']\)/;
const LOADS_KEY = /Keypair\.fromSecretKey|createKeyPairSignerFrom(Private)?(Key)?Bytes|privateKeyToAccount|new\s+(ethers\.)?Wallet\(|Keypair\.from_bytes|from_base58_string|process\.env\.\w*(PRIVATE_KEY|SECRET_KEY|MNEMONIC|SEED)\w*|os\.environ\[?["']\w*(PRIVATE_KEY|MNEMONIC)/;
const SENDS_TX = /sendTransaction|sendAndConfirm|sendRawTransaction|signAndSendTransaction|\.transfer\(|writeContract/;
const UNLIMITED = /MaxUint256|MAX_UINT256|maxUint256|2n\s*\*\*\s*256n|type\(uint256\)\.max|u64::MAX|18446744073709551615|0xf{64}/i;

export const RULES: Rule[] = [
  // ---------------- secrets (any facet) ----------------
  {
    id: "keypair-bytes",
    title: "Solana keypair bytes committed",
    severity: "critical",
    why: "A 64-byte array is a full Solana secret key. Anyone with repo access, or any leak of it, controls that wallet.",
    fix: "Delete it, rotate the wallet, and load keys from a secrets manager or a remote signer at runtime. Add the path to .gitignore.",
    find: (f) => matches(f, /\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/),
  },
  {
    id: "hex-private-key",
    title: "Hard-coded private key",
    severity: "critical",
    why: "A 32-byte hex or base58 secret in source is a wallet anyone can drain once the code leaks.",
    fix: "Remove it, rotate the key, and inject signing through a KMS, HSM, or policy-enforcing remote signer.",
    appliesTo: isCode,
    find: (f) => lines(f, /(private_?key|secret_?key|signer_?key)\w*["']?\s*[:=]\s*["'`](0x)?([0-9a-f]{64}|[1-9A-HJ-NP-Za-km-z]{80,90})["'`]/i),
  },
  {
    id: "seed-phrase",
    title: "Seed phrase in code",
    severity: "critical",
    why: "A mnemonic recovers every account derived from it, across chains.",
    fix: "Remove it, move funds to a fresh wallet, and never store mnemonics outside a hardware wallet or KMS.",
    find: (f) => lines(f, /(mnemonic|seed_?phrase|recovery_?phrase)\w*\s*[:=]\s*["'`]([a-z]{3,8}\s+){11,23}[a-z]{3,8}["'`]/i),
  },

  // ---------------- frontend ----------------
  {
    id: "public-env-secret",
    title: "Secret exposed through a public env var",
    severity: "critical",
    facet: "frontend",
    why: "NEXT_PUBLIC_ / VITE_ / REACT_APP_ variables are bundled into the JavaScript every visitor downloads.",
    fix: "Rename it without the public prefix and only read it server-side. Rotate the exposed value.",
    find: (f) => lines(f, /\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_\w*(PRIVATE|SECRET|MNEMONIC|SEED)\w*/),
  },
  {
    id: "public-rpc-key",
    title: "Paid RPC key shipped to browsers",
    severity: "medium",
    facet: "frontend",
    why: "An RPC URL with an embedded API key in a public env var lets anyone burn your quota or impersonate your app.",
    fix: "Proxy RPC calls through your backend, or use a domain-restricted key.",
    find: (f) => lines(f, /\b(NEXT_PUBLIC|VITE|REACT_APP)_\w*RPC\w*\s*=\s*\S*(api[-_]?key=|\/v\d\/[0-9a-f]{20,})/i),
  },
  {
    id: "unlimited-approval",
    title: "Unlimited token approval",
    severity: "high",
    why: "Approving the max amount lets the spender take the user's entire balance, forever, if it's ever compromised. This is how most drainers profit.",
    fix: "Approve only the amount needed for this action, or use per-transaction permits with short deadlines.",
    appliesTo: isCode,
    find: (f) =>
      f.lines.flatMap((l, i) => {
        // Real approval calls only, not component names or comments that say "approve".
        if (/^\s*(\/\/|#|\*)/.test(l) || !/\.(approve|increaseAllowance)\s*\(|getApprove\w*Instruction\s*\(|approve_checked\s*\(/.test(l)) return [];
        const window = f.lines.slice(Math.max(0, i - 2), i + 3).join("\n");
        return UNLIMITED.test(window) ? [{ line: i + 1 }] : [];
      }),
  },
  {
    id: "blind-signing",
    title: "Blind signing (eth_sign)",
    severity: "high",
    facet: "frontend",
    why: "eth_sign signs raw bytes the user can't read. Wallets warn on it because it's a common phishing vector.",
    fix: "Use EIP-712 typed data (eth_signTypedData_v4) or a structured Solana signMessage so users see what they sign.",
    find: (f) => lines(f, /["']eth_sign["']/),
  },

  // ---------------- backend ----------------
  {
    id: "skip-preflight",
    title: "Transactions sent with preflight disabled",
    severity: "medium",
    facet: "backend",
    why: "skipPreflight sends without simulating, so failing or malicious transactions aren't caught before they cost fees or funds.",
    fix: "Leave preflight on, or simulate explicitly and inspect balance changes before sending.",
    find: (f) => lines(f, /skipPreflight\s*:\s*true/),
  },

  // ---------------- AI agents ----------------
  {
    id: "agent-holds-key",
    title: "AI agent process holds a signing key",
    severity: "critical",
    facet: "agent",
    why: "An LLM and a private key in the same process means one prompt injection away from an empty wallet. The model's judgment is the only safeguard.",
    fix: "Move the key out of the agent. Have the agent request signatures from a policy firewall (spending limits, allowlists, human approval), like Last Look.",
    appliesTo: (f) => isCode(f) && LLM_SDK.test(f.content),
    find: (f) => lines(f, LOADS_KEY),
  },
  {
    id: "agent-direct-send",
    title: "LLM tool can broadcast transactions directly",
    severity: "high",
    facet: "agent",
    why: "If a model-chosen tool both builds and sends a transaction, nothing independent checks the amount or recipient.",
    fix: "Split build from sign. Route signing through an out-of-process policy check before anything is broadcast.",
    appliesTo: (f) => isCode(f) && LLM_SDK.test(f.content) && !LOADS_KEY.test(f.content),
    find: (f) => lines(f, SENDS_TX),
  },

  // ---------------- cloud & CI ----------------
  {
    id: "committed-env",
    title: "Secrets committed in a .env file",
    severity: "critical",
    facet: "cloud",
    why: "Committed .env files end up in every clone, fork, CI cache and backup.",
    fix: "Remove the file from git history, rotate every value in it, and add .env* (except .env.example) to .gitignore.",
    appliesTo: (f) => /(^|\/)\.env(\.[\w-]+)?$/.test(f.path) && !/\.example$|\.sample$|\.template$/.test(f.path),
    find: (f) => lines(f, /^\s*\w*(PRIVATE|SECRET|MNEMONIC|SEED|API_KEY)\w*\s*=\s*\S{8,}/i),
  },
  {
    id: "docker-secret",
    title: "Key material baked into a container image",
    severity: "high",
    facet: "cloud",
    why: "Anything COPY'd or ENV-set in a Dockerfile lives in every image layer and registry that stores it.",
    fix: "Mount secrets at runtime (Docker secrets, cloud secret manager), never at build time.",
    appliesTo: (f) => /(^|\/)Dockerfile[\w.-]*$/.test(f.path),
    find: (f) => lines(f, /^\s*(COPY|ADD)\s+.*(\.env|keys?\/|keypair|id\.json|\.pem)|^\s*(ENV|ARG)\s+\w*(PRIVATE_KEY|MNEMONIC|SECRET)/i),
  },
  {
    id: "ci-secret-echo",
    title: "CI job prints a secret",
    severity: "high",
    facet: "cloud",
    why: "Echoing secrets writes them into build logs that many people (and integrations) can read.",
    fix: "Never echo secrets. Pass them as env vars to the step that needs them.",
    appliesTo: (f) => /\.github\/workflows\/.*\.ya?ml$|\.gitlab-ci\.ya?ml$/.test(f.path),
    find: (f) => lines(f, /(echo|printf|cat)\b.*\$\{\{\s*secrets\./),
  },

  // ---------------- on-chain ----------------
  {
    id: "tx-origin-auth",
    title: "Authorization with tx.origin",
    severity: "high",
    facet: "onchain",
    why: "tx.origin checks can be bypassed by a malicious contract the owner is tricked into calling.",
    fix: "Use msg.sender for authorization.",
    appliesTo: (f) => f.path.endsWith(".sol"),
    find: (f) => lines(f, /tx\.origin\s*==|==\s*tx\.origin|require\s*\(\s*tx\.origin/),
  },
  {
    id: "unchecked-account",
    title: "Anchor account without a safety check",
    severity: "medium",
    facet: "onchain",
    why: "UncheckedAccount / raw AccountInfo skip Anchor's owner and type checks. Missing a manual check lets attackers pass fake accounts.",
    fix: "Use a typed Account<'info, T>, or add explicit owner/key constraints and a /// CHECK: comment explaining why it's safe.",
    appliesTo: (f) => f.path.endsWith(".rs"),
    find: (f) =>
      f.lines.flatMap((l, i) =>
        /UncheckedAccount<|AccountInfo<'info>/.test(l) && !/\/\/\/\s*CHECK/.test(f.lines[i - 1] ?? "") ? [{ line: i + 1 }] : [],
      ),
  },
];

export const FACETS: { id: Facet; label: string; blurb: string }[] = [
  { id: "frontend", label: "Frontend", blurb: "What ships to users' browsers and wallets" },
  { id: "backend", label: "Backend", blurb: "Servers, workers and transaction senders" },
  { id: "cloud", label: "Cloud & CI", blurb: "Env files, containers and pipelines" },
  { id: "agent", label: "AI agents", blurb: "LLMs with access to keys or money" },
  { id: "onchain", label: "On-chain", blurb: "Smart contracts and Solana programs" },
];

/** Which facet a file belongs to, from its path. */
export function facetFor(path: string): Facet {
  const p = path.toLowerCase();
  if (/(^|\/)(dockerfile|docker-compose[\w.-]*|\.env[\w.-]*)$|\.tf$|\.github\/workflows\/|(^|\/)(k8s|helm|infra|deploy|terraform)\//.test(p)) return "cloud";
  if (/\.sol$|(^|\/)programs\/.*\.rs$|(^|\/)contracts\//.test(p)) return "onchain";
  if (/(^|\/)(agents?|ai|llm|bots?)\//.test(p)) return "agent";
  if (/\.(tsx|jsx|vue|svelte)$|(^|\/)(frontend|web|client|app|pages|components|public)\//.test(p)) return "frontend";
  return "backend";
}
