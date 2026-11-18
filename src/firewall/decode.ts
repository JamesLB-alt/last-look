import {
  type Address,
  decompileTransactionMessage,
  getBase64Encoder,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
  type Transaction,
} from "@solana/kit";
import {
  AssociatedTokenInstruction,
  identifyAssociatedTokenInstruction,
  identifyTokenInstruction,
  parseApproveCheckedInstruction,
  parseApproveInstruction,
  parseCloseAccountInstruction,
  parseCreateAssociatedTokenIdempotentInstruction,
  parseCreateAssociatedTokenInstruction,
  parseSetAuthorityInstruction,
  parseTransferCheckedInstruction,
  parseTransferInstruction,
  ASSOCIATED_TOKEN_PROGRAM_ADDRESS,
  TOKEN_PROGRAM_ADDRESS,
  TokenInstruction,
} from "@solana-program/token";
import {
  identifySystemInstruction,
  parseTransferSolInstruction,
  SYSTEM_PROGRAM_ADDRESS,
  SystemInstruction,
} from "@solana-program/system";

// Everything a Solana transaction can do that matters for money, in one flat list.
export type Action =
  | { kind: "token-transfer"; mint: Address | null; amount: bigint; fromAta: Address; toAta: Address }
  | { kind: "token-approve"; delegate: Address; amount: bigint; ata: Address } // lets someone else spend
  | { kind: "token-set-authority"; account: Address; newAuthority: Address | null } // hands over the account
  | { kind: "token-close"; account: Address; rentTo: Address }
  | { kind: "sol-transfer"; to: Address; lamports: bigint }
  | { kind: "create-ata"; ata: Address; owner: Address; mint: Address }
  | { kind: "benign"; program: "compute-budget" | "memo" }
  | { kind: "unknown"; program: Address; note?: string };

export type Decoded = {
  feePayer: Address;
  actions: Action[];
  transaction: Transaction;
};

const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111";
const MEMO_PROGRAMS = new Set([
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
  "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
]);

export function decodeWireTransaction(base64: string): Decoded {
  const transaction = getTransactionDecoder().decode(getBase64Encoder().encode(base64));
  const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  const feePayer = compiled.staticAccounts[0];

  let message;
  try {
    message = decompileTransactionMessage(compiled);
  } catch {
    // Address lookup tables hide which accounts are touched. Treat that as
    // opaque rather than guess.
    return {
      feePayer,
      transaction,
      actions: [{ kind: "unknown", program: feePayer, note: "uses address lookup tables" }],
    };
  }

  // kit types this as a union of two array types; narrow to what we read.
  const instructions = message.instructions as readonly { programAddress: Address }[];
  const actions: Action[] = instructions.map((ix): Action => {
    const program = ix.programAddress as string;
    const i = ix as any; // parsers below check account/data shape themselves

    if (program === COMPUTE_BUDGET) return { kind: "benign", program: "compute-budget" };
    if (MEMO_PROGRAMS.has(program)) return { kind: "benign", program: "memo" };

    if (program === TOKEN_PROGRAM_ADDRESS) {
      switch (identifyTokenInstruction(i)) {
        case TokenInstruction.TransferChecked: {
          const p = parseTransferCheckedInstruction(i);
          return {
            kind: "token-transfer",
            mint: p.accounts.mint.address,
            amount: BigInt(p.data.amount),
            fromAta: p.accounts.source.address,
            toAta: p.accounts.destination.address,
          };
        }
        case TokenInstruction.Transfer: {
          // Unchecked transfer: no mint in the instruction, so the mint is unknown here.
          const p = parseTransferInstruction(i);
          return {
            kind: "token-transfer",
            mint: null,
            amount: BigInt(p.data.amount),
            fromAta: p.accounts.source.address,
            toAta: p.accounts.destination.address,
          };
        }
        case TokenInstruction.Approve: {
          const p = parseApproveInstruction(i);
          return { kind: "token-approve", delegate: p.accounts.delegate.address, amount: BigInt(p.data.amount), ata: p.accounts.source.address };
        }
        case TokenInstruction.ApproveChecked: {
          const p = parseApproveCheckedInstruction(i);
          return { kind: "token-approve", delegate: p.accounts.delegate.address, amount: BigInt(p.data.amount), ata: p.accounts.source.address };
        }
        case TokenInstruction.SetAuthority: {
          const p = parseSetAuthorityInstruction(i);
          const na = p.data.newAuthority as { __option: "Some"; value: Address } | { __option: "None" };
          return { kind: "token-set-authority", account: p.accounts.owned.address, newAuthority: na.__option === "Some" ? na.value : null };
        }
        case TokenInstruction.CloseAccount: {
          const p = parseCloseAccountInstruction(i);
          return { kind: "token-close", account: p.accounts.account.address, rentTo: p.accounts.destination.address };
        }
        default:
          return { kind: "unknown", program: ix.programAddress, note: `token instruction #${identifyTokenInstruction(i)}` };
      }
    }

    if (program === ASSOCIATED_TOKEN_PROGRAM_ADDRESS) {
      const kind = identifyAssociatedTokenInstruction(i);
      if (kind === AssociatedTokenInstruction.CreateAssociatedTokenIdempotent || kind === AssociatedTokenInstruction.CreateAssociatedToken) {
        const p =
          kind === AssociatedTokenInstruction.CreateAssociatedTokenIdempotent
            ? parseCreateAssociatedTokenIdempotentInstruction(i)
            : parseCreateAssociatedTokenInstruction(i);
        return { kind: "create-ata", ata: p.accounts.ata.address, owner: p.accounts.owner.address, mint: p.accounts.mint.address };
      }
    }

    if (program === SYSTEM_PROGRAM_ADDRESS && identifySystemInstruction(i) === SystemInstruction.TransferSol) {
      const p = parseTransferSolInstruction(i);
      return { kind: "sol-transfer", to: p.accounts.destination.address, lamports: BigInt(p.data.amount) };
    }

    return { kind: "unknown", program: ix.programAddress };
  });

  return { feePayer, actions, transaction };
}
