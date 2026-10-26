import {bytes, CryptoError} from '@hzblj/nitro-crypto/adapter'

import {addressBytes, type SolanaAddress} from './address'
import {associatedTokenAddress, type Sha256} from './pda'
import {ASSOCIATED_TOKEN_PROGRAM, SYSTEM_PROGRAM, TOKEN_PROGRAM} from './programs'

/** An account an instruction reads or writes, and whether it must sign. */
export type SolanaAccountMeta = {
  readonly address: SolanaAddress
  readonly isSigner: boolean
  readonly isWritable: boolean
}

/** One call to a program: the accounts it touches, in the program's order, and its input bytes. */
export type SolanaInstruction = {
  readonly programId: SolanaAddress
  readonly accounts: readonly SolanaAccountMeta[]
  readonly data: Uint8Array
}

export type TransferRequest = {readonly from: string; readonly to: string; readonly lamports: bigint}

export type CreateAssociatedTokenAccountRequest = {
  /** Pays the account's rent and signs. */
  readonly payer: string
  /** The wallet the token account is for. */
  readonly owner: string
  readonly mint: string
  readonly tokenProgram?: string
}

export type TransferCheckedRequest = {
  /** The token account debited. */
  readonly source: string
  readonly mint: string
  /** The token account credited. */
  readonly destination: string
  /** The wallet that owns `source`, and signs. */
  readonly owner: string
  /** In the token's smallest unit. */
  readonly amount: bigint
  /** The mint's decimals: the program refuses the transfer when they differ. */
  readonly decimals: number
  readonly tokenProgram?: string
}

export type TransferTokenRequest = {
  /** The sending wallet, which owns its associated token account and signs. */
  readonly from: string
  /** The receiving wallet: tokens go to its associated token account. */
  readonly to: string
  readonly mint: string
  readonly amount: bigint
  readonly decimals: number
  readonly tokenProgram?: string
  /**
   * Prepend an idempotent creation of the recipient's token account, paid by `from`: a no-op when it exists, rent
   * from the sender when it does not. True unless stated.
   */
  readonly createRecipientAccount?: boolean
}

/** Instruction builders for what a wallet sends: SOL, and SPL tokens to a wallet's associated token account. */
export type SolanaInstructions = {
  /** System Program `Transfer`: lamports from `from` (a signer) to `to`. */
  readonly transfer: (request: TransferRequest) => SolanaInstruction
  /** ATA program `CreateIdempotent`: the associated token account of `owner` for `mint`, unless it exists. */
  readonly createAssociatedTokenAccountIdempotent: (request: CreateAssociatedTokenAccountRequest) => SolanaInstruction
  /** Token program `TransferChecked`: `amount` from one token account to another, checked against the decimals. */
  readonly transferChecked: (request: TransferCheckedRequest) => SolanaInstruction
  /** Tokens from one wallet to another: their associated token accounts, created for the recipient if needed. */
  readonly transferToken: (request: TransferTokenRequest) => SolanaInstruction[]
}

const U64_MAX = 2n ** 64n - 1n

const u64 = (value: bigint, name: string): Uint8Array => {
  if (typeof value !== 'bigint' || value < 0n || value > U64_MAX) {
    throw new CryptoError('INVALID_ARGUMENT', `The ${name} is a bigint from 0 to 2^64 - 1.`)
  }

  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, value, true)

  return out
}

const decimalsOf = (decimals: number): number => {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) {
    throw new CryptoError('INVALID_ARGUMENT', 'A mint has 0 to 255 decimals.')
  }

  return decimals
}

/** An address that is checked, so a typo fails here and not at the RPC. */
const checked = (address: string, what: string): SolanaAddress => {
  addressBytes(address, what)

  return address
}

const meta = (address: string, what: string, isSigner: boolean, isWritable: boolean): SolanaAccountMeta => ({
  address: checked(address, what),
  isSigner,
  isWritable,
})

const SYSTEM_TRANSFER = Uint8Array.of(2, 0, 0, 0)
const ATA_CREATE_IDEMPOTENT = Uint8Array.of(1)
const TOKEN_TRANSFER_CHECKED = 12

export const createInstructions = (sha256: Sha256): SolanaInstructions => {
  const transfer = ({from, lamports, to}: TransferRequest): SolanaInstruction => ({
    accounts: [meta(from, 'sender', true, true), meta(to, 'recipient', false, true)],
    data: bytes.concat(SYSTEM_TRANSFER, u64(lamports, 'amount of lamports')),
    programId: SYSTEM_PROGRAM,
  })

  const createAssociatedTokenAccountIdempotent = ({
    mint,
    owner,
    payer,
    tokenProgram = TOKEN_PROGRAM,
  }: CreateAssociatedTokenAccountRequest): SolanaInstruction => ({
    accounts: [
      meta(payer, 'payer', true, true),
      {address: associatedTokenAddress({mint, owner, tokenProgram}, sha256), isSigner: false, isWritable: true},
      meta(owner, 'owner', false, false),
      meta(mint, 'mint', false, false),
      {address: SYSTEM_PROGRAM, isSigner: false, isWritable: false},
      meta(tokenProgram, 'token program', false, false),
    ],
    data: ATA_CREATE_IDEMPOTENT,
    programId: ASSOCIATED_TOKEN_PROGRAM,
  })

  const transferChecked = ({
    amount,
    decimals,
    destination,
    mint,
    owner,
    source,
    tokenProgram = TOKEN_PROGRAM,
  }: TransferCheckedRequest): SolanaInstruction => ({
    accounts: [
      meta(source, 'source token account', false, true),
      meta(mint, 'mint', false, false),
      meta(destination, 'destination token account', false, true),
      meta(owner, 'owner', true, false),
    ],
    data: bytes.concat(
      Uint8Array.of(TOKEN_TRANSFER_CHECKED),
      u64(amount, 'token amount'),
      Uint8Array.of(decimalsOf(decimals))
    ),
    programId: checked(tokenProgram, 'token program'),
  })

  return Object.freeze({
    createAssociatedTokenAccountIdempotent,
    transfer,
    transferChecked,
    transferToken: ({
      amount,
      createRecipientAccount = true,
      decimals,
      from,
      mint,
      to,
      tokenProgram = TOKEN_PROGRAM,
    }: TransferTokenRequest) => {
      const destination = associatedTokenAddress({mint, owner: to, tokenProgram}, sha256)
      const send = transferChecked({
        amount,
        decimals,
        destination,
        mint,
        owner: from,
        source: associatedTokenAddress({mint, owner: from, tokenProgram}, sha256),
        tokenProgram,
      })

      return createRecipientAccount
        ? [createAssociatedTokenAccountIdempotent({mint, owner: to, payer: from, tokenProgram}), send]
        : [send]
    },
  })
}
