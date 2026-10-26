import {base58, CryptoError} from '@hzblj/nitro-crypto/adapter'

import type {SolanaAddress} from './address'
import type {SolanaAccountMeta, SolanaInstruction} from './instructions'
import {ASSOCIATED_TOKEN_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM} from './programs'

/** The Compute Budget program: compute unit limits and priority fees. */
export const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111'

/**
 * What an instruction does, when it is one a wallet sends every day; anything else is `unknown`, with its program.
 * Amounts are in the smallest unit: lamports, or the token's base unit.
 */
export type SolanaInstructionSummary =
  | {readonly type: 'transfer'; readonly from: SolanaAddress; readonly to: SolanaAddress; readonly lamports: bigint}
  | {
      readonly type: 'token-transfer'
      readonly source: SolanaAddress
      readonly mint: SolanaAddress
      readonly destination: SolanaAddress
      readonly owner: SolanaAddress
      readonly amount: bigint
      readonly decimals: number
    }
  | {
      readonly type: 'create-token-account'
      readonly payer: SolanaAddress
      readonly account: SolanaAddress
      readonly owner: SolanaAddress
      readonly mint: SolanaAddress
      readonly idempotent: boolean
    }
  | {readonly type: 'compute-unit-limit'; readonly units: number}
  | {readonly type: 'compute-unit-price'; readonly microLamports: bigint}
  | {readonly type: 'unknown'; readonly programId: SolanaAddress}

/** A legacy message read back: what each signer signs, as a wallet shows it before it signs. */
export type DecodedSolanaMessage = {
  /** Pays the fee: the first account. */
  readonly feePayer: SolanaAddress
  /** Every account that must sign, in order: the fee payer first. */
  readonly signers: readonly SolanaAddress[]
  /** Every account the message names, with its role. */
  readonly accounts: readonly SolanaAccountMeta[]
  readonly recentBlockhash: string
  readonly instructions: readonly (SolanaInstruction & {readonly summary: SolanaInstructionSummary})[]
}

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

type Reader = {readonly data: Uint8Array; offset: number}

const take = (reader: Reader, length: number): Uint8Array => {
  if (length > reader.data.length - reader.offset) {
    throw invalid('The message ends in the middle of a field.')
  }

  const out = reader.data.subarray(reader.offset, reader.offset + length)
  reader.offset += length

  return out
}

/** A compact-u16, canonical as the runtime requires: at most three bytes, no trailing zero byte. */
const readCompactU16 = (reader: Reader): number => {
  let value = 0

  for (let index = 0; index < 3; index++) {
    const byte = take(reader, 1)[0] ?? 0
    value |= (byte & 0x7f) << (index * 7)

    if ((byte & 0x80) === 0) {
      if (index > 0 && byte === 0) {
        throw invalid('A compact-u16 is not in its shortest form.')
      }

      if (value > 0xffff) {
        throw invalid('A compact-u16 is at most 65535.')
      }

      return value
    }
  }

  throw invalid('A compact-u16 is at most three bytes.')
}

const u64 = (data: Uint8Array, offset: number) =>
  new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(offset, true)

const summarize = ({accounts, data, programId}: SolanaInstruction): SolanaInstructionSummary => {
  const address = (index: number) => accounts[index]?.address ?? ''

  if (
    programId === SYSTEM_PROGRAM &&
    data.length === 12 &&
    data[0] === 2 &&
    data[1] === 0 &&
    data[2] === 0 &&
    data[3] === 0 &&
    accounts.length >= 2
  ) {
    return {from: address(0), lamports: u64(data, 4), to: address(1), type: 'transfer'}
  }

  if (
    (programId === TOKEN_PROGRAM || programId === TOKEN_2022_PROGRAM) &&
    data.length === 10 &&
    data[0] === 12 &&
    accounts.length >= 4
  ) {
    return {
      amount: u64(data, 1),
      decimals: data[9] ?? 0,
      destination: address(2),
      mint: address(1),
      owner: address(3),
      source: address(0),
      type: 'token-transfer',
    }
  }

  if (programId === ASSOCIATED_TOKEN_PROGRAM && data.length <= 1 && (data[0] ?? 0) <= 1 && accounts.length >= 4) {
    return {
      account: address(1),
      idempotent: data[0] === 1,
      mint: address(3),
      owner: address(2),
      payer: address(0),
      type: 'create-token-account',
    }
  }

  if (programId === COMPUTE_BUDGET_PROGRAM && data.length === 5 && data[0] === 2) {
    return {type: 'compute-unit-limit', units: new DataView(data.buffer, data.byteOffset).getUint32(1, true)}
  }

  if (programId === COMPUTE_BUDGET_PROGRAM && data.length === 9 && data[0] === 3) {
    return {microLamports: u64(data, 1), type: 'compute-unit-price'}
  }

  return {programId, type: 'unknown'}
}

/**
 * Reads a legacy message, the bytes a Solana signer signs: the header, the accounts with their roles, the blockhash
 * and the instructions, each with a summary of what it does when it is a transfer, a token transfer, a token account
 * creation or a compute budget setting. Strict: canonical lengths, indexes in range, no account twice, nothing after
 * the last instruction. A versioned (v0) message is refused, as this package does not build or sign them.
 */
export const decodeMessage = (message: Uint8Array): DecodedSolanaMessage => {
  if (((message[0] ?? 0) & 0x80) !== 0) {
    throw invalid('Versioned (v0) messages are not supported: only legacy ones.')
  }

  const reader: Reader = {data: message, offset: 0}
  const [required = 0, readonlySigned = 0, readonlyUnsigned = 0] = take(reader, 3)
  const count = readCompactU16(reader)

  if (required === 0 || readonlySigned >= required || required + readonlyUnsigned > count || count > 256) {
    throw invalid('The message header does not describe its accounts.')
  }

  const addresses = Array.from({length: count}, () => base58.encode(take(reader, 32)))

  if (new Set(addresses).size !== addresses.length) {
    throw invalid('The message names an account twice.')
  }

  const accounts = addresses.map((address, index) =>
    Object.freeze({
      address,
      isSigner: index < required,
      isWritable: index < required ? index < required - readonlySigned : index < count - readonlyUnsigned,
    })
  )
  const recentBlockhash = base58.encode(take(reader, 32))
  const instructions = Array.from({length: readCompactU16(reader)}, () => {
    const programIndex = take(reader, 1)[0] ?? 0
    const indexes = take(reader, readCompactU16(reader))
    const data = take(reader, readCompactU16(reader)).slice()
    const program = accounts[programIndex]

    if (!program || programIndex === 0 || [...indexes].some(index => index >= count)) {
      throw invalid('An instruction names an account the message does not have.')
    }

    const instruction = {
      accounts: Array.from(indexes, index => accounts[index] as SolanaAccountMeta),
      data,
      programId: program.address,
    }

    return Object.freeze({...instruction, summary: Object.freeze(summarize(instruction))})
  })

  if (reader.offset !== message.length) {
    throw invalid('The message has bytes after its last instruction.')
  }

  return Object.freeze({
    accounts: Object.freeze(accounts),
    feePayer: addresses[0] ?? '',
    instructions: Object.freeze(instructions),
    recentBlockhash,
    signers: Object.freeze(addresses.slice(0, required)),
  })
}
