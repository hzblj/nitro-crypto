import {base58, CryptoError} from '@hzblj/nitro-crypto/adapter'

import type {SolanaAddress} from './address'
import {ASSOCIATED_TOKEN_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM} from './programs'
import {
  type LookupSource,
  lookupTableEntries,
  type SolanaAddressLookupTables,
  type SolanaMessageVersion,
} from './transaction'

/** The Compute Budget program: compute unit limits and priority fees. */
export const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111'

/**
 * What an instruction does, when it is one a wallet sends every day; anything else is `unknown`, with its program.
 * Amounts are in the smallest unit: lamports, or the token's base unit. An instruction whose accounts come from a
 * lookup table that was not supplied is `unknown` too, as what it does depends on who they are.
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

/**
 * An account a message names, with its roles. One that a v0 message loads from an address lookup table says which
 * table and index; its address is `undefined` when that table's addresses were not supplied.
 */
export type DecodedSolanaAccount = {
  readonly address: SolanaAddress | undefined
  readonly isSigner: boolean
  readonly isWritable: boolean
  /** Where a v0 message loads the account from. Absent for an account the message names in full. */
  readonly lookup?: LookupSource
}

/** An instruction read back: its program (always named in full), its accounts and data, and what it does. */
export type DecodedSolanaInstruction = {
  readonly programId: SolanaAddress
  readonly accounts: readonly DecodedSolanaAccount[]
  readonly data: Uint8Array
  readonly summary: SolanaInstructionSummary
}

/** A table a v0 message loads accounts from: the indexes it loads writable, then those it loads read-only. */
export type SolanaAddressTableLookup = {
  readonly lookupTable: SolanaAddress
  readonly writableIndexes: readonly number[]
  readonly readonlyIndexes: readonly number[]
}

/** A message read back: what each signer signs, as a wallet shows it before it signs. */
export type DecodedSolanaMessage = {
  readonly version: SolanaMessageVersion
  /** Pays the fee: the first account. */
  readonly feePayer: SolanaAddress
  /** Every account that must sign, in order: the fee payer first. Signers are never loaded from a table. */
  readonly signers: readonly SolanaAddress[]
  /**
   * Every account the message names, in the order its instructions index them: those named in full, then those loaded
   * from lookup tables (each table's writable ones, then each table's read-only ones).
   */
  readonly accounts: readonly DecodedSolanaAccount[]
  readonly recentBlockhash: string
  readonly instructions: readonly DecodedSolanaInstruction[]
  /** The lookup tables of a v0 message, as it lists them; empty for a legacy message. */
  readonly addressTableLookups: readonly SolanaAddressTableLookup[]
}

export type DecodeMessageOptions = {
  /**
   * The addresses of the lookup tables a v0 message loads from (`getMultipleAccounts` with `jsonParsed`, or kit's
   * `fetchAddressesForLookupTables`), to name those accounts. A table left out leaves its accounts unnamed. They are
   * taken as given: a signer offline cannot check them against the chain.
   */
  readonly addressLookupTables?: SolanaAddressLookupTables
}

/** A wire transaction read back: its message, decoded, and a signature per signer. */
export type DecodedSolanaTransaction = DecodedSolanaMessage & {
  /** The message bytes: what each signer signs. */
  readonly message: Uint8Array
  /** One per signer, in the order of `signers`: the 64-byte signature, or `undefined` for a slot not signed yet. */
  readonly signatures: readonly (Uint8Array | undefined)[]
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

const takeByte = (reader: Reader) => take(reader, 1)[0] ?? 0

/** A compact-u16, canonical as the runtime requires: at most three bytes, no trailing zero byte. */
const readCompactU16 = (reader: Reader): number => {
  let value = 0

  for (let index = 0; index < 3; index++) {
    const byte = takeByte(reader)
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

/** The addresses at `indexes`, or `undefined` when any of them is missing or was not resolved. */
const named = (accounts: readonly DecodedSolanaAccount[], ...indexes: number[]): SolanaAddress[] | undefined => {
  const addresses = indexes.map(index => accounts[index]?.address)

  return addresses.every(address => address !== undefined) ? (addresses as SolanaAddress[]) : undefined
}

const summarize = (
  programId: SolanaAddress,
  accounts: readonly DecodedSolanaAccount[],
  data: Uint8Array
): SolanaInstructionSummary => {
  const transfer = named(accounts, 0, 1)

  if (
    programId === SYSTEM_PROGRAM &&
    data.length === 12 &&
    data[0] === 2 &&
    data[1] === 0 &&
    data[2] === 0 &&
    data[3] === 0 &&
    transfer
  ) {
    const [from = '', to = ''] = transfer

    return {from, lamports: u64(data, 4), to, type: 'transfer'}
  }

  const four = named(accounts, 0, 1, 2, 3)

  if (
    (programId === TOKEN_PROGRAM || programId === TOKEN_2022_PROGRAM) &&
    data.length === 10 &&
    data[0] === 12 &&
    four
  ) {
    const [source = '', mint = '', destination = '', owner = ''] = four

    return {amount: u64(data, 1), decimals: data[9] ?? 0, destination, mint, owner, source, type: 'token-transfer'}
  }

  if (programId === ASSOCIATED_TOKEN_PROGRAM && data.length <= 1 && (data[0] ?? 0) <= 1 && four) {
    const [payer = '', account = '', owner = '', mint = ''] = four

    return {account, idempotent: data[0] === 1, mint, owner, payer, type: 'create-token-account'}
  }

  if (programId === COMPUTE_BUDGET_PROGRAM && data.length === 5 && data[0] === 2) {
    return {type: 'compute-unit-limit', units: new DataView(data.buffer, data.byteOffset).getUint32(1, true)}
  }

  if (programId === COMPUTE_BUDGET_PROGRAM && data.length === 9 && data[0] === 3) {
    return {microLamports: u64(data, 1), type: 'compute-unit-price'}
  }

  return {programId, type: 'unknown'}
}

const readVersion = (reader: Reader): SolanaMessageVersion => {
  const first = reader.data[reader.offset] ?? 0

  if ((first & 0x80) === 0) {
    return 'legacy'
  }

  if (first !== 0x80) {
    throw invalid(`Only legacy and v0 messages are supported, not v${first & 0x7f}.`)
  }

  reader.offset += 1

  return 0
}

const readLookup = (reader: Reader): SolanaAddressTableLookup => {
  const lookupTable = base58.encode(take(reader, 32))
  const writableIndexes = [...take(reader, readCompactU16(reader))]
  const readonlyIndexes = [...take(reader, readCompactU16(reader))]

  if (writableIndexes.length + readonlyIndexes.length === 0) {
    throw invalid('A lookup table the message lists loads no account.')
  }

  return Object.freeze({
    lookupTable,
    readonlyIndexes: Object.freeze(readonlyIndexes),
    writableIndexes: Object.freeze(writableIndexes),
  })
}

/** The accounts a v0 message loads, in index order, named from the tables supplied. */
const loadedAccounts = (
  lookups: readonly SolanaAddressTableLookup[],
  tables: SolanaAddressLookupTables | undefined
): DecodedSolanaAccount[] => {
  const supplied = new Map(lookupTableEntries(tables ?? {}))
  const load = (lookupTable: SolanaAddress, index: number, isWritable: boolean): DecodedSolanaAccount => {
    const addresses = supplied.get(lookupTable)

    if (addresses && index >= addresses.length) {
      throw invalid(`The message loads index ${index} of ${lookupTable}, which holds ${addresses.length} addresses.`)
    }

    return Object.freeze({
      address: addresses?.[index],
      isSigner: false,
      isWritable,
      lookup: Object.freeze({index, lookupTable}),
    })
  }

  return [
    ...lookups.flatMap(({lookupTable, writableIndexes}) =>
      writableIndexes.map(index => load(lookupTable, index, true))
    ),
    ...lookups.flatMap(({lookupTable, readonlyIndexes}) =>
      readonlyIndexes.map(index => load(lookupTable, index, false))
    ),
  ]
}

const readMessage = (reader: Reader, options: DecodeMessageOptions): DecodedSolanaMessage => {
  const version = readVersion(reader)
  const [required = 0, readonlySigned = 0, readonlyUnsigned = 0] = take(reader, 3)
  const count = readCompactU16(reader)

  if (required === 0 || readonlySigned >= required || required + readonlyUnsigned > count || count > 256) {
    throw invalid('The message header does not describe its accounts.')
  }

  const addresses = Array.from({length: count}, () => base58.encode(take(reader, 32)))
  const recentBlockhash = base58.encode(take(reader, 32))
  const compiled = Array.from({length: readCompactU16(reader)}, () => {
    const programIndex = takeByte(reader)
    const indexes = [...take(reader, readCompactU16(reader))]
    const data = take(reader, readCompactU16(reader)).slice()

    return {data, indexes, programIndex}
  })
  const addressTableLookups =
    version === 0 ? Array.from({length: readCompactU16(reader)}, () => readLookup(reader)) : []
  const loads = addressTableLookups.flatMap(({lookupTable, readonlyIndexes, writableIndexes}) =>
    [...writableIndexes, ...readonlyIndexes].map(index => `${lookupTable}:${index}`)
  )

  if (count + loads.length > 256) {
    throw invalid('A message addresses at most 256 accounts, those it looks up included.')
  }

  if (new Set(loads).size !== loads.length) {
    throw invalid('The message loads an account twice.')
  }

  const accounts: DecodedSolanaAccount[] = [
    ...addresses.map((address, index) =>
      Object.freeze({
        address,
        isSigner: index < required,
        isWritable: index < required ? index < required - readonlySigned : index < count - readonlyUnsigned,
      })
    ),
    ...loadedAccounts(addressTableLookups, options.addressLookupTables),
  ]
  const known = accounts.flatMap(account => (account.address === undefined ? [] : [account.address]))

  if (new Set(known).size !== known.length) {
    throw invalid('The message names an account twice.')
  }

  const instructions = compiled.map(({data, indexes, programIndex}) => {
    const programId = programIndex < count && programIndex !== 0 ? addresses[programIndex] : undefined

    if (programId === undefined || indexes.some(index => index >= accounts.length)) {
      throw invalid('An instruction names an account the message does not have.')
    }

    const used = Object.freeze(indexes.map(index => accounts[index] as DecodedSolanaAccount))

    return Object.freeze({accounts: used, data, programId, summary: Object.freeze(summarize(programId, used, data))})
  })

  return Object.freeze({
    accounts: Object.freeze(accounts),
    addressTableLookups: Object.freeze(addressTableLookups),
    feePayer: addresses[0] ?? '',
    instructions: Object.freeze(instructions),
    recentBlockhash,
    signers: Object.freeze(addresses.slice(0, required)),
    version,
  })
}

/**
 * Reads a message, the bytes a Solana signer signs, legacy or v0: the header, the accounts with their roles, the
 * blockhash, the instructions (each with a summary of what it does when it is a transfer, a token transfer, a token
 * account creation or a compute budget setting) and a v0 message's lookup tables, its looked-up accounts named from
 * `options.addressLookupTables`. Strict: canonical lengths, indexes in range, programs and signers never looked up,
 * no account twice, nothing after the end. Any other version is refused (`INVALID_ARGUMENT`).
 */
export const decodeMessage = (message: Uint8Array, options: DecodeMessageOptions = {}): DecodedSolanaMessage => {
  const reader: Reader = {data: message, offset: 0}
  const decoded = readMessage(reader, options)

  if (reader.offset !== message.length) {
    throw invalid('The message has bytes after its end.')
  }

  return decoded
}

const isZero = (signature: Uint8Array) => signature.every(byte => byte === 0)

/**
 * Reads a wire transaction (what `sendTransaction` takes, and what a dApp hands a wallet to sign): one 64-byte
 * signature slot per signer, then the message, decoded as `decodeMessage` does. A slot of zeros is a signer that has
 * not signed yet. Signatures are read, not verified.
 */
export const decodeTransaction = (
  transaction: Uint8Array,
  options: DecodeMessageOptions = {}
): DecodedSolanaTransaction => {
  const reader: Reader = {data: transaction, offset: 0}
  const slots = Array.from({length: readCompactU16(reader)}, () => take(reader, 64).slice())
  const message = transaction.slice(reader.offset)
  const decoded = decodeMessage(message, options)

  if (slots.length !== decoded.signers.length) {
    throw invalid(`The message needs ${decoded.signers.length} signatures; the transaction has ${slots.length}.`)
  }

  return Object.freeze({
    ...decoded,
    message,
    signatures: Object.freeze(slots.map(slot => (isZero(slot) ? undefined : slot))),
  })
}
