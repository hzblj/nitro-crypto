import {base58, bytes, CryptoError, isCryptoError} from '@hzblj/nitro-crypto/adapter'

import {addressBytes, type SolanaAddress} from './address'
import type {SolanaInstruction} from './instructions'

/** A message's format: `'legacy'`, or `0`, the versioned format that can load accounts from address lookup tables. */
export type SolanaMessageVersion = 'legacy' | 0

/**
 * Address lookup tables, each by its address, with the addresses it holds in order (the table account's
 * `addresses`, as the RPC returns it parsed). Where an address is in several, the first table that has it is used.
 */
export type SolanaAddressLookupTables = Readonly<Record<string, readonly string[]>>

export type CompileMessageRequest = {
  /** Pays the fee: the first account, a writable signer. */
  readonly feePayer: string
  /** A blockhash from `getLatestBlockhash`: the transaction is valid for about a minute after it. */
  readonly recentBlockhash: string
  readonly instructions: readonly SolanaInstruction[]
  /** `'legacy'` unless stated; `0` for a versioned message. */
  readonly version?: SolanaMessageVersion
  /**
   * Tables a v0 message loads accounts from, by index, instead of naming each in full: every account that is not a
   * signer, the fee payer or an invoked program, and is in a table. Refused for a legacy message.
   */
  readonly addressLookupTables?: SolanaAddressLookupTables
}

/** A message, compiled: its signers in order, and its bytes, which each signer signs. */
export type CompiledMessage = {readonly signers: readonly SolanaAddress[]; readonly bytes: Uint8Array}

/** The largest transaction the network accepts (the IPv6 minimum MTU less its headers), signatures included. */
export const TRANSACTION_SIZE_LIMIT = 1232

/** What @solana/kit compiles at most, for either version: accounts (static and looked up), signers, instructions. */
const MAX_ACCOUNTS = 64
const MAX_SIGNERS = 12
const MAX_INSTRUCTIONS = 64
const MAX_INSTRUCTION_ACCOUNTS = 255

/** An address lookup table holds at most 256 addresses: an index into it is one byte. */
const MAX_TABLE_ADDRESSES = 256

const VERSION_PREFIX = 0x80

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

/** Solana's compact-u16: 7 bits a byte, least significant first, at most three bytes. */
export const compactU16 = (value: number): Uint8Array => {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw invalid('A compact-u16 length is 0 to 65535.')
  }

  const out: number[] = []
  let rest = value

  do {
    const low = rest & 0x7f
    rest >>= 7
    out.push(rest > 0 ? low | 0x80 : low)
  } while (rest > 0)

  return Uint8Array.from(out)
}

const LETTER = /[a-z]/i

/** A character's place before case: digits first, then letters regardless of case. */
const primary = (char: string) =>
  LETTER.test(char) ? 10 + char.toLowerCase().charCodeAt(0) - 97 : char.charCodeAt(0) - 48

/**
 * The order @solana/kit and web3.js give accounts of one role: `Intl.Collator('en', {caseFirst: 'lower'})` over Base58,
 * written out so it needs no `Intl`. Letters compare without case, digits before letters; only strings equal but for
 * case are ordered by it, lowercase first, at the first difference.
 */
export const compareAddresses = (left: string, right: string): number => {
  const length = Math.min(left.length, right.length)

  for (let index = 0; index < length; index++) {
    const difference = primary(left[index] ?? '') - primary(right[index] ?? '')

    if (difference !== 0) {
      return Math.sign(difference)
    }
  }

  if (left.length !== right.length) {
    return left.length < right.length ? -1 : 1
  }

  for (let index = 0; index < length; index++) {
    const a = left[index] ?? ''
    const b = right[index] ?? ''

    if (a !== b) {
      return a === a.toLowerCase() ? -1 : 1
    }
  }

  return 0
}

/** Where a v0 message loads an account from: a lookup table, and the address's index in it. */
export type LookupSource = {readonly lookupTable: SolanaAddress; readonly index: number}

type Entry = {address: SolanaAddress; isSigner: boolean; isWritable: boolean; lookup?: LookupSource}

/** Each account once, its roles merged: the fee payer first, the rest in the order they first appear. */
const collectAccounts = (feePayer: SolanaAddress, instructions: readonly SolanaInstruction[]) => {
  const entries = new Map<SolanaAddress, Entry>([[feePayer, {address: feePayer, isSigner: true, isWritable: true}]])
  const programs = new Set<SolanaAddress>()
  const upsert = (address: SolanaAddress, isSigner: boolean, isWritable: boolean) => {
    const entry = entries.get(address)

    if (entry) {
      entry.isSigner ||= isSigner
      entry.isWritable ||= isWritable
    } else {
      entries.set(address, {address, isSigner, isWritable})
    }
  }

  for (const instruction of instructions) {
    addressBytes(instruction.programId, 'program')
    programs.add(instruction.programId)
    upsert(instruction.programId, false, false)

    for (const account of instruction.accounts) {
      addressBytes(account.address, 'account')
      upsert(account.address, account.isSigner, account.isWritable)
    }
  }

  for (const program of programs) {
    if (program === feePayer || entries.get(program)?.isWritable) {
      throw invalid(`A program the transaction invokes is never writable: ${program}.`)
    }
  }

  return {entries: [...entries.values()], programs}
}

/** Signers before non-signers, writable before read-only, and by address within each: the runtime's order. */
const rank = (entry: Entry) => (entry.isSigner ? 0 : 2) + (entry.isWritable ? 0 : 1)

const byRole = (a: Entry, b: Entry) => rank(a) - rank(b) || compareAddresses(a.address, b.address)

/** Looked-up accounts: writable first, then by table, then by address, as kit orders them. */
const byLookup = (a: Entry, b: Entry) =>
  Number(b.isWritable) - Number(a.isWritable) ||
  compareAddresses(a.lookup?.lookupTable ?? '', b.lookup?.lookupTable ?? '') ||
  compareAddresses(a.address, b.address)

/** The tables in the order given, each address checked: a typo fails here, not on the network. */
export const lookupTableEntries = (tables: SolanaAddressLookupTables): [SolanaAddress, readonly SolanaAddress[]][] =>
  Object.entries(tables).map(([table, addresses]) => {
    addressBytes(table, 'lookup table')

    if (addresses.length > MAX_TABLE_ADDRESSES) {
      throw invalid(`An address lookup table holds at most ${MAX_TABLE_ADDRESSES} addresses.`)
    }

    for (const address of addresses) {
      addressBytes(address, 'lookup table entry')
    }

    return [table, addresses]
  })

/** The first table that holds `address`, and its first index there: what kit's compression picks. */
const findInTables = (
  address: SolanaAddress,
  tables: readonly [SolanaAddress, readonly SolanaAddress[]][]
): LookupSource | undefined => {
  for (const [lookupTable, addresses] of tables) {
    const index = addresses.indexOf(address)

    if (index >= 0) {
      return {index, lookupTable}
    }
  }

  return undefined
}

const blockhashBytes = (blockhash: string): Uint8Array => {
  try {
    const decoded = base58.decode(blockhash)

    if (decoded.length === 32) {
      return decoded
    }
  } catch (error) {
    if (!isCryptoError(error, 'INVALID_ENCODING')) {
      throw error
    }
  }

  throw invalid('A recent blockhash is the Base58 text of 32 bytes.')
}

/** `compactU16(items.length)` and the items, as Solana writes every array. */
export const compactArray = (items: readonly Uint8Array[]) => bytes.concat(compactU16(items.length), ...items)

/** An array of one-byte values (lookup table indexes), as Solana writes it. */
const compactBytes = (values: readonly number[]) => bytes.concat(compactU16(values.length), Uint8Array.from(values))

/** The lookups of a v0 message: each table used, in address order, with the indexes it loads writable and read-only. */
const compileLookups = (loaded: readonly Entry[]): Uint8Array[] => {
  const tables = new Map<SolanaAddress, {writable: number[]; readonly: number[]}>()

  for (const {isWritable, lookup} of loaded) {
    if (lookup) {
      const table = tables.get(lookup.lookupTable) ?? {readonly: [], writable: []}
      tables.set(lookup.lookupTable, table)
      ;(isWritable ? table.writable : table.readonly).push(lookup.index)
    }
  }

  return [...tables.entries()]
    .sort(([left], [right]) => compareAddresses(left, right))
    .map(([table, {readonly, writable}]) =>
      bytes.concat(base58.decode(table), compactBytes(writable), compactBytes(readonly))
    )
}

/**
 * A transaction message, legacy or v0: the header (signatures required, read-only signers, read-only non-signers),
 * the static accounts, the blockhash and the instructions, and for v0 the accounts loaded from lookup tables. Each
 * account appears once with its roles merged, in the runtime's order; a v0 message loads every account it can from
 * the tables given (one that is not a signer, the fee payer or an invoked program), choosing and ordering them as
 * @solana/kit's `compressTransactionMessageUsingAddressLookupTables` and compiler do, so the bytes are kit's.
 */
export const compileMessage = ({
  addressLookupTables,
  feePayer,
  instructions,
  recentBlockhash,
  version = 'legacy',
}: CompileMessageRequest): CompiledMessage => {
  if (version !== 'legacy' && version !== 0) {
    throw invalid('A message is legacy or v0.')
  }

  if (addressLookupTables && version !== 0) {
    throw invalid('Address lookup tables need a v0 message.')
  }

  addressBytes(feePayer, 'fee payer')
  const blockhash = blockhashBytes(recentBlockhash)

  if (instructions.length > MAX_INSTRUCTIONS) {
    throw invalid(`A transaction has at most ${MAX_INSTRUCTIONS} instructions.`)
  }

  if (instructions.some(instruction => instruction.accounts.length > MAX_INSTRUCTION_ACCOUNTS)) {
    throw invalid(`An instruction names at most ${MAX_INSTRUCTION_ACCOUNTS} accounts.`)
  }

  const {entries, programs} = collectAccounts(feePayer, instructions)
  const tables = lookupTableEntries(addressLookupTables ?? {})
  const [payer, ...rest] = entries

  for (const entry of rest) {
    if (!(entry.isSigner || programs.has(entry.address))) {
      entry.lookup = findInTables(entry.address, tables)
    }
  }

  const statics = [...(payer ? [payer] : []), ...rest.filter(entry => !entry.lookup).sort(byRole)]
  const loaded = rest.filter(entry => entry.lookup).sort(byLookup)
  const ordered = [...statics, ...loaded]
  const signers = statics.filter(entry => entry.isSigner)

  if (ordered.length > MAX_ACCOUNTS) {
    throw invalid(`A transaction addresses at most ${MAX_ACCOUNTS} accounts, those it looks up included.`)
  }

  if (signers.length > MAX_SIGNERS) {
    throw invalid(`A transaction has at most ${MAX_SIGNERS} signers.`)
  }

  const indexOf = new Map(ordered.map((entry, index) => [entry.address, index]))
  const header = Uint8Array.of(
    signers.length,
    signers.filter(entry => !entry.isWritable).length,
    statics.filter(entry => !(entry.isSigner || entry.isWritable)).length
  )
  const compiled = instructions.map(instruction =>
    bytes.concat(
      Uint8Array.of(indexOf.get(instruction.programId) ?? 0),
      compactU16(instruction.accounts.length),
      Uint8Array.from(instruction.accounts, account => indexOf.get(account.address) ?? 0),
      compactU16(instruction.data.length),
      instruction.data
    )
  )
  const body = bytes.concat(
    header,
    compactArray(statics.map(entry => base58.decode(entry.address))),
    blockhash,
    compactArray(compiled)
  )

  return {
    bytes:
      version === 'legacy'
        ? body
        : bytes.concat(Uint8Array.of(VERSION_PREFIX), body, compactArray(compileLookups(loaded))),
    signers: signers.map(entry => entry.address),
  }
}

/** A signed transaction, ready for `sendTransaction`. */
export type SignedSolanaTransaction = {
  /** The fee payer's signature in Base58: the transaction's id, as explorers and `getSignatureStatuses` take it. */
  readonly signature: string
  /** The wire format: the signatures (compact array of 64 bytes each), then the message. Base64 it for the RPC. */
  readonly serialized: Uint8Array
}

/** A transaction some of whose signers have signed: each slot not signed yet holds 64 zero bytes. */
export type PartiallySignedSolanaTransaction = {
  /** The fee payer's signature in Base58 (the transaction's id), once the fee payer has signed. */
  readonly signature: string | undefined
  /** The wire format, as `SignedSolanaTransaction.serialized`: what goes back to the app, or on to the next signer. */
  readonly serialized: Uint8Array
  /** Whether every signer has signed: only then can it be sent. */
  readonly complete: boolean
}

/** The wire bytes of a message and its signatures, one per signer in the message's order. */
export const serializeTransaction = (message: Uint8Array, signatures: readonly Uint8Array[]): Uint8Array => {
  const serialized = bytes.concat(compactArray(signatures), message)

  if (serialized.length > TRANSACTION_SIZE_LIMIT) {
    throw invalid(`A transaction is at most ${TRANSACTION_SIZE_LIMIT} bytes.`)
  }

  return serialized
}
