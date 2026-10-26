import {base58, bytes, CryptoError, isCryptoError} from '@hzblj/nitro-crypto/adapter'

import {addressBytes, type SolanaAddress} from './address'
import type {SolanaInstruction} from './instructions'

export type CompileMessageRequest = {
  /** Pays the fee: the first account, a writable signer. */
  readonly feePayer: string
  /** A blockhash from `getLatestBlockhash`: the transaction is valid for about a minute after it. */
  readonly recentBlockhash: string
  readonly instructions: readonly SolanaInstruction[]
}

/** A legacy message, compiled: its signers in order, and its bytes, which each signer signs. */
export type CompiledMessage = {readonly signers: readonly SolanaAddress[]; readonly bytes: Uint8Array}

/** The largest transaction the network accepts (the IPv6 minimum MTU less its headers), signatures included. */
export const TRANSACTION_SIZE_LIMIT = 1232

/** Solana's compact-u16: 7 bits a byte, least significant first, at most three bytes. */
export const compactU16 = (value: number): Uint8Array => {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new CryptoError('INVALID_ARGUMENT', 'A compact-u16 length is 0 to 65535.')
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

type Entry = {address: SolanaAddress; isSigner: boolean; isWritable: boolean}

/** The fee payer first, then signers before non-signers, writable before read-only, and by address within each. */
const rank = (entry: Entry) => (entry.isSigner ? 0 : 2) + (entry.isWritable ? 0 : 1)

const orderAccounts = (feePayer: SolanaAddress, instructions: readonly SolanaInstruction[]): Entry[] => {
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
      throw new CryptoError('INVALID_ARGUMENT', `A program the transaction invokes is never writable: ${program}.`)
    }
  }

  const [payer, ...rest] = [...entries.values()]

  return payer ? [payer, ...rest.sort((a, b) => rank(a) - rank(b) || compareAddresses(a.address, b.address))] : []
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

  throw new CryptoError('INVALID_ARGUMENT', 'A recent blockhash is the Base58 text of 32 bytes.')
}

/** `compactU16(items.length)` and the items, as Solana writes every array. */
const compactArray = (items: readonly Uint8Array[]) => bytes.concat(compactU16(items.length), ...items)

/**
 * A legacy transaction message: the header (signatures required, read-only signers, read-only non-signers), the
 * accounts, the blockhash and the instructions, with each account once, its roles merged, in the runtime's order.
 */
export const compileLegacyMessage = ({
  feePayer,
  instructions,
  recentBlockhash,
}: CompileMessageRequest): CompiledMessage => {
  addressBytes(feePayer, 'fee payer')
  const blockhash = blockhashBytes(recentBlockhash)
  const accounts = orderAccounts(feePayer, instructions)

  if (accounts.length > 256) {
    throw new CryptoError('INVALID_ARGUMENT', 'A legacy transaction addresses at most 256 accounts.')
  }

  const indexOf = new Map(accounts.map((entry, index) => [entry.address, index]))
  const signers = accounts.filter(entry => entry.isSigner)
  const header = Uint8Array.of(
    signers.length,
    signers.filter(entry => !entry.isWritable).length,
    accounts.filter(entry => !(entry.isSigner || entry.isWritable)).length
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

  return {
    bytes: bytes.concat(
      header,
      compactArray(accounts.map(entry => base58.decode(entry.address))),
      blockhash,
      compactArray(compiled)
    ),
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

/** The wire bytes of a message and its signatures, one per signer in the message's order. */
export const serializeTransaction = (message: Uint8Array, signatures: readonly Uint8Array[]): Uint8Array => {
  const serialized = bytes.concat(compactArray(signatures), message)

  if (serialized.length > TRANSACTION_SIZE_LIMIT) {
    throw new CryptoError('INVALID_ARGUMENT', `A transaction is at most ${TRANSACTION_SIZE_LIMIT} bytes.`)
  }

  return serialized
}
