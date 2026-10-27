import {base58, utf8} from '@hzblj/nitro-crypto/adapter'
import {hmac} from '@noble/hashes/hmac.js'
import {sha256, sha512} from '@noble/hashes/sha2.js'
import {
  AccountRole,
  type Address,
  type AddressesByLookupTableAddress,
  appendTransactionMessageInstructions,
  type Blockhash,
  compileTransaction,
  compressTransactionMessageUsingAddressLookupTables,
  createTransactionMessage,
  type Instruction,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit'

import type {DecodedSolanaInstruction, SolanaAddressLookupTables, SolanaInstruction} from '../src'

export const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

/** A reproducible stream of bytes: the same inputs on every run, so a failure can be replayed. */
export const randomness = (seed: number) => {
  let counter = 0
  const random = (length: number) => {
    const out = new Uint8Array(length)
    for (let offset = 0; offset < length; offset += 32) {
      out.set(sha256(utf8.encode(`${seed}:${counter++}`)).subarray(0, Math.min(32, length - offset)), offset)
    }
    return out
  }
  const int = (below: number) => new DataView(random(4).buffer).getUint32(0) % below
  return {
    address: () => base58.encode(random(32)),
    blockhash: () => base58.encode(random(32)),
    bytes: random,
    int,
    pick: <T>(items: readonly T[]): T => items[int(items.length)] as T,
    u64: () => new DataView(random(8).buffer).getBigUint64(0, true),
  }
}

/** SLIP-0010 written out with @noble's HMAC, hardened steps only: the seed to give @solana/kit, independently. */
export const slip10Seed = (seed: Uint8Array, path: readonly number[]) => {
  let node = hmac(sha512, utf8.encode('ed25519 seed'), seed)
  for (const index of path) {
    const data = new Uint8Array(37)
    data.set(node.subarray(0, 32), 1)
    new DataView(data.buffer).setUint32(33, (index | 0x80000000) >>> 0)
    node = hmac(sha512, node.subarray(32), data)
  }
  return node.subarray(0, 32)
}

export const roleOf = ({isSigner, isWritable}: {isSigner: boolean; isWritable: boolean}) =>
  isSigner
    ? isWritable
      ? AccountRole.WRITABLE_SIGNER
      : AccountRole.READONLY_SIGNER
    : isWritable
      ? AccountRole.WRITABLE
      : AccountRole.READONLY

/** Ours, as kit's input: the same accounts and data, to compare how each compiles them. */
export const toKit = (instruction: SolanaInstruction): Instruction => ({
  accounts: instruction.accounts.map(account => ({address: account.address as Address, role: roleOf(account)})),
  data: instruction.data,
  programAddress: instruction.programId as Address,
})

/** A decoded instruction whose accounts are all named, as an instruction to compile again. */
export const toInstruction = (instruction: DecodedSolanaInstruction): SolanaInstruction => ({
  accounts: instruction.accounts.map(({address, isSigner, isWritable}) => {
    if (address === undefined) {
      throw new Error('An account is not named')
    }
    return {address, isSigner, isWritable}
  }),
  data: instruction.data,
  programId: instruction.programId,
})

export const kitMessage = (
  version: 'legacy' | 0,
  feePayer: string,
  blockhash: string,
  instructions: readonly Instruction[],
  tables?: SolanaAddressLookupTables
) => {
  const message = pipe(
    createTransactionMessage({version}),
    message => setTransactionMessageFeePayer(feePayer as Address, message),
    message =>
      setTransactionMessageLifetimeUsingBlockhash(
        {blockhash: blockhash as Blockhash, lastValidBlockHeight: 0n},
        message
      ),
    message => appendTransactionMessageInstructions(instructions, message)
  )
  // kit types its compression for v0 messages only; these helpers build either version.
  return tables
    ? (compressTransactionMessageUsingAddressLookupTables(message as never, kitTables(tables)) as typeof message)
    : message
}

export const kitTables = (tables: SolanaAddressLookupTables) => tables as unknown as AddressesByLookupTableAddress

/** The message bytes kit compiles: legacy, or v0 compressed with the tables. */
export const kitBytes = (
  version: 'legacy' | 0,
  feePayer: string,
  blockhash: string,
  instructions: readonly Instruction[],
  tables?: SolanaAddressLookupTables
) => new Uint8Array(compileTransaction(kitMessage(version, feePayer, blockhash, instructions, tables)).messageBytes)

/**
 * Random instructions over a small pool of accounts and programs, with the fee payer and the programs among their
 * accounts now and then: duplicates, merged roles, signers, and programs passed as accounts.
 */
export const randomInstructions = (random: ReturnType<typeof randomness>, payer: string) => {
  const accounts = Array.from({length: 1 + random.int(14)}, random.address)
  const programs = Array.from({length: 1 + random.int(3)}, random.address)
  const instructions: SolanaInstruction[] = Array.from({length: 1 + random.int(4)}, () => ({
    accounts: Array.from({length: random.int(8)}, () => {
      const flags = random.int(4)
      const pick = random.int(accounts.length + 3)
      const address = pick === accounts.length ? payer : pick > accounts.length ? random.pick(programs) : accounts[pick]
      const isProgram = programs.includes(address ?? '')
      return {
        address: address ?? payer,
        isSigner: (flags & 1) === 1 && random.int(3) === 0,
        isWritable: !isProgram && (flags & 2) === 2,
      }
    }),
    data: random.bytes(random.int(40)),
    programId: random.pick(programs),
  }))
  return {accounts, instructions, programs}
}

/** Lookup tables over `pool` and strangers: an address may be in several tables, or twice in one. */
export const randomTables = (
  random: ReturnType<typeof randomness>,
  pool: readonly string[]
): SolanaAddressLookupTables => {
  const tables: Record<string, string[]> = {}
  for (let table = random.int(4); table > 0; table--) {
    const addresses = Array.from({length: random.int(12)}, () =>
      random.int(4) === 0 ? random.address() : random.pick(pool)
    )
    tables[random.address()] = addresses
  }
  return tables
}
