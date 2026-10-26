import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {base58, isCryptoError, utf8} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {ed25519} from '@noble/curves/ed25519.js'
import {hmac} from '@noble/hashes/hmac.js'
import {sha256, sha512} from '@noble/hashes/sha2.js'
import {mnemonicToSeedSync} from '@scure/bip39'
import {
  AccountRole,
  type Address,
  appendTransactionMessageInstructions,
  type Blockhash,
  compileTransaction,
  createKeyPairFromPrivateKeyBytes,
  createTransactionMessage,
  getAddressComparator,
  getAddressEncoder,
  getProgramDerivedAddress,
  getTransactionEncoder,
  type Instruction,
  isOffCurveAddress,
  pipe,
  type SignatureBytes,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransaction,
  verifySignature,
} from '@solana/kit'

import {
  ASSOCIATED_TOKEN_PROGRAM,
  type SolanaInstruction,
  SYSTEM_PROGRAM,
  solanaAdapter,
  TOKEN_2022_PROGRAM,
  TOKEN_PROGRAM,
} from '../src'
import {compactU16, compareAddresses} from '../src/transaction'

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const USDC_DEVNET = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'

const crypto = createTestCryptoEngine({adapters: [solanaAdapter({cluster: 'devnet'})]})
const solana = crypto.chains.solana
const encoder = getAddressEncoder()

/** A reproducible stream of bytes: the same inputs on every run, so a failure can be replayed. */
const randomness = (seed: number) => {
  let counter = 0

  return (length: number) => {
    const out = new Uint8Array(length)
    for (let offset = 0; offset < length; offset += 32) {
      out.set(sha256(utf8.encode(`${seed}:${counter++}`)).subarray(0, Math.min(32, length - offset)), offset)
    }
    return out
  }
}

const random = randomness(1)
const randomAddress = () => base58.encode(random(32))
const randomInt = (below: number) => (random(1)[0] ?? 0) % below
const randomU64 = () => new DataView(random(8).buffer).getBigUint64(0, true)
const randomBlockhash = () => base58.encode(random(32))

/** SLIP-0010 written out with @noble's HMAC: the same key the wallet derives, independently, for @solana/kit. */
const slip10Seed = (seed: Uint8Array, path: readonly number[]) => {
  let node = hmac(sha512, utf8.encode('ed25519 seed'), seed)
  for (const index of path) {
    const data = new Uint8Array(37)
    data.set(node.subarray(0, 32), 1)
    new DataView(data.buffer).setUint32(33, (index | 0x80000000) >>> 0)
    node = hmac(sha512, node.subarray(32), data)
  }
  return node.subarray(0, 32)
}

const roleOf = ({isSigner, isWritable}: {isSigner: boolean; isWritable: boolean}) =>
  isSigner
    ? isWritable
      ? AccountRole.WRITABLE_SIGNER
      : AccountRole.READONLY_SIGNER
    : isWritable
      ? AccountRole.WRITABLE
      : AccountRole.READONLY

/** Ours, as kit's input: the same accounts and data, to compare how each compiles them. */
const toKit = (instruction: SolanaInstruction): Instruction => ({
  accounts: instruction.accounts.map(account => ({address: account.address as Address, role: roleOf(account)})),
  data: instruction.data,
  programAddress: instruction.programId as Address,
})

const kitMessage = (feePayer: string, blockhash: string, instructions: readonly Instruction[]) =>
  pipe(
    createTransactionMessage({version: 'legacy'}),
    message => setTransactionMessageFeePayer(feePayer as Address, message),
    message =>
      setTransactionMessageLifetimeUsingBlockhash(
        {blockhash: blockhash as Blockhash, lastValidBlockHeight: 0n},
        message
      ),
    message => appendTransactionMessageInstructions(instructions, message)
  )

const kitBytes = (feePayer: string, blockhash: string, instructions: readonly Instruction[]) =>
  new Uint8Array(compileTransaction(kitMessage(feePayer, blockhash, instructions)).messageBytes)

const kitAta = async (owner: string, mint: string, tokenProgram = TOKEN_PROGRAM) => {
  const [address] = await getProgramDerivedAddress({
    programAddress: ASSOCIATED_TOKEN_PROGRAM as Address,
    seeds: [encoder.encode(owner as Address), encoder.encode(tokenProgram as Address), encoder.encode(mint as Address)],
  })
  return address as string
}

const u64le = (value: bigint) => {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, value, true)
  return out
}

describe('compact-u16', () => {
  test('the lengths Solana publishes', () => {
    const cases: [number, number[]][] = [
      [0, [0]],
      [1, [1]],
      [0x7f, [0x7f]],
      [0x80, [0x80, 0x01]],
      [0xff, [0xff, 0x01]],
      [0x100, [0x80, 0x02]],
      [0x3fff, [0xff, 0x7f]],
      [0x4000, [0x80, 0x80, 0x01]],
      [0xffff, [0xff, 0xff, 0x03]],
    ]
    for (const [value, expected] of cases) {
      assert.deepEqual([...compactU16(value)], expected, String(value))
    }
    assert.throws(
      () => compactU16(0x10000),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
  })
})

describe('account order', () => {
  test('compareAddresses is kit`s collator, on random addresses and on ones that differ only in case', () => {
    const collator = getAddressComparator()
    const pool = Array.from({length: 400}, randomAddress)
    pool.push('11111111111111111111111111111111', SYSTEM_PROGRAM, TOKEN_PROGRAM, TOKEN_2022_PROGRAM)
    pool.push('abcdefghijk', 'ABCDEFGHJK', 'aBc', 'Abc', 'abC', 'abc', 'ab', 'Ab1', 'ab9', 'Z', 'z', '9', 'zz', 'Zz')
    for (const left of pool.slice(0, 120)) {
      for (const right of pool) {
        assert.equal(compareAddresses(left, right), Math.sign(collator(left, right)), `${left} ${right}`)
      }
    }
  })
})

describe('instructions', () => {
  test('a SOL transfer: System Program, index 2, u64 lamports, the sender a writable signer', () => {
    const from = randomAddress()
    const to = randomAddress()
    const instruction = solana.instructions.transfer({from, lamports: 1_500_000_000n, to})
    assert.equal(instruction.programId, SYSTEM_PROGRAM)
    assert.deepEqual(instruction.accounts, [
      {address: from, isSigner: true, isWritable: true},
      {address: to, isSigner: false, isWritable: true},
    ])
    assert.deepEqual([...instruction.data], [2, 0, 0, 0, ...u64le(1_500_000_000n)])
  })

  test('TransferChecked and CreateIdempotent, as the token programs define them', async () => {
    const owner = randomAddress()
    const recipient = randomAddress()
    const [create, send] = solana.instructions.transferToken({
      amount: 2_500_000n,
      decimals: 6,
      from: owner,
      mint: USDC_DEVNET,
      to: recipient,
    })
    assert.ok(create && send)
    assert.equal(create.programId, ASSOCIATED_TOKEN_PROGRAM)
    assert.deepEqual([...create.data], [1])
    assert.deepEqual(
      create.accounts.map(account => account.address),
      [owner, await kitAta(recipient, USDC_DEVNET), recipient, USDC_DEVNET, SYSTEM_PROGRAM, TOKEN_PROGRAM]
    )
    assert.equal(send.programId, TOKEN_PROGRAM)
    assert.deepEqual([...send.data], [12, ...u64le(2_500_000n), 6])
    assert.deepEqual(send.accounts, [
      {address: await kitAta(owner, USDC_DEVNET), isSigner: false, isWritable: true},
      {address: USDC_DEVNET, isSigner: false, isWritable: false},
      {address: await kitAta(recipient, USDC_DEVNET), isSigner: false, isWritable: true},
      {address: owner, isSigner: true, isWritable: false},
    ])
    const alone = solana.instructions.transferToken({
      amount: 1n,
      createRecipientAccount: false,
      decimals: 6,
      from: owner,
      mint: USDC_DEVNET,
      to: recipient,
      tokenProgram: TOKEN_2022_PROGRAM,
    })
    assert.equal(alone.length, 1)
    assert.equal(alone[0]?.programId, TOKEN_2022_PROGRAM)
  })

  test('amounts outside u64, bad decimals and bad addresses are refused before anything is signed', () => {
    const from = randomAddress()
    const to = randomAddress()
    for (const lamports of [-1n, 2n ** 64n]) {
      assert.throws(
        () => solana.instructions.transfer({from, lamports, to}),
        error => isCryptoError(error, 'INVALID_ARGUMENT')
      )
    }
    assert.throws(
      () => solana.instructions.transfer({from, lamports: 1 as unknown as bigint, to}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    assert.throws(
      () => solana.instructions.transfer({from, lamports: 1n, to: 'not an address'}),
      error => isCryptoError(error, 'INVALID_ADDRESS')
    )
    for (const decimals of [-1, 256, 1.5]) {
      assert.throws(
        () => solana.instructions.transferToken({amount: 1n, decimals, from, mint: USDC_DEVNET, to}),
        error => isCryptoError(error, 'INVALID_ARGUMENT')
      )
    }
  })
})

describe('program-derived addresses', () => {
  test('associated token accounts equal @solana/kit`s, for random owners on both token programs', async () => {
    for (let round = 0; round < 40; round++) {
      const owner = randomAddress()
      const mint = round % 4 === 0 ? USDC_DEVNET : randomAddress()
      const tokenProgram = round % 3 === 0 ? TOKEN_2022_PROGRAM : TOKEN_PROGRAM
      assert.equal(
        solana.associatedTokenAddress({mint, owner, tokenProgram}),
        await kitAta(owner, mint, tokenProgram),
        `${owner} ${mint}`
      )
    }
  })

  test('a known vector: the devnet USDC account of the "abandon … about" wallet', async () => {
    const owner = 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk'
    const ata = solana.associatedTokenAddress({mint: USDC_DEVNET, owner})
    assert.equal(ata, await kitAta(owner, USDC_DEVNET))
    assert.equal(ata, 'Bjr2Shw9sy31UNdm8kYs5y72iTbnxB4JemK98vJqyQWm')
    assert.equal(solana.isOnCurve(ata), false)
  })

  test('findProgramAddress returns the first bump from 255 that is off the curve, as kit does', async () => {
    for (let round = 0; round < 20; round++) {
      const seeds = Array.from({length: 1 + randomInt(4)}, () => random(randomInt(33)))
      const programId = randomAddress()
      const [address, bump] = await getProgramDerivedAddress({programAddress: programId as Address, seeds})
      assert.deepEqual(solana.findProgramAddress(seeds, programId), {address, bump})
    }
    assert.throws(
      () => solana.findProgramAddress([new Uint8Array(33)], SYSTEM_PROGRAM),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    assert.throws(
      () =>
        solana.findProgramAddress(
          Array.from({length: 16}, () => new Uint8Array(1)),
          SYSTEM_PROGRAM
        ),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
  })

  test('isOnCurve agrees with @noble/curves (ZIP-215 decoding) and with kit on random bytes and real keys', async () => {
    const decodes = (bytes: Uint8Array) => {
      try {
        ed25519.Point.fromBytes(bytes, true)
        return true
      } catch {
        return false
      }
    }
    let on = 0
    for (let round = 0; round < 2000; round++) {
      const bytes = random(32)
      const address = base58.encode(bytes)
      const expected = decodes(bytes)
      on += expected ? 1 : 0
      assert.equal(solana.isOnCurve(address), expected, address)
      assert.equal(solana.isOnCurve(address), !(await isOffCurveAddress(address as Address)), address)
    }
    assert.ok(on > 800 && on < 1200, `about half of random bytes decode, ${on} of 2000 did`)

    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    for (const index of [0, 1, 2, 3]) {
      const account = await wallet.deriveAccount({account: index, chain: 'solana'})
      assert.equal(solana.isOnCurve(account.address), true)
    }
    wallet.dispose()

    // x = 0 (y = 1) with the sign bit set: on the curve with ZIP-215, off it for kit; this package decides as kit.
    const signedZero = new Uint8Array(32)
    signedZero[0] = 1
    signedZero[31] = 0x80
    assert.equal(solana.isOnCurve(base58.encode(signedZero)), false)
    assert.equal(await isOffCurveAddress(base58.encode(signedZero) as Address), true)
    signedZero[31] = 0
    assert.equal(solana.isOnCurve(base58.encode(signedZero)), true)
  })
})

describe('messages', () => {
  test('random SOL and token transfers compile to the bytes @solana/kit compiles', async () => {
    for (let round = 0; round < 60; round++) {
      const payer = randomAddress()
      const blockhash = randomBlockhash()
      const instructions =
        round % 2 === 0
          ? [solana.instructions.transfer({from: payer, lamports: randomU64(), to: randomAddress()})]
          : solana.instructions.transferToken({
              amount: randomU64(),
              createRecipientAccount: round % 3 !== 0,
              decimals: randomInt(19),
              from: payer,
              mint: round % 5 === 0 ? USDC_DEVNET : randomAddress(),
              to: randomAddress(),
            })
      assert.deepEqual(
        solana.compileMessage({feePayer: payer, instructions, recentBlockhash: blockhash}),
        kitBytes(payer, blockhash, instructions.map(toKit)),
        `round ${round}`
      )
    }
  })

  test('arbitrary instructions: duplicates merged, roles ORed, every group ordered as kit orders it', () => {
    for (let round = 0; round < 200; round++) {
      const payer = randomAddress()
      const blockhash = randomBlockhash()
      const accounts = Array.from({length: 1 + randomInt(12)}, randomAddress)
      const programs = Array.from({length: 1 + randomInt(3)}, randomAddress)
      const instructions: SolanaInstruction[] = Array.from({length: 1 + randomInt(4)}, () => ({
        accounts: Array.from({length: randomInt(8)}, () => {
          const flags = randomInt(4)
          const pick = randomInt(accounts.length + 2)
          const address = pick === accounts.length ? payer : pick > accounts.length ? programs[0] : accounts[pick]
          const isProgram = address === programs[0]
          return {address: address ?? payer, isSigner: (flags & 1) === 1, isWritable: !isProgram && (flags & 2) === 2}
        }),
        data: random(randomInt(40)),
        programId: programs[randomInt(programs.length)] ?? SYSTEM_PROGRAM,
      }))
      assert.deepEqual(
        solana.compileMessage({feePayer: payer, instructions, recentBlockhash: blockhash}),
        kitBytes(payer, blockhash, instructions.map(toKit)),
        `round ${round}`
      )
    }
  })

  test('a writable or fee-paying program, and a bad blockhash, are refused', () => {
    const payer = randomAddress()
    const program = randomAddress()
    const recentBlockhash = randomBlockhash()
    const writable = {accounts: [{address: program, isSigner: false, isWritable: true}], data: new Uint8Array()}
    assert.throws(
      () =>
        solana.compileMessage({feePayer: payer, instructions: [{...writable, programId: program}], recentBlockhash}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    assert.throws(
      () =>
        solana.compileMessage({
          feePayer: payer,
          instructions: [{accounts: [], data: new Uint8Array(), programId: payer}],
          recentBlockhash,
        }),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    for (const blockhash of ['', 'not base58 0OIl', base58.encode(new Uint8Array(31).fill(1))]) {
      assert.throws(
        () => solana.compileMessage({feePayer: payer, instructions: [], recentBlockhash: blockhash}),
        error => isCryptoError(error, 'INVALID_ARGUMENT'),
        blockhash
      )
    }
  })
})

describe('signed transactions', () => {
  test('equal @solana/kit`s wire bytes for the same key, and verify with both', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const seed = mnemonicToSeedSync(ABANDON)
    for (const index of [0, 1, 7]) {
      const account = await wallet.deriveAccount({account: index, chain: 'solana'})
      const pair = await createKeyPairFromPrivateKeyBytes(slip10Seed(seed, [44, 501, index, 0]))
      for (let round = 0; round < 4; round++) {
        const recentBlockhash = randomBlockhash()
        const instructions =
          round % 2 === 0
            ? [solana.instructions.transfer({from: account.address, lamports: randomU64(), to: randomAddress()})]
            : solana.instructions.transferToken({
                amount: randomU64(),
                decimals: 6,
                from: account.address,
                mint: USDC_DEVNET,
                to: randomAddress(),
              })
        const signed = await account.signTransaction({instructions, recentBlockhash})
        const theirs = await signTransaction(
          [pair],
          compileTransaction(kitMessage(account.address, recentBlockhash, instructions.map(toKit)))
        )
        assert.deepEqual(signed.serialized, new Uint8Array(getTransactionEncoder().encode(theirs)))

        const message = solana.compileMessage({feePayer: account.address, instructions, recentBlockhash})
        const signature = base58.decode(signed.signature)
        assert.deepEqual(signed.serialized, Uint8Array.of(1, ...signature, ...message))
        assert.equal(crypto.ed25519.verify(account.publicKey, message, signature), true)
        assert.equal(await verifySignature(pair.publicKey, signature as SignatureBytes, message), true)
      }
    }
    wallet.dispose()
  })

  test('an instruction that needs another signer is refused, and so is a transaction over 1232 bytes', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const account = await wallet.deriveAccount({chain: 'solana'})
    const recentBlockhash = randomBlockhash()
    await assert.rejects(
      () =>
        account.signTransaction({
          instructions: [solana.instructions.transfer({from: randomAddress(), lamports: 1n, to: account.address})],
          recentBlockhash,
        }),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    await assert.rejects(
      () =>
        account.signTransaction({
          instructions: Array.from({length: 40}, () =>
            solana.instructions.transfer({from: account.address, lamports: 1n, to: randomAddress()})
          ),
          recentBlockhash,
        }),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    wallet.dispose()
  })
})
