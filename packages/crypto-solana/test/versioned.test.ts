import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {base58, isCryptoError} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {mnemonicToSeedSync} from '@scure/bip39'
import {
  type CompiledTransactionMessage,
  type CompiledTransactionMessageWithLifetime,
  compileTransaction,
  createKeyPairFromPrivateKeyBytes,
  decompileTransactionMessage,
  generateKeyPair,
  getAddressComparator,
  getAddressFromPublicKey,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
  getTransactionEncoder,
  partiallySignTransaction,
  signTransaction,
} from '@solana/kit'

import {
  type SolanaAddressLookupTables,
  type SolanaInstruction,
  SYSTEM_PROGRAM,
  solanaAdapter,
  TOKEN_PROGRAM,
} from '../src'
import {
  ABANDON,
  kitBytes,
  kitMessage,
  kitTables,
  randomInstructions,
  randomness,
  randomTables,
  roleOf,
  slip10Seed,
  toInstruction,
  toKit,
} from './support'

const crypto = createTestCryptoEngine({adapters: [solanaAdapter({cluster: 'devnet'})]})
const solana = crypto.chains.solana
const random = randomness(2)

const USDC_DEVNET = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'

/** The same outcome from both: equal bytes, or both refusing. */
const compileBoth = (
  payer: string,
  blockhash: string,
  instructions: readonly SolanaInstruction[],
  tables?: SolanaAddressLookupTables
) => {
  const attempt = <T>(run: () => T): T | Error => {
    try {
      return run()
    } catch (error) {
      return error as Error
    }
  }
  const ours = attempt(() =>
    solana.compileMessage({
      addressLookupTables: tables,
      feePayer: payer,
      instructions,
      recentBlockhash: blockhash,
      version: 0,
    })
  )
  const theirs = attempt(() => kitBytes(0, payer, blockhash, instructions.map(toKit), tables))
  return {ours, theirs}
}

const kitDecode = (bytes: Uint8Array) => {
  const compiled = getCompiledTransactionMessageDecoder().decode(bytes)
  if (compiled.version !== 0) {
    assert.fail('kit reads a v0 message')
  }
  return compiled as CompiledTransactionMessage & CompiledTransactionMessageWithLifetime & {version: 0}
}

describe('v0 messages', () => {
  test('without lookup tables: the bytes kit compiles, version prefix and an empty lookup list', () => {
    for (let round = 0; round < 60; round++) {
      const payer = random.address()
      const blockhash = random.blockhash()
      const {instructions} = randomInstructions(random, payer)
      const {ours, theirs} = compileBoth(payer, blockhash, instructions)
      if (ours instanceof Error || theirs instanceof Error) {
        assert.ok(ours instanceof Error && theirs instanceof Error, `round ${round}: one refused, one did not`)
        continue
      }
      assert.deepEqual(ours, theirs, `round ${round}`)
      assert.equal(ours[0], 0x80)
      assert.equal(ours.at(-1), 0)
      const legacy = solana.compileMessage({feePayer: payer, instructions, recentBlockhash: blockhash})
      assert.deepEqual(ours.subarray(1, -1), legacy)
    }
  })

  test('with lookup tables: kit`s compression and compiler, byte for byte, on random instructions and tables', () => {
    let lookedUp = 0
    for (let round = 0; round < 400; round++) {
      const payer = random.address()
      const blockhash = random.blockhash()
      const {accounts, instructions, programs} = randomInstructions(random, payer)
      const tables = randomTables(random, [...accounts, ...programs, payer])
      const {ours, theirs} = compileBoth(payer, blockhash, instructions, tables)
      if (ours instanceof Error || theirs instanceof Error) {
        assert.ok(ours instanceof Error && theirs instanceof Error, `round ${round}: one refused, one did not`)
        continue
      }
      assert.deepEqual(ours, theirs, `round ${round}`)
      lookedUp += kitDecode(ours).addressTableLookups?.length ?? 0
    }
    assert.ok(lookedUp > 200, `many rounds load accounts from tables (${lookedUp} lookups)`)
  })

  test('which accounts are looked up: never the fee payer, a signer or an invoked program; the first table wins', () => {
    const payer = random.address()
    const signer = random.address()
    const program = random.address()
    const recipient = random.address()
    const reader = random.address()
    const [first, second] = [random.address(), random.address()]
    const tables = {
      [first]: [random.address(), reader, payer, signer, program],
      [second]: [recipient, reader],
    }
    const instructions: SolanaInstruction[] = [
      {
        accounts: [
          {address: signer, isSigner: true, isWritable: false},
          {address: recipient, isSigner: false, isWritable: true},
          {address: reader, isSigner: false, isWritable: false},
          {address: payer, isSigner: false, isWritable: true},
          {address: program, isSigner: false, isWritable: false},
        ],
        data: Uint8Array.of(1),
        programId: program,
      },
    ]
    const recentBlockhash = random.blockhash()
    const message = solana.compileMessage({
      addressLookupTables: tables,
      feePayer: payer,
      instructions,
      recentBlockhash,
      version: 0,
    })
    assert.deepEqual(message, kitBytes(0, payer, recentBlockhash, instructions.map(toKit), tables))
    const decoded = solana.decodeMessage(message)
    assert.deepEqual(
      decoded.accounts.map(account => account.address),
      [payer, signer, program, undefined, undefined]
    )
    // `reader` is in both tables: the first holds it. Tables are listed in kit's address order.
    assert.deepEqual(
      decoded.addressTableLookups,
      [
        {lookupTable: first, readonlyIndexes: [1], writableIndexes: []},
        {lookupTable: second, readonlyIndexes: [], writableIndexes: [0]},
      ].sort((left, right) => getAddressComparator()(left.lookupTable, right.lookupTable))
    )
    const resolved = solana.decodeMessage(message, {addressLookupTables: tables})
    assert.deepEqual(resolved.instructions[0]?.accounts, [
      {address: signer, isSigner: true, isWritable: false},
      {address: recipient, isSigner: false, isWritable: true, lookup: {index: 0, lookupTable: second}},
      {address: reader, isSigner: false, isWritable: false, lookup: {index: 1, lookupTable: first}},
      {address: payer, isSigner: true, isWritable: true},
      {address: program, isSigner: false, isWritable: false},
    ])
  })

  test('decodeMessage reads what kit compiles, and names looked-up accounts as kit`s decompiler does', () => {
    for (let round = 0; round < 150; round++) {
      const payer = random.address()
      const blockhash = random.blockhash()
      const {accounts, instructions, programs} = randomInstructions(random, payer)
      const tables = randomTables(random, [...accounts, ...programs, payer])
      let bytes: Uint8Array
      try {
        bytes = kitBytes(0, payer, blockhash, instructions.map(toKit), tables)
      } catch {
        continue
      }
      const compiled = kitDecode(bytes)
      const theirs = decompileTransactionMessage(compiled, {addressesByLookupTableAddress: kitTables(tables)})
      const decoded = solana.decodeMessage(bytes, {addressLookupTables: tables})

      assert.equal(decoded.version, 0)
      assert.equal(decoded.feePayer, payer)
      assert.equal(decoded.recentBlockhash, blockhash)
      assert.deepEqual(decoded.signers, compiled.staticAccounts.slice(0, compiled.header.numSignerAccounts))
      assert.deepEqual(
        decoded.addressTableLookups.map(lookup => [lookup.lookupTable, lookup.writableIndexes, lookup.readonlyIndexes]),
        (compiled.addressTableLookups ?? []).map(lookup => [
          lookup.lookupTableAddress,
          [...lookup.writableIndexes],
          [...lookup.readonlyIndexes],
        ])
      )
      assert.deepEqual(
        decoded.instructions.map(instruction => [
          instruction.programId,
          instruction.accounts.map(account => [account.address, roleOf(account), account.lookup?.lookupTable]),
          [...instruction.data],
        ]),
        theirs.instructions.map(instruction => [
          instruction.programAddress,
          (instruction.accounts ?? []).map(account => [
            account.address,
            account.role,
            'lookupTableAddress' in account ? account.lookupTableAddress : undefined,
          ]),
          [...(instruction.data ?? [])],
        ])
      )

      // Compiled again with the same tables, the decoded message is the same bytes.
      assert.deepEqual(
        solana.compileMessage({
          addressLookupTables: tables,
          feePayer: payer,
          instructions: decoded.instructions.map(toInstruction),
          recentBlockhash: blockhash,
          version: 0,
        }),
        bytes
      )

      // Without the tables, the looked-up accounts are there, unnamed, with their table and index.
      const bare = solana.decodeMessage(bytes)
      assert.equal(bare.accounts.length, decoded.accounts.length)
      bare.accounts.forEach((account, index) => {
        const named = decoded.accounts[index]
        assert.deepEqual(account, named?.lookup ? {...named, address: undefined} : named)
      })
    }
  })

  test('summaries need the accounts they describe: a transfer to a looked-up account is unknown until it is named', () => {
    const payer = random.address()
    const recipient = random.address()
    const table = random.address()
    const tables = {[table]: [recipient]}
    const message = solana.compileMessage({
      addressLookupTables: tables,
      feePayer: payer,
      instructions: [
        solana.instructions.transfer({from: payer, lamports: 5n, to: recipient}),
        {
          accounts: [],
          data: Uint8Array.of(3, 1, 0, 0, 0, 0, 0, 0, 0),
          programId: 'ComputeBudget111111111111111111111111111111',
        },
      ],
      recentBlockhash: random.blockhash(),
      version: 0,
    })
    const bare = solana.decodeMessage(message)
    assert.deepEqual(bare.instructions[0]?.summary, {programId: SYSTEM_PROGRAM, type: 'unknown'})
    assert.deepEqual(bare.instructions[1]?.summary, {microLamports: 1n, type: 'compute-unit-price'})
    assert.deepEqual(solana.decodeMessage(message, {addressLookupTables: tables}).instructions[0]?.summary, {
      from: payer,
      lamports: 5n,
      to: recipient,
      type: 'transfer',
    })
  })

  test('what kit refuses is refused: lookup tables on a legacy message, too many accounts, signers or instructions', () => {
    const payer = random.address()
    const recentBlockhash = random.blockhash()
    const transfer = solana.instructions.transfer({from: payer, lamports: 1n, to: random.address()})
    const refused = (run: () => unknown) => assert.throws(run, error => isCryptoError(error, 'INVALID_ARGUMENT'))

    refused(() =>
      solana.compileMessage({addressLookupTables: {}, feePayer: payer, instructions: [transfer], recentBlockhash})
    )
    refused(() =>
      solana.compileMessage({feePayer: payer, instructions: [], recentBlockhash, version: 1 as unknown as 0})
    )

    // Recipients in a table, so the transaction stays small: 62 of them make 64 accounts, 63 make one too many.
    const recipients = Array.from({length: 63}, random.address)
    const transfers = recipients.map(to => ({
      accounts: [{address: to, isSigner: false, isWritable: true}],
      data: new Uint8Array(),
      programId: SYSTEM_PROGRAM,
    }))
    const table = {[random.address()]: recipients}
    const fits = compileBoth(payer, recentBlockhash, transfers.slice(0, 62), table)
    assert.ok(fits.ours instanceof Uint8Array)
    assert.deepEqual(fits.ours, fits.theirs)
    const over = compileBoth(payer, recentBlockhash, transfers, table)
    assert.ok(over.ours instanceof Error && over.theirs instanceof Error)
    const instructions = Array.from({length: 65}, () => transfer)
    const tooMany = compileBoth(payer, recentBlockhash, instructions)
    assert.ok(tooMany.ours instanceof Error && tooMany.theirs instanceof Error)

    const signers = Array.from({length: 13}, () => ({address: random.address(), isSigner: true, isWritable: false}))
    const {ours, theirs} = compileBoth(payer, recentBlockhash, [
      {accounts: signers, data: Uint8Array.of(), programId: TOKEN_PROGRAM},
    ])
    assert.ok(ours instanceof Error && theirs instanceof Error)

    refused(() =>
      solana.compileMessage({
        addressLookupTables: {[random.address()]: Array.from({length: 257}, random.address)},
        feePayer: payer,
        instructions: [transfer],
        recentBlockhash,
        version: 0,
      })
    )
    assert.throws(
      () =>
        solana.compileMessage({
          addressLookupTables: {'not a table': []},
          feePayer: payer,
          instructions: [transfer],
          recentBlockhash,
          version: 0,
        }),
      error => isCryptoError(error, 'INVALID_ADDRESS')
    )
  })

  test('malformed v0 messages, and other versions, are refused', () => {
    const payer = random.address()
    const program = random.address()
    const table = random.address()
    const [a, b] = [random.address(), random.address()]
    const message = solana.compileMessage({
      addressLookupTables: {[table]: [a, b]},
      feePayer: payer,
      instructions: [
        {
          accounts: [
            {address: a, isSigner: false, isWritable: true},
            {address: b, isSigner: false, isWritable: false},
          ],
          data: Uint8Array.of(7),
          programId: program,
        },
      ],
      recentBlockhash: random.blockhash(),
      version: 0,
    })
    // 0x80, header (3), 2 static accounts, blockhash, 1 instruction (program 1, accounts 2 and 3, 1 byte of data),
    // 1 lookup (the table, writable [0], read-only [1]).
    const lookupsAt = 1 + 3 + 1 + 64 + 32 + 1 + 1 + 1 + 2 + 1 + 1
    assert.deepEqual([...message.subarray(lookupsAt)], [1, ...base58.decode(table), 1, 0, 1, 1])
    const instructionAt = 1 + 3 + 1 + 64 + 32 + 1
    const refused = (bytes: Uint8Array, options = {}) =>
      assert.throws(
        () => solana.decodeMessage(bytes, options),
        error => isCryptoError(error, 'INVALID_ARGUMENT'),
        String([...bytes.subarray(0, 4)])
      )
    const replace = (at: number, ...values: number[]) => {
      const out = message.slice()
      out.set(values, at)
      return out
    }

    assert.equal(solana.decodeMessage(message).accounts.length, 4)
    refused(Uint8Array.of(0x81, ...message.subarray(1)))
    refused(Uint8Array.of(0xff, ...message.subarray(1)))
    // Without its lookup list, or with a byte after it.
    refused(message.subarray(0, lookupsAt))
    refused(Uint8Array.of(...message, 0))
    // The program loaded from the table; the fee payer as the program; an account index past the last.
    refused(replace(instructionAt, 2))
    refused(replace(instructionAt, 0))
    refused(replace(instructionAt + 2, 4))
    // A lookup that loads nothing, and one that loads index 0 twice.
    refused(Uint8Array.of(...message.subarray(0, lookupsAt + 33), 0, 0))
    refused(Uint8Array.of(...message.subarray(0, lookupsAt + 33), 1, 0, 1, 0))
    // A table supplied that is too short, or that names a static account again.
    refused(message, {addressLookupTables: {[table]: [a]}})
    refused(message, {addressLookupTables: {[table]: [payer, b]}})
    // More than 256 accounts in all: two tables of 128 each, beside the two static ones.
    const half = Array.from({length: 128}, (_, index) => index)
    const lookups = [random.address(), random.address()].flatMap(address => [
      ...base58.decode(address),
      0x80,
      1,
      ...half,
      0,
    ])
    refused(Uint8Array.of(...message.subarray(0, lookupsAt), 2, ...lookups))

    for (let run = 0; run < 3000; run++) {
      const mutated = message.slice()
      mutated[random.int(mutated.length)] = random.int(256)
      try {
        solana.decodeMessage(mutated, {addressLookupTables: {[table]: [a, b]}})
      } catch (error) {
        assert.ok(isCryptoError(error), String(error))
      }
    }
  })
})

describe('v0 transactions', () => {
  test('signed alone, with lookup tables: kit`s wire bytes for the same key', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const seed = mnemonicToSeedSync(ABANDON)
    for (const index of [0, 3]) {
      const account = await wallet.deriveAccount({account: index, chain: 'solana'})
      const pair = await createKeyPairFromPrivateKeyBytes(slip10Seed(seed, [44, 501, index, 0]))
      for (let round = 0; round < 6; round++) {
        const recentBlockhash = random.blockhash()
        const recipient = random.address()
        const instructions = solana.instructions.transferToken({
          amount: random.u64(),
          decimals: 6,
          from: account.address,
          mint: USDC_DEVNET,
          to: recipient,
        })
        const pool = [...new Set(instructions.flatMap(instruction => instruction.accounts.map(meta => meta.address)))]
        const tables = randomTables(random, [...pool, TOKEN_PROGRAM, SYSTEM_PROGRAM])
        const signed = await account.signTransaction({
          addressLookupTables: tables,
          instructions,
          recentBlockhash,
          version: 0,
        })
        const theirs = await signTransaction(
          [pair],
          compileTransaction(kitMessage(0, account.address, recentBlockhash, instructions.map(toKit), tables))
        )
        assert.deepEqual(signed.serialized, new Uint8Array(getTransactionEncoder().encode(theirs)))

        const decoded = solana.decodeTransaction(signed.serialized, {addressLookupTables: tables})
        assert.equal(base58.encode(decoded.signatures[0] ?? new Uint8Array()), signed.signature)
        assert.equal(decoded.version, 0)
        assert.ok(crypto.ed25519.verify(account.publicKey, decoded.message, decoded.signatures[0] ?? new Uint8Array()))
        assert.deepEqual(
          solana.assembleTransaction({
            message: decoded.message,
            signatures: [decoded.signatures[0] ?? new Uint8Array()],
          }),
          signed
        )
      }
    }
    wallet.dispose()
  })

  test('partial signing: each signer fills its own slot, in any order, as kit`s partiallySignTransaction does', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const seed = mnemonicToSeedSync(ABANDON)
    const account = await wallet.deriveAccount({chain: 'solana'})
    const pair = await createKeyPairFromPrivateKeyBytes(slip10Seed(seed, [44, 501, 0, 0]))
    const other = await generateKeyPair()
    const otherAddress = await getAddressFromPublicKey(other.publicKey)
    const stranger = await wallet.deriveAccount({account: 5, chain: 'solana'})
    const encode = (transaction: Parameters<ReturnType<typeof getTransactionEncoder>['encode']>[0]) =>
      new Uint8Array(getTransactionEncoder().encode(transaction))

    for (const [round, feePayerIsOurs] of [true, false, true, false].entries()) {
      const payer = feePayerIsOurs ? account.address : otherAddress
      const cosigner = feePayerIsOurs ? otherAddress : account.address
      const recipient = random.address()
      const tables = {[random.address()]: [recipient, random.address()]}
      const instructions = [
        solana.instructions.transfer({from: payer, lamports: 1000n, to: recipient}),
        solana.instructions.transfer({from: cosigner, lamports: 2000n, to: recipient}),
      ]
      const version = round < 2 ? 0 : 'legacy'
      const compiled = compileTransaction(
        kitMessage(version, payer, random.blockhash(), instructions.map(toKit), version === 0 ? tables : undefined)
      )
      const unsigned = encode(compiled)

      // Ours first, onto the unsigned transaction.
      const first = await account.partiallySignTransaction(unsigned)
      assert.deepEqual(first.serialized, encode(await partiallySignTransaction([pair], compiled)))
      assert.equal(first.complete, false)
      assert.equal(first.signature !== undefined, feePayerIsOurs)
      const decoded = solana.decodeTransaction(first.serialized)
      assert.equal(decoded.signatures.filter(Boolean).length, 1)

      // Then theirs, with kit, onto what we returned: the transaction kit signs completely.
      const both = encode(await partiallySignTransaction([other], getTransactionDecoder().decode(first.serialized)))
      assert.deepEqual(both, encode(await signTransaction([pair, other], compiled)))

      // Theirs first, then ours: the same bytes, now complete, with the fee payer's signature as the id.
      const theirs = encode(await partiallySignTransaction([other], compiled))
      const second = await account.partiallySignTransaction(theirs)
      assert.deepEqual(second.serialized, both)
      assert.equal(second.complete, true)
      assert.equal(second.signature, base58.encode(solana.decodeTransaction(both).signatures[0] ?? new Uint8Array()))

      // Signing again changes nothing; an account that is not a signer is refused.
      assert.deepEqual((await account.partiallySignTransaction(second.serialized)).serialized, both)
      await assert.rejects(stranger.partiallySignTransaction(unsigned), error =>
        isCryptoError(error, 'INVALID_ARGUMENT')
      )

      // And the message signed elsewhere, assembled: the same transaction.
      const message = solana.decodeTransaction(both).message
      const signatures = solana.decodeTransaction(both).signatures.map(signature => signature ?? new Uint8Array())
      assert.deepEqual(solana.assembleTransaction({message, signatures}).serialized, both)
      assert.deepEqual(await account.signTransactionMessage(message), signatures[feePayerIsOurs ? 0 : 1])
    }

    // A transaction whose slots do not match its signers is refused.
    const lone = await account.signTransaction({
      instructions: [solana.instructions.transfer({from: account.address, lamports: 1n, to: random.address()})],
      recentBlockhash: random.blockhash(),
    })
    for (const bytes of [
      Uint8Array.of(2, ...new Uint8Array(64), ...lone.serialized.subarray(1)),
      Uint8Array.of(0, ...lone.serialized.subarray(65)),
    ]) {
      assert.throws(
        () => solana.decodeTransaction(bytes),
        error => isCryptoError(error, 'INVALID_ARGUMENT')
      )
      await assert.rejects(account.partiallySignTransaction(bytes), error => isCryptoError(error, 'INVALID_ARGUMENT'))
    }
    wallet.dispose()
  })

  test('signTransaction still signs alone: a v0 instruction that needs another signer is refused', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const account = await wallet.deriveAccount({chain: 'solana'})
    await assert.rejects(
      () =>
        account.signTransaction({
          instructions: [solana.instructions.transfer({from: random.address(), lamports: 1n, to: account.address})],
          recentBlockhash: random.blockhash(),
          version: 0,
        }),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    wallet.dispose()
  })

  test('lookup tables make room: 40 transfers do not fit a legacy transaction, and fit a v0 one', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const account = await wallet.deriveAccount({chain: 'solana'})
    const recipients = Array.from({length: 40}, random.address)
    const instructions = recipients.map(to => solana.instructions.transfer({from: account.address, lamports: 1n, to}))
    const recentBlockhash = random.blockhash()
    await assert.rejects(account.signTransaction({instructions, recentBlockhash}), error =>
      isCryptoError(error, 'INVALID_ARGUMENT')
    )
    const table = random.address()
    const signed = await account.signTransaction({
      addressLookupTables: {[table]: recipients},
      instructions,
      recentBlockhash,
      version: 0,
    })
    const decoded = solana.decodeTransaction(signed.serialized, {addressLookupTables: {[table]: recipients}})
    assert.deepEqual(
      decoded.instructions.map(instruction => instruction.summary.type === 'transfer' && instruction.summary.to),
      recipients
    )
    wallet.dispose()
  })
})
