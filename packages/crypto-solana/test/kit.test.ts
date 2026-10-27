import assert from 'node:assert/strict'
import {readdirSync, readFileSync} from 'node:fs'
import path from 'node:path'
import {describe, test} from 'node:test'

import {isCryptoError} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {mnemonicToSeedSync} from '@scure/bip39'
import {
  AccountRole,
  type Address,
  appendTransactionMessageInstructions,
  type Blockhash,
  compileTransaction,
  compressTransactionMessageUsingAddressLookupTables,
  createKeyPairSignerFromPrivateKeyBytes,
  createSignableMessage,
  createTransactionMessage,
  generateKeyPairSigner,
  getTransactionEncoder,
  type Instruction,
  isMessagePartialSigner,
  isTransactionPartialSigner,
  type MessagePartialSigner,
  type OffchainMessage,
  type OffchainMessageApplicationDomain,
  OffchainMessageContentFormat,
  partiallySignTransactionMessageWithSigners,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signOffchainMessageWithSigners,
  signTransactionMessageWithSigners,
  type Transaction,
  type TransactionPartialSigner,
  type TransactionSigner,
} from '@solana/kit'

import {type SolanaAddressLookupTables, SYSTEM_PROGRAM, solanaAdapter} from '../src'
import {toKitSigner} from '../src/kit'
import {ABANDON, kitTables, randomness, slip10Seed} from './support'

const crypto = createTestCryptoEngine({adapters: [solanaAdapter({cluster: 'devnet'})]})
const solana = crypto.chains.solana
const random = randomness(4)

const encode = (transaction: Transaction) => new Uint8Array(getTransactionEncoder().encode(transaction))

/** A System transfer whose sender signs through kit: the signer travels in the account meta, as kit's clients do. */
const transfer = (from: TransactionSigner, to: string, lamports: bigint): Instruction => {
  const data = new Uint8Array(12)
  data[0] = 2
  new DataView(data.buffer).setBigUint64(4, lamports, true)
  return {
    accounts: [
      {address: from.address, role: AccountRole.WRITABLE_SIGNER, signer: from},
      {address: to as Address, role: AccountRole.WRITABLE},
    ],
    data,
    programAddress: SYSTEM_PROGRAM as Address,
  } as Instruction
}

type Plan = {
  readonly version: 'legacy' | 0
  readonly blockhash: string
  readonly sends: readonly {readonly to: string; readonly lamports: bigint; readonly by: number}[]
  readonly tables?: SolanaAddressLookupTables
}

/** The same transaction for any set of signers: the fee payer is `signers[0]`, each send signed by `signers[by]`. */
const build = ({blockhash, sends, tables, version}: Plan, signers: readonly TransactionSigner[]) => {
  const payer = signers[0] as TransactionSigner
  const built = pipe(
    createTransactionMessage({version}),
    message => setTransactionMessageFeePayerSigner(payer, message),
    message =>
      setTransactionMessageLifetimeUsingBlockhash(
        {blockhash: blockhash as Blockhash, lastValidBlockHeight: 0n},
        message
      ),
    message =>
      appendTransactionMessageInstructions(
        sends.map(({by, lamports, to}) => transfer(signers[by] as TransactionSigner, to, lamports)),
        message
      )
  )
  // kit types its compression for v0 messages only; this builds either version.
  return tables
    ? (compressTransactionMessageUsingAddressLookupTables(built as never, kitTables(tables)) as typeof built)
    : built
}

/** A compiled transaction as a signer receives it: kit brands it as within the size limit, which these are. */
const signable = (transaction: Transaction) =>
  transaction as Parameters<TransactionPartialSigner['signTransactions']>[0][number]

const plan = (version: 'legacy' | 0, signerCount: number): Plan => {
  const recipients = Array.from({length: 3}, random.address)
  return {
    blockhash: random.blockhash(),
    sends: recipients.map((to, index) => ({by: index % signerCount, lamports: random.u64() % 10_000_000n, to})),
    tables: version === 0 ? {[random.address()]: [random.address(), ...recipients]} : undefined,
    version,
  }
}

describe('toKitSigner', () => {
  test('is a kit transaction and message partial signer, and nothing loads kit', () => {
    const signer = toKitSigner({
      address: random.address(),
      signMessage: async () => new Uint8Array(64),
      signTransactionMessage: async () => new Uint8Array(64),
    })
    const asTransactionSigner: TransactionPartialSigner = signer
    const asMessageSigner: MessagePartialSigner = signer
    assert.ok(isTransactionPartialSigner(asTransactionSigner))
    assert.ok(isMessagePartialSigner(asMessageSigner))

    // Only the kit entry names @solana/kit, and only for its types.
    const source = path.join(import.meta.dirname, '../src')
    for (const file of readdirSync(source)) {
      const imports = readFileSync(path.join(source, file), 'utf8').match(/^import[^;]*?from '@solana\/kit'/gms) ?? []
      if (file === 'kit.ts') {
        assert.equal(imports.length, 1)
        assert.match(imports[0] ?? '', /^import type \{/)
      } else {
        assert.deepEqual(imports, [], file)
      }
    }
    const manifest = JSON.parse(readFileSync(path.join(import.meta.dirname, '../package.json'), 'utf8'))
    assert.deepEqual(manifest.exports['./kit'], {
      default: './build/kit.js',
      source: './src/kit.ts',
      types: './build/kit.d.ts',
    })
    assert.deepEqual(manifest.publishConfig.exports['./kit'], {default: './build/kit.js', types: './build/kit.d.ts'})
    assert.deepEqual(manifest.peerDependenciesMeta, {'@solana/kit': {optional: true}})
  })

  test('signTransactionMessageWithSigners: the bytes a key pair signer of the same key makes, and signTransaction`s', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const seed = mnemonicToSeedSync(ABANDON)
    for (const index of [0, 2]) {
      const account = await wallet.deriveAccount({account: index, chain: 'solana'})
      const ours = toKitSigner(account)
      const theirs = await createKeyPairSignerFromPrivateKeyBytes(slip10Seed(seed, [44, 501, index, 0]))
      assert.equal(ours.address, theirs.address)

      for (const version of ['legacy', 0, 'legacy', 0] as const) {
        const transaction = plan(version, 1)
        const signed = encode(await signTransactionMessageWithSigners(build(transaction, [ours])))
        assert.deepEqual(signed, encode(await signTransactionMessageWithSigners(build(transaction, [theirs]))))

        // The account itself, given the same instructions, signs the same transaction.
        const direct = await account.signTransaction({
          addressLookupTables: transaction.tables,
          instructions: transaction.sends.map(({lamports, to}) =>
            solana.instructions.transfer({from: account.address, lamports, to})
          ),
          recentBlockhash: transaction.blockhash,
          version,
        })
        assert.deepEqual(signed, direct.serialized)
      }
    }
    wallet.dispose()
  })

  test('beside other signers: each signs its own slot, partially or completely, as with key pair signers', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const seed = mnemonicToSeedSync(ABANDON)
    const account = await wallet.deriveAccount({chain: 'solana'})
    const ours = toKitSigner(account)
    const theirs = await createKeyPairSignerFromPrivateKeyBytes(slip10Seed(seed, [44, 501, 0, 0]))
    const other = await generateKeyPairSigner()

    for (const version of ['legacy', 0] as const) {
      for (const oursPays of [true, false]) {
        const transaction = plan(version, 2)
        const signers = (mine: TransactionSigner) => (oursPays ? [mine, other] : [other, mine])
        const complete = encode(await signTransactionMessageWithSigners(build(transaction, signers(ours))))
        assert.deepEqual(complete, encode(await signTransactionMessageWithSigners(build(transaction, signers(theirs)))))

        // Only our slot: what a wallet returns to a dApp that signs the rest.
        const unsigned = compileTransaction(build(transaction, signers(ours)))
        const [slot] = await ours.signTransactions([signable(unsigned)])
        const [theirSlot] = await theirs.signTransactions([signable(unsigned)])
        assert.deepEqual(slot, theirSlot)
        const partial = await account.partiallySignTransaction(encode(unsigned))
        assert.equal(partial.complete, false)
        assert.deepEqual(
          partial.serialized,
          encode({...unsigned, signatures: {...unsigned.signatures, ...slot}} as Transaction)
        )

        // kit's partial helper with both signers is the complete transaction.
        const both = await partiallySignTransactionMessageWithSigners(build(transaction, signers(ours)))
        assert.deepEqual(encode(both), complete)
      }
    }
    wallet.dispose()
  })

  test('messages: plain and off-chain, signed as a key pair signer signs them', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const seed = mnemonicToSeedSync(ABANDON)
    const account = await wallet.deriveAccount({account: 1, chain: 'solana'})
    const ours = toKitSigner(account)
    const theirs = await createKeyPairSignerFromPrivateKeyBytes(slip10Seed(seed, [44, 501, 1, 0]))
    const contents = ['Sign in to Example', new Uint8Array(0), random.bytes(300)]
    const messages = contents.map(content => createSignableMessage(content))
    assert.deepEqual(await ours.signMessages(messages), await theirs.signMessages(messages))

    const applicationDomain = random.address() as unknown as OffchainMessageApplicationDomain
    const offchain = (signer: MessagePartialSigner): OffchainMessage[] => [
      {content: 'Hello from Expo', requiredSignatories: [signer], version: 1},
      {
        applicationDomain,
        content: {format: OffchainMessageContentFormat.RESTRICTED_ASCII_1232_BYTES_MAX, text: 'Vote yes'},
        requiredSignatories: [signer],
        version: 0,
      } as unknown as OffchainMessage,
    ]
    const [first, second] = [offchain(ours), offchain(theirs)]
    for (const [index, message] of first.entries()) {
      const mine = await signOffchainMessageWithSigners(message as never)
      const kits = await signOffchainMessageWithSigners(second[index] as never)
      assert.deepEqual(mine, kits)
      // And our own signOffchainMessage of the same message.
      const signed = await account.signOffchainMessage(new Uint8Array(mine.content))
      assert.deepEqual(signed.signature, mine.signatures[ours.address])
    }
    wallet.dispose()
  })

  test('refuses a transaction the account is not a signer of, and stops when aborted', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const ours = toKitSigner(await wallet.deriveAccount({chain: 'solana'}))
    const other = await generateKeyPairSigner()
    const foreign = compileTransaction(build(plan(0, 1), [other]))
    await assert.rejects(ours.signTransactions([signable(foreign)]), error => isCryptoError(error, 'INVALID_ARGUMENT'))

    const controller = new AbortController()
    controller.abort()
    const mine = compileTransaction(build(plan('legacy', 1), [ours]))
    await assert.rejects(ours.signTransactions([signable(mine)], {abortSignal: controller.signal}), {
      name: 'AbortError',
    })
    await assert.rejects(ours.signMessages([createSignableMessage('x')], {abortSignal: controller.signal}), {
      name: 'AbortError',
    })
    wallet.dispose()
  })
})
