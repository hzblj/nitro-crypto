import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {base58, isCryptoError, utf8} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {mnemonicToSeedSync} from '@scure/bip39'
import {
  type Address,
  compileOffchainMessageEnvelope,
  createKeyPairFromPrivateKeyBytes,
  getOffchainMessageDecoder,
  getOffchainMessageEncoder,
  type OffchainMessage,
  OffchainMessageContentFormat,
  partiallySignOffchainMessageEnvelope,
  type SignatureBytes,
  verifyOffchainMessageEnvelope,
} from '@solana/kit'

import {type SolanaOffchainMessage, type SolanaOffchainMessageFormat, solanaAdapter} from '../src'
import {ABANDON, randomness, slip10Seed} from './support'

const crypto = createTestCryptoEngine({adapters: [solanaAdapter()]})
const solana = crypto.chains.solana
const random = randomness(3)

/** Byte order of two addresses: how version 1 lists its signers. */
const compare = (left: string, right: string) => {
  const [x, y] = [base58.decode(left), base58.decode(right)]
  const index = x.findIndex((byte, at) => byte !== y[at])
  return index < 0 ? 0 : (x[index] ?? 0) - (y[index] ?? 0)
}

const FORMATS: Record<SolanaOffchainMessageFormat, OffchainMessageContentFormat> = {
  'extended-utf8': OffchainMessageContentFormat.UTF8_65535_BYTES_MAX,
  'limited-utf8': OffchainMessageContentFormat.UTF8_1232_BYTES_MAX,
  'restricted-ascii': OffchainMessageContentFormat.RESTRICTED_ASCII_1232_BYTES_MAX,
}

/** Ours, as kit's input. */
const toKit = (message: SolanaOffchainMessage, format?: SolanaOffchainMessageFormat): OffchainMessage =>
  (message.version === 0
    ? {
        applicationDomain: message.applicationDomain,
        content: {format: FORMATS[format ?? message.format ?? 'restricted-ascii'], text: message.text},
        requiredSignatories: message.signers.map(address => ({address})),
        version: 0,
      }
    : {
        content: message.text,
        requiredSignatories: message.signers.map(address => ({address})),
        version: 1,
      }) as unknown as OffchainMessage

const kitEncode = (message: OffchainMessage) => new Uint8Array(getOffchainMessageEncoder().encode(message))

const outcome = <T>(run: () => T): T | Error => {
  try {
    return run()
  } catch (error) {
    return error as Error
  }
}

const TEXTS = [
  () => 'Sign in to Example',
  () => 'Ünïcödé, 你好, and 🧪',
  () => 'a'.repeat(1100 + random.int(200)),
  () => '€'.repeat(300 + random.int(150)),
  () => 'Long. '.repeat(400 + random.int(200)),
  () => '\u0007 a bell is not printable',
  () => '',
]

describe('off-chain messages', () => {
  test('encode as kit`s getOffchainMessageEncoder does: v0 in each format, v1, random signers and texts', () => {
    let encoded = 0
    for (let round = 0; round < 300; round++) {
      const signers = Array.from({length: 1 + random.int(4)}, random.address)
      const text = random.pick(TEXTS)()
      const v1: SolanaOffchainMessage = {signers, text, version: 1}
      const v0: SolanaOffchainMessage = {applicationDomain: random.address(), signers, text, version: 0}
      const cases: [SolanaOffchainMessage, OffchainMessage][] = [
        [v1, toKit(v1)],
        ...(['restricted-ascii', 'limited-utf8', 'extended-utf8'] as const).map(
          (format): [SolanaOffchainMessage, OffchainMessage] => [{...v0, format}, toKit(v0, format)]
        ),
      ]
      for (const [ours, theirs] of cases) {
        const mine = outcome(() => solana.encodeOffchainMessage(ours))
        const kits = outcome(() => kitEncode(theirs))
        if (mine instanceof Error || kits instanceof Error) {
          assert.ok(mine instanceof Error && kits instanceof Error, `round ${round}: one refused, one did not`)
          assert.ok(isCryptoError(mine, 'INVALID_ARGUMENT'), String(mine))
          continue
        }
        encoded++
        assert.deepEqual(mine, kits, `round ${round}`)
        assert.deepEqual(solana.decodeOffchainMessage(mine), {
          ...ours,
          signers: ours.version === 1 ? [...signers].sort(compare) : signers,
        })
        const decoded = getOffchainMessageDecoder().decode(mine)
        assert.equal(decoded.version, ours.version)
      }
    }
    assert.ok(encoded > 400, `${encoded} messages encoded`)
  })

  test('a v0 message without a format gets the most restrictive one its text fits', () => {
    const signers = [random.address()]
    const applicationDomain = random.address()
    const formatOf = (text: string) => {
      const decoded = solana.decodeOffchainMessage(
        solana.encodeOffchainMessage({applicationDomain, signers, text, version: 0})
      )
      return decoded.version === 0 ? decoded.format : undefined
    }
    // The v0 header with one signer is 85 bytes, which leaves 1147 for the text in the two limited formats.
    assert.equal(formatOf('Hello'), 'restricted-ascii')
    assert.equal(formatOf('a'.repeat(1147)), 'restricted-ascii')
    assert.equal(formatOf('a'.repeat(1148)), 'extended-utf8')
    assert.equal(formatOf('Héllo'), 'limited-utf8')
    assert.equal(formatOf('line\nbreak'), 'limited-utf8')
    assert.equal(formatOf('é'.repeat(5000)), 'extended-utf8')
    assert.throws(
      () => solana.encodeOffchainMessage({applicationDomain, signers, text: 'a'.repeat(65536), version: 0}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
  })

  test('signatures equal kit`s partiallySignOffchainMessageEnvelope for the same key, and verify both ways', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const seed = mnemonicToSeedSync(ABANDON)
    const account = await wallet.deriveAccount({chain: 'solana'})
    const other = await wallet.deriveAccount({account: 1, chain: 'solana'})
    const pair = await createKeyPairFromPrivateKeyBytes(slip10Seed(seed, [44, 501, 0, 0]))
    const messages: SolanaOffchainMessage[] = [
      {signers: [account.address], text: 'Hello from Expo', version: 1},
      {signers: [other.address, account.address, random.address()], text: 'Ünïcödé', version: 1},
      {applicationDomain: random.address(), signers: [account.address], text: 'Approve the vote', version: 0},
      {
        applicationDomain: random.address(),
        format: 'extended-utf8',
        signers: [random.address(), account.address],
        text: 'x'.repeat(3000),
        version: 0,
      },
    ]
    for (const message of messages) {
      const signed = await account.signOffchainMessage(message)
      // Partially: kit's envelope wants every signer's signature to be complete, and some of these have others.
      const envelope = await partiallySignOffchainMessageEnvelope(
        [pair],
        compileOffchainMessageEnvelope(toKit(message, message.version === 0 ? message.format : undefined))
      )
      assert.deepEqual(signed.message, new Uint8Array(envelope.content))
      assert.deepEqual(signed.signature, new Uint8Array(envelope.signatures[account.address as Address] ?? []))

      // Given as the bytes a dApp would send, it signs the same.
      assert.deepEqual(await account.signOffchainMessage(signed.message), signed)

      assert.equal(solana.verifyOffchainMessage({address: account.address, message, signature: signed.signature}), true)
      assert.equal(
        solana.verifyOffchainMessage({
          address: account.address,
          message: signed.message,
          signature: base58.encode(signed.signature),
        }),
        true
      )
      const tampered = signed.signature.slice()
      tampered[0] = (tampered[0] ?? 0) ^ 1
      assert.equal(solana.verifyOffchainMessage({address: account.address, message, signature: tampered}), false)
    }

    // A message only this account signs: kit verifies the envelope our signature makes.
    const [single] = messages
    assert.ok(single)
    const signed = await account.signOffchainMessage(single)
    await verifyOffchainMessageEnvelope({
      content: signed.message as never,
      signatures: {[account.address]: signed.signature as SignatureBytes},
    } as never)

    // The account's own raw signature of the bytes verifies, but not for an address the message does not name.
    const outsider = await other.signOffchainMessage({signers: [other.address], text: 'Hello', version: 1})
    assert.equal(
      solana.verifyOffchainMessage({
        address: account.address,
        message: outsider.message,
        signature: outsider.signature,
      }),
      false
    )
    assert.throws(
      () => solana.verifyOffchainMessage({address: 'nope', message: outsider.message, signature: outsider.signature}),
      error => isCryptoError(error, 'INVALID_ADDRESS')
    )
    const raw = await account.signMessage({message: outsider.message})
    assert.equal(
      solana.verifyOffchainMessage({address: account.address, message: outsider.message, signature: raw}),
      false
    )
    wallet.dispose()
  })

  test('an account signs only a message that names it, and only an off-chain message', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const account = await wallet.deriveAccount({chain: 'solana'})
    const transaction = solana.compileMessage({
      feePayer: account.address,
      instructions: [solana.instructions.transfer({from: account.address, lamports: 1n, to: random.address()})],
      recentBlockhash: random.blockhash(),
    })
    const refused = (message: SolanaOffchainMessage | Uint8Array) =>
      assert.rejects(account.signOffchainMessage(message), error => isCryptoError(error, 'INVALID_ARGUMENT'))

    await refused({signers: [random.address()], text: 'Not yours', version: 1})
    await refused(transaction)
    await refused(utf8.encode('Plain text is not an off-chain message'))

    // The two formats cannot be mistaken for each other.
    const offchain = await account.signOffchainMessage({signers: [account.address], text: 'Hi', version: 1})
    assert.throws(
      () => solana.decodeMessage(offchain.message),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    assert.throws(
      () => solana.decodeOffchainMessage(transaction),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    wallet.dispose()
  })

  test('malformed messages are refused, strictly', () => {
    const signer = random.address()
    const [a, b] = [random.address(), random.address()].sort(compare)
    const v0 = solana.encodeOffchainMessage({
      applicationDomain: random.address(),
      format: 'limited-utf8',
      signers: [signer],
      text: 'Héllo',
      version: 0,
    })
    const v1 = solana.encodeOffchainMessage({signers: [a ?? '', b ?? ''], text: 'Hello', version: 1})
    const textAt = 16 + 1 + 32 + 1 + 1 + 32 + 2
    const encodeRefused = (message: SolanaOffchainMessage) =>
      assert.throws(
        () => solana.encodeOffchainMessage(message),
        error => isCryptoError(error, 'INVALID_ARGUMENT') || isCryptoError(error, 'INVALID_ADDRESS')
      )
    const decodeRefused = (bytes: Uint8Array) =>
      assert.throws(
        () => solana.decodeOffchainMessage(bytes),
        error => isCryptoError(error, 'INVALID_ARGUMENT'),
        String([...bytes.subarray(0, 20)])
      )

    encodeRefused({signers: [], text: 'x', version: 1})
    encodeRefused({signers: [signer, signer], text: 'x', version: 1})
    encodeRefused({signers: [signer], text: '', version: 1})
    encodeRefused({signers: ['nope'], text: 'x', version: 1})
    encodeRefused({applicationDomain: 'nope', signers: [signer], text: 'x', version: 0})
    encodeRefused({applicationDomain: signer, format: 'restricted-ascii', signers: [signer], text: 'é', version: 0})
    encodeRefused({
      applicationDomain: signer,
      format: 'limited-utf8',
      signers: [signer],
      text: 'a'.repeat(1148),
      version: 0,
    })
    encodeRefused({signers: [signer], text: 'x', version: 2} as unknown as SolanaOffchainMessage)

    const replace = (bytes: Uint8Array, at: number, ...values: number[]) => {
      const out = bytes.slice()
      out.set(values, at)
      return out
    }
    // The signing domain, the version, the format, no signers, the length, the text, trailing bytes.
    decodeRefused(replace(v0, 0, 0xfe))
    decodeRefused(replace(v0, 16, 2))
    decodeRefused(replace(v0, 49, 3))
    decodeRefused(replace(v0, 49, 0))
    decodeRefused(replace(v0, 50, 0))
    decodeRefused(replace(v0, textAt - 2, 5))
    decodeRefused(Uint8Array.of(...v0, 0x21))
    decodeRefused(replace(v0, textAt + 1, 0xff))
    decodeRefused(v0.subarray(0, textAt))
    // Version 1: signers out of byte order, twice, none; no text; text that is not UTF-8.
    decodeRefused(
      Uint8Array.of(...v1.subarray(0, 18), ...v1.subarray(50, 82), ...v1.subarray(18, 50), ...v1.subarray(82))
    )
    decodeRefused(
      Uint8Array.of(...v1.subarray(0, 18), ...v1.subarray(18, 50), ...v1.subarray(18, 50), ...v1.subarray(82))
    )
    decodeRefused(Uint8Array.of(...v1.subarray(0, 17), 0, ...v1.subarray(82)))
    decodeRefused(v1.subarray(0, 82))
    decodeRefused(Uint8Array.of(...v1.subarray(0, 82), 0xc3))

    for (const message of [v0, v1]) {
      for (let run = 0; run < 2000; run++) {
        const mutated = message.slice()
        mutated[random.int(mutated.length)] = random.int(256)
        try {
          solana.decodeOffchainMessage(mutated)
        } catch (error) {
          assert.ok(isCryptoError(error), String(error))
        }
      }
    }
  })
})
