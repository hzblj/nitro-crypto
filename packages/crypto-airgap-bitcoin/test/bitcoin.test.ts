import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {after, describe, test} from 'node:test'

import {
  CRYPTO_MULTI_ACCOUNTS,
  createMultipartDecoder,
  createMultipartEncoder,
  decodeUR,
  encodeCbor,
  encodeUR,
  fromUR,
  isAirgapError,
  parseKeypath,
  toUR,
  writeMap,
} from '@hzblj/crypto-airgap'
import {type BitcoinUtxo, bitcoinAdapter} from '@hzblj/crypto-bitcoin'
import {hex} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {CryptoAccount, CryptoPSBT} from '@keystonehq/bc-ur-registry'
import {base58check} from '@scure/base'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'
import {Transaction} from '@scure/btc-signer'

import {bitcoinAirgap, CRYPTO_ACCOUNT, CRYPTO_OUTPUT, CRYPTO_PSBT, VERSION} from '../src'

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const VECTOR = JSON.parse(readFileSync(new URL('./vectors/bcr-2020-015.json', import.meta.url), 'utf8'))

const crypto = createTestCryptoEngine({adapters: [bitcoinAdapter({network: 'testnet'})]})
const airgap = bitcoinAirgap(crypto.chains.bitcoin)

const throwsCode = (run: () => unknown, code: Parameters<typeof isAirgapError>[1]) =>
  assert.throws(run, error => isAirgapError(error, code))

const utxo = (txid: string, value: number, vout = 0): BitcoinUtxo => ({
  txid: txid.repeat(64 / txid.length),
  value: BigInt(value),
  vout,
})

/** The xpub text of an HD key from a descriptor: BIP-32's serialization, from what the UR carries. */
const xpub = (key: {
  keyData: Uint8Array
  chainCode?: Uint8Array
  parentFingerprint?: number
  origin?: {components: readonly {index?: number; hardened: boolean}[]}
}) => {
  const components = key.origin?.components ?? []
  const last = components[components.length - 1]
  const out = new Uint8Array(78)
  const view = new DataView(out.buffer)
  view.setUint32(0, 0x0488b21e, false)
  out[4] = components.length
  view.setUint32(5, key.parentFingerprint ?? 0, false)
  view.setUint32(9, last ? (last.index ?? 0) + (last.hardened ? 0x80000000 : 0) : 0, false)
  out.set(key.chainCode ?? new Uint8Array(32), 13)
  out.set(key.keyData, 45)

  return base58check(crypto.hash.sha256).encode(out)
}

describe('crypto-account: the specification`s example', () => {
  test('the UR decodes to the seven descriptors the specification lists, keys and all', () => {
    const ur = decodeUR(VECTOR.ur, {allowedTypes: ['crypto-account']})
    assert.equal(hex.encode(ur.cbor), VECTOR.cbor)

    const account = fromUR(CRYPTO_ACCOUNT, ur)
    assert.equal(account.masterFingerprint, 0x37b5eed4)
    assert.deepEqual(
      account.descriptors.map(descriptor => descriptor.scripts.join('(')),
      ['pkh', 'sh(wpkh', 'wpkh', 'sh(cosigner', 'sh(wsh(cosigner', 'wsh(cosigner', 'tr']
    )

    account.descriptors.forEach((descriptor, index) => {
      const [key] = descriptor.keys
      assert.ok(key && 'hdkey' in key)
      assert.ok(VECTOR.descriptors[index].includes(xpub(key.hdkey)), VECTOR.descriptors[index])
    })
  })

  test('re-encoded, it is the same bytes', () => {
    const account = fromUR(CRYPTO_ACCOUNT, decodeUR(VECTOR.ur, {allowedTypes: ['crypto-account']}))
    assert.equal(encodeUR(toUR(CRYPTO_ACCOUNT, account)), VECTOR.ur)
  })

  test('Keystone`s registry writes descriptors without the 308 tag, and both forms read here', () => {
    const account = fromUR(CRYPTO_ACCOUNT, decodeUR(VECTOR.ur, {allowedTypes: ['crypto-account']}))
    // Keystone's registry (0.8.1) knows neither `tr` nor `cosigner`: the single-key descriptors it can write.
    const supported = account.descriptors.slice(0, 3)
    const keystoneForm = encodeCbor(
      writeMap([
        [1, account.masterFingerprint],
        [2, supported.map(descriptor => CRYPTO_OUTPUT.toCbor(descriptor))],
      ])
    )
    const theirs = CryptoAccount.fromCBOR(Buffer.from(keystoneForm))
    assert.deepEqual(
      theirs.getOutputDescriptors().map(descriptor => descriptor.toString()),
      // Keystone's text drops the brackets around a key's origin; the keys are the same.
      VECTOR.descriptors.slice(0, 3).map((descriptor: string) => descriptor.replace(/[[\]]/g, ''))
    )
    assert.equal(theirs.toCBOR().toString('hex'), hex.encode(keystoneForm))
    assert.deepEqual(fromUR(CRYPTO_ACCOUNT, {cbor: theirs.toCBOR(), type: 'crypto-account'}).descriptors, supported)

    // The specification's own form, with 308 around each descriptor, is one Keystone's registry cannot read.
    assert.throws(() =>
      CryptoAccount.fromCBOR(Buffer.from(toUR(CRYPTO_ACCOUNT, {...account, descriptors: supported}).cbor))
    )
  })

  test('none of these is a key this network can watch: they are mainnet, at account level', () => {
    assert.equal(airgap.decodeAccount(decodeUR(VECTOR.ur, {allowedTypes: ['crypto-account']})).accounts.length, 0)
  })
})

describe('air-gapped signing, both sides', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
  const signer = await wallet.deriveAccount({chain: 'bitcoin'})
  const recipient = (await wallet.deriveAccount({chain: 'bitcoin', index: 1})).address
  after(() => wallet.dispose())

  /** The online wallet: only the public key, from pairing. */
  const pair = () => {
    const pairing = encodeUR(
      airgap.encodeAccount({keys: [airgap.pairingKey(signer)], masterFingerprint: wallet.fingerprint})
    )
    const imported = airgap.decodeAccount(decodeUR(pairing, {allowedTypes: ['crypto-account']}))
    const [account] = imported.accounts
    assert.ok(account)

    return account
  }

  /** What the camera sees: every string of a multipart message, read by a decoder that loses one part in three. */
  const transmit = (text: () => string, allowedTypes: string[]) => {
    const decoder = createMultipartDecoder({allowedTypes, sha256: crypto.hash.sha256})
    let count = 0

    while (!decoder.isComplete()) {
      const part = text()

      if (count++ % 3 !== 1) {
        decoder.receivePart(part)
      }
    }

    return decoder.result()
  }

  test('pairing: the watch-only account is the signer`s address, without its key', () => {
    const watch = pair()
    assert.equal(watch.address, signer.address)
    assert.equal(watch.fingerprint, 0x73c5da0a)
    assert.equal(watch.path, "m/84'/1'/0'/0/0")
    assert.equal('signPsbt' in watch, false)
  })

  test('a payment goes out as an animated QR, comes back signed, and is checked before it is broadcast', async () => {
    const watch = pair()
    const plan = watch.createTransaction({
      amount: 120_000n,
      feeRate: 4,
      to: recipient,
      utxos: [utxo('a1', 90_000), utxo('b2', 70_000, 2), utxo('c3', 10_000)],
    })
    const unsigned = watch.createPsbt(plan)

    // Online to offline.
    const request = createMultipartEncoder(airgap.encodeSignRequest({psbt: unsigned}), {
      maxFragmentLength: 60,
      sha256: crypto.hash.sha256,
    })
    assert.ok(request.fragmentCount > 1)
    const scanned = transmit(request.nextPart, [...airgap.requestTypes])

    // The signer reads it and says what it does.
    const review = airgap.decodeSignRequest(scanned, {account: signer})
    assert.equal(review.fee, plan.fee)
    assert.equal(review.sending, 120_000n)
    assert.equal(review.spending, 160_000n)
    assert.deepEqual(
      review.outputs.map(output => [output.address, output.change]),
      [
        [recipient, false],
        [signer.address, true],
      ]
    )
    assert.deepEqual(review.warnings, ['UNVERIFIED_VALUES'])

    // The user agrees; the key in the engine signs.
    const {psbt: signed} = await signer.signPsbt(review.psbt)
    const response = createMultipartEncoder(airgap.encodeSignResponse({psbt: signed}), {
      maxFragmentLength: 60,
      sha256: crypto.hash.sha256,
    })

    // Offline to online, checked against what was sent.
    const answer = airgap.decodeSignResponse(transmit(response.nextPart, [...airgap.responseTypes]), {
      request: unsigned,
    })
    assert.deepEqual(answer.transaction, await signer.signTransaction(plan))
  })

  test('an answer to another request is REQUEST_MISMATCH, however well it is signed', async () => {
    const watch = pair()
    const first = watch.createPsbt(
      watch.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    )
    const second = watch.createPsbt(
      watch.createTransaction({amount: 20_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    )
    const signedSecond = (await signer.signPsbt(second)).psbt

    throwsCode(() => airgap.decodeSignResponse(toUR(CRYPTO_PSBT, signedSecond), {request: first}), 'REQUEST_MISMATCH')
  })

  test('an answer with a broken signature fails, and says why', async () => {
    const watch = pair()
    const unsigned = watch.createPsbt(
      watch.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    )
    const theirs = Transaction.fromPSBT((await signer.signPsbt(unsigned)).psbt)
    const [[publicKey, signature] = [new Uint8Array(), new Uint8Array()]] = theirs.getInput(0).partialSig ?? []
    // r replaced by another valid-looking r: still DER, no longer this transaction's signature.
    const forged = signature.slice()
    forged[10] = (forged[10] ?? 0) ^ 0x01
    const tampered = Transaction.fromPSBT(unsigned)
    tampered.updateInput(0, {partialSig: [[publicKey, forged]]})

    throwsCode(
      () => airgap.decodeSignResponse(toUR(CRYPTO_PSBT, tampered.toPSBT()), {request: unsigned}),
      'INVALID_PROTOCOL_DATA'
    )
    // An unsigned "answer" is not an answer.
    throwsCode(
      () => airgap.decodeSignResponse(toUR(CRYPTO_PSBT, unsigned), {request: unsigned}),
      'INVALID_PROTOCOL_DATA'
    )
  })

  test('a signer refuses a request that is not for its account, or misplaces its key', async () => {
    const other = await crypto.createEphemeralWallet({mnemonic: MNEMONIC, passphrase: 'other'})
    const stranger = await other.deriveAccount({chain: 'bitcoin'})
    const psbt = stranger.createPsbt(
      stranger.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    )
    throwsCode(() => airgap.decodeSignRequest(toUR(CRYPTO_PSBT, psbt), {account: signer}), 'REQUEST_MISMATCH')
    other.dispose()

    const plan = signer.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    const misplaced = crypto.chains.bitcoin
      .watchAccount({fingerprint: 0x01020304, path: signer.path, publicKey: signer.publicKey})
      .createPsbt(plan)
    throwsCode(() => airgap.decodeSignRequest(toUR(CRYPTO_PSBT, misplaced), {account: signer}), 'REQUEST_MISMATCH')
  })

  test('Keystone`s registry carries the same PSBT bytes', () => {
    const psbt = signer.createPsbt(
      signer.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    )
    const ours = toUR(CRYPTO_PSBT, psbt)
    assert.equal(hex.encode(ours.cbor), new CryptoPSBT(Buffer.from(psbt)).toCBOR().toString('hex'))
    assert.equal(encodeUR(ours), new CryptoPSBT(Buffer.from(psbt)).toUREncoder(100_000).nextPart())
    throwsCode(() => toUR(CRYPTO_PSBT, new Uint8Array(10)), 'INVALID_ARGUMENT')
    throwsCode(
      () =>
        airgap.decodeSignRequest(
          {cbor: new CryptoPSBT(Buffer.from('not a psbt')).toCBOR(), type: 'crypto-psbt'},
          {account: signer}
        ),
      'INVALID_PROTOCOL_DATA'
    )
  })

  test('keys from crypto-multi-accounts: full BIP-84 paths on this network only', () => {
    const fingerprint = wallet.fingerprint
    const shared = fromUR(
      CRYPTO_MULTI_ACCOUNTS,
      toUR(CRYPTO_MULTI_ACCOUNTS, {
        keys: [
          {keyData: signer.publicKey, origin: parseKeypath(signer.path, fingerprint), useInfo: {network: 1, type: 0}},
        ],
        masterFingerprint: fingerprint,
      })
    )
    const [key] = shared.keys
    assert.ok(key)
    assert.equal(airgap.watchAccount(key).address, signer.address)

    throwsCode(
      () => airgap.watchAccount({...key, origin: parseKeypath("m/84'/0'/0'/0/0", fingerprint)}),
      'REQUEST_MISMATCH'
    )
    throwsCode(() => airgap.watchAccount({...key, useInfo: {network: 0, type: 0}}), 'REQUEST_MISMATCH')
    throwsCode(
      () => airgap.watchAccount({...key, origin: parseKeypath("m/84'/1'/0'", fingerprint)}),
      'INVALID_PROTOCOL_DATA'
    )
    throwsCode(() => airgap.watchAccount({keyData: key.keyData}), 'INVALID_PROTOCOL_DATA')
  })

  test('VERSION matches package.json', () => {
    const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
    assert.equal(VERSION, manifest.version)
  })
})

describe('account keys: pairing as Sparrow and other coordinators do', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
  const fingerprint = wallet.fingerprint
  const accountPath = "m/84'/1'/0'"
  const extendedKey = wallet.extendedPublicKey(accountPath)
  const recipient = (await wallet.deriveAccount({account: 1, chain: 'bitcoin'})).address
  after(() => wallet.dispose())

  test('crypto-account carries the account`s extended key, the tpub @scure/bip32 derives, and reads back watchable', async () => {
    const ur = airgap.encodeAccount({
      keys: [airgap.accountKey({extendedKey, fingerprint, path: accountPath})],
      masterFingerprint: fingerprint,
    })
    const reference = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC)).derive(accountPath)

    // Keystone's registry reads it (in the form it writes, without the 308 tag), and its BIP-32 text is the reference's.
    const [descriptor] = fromUR(CRYPTO_ACCOUNT, ur).descriptors
    assert.ok(descriptor)
    const theirs = CryptoAccount.fromCBOR(
      Buffer.from(
        encodeCbor(
          writeMap([
            [1, fingerprint],
            [2, [CRYPTO_OUTPUT.toCbor(descriptor)]],
          ])
        )
      )
    )
    assert.equal(
      theirs.getOutputDescriptors()[0]?.toString(),
      `wpkh(${hex.encode(Uint8Array.of(fingerprint >>> 24, fingerprint >>> 16, fingerprint >>> 8, fingerprint))}/84'/1'/0'${reference.publicExtendedKey})`
    )

    const imported = airgap.decodeAccount(decodeUR(encodeUR(ur), {allowedTypes: ['crypto-account']}))
    const [account] = imported.accounts
    assert.ok(account)
    assert.equal(account.address, (await wallet.deriveAccount({chain: 'bitcoin'})).address)
    assert.equal(account.path, "m/84'/1'/0'/0/0")
    const key = imported.descriptors[0]?.keys[0]
    assert.ok(key && 'hdkey' in key)
    assert.deepEqual(key.hdkey.chainCode, reference.chainCode)
    assert.equal(key.hdkey.parentFingerprint, reference.parentFingerprint)

    // Any receiving address, from the account key alone.
    assert.equal(
      airgap.watchAccount(key.hdkey, fingerprint, 7).address,
      (await wallet.deriveAccount({chain: 'bitcoin', index: 7})).address
    )
  })

  test('a coordinator`s PSBT spending three addresses of the account, with change to a fourth, signs key by key', async () => {
    const coins = [
      {change: 0, index: 0, value: 40_000n},
      {change: 0, index: 3, value: 25_000n},
      {change: 1, index: 0, value: 15_000n},
    ] as const
    const theirs = new Transaction({lockTime: 0, version: 2})

    for (const [position, coin] of coins.entries()) {
      const owner = await wallet.deriveAccount({chain: 'bitcoin', change: coin.change, index: coin.index})
      theirs.addInput({
        bip32Derivation: [
          [owner.publicKey, {fingerprint, path: [0x80000054, 0x80000001, 0x80000000, coin.change, coin.index]}],
        ],
        index: position,
        sequence: 0xfffffffd,
        txid: (position + 10).toString(16).repeat(64),
        witnessUtxo: {amount: coin.value, script: owner.scriptPubKey},
      })
    }

    const change = await wallet.deriveAccount({chain: 'bitcoin', change: 1, index: 1})
    theirs.addOutput({
      amount: 60_000n,
      script: crypto.chains.bitcoin.validateAddress(recipient).valid
        ? (crypto.chains.bitcoin.validateAddress(recipient) as {scriptPubKey: Uint8Array}).scriptPubKey
        : new Uint8Array(),
    })
    theirs.addOutput({
      amount: 19_000n,
      bip32Derivation: [[change.publicKey, {fingerprint, path: [0x80000054, 0x80000001, 0x80000000, 1, 1]}]],
      script: change.scriptPubKey,
    })
    const psbt = theirs.toPSBT()

    const review = airgap.decodeSignRequest(toUR(CRYPTO_PSBT, psbt), {accountPath, fingerprint})
    assert.deepEqual(
      review.keys.map(key => key.path),
      ["m/84'/1'/0'/0/0", "m/84'/1'/0'/0/3", "m/84'/1'/0'/1/0"]
    )
    assert.deepEqual(
      review.outputs.map(output => output.change),
      [false, true]
    )
    assert.equal(review.spending, 80_000n)
    assert.equal(review.sending, 60_000n)
    assert.equal(review.fee, 1_000n)

    const {psbt: signed} = await airgap.signRequest(review, path => wallet.deriveAccount({chain: 'bitcoin', path}))
    const transaction = crypto.chains.bitcoin.finalizePsbt(signed)
    const reference = Transaction.fromPSBT(signed)
    reference.finalize()
    assert.equal(transaction.hex, hex.encode(reference.extract()))

    // Another wallet's request, or a key named under this fingerprint that does not pay its coin, is not this signer's.
    throwsCode(
      () => airgap.decodeSignRequest(toUR(CRYPTO_PSBT, psbt), {accountPath, fingerprint: 0x01020304}),
      'REQUEST_MISMATCH'
    )
    const lying = Transaction.fromPSBT(psbt)
    const stranger = await wallet.deriveAccount({account: 5, chain: 'bitcoin'})
    for (let index = 0; index < lying.inputsLength; index++) {
      lying.updateInput(
        index,
        {bip32Derivation: [[stranger.publicKey, {fingerprint, path: [0x80000054, 0x80000001, 0x80000000, 0, index]}]]},
        true
      )
    }
    throwsCode(
      () => airgap.decodeSignRequest(toUR(CRYPTO_PSBT, lying.toPSBT()), {accountPath, fingerprint}),
      'REQUEST_MISMATCH'
    )
  })
})

describe('Keystone`s firmware codec (keystone-sdk-rust)', () => {
  const KEYSTONE = JSON.parse(readFileSync(new URL('./vectors/keystone.json', import.meta.url), 'utf8'))

  test('crypto-account with single keys and a multisig, written without the 308 tag and read with it', () => {
    const written = fromUR(CRYPTO_ACCOUNT, {cbor: hex.decode(KEYSTONE.encoded), type: 'crypto-account'})
    const read = fromUR(CRYPTO_ACCOUNT, decodeUR(KEYSTONE.decodedUr, {allowedTypes: ['crypto-account']}))
    assert.equal(
      hex.encode(decodeUR(KEYSTONE.decodedUr, {allowedTypes: ['crypto-account']}).cbor),
      KEYSTONE.decodedCbor
    )
    assert.deepEqual(read, written)
    assert.equal(read.masterFingerprint, 0x78230804)
    assert.deepEqual(
      read.descriptors.map(descriptor => [descriptor.scripts.join('('), descriptor.keys.length, descriptor.threshold]),
      [
        ['pkh', 1, undefined],
        ['sh(wpkh', 1, undefined],
        ['sh(multi', 2, 2],
      ]
    )
    // Written the specification's way, each descriptor inside 308, it is the bytes Keystone's decode test reads.
    assert.equal(hex.encode(toUR(CRYPTO_ACCOUNT, read).cbor), KEYSTONE.decodedCbor)
  })
})
