import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {after, describe, test} from 'node:test'

import {
  CRYPTO_HDKEY,
  CRYPTO_MULTI_ACCOUNTS,
  createMultipartDecoder,
  createMultipartEncoder,
  createRequestId,
  decodeUR,
  encodeUR,
  formatKeypath,
  fromUR,
  isAirgapError,
  parseKeypath,
  toUR,
} from '@hzblj/crypto-airgap'
import {type EthereumTransactionRequest, ethereumAdapter} from '@hzblj/crypto-ethereum'
import {hex} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {CryptoHDKey, DataType, ETHSignature, EthSignRequest} from '@keystonehq/bc-ur-registry-eth'
import {recoverTransactionAddress, type TransactionSerializedEIP1559, verifyMessage} from 'viem'
import {HDKey, mnemonicToAccount} from 'viem/accounts'

import {ETH_SIGN_REQUEST, ETH_SIGNATURE, type EthereumAirgapRequest, ethereumAirgap, VERSION} from '../src'

const HARDHAT = 'test test test test test test test test test test test junk'
const SEPOLIA = 11_155_111

const crypto = createTestCryptoEngine({adapters: [ethereumAdapter({chainId: SEPOLIA, name: 'Sepolia'})]})
const chain = crypto.chains.ethereum
const airgap = ethereumAirgap(chain)

const throwsCode = (run: () => unknown, code: Parameters<typeof isAirgapError>[1]) =>
  assert.throws(run, error => isAirgapError(error, code))

/** Fixed "random" bytes, so request ids are the same on every run. */
const counter = (start: number) => {
  let next = start

  return (length: number) => Uint8Array.from({length}, () => next++ & 0xff)
}

/** What the camera sees: a multipart message, read by a decoder that loses one part in three. */
const transmit = (encoder: ReturnType<typeof createMultipartEncoder>, allowedTypes: readonly string[]) => {
  const decoder = createMultipartDecoder({allowedTypes, sha256: crypto.hash.sha256})
  let count = 0

  while (!decoder.isComplete()) {
    const part = encoder.nextPart()

    if (count++ % 3 !== 1) {
      decoder.receivePart(part)
    }
  }

  return decoder.result()
}

const transfer: EthereumTransactionRequest = {
  gas: 21_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 1_500_000_000n,
  nonce: 7,
  to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  value: 12_345_678_900_000_000n,
}

describe('ERC-4527 against Keystone`s registry', () => {
  const unsigned = hex.decode(chain.serializeTransaction(transfer))
  const requestId = '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'

  test('eth-sign-request: the same CBOR as Keystone writes, both ways', () => {
    const theirs = EthSignRequest.constructETHRequest(
      Buffer.from(unsigned),
      DataType.typedTransaction,
      "m/44'/60'/0'/0/0",
      '73c5da0a',
      requestId,
      SEPOLIA,
      '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      'Nitro Wallet'
    )
    const ours = toUR(ETH_SIGN_REQUEST, {
      address: hex.decode('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'),
      chainId: SEPOLIA,
      dataType: 'typed-transaction',
      derivationPath: parseKeypath("m/44'/60'/0'/0/0", 0x73c5da0a),
      origin: 'Nitro Wallet',
      requestId,
      signData: unsigned,
    })

    assert.equal(hex.encode(ours.cbor), theirs.toCBOR().toString('hex'))
    assert.equal(encodeUR(ours), theirs.toUREncoder(1000).nextPart())

    const read = EthSignRequest.fromCBOR(Buffer.from(ours.cbor))
    assert.equal(read.getDerivationPath(), "44'/60'/0'/0/0")
    assert.equal(read.getChainId(), SEPOLIA)
    assert.equal(read.getDataType(), DataType.typedTransaction)
  })

  test('eth-signature: the same CBOR, both ways', () => {
    const signature = Uint8Array.from({length: 65}, (_, index) => index)
    const theirs = new ETHSignature(
      Buffer.from(signature),
      Buffer.from(requestId.replaceAll('-', ''), 'hex'),
      'Keystone'
    )
    const ours = toUR(ETH_SIGNATURE, {origin: 'Keystone', requestId, signature})
    assert.equal(hex.encode(ours.cbor), theirs.toCBOR().toString('hex'))
    assert.deepEqual(fromUR(ETH_SIGNATURE, {cbor: theirs.toCBOR(), type: 'eth-signature'}), {
      origin: 'Keystone',
      requestId,
      signature,
    })
  })

  test('a request Keystone writes without optional fields still reads, chain id 1 by default', () => {
    const theirs = EthSignRequest.constructETHRequest(
      Buffer.from('hello'),
      DataType.personalMessage,
      "m/44'/60'/0'/0/0",
      '73c5da0a'
    )
    const read = fromUR(ETH_SIGN_REQUEST, {cbor: theirs.toCBOR(), type: 'eth-sign-request'})
    assert.equal(read.chainId, undefined)
    assert.equal(read.requestId, undefined)
    assert.equal(read.dataType, 'personal-message')
  })
})

describe('air-gapped signing, both sides', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
  const signer = await wallet.deriveAccount({chain: 'ethereum', index: 0})
  const other = await wallet.deriveAccount({chain: 'ethereum', index: 1})
  after(() => wallet.dispose())

  /** The online wallet's view of the signer: from the key it shared when pairing. */
  const pair = () => {
    const shared = toUR(CRYPTO_MULTI_ACCOUNTS, {
      device: 'Nitro Wallet',
      keys: [airgap.pairingKey(signer, wallet.fingerprint)],
      masterFingerprint: wallet.fingerprint,
    })
    const [key] = fromUR(CRYPTO_MULTI_ACCOUNTS, shared).keys
    assert.ok(key)

    return airgap.watchAccount(key)
  }

  const context = {account: {address: signer.address, fingerprint: wallet.fingerprint, path: signer.path}}

  test('pairing gives the signer`s address and path', () => {
    assert.deepEqual(pair(), context.account)
  })

  test('a transaction goes out, comes back signed by the account asked, and is ready to broadcast', async () => {
    const request: EthereumAirgapRequest = {
      account: pair(),
      origin: 'Nitro Wallet',
      requestId: createRequestId(counter(1)),
      transaction: transfer,
    }
    const scanned = transmit(
      createMultipartEncoder(airgap.encodeSignRequest(request), {maxFragmentLength: 40, sha256: crypto.hash.sha256}),
      airgap.requestTypes
    )
    const review = airgap.decodeSignRequest(scanned, context)

    assert.equal(review.kind, 'transaction')
    assert.ok(review.kind === 'transaction')
    assert.equal(review.transaction.to, transfer.to)
    assert.equal(review.transaction.value, transfer.value)
    assert.equal(review.transaction.chainId, SEPOLIA)
    assert.equal(review.maxFee, 21_000n * 30_000_000_000n)
    assert.equal(review.origin, 'Nitro Wallet')

    const signed = await signer.signTransaction(review.transaction)
    const response = airgap.encodeSignResponse({requestId: review.requestId, signature: signed.signature})
    const answer = airgap.decodeSignResponse(
      transmit(
        createMultipartEncoder(response, {maxFragmentLength: 30, sha256: crypto.hash.sha256}),
        airgap.responseTypes
      ),
      {request}
    )

    assert.ok(answer.kind === 'transaction')
    assert.deepEqual(answer.transaction, signed)
    assert.equal(
      await recoverTransactionAddress({
        serializedTransaction: answer.transaction.serialized as TransactionSerializedEIP1559,
      }),
      signer.address
    )
  })

  test('a message goes out and comes back with a signature viem verifies', async () => {
    const request: EthereumAirgapRequest = {
      account: pair(),
      message: 'Sign in to Nitro Wallet',
      requestId: createRequestId(counter(40)),
    }
    const review = airgap.decodeSignRequest(airgap.encodeSignRequest(request), context)
    assert.ok(review.kind === 'message')
    assert.equal(review.text, 'Sign in to Nitro Wallet')

    const signature = await signer.signMessage({message: review.message})
    const answer = airgap.decodeSignResponse(airgap.encodeSignResponse({requestId: review.requestId, signature}), {
      request,
    })
    assert.ok(answer.kind === 'message')
    assert.equal(
      await verifyMessage({address: signer.address, message: 'Sign in to Nitro Wallet', signature: answer.signature}),
      true
    )

    // A message that is not text is shown as bytes only.
    const binary = airgap.decodeSignRequest(
      airgap.encodeSignRequest({...request, message: Uint8Array.of(0, 1, 2, 255)}),
      context
    )
    assert.ok(binary.kind === 'message' && binary.text === undefined)
  })

  test('ERC-20 transfers are recognized for the signer to show', async () => {
    const data = chain.erc20.transferData(other.address, 2_500_000n)
    const request: EthereumAirgapRequest = {
      account: pair(),
      requestId: createRequestId(counter(80)),
      transaction: {...transfer, data, to: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238', value: 0n},
    }
    const review = airgap.decodeSignRequest(airgap.encodeSignRequest(request), context)
    assert.ok(review.kind === 'transaction')
    assert.deepEqual(review.erc20Transfer, {amount: 2_500_000n, recipient: other.address})
  })

  test('answers to another request, by another key, or of another transaction are REQUEST_MISMATCH', async () => {
    const request: EthereumAirgapRequest = {
      account: pair(),
      requestId: createRequestId(counter(120)),
      transaction: transfer,
    }
    const signed = await signer.signTransaction(transfer)

    throwsCode(
      () =>
        airgap.decodeSignResponse(
          airgap.encodeSignResponse({requestId: createRequestId(counter(7)), signature: signed.signature}),
          {request}
        ),
      'REQUEST_MISMATCH'
    )
    throwsCode(
      () => airgap.decodeSignResponse(airgap.encodeSignResponse({signature: signed.signature}), {request}),
      'REQUEST_MISMATCH'
    )

    const byOther = await other.signTransaction(transfer)
    throwsCode(
      () =>
        airgap.decodeSignResponse(
          airgap.encodeSignResponse({requestId: request.requestId, signature: byOther.signature}),
          {request}
        ),
      'REQUEST_MISMATCH'
    )

    const ofAnother = await signer.signTransaction({...transfer, value: 1n})
    throwsCode(
      () =>
        airgap.decodeSignResponse(
          airgap.encodeSignResponse({requestId: request.requestId, signature: ofAnother.signature}),
          {request}
        ),
      'REQUEST_MISMATCH'
    )

    const message: EthereumAirgapRequest = {account: pair(), message: 'hello', requestId: request.requestId}
    const wrongSigner = await other.signMessage({message: 'hello'})
    throwsCode(
      () =>
        airgap.decodeSignResponse(airgap.encodeSignResponse({requestId: request.requestId, signature: wrongSigner}), {
          request: message,
        }),
      'REQUEST_MISMATCH'
    )
  })

  test('a signer refuses requests for another key, wallet, address or chain, and what it cannot sign', () => {
    const request: EthereumAirgapRequest = {
      account: pair(),
      requestId: createRequestId(counter(160)),
      transaction: transfer,
    }
    const ur = airgap.encodeSignRequest(request)

    throwsCode(
      () => airgap.decodeSignRequest(ur, {account: {...context.account, path: other.path}}),
      'REQUEST_MISMATCH'
    )
    throwsCode(() => airgap.decodeSignRequest(ur, {account: {...context.account, fingerprint: 1}}), 'REQUEST_MISMATCH')
    throwsCode(
      () => airgap.decodeSignRequest(ur, {account: {...context.account, address: other.address}}),
      'REQUEST_MISMATCH'
    )

    const mainnet = ethereumAirgap(createTestCryptoEngine({adapters: [ethereumAdapter()]}).chains.ethereum)
    throwsCode(() => mainnet.decodeSignRequest(ur, context), 'REQUEST_MISMATCH')

    const typedData = toUR(ETH_SIGN_REQUEST, {
      chainId: SEPOLIA,
      dataType: 'typed-data',
      derivationPath: parseKeypath(signer.path, wallet.fingerprint),
      signData: new TextEncoder().encode('{"types":{}}'),
    })
    throwsCode(() => airgap.decodeSignRequest(typedData, context), 'INVALID_PROTOCOL_DATA')

    const legacy = toUR(ETH_SIGN_REQUEST, {
      chainId: SEPOLIA,
      dataType: 'typed-transaction',
      derivationPath: parseKeypath(signer.path, wallet.fingerprint),
      signData: Uint8Array.of(0x01, 0xc0),
    })
    throwsCode(() => airgap.decodeSignRequest(legacy, context), 'INVALID_PROTOCOL_DATA')

    const garbage = toUR(ETH_SIGN_REQUEST, {
      chainId: SEPOLIA,
      dataType: 'typed-transaction',
      derivationPath: parseKeypath(signer.path, wallet.fingerprint),
      signData: Uint8Array.of(0x02, 0xc3, 0x81, 0x05, 0x01),
    })
    throwsCode(() => airgap.decodeSignRequest(garbage, context), 'INVALID_PROTOCOL_DATA')
  })

  test('a request Keystone`s registry writes is read and answered here', async () => {
    const theirs = EthSignRequest.constructETHRequest(
      Buffer.from(hex.decode(chain.serializeTransaction(transfer))),
      DataType.typedTransaction,
      signer.path,
      wallet.fingerprint.toString(16).padStart(8, '0'),
      '0b2a8d8e-5e2c-4f8e-9d0e-6f3c1a2b3c4d',
      SEPOLIA
    )
    const review = airgap.decodeSignRequest({cbor: theirs.toCBOR(), type: 'eth-sign-request'}, context)
    assert.ok(review.kind === 'transaction')
    const signed = await signer.signTransaction(review.transaction)
    const response = ETHSignature.fromCBOR(
      Buffer.from(airgap.encodeSignResponse({requestId: review.requestId, signature: signed.signature}).cbor)
    )
    assert.equal(response.getRequestId()?.toString('hex'), '0b2a8d8e5e2c4f8e9d0e6f3c1a2b3c4d')
    assert.equal(response.getSignature().readUInt8(64), signed.signature.recovery)
  })

  test('keys of other chains, or not at full paths, are not Ethereum accounts', () => {
    const key = airgap.pairingKey(signer, wallet.fingerprint)
    throwsCode(
      () => airgap.watchAccount({...key, origin: parseKeypath("m/44'/501'/0'/0'", wallet.fingerprint)}),
      'REQUEST_MISMATCH'
    )
    throwsCode(
      () => airgap.watchAccount({...key, origin: parseKeypath("m/44'/60'/0'", wallet.fingerprint)}),
      'INVALID_PROTOCOL_DATA'
    )
    throwsCode(() => airgap.watchAccount({keyData: key.keyData}), 'INVALID_PROTOCOL_DATA')
  })

  test('VERSION matches package.json', () => {
    const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
    assert.equal(VERSION, manifest.version)
  })
})

describe('account keys: pairing as MetaMask and other watch-only wallets do', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
  const accountPath = "m/44'/60'/0'"
  const fingerprint = wallet.fingerprint
  const signerContext = {accountPath, fingerprint}
  after(() => wallet.dispose())

  const shared = () =>
    airgap.accountKey({
      extendedKey: wallet.extendedPublicKey(accountPath),
      fingerprint,
      name: 'Nitro Wallet',
      path: accountPath,
    })

  test('crypto-hdkey as Keystone and OneKey write it, read by Keystone`s registry as MetaMask`s keyring reads it', () => {
    const ur = toUR(CRYPTO_HDKEY, shared())
    const theirs = CryptoHDKey.fromCBOR(Buffer.from(ur.cbor))

    assert.equal(theirs.getBip32Key(), mnemonicToAccount(HARDHAT, {path: accountPath}).getHdKey().publicExtendedKey)
    assert.equal(theirs.getOrigin()?.getPath(), "44'/60'/0'")
    assert.equal(theirs.getOrigin()?.getSourceFingerprint()?.readUInt32BE(0), fingerprint)
    assert.equal(theirs.getChildren()?.getPath(), '0/*')
    assert.equal(theirs.getNote(), 'account.standard')
    assert.equal(theirs.getName(), 'Nitro Wallet')
  })

  test('any address of the account, from its extended key alone', async () => {
    const key = fromUR(CRYPTO_HDKEY, toUR(CRYPTO_HDKEY, shared()))

    for (const index of [0, 1, 19]) {
      const expected = await wallet.deriveAccount({chain: 'ethereum', index})
      assert.deepEqual(airgap.watchAccount(key, undefined, index), {
        address: expected.address,
        fingerprint,
        path: expected.path,
      })
    }

    // Ledger's legacy layout names its children `*`: addresses directly below the account.
    const legacy = airgap.watchAccount(
      {...key, children: {components: [{hardened: false, wildcard: true}]}},
      undefined,
      4
    )
    assert.equal(legacy.path, "m/44'/60'/0'/4")
    assert.equal(legacy.address, (await wallet.deriveAccount({chain: 'ethereum', path: "m/44'/60'/0'/4"})).address)

    // Hardened children cannot be derived from a public key.
    throwsCode(
      () =>
        airgap.watchAccount({
          ...key,
          children: {
            components: [
              {hardened: true, index: 0},
              {hardened: false, wildcard: true},
            ],
          },
        }),
      'INVALID_PROTOCOL_DATA'
    )
  })

  test('a transaction for the account`s fourth address, signed by the key the signer derives for it', async () => {
    const account = airgap.watchAccount(fromUR(CRYPTO_HDKEY, toUR(CRYPTO_HDKEY, shared())), undefined, 3)
    const request: EthereumAirgapRequest = {account, requestId: createRequestId(counter(200)), transaction: transfer}
    const review = airgap.decodeSignRequest(airgap.encodeSignRequest(request), signerContext)

    assert.equal(review.path, "m/44'/60'/0'/0/3")
    assert.equal(review.address, account.address)

    const signature = await airgap.signRequest(review, path => wallet.deriveAccount({chain: 'ethereum', path}))
    const answer = airgap.decodeSignResponse(airgap.encodeSignResponse(signature), {request})
    assert.ok(answer.kind === 'transaction')
    assert.equal(
      await recoverTransactionAddress({
        serializedTransaction: answer.transaction.serialized as TransactionSerializedEIP1559,
      }),
      account.address
    )

    const message = {account, message: 'Sign in', requestId: createRequestId(counter(220))}
    const messageReview = airgap.decodeSignRequest(airgap.encodeSignRequest(message), signerContext)
    const signed = await airgap.signRequest(messageReview, path => wallet.deriveAccount({chain: 'ethereum', path}))
    const verified = airgap.decodeSignResponse(airgap.encodeSignResponse(signed), {request: message})
    assert.ok(verified.kind === 'message')
    assert.ok(await verifyMessage({address: account.address, message: 'Sign in', signature: verified.signature}))
  })

  test('the signer refuses keys outside the account, of another wallet, and addresses it does not have', async () => {
    const elsewhere = async (path: string) => {
      const owner = await wallet.deriveAccount({chain: 'ethereum', path})

      return airgap.encodeSignRequest({
        account: {address: owner.address, fingerprint, path},
        requestId: createRequestId(counter(240)),
        transaction: transfer,
      })
    }

    for (const path of ["m/44'/60'/1'/0/0", "m/44'/60'/0'/1/0", "m/44'/60'/0'/0/0'", "m/44'/60'/0'/0"]) {
      const ur = await elsewhere(path)
      throwsCode(() => airgap.decodeSignRequest(ur, signerContext), 'REQUEST_MISMATCH')
    }

    const ur = await elsewhere("m/44'/60'/0'/0/2")
    throwsCode(() => airgap.decodeSignRequest(ur, {accountPath, fingerprint: 0x01020304}), 'REQUEST_MISMATCH')

    // A request that names an address other than its path's is shown with it, and refused when the key is derived.
    const other = await wallet.deriveAccount({chain: 'ethereum', index: 5})
    const lying = airgap.encodeSignRequest({
      account: {address: other.address, fingerprint, path: "m/44'/60'/0'/0/2"},
      requestId: createRequestId(counter(260)),
      transaction: transfer,
    })
    const review = airgap.decodeSignRequest(lying, signerContext)
    assert.equal(review.address, other.address)
    await assert.rejects(
      airgap.signRequest(review, path => wallet.deriveAccount({chain: 'ethereum', path})),
      error => isAirgapError(error, 'REQUEST_MISMATCH')
    )
  })
})

describe('hardware wallets: what they share and send', () => {
  const HARDWARE = JSON.parse(readFileSync(new URL('./vectors/hardware.json', import.meta.url), 'utf8'))
  const mainnet = ethereumAirgap(createTestCryptoEngine({adapters: [ethereumAdapter()]}).chains.ethereum)

  /** The address @scure/bip32 (through viem) derives from a key at `m/0/index` below it. */
  const reference = (xpub: string, index: number) =>
    chain.addressFromPublicKey(
      HDKey.fromExtendedKey(xpub).deriveChild(0).deriveChild(index).publicKey ?? new Uint8Array()
    )

  const xpubOf = (key: {keyData: Uint8Array; chainCode?: Uint8Array; parentFingerprint?: number}) =>
    new HDKey({
      chainCode: key.chainCode,
      depth: 3,
      index: 0x80000000,
      parentFingerprint: key.parentFingerprint,
      publicKey: key.keyData,
    }).publicExtendedKey

  test('a Keystone`s crypto-hdkey for MetaMask: the xpub its documentation shows, and its addresses', () => {
    const key = fromUR(CRYPTO_HDKEY, decodeUR(HARDWARE.keystoneHub.hdkey, {allowedTypes: ['crypto-hdkey']}))

    assert.equal(xpubOf(key), HARDWARE.keystoneHub.xpub)
    assert.equal(key.name, 'Keystone')
    assert.equal(key.note, 'account.standard')
    for (const index of [0, 1, 7]) {
      const account = mainnet.watchAccount(key, undefined, index)
      assert.equal(account.address, reference(HARDWARE.keystoneHub.xpub, index))
      assert.equal(account.path, `m/44'/60'/0'/0/${index}`)
      assert.equal(account.fingerprint, 0xfdd358f4)
    }
  })

  test('a OneKey`s EVM account, the same way', () => {
    const key = fromUR(CRYPTO_HDKEY, decodeUR(HARDWARE.onekey.hdkey, {allowedTypes: ['crypto-hdkey']}))
    assert.equal(key.name, 'OneKey')
    assert.equal(mainnet.watchAccount(key, undefined, 2).address, reference(xpubOf(key), 2))
  })

  test('a Keystone 3 Pro`s crypto-multi-accounts (its firmware`s codec): the Ethereum account key, and not the Solana one', () => {
    const accounts = fromUR(
      CRYPTO_MULTI_ACCOUNTS,
      decodeUR(HARDWARE.keystoneMultiAccounts.ur, {allowedTypes: ['crypto-multi-accounts']})
    )
    const [ethereum, solana] = accounts.keys
    assert.ok(ethereum && solana)
    assert.equal(accounts.device, 'Keystone 3 Pro')
    assert.equal(hex.encode(ethereum.keyData), HARDWARE.keystoneMultiAccounts.key)
    assert.equal(hex.encode(ethereum.chainCode ?? new Uint8Array()), HARDWARE.keystoneMultiAccounts.chainCode)

    const account = mainnet.watchAccount(ethereum, accounts.masterFingerprint)
    assert.equal(account.fingerprint, accounts.masterFingerprint)
    assert.equal(account.address, reference(xpubOf(ethereum), 0))
    throwsCode(() => mainnet.watchAccount(solana, accounts.masterFingerprint), 'INVALID_PROTOCOL_DATA')
  })

  test('Keystone`s firmware codec: eth-sign-request and eth-signature, byte for byte', () => {
    const legacy = fromUR(ETH_SIGN_REQUEST, {
      cbor: hex.decode(HARDWARE.keystoneFirmware.legacyRequest),
      type: 'eth-sign-request',
    })
    assert.equal(legacy.dataType, 'legacy-transaction')
    assert.equal(legacy.origin, 'metamask')
    assert.equal(hex.encode(toUR(ETH_SIGN_REQUEST, legacy).cbor), HARDWARE.keystoneFirmware.legacyRequest)
    // Legacy transactions are not signed here, as the Ethereum adapter does not sign them.
    throwsCode(
      () =>
        mainnet.decodeSignRequest(toUR(ETH_SIGN_REQUEST, legacy), {
          accountPath: "m/44'/1'/1'",
          fingerprint: 0x12345678,
        }),
      'INVALID_PROTOCOL_DATA'
    )

    const fuji = fromUR(
      ETH_SIGN_REQUEST,
      decodeUR(HARDWARE.keystoneFirmware.fujiRequest, {allowedTypes: ['eth-sign-request']})
    )
    assert.equal(fuji.chainId, 43_113)
    assert.equal(fuji.origin, 'core wallet')
    assert.equal(formatKeypath(fuji.derivationPath), "m/44'/60'/0'/0/6")
    assert.equal(fuji.derivationPath.sourceFingerprint, 0xbdeee782)
    assert.equal(encodeUR(toUR(ETH_SIGN_REQUEST, fuji)), HARDWARE.keystoneFirmware.fujiRequest)

    const signature = fromUR(ETH_SIGNATURE, {
      cbor: hex.decode(HARDWARE.keystoneFirmware.signature),
      type: 'eth-signature',
    })
    assert.equal(signature.requestId, '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    assert.equal(signature.origin, 'keystone')
    assert.equal(hex.encode(toUR(ETH_SIGNATURE, signature).cbor), HARDWARE.keystoneFirmware.signature)

    const hub = fromUR(ETH_SIGNATURE, decodeUR(HARDWARE.keystoneHub.signature, {allowedTypes: ['eth-signature']}))
    assert.equal(hub.signature.length, 65)
    assert.equal(encodeUR(toUR(ETH_SIGNATURE, hub)), HARDWARE.keystoneHub.signature)
  })
})
