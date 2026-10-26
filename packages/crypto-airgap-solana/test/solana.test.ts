import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {after, describe, test} from 'node:test'

import {
  CRYPTO_MULTI_ACCOUNTS,
  createMultipartDecoder,
  createMultipartEncoder,
  createRequestId,
  decodeUR,
  encodeUR,
  fromUR,
  isAirgapError,
  parseKeypath,
  toUR,
} from '@hzblj/crypto-airgap'
import {solanaAdapter} from '@hzblj/crypto-solana'
import {base58, hex} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {SignType, SolSignature, SolSignRequest} from '@keystonehq/bc-ur-registry-sol'

import {SOL_SIGN_REQUEST, SOL_SIGNATURE, type SolanaAirgapRequest, solanaAirgap, VERSION} from '../src'

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N'

const crypto = createTestCryptoEngine({adapters: [solanaAdapter({cluster: 'devnet'})]})
const chain = crypto.chains.solana
const airgap = solanaAirgap(chain)

const throwsCode = (run: () => unknown, code: Parameters<typeof isAirgapError>[1]) =>
  assert.throws(run, error => isAirgapError(error, code))

const counter = (start: number) => {
  let next = start

  return (length: number) => Uint8Array.from({length}, () => next++ & 0xff)
}

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

describe('sol-sign-request and sol-signature against Keystone`s registry', () => {
  const requestId = '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'

  test('the same CBOR both ways, for a transaction and a message', () => {
    for (const [signType, theirsType] of [
      ['transaction', SignType.Transaction],
      ['message', SignType.Message],
    ] as const) {
      const data = Uint8Array.from({length: 150}, (_, index) => index)
      const theirs = SolSignRequest.constructSOLRequest(
        Buffer.from(data),
        "m/44'/501'/0'/0'",
        '73c5da0a',
        theirsType,
        requestId,
        undefined,
        'Nitro Wallet'
      )
      const ours = toUR(SOL_SIGN_REQUEST, {
        derivationPath: parseKeypath("m/44'/501'/0'/0'", 0x73c5da0a),
        origin: 'Nitro Wallet',
        requestId,
        signData: data,
        signType,
      })

      assert.equal(hex.encode(ours.cbor), theirs.toCBOR().toString('hex'))
      assert.equal(encodeUR(ours), theirs.toUREncoder(1000).nextPart())
      assert.equal(SolSignRequest.fromCBOR(Buffer.from(ours.cbor)).getDerivationPath(), "44'/501'/0'/0'")
    }

    const signature = Uint8Array.from({length: 64}, (_, index) => 255 - index)
    const theirs = new SolSignature(Buffer.from(signature), Buffer.from(requestId.replaceAll('-', ''), 'hex'))
    assert.equal(hex.encode(toUR(SOL_SIGNATURE, {requestId, signature}).cbor), theirs.toCBOR().toString('hex'))
    assert.deepEqual(fromUR(SOL_SIGNATURE, {cbor: theirs.toCBOR(), type: 'sol-signature'}), {requestId, signature})
  })
})

describe('air-gapped signing, both sides', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
  const signer = await wallet.deriveAccount({chain: 'solana'})
  const other = await wallet.deriveAccount({account: 1, chain: 'solana'})
  after(() => wallet.dispose())

  const pair = () => {
    const shared = toUR(CRYPTO_MULTI_ACCOUNTS, {
      keys: [airgap.pairingKey(signer, wallet.fingerprint)],
      masterFingerprint: wallet.fingerprint,
    })
    const [key] = fromUR(CRYPTO_MULTI_ACCOUNTS, shared).keys
    assert.ok(key)

    return airgap.watchAccount(key)
  }

  const context = {account: {address: signer.address, fingerprint: wallet.fingerprint, path: signer.path}}

  const sendRequest = (requestId = createRequestId(counter(1))): SolanaAirgapRequest => ({
    account: pair(),
    origin: 'Nitro Wallet',
    requestId,
    transaction: {
      instructions: [chain.instructions.transfer({from: signer.address, lamports: 250_000_000n, to: other.address})],
      recentBlockhash: BLOCKHASH,
    },
  })

  test('pairing gives the signer`s address and path', () => {
    assert.deepEqual(pair(), context.account)
  })

  test('a transfer goes out, comes back signed, and is the transaction the signer would have made itself', async () => {
    const request = sendRequest()
    const review = airgap.decodeSignRequest(
      transmit(
        createMultipartEncoder(airgap.encodeSignRequest(request), {maxFragmentLength: 50, sha256: crypto.hash.sha256}),
        airgap.requestTypes
      ),
      context
    )

    assert.ok(review.kind === 'transaction')
    assert.equal(review.lamports, 250_000_000n)
    assert.deepEqual(review.warnings, [])
    assert.equal(review.decoded.feePayer, signer.address)
    assert.deepEqual(review.decoded.instructions[0]?.summary, {
      from: signer.address,
      lamports: 250_000_000n,
      to: other.address,
      type: 'transfer',
    })

    const signature = await signer.signTransactionMessage(review.message)
    const answer = airgap.decodeSignResponse(
      transmit(
        createMultipartEncoder(airgap.encodeSignResponse({requestId: review.requestId, signature}), {
          sha256: crypto.hash.sha256,
        }),
        airgap.responseTypes
      ),
      {request}
    )

    assert.ok(answer.kind === 'transaction')
    assert.deepEqual(
      answer.transaction,
      await signer.signTransaction({
        instructions: [chain.instructions.transfer({from: signer.address, lamports: 250_000_000n, to: other.address})],
        recentBlockhash: BLOCKHASH,
      })
    )
  })

  test('a message goes out and comes back verified', async () => {
    const request: SolanaAirgapRequest = {
      account: pair(),
      message: 'Sign in to Nitro Wallet',
      requestId: createRequestId(counter(30)),
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
      chain.verifyMessage({address: signer.address, message: 'Sign in to Nitro Wallet', signature: answer.signature}),
      true
    )
  })

  test('a transaction sent as a "message" is refused', () => {
    const message = chain.compileMessage({
      feePayer: signer.address,
      instructions: [chain.instructions.transfer({from: signer.address, lamports: 1n, to: other.address})],
      recentBlockhash: BLOCKHASH,
    })
    const disguised: SolanaAirgapRequest = {account: pair(), message, requestId: createRequestId(counter(60))}
    throwsCode(() => airgap.decodeSignRequest(airgap.encodeSignRequest(disguised), context), 'INVALID_PROTOCOL_DATA')
  })

  test('answers to another request, by another key, or of another transaction are REQUEST_MISMATCH', async () => {
    const request = sendRequest(createRequestId(counter(90)))
    const review = airgap.decodeSignRequest(airgap.encodeSignRequest(request), context)
    assert.ok(review.kind === 'transaction')
    const signature = await signer.signTransactionMessage(review.message)

    throwsCode(
      () =>
        airgap.decodeSignResponse(airgap.encodeSignResponse({requestId: createRequestId(counter(5)), signature}), {
          request,
        }),
      'REQUEST_MISMATCH'
    )
    throwsCode(() => airgap.decodeSignResponse(airgap.encodeSignResponse({signature}), {request}), 'REQUEST_MISMATCH')

    const byOther = await other.signMessage({message: review.message})
    throwsCode(
      () =>
        airgap.decodeSignResponse(airgap.encodeSignResponse({requestId: request.requestId, signature: byOther}), {
          request,
        }),
      'REQUEST_MISMATCH'
    )

    const ofAnother = await signer.signMessage({message: Uint8Array.of(...review.message, 0)})
    throwsCode(
      () =>
        airgap.decodeSignResponse(airgap.encodeSignResponse({requestId: request.requestId, signature: ofAnother}), {
          request,
        }),
      'REQUEST_MISMATCH'
    )
  })

  test('a signer refuses requests for another key, wallet or address, and transactions it does not sign', () => {
    const ur = airgap.encodeSignRequest(sendRequest(createRequestId(counter(120))))
    throwsCode(
      () => airgap.decodeSignRequest(ur, {account: {...context.account, path: other.path}}),
      'REQUEST_MISMATCH'
    )
    throwsCode(() => airgap.decodeSignRequest(ur, {account: {...context.account, fingerprint: 7}}), 'REQUEST_MISMATCH')
    throwsCode(
      () => airgap.decodeSignRequest(ur, {account: {...context.account, address: other.address}}),
      'REQUEST_MISMATCH'
    )

    const notSigner = toUR(SOL_SIGN_REQUEST, {
      derivationPath: parseKeypath(signer.path, wallet.fingerprint),
      signData: chain.compileMessage({
        feePayer: other.address,
        instructions: [chain.instructions.transfer({from: other.address, lamports: 1n, to: signer.address})],
        recentBlockhash: BLOCKHASH,
      }),
      signType: 'transaction',
    })
    throwsCode(() => airgap.decodeSignRequest(notSigner, context), 'REQUEST_MISMATCH')

    const versioned = toUR(SOL_SIGN_REQUEST, {
      derivationPath: parseKeypath(signer.path, wallet.fingerprint),
      signData: Uint8Array.of(0x80, 1, 0, 0),
      signType: 'transaction',
    })
    throwsCode(() => airgap.decodeSignRequest(versioned, context), 'INVALID_PROTOCOL_DATA')
  })

  test('unknown programs and other signers are said before signing', () => {
    const unknownProgram = base58.encode(new Uint8Array(32).fill(7))
    const ur = toUR(SOL_SIGN_REQUEST, {
      derivationPath: parseKeypath(signer.path, wallet.fingerprint),
      signData: chain.compileMessage({
        feePayer: other.address,
        instructions: [
          {
            accounts: [
              {address: signer.address, isSigner: true, isWritable: true},
              {address: other.address, isSigner: true, isWritable: true},
            ],
            data: Uint8Array.of(1, 2, 3),
            programId: unknownProgram,
          },
        ],
        recentBlockhash: BLOCKHASH,
      }),
      signType: 'transaction',
    })
    const review = airgap.decodeSignRequest(ur, context)
    assert.ok(review.kind === 'transaction')
    assert.deepEqual(review.warnings, ['UNKNOWN_INSTRUCTIONS', 'NOT_FEE_PAYER', 'OTHER_SIGNERS'])
  })

  test('keys of other chains, or not hardened, are not Solana accounts', () => {
    const key = airgap.pairingKey(signer, wallet.fingerprint)
    throwsCode(
      () => airgap.watchAccount({...key, origin: parseKeypath("m/44'/60'/0'/0/0", wallet.fingerprint)}),
      'REQUEST_MISMATCH'
    )
    throwsCode(
      () => airgap.watchAccount({...key, origin: parseKeypath("m/44'/501'/0'/0", wallet.fingerprint)}),
      'INVALID_PROTOCOL_DATA'
    )
    throwsCode(() => airgap.watchAccount({keyData: key.keyData}), 'INVALID_PROTOCOL_DATA')
  })

  test('VERSION matches package.json', () => {
    const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
    assert.equal(VERSION, manifest.version)
  })
})

describe('Keystone`s firmware codec (keystone-sdk-rust)', () => {
  const KEYSTONE = JSON.parse(readFileSync(new URL('./vectors/keystone.json', import.meta.url), 'utf8'))
  const mainnet = solanaAirgap(createTestCryptoEngine({adapters: [solanaAdapter()]}).chains.solana)

  test('crypto-multi-accounts: each Solana account Keystone shares is one to ask for signatures', () => {
    const shared = fromUR(
      CRYPTO_MULTI_ACCOUNTS,
      decodeUR(KEYSTONE.multiAccounts, {allowedTypes: ['crypto-multi-accounts']})
    )
    const accounts = shared.keys.map(key => mainnet.watchAccount(key, shared.masterFingerprint))

    assert.ok(accounts.length > 1)
    assert.deepEqual(
      accounts.map(account => account.path),
      accounts.map((_, index) => `m/44'/501'/${index}'/0'`)
    )
    for (const [index, account] of accounts.entries()) {
      assert.equal(account.address, base58.encode(shared.keys[index]?.keyData ?? new Uint8Array()))
      assert.equal(account.fingerprint, shared.masterFingerprint)
    }
  })

  test('sol-sign-request: a transfer of 0.1 SOL, read byte for byte and shown to its fee payer', () => {
    const cbor = hex.decode(KEYSTONE.signRequest)
    const request = fromUR(SOL_SIGN_REQUEST, {cbor, type: 'sol-sign-request'})
    assert.equal(hex.encode(toUR(SOL_SIGN_REQUEST, request).cbor), KEYSTONE.signRequest)
    assert.equal(request.origin, 'solflare')

    const payer = base58.encode(request.signData.subarray(4, 36))
    const review = mainnet.decodeSignRequest(
      {cbor, type: 'sol-sign-request'},
      {account: {address: payer, fingerprint: 0x12121212, path: "m/44'/501'/0'/0'"}}
    )
    assert.ok(review.kind === 'transaction')
    assert.equal(review.lamports, 100_000_000n)
    assert.deepEqual(review.warnings, [])
    assert.deepEqual(review.decoded.instructions[0]?.summary, {
      from: payer,
      lamports: 100_000_000n,
      to: base58.encode(request.signData.subarray(36, 68)),
      type: 'transfer',
    })
  })

  test('sol-signature, byte for byte', () => {
    const signature = fromUR(SOL_SIGNATURE, {cbor: hex.decode(KEYSTONE.signature), type: 'sol-signature'})
    assert.equal(signature.requestId, '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    assert.equal(signature.signature.length, 64)
    assert.equal(hex.encode(toUR(SOL_SIGNATURE, signature).cbor), KEYSTONE.signature)
  })
})
