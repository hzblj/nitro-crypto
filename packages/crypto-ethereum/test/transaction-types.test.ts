import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {
  getAddress,
  keccak256,
  parseTransaction,
  recoverTransactionAddress,
  serializeTransaction,
  type TransactionSerializable,
  type TransactionSerializedEIP1559,
  type TransactionSerializedGeneric,
  toRlp,
} from 'viem'
import {mnemonicToAccount} from 'viem/accounts'

import {
  type EthereumAccessList,
  type EthereumAuthorization,
  type EthereumTransactionRequest,
  ethereumAdapter,
  type Hex,
  type ParsedEthereumTransaction,
} from '../src'
import {HARDHAT, keySourceOf, type Random, random, rejectsCode, SEPOLIA, throwsCode, toHex} from './support'

const crypto = createTestCryptoEngine({
  adapters: [ethereumAdapter(), ethereumAdapter({chainId: SEPOLIA, id: 'sepolia', name: 'Sepolia'})],
})
const {ethereum, sepolia} = crypto.chains

const TYPES = ['legacy', 'eip2930', 'eip1559', 'eip7702'] as const

const randomAddress = (rng: Random) => {
  const raw = toHex(rng.bytes(20))

  return rng.int(2) === 0 ? raw : getAddress(raw)
}

const randomAccessList = (rng: Random): EthereumAccessList | undefined =>
  rng.int(4) === 0
    ? undefined
    : Array.from({length: rng.int(4)}, () => ({
        address: randomAddress(rng),
        storageKeys: Array.from({length: rng.int(4)}, () => toHex(rng.bytes(32))),
      }))

/** Authorizations as a sponsor collects them: signatures from accounts here, and arbitrary ones (r and s of any size). */
const randomAuthorizations = async (rng: Random, signers: readonly Signer[]): Promise<EthereumAuthorization[]> =>
  Promise.all(
    Array.from({length: 1 + rng.int(3)}, async () => {
      const address = randomAddress(rng)
      const nonce = rng.pick([0, 1, 255, 256, Number.MAX_SAFE_INTEGER, rng.int(2 ** 32)])
      const allChains = rng.int(4) === 0

      if (rng.int(2) === 0) {
        return rng
          .pick(signers)
          .signAuthorization({address, allowAllChains: allChains, chainId: allChains ? 0 : undefined, nonce})
      }

      const signature = rng.bytes(64)
      signature.fill(0, 0, rng.int(3) === 0 ? rng.int(32) : 0)

      return {address, chainId: allChains ? 0 : SEPOLIA, nonce, signature: {recovery: rng.int(2) as 0 | 1, signature}}
    })
  )

type Signer = Awaited<ReturnType<typeof sepolia.deriveAccount>>

const randomRequest = async (
  rng: Random,
  type: (typeof TYPES)[number],
  signers: readonly Signer[]
): Promise<EthereumTransactionRequest> => {
  const lengths = [0, 1, 4, 55, 56, 68, 300]
  const nonce = rng.pick([0, 1, 127, 128, 255, 256, 65535, Number.MAX_SAFE_INTEGER, rng.int(2 ** 32)])
  const create = type !== 'eip7702' && rng.int(5) === 0
  const data = create
    ? toHex(rng.bytes(1 + rng.int(200)))
    : rng.int(3) === 0
      ? undefined
      : toHex(rng.bytes(rng.pick(lengths)))
  const common = {
    data,
    gas: rng.uint(64),
    nonce: rng.int(2) === 0 ? nonce : BigInt(nonce),
    to: create ? null : randomAddress(rng),
    value: rng.uint(256),
  }
  const maxFeePerGas = rng.uint(256)
  const fees = {
    maxFeePerGas,
    maxPriorityFeePerGas: maxFeePerGas === 0n ? 0n : maxFeePerGas >> BigInt(rng.int(256)),
  }

  switch (type) {
    case 'legacy':
      return {...common, gasPrice: rng.uint(256), type}
    case 'eip2930':
      return {...common, accessList: randomAccessList(rng), gasPrice: rng.uint(256), type}
    case 'eip1559':
      return {...common, ...fees, accessList: randomAccessList(rng), ...(rng.int(2) === 0 ? {} : {type})}
    case 'eip7702':
      return {
        ...common,
        ...fees,
        accessList: randomAccessList(rng),
        authorizationList: await randomAuthorizations(rng, signers),
        to: randomAddress(rng),
        type,
      }
  }
}

/** The same request as viem's `TransactionSerializable`. */
const viemRequest = (request: EthereumTransactionRequest): TransactionSerializable => {
  const fields = request as EthereumTransactionRequest & Record<string, unknown>
  const authorizationList = (fields.authorizationList as EthereumAuthorization[] | undefined)?.map(entry => {
    const {recovery, signature} = entry.signature as {recovery: 0 | 1; signature: Uint8Array}

    return {
      address: entry.address as Hex,
      chainId: Number(entry.chainId),
      nonce: Number(entry.nonce),
      r: toHex(signature.subarray(0, 32)),
      s: toHex(signature.subarray(32)),
      yParity: recovery,
    }
  })

  return {
    accessList: fields.accessList as never,
    authorizationList,
    chainId: SEPOLIA,
    data: fields.data as Hex | undefined,
    gas: request.gas,
    gasPrice: fields.gasPrice as bigint | undefined,
    maxFeePerGas: fields.maxFeePerGas as bigint | undefined,
    maxPriorityFeePerGas: fields.maxPriorityFeePerGas as bigint | undefined,
    nonce: Number(request.nonce),
    to: (request.to ?? undefined) as Hex | undefined,
    type: request.type ?? 'eip1559',
    value: request.value,
  } as TransactionSerializable
}

/** What viem's parser and ours agree a transaction says. */
const assertSameFields = (ours: ParsedEthereumTransaction, theirs: ReturnType<typeof parseTransaction>) => {
  assert.equal(theirs.type, ours.type)
  assert.equal(theirs.chainId, ours.chainId)
  assert.equal(BigInt(theirs.nonce ?? 0), ours.nonce)
  assert.equal(theirs.to ? getAddress(theirs.to) : null, ours.to)
  assert.equal(theirs.value ?? 0n, ours.value)
  assert.equal(theirs.gas ?? 0n, ours.gas)
  assert.equal(theirs.data ?? '0x', ours.data)

  if (ours.type === 'legacy' || ours.type === 'eip2930') {
    assert.equal(theirs.gasPrice ?? 0n, ours.gasPrice)
  } else {
    assert.equal(theirs.maxFeePerGas ?? 0n, ours.maxFeePerGas)
    assert.equal(theirs.maxPriorityFeePerGas ?? 0n, ours.maxPriorityFeePerGas)
  }

  if (ours.type !== 'legacy') {
    const list = (theirs as {accessList?: readonly {address: string; storageKeys: readonly string[]}[]}).accessList
    assert.deepEqual(
      (list ?? []).map(({address, storageKeys}) => ({address: getAddress(address), storageKeys: [...storageKeys]})),
      ours.accessList.map(({address, storageKeys}) => ({address, storageKeys: [...storageKeys]}))
    )
  }

  if (ours.type === 'eip7702') {
    const list = (theirs as {authorizationList?: readonly {address: string; chainId: number; nonce: number}[]})
      .authorizationList
    assert.deepEqual(
      (list ?? []).map(({address, chainId, nonce}) => [getAddress(address), chainId, BigInt(nonce)]),
      ours.authorizationList.map(({address, chainId, nonce}) => [address, chainId, nonce])
    )
  }
}

describe('every transaction type', () => {
  test('unsigned and signed transactions of types 0, 1, 2 and 4 equal viem`s byte for byte', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const signers = await Promise.all([0, 1, 2].map(index => wallet.deriveAccount({chain: 'sepolia', index})))
    const rng = random(2930)

    for (const type of TYPES) {
      for (let run = 0; run < 60; run++) {
        const request = await randomRequest(rng, type, signers)
        const index = rng.int(signers.length)
        const account = signers[index] as Signer
        const unsigned = sepolia.serializeTransaction(request)
        const signed = await account.signTransaction(request)

        assert.equal(unsigned, serializeTransaction(viemRequest(request)), `${type} ${run}`)
        assert.equal(
          signed.serialized,
          await mnemonicToAccount(HARDHAT, {addressIndex: index}).signTransaction(viemRequest(request))
        )
        assert.equal(signed.hash, keccak256(signed.serialized))
        assert.equal(
          await recoverTransactionAddress({serializedTransaction: signed.serialized as TransactionSerializedEIP1559}),
          account.address
        )
        assert.equal(
          sepolia.recoverTransactionAddress({signature: signed.signature, transaction: request}),
          account.address
        )
        assert.deepEqual(sepolia.assembleTransaction(request, signed.signature), signed)
        assert.equal(sepolia.serializeTransaction(request, signed.signature), signed.serialized)

        // What viem reads from the signed transaction is what was asked for.
        const parsed = sepolia.parseTransaction(unsigned)
        assertSameFields(parsed, parseTransaction(signed.serialized as TransactionSerializedGeneric))
      }
    }
    wallet.dispose()
  })

  test('parseTransaction reads every type back, ours and viem`s, and serializes it to the same bytes', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const signers = [await wallet.deriveAccount({chain: 'sepolia'})]
    const rng = random(4527)

    for (const type of TYPES) {
      for (let run = 0; run < 60; run++) {
        const request = await randomRequest(rng, type, signers)
        const unsigned = serializeTransaction(viemRequest(request))
        const parsed = sepolia.parseTransaction(unsigned)

        assert.equal(sepolia.serializeTransaction(parsed), unsigned)
        assert.equal(parsed.type, type)
        assertSameFields(parsed, parseTransaction(unsigned))
        assert.ok(Object.isFrozen(parsed))
      }
    }
    wallet.dispose()
  })

  test('EIP-155`s own example: the signing payload, its hash, and the signed transaction', async () => {
    const request = {
      gas: 21000n,
      gasPrice: 20_000_000_000n,
      nonce: 9,
      to: '0x3535353535353535353535353535353535353535',
      type: 'legacy',
      value: 10n ** 18n,
    } as const
    const unsigned = ethereum.serializeTransaction(request)
    assert.equal(
      unsigned,
      '0xec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080'
    )
    assert.equal(keccak256(unsigned), '0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53')

    const key = crypto.keys.importRawSecret('secp256k1', new Uint8Array(32).fill(0x46))
    const account = await ethereum.deriveAccount(keySourceOf(key), {index: 0})
    assert.equal(
      (await account.signTransaction(request)).serialized,
      '0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83'
    )
    assert.deepEqual(ethereum.parseTransaction(unsigned), {...request, chainId: 1, data: '0x', nonce: 9n})
  })

  test('contract creation (to: null, init code in data) for types 0, 1 and 2, and never for type 4', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'sepolia'})
    const theirs = mnemonicToAccount(HARDHAT)
    const data =
      '0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea164736f6c6343000818000a'
    const common = {data, gas: 100_000n, nonce: 3, to: null} as const
    const requests: EthereumTransactionRequest[] = [
      {...common, gasPrice: 10n ** 9n, type: 'legacy'},
      {...common, accessList: [], gasPrice: 10n ** 9n, type: 'eip2930'},
      {...common, maxFeePerGas: 3n * 10n ** 9n, maxPriorityFeePerGas: 10n ** 9n},
    ]

    for (const request of requests) {
      const signed = await account.signTransaction(request)
      assert.equal(signed.serialized, await theirs.signTransaction(viemRequest(request)))
      const parsed = sepolia.parseTransaction(sepolia.serializeTransaction(request))
      assert.equal(parsed.to, null)
      assert.equal(parsed.data, data)
      // Without init code there is nothing to create, and without `to` (rather than `to: null`), no recipient.
      throwsCode(() => sepolia.serializeTransaction({...request, data: undefined}), 'INVALID_ARGUMENT')
      throwsCode(() => sepolia.serializeTransaction({...request, to: undefined} as never), 'INVALID_ADDRESS')
    }

    throwsCode(
      () =>
        sepolia.serializeTransaction({
          ...common,
          authorizationList: [],
          maxFeePerGas: 1n,
          maxPriorityFeePerGas: 1n,
          type: 'eip7702',
        } as never),
      'INVALID_ARGUMENT'
    )
    wallet.dispose()
  })

  test('requests that mix types, blob transactions and unknown types are refused', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'sepolia'})
    const authorization = await account.signAuthorization({address: account.address, nonce: 1})
    const base = {gas: 21000n, nonce: 0, to: account.address}
    const legacy = {...base, gasPrice: 1n, type: 'legacy'} as const
    const dynamic = {...base, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n}
    const refused = (
      request: unknown,
      code: 'INVALID_ARGUMENT' | 'UNSUPPORTED' | 'CHAIN_MISMATCH' | 'INVALID_SIGNATURE'
    ) => throwsCode(() => sepolia.serializeTransaction(request as EthereumTransactionRequest), code)

    refused({...legacy, maxFeePerGas: 1n}, 'INVALID_ARGUMENT')
    refused({...legacy, accessList: []}, 'INVALID_ARGUMENT')
    refused({...legacy, gasPrice: undefined}, 'INVALID_ARGUMENT')
    refused({...legacy, maxPriorityFeePerGas: 1n, type: 'eip2930'}, 'INVALID_ARGUMENT')
    refused({...dynamic, gasPrice: 1n}, 'INVALID_ARGUMENT')
    refused({...dynamic, authorizationList: [authorization]}, 'INVALID_ARGUMENT')
    refused({...dynamic, type: 'eip7702'}, 'INVALID_ARGUMENT')
    refused({...dynamic, authorizationList: [], type: 'eip7702'}, 'INVALID_ARGUMENT')
    refused({...dynamic, type: 'eip4844'}, 'UNSUPPORTED')
    refused({...dynamic, blobVersionedHashes: [], maxFeePerBlobGas: 1n}, 'UNSUPPORTED')
    refused({...dynamic, type: 'deposit'}, 'UNSUPPORTED')
    refused({...dynamic, accessList: [{address: account.address, storageKeys: ['0x01']}]}, 'INVALID_ARGUMENT')
    refused({...dynamic, accessList: [{address: account.address}]}, 'INVALID_ARGUMENT')
    refused({...dynamic, accessList: {}}, 'INVALID_ARGUMENT')
    throwsCode(
      () => sepolia.serializeTransaction({...dynamic, accessList: [{address: '0x12', storageKeys: []}]}),
      'INVALID_ADDRESS'
    )

    // Authorizations in a type 4 transaction: this network`s or chain id 0, each signed.
    const typed = {...dynamic, type: 'eip7702'} as const
    assert.ok(sepolia.serializeTransaction({...typed, authorizationList: [{...authorization, chainId: 0}]}))
    refused({...typed, authorizationList: [{...authorization, chainId: 1}]}, 'CHAIN_MISMATCH')
    refused({...typed, authorizationList: [{...authorization, chainId: undefined}]}, 'INVALID_ARGUMENT')
    refused(
      {...typed, authorizationList: [{...authorization, signature: {recovery: 2, signature: new Uint8Array(64)}}]},
      'INVALID_SIGNATURE'
    )
    await rejectsCode(
      () => account.signTransaction({...typed, authorizationList: [authorization], chainId: 1}),
      'CHAIN_MISMATCH'
    )
    wallet.dispose()
  })

  test('parseTransaction refuses what it does not sign: unprotected, signed, blob, unknown or for another chain', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'sepolia'})
    const authorization = await account.signAuthorization({address: account.address, nonce: 1})
    const legacy = {gas: 21000n, gasPrice: 1n, nonce: 5, to: account.address, type: 'legacy', value: 1n} as const
    const typed = {
      authorizationList: [authorization],
      gas: 21000n,
      maxFeePerGas: 2n,
      maxPriorityFeePerGas: 1n,
      nonce: 5,
      to: account.address,
      type: 'eip7702',
    } as const

    // A legacy transaction without a chain id is valid on every chain.
    const unprotected = serializeTransaction({...legacy, chainId: undefined, to: account.address})
    throwsCode(() => sepolia.parseTransaction(unprotected), 'INVALID_ARGUMENT')
    const signedLegacy = (await account.signTransaction(legacy)).serialized
    const signedTyped = (await account.signTransaction(typed)).serialized
    throwsCode(() => sepolia.parseTransaction(signedLegacy), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.parseTransaction(signedTyped), 'INVALID_ARGUMENT')
    throwsCode(() => ethereum.parseTransaction(sepolia.serializeTransaction(legacy)), 'CHAIN_MISMATCH')
    throwsCode(() => ethereum.parseTransaction(sepolia.serializeTransaction(typed)), 'CHAIN_MISMATCH')

    // Blob transactions (type 3) and types this adapter does not know.
    throwsCode(() => sepolia.parseTransaction('0x03c0'), 'UNSUPPORTED')
    throwsCode(() => sepolia.parseTransaction('0x05c0'), 'UNSUPPORTED')
    throwsCode(() => sepolia.parseTransaction('0x7ec0'), 'UNSUPPORTED')
    throwsCode(() => sepolia.parseTransaction('0x'), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.parseTransaction('0x80'), 'INVALID_ARGUMENT')

    // Type 4: fields as viem writes them, then one at a time made wrong.
    const fields = (overrides: Record<number, unknown> = {}): Hex => {
      const base = [
        '0xaa36a7',
        '0x05',
        '0x01',
        '0x02',
        '0x5208',
        account.address.toLowerCase(),
        '0x',
        '0x',
        [],
        [
          [
            '0xaa36a7',
            account.address.toLowerCase(),
            '0x01',
            authorization.signature.recovery ? '0x01' : '0x',
            toHex(authorization.signature.signature.subarray(0, 32)).replace(/^0x(00)+/, '0x'),
            toHex(authorization.signature.signature.subarray(32)).replace(/^0x(00)+/, '0x'),
          ],
        ],
      ]

      return `0x04${toRlp(base.map((item, index) => (index in overrides ? overrides[index] : item)) as Hex[]).slice(2)}` as Hex
    }

    assert.equal(fields(), sepolia.serializeTransaction(typed))
    throwsCode(() => sepolia.parseTransaction(fields({9: []})), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.parseTransaction(fields({9: '0x'})), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.parseTransaction(fields({5: '0x'})), 'INVALID_ARGUMENT')
    throwsCode(
      () => sepolia.parseTransaction(fields({9: [['0x01', account.address, '0x01', '0x', '0x01', '0x01']]})),
      'CHAIN_MISMATCH'
    )
    throwsCode(
      () => sepolia.parseTransaction(fields({9: [['0xaa36a7', account.address, '0x01', '0x02', '0x01', '0x01']]})),
      'INVALID_ARGUMENT'
    )
    throwsCode(
      () => sepolia.parseTransaction(fields({9: [['0xaa36a7', account.address, '0x01', '0x']]})),
      'INVALID_ARGUMENT'
    )
    throwsCode(
      () => sepolia.parseTransaction(fields({9: [['0xaa36a7', '0x1234', '0x01', '0x', '0x01', '0x01']]})),
      'INVALID_ARGUMENT'
    )
    const anyChain = sepolia.parseTransaction(fields({9: [['0x', account.address, '0x01', '0x', '0x01', '0x01']]}))
    assert.equal(anyChain.type === 'eip7702' && anyChain.authorizationList[0]?.chainId, 0)
    wallet.dispose()
  })
})
