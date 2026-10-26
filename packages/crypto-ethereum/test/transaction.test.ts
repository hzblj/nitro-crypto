import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {isCryptoError} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {
  bytesToHex,
  encodeAbiParameters,
  encodeFunctionData,
  erc20Abi,
  getAddress,
  keccak256,
  parseTransaction,
  recoverTransactionAddress,
  serializeTransaction,
  type TransactionSerializedEIP1559,
  toRlp,
} from 'viem'
import {mnemonicToAccount} from 'viem/accounts'

import {type EthereumTransactionRequest, ethereumAdapter, type Hex} from '../src'
import {type RlpItem, rlpEncode} from '../src/rlp'

const HARDHAT = 'test test test test test test test test test test test junk'
const SEPOLIA = 11155111

const crypto = createTestCryptoEngine({
  adapters: [ethereumAdapter(), ethereumAdapter({chainId: SEPOLIA, id: 'sepolia', name: 'Sepolia'})],
})
const sepolia = crypto.chains.sepolia

const throwsCode = (run: () => unknown, code: string) =>
  assert.throws(run, error => isCryptoError(error) && error.code === code, code)

const toHex = (bytes: Uint8Array) => bytesToHex(bytes)

/** viem's `toRlp` input. */
type Nested = Hex | readonly Nested[]

/** A seeded generator (mulberry32): the same "random" cases on every run. */
const random = (seed: number) => {
  let state = seed

  const next = () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t

    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const int = (max: number) => Math.floor(next() * max)
  const bytes = (length: number) => Uint8Array.from({length}, () => int(256))
  // Integers of every size up to `bits`, zero and the extremes included, as RLP must strip their leading zeros.
  const uint = (bits: number): bigint => {
    const pick = int(10)

    if (pick === 0) {
      return 0n
    }

    if (pick === 1) {
      return (1n << BigInt(bits)) - 1n
    }

    const size = 1 + int(bits / 8)

    return BigInt(toHex(bytes(size))) >> BigInt(int(8))
  }

  return {bytes, int, uint}
}

const randomRequest = (rng: ReturnType<typeof random>): EthereumTransactionRequest => {
  const maxFeePerGas = rng.uint(256)
  const raw = toHex(rng.bytes(20))
  const to = rng.int(2) === 0 ? raw : getAddress(raw)
  const lengths = [0, 1, 4, 55, 56, 68, 300]
  // viem takes the nonce as a number, so parity stops at 2^53 - 1; the range check above it has its own test.
  const nonces = [0, 1, 127, 128, 255, 256, 65535, Number.MAX_SAFE_INTEGER, rng.int(2 ** 32)]
  const nonce = nonces[rng.int(nonces.length)] ?? 0

  return {
    data: rng.int(3) === 0 ? undefined : toHex(rng.bytes(lengths[rng.int(lengths.length)] ?? 0)),
    gas: rng.uint(64),
    maxFeePerGas,
    maxPriorityFeePerGas: maxFeePerGas === 0n ? 0n : maxFeePerGas >> BigInt(rng.int(256)),
    nonce: rng.int(2) === 0 ? nonce : BigInt(nonce),
    to,
    value: rng.uint(256),
  }
}

/** The same request as viem takes it. */
const viemRequest = (request: EthereumTransactionRequest, chainId = SEPOLIA) => ({
  chainId,
  data: request.data as Hex | undefined,
  gas: request.gas,
  maxFeePerGas: request.maxFeePerGas,
  maxPriorityFeePerGas: request.maxPriorityFeePerGas,
  nonce: Number(request.nonce),
  to: request.to as Hex,
  type: 'eip1559' as const,
  value: request.value,
})

describe('RLP', () => {
  const text = (value: string) => new TextEncoder().encode(value)
  const integer = (value: number) => {
    const digits = value === 0 ? '' : value.toString(16)

    return Uint8Array.from(Buffer.from(digits.length % 2 ? `0${digits}` : digits, 'hex'))
  }

  test('the published examples', () => {
    const cases: [RlpItem, string][] = [
      [text('dog'), '0x83646f67'],
      [[text('cat'), text('dog')], '0xc88363617483646f67'],
      [text(''), '0x80'],
      [[], '0xc0'],
      [integer(0), '0x80'],
      [Uint8Array.of(0), '0x00'],
      [integer(15), '0x0f'],
      [integer(1024), '0x820400'],
      [[[], [[]], [[], [[]]]], '0xc7c0c1c0c3c0c1c0'],
      [
        text('Lorem ipsum dolor sit amet, consectetur adipisicing elit'),
        `0xb838${Buffer.from('Lorem ipsum dolor sit amet, consectetur adipisicing elit').toString('hex')}`,
      ],
    ]

    for (const [item, expected] of cases) {
      assert.equal(toHex(rlpEncode(item)), expected)
    }
  })

  test('equals viem on random nested items, long strings and long lists included', () => {
    const rng = random(7)
    const item = (depth: number): RlpItem =>
      depth > 0 && rng.int(3) === 0
        ? Array.from({length: rng.int(6)}, () => item(depth - 1))
        : rng.bytes([0, 1, 2, 55, 56, 300, 70000][rng.int(7)] ?? 0)
    const asViem = (value: RlpItem): Nested => (value instanceof Uint8Array ? toHex(value) : value.map(asViem))

    for (let run = 0; run < 300; run++) {
      const value = item(4)
      assert.equal(toHex(rlpEncode(value)), toRlp(asViem(value)))
    }
  })
})

describe('EIP-1559 transactions', () => {
  test('unsigned serialization equals viem on random requests', () => {
    const rng = random(1559)

    for (let run = 0; run < 300; run++) {
      const request = randomRequest(rng)
      assert.equal(sepolia.serializeTransaction(request), serializeTransaction(viemRequest(request)))
    }
  })

  test('signed transactions equal viem`s byte for byte, and viem recovers the sender and reads every field', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const rng = random(2718)

    for (const index of [0, 1, 7]) {
      const account = await wallet.deriveAccount({chain: 'sepolia', index})
      const theirs = mnemonicToAccount(HARDHAT, {addressIndex: index})

      for (let run = 0; run < 30; run++) {
        const request = randomRequest(rng)
        const signed = await account.signTransaction(request)

        assert.equal(signed.serialized, await theirs.signTransaction(viemRequest(request)))
        assert.equal(signed.hash, keccak256(signed.serialized))
        assert.equal(
          await recoverTransactionAddress({
            serializedTransaction: signed.serialized as TransactionSerializedEIP1559,
          }),
          account.address
        )

        const parsed = parseTransaction(signed.serialized)
        assert.equal(parsed.type, 'eip1559')
        assert.equal(parsed.chainId, SEPOLIA)
        assert.equal(BigInt(parsed.nonce ?? 0), BigInt(request.nonce))
        assert.equal(parsed.to?.toLowerCase(), request.to.toLowerCase())
        assert.equal(parsed.value ?? 0n, request.value)
        assert.equal(parsed.gas ?? 0n, request.gas)
        assert.equal(parsed.maxFeePerGas ?? 0n, request.maxFeePerGas)
        assert.equal(parsed.maxPriorityFeePerGas ?? 0n, request.maxPriorityFeePerGas)
        assert.equal(parsed.data ?? '0x', request.data ?? '0x')
      }
    }
    wallet.dispose()
  })

  test('a signature handed to serializeTransaction gives the signed envelope', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'sepolia'})
    const request = {
      gas: 21000n,
      maxFeePerGas: 3n * 10n ** 9n,
      maxPriorityFeePerGas: 10n ** 9n,
      nonce: 4,
      to: account.address,
      value: 10n ** 15n,
    }
    const signed = await account.signTransaction(request)
    const parsed = parseTransaction(signed.serialized)
    const signature = Uint8Array.from(
      Buffer.from(`${parsed.r?.slice(2).padStart(64, '0')}${parsed.s?.slice(2).padStart(64, '0')}`, 'hex')
    )

    assert.equal(
      sepolia.serializeTransaction(request, {recovery: parsed.yParity === 1 ? 1 : 0, signature}),
      signed.serialized
    )
    wallet.dispose()
  })

  test('the chain id is the adapter`s: the default, and nothing else', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const onSepolia = await wallet.deriveAccount({chain: 'sepolia'})
    const onMainnet = await wallet.deriveAccount({chain: 'ethereum'})
    const request = {gas: 21000n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, nonce: 0, to: onSepolia.address}

    assert.equal(parseTransaction((await onSepolia.signTransaction(request)).serialized).chainId, SEPOLIA)
    assert.equal(parseTransaction((await onMainnet.signTransaction(request)).serialized).chainId, 1)
    assert.equal(
      parseTransaction((await onSepolia.signTransaction({...request, chainId: SEPOLIA})).serialized).chainId,
      SEPOLIA
    )
    await assert.rejects(
      () => onMainnet.signTransaction({...request, chainId: SEPOLIA}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    throwsCode(() => sepolia.serializeTransaction({...request, chainId: 1}), 'INVALID_ARGUMENT')
    wallet.dispose()
  })

  test('out-of-range numbers, a tip above the fee cap and a bad recipient are refused', () => {
    const base = {
      gas: 21000n,
      maxFeePerGas: 2n,
      maxPriorityFeePerGas: 1n,
      nonce: 0,
      to: getAddress(`0x${'ab'.repeat(20)}`),
    }
    const tooBig = 1n << 256n

    throwsCode(() => sepolia.serializeTransaction({...base, value: -1n}), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.serializeTransaction({...base, value: tooBig}), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.serializeTransaction({...base, gas: -1n}), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.serializeTransaction({...base, maxFeePerGas: tooBig}), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.serializeTransaction({...base, maxPriorityFeePerGas: 3n}), 'INVALID_ARGUMENT')
    // EIP-2681: a nonce is at most 2^64 - 1. viem reads nonces as numbers, so the check is on the RLP: the chain id
    // (0xaa36a7), then eight 0xff bytes.
    assert.ok(sepolia.serializeTransaction({...base, nonce: (1n << 64n) - 1n}).includes('83aa36a788ffffffffffffffff'))
    throwsCode(() => sepolia.serializeTransaction({...base, nonce: 1n << 64n}), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.serializeTransaction({...base, nonce: 1.5}), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.serializeTransaction({...base, nonce: -1}), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.serializeTransaction({...base, to: '0x1234'}), 'INVALID_ADDRESS')
    throwsCode(() => sepolia.serializeTransaction({...base, to: base.to.replace('aB', 'ab')}), 'INVALID_ADDRESS')
    throwsCode(() => sepolia.serializeTransaction({...base, data: '0xabc' as Hex}), 'INVALID_ENCODING')
    throwsCode(
      () => sepolia.serializeTransaction(base, {recovery: 2, signature: new Uint8Array(64)}),
      'INVALID_SIGNATURE'
    )
  })

  test('signing with a disposed wallet`s account throws DISPOSED', async () => {
    const wallet = await crypto.createEphemeralWallet()
    const account = await wallet.deriveAccount({chain: 'sepolia'})
    wallet.dispose()
    await assert.rejects(
      () =>
        account.signTransaction({
          gas: 21000n,
          maxFeePerGas: 2n,
          maxPriorityFeePerGas: 1n,
          nonce: 0,
          to: account.address,
        }),
      error => isCryptoError(error, 'DISPOSED')
    )
  })
})

describe('ERC-20', () => {
  test('call data equals viem`s encodeFunctionData', () => {
    const rng = random(20)

    for (let run = 0; run < 100; run++) {
      const address = getAddress(toHex(rng.bytes(20)))
      const amount = rng.uint(256)
      assert.equal(
        sepolia.erc20.transferData(address.toLowerCase(), amount),
        encodeFunctionData({abi: erc20Abi, args: [address, amount], functionName: 'transfer'})
      )
      assert.equal(
        sepolia.erc20.balanceOfData(address),
        encodeFunctionData({abi: erc20Abi, args: [address], functionName: 'balanceOf'})
      )
    }
  })

  test('a uint256 result decodes; an empty or short one throws', () => {
    for (const value of [0n, 1n, 10n ** 18n, (1n << 256n) - 1n]) {
      assert.equal(sepolia.erc20.decodeUint256(encodeAbiParameters([{type: 'uint256'}], [value])), value)
    }
    throwsCode(() => sepolia.erc20.decodeUint256('0x'), 'INVALID_ENCODING')
    throwsCode(() => sepolia.erc20.decodeUint256(`0x${'00'.repeat(31)}`), 'INVALID_ENCODING')
  })

  test('a bad recipient or amount is refused', () => {
    throwsCode(() => sepolia.erc20.transferData('0x12', 1n), 'INVALID_ADDRESS')
    throwsCode(() => sepolia.erc20.transferData(`0x${'ab'.repeat(20)}`, -1n), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.erc20.transferData(`0x${'ab'.repeat(20)}`, 1n << 256n), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.erc20.balanceOfData('nope'), 'INVALID_ADDRESS')
  })
})

describe('reading transactions to sign elsewhere', () => {
  test('parseTransaction reads back every request serializeTransaction writes, and viem`s too', () => {
    const rng = random(4527)

    for (let run = 0; run < 300; run++) {
      const request = randomRequest(rng)
      const unsigned = sepolia.serializeTransaction(request)
      const parsed = sepolia.parseTransaction(unsigned)

      assert.equal(sepolia.serializeTransaction(parsed), unsigned)
      assert.equal(parsed.chainId, SEPOLIA)
      assert.equal(parsed.to, getAddress(request.to))
      assert.equal(parsed.nonce, BigInt(request.nonce))
      assert.equal(parsed.value, request.value ?? 0n)
      assert.equal(parsed.data, request.data ?? '0x')
      assert.equal(sepolia.parseTransaction(serializeTransaction(viemRequest(request))).value, request.value ?? 0n)
    }
  })

  test('a signature made elsewhere: the signer recovers, and the envelope is viem`s', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'sepolia', index: 3})
    const theirs = mnemonicToAccount(HARDHAT, {addressIndex: 3})
    const rng = random(65)

    for (let run = 0; run < 20; run++) {
      const request = randomRequest(rng)
      const signed = await account.signTransaction(request)

      assert.equal(
        sepolia.recoverTransactionAddress({signature: signed.signature, transaction: request}),
        account.address
      )
      assert.deepEqual(sepolia.assembleTransaction(request, signed.signature), signed)

      // As 65 bytes, v as y parity or 27 + y parity, the way signers send it.
      const raw = new Uint8Array(65)
      raw.set(signed.signature.signature)
      raw[64] = signed.signature.recovery
      assert.equal(
        sepolia.assembleTransaction(request, raw).serialized,
        await theirs.signTransaction(viemRequest(request))
      )
      raw[64] = 27 + signed.signature.recovery
      assert.equal(sepolia.recoverTransactionAddress({signature: toHex(raw), transaction: request}), account.address)

      // A signature over another transaction recovers someone else.
      const other = {...request, nonce: BigInt(request.nonce) + 1n}
      assert.notEqual(
        sepolia.recoverTransactionAddress({signature: signed.signature, transaction: other}),
        account.address
      )
    }

    assert.equal(
      sepolia.recoverTransactionAddress({signature: new Uint8Array(65), transaction: randomRequest(rng)}),
      undefined
    )
    wallet.dispose()
  })

  test('addresses below an account`s extended key, derived publicly by the engine, are its accounts', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = wallet.extendedPublicKey("m/44'/60'/0'")

    for (const index of [0, 1, 7]) {
      const derived = sepolia.derivePublic(account, `m/0/${index}`)
      assert.equal(
        sepolia.addressFromPublicKey(derived.publicKey),
        (await wallet.deriveAccount({chain: 'sepolia', index})).address
      )
    }

    throwsCode(() => sepolia.derivePublic(account, "m/0'"), 'INVALID_PATH')
    wallet.dispose()
  })

  test('addresses from public keys, compressed or not', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'sepolia'})
    const key = Buffer.from(account.publicKey.slice(2), 'hex')
    const compressed = crypto.secp256k1.convertPublicKey(key, 'compressed')
    assert.equal(sepolia.addressFromPublicKey(key), account.address)
    assert.equal(sepolia.addressFromPublicKey(compressed), account.address)
    throwsCode(() => sepolia.addressFromPublicKey(new Uint8Array(33)), 'INVALID_PUBLIC_KEY')
    wallet.dispose()
  })

  test('anything but an unsigned EIP-1559 transaction of this network is refused', async () => {
    const request = {
      gas: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      nonce: 5,
      to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      value: 10n ** 16n,
    } as const
    const unsigned = sepolia.serializeTransaction(request)
    const fields = (extra: Nested[] = [], overrides: Record<number, Nested> = {}) => {
      const base: Nested[] = [
        '0xaa36a7',
        '0x05',
        '0x3b9aca00',
        '0x06fc23ac00',
        '0x5208',
        '0x70997970c51812dc3a010c7d01b50e0d17dc79c8',
        '0x2386f26fc10000',
        '0x',
        [],
        ...extra,
      ]

      return `0x02${toRlp(base.map((item, index) => overrides[index] ?? item)).slice(2)}` as Hex
    }

    assert.equal(fields(), unsigned)
    throwsCode(() => crypto.chains.ethereum.parseTransaction(unsigned), 'INVALID_ARGUMENT')
    // A legacy (EIP-155) transaction, as viem serializes one: an RLP list, no type byte.
    throwsCode(
      () => sepolia.parseTransaction('0xe205018252089470997970c51812dc3a010c7d01b50e0d17dc79c8018083aa36a78080'),
      'INVALID_ARGUMENT'
    )
    throwsCode(() => sepolia.parseTransaction(fields(['0x01', '0x02', '0x03'])), 'INVALID_ARGUMENT')
    throwsCode(
      () => sepolia.parseTransaction(fields([], {8: [['0x70997970c51812dc3a010c7d01b50e0d17dc79c8', []]]})),
      'INVALID_ARGUMENT'
    )
    throwsCode(() => sepolia.parseTransaction(fields([], {5: '0x'})), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.parseTransaction(fields([], {1: '0x0005'})), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.parseTransaction(fields([], {2: '0x06fc23ac01'})), 'INVALID_ARGUMENT')
    // Non-canonical RLP: a single byte below 0x80 wrapped in a string header.
    throwsCode(() => sepolia.parseTransaction(`0x02${toRlp(['0x', '0x05']).slice(2)}` as Hex), 'INVALID_ARGUMENT')
    throwsCode(() => sepolia.parseTransaction('0x02c3810501' as Hex), 'INVALID_ENCODING')
    throwsCode(() => sepolia.parseTransaction(`${unsigned}00` as Hex), 'INVALID_ENCODING')
    throwsCode(() => sepolia.parseTransaction('0x02' as Hex), 'INVALID_ENCODING')
  })
})
