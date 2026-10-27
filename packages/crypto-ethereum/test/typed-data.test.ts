import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {isCryptoError} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {
  getAddress,
  keccak256,
  recoverTypedDataAddress,
  stringToBytes,
  verifyTypedData,
  hashDomain as viemHashDomain,
  hashStruct as viemHashStruct,
  hashTypedData as viemHashTypedData,
} from 'viem'
import {mnemonicToAccount} from 'viem/accounts'

import {ethereumAdapter, type Hex, type TypedDataDefinition, type TypedDataField} from '../src'
import {HARDHAT, keySourceOf, type Random, random, rejectsCode, SEPOLIA, throwsCode, toHex} from './support'

const crypto = createTestCryptoEngine({
  adapters: [ethereumAdapter(), ethereumAdapter({chainId: SEPOLIA, id: 'sepolia', name: 'Sepolia'})],
})
const {ethereum, sepolia} = crypto.chains

/** viem's typed data parameter, from ours: the same object, typed loosely. */
const loose = (typedData: TypedDataDefinition): any => typedData

// EIP-712's own example (its reference implementation, Example.js): the digest and signature it publishes.
const MAIL = {
  domain: {
    chainId: 1,
    name: 'Ether Mail',
    verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    version: '1',
  },
  message: {
    contents: 'Hello, Bob!',
    from: {name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826'},
    to: {name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'},
  },
  primaryType: 'Mail',
  types: {
    Mail: [
      {name: 'from', type: 'Person'},
      {name: 'to', type: 'Person'},
      {name: 'contents', type: 'string'},
    ],
    Person: [
      {name: 'name', type: 'string'},
      {name: 'wallet', type: 'address'},
    ],
  },
} as const satisfies TypedDataDefinition

const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3'
const USDC = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238'
const SPENDER = '0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD'

// The shapes wallets meet most: ERC-2612 permits, and Permit2's single, batch and witness transfers.
const PAYLOADS = {
  permit: {
    domain: {chainId: SEPOLIA, name: 'USD Coin', verifyingContract: USDC, version: '2'},
    message: {deadline: 1_900_000_000n, nonce: 0n, owner: SPENDER, spender: PERMIT2, value: 2n ** 256n - 1n},
    primaryType: 'Permit',
    types: {
      Permit: [
        {name: 'owner', type: 'address'},
        {name: 'spender', type: 'address'},
        {name: 'value', type: 'uint256'},
        {name: 'nonce', type: 'uint256'},
        {name: 'deadline', type: 'uint256'},
      ],
    },
  },
  permit2Batch: {
    domain: {chainId: SEPOLIA, name: 'Permit2', verifyingContract: PERMIT2},
    message: {
      details: [
        {amount: 2n ** 160n - 1n, expiration: 2n ** 48n - 1n, nonce: 0, token: USDC},
        {amount: 1_000_000n, expiration: 1_900_000_000, nonce: 7, token: SPENDER.toLowerCase()},
      ],
      sigDeadline: 1_900_000_000n,
      spender: SPENDER,
    },
    primaryType: 'PermitBatch',
    types: {
      PermitBatch: [
        {name: 'details', type: 'PermitDetails[]'},
        {name: 'spender', type: 'address'},
        {name: 'sigDeadline', type: 'uint256'},
      ],
      PermitDetails: [
        {name: 'token', type: 'address'},
        {name: 'amount', type: 'uint160'},
        {name: 'expiration', type: 'uint48'},
        {name: 'nonce', type: 'uint48'},
      ],
    },
  },
  permit2Single: {
    domain: {chainId: SEPOLIA, name: 'Permit2', verifyingContract: PERMIT2},
    message: {
      details: {amount: 1_000_000n, expiration: 1_900_000_000, nonce: 3, token: USDC},
      sigDeadline: 1_900_000_000n,
      spender: SPENDER,
    },
    primaryType: 'PermitSingle',
    types: {
      PermitDetails: [
        {name: 'token', type: 'address'},
        {name: 'amount', type: 'uint160'},
        {name: 'expiration', type: 'uint48'},
        {name: 'nonce', type: 'uint48'},
      ],
      PermitSingle: [
        {name: 'details', type: 'PermitDetails'},
        {name: 'spender', type: 'address'},
        {name: 'sigDeadline', type: 'uint256'},
      ],
    },
  },
  permit2Witness: {
    domain: {chainId: SEPOLIA, name: 'Permit2', verifyingContract: PERMIT2},
    message: {
      deadline: 1_900_000_000n,
      nonce: 2n ** 248n + 5n,
      permitted: [
        {amount: 10n ** 18n, token: USDC},
        {amount: 1n, token: SPENDER},
      ],
      spender: SPENDER,
      witness: {exampleMinimumAmountOut: 99n, exampleTokenAddress: USDC},
    },
    primaryType: 'PermitBatchWitnessTransferFrom',
    types: {
      ExampleTrade: [
        {name: 'exampleTokenAddress', type: 'address'},
        {name: 'exampleMinimumAmountOut', type: 'uint256'},
      ],
      PermitBatchWitnessTransferFrom: [
        {name: 'permitted', type: 'TokenPermissions[]'},
        {name: 'spender', type: 'address'},
        {name: 'nonce', type: 'uint256'},
        {name: 'deadline', type: 'uint256'},
        {name: 'witness', type: 'ExampleTrade'},
      ],
      TokenPermissions: [
        {name: 'token', type: 'address'},
        {name: 'amount', type: 'uint256'},
      ],
    },
  },
} satisfies Record<string, TypedDataDefinition>

const INTEGER_BITS = Array.from({length: 32}, (_, index) => (index + 1) * 8)
const STRUCT_NAMES = ['Order', 'asset', 'Z_9', 'Item', 'b', 'Mail']
const FIELD_NAMES = ['amount', 'to', 'data', 'flag', 'note', 'items', 'id', 'x', '_y', 'value']

/** Random struct types, acyclic (a struct refers only to those after it), and a value of each. */
const randomTypedData = (rng: Random): TypedDataDefinition => {
  const count = 1 + rng.int(4)
  const names = [...STRUCT_NAMES].sort(() => rng.int(3) - 1).slice(0, count)
  const types: Record<string, TypedDataField[]> = {}

  names.forEach((name, index) => {
    const fields = [...FIELD_NAMES].sort(() => rng.int(3) - 1).slice(0, 1 + rng.int(6))
    types[name] = fields.map(field => {
      const later = names.slice(index + 1)
      const base =
        later.length > 0 && rng.int(4) === 0
          ? rng.pick(later)
          : rng.pick([
              'address',
              'bool',
              'string',
              'bytes',
              `bytes${1 + rng.int(32)}`,
              `uint${rng.pick(INTEGER_BITS)}`,
              `int${rng.pick(INTEGER_BITS)}`,
            ])
      const dimensions = rng.int(5) === 0 ? rng.pick(['[]', '[2]', '[][3]', '[1][]']) : ''

      return {name: field, type: `${base}${dimensions}`}
    })
  })

  const value = (type: string, depth: number): unknown => {
    const array = /^(.+)\[(\d*)\]$/.exec(type)

    if (array) {
      const length = array[2] === '' ? rng.int(4) : Number(array[2])

      return Array.from({length}, () => value(array[1] ?? '', depth + 1))
    }

    if (types[type]) {
      return Object.fromEntries((types[type] ?? []).map(field => [field.name, value(field.type, depth + 1)]))
    }

    if (type === 'address') {
      const raw = toHex(rng.bytes(20))

      return rng.int(2) === 0 ? raw : getAddress(raw)
    }

    if (type === 'bool') {
      return rng.int(2) === 0
    }

    if (type === 'string') {
      return rng.pick(['', 'Hello, Bob!', 'ñandú 日本 😀', 'x'.repeat(100)])
    }

    if (type === 'bytes') {
      return toHex(rng.bytes(rng.pick([0, 1, 31, 32, 33, 100])))
    }

    const fixed = /^bytes(\d+)$/.exec(type)

    if (fixed) {
      return toHex(rng.bytes(Number(fixed[1])))
    }

    const [, unsigned, bitsText] = /^(u?)int(\d+)$/.exec(type) ?? []
    const bits = Number(bitsText)

    if (unsigned) {
      return rng.uint(bits)
    }

    const magnitude = rng.uint(bits - 1)

    return rng.int(2) === 0 ? magnitude : -magnitude - (rng.int(2) === 0 ? 0n : 1n)
  }

  const primaryType = names[0] ?? ''
  const domainFields = {
    chainId: SEPOLIA,
    name: 'Random',
    salt: toHex(rng.bytes(32)),
    verifyingContract: getAddress(toHex(rng.bytes(20))),
    version: String(rng.int(10)),
  }
  const domain = Object.fromEntries(Object.entries(domainFields).filter(() => rng.int(2) === 0))

  return {
    domain: Object.keys(domain).length > 0 ? domain : {name: 'Random'},
    message: value(primaryType, 0) as Record<string, unknown>,
    primaryType,
    types,
  }
}

const importAccount = async (secret: Hex) =>
  ethereum.deriveAccount(keySourceOf(crypto.keys.importRawSecret('secp256k1', Buffer.from(secret.slice(2), 'hex'))), {
    index: 0,
  })

describe('EIP-712 typed data', () => {
  test('the EIP-712 example: its type encoding, struct hash, domain separator, digest and signature', async () => {
    assert.equal(
      toHex(ethereum.hashDomain({domain: MAIL.domain})),
      '0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f'
    )
    assert.equal(
      toHex(ethereum.hashStruct({data: MAIL.message, primaryType: 'Mail', types: MAIL.types})),
      '0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e'
    )
    assert.equal(
      toHex(ethereum.hashTypedData(MAIL)),
      '0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2'
    )

    // The example's key is keccak256("cow").
    const cow = await importAccount(keccak256(stringToBytes('cow')))
    assert.equal(cow.address, MAIL.message.from.wallet)
    assert.equal(
      await cow.signTypedData(MAIL),
      '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c'
    )
  })

  test('permits and Permit2 payloads: hashes and signatures equal viem`s, and each recovers the other`s', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})

    for (const index of [0, 3]) {
      const ours = await wallet.deriveAccount({chain: 'sepolia', index})
      const theirs = mnemonicToAccount(HARDHAT, {addressIndex: index})

      for (const typedData of Object.values(PAYLOADS)) {
        assert.equal(toHex(sepolia.hashTypedData(typedData)), viemHashTypedData(loose(typedData)))
        const signature = await ours.signTypedData(typedData)
        assert.equal(signature, await theirs.signTypedData(loose(typedData)))
        assert.equal(await recoverTypedDataAddress({...loose(typedData), signature}), ours.address)
        assert.equal(await verifyTypedData({...loose(typedData), address: ours.address, signature}), true)
        assert.equal(sepolia.recoverTypedDataAddress({...typedData, signature}), ours.address)
        assert.equal(sepolia.verifyTypedData({...typedData, address: ours.address, signature}), true)
        assert.equal(await ours.verifyTypedData({...typedData, signature}), true)
      }
    }
    wallet.dispose()
  })

  test('random types (every intN, uintN and bytesN, nested structs, arrays of any dimension) hash and sign as viem', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const ours = await wallet.deriveAccount({chain: 'sepolia', index: 1})
    const theirs = mnemonicToAccount(HARDHAT, {addressIndex: 1})
    const rng = random(712)
    const seen = new Set<string>()

    for (let run = 0; run < 300; run++) {
      const typedData = randomTypedData(rng)

      for (const field of Object.values(typedData.types).flat()) {
        const base = field.type.replace(/(\[\d*\])+$/, '')
        const kind = typedData.types[base] ? 'struct' : base.replace(/\d+$/, '')
        seen.add(field.type.endsWith(']') ? `${kind}[]` : kind)
        seen.add(/\]\[/.test(field.type) ? 'nested array' : 'flat')
      }
      assert.equal(toHex(sepolia.hashTypedData(typedData)), viemHashTypedData(loose(typedData)), `run ${run}`)
      assert.equal(
        toHex(
          sepolia.hashStruct({data: typedData.message, primaryType: typedData.primaryType, types: typedData.types})
        ),
        viemHashStruct({data: typedData.message, primaryType: typedData.primaryType, types: loose(typedData).types})
      )

      if (run % 10 === 0) {
        assert.equal(await ours.signTypedData(typedData), await theirs.signTypedData(loose(typedData)))
      }
    }

    for (const kind of [
      'struct',
      'struct[]',
      'nested array',
      'int',
      'uint[]',
      'bytes',
      'bytes[]',
      'string',
      'address',
    ]) {
      assert.ok(seen.has(kind), kind)
    }
    wallet.dispose()
  })

  test('as a dApp sends it: EIP712Domain declared, integers as text, bytes as Uint8Array', () => {
    const declared = {
      ...PAYLOADS.permit2Single,
      types: {
        ...PAYLOADS.permit2Single.types,
        EIP712Domain: [
          {name: 'name', type: 'string'},
          {name: 'chainId', type: 'uint256'},
          {name: 'verifyingContract', type: 'address'},
        ],
      },
    } as TypedDataDefinition
    const expected = viemHashTypedData(loose(declared))
    assert.equal(toHex(sepolia.hashTypedData(declared)), viemHashTypedData(loose(PAYLOADS.permit2Single)))
    assert.equal(toHex(sepolia.hashTypedData(declared)), expected)

    const json = JSON.parse(
      JSON.stringify(declared, (_, value) => (typeof value === 'bigint' ? value.toString() : value))
    ) as TypedDataDefinition
    assert.equal(toHex(sepolia.hashTypedData({...json, domain: {...json.domain, chainId: '0xaa36a7'}})), expected)

    // A domain in another order than EIP-712's is hashed in the order it is declared, as viem and MetaMask do.
    const reordered = {
      ...declared,
      types: {...declared.types, EIP712Domain: [...(declared.types.EIP712Domain ?? [])].reverse()},
    }
    assert.equal(toHex(sepolia.hashTypedData(reordered)), viemHashTypedData(loose(reordered)))

    const bytesData: TypedDataDefinition = {
      domain: {name: 'Bytes', salt: new Uint8Array(32).fill(7)},
      message: {blob: new Uint8Array([1, 2, 3]), word: new Uint8Array(4).fill(9)},
      primaryType: 'Data',
      types: {
        Data: [
          {name: 'blob', type: 'bytes'},
          {name: 'word', type: 'bytes4'},
        ],
      },
    }
    assert.equal(
      toHex(sepolia.hashTypedData(bytesData)),
      viemHashTypedData({
        domain: {name: 'Bytes', salt: `0x${'07'.repeat(32)}`},
        message: {blob: '0x010203', word: '0x09090909'},
        primaryType: 'Data',
        types: loose(bytesData).types,
      })
    )
  })

  test('members the types do not declare are ignored, as viem ignores them; only declared ones are signed', () => {
    const permit = PAYLOADS.permit
    const extra = {...permit, message: {...permit.message, totalOriginalConsiderationItems: 3}}
    assert.deepEqual(sepolia.hashTypedData(extra), sepolia.hashTypedData(permit))
  })

  test('primaryType EIP712Domain signs the domain alone, as viem does', async () => {
    const typedData: TypedDataDefinition = {
      domain: MAIL.domain,
      message: {},
      primaryType: 'EIP712Domain',
      types: MAIL.types,
    }
    assert.equal(toHex(ethereum.hashTypedData(typedData)), viemHashTypedData(loose(typedData)))
    assert.equal(
      toHex(ethereum.hashDomain({domain: {name: 'x', salt: `0x${'ab'.repeat(32)}`}})),
      viemHashDomain({
        domain: {name: 'x', salt: `0x${'ab'.repeat(32)}`},
        types: {
          EIP712Domain: [
            {name: 'name', type: 'string'},
            {name: 'salt', type: 'bytes32'},
          ],
        },
      })
    )
  })

  test('the domain`s chain id must be the adapter`s: CHAIN_MISMATCH otherwise; a domain without one binds none', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const onMainnet = await wallet.deriveAccount({chain: 'ethereum'})
    const onSepolia = await wallet.deriveAccount({chain: 'sepolia'})
    const permit: TypedDataDefinition = PAYLOADS.permit

    await rejectsCode(() => onMainnet.signTypedData(permit), 'CHAIN_MISMATCH')
    throwsCode(() => ethereum.hashTypedData(permit), 'CHAIN_MISMATCH')
    const signature = await onSepolia.signTypedData(permit)
    throwsCode(() => ethereum.recoverTypedDataAddress({...permit, signature}), 'CHAIN_MISMATCH')
    throwsCode(() => ethereum.verifyTypedData({...permit, address: onSepolia.address, signature}), 'CHAIN_MISMATCH')
    await rejectsCode(
      () => onMainnet.signTypedData({...permit, domain: {...permit.domain, chainId: 0}}),
      'CHAIN_MISMATCH'
    )
    assert.equal(
      await onSepolia.signTypedData({...permit, domain: {...permit.domain, chainId: `${SEPOLIA}`}}),
      signature
    )

    // A chain id the types do not declare still has to match: what a review screen shows is what is checked.
    const undeclared = {
      ...permit,
      types: {...permit.types, EIP712Domain: [{name: 'name', type: 'string'}]},
    }
    await rejectsCode(() => onMainnet.signTypedData(undeclared), 'CHAIN_MISMATCH')

    const unbound = {...permit, domain: {...permit.domain, chainId: undefined}}
    assert.equal(await onMainnet.signTypedData(unbound), await onSepolia.signTypedData(unbound))
    wallet.dispose()
  })

  test('a changed message, another signer or a malformed signature does not verify', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'sepolia'})
    const other = await wallet.deriveAccount({chain: 'sepolia', index: 1})
    const permit: TypedDataDefinition = PAYLOADS.permit
    const signature = await account.signTypedData(permit)

    assert.equal(await account.verifyTypedData({...permit, message: {...permit.message, nonce: 1n}, signature}), false)
    assert.equal(await other.verifyTypedData({...permit, signature}), false)
    assert.equal(await account.verifyTypedData({...permit, signature: '0x1234'}), false)
    assert.equal(sepolia.recoverTypedDataAddress({...permit, signature: `0x${'00'.repeat(65)}`}), undefined)
    throwsCode(() => sepolia.verifyTypedData({...permit, address: '0x12', signature}), 'INVALID_ADDRESS')
    wallet.dispose()
  })
})

describe('EIP-712 validation', () => {
  const PERSON = [
    {name: 'name', type: 'string'},
    {name: 'wallet', type: 'address'},
  ]
  const base = (
    types: Record<string, readonly TypedDataField[]>,
    message: Record<string, unknown>,
    primaryType = 'T'
  ) => ({domain: {chainId: 1, name: 'Test'}, message, primaryType, types}) as TypedDataDefinition
  const refused = (typedData: TypedDataDefinition, code: 'INVALID_ARGUMENT' | 'INVALID_ADDRESS' | 'INVALID_ENCODING') =>
    throwsCode(() => ethereum.hashTypedData(typedData), code)

  test('unknown, recursive and misnamed types are refused', () => {
    refused(base({T: [{name: 'x', type: 'Nope'}]}, {x: {}}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'uint'}]}, {x: 1}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'int'}]}, {x: 1}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'uint7'}]}, {x: 1}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'uint264'}]}, {x: 1}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'bytes33'}]}, {x: '0x'}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'bytes0'}]}, {x: '0x'}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'fixed128x18'}]}, {x: 1}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'uint8[0]'}]}, {x: []}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'uint8[01]'}]}, {x: [1]}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'uint8[ ]'}]}, {x: [1]}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'T'}]}, {x: {}}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'T[]'}]}, {x: []}), 'INVALID_ARGUMENT')
    refused(
      base({A: [{name: 'b', type: 'B[2]'}], B: [{name: 'a', type: 'A'}], T: [{name: 'a', type: 'A'}]}, {}),
      'INVALID_ARGUMENT'
    )
    // A cycle among types the primary type never reaches is refused too: all the types are checked.
    refused(base({A: [{name: 'b', type: 'B'}], B: [{name: 'a', type: 'A'}], T: []}, {}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'x', type: 'EIP712Domain'}]}, {x: {}}), 'INVALID_ARGUMENT')
    refused(base({T: [], uint256: []}, {}), 'INVALID_ARGUMENT')
    refused(base({bytes7: [], T: []}, {}), 'INVALID_ARGUMENT')
    refused(base({T: [], 'T(x)': []}, {}), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'a b', type: 'uint8'}]}, {'a b': 1}), 'INVALID_ARGUMENT')
    refused(
      base(
        {
          T: [
            {name: 'x', type: 'uint8'},
            {name: 'x', type: 'uint16'},
          ],
        },
        {x: 1}
      ),
      'INVALID_ARGUMENT'
    )
    refused(base({T: [{name: 'x'} as TypedDataField]}, {x: 1}), 'INVALID_ARGUMENT')
    refused(base({T: {name: 'x', type: 'uint8'} as unknown as TypedDataField[]}, {x: 1}), 'INVALID_ARGUMENT')
    refused(base({Person: PERSON}, {}, 'Mail'), 'INVALID_ARGUMENT')
    refused({...base({T: []}, {}), types: null as unknown as Record<string, TypedDataField[]>}, 'INVALID_ARGUMENT')
  })

  test('nesting deeper than 64 levels is refused as such, not as a stack overflow', () => {
    const chain: Record<string, TypedDataField[]> = {T: [{name: 'next', type: 'S0'}]}
    for (let index = 0; index < 5000; index++) {
      chain[`S${index}`] = [{name: 'next', type: `S${index + 1}`}]
    }
    chain.S5000 = []
    refused(base(chain, {next: {}}), 'INVALID_ARGUMENT')

    let nested: unknown = 1
    for (let index = 0; index < 5000; index++) {
      nested = [nested]
    }
    refused(base({T: [{name: 'x', type: `uint8${'[]'.repeat(5000)}`}]}, {x: nested}), 'INVALID_ARGUMENT')
    const shallow = base({T: [{name: 'x', type: `uint8${'[]'.repeat(10)}`}]}, {x: [[[[[[[[[[1]]]]]]]]]]})
    assert.ok(ethereum.hashTypedData(shallow))
  })

  test('missing members and values of the wrong type or out of range are refused', () => {
    const one = (type: string, x: unknown) => base({T: [{name: 'x', type}]}, {x})

    refused(base({Person: PERSON, T: [{name: 'p', type: 'Person'}]}, {p: {name: 'Bob'}}), 'INVALID_ARGUMENT')
    refused(one('uint8', undefined), 'INVALID_ARGUMENT')
    refused(base({T: [{name: 'constructor', type: 'uint8'}]}, {}), 'INVALID_ARGUMENT')
    refused(one('uint8', 256), 'INVALID_ARGUMENT')
    refused(one('uint8', -1), 'INVALID_ARGUMENT')
    refused(one('uint256', 2n ** 256n), 'INVALID_ARGUMENT')
    refused(one('int8', 128), 'INVALID_ARGUMENT')
    refused(one('int8', -129), 'INVALID_ARGUMENT')
    refused(one('int256', 2n ** 255n), 'INVALID_ARGUMENT')
    refused(one('uint64', 1.5), 'INVALID_ARGUMENT')
    refused(one('uint64', 2 ** 53), 'INVALID_ARGUMENT')
    refused(one('uint64', '12abc'), 'INVALID_ARGUMENT')
    refused(one('uint64', ''), 'INVALID_ARGUMENT')
    refused(one('uint64', ' 1'), 'INVALID_ARGUMENT')
    refused(one('uint64', true), 'INVALID_ARGUMENT')
    refused(one('bool', 1), 'INVALID_ARGUMENT')
    refused(one('bool', 'true'), 'INVALID_ARGUMENT')
    refused(one('string', 5), 'INVALID_ARGUMENT')
    refused(one('address', '0x1234'), 'INVALID_ADDRESS')
    refused(one('address', '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8Dd826'), 'INVALID_ADDRESS')
    refused(one('address', 5), 'INVALID_ADDRESS')
    refused(one('bytes', 'hello'), 'INVALID_ENCODING')
    refused(one('bytes', '0xabc'), 'INVALID_ENCODING')
    refused(one('bytes', 'abcd'), 'INVALID_ENCODING')
    refused(one('bytes', [1, 2]), 'INVALID_ARGUMENT')
    refused(one('bytes4', '0x010203'), 'INVALID_ARGUMENT')
    refused(one('bytes4', '0x0102030405'), 'INVALID_ARGUMENT')
    refused(one('uint8[2]', [1]), 'INVALID_ARGUMENT')
    refused(one('uint8[2]', [1, 2, 3]), 'INVALID_ARGUMENT')
    refused(one('uint8[]', '0x0102'), 'INVALID_ARGUMENT')
    refused(one('uint8[][2]', [[1], 5]), 'INVALID_ARGUMENT')
    refused(base({Person: PERSON, T: [{name: 'p', type: 'Person'}]}, {p: 'Bob'}), 'INVALID_ARGUMENT')
    refused(base({Person: PERSON, T: [{name: 'p', type: 'Person[]'}]}, {p: [null]}), 'INVALID_ARGUMENT')
    refused({...base({T: []}, {}), message: null as unknown as Record<string, unknown>}, 'INVALID_ARGUMENT')
  })

  test('the domain: at least one field, only EIP-712`s with their types, each declared one present', () => {
    const message = {x: 1}
    const types = {T: [{name: 'x', type: 'uint8'}]}

    refused({domain: {}, message, primaryType: 'T', types}, 'INVALID_ARGUMENT')
    refused({message, primaryType: 'T', types} as TypedDataDefinition, 'INVALID_ARGUMENT')
    refused({domain: 'Test' as never, message, primaryType: 'T', types}, 'INVALID_ARGUMENT')
    refused({domain: {name: 5 as never}, message, primaryType: 'T', types}, 'INVALID_ARGUMENT')
    refused({domain: {chainId: -1}, message, primaryType: 'T', types}, 'INVALID_ARGUMENT')
    refused({domain: {chainId: 'one'}, message, primaryType: 'T', types}, 'INVALID_ARGUMENT')
    refused({domain: {verifyingContract: '0x12'}, message, primaryType: 'T', types}, 'INVALID_ADDRESS')
    refused({domain: {salt: '0x1234'}, message, primaryType: 'T', types}, 'INVALID_ARGUMENT')
    const declared = (EIP712Domain: TypedDataField[], domain = {name: 'Test'}) =>
      refused({domain, message, primaryType: 'T', types: {...types, EIP712Domain}}, 'INVALID_ARGUMENT')
    declared([{name: 'name', type: 'bytes32'}])
    declared([{name: 'chainId', type: 'uint64'}])
    declared([{name: 'owner', type: 'address'}])
    declared([{name: 'version', type: 'string'}])
    declared([])
  })

  test('no error message repeats a value', () => {
    const secret = 'SECRET 4f3c2a VALUE'
    const typedData = (type: string, value: unknown) =>
      ({
        domain: {chainId: 1, name: secret},
        message: {x: value},
        primaryType: 'T',
        types: {T: [{name: 'x', type}]},
      }) as TypedDataDefinition
    const cases: [string, unknown][] = [
      ['uint8', secret],
      ['uint8', 999_999_999],
      ['address', secret],
      ['bytes', secret],
      ['bytes32', '0xdeadbeefcafe'],
      ['bool', secret],
      ['string', {secret}],
      ['uint8[2]', [secret]],
    ]

    for (const [type, value] of cases) {
      assert.throws(
        () => ethereum.hashTypedData(typedData(type, value)),
        error => {
          assert.ok(isCryptoError(error))
          assert.doesNotMatch(error.message, /SECRET|4f3c2a|999999999|deadbeef/)

          return true
        }
      )
    }

    assert.throws(
      () => ethereum.hashTypedData({...typedData('uint8', 1), domain: {chainId: 31_337_031, name: secret}}),
      error => isCryptoError(error, 'CHAIN_MISMATCH') && !error.message.includes('31337031')
    )
  })
})
