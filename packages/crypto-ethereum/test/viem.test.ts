import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {isCryptoError} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {
  type Account,
  type Chain,
  createWalletClient,
  custom,
  keccak256,
  numberToHex,
  parseTransaction,
  type SerializeTransactionFn,
  type TransactionSerializable,
} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {base, sepolia as sepoliaChain} from 'viem/chains'

import {type EthereumAccount, ethereumAdapter, type Hex} from '../src'
import {toViemAccount} from '../src/viem'
import {HARDHAT, HARDHAT_KEY, keySourceOf, SEPOLIA} from './support'

const crypto = createTestCryptoEngine({
  adapters: [
    ethereumAdapter({chainId: SEPOLIA, id: 'sepolia', name: 'Sepolia'}),
    ethereumAdapter({chainId: 8453, id: 'base', name: 'Base'}),
  ],
})

const DELEGATE = '0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B'
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
const INIT_CODE =
  '0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea164736f6c6343000818000a'

/**
 * A node that answers what viem asks while preparing a transaction, the same way every time, and keeps what it is
 * asked to broadcast.
 */
const node = (chain: Chain) => {
  const sent: Hex[] = []
  const transport = custom({
    request: async ({method, params}: {method: string; params?: unknown}) => {
      switch (method) {
        case 'eth_chainId':
          return numberToHex(chain.id)
        case 'eth_getTransactionCount':
          return '0x7'
        case 'eth_estimateGas':
          return '0x186a0'
        case 'eth_gasPrice':
          return '0x3b9aca00'
        case 'eth_maxPriorityFeePerGas':
          return '0x59682f00'
        case 'eth_getBlockByNumber':
          return {
            baseFeePerGas: '0x3b9aca00',
            difficulty: '0x0',
            gasLimit: '0x1c9c380',
            gasUsed: '0x0',
            hash: `0x${'11'.repeat(32)}`,
            number: '0x10',
            timestamp: '0x6553f100',
            transactions: [],
          }
        case 'eth_sendRawTransaction': {
          const [raw] = params as [Hex]
          sent.push(raw)

          return keccak256(raw)
        }
        default:
          throw new Error(`The test node does not answer ${method}.`)
      }
    },
  })

  return {sent, transport}
}

const clientFor = (account: Account, chain: Chain) => {
  const {sent, transport} = node(chain)

  return {client: createWalletClient({account, chain, transport}), sent}
}

const accountFor = async (chain: 'sepolia' | 'base'): Promise<EthereumAccount> => {
  const key = crypto.keys.importRawSecret('secp256k1', Buffer.from(HARDHAT_KEY.slice(2), 'hex'))

  return crypto.chains[chain].deriveAccount(keySourceOf(key), {index: 0})
}

/** The same calls through both accounts: everything each one broadcast or returned. */
const both = async <T>(
  chain: Chain,
  ours: Account,
  run: (client: ReturnType<typeof clientFor>['client']) => Promise<T>
) => {
  const mine = clientFor(ours, chain)
  const reference = clientFor(privateKeyToAccount(HARDHAT_KEY), chain)

  return {
    ours: {result: await run(mine.client), sent: mine.sent},
    theirs: {result: await run(reference.client), sent: reference.sent},
  }
}

describe('viem bridge', () => {
  test('a LocalAccount with the account`s address and public key, and no raw-hash sign', async () => {
    const account = await accountFor('sepolia')
    const viemAccount = toViemAccount(account)
    const reference = privateKeyToAccount(HARDHAT_KEY)

    assert.equal(viemAccount.address, reference.address)
    assert.equal(viemAccount.publicKey, reference.publicKey)
    assert.equal(viemAccount.type, 'local')
    assert.equal(viemAccount.source, 'nitro-crypto')
    assert.equal(viemAccount.sign, undefined)

    // The same key from the Hardhat mnemonic.
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    assert.equal(toViemAccount(await wallet.deriveAccount({chain: 'sepolia'})).address, reference.address)
    wallet.dispose()
  })

  test('sendTransaction through a wallet client broadcasts exactly what privateKeyToAccount`s would', async () => {
    const ours = toViemAccount(await accountFor('sepolia'))
    const authorization = await createWalletClient({
      account: privateKeyToAccount(HARDHAT_KEY),
      chain: sepoliaChain,
      transport: node(sepoliaChain).transport,
    }).signAuthorization({address: DELEGATE, executor: 'self'})
    const calls = [
      // EIP-1559, every field from the node.
      {to: RECIPIENT, value: 10n ** 15n},
      // An ERC-20 style call with explicit fees and nonce.
      {data: '0xa9059cbb', maxFeePerGas: 3n * 10n ** 9n, maxPriorityFeePerGas: 10n ** 9n, nonce: 12, to: RECIPIENT},
      {gasPrice: 2n * 10n ** 9n, to: RECIPIENT, type: 'legacy', value: 1n},
      {
        accessList: [{address: RECIPIENT, storageKeys: [`0x${'00'.repeat(31)}01`]}],
        gasPrice: 2n * 10n ** 9n,
        to: RECIPIENT,
        type: 'eip2930',
      },
      {accessList: [{address: DELEGATE, storageKeys: []}], to: RECIPIENT, type: 'eip1559'},
      // Contract creation: no `to`, init code in data.
      {data: INIT_CODE},
      {data: INIT_CODE, gasPrice: 10n ** 9n, type: 'legacy'},
      // EIP-7702, the account authorizing itself.
      {authorizationList: [authorization], to: privateKeyToAccount(HARDHAT_KEY).address},
    ] as const

    for (const call of calls) {
      const {ours: mine, theirs} = await both(sepoliaChain, ours, client => client.sendTransaction(call as never))
      assert.equal(mine.sent.length, 1)
      assert.deepEqual(mine.sent, theirs.sent)
      assert.equal(mine.result, theirs.result)
    }
  })

  test('signTypedData, signMessage and signAuthorization through a client equal privateKeyToAccount`s', async () => {
    const ours = toViemAccount(await accountFor('sepolia'))
    const typedData = {
      domain: {chainId: SEPOLIA, name: 'Permit2', verifyingContract: '0x000000000022D473030F116dDEE9F6B43aC78BA3'},
      message: {
        details: {amount: 10n ** 6n, expiration: 1_900_000_000, nonce: 0, token: RECIPIENT},
        sigDeadline: 1_900_000_000n,
        spender: DELEGATE,
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
    } as const

    const typed = await both(sepoliaChain, ours, client => client.signTypedData(typedData))
    assert.equal(typed.ours.result, typed.theirs.result)

    for (const message of ['Hello from Expo', {raw: '0x00ff' as const}, {raw: new Uint8Array([1, 2, 3])}]) {
      const signed = await both(sepoliaChain, ours, client => client.signMessage({message}))
      assert.equal(signed.ours.result, signed.theirs.result)
    }

    for (const parameters of [
      {address: DELEGATE},
      {contractAddress: DELEGATE, nonce: 40},
      {address: DELEGATE, executor: 'self'},
    ]) {
      const signed = await both(sepoliaChain, ours, client => client.signAuthorization(parameters as never))
      assert.deepEqual(signed.ours.result, signed.theirs.result)
    }
  })

  test('chain ids: another network`s is refused; authorizations for chain id 0 only with allowAllChains', async () => {
    const account = await accountFor('sepolia')
    const ours = toViemAccount(account)
    const reference = privateKeyToAccount(HARDHAT_KEY)
    const refused = (error: unknown, code: string) => {
      // viem wraps an account's error in its own; the CryptoError is its cause.
      let cause = error

      while (cause && !isCryptoError(cause)) {
        cause = (cause as {cause?: unknown}).cause
      }

      return isCryptoError(cause) && cause.code === code
    }

    await assert.rejects(
      () => ours.signAuthorization?.({address: DELEGATE, chainId: 0, nonce: 0}) ?? Promise.resolve(),
      error => refused(error, 'CHAIN_MISMATCH')
    )
    const everywhere = toViemAccount(account, {allowAllChains: true})
    assert.deepEqual(
      await everywhere.signAuthorization?.({address: DELEGATE, chainId: 0, nonce: 0}),
      await reference.signAuthorization({address: DELEGATE, chainId: 0, nonce: 0})
    )

    await assert.rejects(
      () => ours.signTransaction({chainId: 1, gas: 21000n, maxFeePerGas: 1n, nonce: 0, to: RECIPIENT}),
      error => refused(error, 'CHAIN_MISMATCH')
    )
    await assert.rejects(
      () =>
        createWalletClient({account: ours, chain: base, transport: node(base).transport}).sendTransaction({
          to: RECIPIENT,
        }),
      error => refused(error, 'CHAIN_MISMATCH')
    )
    await assert.rejects(
      () =>
        ours.signTypedData({
          domain: {chainId: 1, name: 'x'},
          message: {a: 1},
          primaryType: 'T',
          types: {T: [{name: 'a', type: 'uint8'}]},
        }),
      error => refused(error, 'CHAIN_MISMATCH')
    )
  })

  test('what viem would sign differently or this adapter does not sign is refused', async () => {
    const ours = toViemAccount(await accountFor('sepolia'))
    const refused = (transaction: TransactionSerializable, code: string, serializer?: SerializeTransactionFn) =>
      assert.rejects(
        () => ours.signTransaction(transaction, {serializer}),
        error => isCryptoError(error) && error.code === code
      )
    const transfer = {
      chainId: SEPOLIA,
      gas: 21000n,
      maxFeePerGas: 2n,
      maxPriorityFeePerGas: 1n,
      nonce: 0,
      to: RECIPIENT,
    } as const

    // A legacy transaction without a chain id: viem would sign it without replay protection.
    await refused({gas: 21000n, gasPrice: 1n, nonce: 0, to: RECIPIENT}, 'INVALID_ARGUMENT')
    await refused({...transfer, blobVersionedHashes: [`0x01${'00'.repeat(31)}`], maxFeePerBlobGas: 1n}, 'UNSUPPORTED')
    await refused({...transfer, type: 'deposit'} as never, 'UNSUPPORTED')
    await refused({chainId: SEPOLIA, gas: 21000n, nonce: 0, to: RECIPIENT}, 'INVALID_ARGUMENT')
    await refused({...transfer, authorizationList: [], to: undefined, type: 'eip7702'}, 'INVALID_ARGUMENT')
    await refused({...transfer, to: undefined}, 'INVALID_ARGUMENT')
    await refused({...transfer, gasPrice: 1n, type: 'legacy'} as never, 'INVALID_ARGUMENT')
    // A gas price on an EIP-1559 transaction is ignored, as viem's serializer ignores it.
    assert.equal(
      await ours.signTransaction({...transfer, gasPrice: 1n} as never),
      await privateKeyToAccount(HARDHAT_KEY).signTransaction({...transfer, gasPrice: 1n} as never)
    )

    // A serializer that writes something else than the standard envelope, unsigned or signed.
    const appended: SerializeTransactionFn = async (transaction, signature) =>
      `${(await import('viem')).serializeTransaction(transaction, signature)}00` as never
    await refused(transfer, 'UNSUPPORTED', appended)
    const signedOnly: SerializeTransactionFn = async (transaction, signature) =>
      `${(await import('viem')).serializeTransaction(transaction, signature)}${signature ? '00' : ''}` as never
    await refused(transfer, 'UNSUPPORTED', signedOnly)
  })

  test('an OP Stack chain`s serializer (Base): standard types are signed as viem signs them, deposits refused', async () => {
    const ours = toViemAccount(await accountFor('base'))
    const serializer = base.serializers?.transaction as SerializeTransactionFn

    const sent = await both(base, ours, client => client.sendTransaction({to: RECIPIENT, value: 1n}))
    assert.deepEqual(sent.ours.sent, sent.theirs.sent)
    assert.equal(parseTransaction(sent.ours.sent[0] ?? '0x').chainId, 8453)

    const transfer = {
      chainId: 8453,
      gas: 21000n,
      maxFeePerGas: 2n,
      maxPriorityFeePerGas: 1n,
      nonce: 0,
      to: RECIPIENT,
    } as const
    assert.equal(
      await ours.signTransaction(transfer, {serializer}),
      await privateKeyToAccount(HARDHAT_KEY).signTransaction(transfer, {serializer})
    )
    await assert.rejects(
      () =>
        ours.signTransaction(
          {
            from: RECIPIENT,
            gas: 21000n,
            mint: 1n,
            sourceHash: `0x${'22'.repeat(32)}`,
            to: RECIPIENT,
            type: 'deposit',
          } as never,
          {serializer}
        ),
      error => isCryptoError(error, 'UNSUPPORTED')
    )
  })
})
