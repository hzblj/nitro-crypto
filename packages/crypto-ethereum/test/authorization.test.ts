import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {getAddress, type SignedAuthorization} from 'viem'
import {mnemonicToAccount, privateKeyToAccount} from 'viem/accounts'
import {hashAuthorization, recoverAuthorizationAddress} from 'viem/utils'

import {ethereumAdapter, type Hex, type SignedEthereumAuthorization} from '../src'
import {HARDHAT, random, rejectsCode, SEPOLIA, throwsCode, toHex} from './support'

const crypto = createTestCryptoEngine({
  adapters: [ethereumAdapter(), ethereumAdapter({chainId: SEPOLIA, id: 'sepolia', name: 'Sepolia'})],
})
const {sepolia} = crypto.chains

/** Ours as viem writes a signed authorization. */
const asViem = ({address, chainId, nonce, signature}: SignedEthereumAuthorization): SignedAuthorization => ({
  address,
  chainId,
  nonce: Number(nonce),
  r: toHex(signature.signature.subarray(0, 32)),
  s: toHex(signature.signature.subarray(32)),
  yParity: signature.recovery,
})

const DELEGATE = '0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B'

/** viem's account for the Hardhat mnemonic's address `index`, from its private key (it signs authorizations). */
const viemAccount = (index = 0) => {
  const key = mnemonicToAccount(HARDHAT, {addressIndex: index}).getHdKey().privateKey

  assert.ok(key)

  return privateKeyToAccount(toHex(key))
}

describe('EIP-7702 authorizations', () => {
  test('signatures and digests equal viem`s, and each recovers the other`s signer', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const rng = random(7702)

    for (const index of [0, 2]) {
      const ours = await wallet.deriveAccount({chain: 'sepolia', index})
      const theirs = viemAccount(index)

      for (let run = 0; run < 25; run++) {
        const raw = toHex(rng.bytes(20))
        const address = rng.int(2) === 0 ? raw : getAddress(raw)
        const nonce = rng.pick([0, 1, 127, 128, 2 ** 32, Number.MAX_SAFE_INTEGER, rng.int(1000)])
        const request = {address, nonce}

        const signed = await ours.signAuthorization(rng.int(2) === 0 ? request : {...request, chainId: SEPOLIA})
        const viemSigned = await theirs.signAuthorization({...request, chainId: SEPOLIA})

        assert.equal(signed.address, getAddress(address))
        assert.equal(signed.chainId, SEPOLIA)
        assert.equal(signed.nonce, BigInt(nonce))
        assert.equal(asViem(signed).r, viemSigned.r)
        assert.equal(asViem(signed).s, viemSigned.s)
        assert.equal(signed.signature.recovery, viemSigned.yParity)
        assert.equal(toHex(sepolia.hashAuthorization(request)), hashAuthorization({...request, chainId: SEPOLIA}))

        assert.equal(await recoverAuthorizationAddress({authorization: asViem(signed)}), ours.address)
        assert.equal(sepolia.recoverAuthorizationAddress(signed), ours.address)
        assert.equal(
          sepolia.recoverAuthorizationAddress({
            ...request,
            chainId: SEPOLIA,
            signature: `${viemSigned.r}${viemSigned.s.slice(2)}${viemSigned.yParity ? '1c' : '1b'}` as Hex,
          }),
          ours.address
        )
        assert.notEqual(sepolia.recoverAuthorizationAddress({...signed, nonce: signed.nonce + 1n}), ours.address)
      }
    }
    wallet.dispose()
  })

  test('the largest nonce, 2^64 - 1, is signed; 2^64 is refused', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'sepolia'})
    const signed = await account.signAuthorization({address: DELEGATE, nonce: 2n ** 64n - 1n})

    assert.equal(sepolia.recoverAuthorizationAddress(signed), account.address)
    await rejectsCode(() => account.signAuthorization({address: DELEGATE, nonce: 2n ** 64n}), 'INVALID_ARGUMENT')
    await rejectsCode(() => account.signAuthorization({address: DELEGATE, nonce: -1}), 'INVALID_ARGUMENT')
    await rejectsCode(() => account.signAuthorization({address: '0x1234', nonce: 0}), 'INVALID_ADDRESS')
    await rejectsCode(
      () => account.signAuthorization({address: DELEGATE.replace('63c0', '63C0'), nonce: 0}),
      'INVALID_ADDRESS'
    )
    wallet.dispose()
  })

  test('chain id 0 (every chain) only with allowAllChains; another network`s never', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'sepolia'})
    const theirs = viemAccount()

    await rejectsCode(() => account.signAuthorization({address: DELEGATE, chainId: 0, nonce: 0}), 'CHAIN_MISMATCH')
    await rejectsCode(
      () => account.signAuthorization({address: DELEGATE, allowAllChains: false, chainId: 0n, nonce: 0}),
      'CHAIN_MISMATCH'
    )
    throwsCode(() => sepolia.hashAuthorization({address: DELEGATE, chainId: 0, nonce: 0}), 'CHAIN_MISMATCH')
    await rejectsCode(() => account.signAuthorization({address: DELEGATE, chainId: 1, nonce: 0}), 'CHAIN_MISMATCH')
    await rejectsCode(
      () => account.signAuthorization({address: DELEGATE, allowAllChains: true, chainId: 1, nonce: 0}),
      'CHAIN_MISMATCH'
    )
    await rejectsCode(() => account.signAuthorization({address: DELEGATE, chainId: -1, nonce: 0}), 'INVALID_ARGUMENT')

    const everywhere = await account.signAuthorization({address: DELEGATE, allowAllChains: true, chainId: 0, nonce: 3})
    const viemEverywhere = await theirs.signAuthorization({address: DELEGATE, chainId: 0, nonce: 3})
    assert.equal(everywhere.chainId, 0)
    assert.equal(asViem(everywhere).r, viemEverywhere.r)
    assert.equal(asViem(everywhere).s, viemEverywhere.s)
    // Already signed, it is read and recovered without the opt-in, on any adapter.
    assert.equal(sepolia.recoverAuthorizationAddress(everywhere), account.address)
    assert.equal(crypto.chains.ethereum.recoverAuthorizationAddress(everywhere), account.address)
    throwsCode(
      () => crypto.chains.ethereum.recoverAuthorizationAddress({...everywhere, chainId: SEPOLIA}),
      'CHAIN_MISMATCH'
    )
    wallet.dispose()
  })

  test('a malformed signature recovers no one', () => {
    const authorization = {address: DELEGATE, chainId: SEPOLIA, nonce: 0}

    assert.equal(sepolia.recoverAuthorizationAddress({...authorization, signature: new Uint8Array(65)}), undefined)
    assert.equal(sepolia.recoverAuthorizationAddress({...authorization, signature: '0x1234'}), undefined)
    throwsCode(
      () => sepolia.recoverAuthorizationAddress({...authorization, chainId: undefined as never, signature: '0x'}),
      'INVALID_ARGUMENT'
    )
  })
})
