import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {type AnyAdapter, defineAdapter, hex, isCryptoError} from '../src/adapter'
import {CAPABILITIES} from '../src/engine/info'
import {createTestCryptoEngine} from '../src/testing'
import {ABANDON} from './support'

/** Two toy chains with different request and account shapes, written only against `@hzblj/nitro-crypto/adapter`. */
const alphaAdapter = () =>
  defineAdapter({
    create: context => ({
      deriveAccount: async (keys, request: {index: number}) => {
        const key = keys.deriveKey('bip32', `m/0/${request.index}`)
        return {address: hex.encode(context.hash.sha256(key.publicKey()).subarray(0, 8)), kind: 'alpha' as const}
      },
      greet: () => 'alpha',
      validateAddress: (address: string) =>
        hex.isHex(address) && address.length === 16
          ? {normalized: address.toLowerCase(), valid: true as const}
          : {reason: 'Not 8 bytes of hex.', valid: false as const},
    }),
    curve: 'secp256k1',
    features: {messageSigning: false},
    formats: {address: ['alpha-hex'], signature: []},
    id: 'alpha',
    name: 'Alpha',
    requires: ['sha256', 'bip32-secp256k1'],
    version: '1.0.0',
  })

const betaAdapter = (id = 'beta' as const) =>
  defineAdapter({
    create: () => ({
      deriveAccount: async (keys, _request: {readonly memo?: string}) => ({
        kind: 'beta' as const,
        publicKey: keys.deriveKey('slip10', "m/0'").publicKey(),
      }),
      validateAddress: () => ({reason: 'Beta has no addresses.', valid: false as const}),
    }),
    curve: 'ed25519',
    features: {},
    formats: {address: [], signature: []},
    id,
    name: 'Beta',
    requires: ['slip10-ed25519'],
    version: '1.0.0',
  })

const fails = (run: () => unknown, code: string, mention?: string) =>
  assert.throws(
    run,
    error => isCryptoError(error) && error.code === code && (!mention || error.message.includes(mention)),
    `${code}${mention ? ` mentioning ${mention}` : ''}`
  )

describe('registration', () => {
  test('registers adapters by id, typed, with their descriptions', async () => {
    const crypto = createTestCryptoEngine({adapters: [alphaAdapter(), betaAdapter()]})
    assert.deepEqual(
      crypto.adapters.map(adapter => adapter.id),
      ['alpha', 'beta']
    )
    assert.equal('create' in (crypto.adapters[0] ?? {}), false)
    assert.ok(Object.isFrozen(crypto.chains))
    assert.equal(crypto.chains.alpha.greet(), 'alpha')

    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const alpha = await wallet.deriveAccount({chain: 'alpha', index: 3})
    const beta = await wallet.deriveAccount({chain: 'beta'})
    assert.equal(alpha.kind, 'alpha')
    assert.equal(alpha.address.length, 16)
    assert.equal(beta.publicKey.length, 32)
    wallet.dispose()
  })

  test('an engine without adapters still does everything else', () => {
    const crypto = createTestCryptoEngine()
    assert.deepEqual(crypto.adapters, [])
    assert.deepEqual(Object.keys(crypto.chains), [])
    assert.equal(crypto.hash.sha256(new Uint8Array()).length, 32)
  })

  test('duplicate ids are refused, naming the id', () => {
    fails(() => createTestCryptoEngine({adapters: [alphaAdapter(), alphaAdapter()]}), 'DUPLICATE_ADAPTER', '"alpha"')
  })

  test('a missing capability is refused, naming it and the adapter', () => {
    const needy = {...alphaAdapter(), id: 'needy', requires: ['sha256', 'schnorr-bip340']} as unknown as AnyAdapter
    fails(() => createTestCryptoEngine({adapters: [needy]}), 'MISSING_CAPABILITY', 'schnorr-bip340')
  })

  test('an adapter needing every capability the engine has registers', () => {
    const greedy = {...alphaAdapter(), id: 'greedy', requires: [...CAPABILITIES]}
    assert.doesNotThrow(() => createTestCryptoEngine({adapters: [greedy]}))
  })

  test('malformed adapters are refused before any is bound', () => {
    let bound = false
    const watched = {
      ...betaAdapter(),
      create: () => (
        (bound = true), {deriveAccount: async () => 0, validateAddress: () => ({reason: '', valid: false as const})}
      ),
    }
    const cases: [Partial<AnyAdapter>, string][] = [
      [{id: 'Alpha'}, 'the id'],
      [{id: '9lives'}, 'the id'],
      [{name: ''}, 'name'],
      [{version: ''}, 'version'],
      [{curve: 'p256' as 'ed25519'}, 'curve'],
      [{requires: 'sha256' as unknown as []}, 'requires'],
      [{formats: {address: [], signature: 'x' as unknown as []}}, 'formats'],
      [{create: undefined as unknown as AnyAdapter['create']}, 'create'],
    ]
    for (const [override, mention] of cases) {
      const broken = {...alphaAdapter(), ...override} as AnyAdapter
      fails(() => createTestCryptoEngine({adapters: [watched, broken]}), 'INVALID_ADAPTER', mention)
    }
    assert.equal(bound, false)
  })

  test('a create that returns no client is refused', () => {
    const empty = {...alphaAdapter(), create: () => ({})} as unknown as AnyAdapter
    fails(() => createTestCryptoEngine({adapters: [empty]}), 'INVALID_ADAPTER', 'deriveAccount')
  })

  test('an id that arrives as data and names no adapter is UNKNOWN_CHAIN', async () => {
    const crypto = createTestCryptoEngine({adapters: [alphaAdapter()]})
    const wallet = await crypto.createEphemeralWallet()
    await assert.rejects(
      () => wallet.deriveAccount({chain: 'gamma'} as never),
      error => isCryptoError(error, 'UNKNOWN_CHAIN')
    )
    wallet.dispose()
  })

  test('the same adapter registers twice under different ids', () => {
    const crypto = createTestCryptoEngine({adapters: [betaAdapter(), betaAdapter('beta-test' as 'beta')]})
    assert.equal(crypto.adapters.length, 2)
  })
})

/** Compile-time checks: `yarn tsc:check` type-checks this function; the test only makes sure it is referenced. */
export const inference = async () => {
  const crypto = createTestCryptoEngine({adapters: [alphaAdapter(), betaAdapter()]})
  const wallet = await crypto.createEphemeralWallet()

  const alpha: {address: string; kind: 'alpha'} = await wallet.deriveAccount({chain: 'alpha', index: 0})
  const beta: {kind: 'beta'; publicKey: Uint8Array} = await wallet.deriveAccount({chain: 'beta', memo: 'x'})
  const greeting: string = crypto.chains.alpha.greet()

  // @ts-expect-error: alpha needs an index
  await wallet.deriveAccount({chain: 'alpha'})
  // @ts-expect-error: no adapter has this id
  await wallet.deriveAccount({chain: 'gamma'})
  // @ts-expect-error: beta's account has no address
  void (await wallet.deriveAccount({chain: 'beta'})).address
  // @ts-expect-error: no chain gamma
  void crypto.chains.gamma

  return [alpha, beta, greeting]
}

test('the inference checks are compiled', () => {
  assert.equal(typeof inference, 'function')
})
