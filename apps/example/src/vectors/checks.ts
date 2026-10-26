import {hex, type SigningKey, utf8} from '@hzblj/nitro-crypto'

import type {AppCrypto, AppWallet} from '../crypto'

/** The mnemonic of BIP-84's own test vectors, and of most wallets' tests: never a wallet anyone should use. */
export const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

type Context = {readonly crypto: AppCrypto; readonly wallet: AppWallet}

export type VectorCheck = {
  readonly id: string
  readonly title: string
  /** Where the expected value is published. */
  readonly source: string
  readonly expected: string
  /** The value the engine computes, as text to compare with `expected`. */
  readonly run: (context: Context) => Promise<string> | string
}

export type VectorResult = {
  readonly check: VectorCheck
  readonly actual: string
  readonly passed: boolean
  readonly milliseconds: number
}

/** A key that exists only for the duration of one check. */
const withKey = <T>(key: SigningKey, use: (key: SigningKey) => T): T => {
  try {
    return use(key)
  } finally {
    key.dispose()
  }
}

const RFC8032_SECRET = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

export const CHECKS: readonly VectorCheck[] = [
  {
    expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    id: 'sha256',
    run: ({crypto}) => hex.encode(crypto.hash.sha256(utf8.encode('abc'))),
    source: 'FIPS 180-4',
    title: 'SHA-256("abc")',
  },
  {
    expected:
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    id: 'sha512',
    run: ({crypto}) => hex.encode(crypto.hash.sha512(utf8.encode('abc'))),
    source: 'FIPS 180-4',
    title: 'SHA-512("abc")',
  },
  {
    expected: 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    id: 'keccak256',
    run: ({crypto}) => hex.encode(crypto.hash.keccak256(new Uint8Array())),
    source: 'Keccak, as Ethereum uses it',
    title: 'Keccak-256("")',
  },
  {
    expected: '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc',
    id: 'ripemd160',
    run: ({crypto}) => hex.encode(crypto.hash.ripemd160(utf8.encode('abc'))),
    source: 'RIPEMD-160 reference',
    title: 'RIPEMD-160("abc")',
  },
  {
    expected:
      '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    id: 'hmac',
    run: ({crypto}) => hex.encode(crypto.hmac.sha512(utf8.encode('Jefe'), utf8.encode('what do ya want for nothing?'))),
    source: 'RFC 4231, test 2',
    title: 'HMAC-SHA-512',
  },
  {
    expected: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    id: 'ed25519-public',
    run: ({crypto}) =>
      withKey(crypto.keys.importRawSecret('ed25519', hex.decode(RFC8032_SECRET)), key => hex.encode(key.publicKey())),
    source: 'RFC 8032, test 1',
    title: 'Ed25519 public key',
  },
  {
    expected:
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    id: 'ed25519-sign',
    run: ({crypto}) =>
      withKey(crypto.keys.importRawSecret('ed25519', hex.decode(RFC8032_SECRET)), key =>
        key.curve === 'ed25519' ? hex.encode(key.sign(new Uint8Array())) : ''
      ),
    source: 'RFC 8032, test 1',
    title: 'Ed25519 signature of ""',
  },
  {
    expected: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    id: 'secp256k1-generator',
    run: ({crypto}) => {
      const one = new Uint8Array(32)
      one[31] = 1
      return withKey(crypto.keys.importRawSecret('secp256k1', one), key => hex.encode(key.publicKey()))
    },
    source: 'SEC 2: the generator G',
    title: 'secp256k1 public key of 1',
  },
  {
    expected: 'recovers its signer',
    id: 'secp256k1-recover',
    run: ({crypto}) =>
      withKey(crypto.keys.generate('secp256k1'), key => {
        if (key.curve !== 'secp256k1') {
          return ''
        }
        const digest = crypto.random(32)
        const recovered = crypto.secp256k1.recover(digest, key.sign(digest))
        return hex.encode(recovered) === hex.encode(key.publicKey()) ? 'recovers its signer' : 'another key'
      }),
    source: 'RFC 6979 nonce, lower S',
    title: 'secp256k1 sign and recover',
  },
  {
    expected: '73c5da0a',
    id: 'bip39',
    run: ({wallet}) => wallet.fingerprint.toString(16).padStart(8, '0'),
    source: 'BIP-39 + BIP-32',
    title: 'Fingerprint of "abandon … about"',
  },
  {
    expected: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94',
    id: 'ethereum',
    run: async ({wallet}) => (await wallet.deriveAccount({chain: 'ethereum'})).address,
    source: "BIP-44 m/44'/60'/0'/0/0, EIP-55",
    title: 'Ethereum address',
  },
  {
    expected: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
    id: 'bitcoin',
    run: async ({wallet}) => (await wallet.deriveAccount({chain: 'bitcoin'})).address,
    source: 'BIP-84 test vector',
    title: 'Bitcoin address',
  },
  {
    expected: 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk',
    id: 'solana',
    run: async ({wallet}) => (await wallet.deriveAccount({chain: 'solana'})).address,
    source: "SLIP-0010 m/44'/501'/0'/0'",
    title: 'Solana address',
  },
  {
    expected: 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH',
    id: 'tron',
    run: async ({wallet}) => (await wallet.deriveAccount({chain: 'tron'})).address,
    source: "BIP-44 m/44'/195'/0'/0/0",
    title: 'TRON address (this app’s adapter)',
  },
  {
    expected: 'verifies',
    id: 'eip191',
    run: async ({crypto, wallet}) => {
      const account = await wallet.deriveAccount({chain: 'ethereum'})
      const signature = await account.signMessage({message: 'Hello from Expo'})
      const recovered = crypto.chains.ethereum.recoverMessageAddress({message: 'Hello from Expo', signature})
      return recovered === account.address ? 'verifies' : `recovers ${recovered ?? 'nothing'}`
    },
    source: 'EIP-191 personal_sign',
    title: 'Ethereum message signature',
  },
]

/**
 * Every check, in order, against a wallet of its own made from the test mnemonic and disposed afterwards: nothing it
 * derives outlives the run.
 */
export const runChecks = async (crypto: AppCrypto): Promise<VectorResult[]> => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: TEST_MNEMONIC})
  const results: VectorResult[] = []
  try {
    for (const check of CHECKS) {
      const started = performance.now()
      let actual: string
      try {
        actual = await check.run({crypto, wallet})
      } catch (error) {
        actual = error instanceof Error ? error.message : String(error)
      }
      results.push({actual, check, milliseconds: performance.now() - started, passed: actual === check.expected})
    }
  } finally {
    wallet.dispose()
  }
  return results
}
