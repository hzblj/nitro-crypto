import {
  type AdapterContext,
  type ChainAdapter,
  CryptoError,
  defineAdapter,
  type ExtendedPublicKey,
  type KeySource,
} from '@hzblj/nitro-crypto/adapter'

import {type BitcoinAccount, type BitcoinWatchAccount, createAccount, createWatchAccount} from './account'
import {type BitcoinAddressValidation, p2wpkhAddress, validateAddress} from './address'
import {type BitcoinNetwork, type BitcoinNetworkName, NETWORKS} from './networks'
import {type BitcoinAccountRequest, checkPath, derivationPath} from './path'
import {type BitcoinPsbt, decodePsbt, finalizePsbt} from './psbt'
import {dustThreshold, type SignedBitcoinTransaction} from './transaction'
import {VERSION} from './version'

/** A key the wallet does not hold: its public half, and where it came from. */
export type BitcoinWatchRequest =
  | {
      /** SEC1, 33 bytes compressed (65 uncompressed is compressed first). */
      readonly publicKey: Uint8Array
      /** The path it was derived at, `m/84'/1'/0'/0/0`: what a PSBT tells its signer. */
      readonly path: string
      /** The BIP-32 fingerprint of the master key the path starts from. */
      readonly fingerprint: number
    }
  | {
      /**
       * An account's extended public key, as a hardware wallet or another signer shares it (`m/84'/1'/0'`): the
       * address at `change`/`index` below it is derived publicly, by the engine.
       */
      readonly extendedKey: ExtendedPublicKey
      /** The extended key's own path, `m/84'/1'/0'`. */
      readonly path: string
      readonly fingerprint: number
      /** 0 (receiving, the default) or 1 (change). */
      readonly change?: 0 | 1
      /** 0 unless stated. */
      readonly index?: number
    }

export type BitcoinConfig<Id extends string = 'bitcoin'> = {
  /** The id it registers under: `bitcoin`, or one per network to register several (`bitcoin-testnet`). */
  readonly id?: Id
  /** Mainnet unless stated. Addresses, paths and validation all follow it. */
  readonly network?: BitcoinNetworkName
  /** For people. Defaults to "Bitcoin", or "Bitcoin testnet" and so on. */
  readonly name?: string
}

/** Bitcoin, bound to an engine: `crypto.chains.bitcoin`. */
export type BitcoinChain<Id extends string = 'bitcoin'> = {
  readonly network: BitcoinNetwork
  readonly deriveAccount: (keys: KeySource, request: BitcoinAccountRequest) => Promise<BitcoinAccount<Id>>
  /** Any address this network can pay, with its type and the script that pays it. */
  readonly validateAddress: (address: string) => BitcoinAddressValidation
  /** The P2WPKH address of a compressed public key on this network. */
  readonly addressFromPublicKey: (publicKey: Uint8Array) => string
  /**
   * The smallest amount in satoshis an output to `address` may carry for nodes to relay it (Bitcoin Core's dust limit
   * at 3 sat/vB): 294 for P2WPKH, 330 for P2WSH and P2TR, 546 for P2PKH. Throws `INVALID_ADDRESS` for anything that
   * is not an address of this network.
   */
  readonly dustThreshold: (address: string) => bigint
  /**
   * An account of a key held elsewhere (an air-gapped signer, a hardware wallet): its address, payments planned from
   * it, and PSBTs for its signer. Throws `INVALID_PUBLIC_KEY` for a key that is not a point, `INVALID_PATH` for a path
   * that is not one, and `INVALID_ARGUMENT` for a fingerprint that is not 32 bits.
   */
  readonly watchAccount: (request: BitcoinWatchRequest) => BitcoinWatchAccount<Id>
  /**
   * What a PSBT asks: the coins it spends (with their addresses and whether their values can be checked), the
   * outputs and their addresses, the fee, and the signatures so far. Strict BIP-174 version 0; anything malformed is
   * `INVALID_ARGUMENT`.
   */
  readonly decodePsbt: (psbt: Uint8Array) => BitcoinPsbt
  /**
   * The transaction to broadcast from a PSBT whose every input is a signed P2WPKH coin. Each signature is verified by
   * the engine, against the key its coin pays, before it becomes a witness: one that fails is `INVALID_SIGNATURE`.
   */
  readonly finalizePsbt: (psbt: Uint8Array) => SignedBitcoinTransaction
  /**
   * BIP-32 public derivation, the engine's: the extended key `path` below `key`, every step non-hardened (`m/0/5`).
   * `UNSUPPORTED` on an engine without it.
   */
  readonly derivePublic: (key: ExtendedPublicKey, path: string) => ExtendedPublicKey
}

const createChain = <Id extends string>(context: AdapterContext, id: Id, network: BitcoinNetwork): BitcoinChain<Id> => {
  const derivePublic = (key: ExtendedPublicKey, path: string) => {
    if (!context.engine.has('bip32-public-derivation')) {
      throw new CryptoError('UNSUPPORTED', 'This engine has no BIP-32 public derivation.')
    }

    return context.bip32.derivePublic(key, path)
  }

  return Object.freeze({
    addressFromPublicKey: (publicKey: Uint8Array) =>
      p2wpkhAddress(publicKey, network, context.hash.sha256, context.hash.ripemd160).address,
    decodePsbt: (psbt: Uint8Array) => decodePsbt(psbt, network, context.hash.sha256),
    deriveAccount: async (keys: KeySource, request: BitcoinAccountRequest) =>
      createAccount(context, id, network, keys.deriveKey('bip32', derivationPath(request, network)), keys.fingerprint),
    derivePublic,
    dustThreshold: (address: string) => {
      const result = validateAddress(address, network, context.hash.sha256)

      if (!result.valid) {
        throw new CryptoError('INVALID_ADDRESS', result.reason)
      }

      return dustThreshold(result.scriptPubKey)
    },
    finalizePsbt: (psbt: Uint8Array) =>
      finalizePsbt(psbt, {
        network,
        ripemd160: context.hash.ripemd160,
        sha256: context.hash.sha256,
        verify: context.secp256k1.verify,
      }),
    network,
    validateAddress: (address: string) => validateAddress(address, network, context.hash.sha256),
    watchAccount: (request: BitcoinWatchRequest) => {
      const {fingerprint} = request

      if (!Number.isInteger(fingerprint) || fingerprint < 0 || fingerprint > 0xffffffff) {
        throw new CryptoError('INVALID_ARGUMENT', 'A fingerprint is a 32-bit unsigned integer.')
      }

      if ('publicKey' in request) {
        const compressed = context.secp256k1.convertPublicKey(request.publicKey, 'compressed')

        return createWatchAccount(context, id, network, compressed, checkPath(request.path), fingerprint)
      }

      const {change = 0, extendedKey, index = 0} = request
      const accountPath = checkPath(request.path)

      if (extendedKey.depth !== accountPath.split('/').length - 1) {
        throw new CryptoError('INVALID_ARGUMENT', 'The extended key is not at the depth its path says.')
      }

      if (change !== 0 && change !== 1) {
        throw new CryptoError('INVALID_ARGUMENT', 'The change index is 0 (receiving) or 1 (change).')
      }

      const relative = `m/${change}/${index}`
      const leaf = derivePublic(extendedKey, relative)

      return createWatchAccount(
        context,
        id,
        network,
        leaf.publicKey,
        checkPath(`${accountPath}/${change}/${index}`),
        fingerprint
      )
    },
  })
}

/**
 * Bitcoin: native SegWit (P2WPKH) accounts at BIP-84 paths on mainnet, testnet, signet or regtest, validation of
 * every address type, payments from an account (coin selection, fees and BIP-143 signatures), and PSBTs (BIP-174) for
 * keys held elsewhere: watch-only accounts write them, accounts sign them, the chain checks and finalizes them.
 * Message signing (BIP-322) and Taproot (BIP-86, Schnorr) are later capabilities, and `features` says so.
 */
export const bitcoinAdapter = <const Id extends string = 'bitcoin'>(
  config: BitcoinConfig<Id> = {}
): ChainAdapter<NoInfer<Id>, BitcoinChain<NoInfer<Id>>> => {
  const network = NETWORKS[config.network ?? 'mainnet']

  if (!network) {
    throw new CryptoError('INVALID_CONFIG', 'A Bitcoin network is mainnet, testnet, signet or regtest.')
  }

  const name = config.name ?? (network.name === 'mainnet' ? 'Bitcoin' : `Bitcoin ${network.name}`)

  if (name.trim() === '') {
    throw new CryptoError('INVALID_CONFIG', 'A Bitcoin adapter needs a name.')
  }

  const id = (config.id ?? 'bitcoin') as Id

  return defineAdapter({
    create: (context: AdapterContext) => createChain(context, id, network),
    curve: 'secp256k1',
    features: {messageSigning: false, psbt: true, taproot: false, transactionSigning: true},
    formats: {address: ['bech32-p2wpkh'], signature: ['p2wpkh-bip143']},
    id,
    name,
    requires: ['sha256', 'ripemd160', 'bip32-secp256k1'],
    version: VERSION,
  })
}
