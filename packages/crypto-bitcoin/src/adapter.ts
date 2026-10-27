import {
  type AdapterContext,
  type Capability,
  type ChainAdapter,
  CryptoError,
  defineAdapter,
  type ExtendedPublicKey,
  type KeySource,
} from '@hzblj/nitro-crypto/adapter'

import {
  accountOutput,
  type BitcoinAccount,
  type BitcoinWatchAccount,
  createAccount,
  createWatchAccount,
} from './account'
import {type BitcoinAccountType, type BitcoinAddressValidation, validateAddress} from './address'
import {type BitcoinMessage, type MessageContext, verifyMessage} from './message'
import {type BitcoinNetwork, type BitcoinNetworkName, NETWORKS} from './networks'
import {accountType, type BitcoinAccountRequest, checkPath, derivationPath} from './path'
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
      /** `p2wpkh` (the default) or `p2tr`: BIP-86's Taproot output of the key. */
      readonly addressType?: BitcoinAccountType
    }
  | {
      /**
       * An account's extended public key, as a hardware wallet or another signer shares it (`m/84'/1'/0'`, or
       * `m/86'/1'/0'` for Taproot): the address at `change`/`index` below it is derived publicly, by the engine.
       */
      readonly extendedKey: ExtendedPublicKey
      /** The extended key's own path, `m/84'/1'/0'`. */
      readonly path: string
      readonly fingerprint: number
      /** 0 (receiving, the default) or 1 (change). */
      readonly change?: 0 | 1
      /** 0 unless stated. */
      readonly index?: number
      /** `p2wpkh` (the default) or `p2tr`: BIP-86's Taproot output of each key. */
      readonly addressType?: BitcoinAccountType
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
  /** Any address this network can pay, with its type and the script that pays it (Taproot's Bech32m included). */
  readonly validateAddress: (address: string) => BitcoinAddressValidation
  /**
   * The address of a public key on this network: P2WPKH of a compressed key (the default), or with `p2tr` the BIP-86
   * Taproot address of a key with no script tree (SEC1, or x-only 32 bytes), its tweak the engine's. Throws
   * `INVALID_PUBLIC_KEY` for a key that is not one, and `UNSUPPORTED` for `p2tr` on an engine without `taproot-tweak`.
   */
  readonly addressFromPublicKey: (publicKey: Uint8Array, addressType?: BitcoinAccountType) => string
  /**
   * Whether `signature` (Base64 text) is a signature of `message` by `address`: BIP-322's simple form, prefixed `smp`
   * or not, for P2WPKH and Taproot (key path) addresses, and the legacy "Bitcoin Signed Message" (BIP-137, and
   * Electrum's headers) for P2PKH, P2SH-P2WPKH and P2WPKH. A malformed or wrong signature is `false`. Throws
   * `INVALID_ADDRESS` for an address that is not one of this network, and `UNSUPPORTED` for what this cannot decide:
   * BIP-322's full and proof-of-funds forms, script addresses (P2WSH), Taproot script paths, and Taproot on an
   * engine without `secp256k1-schnorr`.
   */
  readonly verifyMessage: (request: {
    readonly address: string
    readonly message: BitcoinMessage
    readonly signature: string
  }) => boolean
  /**
   * The smallest amount in satoshis an output to `address` may carry for nodes to relay it (Bitcoin Core's dust limit
   * at 3 sat/vB): 294 for P2WPKH, 330 for P2WSH and P2TR, 546 for P2PKH. Throws `INVALID_ADDRESS` for anything that
   * is not an address of this network.
   */
  readonly dustThreshold: (address: string) => bigint
  /**
   * An account of a key held elsewhere (an air-gapped signer, a hardware wallet): its address, payments planned from
   * it, and PSBTs for its signer, P2WPKH or (with `addressType: 'p2tr'`) Taproot. Throws `INVALID_PUBLIC_KEY` for a
   * key that is not a point, `INVALID_PATH` for a path that is not one, `INVALID_ARGUMENT` for a fingerprint that is
   * not 32 bits, and `UNSUPPORTED` for Taproot on an engine without `taproot-tweak`.
   */
  readonly watchAccount: (request: BitcoinWatchRequest) => BitcoinWatchAccount<Id>
  /**
   * What a PSBT asks: the coins it spends (with their addresses and whether their values can be checked), the
   * outputs and their addresses, the fee, and the signatures so far. Strict BIP-174 version 0; anything malformed is
   * `INVALID_ARGUMENT`.
   */
  readonly decodePsbt: (psbt: Uint8Array) => BitcoinPsbt
  /**
   * The transaction to broadcast from a PSBT whose every input is a signed P2WPKH or Taproot (key path) coin, of any
   * accounts, or one its signer already finalized. Each signature is verified by the engine, against the key its coin
   * pays, before it becomes a witness: one that fails is `INVALID_SIGNATURE`. Taproot inputs need an engine with
   * `secp256k1-schnorr` (`UNSUPPORTED` otherwise).
   */
  readonly finalizePsbt: (psbt: Uint8Array) => SignedBitcoinTransaction
  /**
   * BIP-32 public derivation, the engine's: the extended key `path` below `key`, every step non-hardened (`m/0/5`).
   * `UNSUPPORTED` on an engine without it.
   */
  readonly derivePublic: (key: ExtendedPublicKey, path: string) => ExtendedPublicKey
}

/**
 * Taproot needs two capabilities an engine from before them lacks, and P2WPKH needs neither: the adapter does not
 * require them, so it registers on such an engine, and what needs them throws `UNSUPPORTED` when it is asked for.
 */
const TAPROOT: readonly Capability[] = ['secp256k1-schnorr', 'taproot-tweak']

const requireCapabilities = (context: AdapterContext, capabilities: readonly Capability[], what: string) => {
  const missing = capabilities.filter(capability => !context.engine.has(capability))

  if (missing.length > 0) {
    throw new CryptoError('UNSUPPORTED', `${what} needs ${missing.join(' and ')}, which this engine lacks.`)
  }
}

const createChain = <Id extends string>(context: AdapterContext, id: Id, network: BitcoinNetwork): BitcoinChain<Id> => {
  const derivePublic = (key: ExtendedPublicKey, path: string) => {
    if (!context.engine.has('bip32-public-derivation')) {
      throw new CryptoError('UNSUPPORTED', 'This engine has no BIP-32 public derivation.')
    }

    return context.bip32.derivePublic(key, path)
  }
  const verifySchnorr = (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => {
    requireCapabilities(context, ['secp256k1-schnorr'], 'Verifying a Taproot signature')

    return context.schnorr.verify(publicKey, message, signature)
  }
  const messages: MessageContext = {
    network,
    recover: context.secp256k1.recover,
    ripemd160: context.hash.ripemd160,
    sha256: context.hash.sha256,
    tweak: (internalKey: Uint8Array, merkleRoot?: Uint8Array) => {
      requireCapabilities(context, ['taproot-tweak'], 'Checking a Taproot script path')

      return context.schnorr.taprootTweak(internalKey, merkleRoot)
    },
    verify: context.secp256k1.verify,
    verifySchnorr,
  }
  /** The type a request asks for, checked against the engine: Taproot needs its Schnorr signatures and tweaks. */
  const typeOf = (requested: unknown, capabilities: readonly Capability[]) => {
    const type = accountType(requested)

    if (type === 'p2tr') {
      requireCapabilities(context, capabilities, 'A Taproot account')
    }

    return type
  }

  return Object.freeze({
    addressFromPublicKey: (publicKey: Uint8Array, addressType?: BitcoinAccountType) =>
      accountOutput(context, network, typeOf(addressType, ['taproot-tweak']), publicKey).address,
    decodePsbt: (psbt: Uint8Array) => decodePsbt(psbt, network, context.hash.sha256),
    deriveAccount: async (keys: KeySource, request: BitcoinAccountRequest) => {
      const type = typeOf(request.addressType, TAPROOT)
      const key = keys.deriveKey('bip32', derivationPath(request, network))

      return createAccount(context, id, network, type, key, keys.fingerprint, messages)
    },
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
        verifySchnorr,
      }),
    network,
    validateAddress: (address: string) => validateAddress(address, network, context.hash.sha256),
    verifyMessage: ({address, message, signature}: {address: string; message: BitcoinMessage; signature: string}) =>
      verifyMessage(address, message, signature, messages),
    watchAccount: (request: BitcoinWatchRequest) => {
      const {fingerprint} = request

      if (!Number.isInteger(fingerprint) || fingerprint < 0 || fingerprint > 0xffffffff) {
        throw new CryptoError('INVALID_ARGUMENT', 'A fingerprint is a 32-bit unsigned integer.')
      }

      const type = typeOf(request.addressType, ['taproot-tweak'])

      if ('publicKey' in request) {
        const compressed = context.secp256k1.convertPublicKey(request.publicKey, 'compressed')

        return createWatchAccount(context, id, network, type, compressed, checkPath(request.path), fingerprint)
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
        type,
        leaf.publicKey,
        checkPath(`${accountPath}/${change}/${index}`),
        fingerprint
      )
    },
  })
}

/**
 * Bitcoin: native SegWit (P2WPKH, BIP-84) and Taproot (P2TR, BIP-86) accounts on mainnet, testnet, signet or regtest,
 * validation of every address type, payments from an account (coin selection, fees, BIP-143 and BIP-341 signatures),
 * PSBTs (BIP-174, with BIP-371's Taproot fields) for keys held elsewhere, and message signatures (BIP-322 and the
 * legacy BIP-137). Taproot needs an engine with `secp256k1-schnorr` and `taproot-tweak`; the adapter does not require
 * them, so P2WPKH works on an engine without them, and Taproot throws `UNSUPPORTED` there.
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
    features: {messageSigning: true, psbt: true, taproot: true, transactionSigning: true},
    formats: {
      address: ['bech32-p2wpkh', 'bech32m-p2tr'],
      signature: ['p2wpkh-bip143', 'p2tr-bip341', 'bip322-simple', 'bip137'],
    },
    id,
    name,
    requires: ['sha256', 'ripemd160', 'bip32-secp256k1'],
    version: VERSION,
  })
}
