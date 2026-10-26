import {
  AirgapError,
  type AirgapRequester,
  type AirgapResponder,
  formatKeypath,
  fromUR,
  type HDKey,
  parseKeypath,
  toUR,
  type UR,
} from '@hzblj/crypto-airgap'
import type {
  BitcoinAccount,
  BitcoinChain,
  BitcoinPsbt,
  BitcoinPsbtInput,
  BitcoinPsbtOutput,
  BitcoinWatchAccount,
  SignedBitcoinTransaction,
} from '@hzblj/crypto-bitcoin'
import {bytes, type ExtendedPublicKey, isCryptoError} from '@hzblj/nitro-crypto/adapter'

import {type BitcoinAirgapAccount, CRYPTO_ACCOUNT, CRYPTO_PSBT, type OutputDescriptor} from './types'

/** What a watch-only wallet sends: an unsigned PSBT, as `account.createPsbt` writes it. */
export type BitcoinSignRequestInput = {readonly psbt: Uint8Array}

/** What it gets back, checked: the signed PSBT, and the transaction to broadcast, every signature verified. */
export type BitcoinSignResponse = {
  readonly psbt: Uint8Array
  readonly transaction: SignedBitcoinTransaction
}

/**
 * Something a signer should say before it signs:
 * - `FOREIGN_INPUTS`: some inputs spend coins of other keys, which this signer will not sign.
 * - `UNVERIFIED_VALUES`: some of the signer's coins come without their previous transaction, so the values (and the
 *   fee) are the coordinator's word.
 * - `UNKNOWN_FEE`: an input does not state its value at all.
 * - `NO_ADDRESS_OUTPUT`: an output pays a script with no address (an `OP_RETURN`, a bare script).
 */
export type BitcoinSignWarning = 'FOREIGN_INPUTS' | 'UNVERIFIED_VALUES' | 'UNKNOWN_FEE' | 'NO_ADDRESS_OUTPUT'

/** A key the signer signs with: its path below the master key, and the public key the PSBT says it has there. */
export type BitcoinSigningKey = {readonly path: string; readonly publicKey: Uint8Array}

/** A request as the signer reads it: everything to show before asking whether to sign. */
export type BitcoinSignRequest = {
  readonly psbt: Uint8Array
  /** The id the transaction will have. */
  readonly txid: string
  /** Each input, and whether it spends a coin of this signer. */
  readonly inputs: readonly (BitcoinPsbtInput & {readonly mine: boolean})[]
  /** Each output, and whether it pays this signer back (its change). */
  readonly outputs: readonly (BitcoinPsbtOutput & {readonly change: boolean})[]
  /** The signer's keys its inputs need, one per address spent from. */
  readonly keys: readonly BitcoinSigningKey[]
  /** Satoshis the signer's coins put in. */
  readonly spending: bigint
  /** Satoshis paid to others: every output but the change. */
  readonly sending: bigint
  readonly fee: bigint | undefined
  readonly warnings: readonly BitcoinSignWarning[]
}

/**
 * Who signs: one account (its one address), or a wallet's account as a coordinator such as Sparrow uses it, every
 * receiving and change address below `accountPath` ("m/84'/0'/0'") that the PSBT names under the wallet's
 * fingerprint, each checked against the coin it spends.
 */
export type BitcoinSignContext =
  | {readonly account: BitcoinWatchAccount}
  | {readonly fingerprint: number; readonly accountPath: string}

/** What a signer answers with: the PSBT its accounts signed (`signRequest`, or `account.signPsbt`). */
export type BitcoinSignature = {readonly psbt: Uint8Array}

/** An account's extended public key, where it is, and the wallet it is of: what a signer shares to pair. */
export type BitcoinAccountKey = {
  readonly extendedKey: ExtendedPublicKey
  /** `m/84'/1'/0'`. */
  readonly path: string
  readonly fingerprint: number
}

/** One wallet's accounts as a `crypto-account` carries them, and those this network can watch. */
export type BitcoinAccountImport = {
  readonly masterFingerprint: number
  readonly descriptors: readonly OutputDescriptor[]
  /**
   * The P2WPKH descriptors this network can watch: single keys at full BIP-84 paths, and account keys (`m/84'/c'/a'`
   * with a chain code), watched at their first receiving address.
   */
  readonly accounts: readonly BitcoinWatchAccount[]
}

export type BitcoinAirgap = AirgapRequester<
  BitcoinSignRequestInput,
  BitcoinSignResponse,
  {readonly request: Uint8Array}
> &
  AirgapResponder<BitcoinSignRequest, BitcoinSignContext, BitcoinSignature> & {
    /**
     * A key shared by a signer (from `crypto-account`, `crypto-multi-accounts` or `crypto-hdkey`) as a watch-only
     * account: a single key at a full BIP-84 path, or an account's extended key (`m/84'/c'/a'`), at its receiving
     * address `index` (0 unless stated), derived publicly by the engine.
     */
    readonly watchAccount: (key: HDKey, masterFingerprint?: number, index?: number) => BitcoinWatchAccount
    /** An account's single public key as a signer shares it, with its path and wallet. */
    readonly pairingKey: (account: BitcoinWatchAccount) => HDKey
    /** An account's extended public key as a signer shares it (`wallet.extendedPublicKey("m/84'/1'/0'")`). */
    readonly accountKey: (key: BitcoinAccountKey) => HDKey
    /**
     * Keys as a `crypto-account` UR, one P2WPKH descriptor each: what Sparrow and other coordinators import, given
     * account keys (`accountKey`).
     */
    readonly encodeAccount: (request: {
      readonly masterFingerprint: number
      readonly keys: readonly HDKey[]
    }) => UR<'crypto-account'>
    readonly decodeAccount: (ur: UR) => BitcoinAccountImport
    /**
     * Signs a request the user agreed to: each key it needs, derived by `account(path)` (the wallet's
     * `deriveAccount({chain, path})`) and checked against the public key the PSBT names, signs its inputs in turn.
     */
    readonly signRequest: (
      request: BitcoinSignRequest,
      account: (path: string) => Promise<BitcoinAccount>
    ) => Promise<BitcoinSignature>
  }

const sum = (values: readonly bigint[]) => values.reduce((total, value) => total + value, 0n)

/** A chain's verdict on bytes from outside, as the protocol's error: the cause keeps the chain's own. */
const fromChain = <T>(run: () => T, message: string): T => {
  try {
    return run()
  } catch (error) {
    if (isCryptoError(error)) {
      throw new AirgapError('INVALID_PROTOCOL_DATA', `${message} ${error.message}`, {cause: error})
    }

    throw error
  }
}

const HARDENED = 0x80000000
const BIP84 = 84 + HARDENED

const indexesOf = (key: HDKey) =>
  (key.origin?.components ?? []).map(step =>
    'index' in step ? (step.hardened ? step.index + HARDENED : step.index) : Number.NaN
  )

/** Whether `path` is a receiving or change address directly below `accountPath`: `<account>/0/7`, `<account>/1/0`. */
const isBelowAccount = (path: string, accountPath: string) => {
  const rest = path.startsWith(`${accountPath}/`) ? path.slice(accountPath.length + 1).split('/') : []

  return rest.length === 2 && (rest[0] === '0' || rest[0] === '1') && /^\d+$/.test(rest[1] ?? '')
}

/**
 * Air-gapped signing for Bitcoin, bound to a chain (`crypto.chains.bitcoin`): PSBTs (BIP-174) travel as
 * `crypto-psbt` both ways, accounts as `crypto-account`. Nothing here signs or verifies by itself: the chain decodes,
 * signs and finalizes, the engine verifies.
 *
 * A watch-only wallet: `encodeSignRequest` its PSBT, show it, scan the answer, `decodeSignResponse` it against the
 * PSBT it sent, broadcast the transaction. A signer: `decodeSignRequest` what it scans, show it, `signRequest` once
 * the user agrees, `encodeSignResponse`.
 */
export const bitcoinAirgap = (chain: BitcoinChain<string>): BitcoinAirgap => {
  const network = chain.network
  const coinType = network.coinType
  const useInfo = {network: coinType === 0 ? 0 : 1, type: 0}

  const decodePsbt = (psbt: Uint8Array, what: string) =>
    fromChain((): BitcoinPsbt => chain.decodePsbt(psbt), `${what} is not a PSBT this reads.`)

  const watchAccount = (key: HDKey, masterFingerprint?: number, index = 0) => {
    const fingerprint = key.origin?.sourceFingerprint ?? masterFingerprint
    const indexes = indexesOf(key)

    if (key.keyData.length !== 33) {
      throw new AirgapError('INVALID_PROTOCOL_DATA', 'A Bitcoin key is a compressed secp256k1 public key.')
    }

    if (fingerprint === undefined || !key.origin) {
      throw new AirgapError('INVALID_PROTOCOL_DATA', 'A key to watch says which wallet and path it is from.')
    }

    const isAccount = indexes.length === 3 && key.chainCode !== undefined
    const isAddress = indexes.length === 5

    if (!(isAccount || isAddress) || indexes[0] !== BIP84 || indexes.some(Number.isNaN)) {
      throw new AirgapError(
        'INVALID_PROTOCOL_DATA',
        "A key to watch is an account's extended key (m/84'/coin'/account') or one address's (…/change/index)."
      )
    }

    if (
      indexes[1] !== coinType + HARDENED ||
      (key.useInfo && (key.useInfo.type !== 0 || (key.useInfo.network === 0) !== (coinType === 0)))
    ) {
      throw new AirgapError('REQUEST_MISMATCH', `This key is not for Bitcoin ${network.name}.`)
    }

    const path = formatKeypath(key.origin)

    if (isAddress) {
      return fromChain(
        () => chain.watchAccount({fingerprint, path, publicKey: key.keyData}),
        'The key is not one to watch.'
      )
    }

    const extendedKey: ExtendedPublicKey = {
      chainCode: key.chainCode ?? new Uint8Array(32),
      childNumber: indexes[2] ?? 0,
      depth: 3,
      parentFingerprint: key.parentFingerprint ?? 0,
      publicKey: key.keyData,
    }

    return fromChain(() => chain.watchAccount({extendedKey, fingerprint, index, path}), 'The key is not one to watch.')
  }

  /** The P2WPKH address of a key named in a PSBT, to compare with the coin or output it is named for. */
  const addressOf = (publicKey: Uint8Array) => {
    try {
      return chain.addressFromPublicKey(publicKey)
    } catch {
      return undefined
    }
  }

  return Object.freeze({
    accountKey: ({extendedKey, fingerprint, path}: BitcoinAccountKey): HDKey => ({
      chainCode: extendedKey.chainCode,
      keyData: extendedKey.publicKey,
      origin: parseKeypath(path, fingerprint),
      parentFingerprint: extendedKey.parentFingerprint || undefined,
      useInfo,
    }),
    chain: 'bitcoin',
    decodeAccount: (ur: UR): BitcoinAccountImport => {
      const account: BitcoinAirgapAccount = fromUR(CRYPTO_ACCOUNT, ur)
      const accounts = account.descriptors.flatMap(descriptor => {
        const [key] = descriptor.keys

        if (descriptor.scripts.length !== 1 || descriptor.scripts[0] !== 'wpkh' || !key || !('hdkey' in key)) {
          return []
        }

        try {
          return [watchAccount(key.hdkey, account.masterFingerprint)]
        } catch (error) {
          if (error instanceof AirgapError) {
            return []
          }

          throw error
        }
      })

      return Object.freeze({...account, accounts: Object.freeze(accounts)})
    },
    decodeSignRequest: (ur: UR, context: BitcoinSignContext): BitcoinSignRequest => {
      const psbt = fromUR(CRYPTO_PSBT, ur)
      const decoded = decodePsbt(psbt, 'The request')
      const keys = new Map<string, BitcoinSigningKey>()

      /** The signer's key behind a script, by the context: its one account's, or one the PSBT names below its account. */
      const ownKey = (
        scriptPubKey: Uint8Array | undefined,
        address: string | undefined,
        derivations: BitcoinPsbtInput['derivations']
      ): BitcoinSigningKey | undefined => {
        if ('account' in context) {
          const {account} = context

          return scriptPubKey && bytes.equal(scriptPubKey, account.scriptPubKey)
            ? {path: account.path, publicKey: account.publicKey}
            : undefined
        }

        const origin = derivations.find(
          ({fingerprint, path}) => fingerprint === context.fingerprint && isBelowAccount(path, context.accountPath)
        )

        // The PSBT's word for whose key it is counts only when the key really pays this script.
        return origin && address !== undefined && addressOf(origin.publicKey) === address
          ? {path: origin.path, publicKey: origin.publicKey}
          : undefined
      }

      if ('account' in context) {
        const {account} = context

        // The PSBT may say where the account's key came from: it must agree with the account.
        for (const input of decoded.inputs) {
          for (const origin of input.derivations) {
            if (
              bytes.equal(origin.publicKey, account.publicKey) &&
              (origin.fingerprint !== account.fingerprint || origin.path !== account.path)
            ) {
              throw new AirgapError('REQUEST_MISMATCH', 'The PSBT places this account`s key in another wallet or path.')
            }
          }
        }
      }

      const inputs = decoded.inputs.map(input => {
        const key = ownKey(input.spent?.scriptPubKey, input.address, input.derivations)

        if (key) {
          keys.set(key.path, key)
        }

        return Object.freeze({...input, mine: key !== undefined})
      })
      const own = inputs.filter(input => input.mine)

      if (own.length === 0) {
        throw new AirgapError('REQUEST_MISMATCH', 'No input of this PSBT spends a coin of this signer.')
      }

      const outputs = decoded.outputs.map(output =>
        Object.freeze({
          ...output,
          change: ownKey(output.scriptPubKey, output.address, output.derivations) !== undefined,
        })
      )
      const warnings: BitcoinSignWarning[] = []

      if (own.length !== inputs.length) {
        warnings.push('FOREIGN_INPUTS')
      }

      if (own.some(input => !input.verifiedValue)) {
        warnings.push('UNVERIFIED_VALUES')
      }

      if (decoded.fee === undefined) {
        warnings.push('UNKNOWN_FEE')
      }

      if (outputs.some(output => output.address === undefined)) {
        warnings.push('NO_ADDRESS_OUTPUT')
      }

      return Object.freeze({
        fee: decoded.fee,
        inputs: Object.freeze(inputs),
        keys: Object.freeze([...keys.values()].map(key => Object.freeze(key))),
        outputs: Object.freeze(outputs),
        psbt,
        sending: sum(outputs.filter(output => !output.change).map(output => output.value)),
        spending: sum(own.map(input => input.spent?.value ?? 0n)),
        txid: decoded.txid,
        warnings: Object.freeze(warnings),
      })
    },
    decodeSignResponse: (ur: UR, {request}: {readonly request: Uint8Array}): BitcoinSignResponse => {
      const psbt = fromUR(CRYPTO_PSBT, ur)
      const sent = decodePsbt(request, 'The request')
      const answer = decodePsbt(psbt, 'The response')

      // The transaction id commits to every input, output, the version and the lock time.
      if (answer.txid !== sent.txid) {
        throw new AirgapError('REQUEST_MISMATCH', 'The signed PSBT is of another transaction than the one sent.')
      }

      const sameCoins = sent.inputs.every((input, index) => {
        const other = answer.inputs[index]?.spent

        return (
          input.spent === undefined ||
          (other !== undefined &&
            other.value === input.spent.value &&
            bytes.equal(other.scriptPubKey, input.spent.scriptPubKey))
        )
      })

      if (!sameCoins) {
        throw new AirgapError('REQUEST_MISMATCH', 'The signed PSBT states other coins than the one sent.')
      }

      return Object.freeze({
        psbt,
        transaction: fromChain(() => chain.finalizePsbt(psbt), 'The signed PSBT does not finalize.'),
      })
    },
    encodeAccount: ({keys, masterFingerprint}) =>
      toUR(CRYPTO_ACCOUNT, {
        descriptors: keys.map(hdkey => ({keys: [{hdkey}], scripts: ['wpkh'] as const})),
        masterFingerprint,
      }),
    encodeSignRequest: ({psbt}: BitcoinSignRequestInput) => {
      // What goes out must be a PSBT this chain reads: a malformed one is the caller's mistake, said here.
      decodePsbt(psbt, 'The PSBT')

      return toUR(CRYPTO_PSBT, psbt)
    },
    encodeSignResponse: ({psbt}: BitcoinSignature) => toUR(CRYPTO_PSBT, psbt),
    pairingKey: (account: BitcoinWatchAccount): HDKey => ({
      keyData: account.publicKey,
      origin: parseKeypath(account.path, account.fingerprint),
      useInfo,
    }),
    requestTypes: Object.freeze(['crypto-psbt']),
    responseTypes: Object.freeze(['crypto-psbt']),
    signRequest: async (request: BitcoinSignRequest, account: (path: string) => Promise<BitcoinAccount>) => {
      let psbt = request.psbt

      for (const key of request.keys) {
        const signer = await account(key.path)

        if (!bytes.equal(signer.publicKey, key.publicKey)) {
          throw new AirgapError('REQUEST_MISMATCH', 'The PSBT names a key this wallet does not have at that path.')
        }

        psbt = (await signer.signPsbt(psbt)).psbt
      }

      return Object.freeze({psbt})
    },
    watchAccount,
  })
}
