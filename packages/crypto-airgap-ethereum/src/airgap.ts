import {
  AirgapError,
  type AirgapRequester,
  type AirgapResponder,
  formatKeypath,
  fromUR,
  type HDKey,
  type Keypath,
  parseKeypath,
  type RequestId,
  toUR,
  type UR,
} from '@hzblj/crypto-airgap'
import type {
  Address,
  EthereumAccount,
  EthereumChain,
  EthereumTransactionRequest,
  Hex,
  SignableMessage,
  SignedEthereumTransaction,
} from '@hzblj/crypto-ethereum'
import {
  bytes,
  type ExtendedPublicKey,
  hex,
  isCryptoError,
  type RecoverableSignature,
  utf8,
} from '@hzblj/nitro-crypto/adapter'

import {ETH_SIGN_REQUEST, ETH_SIGNATURE, type EthSignRequest} from './types'

/** An account by its address and where its key is: all a watch-only wallet knows, and all a request names. */
export type EthereumAirgapAccount = {
  readonly address: Address
  /** `m/44'/60'/0'/0/0`. */
  readonly path: string
  /** The BIP-32 fingerprint of the signer's master key. */
  readonly fingerprint: number
}

/** What a watch-only wallet asks to be signed: an EIP-1559 transaction, or a message for `personal_sign`. */
export type EthereumAirgapRequest = {
  /** A fresh id per request (`createRequestId`): the answer must repeat it. */
  readonly requestId: RequestId
  readonly account: EthereumAirgapAccount
  /** Who asks, for the signer to show: the wallet's name. */
  readonly origin?: string
} & ({readonly transaction: EthereumTransactionRequest} | {readonly message: SignableMessage})

/** The answer, checked: a transaction ready to broadcast, or a message signature, each by the account asked. */
export type EthereumAirgapResponse =
  | {readonly kind: 'transaction'; readonly transaction: SignedEthereumTransaction; readonly origin?: string}
  | {readonly kind: 'message'; readonly signature: Hex; readonly origin?: string}

/** An ERC-20 `transfer` the call data makes: who receives, and how many base units. */
export type Erc20Transfer = {readonly recipient: Address; readonly amount: bigint}

/** A request as the signer reads it: everything to show before asking whether to sign. */
export type EthereumSignRequest = {
  readonly requestId?: RequestId
  readonly origin?: string
  /** The key asked for, below the signer's master key: `m/44'/60'/0'/0/3`. */
  readonly path: string
  /**
   * The address that signs, when known: the account's, or the one the request names. A request may name none; then
   * the signer knows it once it derives the key (`signRequest` does, and checks any address named against it).
   */
  readonly address?: Address
} & (
  | {
      readonly kind: 'transaction'
      readonly transaction: EthereumTransactionRequest & {
        readonly chainId: number
        readonly to: Address
        readonly data: Hex
      }
      /** When the call data is an ERC-20 `transfer` (the token is `transaction.to`). */
      readonly erc20Transfer?: Erc20Transfer
      /** The most it can cost: `gas × maxFeePerGas`, in wei. */
      readonly maxFee: bigint
    }
  | {
      readonly kind: 'message'
      readonly message: Uint8Array
      /** The message as text, when it is UTF-8 without control characters: what to show. */
      readonly text?: string
    }
)

/**
 * Who signs: one account, or a wallet's account as MetaMask and other watch-only wallets use an extended key (any
 * address `<accountPath>/0/index` the request asks for under the wallet's fingerprint).
 */
export type EthereumSignContext =
  | {readonly account: EthereumAirgapAccount}
  | {readonly fingerprint: number; readonly accountPath: string}

/** An account's extended public key, where it is, and the wallet it is of: what a signer shares to pair. */
export type EthereumAccountKey = {
  readonly extendedKey: ExtendedPublicKey
  /** `m/44'/60'/0'`. */
  readonly path: string
  readonly fingerprint: number
  /** The signer's name, which a watch-only wallet shows (MetaMask does). */
  readonly name?: string
}

/**
 * The signer's answer. A transaction's `signature` is the engine's (`account.signTransaction(…).signature`) and goes
 * out with v as the y parity, as ERC-4527 signers send it for typed transactions; a message's is the 65-byte hex
 * `account.signMessage` returns, v as 27 or 28.
 */
export type EthereumSignature = {
  readonly requestId?: RequestId
  readonly signature: RecoverableSignature | Hex
  readonly origin?: string
}

export type EthereumAirgap = AirgapRequester<
  EthereumAirgapRequest,
  EthereumAirgapResponse,
  {readonly request: EthereumAirgapRequest}
> &
  AirgapResponder<EthereumSignRequest, EthereumSignContext, EthereumSignature> & {
    /**
     * A key shared by a signer (from `crypto-multi-accounts`, or a `crypto-hdkey`) as an account to ask for
     * signatures: a single key at a full path, or an account's extended key (`m/44'/60'/a'`), at its address `index`
     * (0 unless stated) below the children it names (`0/*` unless stated, as MetaMask reads it), derived publicly by
     * the engine.
     */
    readonly watchAccount: (key: HDKey, masterFingerprint?: number, index?: number) => EthereumAirgapAccount
    /** An account's public key as a signer shares it: compressed, with its path and the wallet's fingerprint. */
    readonly pairingKey: (account: {readonly publicKey: Hex; readonly path: string}, fingerprint: number) => HDKey
    /**
     * An account's extended public key as a `crypto-hdkey` for MetaMask and other watch-only wallets, as Keystone and
     * OneKey share it: children `0/*`, the note `account.standard`, and `name` (`wallet.extendedPublicKey("m/44'/60'/0'")`).
     */
    readonly accountKey: (key: EthereumAccountKey) => HDKey
    /**
     * Signs a request the user agreed to, with the key `account(path)` derives (the wallet's
     * `deriveAccount({chain, path})`), after checking it is at the path asked and is any address the request names.
     */
    readonly signRequest: (
      request: EthereumSignRequest,
      account: (path: string) => Promise<EthereumAccount>
    ) => Promise<EthereumSignature>
  }

const HARDENED = 0x80000000
const BIP44 = 44 + HARDENED
const ETHEREUM = 60 + HARDENED

/** `0/*`: the receiving addresses below an account, where MetaMask and Keystone look. */
const RECEIVING: Keypath = {
  components: [
    {hardened: false, index: 0},
    {hardened: false, wildcard: true},
  ],
}

/** Whether `path` is a receiving address directly below `accountPath`: `<account>/0/7`. */
const isBelowAccount = (path: string, accountPath: string) => {
  const rest = path.startsWith(`${accountPath}/`) ? path.slice(accountPath.length + 1).split('/') : []

  return rest.length === 2 && rest[0] === '0' && /^\d+$/.test(rest[1] ?? '')
}

/**
 * Where an account key's address `index` is, from the children it names: non-hardened indexes and a last wildcard
 * (`0/*`, the default; Ledger's legacy layout is `*`). Anything else is not a set of addresses to watch.
 */
const childPath = (children: Keypath | undefined, index: number) => {
  const components = (children ?? RECEIVING).components
  const steps = components.map((step, position) => {
    if (step.hardened) {
      return undefined
    }

    if (position === components.length - 1) {
      return 'wildcard' in step ? `${index}` : undefined
    }

    return 'index' in step ? `${step.index}` : undefined
  })

  if (steps.length === 0 || steps.some(step => step === undefined)) {
    throw new AirgapError('INVALID_PROTOCOL_DATA', 'An account key`s children are a path of indexes ending in `*`.')
  }

  return steps.join('/')
}

/** EIP-2718 type 2: the only typed transaction the Ethereum adapter reads. */
const EIP1559 = 0x02

/** `transfer(address,uint256)`. */
const TRANSFER = '0xa9059cbb'

const mismatch = (message: string) => new AirgapError('REQUEST_MISMATCH', message)

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

const messageBytes = (message: SignableMessage) => (typeof message === 'string' ? utf8.encode(message) : message)

/** Text worth showing as text: valid UTF-8 that decodes back to the same bytes, without control characters. */
const readableText = (message: Uint8Array): string | undefined => {
  const text = utf8.decode(message)

  // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are exactly what this looks for.
  return bytes.equal(utf8.encode(text), message) && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)
    ? text
    : undefined
}

/** 65 bytes, `r || s || v`, from either form a signer hands over. */
const signatureBytes = (signature: RecoverableSignature | Hex): Uint8Array => {
  if (typeof signature === 'string') {
    return hex.decode(signature)
  }

  const out = new Uint8Array(65)
  out.set(signature.signature)
  out[64] = signature.recovery

  return out
}

/** v as 27 or 28, as `personal_sign` and every verifier take it. */
const legacyV = (signature: Uint8Array): Hex => {
  const out = signature.slice()
  const v = out[64] ?? 0
  out[64] = v < 27 ? v + 27 : v

  return hex.encode(out, {prefix: true}) as Hex
}

/**
 * Air-gapped signing for Ethereum and every EVM chain, bound to a chain (`crypto.chains.ethereum`): ERC-4527's
 * `eth-sign-request` and `eth-signature`, for EIP-1559 transactions and `personal_sign` messages. Legacy transactions
 * and EIP-712 typed data are refused, as the Ethereum adapter does not sign them. Nothing here signs or verifies by
 * itself: the chain parses and recovers, the engine signs.
 */
export const ethereumAirgap = (chain: EthereumChain<string>): EthereumAirgap => {
  const chainId = chain.network.chainId

  const watchAccount = (key: HDKey, masterFingerprint?: number, index = 0): EthereumAirgapAccount => {
    const fingerprint = key.origin?.sourceFingerprint ?? masterFingerprint
    const indexes = (key.origin?.components ?? []).map(step =>
      'index' in step ? (step.hardened ? step.index + HARDENED : step.index) : Number.NaN
    )

    if (key.keyData.length !== 33) {
      throw new AirgapError('INVALID_PROTOCOL_DATA', 'An Ethereum key is a compressed secp256k1 public key.')
    }

    if (fingerprint === undefined || !key.origin) {
      throw new AirgapError('INVALID_PROTOCOL_DATA', 'A key to sign with says which wallet and path it is from.')
    }

    if (indexes[0] !== BIP44 || indexes[1] !== ETHEREUM || (key.useInfo && key.useInfo.type !== 60)) {
      throw mismatch("This key is not an Ethereum key (m/44'/60'/…).")
    }

    const isAccount = indexes.length === 3 && key.chainCode !== undefined

    if (!(isAccount || indexes.length >= 5) || indexes.some(Number.isNaN)) {
      throw new AirgapError(
        'INVALID_PROTOCOL_DATA',
        "A key to sign with is an account's extended key (m/44'/60'/account') or an address's (m/44'/60'/…/index)."
      )
    }

    const path = formatKeypath(key.origin)

    if (!isAccount) {
      return Object.freeze({
        address: fromChain(() => chain.addressFromPublicKey(key.keyData), 'The key is not a public key.'),
        fingerprint,
        path,
      })
    }

    const relative = childPath(key.children, index)
    const extendedKey: ExtendedPublicKey = {
      chainCode: key.chainCode ?? new Uint8Array(32),
      childNumber: indexes[2] ?? 0,
      depth: 3,
      parentFingerprint: key.parentFingerprint ?? 0,
      publicKey: key.keyData,
    }
    const leaf = fromChain(() => chain.derivePublic(extendedKey, `m/${relative}`), 'The key is not one to derive from.')

    return Object.freeze({
      address: fromChain(() => chain.addressFromPublicKey(leaf.publicKey), 'The key is not a public key.'),
      fingerprint,
      path: `${path}/${relative}`,
    })
  }

  const signRequestOf = (request: EthereumAirgapRequest): EthSignRequest => {
    const base = {
      address: hex.decode(request.account.address),
      chainId,
      derivationPath: parseKeypath(request.account.path, request.account.fingerprint),
      origin: request.origin,
      requestId: request.requestId,
    }

    return 'transaction' in request
      ? {
          ...base,
          dataType: 'typed-transaction',
          signData: hex.decode(
            fromChain(() => chain.serializeTransaction(request.transaction), 'The transaction is not one to sign.')
          ),
        }
      : {...base, dataType: 'personal-message', signData: messageBytes(request.message)}
  }

  return Object.freeze({
    accountKey: ({extendedKey, fingerprint, name, path}: EthereumAccountKey): HDKey => ({
      chainCode: extendedKey.chainCode,
      children: RECEIVING,
      keyData: extendedKey.publicKey,
      name,
      note: 'account.standard',
      origin: parseKeypath(path, fingerprint),
      parentFingerprint: extendedKey.parentFingerprint || undefined,
      useInfo: {network: 0, type: 60},
    }),
    chain: 'ethereum',
    decodeSignRequest: (ur: UR, context: EthereumSignContext): EthereumSignRequest => {
      const request = fromUR(ETH_SIGN_REQUEST, ur)
      const path = formatKeypath(request.derivationPath)
      const account = 'account' in context ? context.account : undefined
      const fingerprint = 'account' in context ? context.account.fingerprint : context.fingerprint
      const asked = 'account' in context ? path === context.account.path : isBelowAccount(path, context.accountPath)

      if (!asked) {
        throw mismatch('The request is for another key than this account`s.')
      }

      const source = request.derivationPath.sourceFingerprint

      if (source !== undefined && source !== fingerprint) {
        throw mismatch('The request is for another wallet than this one.')
      }

      if (account && request.address && !bytes.equal(request.address, hex.decode(account.address))) {
        throw mismatch('The request names another address than this account`s.')
      }

      const named = request.address
      const address =
        account?.address ?? (named && fromChain(() => chain.checksumAddress(named), 'The address is not one.'))
      const common = {origin: request.origin, path, requestId: request.requestId, ...(address ? {address} : {})}

      if ((request.chainId ?? 1) !== chainId) {
        throw mismatch(`The request is for chain id ${request.chainId ?? 1}, not ${chainId} (${chain.network.name}).`)
      }

      if (request.dataType === 'personal-message') {
        const text = readableText(request.signData)

        return Object.freeze({
          ...common,
          kind: 'message',
          message: request.signData,
          ...(text === undefined ? {} : {text}),
        })
      }

      if (request.dataType !== 'typed-transaction' || request.signData[0] !== EIP1559) {
        throw new AirgapError(
          'INVALID_PROTOCOL_DATA',
          'Only EIP-1559 transactions and personal messages are signed here: not legacy transactions, other typed transactions, or EIP-712 data.'
        )
      }

      const transaction = fromChain(
        () => chain.parseTransaction(request.signData),
        'The transaction is not one to sign.'
      )
      const data = hex.decode(transaction.data)
      const erc20Transfer =
        transaction.data.toLowerCase().startsWith(TRANSFER) &&
        data.length === 68 &&
        data.subarray(4, 16).every(byte => byte === 0)
          ? {
              amount: BigInt(hex.encode(data.subarray(36), {prefix: true})),
              recipient: chain.checksumAddress(data.subarray(16, 36)),
            }
          : undefined

      return Object.freeze({
        ...common,
        kind: 'transaction',
        maxFee: transaction.gas * transaction.maxFeePerGas,
        transaction,
        ...(erc20Transfer ? {erc20Transfer} : {}),
      })
    },
    decodeSignResponse: (ur: UR, {request}: {readonly request: EthereumAirgapRequest}): EthereumAirgapResponse => {
      const answer = fromUR(ETH_SIGNATURE, ur)

      if (answer.requestId !== request.requestId) {
        throw mismatch('The signature answers another request than this one.')
      }

      const origin = answer.origin === undefined ? {} : {origin: answer.origin}

      if ('message' in request) {
        const signature = legacyV(answer.signature)
        const valid = fromChain(
          () => chain.verifyMessage({address: request.account.address, message: request.message, signature}),
          'The signature is not one this reads.'
        )

        if (!valid) {
          throw mismatch('The message signature is not by the account asked.')
        }

        return Object.freeze({kind: 'message', signature, ...origin})
      }

      const signer = fromChain(
        () => chain.recoverTransactionAddress({signature: answer.signature, transaction: request.transaction}),
        'The signature is not one this reads.'
      )

      if (signer !== request.account.address) {
        throw mismatch('The transaction signature is not by the account asked, or not of this transaction.')
      }

      return Object.freeze({
        kind: 'transaction',
        transaction: fromChain(
          () => chain.assembleTransaction(request.transaction, answer.signature),
          'The signature does not fit the transaction.'
        ),
        ...origin,
      })
    },
    encodeSignRequest: (request: EthereumAirgapRequest) => toUR(ETH_SIGN_REQUEST, signRequestOf(request)),
    encodeSignResponse: ({origin, requestId, signature}: EthereumSignature) =>
      toUR(ETH_SIGNATURE, {origin, requestId, signature: signatureBytes(signature)}),
    pairingKey: ({path, publicKey}, fingerprint) => {
      const uncompressed = hex.decode(publicKey)

      if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
        throw new AirgapError('INVALID_ARGUMENT', 'An Ethereum account`s public key is 65 bytes, uncompressed.')
      }

      // Compressing needs no curve arithmetic: the parity of y picks the prefix, and x follows.
      const compressed = bytes.concat(Uint8Array.of(0x02 | ((uncompressed[64] ?? 0) & 1)), uncompressed.subarray(1, 33))

      return {keyData: compressed, origin: parseKeypath(path, fingerprint), useInfo: {network: 0, type: 60}}
    },
    requestTypes: Object.freeze(['eth-sign-request']),
    responseTypes: Object.freeze(['eth-signature']),
    signRequest: async (request: EthereumSignRequest, account: (path: string) => Promise<EthereumAccount>) => {
      const signer = await account(request.path)

      if (signer.path !== request.path || (request.address !== undefined && signer.address !== request.address)) {
        throw mismatch('The request names an address this wallet does not have at that path.')
      }

      const signature =
        request.kind === 'transaction'
          ? (await signer.signTransaction(request.transaction)).signature
          : await signer.signMessage({message: request.message})

      return Object.freeze({signature, ...(request.requestId === undefined ? {} : {requestId: request.requestId})})
    },
    watchAccount,
  })
}
