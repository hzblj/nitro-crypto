import {createRequestId} from '@hzblj/crypto-airgap'
import {solanaAirgap} from '@hzblj/crypto-airgap-solana'
import type {SolanaChain, SolanaInstruction} from '@hzblj/crypto-solana'

import {NETWORKS} from '../config'
import {formatUnits} from '../utils'
import {NetworkError, rpc, rpcBatch, rpcBatchSettled} from './http'
import {AIRGAP_ORIGIN} from './origin'
import type {ActivityItem, ChainService, SendRequest, TransactionStatus} from './types'

const network = NETWORKS.solana
const url = network.endpoint
const CONFIRMED = {commitment: 'confirmed'} as const
/** A token account's size: what its rent exemption is computed for. */
const TOKEN_ACCOUNT_SIZE = 165

const toBase64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))

/** Confirmed transactions never change: each is fetched once per app run. */
const transactions = new Map<string, NonNullable<ParsedTransaction>>()

type Value<T> = {readonly value: T}
type TokenAccounts = Value<
  readonly {
    readonly account: {readonly data: {readonly parsed: {readonly info: {readonly tokenAmount: {amount: string}}}}}
  }[]
>
type SignatureInfo = {readonly signature: string; readonly blockTime: number | null; readonly err: unknown}
type TokenBalance = {readonly mint: string; readonly owner?: string; readonly uiTokenAmount: {readonly amount: string}}
type ParsedInstruction = {readonly parsed?: {readonly type?: string; readonly info?: Record<string, unknown>}}
type ParsedTransaction = {
  readonly blockTime: number | null
  readonly meta: {
    readonly err: unknown
    readonly fee: number
    readonly preBalances: readonly number[]
    readonly postBalances: readonly number[]
    readonly preTokenBalances?: readonly TokenBalance[]
    readonly postTokenBalances?: readonly TokenBalance[]
  } | null
  readonly transaction: {
    readonly message: {
      readonly accountKeys: readonly {readonly pubkey: string}[]
      readonly instructions: readonly ParsedInstruction[]
    }
  }
} | null
type SignatureStatus = {readonly err: unknown; readonly confirmationStatus: string | null} | null

const tokenAmount = (balances: readonly TokenBalance[] | undefined, owner: string, mint: string) =>
  (balances ?? [])
    .filter(balance => balance.owner === owner && balance.mint === mint)
    .reduce((total, balance) => total + BigInt(balance.uiTokenAmount.amount), 0n)

/** The other side of a transfer, read from the parsed instructions: a system or a token transfer. */
const counterpartyOf = (transaction: NonNullable<ParsedTransaction>, address: string): string | undefined => {
  for (const instruction of transaction.transaction.message.instructions) {
    const info = instruction.parsed?.info ?? {}
    const source = (info.source ?? info.authority ?? info.multisigAuthority) as string | undefined
    const destination = info.destination as string | undefined

    if (instruction.parsed?.type?.startsWith('transfer')) {
      return source === address ? destination : source
    }
  }
  return undefined
}

/** The movements one transaction made for `address`: a token's, else SOL's (the fee left out of what was sent). */
const toActivity = (address: string, info: SignatureInfo, transaction: ParsedTransaction): ActivityItem[] => {
  if (!transaction?.meta) {
    return []
  }

  const {meta} = transaction
  const status: TransactionStatus = info.err || meta.err ? 'failed' : 'confirmed'
  const timestamp = (transaction.blockTime ?? info.blockTime ?? 0) * 1000 || undefined
  const counterparty = counterpartyOf(transaction, address)
  const base = {chain: 'solana' as const, counterparty, hash: info.signature, status, timestamp}

  const tokens = network.tokens.flatMap((token): ActivityItem[] => {
    const mint = token.contract ?? ''
    const delta = tokenAmount(meta.postTokenBalances, address, mint) - tokenAmount(meta.preTokenBalances, address, mint)

    return delta === 0n
      ? []
      : [
          {
            ...base,
            amount: delta < 0n ? -delta : delta,
            asset: token,
            direction: delta < 0n ? 'out' : 'in',
            id: `solana:${info.signature}:${token.id}`,
          },
        ]
  })

  if (tokens.length > 0) {
    return tokens
  }

  const keys = transaction.transaction.message.accountKeys
  const index = keys.findIndex(key => key.pubkey === address)

  if (index < 0) {
    return []
  }

  const paidFee = index === 0 ? BigInt(meta.fee) : 0n
  const delta = BigInt((meta.postBalances[index] ?? 0) - (meta.preBalances[index] ?? 0))
  // A transaction that moved no SOL of this account's but its fee (a program call, a failed transfer) still cost it the
  // fee: listed as what it spent, not as "0 SOL".
  const moved = delta + paidFee === 0n ? delta : delta + paidFee

  return [
    {
      ...base,
      amount: moved < 0n ? -moved : moved,
      asset: network.native,
      direction: moved < 0n ? 'out' : moved > 0n ? 'in' : 'self',
      id: `solana:${info.signature}`,
    },
  ]
}

const tokenBalance = async (owner: string, mint: string) => {
  const {value} = await rpc<TokenAccounts>(url, 'getTokenAccountsByOwner', [
    owner,
    {mint},
    {...CONFIRMED, encoding: 'jsonParsed'},
  ])

  return value.reduce((total, entry) => total + BigInt(entry.account.data.parsed.info.tokenAmount.amount), 0n)
}

const prepare = async (chain: SolanaChain, address: string, {amount, asset, to}: SendRequest) => {
  const recipient = chain.validateAddress(to)

  if (!recipient.valid) {
    throw new NetworkError(recipient.reason)
  }

  const mint = asset.contract
  const recipientTokenAccount = mint ? chain.associatedTokenAddress({mint, owner: to}) : undefined
  const [blockhash, balance, recipientAccount, rentFloor, tokenRent] = (await rpcBatch(url, [
    {method: 'getLatestBlockhash', params: [CONFIRMED]},
    {method: 'getBalance', params: [address, CONFIRMED]},
    {method: 'getAccountInfo', params: [recipientTokenAccount ?? to, {...CONFIRMED, encoding: 'base64'}]},
    {method: 'getMinimumBalanceForRentExemption', params: [0]},
    {method: 'getMinimumBalanceForRentExemption', params: [TOKEN_ACCOUNT_SIZE]},
  ])) as [Value<{blockhash: string}>, Value<number>, Value<unknown>, number, number]

  const lamports = BigInt(balance.value)
  const recipientExists = recipientAccount.value !== null
  const held = mint ? await tokenBalance(address, mint) : lamports
  const build = (value: bigint): SolanaInstruction[] =>
    mint
      ? chain.instructions.transferToken({amount: value, decimals: asset.decimals, from: address, mint, to})
      : [chain.instructions.transfer({from: address, lamports: value, to})]
  const message = chain.compileMessage({
    feePayer: address,
    instructions: build(1n),
    recentBlockhash: blockhash.value.blockhash,
  })
  const {value: networkFee} = await rpc<Value<number | null>>(url, 'getFeeForMessage', [toBase64(message), CONFIRMED])
  // A new token account is paid for by the sender: its rent is part of what this costs.
  const rent = mint && !recipientExists ? BigInt(tokenRent) : 0n
  const fee = BigInt(networkFee ?? 5000) + rent
  const value = amount === 'max' ? (mint ? held : lamports - fee) : amount

  if (value <= 0n || value > held || (mint ? fee > lamports : value + fee > lamports)) {
    throw new NetworkError(
      mint && value <= held
        ? `The fee is paid in SOL: this needs ${formatUnits(fee, 9)} SOL, the wallet has ${formatUnits(lamports, 9)}.`
        : `Not enough ${asset.symbol}: the wallet has ${formatUnits(held, asset.decimals)}.`
    )
  }
  if (!mint && !recipientExists && value < BigInt(rentFloor)) {
    throw new NetworkError(
      `A new Solana account must start with at least ${formatUnits(BigInt(rentFloor), 9)} SOL (its rent exemption).`
    )
  }
  const left = lamports - fee - (mint ? 0n : value)
  if (left > 0n && left < BigInt(rentFloor)) {
    throw new NetworkError(
      `That would leave ${formatUnits(left, 9)} SOL, below the ${formatUnits(BigInt(rentFloor), 9)} SOL an account keeps for rent: send less, or everything.`
    )
  }

  return {
    amount: value,
    details: [
      {label: 'Network', value: `Solana ${network.testnet}`},
      {label: 'Recent blockhash', value: `${blockhash.value.blockhash.slice(0, 12)}…`},
      {label: 'Instructions', value: mint ? 'Create token account (if new), transfer checked' : 'System transfer'},
      ...(rent > 0n ? [{label: 'Token account rent', value: `${formatUnits(rent, 9)} SOL`}] : []),
    ],
    fee,
    transaction: {instructions: build(value), recentBlockhash: blockhash.value.blockhash},
  }
}

const broadcast = (serialized: Uint8Array) =>
  rpc<string>(url, 'sendTransaction', [toBase64(serialized), {encoding: 'base64', preflightCommitment: 'confirmed'}])

export const solanaService = (chain: SolanaChain, random: (length: number) => Uint8Array): ChainService<'solana'> => {
  const airgap = solanaAirgap(chain)

  return {
    activity: async address => {
      const signatures = await rpc<SignatureInfo[]>(url, 'getSignaturesForAddress', [
        address,
        {...CONFIRMED, limit: 15},
      ])
      // Devnet limits getTransaction hard: ask only for what is not known yet, and keep whatever does come back.
      const missing = signatures.filter(info => !transactions.has(info.signature))

      if (missing.length > 0) {
        const settled = await rpcBatchSettled(
          url,
          missing.map(info => ({
            method: 'getTransaction',
            params: [info.signature, {...CONFIRMED, encoding: 'jsonParsed', maxSupportedTransactionVersion: 0}],
          }))
        )
        settled.forEach((entry, index) => {
          const info = missing[index]
          if (info && 'result' in entry && entry.result) {
            transactions.set(info.signature, entry.result as NonNullable<ParsedTransaction>)
          }
        })
      }

      return signatures.flatMap(info => toActivity(address, info, transactions.get(info.signature) ?? null))
    },
    airgapQuote: async (account, send) => {
      const {transaction, ...quote} = await prepare(chain, account.address, send)
      const request = {account, origin: AIRGAP_ORIGIN, requestId: createRequestId(random), transaction}

      return {
        ...quote,
        complete: async answer => {
          const response = airgap.decodeSignResponse(answer, {request})

          if (response.kind !== 'transaction') {
            throw new NetworkError('The signer answered with a message signature, not a transaction.')
          }

          return broadcast(response.transaction.serialized)
        },
        request: airgap.encodeSignRequest(request),
      }
    },
    holdings: async address => {
      const [{value: lamports}, ...tokens] = await Promise.all([
        rpc<Value<number>>(url, 'getBalance', [address, CONFIRMED]),
        ...network.tokens.map(token => tokenBalance(address, token.contract ?? '')),
      ])

      return [
        {asset: network.native, balance: BigInt(lamports)},
        ...network.tokens.map((asset, index) => ({asset, balance: tokens[index] ?? 0n})),
      ]
    },
    quote: async (account, send) => {
      const {transaction, ...quote} = await prepare(chain, account.address, send)

      return {
        ...quote,
        send: async () => broadcast((await account.signTransaction(transaction)).serialized),
      }
    },
    status: async signature => {
      const {value} = await rpc<Value<SignatureStatus[]>>(url, 'getSignatureStatuses', [
        [signature],
        {searchTransactionHistory: true},
      ])
      const status = value[0]

      if (!status) {
        return 'pending'
      }
      if (status.err) {
        return 'failed'
      }
      return status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized'
        ? 'confirmed'
        : 'pending'
    },
  }
}
