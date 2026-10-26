import type {BitcoinChain, BitcoinUtxo} from '@hzblj/crypto-bitcoin'

import {NETWORKS} from '../config'
import {formatUnits} from '../utils'
import {getJson, NetworkError, postText} from './http'
import type {ActivityItem, ChainService} from './types'

const network = NETWORKS.bitcoin
const api = network.endpoint

type Stats = {readonly funded_txo_sum: number; readonly spent_txo_sum: number}
type AddressInfo = {readonly chain_stats: Stats; readonly mempool_stats: Stats}
type Status = {readonly confirmed: boolean; readonly block_time?: number}
type Output = {readonly scriptpubkey_address?: string; readonly value: number}
type EsploraTransaction = {
  readonly txid: string
  readonly vin: readonly {readonly prevout: Output | null}[]
  readonly vout: readonly Output[]
  readonly fee: number
  readonly status: Status
}
type EsploraUtxo = {readonly txid: string; readonly vout: number; readonly value: number}
type Fees = {readonly halfHourFee: number; readonly minimumFee: number}

const sum = (outputs: readonly Output[]) => outputs.reduce((total, output) => total + BigInt(output.value), 0n)

/** One Esplora transaction from the address's side: what it sent others, or what it received. */
const toActivity = (address: string, transaction: EsploraTransaction): ActivityItem => {
  const ours = (output: Output | null) => output?.scriptpubkey_address === address
  const spending = transaction.vin.some(input => ours(input.prevout))
  const others = transaction.vout.filter(output => !ours(output))
  const direction = spending ? (others.length === 0 ? 'self' : 'out') : 'in'

  return {
    // Sent: what others got. Received, or moved between this address's own coins: what came back to it.
    amount: direction === 'out' ? sum(others) : sum(transaction.vout.filter(ours)),
    asset: network.native,
    chain: 'bitcoin',
    counterparty: spending
      ? others[0]?.scriptpubkey_address
      : transaction.vin.find(input => !ours(input.prevout))?.prevout?.scriptpubkey_address,
    direction,
    hash: transaction.txid,
    id: `bitcoin:${transaction.txid}`,
    status: transaction.status.confirmed ? 'confirmed' : 'pending',
    timestamp: transaction.status.block_time ? transaction.status.block_time * 1000 : undefined,
  }
}

export const bitcoinService = (chain: BitcoinChain): ChainService<'bitcoin'> => ({
  activity: async address =>
    (await getJson<EsploraTransaction[]>(`${api}/address/${address}/txs`)).map(transaction =>
      toActivity(address, transaction)
    ),
  holdings: async address => {
    const {chain_stats: confirmed, mempool_stats: pending} = await getJson<AddressInfo>(`${api}/address/${address}`)
    const balance =
      BigInt(confirmed.funded_txo_sum - confirmed.spent_txo_sum) +
      BigInt(pending.funded_txo_sum - pending.spent_txo_sum)

    return [{asset: network.native, balance}]
  },
  quote: async (account, {amount, to}) => {
    const recipient = chain.validateAddress(to)

    if (!recipient.valid) {
      throw new NetworkError(recipient.reason)
    }

    const [coins, fees] = await Promise.all([
      getJson<EsploraUtxo[]>(`${api}/address/${account.address}/utxo`),
      getJson<Fees>(`${api}/v1/fees/recommended`),
    ])

    if (coins.length === 0) {
      throw new NetworkError('This address has no coins to spend yet: fund it from a testnet4 faucet.')
    }

    const utxos: BitcoinUtxo[] = coins.map(coin => ({txid: coin.txid, value: BigInt(coin.value), vout: coin.vout}))
    const feeRate = Math.max(fees.halfHourFee, fees.minimumFee, 1)
    const plan = account.createTransaction({amount, feeRate, to: recipient.normalized, utxos})

    return {
      amount: plan.amount,
      details: [
        {label: 'Network', value: `Bitcoin ${network.testnet}`},
        {label: 'Fee rate', value: `${feeRate} sat/vB`},
        {label: 'Size', value: `${plan.vsize} vB, at most`},
        {label: 'Inputs', value: `${plan.inputs.length} of ${utxos.length} coins`},
        {
          label: 'Change',
          value: plan.change > 0n ? `${formatUnits(plan.change, 8, 8)} BTC back to this address` : 'None',
        },
      ],
      fee: plan.fee,
      send: async () => {
        const signed = await account.signTransaction(plan)

        return postText(`${api}/tx`, signed.hex)
      },
    }
  },
  status: async txid => {
    try {
      return (await getJson<Status>(`${api}/tx/${txid}/status`)).confirmed ? 'confirmed' : 'pending'
    } catch (error) {
      // Not yet propagated to the explorer's node.
      if (error instanceof NetworkError && /not found/i.test(error.message)) {
        return 'pending'
      }
      throw error
    }
  },
})
