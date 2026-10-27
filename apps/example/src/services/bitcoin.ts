import {bitcoinAirgap} from '@hzblj/crypto-airgap-bitcoin'
import type {BitcoinChain, BitcoinWatchAccount} from '@hzblj/crypto-bitcoin'
import {type AccountTransaction, type BitcoinSync, createBitcoinSync, esploraBackend} from '@hzblj/crypto-bitcoin/sync'

import {fetch} from 'react-native-nitro-fetch'

import {NETWORKS} from '../config'
import {formatUnits} from '../utils'
import {NetworkError} from './http'
import type {ActivityItem, ChainService, SendRequest} from './types'

const network = NETWORKS.bitcoin

/** A balance and a history asked for together (the home screen does) share one sync. */
const FRESH_MS = 5_000

const DIRECTIONS = {received: 'in', self: 'self', sent: 'out'} as const

/** One transaction from the address's side, as the sync accounts for it: what it sent others, or what it received. */
const toActivity = (transaction: AccountTransaction): ActivityItem => ({
  amount: transaction.amount,
  asset: network.native,
  chain: 'bitcoin',
  counterparty: transaction.counterparties[0],
  direction: DIRECTIONS[transaction.kind],
  hash: transaction.txid,
  id: `bitcoin:${transaction.txid}`,
  status: transaction.confirmations > 0 ? 'confirmed' : 'pending',
  timestamp: transaction.blockTime ? transaction.blockTime * 1000 : undefined,
})

export const bitcoinService = (chain: BitcoinChain): ChainService<'bitcoin'> => {
  const airgap = bitcoinAirgap(chain)
  // Over react-native-nitro-fetch (URLSession on iOS, Cronet on Android): any client that answers like `fetch` does, and
  // forwards the signal, so a sync that is cancelled really stops its requests.
  const backend = esploraBackend({fetch, network: chain.network.name, url: network.endpoint})
  const syncs = new Map<string, BitcoinSync>()

  /**
   * The address's sync, one per address for the app's run. The screens read balances and histories by address;
   * a payment needs the account's key, and its sync takes over what the address's had read (`snapshot`).
   */
  const syncOf = (address: string, account?: BitcoinWatchAccount) => {
    const current = syncs.get(address)

    if (current && (current.scriptType !== undefined || !account)) {
      return current
    }

    const next = account
      ? createBitcoinSync({account, backend, chain, snapshot: current?.snapshot()})
      : createBitcoinSync({address, backend, chain})
    syncs.set(address, next)

    return next
  }

  /** A payment from `account` at the network's current state: the coins it spends, the fee, what the screens list. */
  const prepare = async (account: BitcoinWatchAccount, {amount, to}: SendRequest) => {
    const recipient = chain.validateAddress(to)

    if (!recipient.valid) {
      throw new NetworkError(recipient.reason)
    }

    const sync = syncOf(account.address, account)
    const [view, fees] = await Promise.all([sync.sync(), sync.feeEstimates()])

    if (view.utxos.length === 0) {
      throw new NetworkError('This address has no coins to spend yet: fund it from a testnet4 faucet.')
    }

    const feeRate = Math.max(fees.halfHour, fees.minimum, 1)
    // Unconfirmed coins too, as faucets pay them: a test wallet should not make the user wait for a block.
    const payment = sync.createPayment({amount, feeRate, to: recipient.normalized, unconfirmed: 'all'})
    const {plan} = payment

    return {
      amount: plan.amount,
      details: [
        {label: 'Network', value: `Bitcoin ${network.testnet}`},
        {label: 'Fee rate', value: `${feeRate} sat/vB`},
        {label: 'Size', value: `${plan.vsize} vB, at most`},
        {label: 'Inputs', value: `${plan.inputs.length} of ${view.utxos.length} coins`},
        {
          label: 'Change',
          value: plan.change > 0n ? `${formatUnits(plan.change, 8, 8)} BTC back to this address` : 'None',
        },
      ],
      fee: plan.fee,
      payment,
      sync,
    }
  }

  return {
    activity: async address => (await syncOf(address).sync({maxAgeMs: FRESH_MS})).transactions.map(toActivity),
    airgapQuote: async (account, send) => {
      const {payment, sync, ...quote} = await prepare(account, send)
      // Each coin's whole previous transaction goes with it, so the signer can check the values it signs.
      const psbt = await sync.createPsbt(payment)

      return {
        ...quote,
        complete: async answer => sync.broadcast(airgap.decodeSignResponse(answer, {request: psbt}).transaction),
        request: airgap.encodeSignRequest({psbt}),
      }
    },
    holdings: async address => {
      const {balance} = await syncOf(address).sync({maxAgeMs: FRESH_MS})

      return [{asset: network.native, balance: balance.total}]
    },
    quote: async (account, send) => {
      const {payment, sync, ...quote} = await prepare(account, send)

      return {
        ...quote,
        send: async () => sync.broadcast(await account.signTransaction(payment.plan)),
      }
    },
    // Unknown is not yet propagated to the explorer's node: pending, as far as the screens go.
    status: async txid => ((await backend.transactionStatus(txid))?.confirmed ? 'confirmed' : 'pending'),
  }
}
