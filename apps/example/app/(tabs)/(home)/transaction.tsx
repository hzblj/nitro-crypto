import {Stack, useLocalSearchParams} from 'expo-router'
import {isChainId} from '../../../src/config'
import {TransactionScreen} from '../../../src/features/transaction'

export default function Transaction() {
  const {amount, asset, chain, hash, to} = useLocalSearchParams<{
    amount?: string
    asset?: string
    chain: string
    hash: string
    to?: string
  }>()

  return (
    <>
      <Stack.Screen options={{headerBackVisible: false, title: 'Transaction'}} />
      <TransactionScreen
        amount={amount}
        asset={asset}
        chain={isChainId(chain) ? chain : 'ethereum'}
        hash={hash ?? ''}
        to={to}
      />
    </>
  )
}
