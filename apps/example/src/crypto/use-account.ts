import {useEffect, useState} from 'react'

import {type AppAccount, type ChainId, useCrypto} from './crypto-provider'

export type AccountState<Id extends ChainId> =
  | {readonly status: 'idle' | 'loading'}
  | {readonly status: 'ready'; readonly account: AppAccount<Id>}
  | {readonly status: 'failed'; readonly message: string}

/** The `n`th account of `chain` in the current wallet, as it loads: `idle` without a wallet. */
export const useAccount = <Id extends ChainId>(chain: Id, n: number): AccountState<Id> => {
  const {account, wallet} = useCrypto()
  const [state, setState] = useState<AccountState<Id>>({status: 'idle'})

  useEffect(() => {
    if (!wallet) {
      setState({status: 'idle'})
      return
    }
    let current = true
    setState({status: 'loading'})
    account(chain, n).then(
      loaded => current && setState({account: loaded, status: 'ready'}),
      (error: Error) => current && setState({message: error.message, status: 'failed'})
    )
    return () => {
      current = false
    }
  }, [account, chain, n, wallet])

  return state
}
