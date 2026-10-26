import {Stack} from 'expo-router'

import {AccountsScreen} from '../../../src/features/debug/accounts'

export default function Accounts() {
  return (
    <>
      <Stack.Screen options={{title: 'Accounts'}} />
      <AccountsScreen />
    </>
  )
}
