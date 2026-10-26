import {Stack} from 'expo-router'

import {DemoWalletScreen} from '../../../src/features/debug/demo-wallet'

export default function DemoWallet() {
  return (
    <>
      <Stack.Screen options={{title: 'Demo wallet'}} />
      <DemoWalletScreen />
    </>
  )
}
