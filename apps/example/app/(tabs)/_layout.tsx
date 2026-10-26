import {Tabs} from '@hzblj/kara-ui/router'

export default function TabLayout() {
  return (
    <Tabs>
      <Tabs.Screen icon="bolt" name="(overview)" selectedIcon="bolt-filled" title="Overview" />
      <Tabs.Screen icon="wallet" name="wallet" selectedIcon="wallet-filled" title="Wallet" />
      <Tabs.Screen icon="layers" name="accounts" selectedIcon="layers-filled" title="Accounts" />
      <Tabs.Screen icon="verified" name="sign" selectedIcon="verified-filled" title="Sign" />
      <Tabs.Screen icon="science" name="lab" selectedIcon="science-filled" title="Lab" />
    </Tabs>
  )
}
