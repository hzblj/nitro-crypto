import {Tabs} from '@hzblj/kara-ui/router'

export default function TabLayout() {
  return (
    <Tabs>
      <Tabs.Screen icon="wallet" name="(home)" selectedIcon="wallet-filled" title="Wallet" />
      <Tabs.Screen icon="receipt-long" name="activity" selectedIcon="receipt-long-filled" title="Activity" />
      <Tabs.Screen icon="settings" name="settings" selectedIcon="settings-filled" title="Settings" />
      <Tabs.Screen icon="bug-report" name="debug" selectedIcon="bug-report-filled" title="Debug" />
    </Tabs>
  )
}
