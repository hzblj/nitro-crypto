import {Island, Label, Text, VStack} from '@hzblj/kara-ui'

/**
 * The warning every wallet-like screen carries: this is a developer showcase. The keys are real cryptography, but
 * nothing about storage, recovery or review makes them fit for anything of value.
 */
export const DemoNotice = ({compact = false}: {compact?: boolean}) => (
  <Island>
    <VStack align="start" bg="fill.destructive.base" borderRadius="large" p="s16" spacing="s8" wide>
      <Label color="content.destructive" icon="warning-filled" title="Demo only, not audited" variant="headline" />
      <Text color="content.secondary" variant="subheadline">
        {compact
          ? 'Never use these keys for real funds.'
          : 'Real cryptography, demo keys: nothing here has been security audited, keys live in memory only and vanish on reset, reload or reinstall, and none of it is a wallet. Never send real funds to these addresses.'}
      </Text>
    </VStack>
  </Island>
)
