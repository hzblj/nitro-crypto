import {Island, Label, Text, VStack} from '@hzblj/kara-ui'

/**
 * The warning the Debug screens carry: this is a developer showcase. The keys are real cryptography, but nothing has
 * been reviewed to make them fit for anything of value.
 */
export const DemoNotice = ({compact = false}: {compact?: boolean}) => (
  <Island>
    <VStack align="start" bg="fill.destructive.base" borderRadius="large" p="s16" spacing="s8" wide>
      <Label color="content.destructive" icon="warning-filled" title="Demo only, not audited" variant="headline" />
      <Text color="content.secondary" variant="subheadline">
        {compact
          ? 'Never use these keys for real funds.'
          : 'Real cryptography on test networks: nothing here has been security audited. Never send real funds to these addresses.'}
      </Text>
    </VStack>
  </Island>
)
