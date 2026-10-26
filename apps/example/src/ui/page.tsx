import {Box, Divider, RnScrollView, RnText, VStack} from '@hzblj/kara-ui'
import type {ReactNode} from 'react'

/** Every screen of the example: one React Native scroll view under the native large title, with room for the tab bar. */
export const Page = ({children, testID}: {children: ReactNode; testID?: string}) => (
  <RnScrollView
    bg="surface.base"
    content={{gap: 's32', pb: 's80', pt: 's8', px: 's20'}}
    contentInsetAdjustmentBehavior="automatic"
    flex={1}
    keyboardShouldPersistTaps="handled"
    testID={testID}
  >
    {children}
  </RnScrollView>
)

/** The sentence under a page's title that says what the page is about. */
export const Lead = ({children}: {children: ReactNode}) => (
  <RnText color="content.secondary" variant="body">
    {children}
  </RnText>
)

type SectionProps = {
  /** A line under the content: what to notice, or what is not supported. */
  caption?: string
  children: ReactNode
  title?: string
}

/** A titled block of a page, in the style of a grouped list's header and footer. */
export const Section = ({caption, children, title}: SectionProps) => (
  <Box gap="s8">
    {title ? (
      <RnText color="content.secondary" variant="footnoteMedium">
        {title.toUpperCase()}
      </RnText>
    ) : null}
    {children}
    {caption ? (
      <RnText color="content.tertiary" variant="footnote">
        {caption}
      </RnText>
    ) : null}
  </Box>
)

/** A card of native rows (`LabeledContent`), as a grouped list draws one. */
export const Rows = ({children}: {children: ReactNode}) => (
  <VStack bg="surface.primary" borderRadius="large" px="s16" py="s4" wide>
    {children}
  </VStack>
)

export const RowDivider = () => <Divider />

/** A card for React Native content. */
export const Card = ({children, testID}: {children: ReactNode; testID?: string}) => (
  <Box bg="surface.primary" borderRadius="large" gap="s12" p="s16" testID={testID}>
    {children}
  </Box>
)
