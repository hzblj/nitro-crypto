import {Box, IconButton, Island, RnText} from '@hzblj/kara-ui'

import {useCopy} from './copy'

type ValueProps = {
  /** What it is, above the value: "Address", "Public key". */
  label: string
  /** Shown monospaced and selectable: hex, Base58, a path. */
  value: string
  /** What the copy button says it copies; no button without it. */
  copyAs?: string
  testID?: string
}

/** A labelled value that is meant to be read character by character, and copied. */
export const Value = ({copyAs, label, testID, value}: ValueProps) => {
  const copy = useCopy()

  return (
    <Box align="center" gap="s8" row>
      <Box fill gap="s2">
        <RnText color="content.secondary" variant="caption">
          {label}
        </RnText>
        <RnText monospaced selectable testID={testID} variant="footnote">
          {value}
        </RnText>
      </Box>
      {copyAs ? (
        // An explicit size: a native island in a row takes no width of its own (48 is Android's tap target, and
        // holds iOS's 44).
        <Island h={48} w={48}>
          <IconButton
            accessibilityLabel={`Copy the ${copyAs}`}
            name="content-copy"
            onPress={() => copy(value, copyAs)}
          />
        </Island>
      ) : null}
    </Box>
  )
}
