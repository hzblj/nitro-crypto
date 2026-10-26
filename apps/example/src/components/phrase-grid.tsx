import {Box, RnText} from '@hzblj/kara-ui'

/** A recovery phrase, numbered, two columns: the layout people copy onto paper. */
export const PhraseGrid = ({testID, words}: {testID?: string; words: readonly string[]}) => (
  <Box gap="s8" row testID={testID} wrap>
    {words.map((word, index) => (
      <Box
        align="center"
        bg="surface.primary"
        borderRadius="medium"
        gap="s8"
        key={`${index}:${word}`}
        px="s12"
        py="s10"
        row
        w="48.5%"
      >
        <RnText color="content.tertiary" monospacedDigit variant="footnote" w={20}>
          {index + 1}
        </RnText>
        <RnText selectable={false} testID={`phrase-word-${index + 1}`} variant="body">
          {word}
        </RnText>
      </Box>
    ))}
  </Box>
)
